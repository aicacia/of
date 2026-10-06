use std::{future::Future, io, path::PathBuf};

use ofdb_sql::{SyncStage, SyncStageFactory};
use tokio::{
    fs,
    io::{AsyncReadExt, AsyncWriteExt},
};

const MAX_RECORD_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_STAGE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Debug)]
pub(crate) struct FileSyncStageFactory {
    directory: PathBuf,
}

impl FileSyncStageFactory {
    pub(crate) fn new(directory: PathBuf) -> Self {
        Self { directory }
    }
}

pub(crate) struct FileSyncStage {
    path: PathBuf,
    writer: Option<fs::File>,
    reader: Option<fs::File>,
    used_bytes: usize,
    finished: bool,
}

impl SyncStageFactory for FileSyncStageFactory {
    type Stage = FileSyncStage;
    type Error = io::Error;

    fn create(&self) -> impl Future<Output = Result<Self::Stage, Self::Error>> + Send {
        let directory = self.directory.clone();
        async move {
            fs::create_dir_all(&directory).await?;
            let path = directory.join(format!("sync-{}.stage", idp_model::model::Id::now_v7()));
            let writer = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&path)
                .await?;
            Ok(FileSyncStage {
                path,
                writer: Some(writer),
                reader: None,
                used_bytes: 0,
                finished: false,
            })
        }
    }
}

impl SyncStage for FileSyncStage {
    type Error = io::Error;

    fn append(&mut self, record: Vec<u8>) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async move {
            if self.finished {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "sync stage is finished",
                ));
            }
            if record.len() > MAX_RECORD_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "sync stage record exceeds 1 MiB",
                ));
            }
            let next_bytes = self
                .used_bytes
                .saturating_add(record.len())
                .saturating_add(4);
            if next_bytes > MAX_STAGE_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::OutOfMemory,
                    "sync stage exceeds 64 MiB",
                ));
            }
            let length = u32::try_from(record.len()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "sync stage record is too large")
            })?;
            let writer = self.writer.as_mut().ok_or_else(|| {
                io::Error::new(io::ErrorKind::BrokenPipe, "sync stage writer is closed")
            })?;
            writer.write_all(&length.to_be_bytes()).await?;
            writer.write_all(&record).await?;
            self.used_bytes = next_bytes;
            Ok(())
        }
    }

    fn finish(&mut self) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async move {
            if self.finished {
                return Ok(());
            }
            if let Some(mut writer) = self.writer.take() {
                writer.flush().await?;
                drop(writer);
            }
            self.reader = Some(fs::File::open(&self.path).await?);
            self.finished = true;
            Ok(())
        }
    }

    fn next_record(&mut self) -> impl Future<Output = Result<Option<Vec<u8>>, Self::Error>> + Send {
        async move {
            if !self.finished {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "sync stage is not finished",
                ));
            }
            let reader = self.reader.as_mut().ok_or_else(|| {
                io::Error::new(io::ErrorKind::BrokenPipe, "sync stage reader is closed")
            })?;
            let mut prefix = [0; 4];
            if reader.read(&mut prefix[..1]).await? == 0 {
                return Ok(None);
            }
            reader.read_exact(&mut prefix[1..]).await?;
            let length = u32::from_be_bytes(prefix) as usize;
            if length > MAX_RECORD_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid sync stage record length",
                ));
            }
            let mut record = vec![0; length];
            reader.read_exact(&mut record).await?;
            Ok(Some(record))
        }
    }
}

impl Drop for FileSyncStage {
    fn drop(&mut self) {
        self.writer.take();
        self.reader.take();
        if let Err(error) = std::fs::remove_file(&self.path) {
            if error.kind() != io::ErrorKind::NotFound {
                log::warn!("failed to remove sync stage file: {error}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ofdb_sql::{
        Database, SessionConfig, SyncRole, SyncStage, SyncStageFactory, SyncStateUnit,
        SyncTransport,
    };
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    struct ChannelTransport {
        sender: tokio::sync::mpsc::Sender<Vec<u8>>,
        receiver: tokio::sync::mpsc::Receiver<Vec<u8>>,
    }

    impl SyncTransport for ChannelTransport {
        type Error = io::Error;

        async fn send(&mut self, frame: Vec<u8>) -> Result<(), Self::Error> {
            self.sender
                .send(frame)
                .await
                .map_err(|error| io::Error::new(io::ErrorKind::BrokenPipe, error.to_string()))
        }

        async fn receive(&mut self) -> Result<Vec<u8>, Self::Error> {
            self.receiver.recv().await.ok_or_else(|| {
                io::Error::new(io::ErrorKind::UnexpectedEof, "sync peer closed channel")
            })
        }
    }

    struct PauseAfterState {
        inner: ChannelTransport,
        received_frames: usize,
        reached_pause: Option<tokio::sync::oneshot::Sender<()>>,
    }

    impl SyncTransport for PauseAfterState {
        type Error = io::Error;

        async fn send(&mut self, frame: Vec<u8>) -> Result<(), Self::Error> {
            self.inner.send(frame).await
        }

        async fn receive(&mut self) -> Result<Vec<u8>, Self::Error> {
            if self.received_frames >= 4 {
                self.reached_pause
                    .take()
                    .expect("signal once after a staged state frame")
                    .send(())
                    .expect("test is waiting for the staged frame");
                return core::future::pending().await;
            }
            let frame = self.inner.receive().await?;
            self.received_frames += 1;
            Ok(frame)
        }
    }

    struct MalformedStateTransport {
        inner: ChannelTransport,
        received_frames: usize,
        staging_directory: PathBuf,
    }

    impl SyncTransport for MalformedStateTransport {
        type Error = io::Error;

        async fn send(&mut self, frame: Vec<u8>) -> Result<(), Self::Error> {
            self.inner.send(frame).await
        }

        async fn receive(&mut self) -> Result<Vec<u8>, Self::Error> {
            let frame = self.inner.receive().await?;
            if self.received_frames == 3 {
                assert!(
                    std::fs::read_dir(&self.staging_directory)?.count() > 0,
                    "session stages exist before the malformed frame"
                );
                self.received_frames += 1;
                return Ok(Vec::new());
            }
            self.received_frames += 1;
            Ok(frame)
        }
    }

    #[derive(Clone)]
    struct InvalidReplayFactory {
        inner: FileSyncStageFactory,
        corrupt_stage: usize,
        corrupt_state: bool,
        created: Arc<AtomicUsize>,
    }

    struct InvalidReplayStage {
        inner: FileSyncStage,
        corrupt_first_record: bool,
        corrupt_state: bool,
        corrupted: bool,
    }

    impl SyncStageFactory for InvalidReplayFactory {
        type Stage = InvalidReplayStage;
        type Error = io::Error;

        fn create(&self) -> impl Future<Output = Result<Self::Stage, Self::Error>> + Send {
            let factory = self.inner.clone();
            let corrupt_stage = self.corrupt_stage;
            let corrupt_state = self.corrupt_state;
            let created = Arc::clone(&self.created);
            async move {
                let stage_index = created.fetch_add(1, Ordering::SeqCst);
                Ok(InvalidReplayStage {
                    inner: factory.create().await?,
                    corrupt_first_record: stage_index == corrupt_stage,
                    corrupt_state,
                    corrupted: false,
                })
            }
        }
    }

    async fn synchronize_databases(initiator_db: &Database, responder_db: &Database) {
        let (initiator_tx, responder_rx) = tokio::sync::mpsc::channel(8);
        let (responder_tx, initiator_rx) = tokio::sync::mpsc::channel(8);
        let mut initiator_transport = ChannelTransport {
            sender: initiator_tx,
            receiver: initiator_rx,
        };
        let mut responder_transport = ChannelTransport {
            sender: responder_tx,
            receiver: responder_rx,
        };
        let config = SessionConfig::default();
        let initiator_config = config.clone();
        let responder_config = config;
        let initiator_db = initiator_db.clone();
        let responder_db = responder_db.clone();
        let initiator_task = tokio::spawn(async move {
            initiator_db
                .synchronize(
                    &mut initiator_transport,
                    &initiator_config,
                    SyncRole::Initiator,
                )
                .await
        });
        let responder_task = tokio::spawn(async move {
            responder_db
                .synchronize(
                    &mut responder_transport,
                    &responder_config,
                    SyncRole::Responder,
                )
                .await
        });
        let (initiator_result, responder_result) =
            tokio::time::timeout(Duration::from_secs(30), async {
                tokio::join!(initiator_task, responder_task)
            })
            .await
            .expect("database sync pair completes");
        initiator_result
            .expect("initiator task joins")
            .expect("initiator database sync succeeds");
        responder_result
            .expect("responder task joins")
            .expect("responder database sync succeeds");
    }

    impl SyncStage for InvalidReplayStage {
        type Error = io::Error;

        fn append(
            &mut self,
            record: Vec<u8>,
        ) -> impl Future<Output = Result<(), Self::Error>> + Send {
            self.inner.append(record)
        }

        fn finish(&mut self) -> impl Future<Output = Result<(), Self::Error>> + Send {
            self.inner.finish()
        }

        fn next_record(
            &mut self,
        ) -> impl Future<Output = Result<Option<Vec<u8>>, Self::Error>> + Send {
            async move {
                let record = self.inner.next_record().await?;
                let Some(record) = record else {
                    return Ok(None);
                };
                if self.corrupt_first_record && !self.corrupted {
                    self.corrupted = true;
                    if self.corrupt_state {
                        let mut unit: SyncStateUnit =
                            postcard::from_bytes(&record).map_err(io::Error::other)?;
                        unit.state = vec![0xff];
                        return Ok(Some(
                            postcard::to_allocvec(&unit).map_err(io::Error::other)?,
                        ));
                    }
                    return Ok(Some(Vec::new()));
                }
                Ok(Some(record))
            }
        }
    }

    #[tokio::test]
    async fn replay_error_preserves_local_catalog_and_cleans_files() {
        let base = std::env::temp_dir().join(format!(
            "storage-sync-stage-replay-error-{}",
            idp_model::model::Id::now_v7()
        ));
        std::fs::create_dir_all(&base).expect("create sync test directory");
        let initiator_db = Database::open(base.join("initiator.redb")).expect("open initiator db");
        let responder_db = Database::open(base.join("responder.redb")).expect("open responder db");
        initiator_db
            .client()
            .execute_sql(
                "CREATE TABLE staged_rows (id UUID PRIMARY KEY, value TEXT)",
                None,
            )
            .await
            .expect("create source table");

        let (initiator_tx, responder_rx) = tokio::sync::mpsc::channel(8);
        let (responder_tx, initiator_rx) = tokio::sync::mpsc::channel(8);
        let initiator_transport = ChannelTransport {
            sender: initiator_tx,
            receiver: initiator_rx,
        };
        let responder_transport = ChannelTransport {
            sender: responder_tx,
            receiver: responder_rx,
        };
        let staging_directory = base.join("stages");
        let config = SessionConfig::default();
        let initiator_config = config.clone();
        let responder_config = config;
        let responder_sync_db = responder_db.clone();
        let initiator = tokio::spawn(async move {
            let mut transport = initiator_transport;
            initiator_db
                .synchronize(&mut transport, &initiator_config, SyncRole::Initiator)
                .await
        });
        let factory = InvalidReplayFactory {
            inner: FileSyncStageFactory::new(staging_directory.clone()),
            corrupt_stage: 0,
            corrupt_state: false,
            created: Arc::new(AtomicUsize::new(0)),
        };
        let responder = tokio::spawn(async move {
            let mut transport = responder_transport;
            responder_sync_db
                .synchronize_with_stage_factory(
                    &mut transport,
                    &responder_config,
                    SyncRole::Responder,
                    &factory,
                )
                .await
        });
        let (initiator_result, responder_result) =
            tokio::time::timeout(Duration::from_secs(30), async {
                tokio::join!(initiator, responder)
            })
            .await
            .expect("sync pair completes after replay error");
        let initiator_result = initiator_result.expect("initiator task joins");
        let responder_result = responder_result.expect("responder task joins");
        assert!(
            initiator_result.is_err() || responder_result.is_err(),
            "invalid staged catalog record fails sync"
        );
        assert!(
            responder_db
                .client()
                .execute_sql("SELECT * FROM staged_rows", None)
                .await
                .is_err(),
            "failed catalog replay leaves the destination catalog unchanged"
        );
        assert_eq!(
            std::fs::read_dir(&staging_directory)
                .expect("read stage directory after replay error")
                .count(),
            0,
            "replay error removes all stage files"
        );
        std::fs::remove_dir_all(base).expect("remove sync test directory");
    }

    #[tokio::test]
    async fn user_data_apply_error_rolls_back_row_and_cleans_files() {
        let base = std::env::temp_dir().join(format!(
            "storage-sync-stage-user-replay-error-{}",
            idp_model::model::Id::now_v7()
        ));
        std::fs::create_dir_all(&base).expect("create sync test directory");
        let initiator_db = Database::open(base.join("initiator.redb")).expect("open initiator db");
        let responder_db = Database::open(base.join("responder.redb")).expect("open responder db");
        initiator_db
            .client()
            .execute_sql(
                "CREATE TABLE staged_rows (id UUID PRIMARY KEY, value TEXT)",
                None,
            )
            .await
            .expect("create source table");
        synchronize_databases(&initiator_db, &responder_db).await;
        responder_db
            .client()
            .execute_sql(
                "INSERT INTO staged_rows VALUES (CAST('018f0f8e-7b6d-7c4a-8f12-123456789abd' AS UUID), 'local')",
                None,
            )
            .await
            .expect("insert destination-local row");
        initiator_db
            .client()
            .execute_sql(
                "INSERT INTO staged_rows VALUES (CAST('018f0f8e-7b6d-7c4a-8f12-123456789abc' AS UUID), 'source')",
                None,
            )
            .await
            .expect("insert source row");

        let (initiator_tx, responder_rx) = tokio::sync::mpsc::channel(8);
        let (responder_tx, initiator_rx) = tokio::sync::mpsc::channel(8);
        let initiator_transport = ChannelTransport {
            sender: initiator_tx,
            receiver: initiator_rx,
        };
        let responder_transport = ChannelTransport {
            sender: responder_tx,
            receiver: responder_rx,
        };
        let staging_directory = base.join("stages");
        let config = SessionConfig::default();
        let initiator_config = config.clone();
        let responder_config = config;
        let initiator = tokio::spawn(async move {
            let mut transport = initiator_transport;
            initiator_db
                .synchronize(&mut transport, &initiator_config, SyncRole::Initiator)
                .await
        });
        let factory = InvalidReplayFactory {
            inner: FileSyncStageFactory::new(staging_directory.clone()),
            corrupt_stage: 8,
            corrupt_state: true,
            created: Arc::new(AtomicUsize::new(0)),
        };
        let responder_db_for_sync = responder_db.clone();
        let responder = tokio::spawn(async move {
            let mut transport = responder_transport;
            responder_db_for_sync
                .synchronize_with_stage_factory(
                    &mut transport,
                    &responder_config,
                    SyncRole::Responder,
                    &factory,
                )
                .await
        });
        let (initiator_result, responder_result) =
            tokio::time::timeout(Duration::from_secs(30), async {
                tokio::join!(initiator, responder)
            })
            .await
            .expect("sync pair completes after staged data error");
        let initiator_result = initiator_result.expect("initiator task joins");
        let responder_result = responder_result.expect("responder task joins");
        assert!(
            initiator_result.is_err() || responder_result.is_err(),
            "invalid staged user row fails sync"
        );
        let rows = responder_db
            .client()
            .execute_sql("SELECT value FROM staged_rows", None)
            .await
            .expect("catalog commits before user data replay");
        assert_eq!(rows[0].rows.len(), 1, "invalid staged row is not applied");
        assert_eq!(
            rows[0].rows[0].values[0].as_text(),
            Some("local"),
            "destination-local row is preserved"
        );
        assert_eq!(
            std::fs::read_dir(&staging_directory)
                .expect("read stage directory after user data replay error")
                .count(),
            0,
            "user data replay error removes all stage files"
        );
        std::fs::remove_dir_all(base).expect("remove sync test directory");
    }

    #[tokio::test]
    async fn malformed_sync_frame_removes_staged_files() {
        let base = std::env::temp_dir().join(format!(
            "storage-sync-stage-invalid-frame-{}",
            idp_model::model::Id::now_v7()
        ));
        std::fs::create_dir_all(&base).expect("create sync test directory");
        let initiator_db = Database::open(base.join("initiator.redb")).expect("open initiator db");
        let responder_db = Database::open(base.join("responder.redb")).expect("open responder db");
        initiator_db
            .client()
            .execute_sql(
                "CREATE TABLE staged_rows (id UUID PRIMARY KEY, value TEXT)",
                None,
            )
            .await
            .expect("create source table");

        let (initiator_tx, responder_rx) = tokio::sync::mpsc::channel(8);
        let (responder_tx, initiator_rx) = tokio::sync::mpsc::channel(8);
        let initiator_transport = ChannelTransport {
            sender: initiator_tx,
            receiver: initiator_rx,
        };
        let staging_directory = base.join("stages");
        let responder_transport = MalformedStateTransport {
            inner: ChannelTransport {
                sender: responder_tx,
                receiver: responder_rx,
            },
            received_frames: 0,
            staging_directory: staging_directory.clone(),
        };
        let config = SessionConfig::default();
        let initiator_config = config.clone();
        let responder_config = config;
        let initiator = tokio::spawn(async move {
            let mut transport = initiator_transport;
            initiator_db
                .synchronize(&mut transport, &initiator_config, SyncRole::Initiator)
                .await
        });
        let factory = FileSyncStageFactory::new(staging_directory.clone());
        let responder = tokio::spawn(async move {
            let mut transport = responder_transport;
            responder_db
                .synchronize_with_stage_factory(
                    &mut transport,
                    &responder_config,
                    SyncRole::Responder,
                    &factory,
                )
                .await
        });
        let result = tokio::time::timeout(Duration::from_secs(30), responder)
            .await
            .expect("receiver returns after malformed frame")
            .expect("receiver task joins");
        assert!(result.is_err(), "malformed frame fails sync");
        initiator.abort();
        let _ = initiator.await;
        assert_eq!(
            std::fs::read_dir(&staging_directory)
                .expect("read stage directory after protocol failure")
                .count(),
            0,
            "protocol failure removes all stage files"
        );
        std::fs::remove_dir_all(base).expect("remove sync test directory");
    }

    #[tokio::test]
    async fn timed_out_database_sync_removes_staged_files() {
        let base = std::env::temp_dir().join(format!(
            "storage-sync-stage-cancel-{}",
            idp_model::model::Id::now_v7()
        ));
        std::fs::create_dir_all(&base).expect("create sync test directory");
        let initiator_db = Database::open(base.join("initiator.redb")).expect("open initiator db");
        let responder_db = Database::open(base.join("responder.redb")).expect("open responder db");
        initiator_db
            .client()
            .execute_sql(
                "CREATE TABLE staged_rows (id UUID PRIMARY KEY, value TEXT)",
                None,
            )
            .await
            .expect("create source table");

        let (initiator_tx, responder_rx) = tokio::sync::mpsc::channel(8);
        let (responder_tx, initiator_rx) = tokio::sync::mpsc::channel(8);
        let initiator_transport = ChannelTransport {
            sender: initiator_tx,
            receiver: initiator_rx,
        };
        let responder_transport = PauseAfterState {
            inner: ChannelTransport {
                sender: responder_tx,
                receiver: responder_rx,
            },
            received_frames: 0,
            reached_pause: None,
        };
        let (pause_tx, pause_rx) = tokio::sync::oneshot::channel();
        let config = SessionConfig::default();
        let initiator_config = config.clone();
        let responder_config = config.clone();
        let initiator = tokio::spawn(async move {
            let mut transport = initiator_transport;
            initiator_db
                .synchronize(&mut transport, &initiator_config, SyncRole::Initiator)
                .await
        });
        let staging_directory = base.join("stages");
        let stage_factory = FileSyncStageFactory::new(staging_directory.clone());
        let responder = tokio::spawn(async move {
            let mut transport = responder_transport;
            transport.reached_pause = Some(pause_tx);
            crate::sync_timeout::run(
                Duration::from_millis(100),
                "database sync operation timed out",
                async {
                    responder_db
                        .synchronize_with_stage_factory(
                            &mut transport,
                            &responder_config,
                            SyncRole::Responder,
                            &stage_factory,
                        )
                        .await
                        .map_err(io::Error::other)
                },
            )
            .await
        });

        tokio::time::timeout(Duration::from_secs(30), pause_rx)
            .await
            .expect("receiver reaches pause")
            .expect("receiver signals pause");
        assert!(
            std::fs::read_dir(&staging_directory)
                .expect("read stage directory")
                .count()
                > 0,
            "receiver has created stage files before cancellation"
        );
        assert_eq!(
            responder
                .await
                .expect("timed-out receiver task joins")
                .expect_err("sync operation times out")
                .kind(),
            io::ErrorKind::TimedOut
        );
        initiator.abort();
        let _ = initiator.await;
        assert_eq!(
            std::fs::read_dir(&staging_directory)
                .expect("read stage directory after cancellation")
                .count(),
            0,
            "canceled sync removes all stage files"
        );
        std::fs::remove_dir_all(base).expect("remove sync test directory");
    }

    #[tokio::test]
    async fn database_sync_replays_staged_catalog_and_cleans_files() {
        let base = std::env::temp_dir().join(format!(
            "storage-sync-stage-integration-{}",
            idp_model::model::Id::now_v7()
        ));
        std::fs::create_dir_all(&base).expect("create sync test directory");
        let initiator_db = Database::open(base.join("initiator.redb")).expect("open initiator db");
        let responder_db = Database::open(base.join("responder.redb")).expect("open responder db");
        initiator_db
            .client()
            .execute_sql(
                "CREATE TABLE staged_rows (id UUID PRIMARY KEY, value TEXT)",
                None,
            )
            .await
            .expect("create source table");
        for batch_start in (0..4096).step_by(32) {
            let values = (batch_start..batch_start + 32)
                .map(|index| {
                    let mut state = index as u32 + 1;
                    let payload = (0..1024)
                        .map(|_| {
                            state ^= state << 13;
                            state ^= state >> 17;
                            state ^= state << 5;
                            char::from(b'a' + (state % 26) as u8)
                        })
                        .collect::<String>();
                    format!(
                        "(CAST('{}' AS UUID), '{}')",
                        idp_model::model::Id::now_v7(),
                        payload
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            initiator_db
                .client()
                .execute_sql(&format!("INSERT INTO staged_rows VALUES {values}"), None)
                .await
                .expect("insert source row batch");
        }

        let (initiator_tx, responder_rx) = tokio::sync::mpsc::channel(8);
        let (responder_tx, initiator_rx) = tokio::sync::mpsc::channel(8);
        let initiator_transport = ChannelTransport {
            sender: initiator_tx,
            receiver: initiator_rx,
        };
        let responder_transport = ChannelTransport {
            sender: responder_tx,
            receiver: responder_rx,
        };
        let stage_directory = base.join("stages");
        let stage_factory = FileSyncStageFactory::new(stage_directory.clone());
        let config = SessionConfig::default();
        let initiator_config = config.clone();
        let responder_db_for_sync = responder_db.clone();
        let initiator_task = tokio::spawn(async move {
            let mut transport = initiator_transport;
            initiator_db
                .synchronize(&mut transport, &initiator_config, SyncRole::Initiator)
                .await
        });
        let responder_task = tokio::spawn(async move {
            let mut transport = responder_transport;
            responder_db_for_sync
                .synchronize_with_stage_factory(
                    &mut transport,
                    &config,
                    SyncRole::Responder,
                    &stage_factory,
                )
                .await
        });
        let (sent, received) = tokio::time::timeout(Duration::from_secs(180), async {
            tokio::join!(initiator_task, responder_task)
        })
        .await
        .expect("sync pair completes within its test deadline");
        sent.expect("initiator task joins").expect("initiator sync");
        received
            .expect("responder task joins")
            .expect("responder sync");
        let rows = responder_db
            .client()
            .execute_sql("SELECT value FROM staged_rows", None)
            .await
            .expect("read staged rows");
        assert_eq!(rows[0].rows.len(), 4096);
        assert_eq!(
            std::fs::read_dir(&stage_directory)
                .expect("read stage directory")
                .count(),
            0,
            "successful sync removes every staged file"
        );

        std::fs::remove_dir_all(base).expect("remove sync test directory");
    }

    #[tokio::test]
    async fn stage_replays_records_in_order_and_removes_file_on_drop() {
        let directory = std::env::temp_dir().join(format!(
            "storage-sync-stage-test-{}",
            idp_model::model::Id::now_v7()
        ));
        let mut stage = FileSyncStageFactory::new(directory.clone())
            .create()
            .await
            .expect("create stage");
        let path = stage.path.clone();
        stage
            .append(b"catalog".to_vec())
            .await
            .expect("append catalog");
        stage.append(b"data".to_vec()).await.expect("append data");
        stage.finish().await.expect("finish stage");
        assert_eq!(
            stage.next_record().await.expect("read catalog"),
            Some(b"catalog".to_vec())
        );
        assert_eq!(
            stage.next_record().await.expect("read data"),
            Some(b"data".to_vec())
        );
        assert_eq!(stage.next_record().await.expect("read end"), None);
        drop(stage);
        assert!(!path.exists(), "stage file is removed on drop");
        std::fs::remove_dir(directory).expect("remove empty staging directory");
    }

    #[tokio::test]
    async fn stage_drop_removes_unfinished_file() {
        let directory = std::env::temp_dir().join(format!(
            "storage-sync-stage-test-{}",
            idp_model::model::Id::now_v7()
        ));
        let stage = FileSyncStageFactory::new(directory.clone())
            .create()
            .await
            .expect("create stage");
        let path = stage.path.clone();
        drop(stage);
        assert!(!path.exists(), "unfinished stage file is removed on drop");
        std::fs::remove_dir(directory).expect("remove empty staging directory");
    }

    #[tokio::test]
    async fn canceled_stage_owner_removes_file() {
        let directory = std::env::temp_dir().join(format!(
            "storage-sync-stage-test-{}",
            idp_model::model::Id::now_v7()
        ));
        let stage = FileSyncStageFactory::new(directory.clone())
            .create()
            .await
            .expect("create stage");
        let path = stage.path.clone();
        let task = tokio::spawn(async move {
            let _stage = stage;
            core::future::pending::<()>().await;
        });
        task.abort();
        assert!(
            task.await
                .expect_err("stage owner task is canceled")
                .is_cancelled()
        );
        assert!(
            !path.exists(),
            "cancellation drops and removes the stage file"
        );
        std::fs::remove_dir(directory).expect("remove empty staging directory");
    }

    #[tokio::test]
    async fn file_stage_replays_a_full_configured_stage_limit() {
        let directory = std::env::temp_dir().join(format!(
            "storage-sync-stage-stress-{}",
            idp_model::model::Id::now_v7()
        ));
        let mut stage = FileSyncStageFactory::new(directory.clone())
            .create()
            .await
            .expect("create stage");
        let record_bytes = MAX_RECORD_BYTES - 4;
        let record = vec![0xA5; record_bytes];
        let record_count = MAX_STAGE_BYTES / MAX_RECORD_BYTES;
        for _ in 0..record_count {
            stage
                .append(record.clone())
                .await
                .expect("append record within configured stage cap");
        }
        assert_eq!(stage.used_bytes, MAX_STAGE_BYTES);
        stage.finish().await.expect("finish stage");

        for _ in 0..record_count {
            let replayed = stage
                .next_record()
                .await
                .expect("replay staged record")
                .expect("record exists");
            assert_eq!(replayed.len(), record_bytes);
            assert!(replayed.iter().all(|byte| *byte == 0xA5));
        }
        assert_eq!(stage.next_record().await.expect("read end"), None);
        drop(stage);
        assert_eq!(
            std::fs::read_dir(&directory)
                .expect("read staging directory after replay")
                .count(),
            0,
            "replayed stage file is removed"
        );
        std::fs::remove_dir(directory).expect("remove empty staging directory");
    }

    #[tokio::test]
    async fn stage_rejects_records_after_its_byte_limit() {
        let directory = std::env::temp_dir().join(format!(
            "storage-sync-stage-test-{}",
            idp_model::model::Id::now_v7()
        ));
        let mut stage = FileSyncStageFactory::new(directory.clone())
            .create()
            .await
            .expect("create stage");
        let path = stage.path.clone();
        stage.used_bytes = MAX_STAGE_BYTES;
        let error = stage
            .append(Vec::new())
            .await
            .expect_err("stage limit is enforced");
        assert_eq!(error.kind(), io::ErrorKind::OutOfMemory);
        drop(stage);
        assert!(!path.exists(), "rejected stage file is removed on drop");
        std::fs::remove_dir(directory).expect("remove empty staging directory");
    }
}
