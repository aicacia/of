use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use db::Database;
use idp_model::model::Id;
use idp_service::security_sync::public_security_tables;
use ofdb_sql::{SessionConfig, SyncMessage, SyncRole, SyncTransport, SyncValidationDirection};
use tokio::sync::mpsc;

use crate::security_sync_tests::sql;

struct Channel {
    sender: mpsc::UnboundedSender<Vec<u8>>,
    receiver: mpsc::UnboundedReceiver<Vec<u8>>,
    payloads: Arc<AtomicUsize>,
}

impl SyncTransport for Channel {
    type Error = io::Error;

    async fn send(&mut self, frame: Vec<u8>) -> io::Result<()> {
        let application = |table: &str| {
            public_security_tables()
                .into_iter()
                .any(|public| public.name() == table)
        };
        let payload = match postcard::from_bytes::<SyncMessage>(&frame) {
            Ok(SyncMessage::State(units)) => units.iter().any(|unit| {
                let ofdb_sql::SyncKey::Row { table, .. } = &unit.key;
                application(table)
            }),
            Ok(SyncMessage::Changes(changes)) => {
                changes.iter().any(|change| application(&change.table))
            }
            _ => false,
        };
        if payload {
            self.payloads.fetch_add(1, Ordering::SeqCst);
        }
        self.sender
            .send(frame)
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "test channel closed"))
    }

    async fn receive(&mut self) -> io::Result<Vec<u8>> {
        self.receiver
            .recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "test channel closed"))
    }
}

async fn source_to_joiner(
    source: &Database,
    joiner: &Database,
    root: &std::path::Path,
) -> (
    Result<ofdb_sql::SyncResult, String>,
    Result<ofdb_sql::SyncResult, String>,
    usize,
) {
    let (a_send, b_recv) = mpsc::unbounded_channel();
    let (b_send, a_recv) = mpsc::unbounded_channel();
    let joiner_payloads = Arc::new(AtomicUsize::new(0));
    let mut a = Channel {
        sender: a_send,
        receiver: a_recv,
        payloads: Arc::new(AtomicUsize::new(0)),
    };
    let mut b = Channel {
        sender: b_send,
        receiver: b_recv,
        payloads: joiner_payloads.clone(),
    };
    let tables = public_security_tables()
        .into_iter()
        .map(|table| table.name())
        .collect::<Vec<_>>();
    let validate = |table: &str, column: &str, value: &db::Value| {
        if public_security_tables()
            .into_iter()
            .any(|public| public.name() == table && public.permits_historical_value(column, value))
        {
            Ok(())
        } else {
            Err("invalid public history".into())
        }
    };
    let config = SessionConfig::default();
    let source_session = source
        .synchronize_tables_with_stage_directory_candidate_validated_checked(
            &mut a,
            &config,
            SyncRole::Initiator,
            root.join("source-stage"),
            &tables,
            validate,
            |view| {
                if view.direction == SyncValidationDirection::Incoming
                    && !view.candidates.is_empty()
                {
                    Err("bootstrap source must not import joining application history".into())
                } else {
                    Ok(())
                }
            },
            || async { Ok(()) },
        );
    let joiner_session = joiner
        .synchronize_tables_with_stage_directory_candidate_validated_checked(
            &mut b,
            &config,
            SyncRole::Responder,
            root.join("joining-stage"),
            &tables,
            validate,
            |view| {
                if view.direction == SyncValidationDirection::Outgoing
                    && !view.candidates.is_empty()
                {
                    Err("bootstrap joiner must not publish application history".into())
                } else {
                    Ok(())
                }
            },
            || async { Ok(()) },
        );
    let (a, b) = tokio::join!(source_session, joiner_session);
    (
        a.map_err(|error| error.to_string()),
        b.map_err(|error| error.to_string()),
        joiner_payloads.load(Ordering::SeqCst),
    )
}

#[tokio::test]
async fn bootstrap_receive_only_guard_allows_empty_import_but_blocks_native_retry() {
    tokio::time::timeout(Duration::from_secs(180), receive_only_retry())
        .await
        .expect("native owner sessions complete");
}

async fn receive_only_retry() {
    let root = std::env::temp_dir().join(format!("of-bootstrap-one-way-{}", Id::now_v7()));
    std::fs::create_dir_all(&root).expect("isolated native stores");
    let source = Database::open(root.join("source.redb")).expect("source public owner");
    let joiner = Database::open(root.join("joining.redb")).expect("empty joining owner");
    idp_model::replica::up(&source)
        .await
        .expect("source fixed schema");
    idp_model::replica::up(&joiner)
        .await
        .expect("joining fixed schema");
    let user = Id::now_v7();
    sql(&source, &format!("INSERT INTO users (id, handle, name, created_at, updated_at) VALUES (CAST('{user}' AS UUID), 'source-user', 'Public User', 1, 1)")).await;

    let (a, b, published) = source_to_joiner(&source, &joiner, &root).await;
    assert_eq!(
        published, 0,
        "empty joining owner publishes no application frames"
    );
    a.expect("first source session accepts catalog exchange but no joining application history");
    assert!(
        b.expect("empty joining owner receives public history")
            .received_units
            > 0
    );
    let source_before = source
        .sync_manifest()
        .await
        .expect("source after allowed catalog exchange");
    assert_eq!(
        sql(&joiner, "SELECT id, name FROM users").await[0].rows[0].values,
        vec![db::Value::Uuid(user), db::Value::Text("Public User".into())]
    );
    let joined_before = joiner
        .sync_manifest()
        .await
        .expect("durable joined progress");
    drop(joiner);
    let joiner = Database::open(root.join("joining.redb"))
        .expect("native reopen preserves imported history");
    let (a, b, published) = source_to_joiner(&source, &joiner, &root).await;
    assert_eq!(
        published, 0,
        "exact retry must not publish joining application frames"
    );
    assert!(
        a.expect_err("source observes denied reverse export preflight")
            .contains("bootstrap joiner must not publish application history")
    );
    assert!(
        b.expect_err("owner preflights retained receiver rows even on an exact retry")
            .contains("bootstrap joiner must not publish application history")
    );
    assert_eq!(
        joiner
            .sync_manifest()
            .await
            .expect("retry preserves progress"),
        joined_before
    );
    assert_eq!(
        source
            .sync_manifest()
            .await
            .expect("retry source unchanged"),
        source_before
    );
    let additional = Id::now_v7();
    sql(&source, &format!("INSERT INTO users (id, handle, name, created_at, updated_at) VALUES (CAST('{additional}' AS UUID), 'later-user', 'Later Public User', 2, 2)")).await;
    let source_updated = source.sync_manifest().await.expect("source new history");
    let (a, b, published) = source_to_joiner(&source, &joiner, &root).await;
    assert!(
        a.is_err() && b.is_err(),
        "retained partial bootstrap progress blocks further source imports too"
    );
    assert_eq!(
        published, 0,
        "resume cannot disclose arbitrary joining application history"
    );
    assert_eq!(
        joiner
            .sync_manifest()
            .await
            .expect("failed resume preserves retained progress"),
        joined_before
    );
    assert_eq!(
        source
            .sync_manifest()
            .await
            .expect("source new history retained on rejection"),
        source_updated
    );
    assert_eq!(
        sql(&joiner, "SELECT id FROM users").await[0].rows.len(),
        1,
        "failed resume imports no additional User or duplicate"
    );
    drop(joiner);
    drop(source);
    std::fs::remove_dir_all(root).expect("remove isolated owner test stores");
}
