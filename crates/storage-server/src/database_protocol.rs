use std::{future::Future, io, pin::Pin, sync::Arc, time::Duration};

use iroh::{
    EndpointId,
    endpoint::Connection,
    protocol::{AcceptError, ProtocolHandler},
};
use iroh_chain::{DATA_ALPN, Server};
use model::contract::SelectedResource;
use ofdb_sql::{IrohTransport, SessionConfig, SyncRole, SyncTransport};
use serde::{Deserialize, Serialize};
use storage_model::StorageNamespace;
use storage_service::{DatabaseId, DatabaseRuntime};

use crate::{ManagementClient, data_protocol::DATABASE_STREAM_KIND, sync_timeout};

type FrameAuthorizer = Arc<dyn Fn() -> Pin<Box<dyn Future<Output = bool> + Send>> + Send + Sync>;

const MAX_HANDSHAKE_BYTES: usize = 4096;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const POLICY_CHECK_TIMEOUT: Duration = Duration::from_secs(10);
const SYNC_OPERATION_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_SYNC_FRAME_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct DatabaseResourceDescriptor {
    pub(crate) owner_subject: String,
    pub(crate) application_id: String,
    pub(crate) database_id: String,
}

#[derive(Deserialize, Serialize)]
struct DatabaseSyncHandshake {
    resource: DatabaseResourceDescriptor,
    deleted: bool,
}

#[derive(Clone)]
pub(crate) struct DatabaseProtocolHandler {
    server: Server,
    management: ManagementClient,
    databases: Arc<DatabaseRuntime>,
}

impl DatabaseProtocolHandler {
    pub(crate) fn new(
        server: Server,
        management: ManagementClient,
        databases: Arc<DatabaseRuntime>,
    ) -> Self {
        Self {
            server,
            management,
            databases,
        }
    }

    pub(crate) async fn synchronize_selected_peers(&self) {
        let local_public_key = self.server.endpoint().id().to_string();
        let selected = match self.management.selected_resources(&local_public_key).await {
            Ok(response) => response.resources,
            Err(error) => {
                log::warn!("failed to list selected databases: {error}");
                return;
            }
        };
        for peer in self.server.peers().ids() {
            let remote_public_key = peer.to_string();
            if local_public_key >= remote_public_key {
                continue;
            }
            for resource in selected
                .iter()
                .filter(|resource| resource.kind == "database")
            {
                let descriptor = descriptor(resource);
                if let Err(error) = self.synchronize_peer(peer, descriptor).await {
                    log::debug!("database sync with {remote_public_key} failed: {error}");
                }
            }
        }
    }

    pub(crate) async fn synchronize_peer(
        &self,
        peer: EndpointId,
        resource: DatabaseResourceDescriptor,
    ) -> io::Result<()> {
        let connection = tokio::time::timeout(
            HANDSHAKE_TIMEOUT,
            self.server.connect_direct_with_alpn(peer, DATA_ALPN),
        )
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "database sync connection timed out",
            )
        })?
        .map_err(io::Error::other)?;
        if !self.authorize_bounded(&resource, &connection).await {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "database resource is not authorized for sync",
            ));
        }
        let database_id = resource
            .database_id
            .parse::<DatabaseId>()
            .map_err(io::Error::other)?;
        let application_id = resource.application_id.parse().map_err(io::Error::other)?;
        let namespace = Namespace {
            owner_subject: resource.owner_subject.clone(),
            application_id,
        };
        let deleted = self.databases.is_tombstoned(&namespace, database_id)?;
        let (send, recv) = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
            let (mut send, mut recv) = connection.open_bi().await.map_err(io::Error::other)?;
            send.write_all(&[DATABASE_STREAM_KIND])
                .await
                .map_err(io::Error::other)?;
            write_frame(
                &mut send,
                &serde_json::to_vec(&DatabaseSyncHandshake {
                    resource: resource.clone(),
                    deleted,
                })
                .map_err(io::Error::other)?,
            )
            .await?;
            if read_frame(&mut recv, MAX_HANDSHAKE_BYTES).await? != b"OK" {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid database sync acknowledgement",
                ));
            }
            Ok::<_, io::Error>((send, recv))
        })
        .await
        .map_err(|_| {
            io::Error::new(io::ErrorKind::TimedOut, "database sync handshake timed out")
        })??;

        if deleted {
            return Ok(());
        }
        let database = self
            .databases
            .open(&namespace, database_id)
            .map_err(io::Error::other)?
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "database resource not found")
            })?;
        let kv_store = self
            .databases
            .open_kv_selected(&namespace, database_id)
            .map_err(io::Error::other)?
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "database KV store not found")
            })?;
        let handler = self.clone();
        let resource_for_guard = resource.clone();
        let authorize: FrameAuthorizer = Arc::new(move || {
            let handler = handler.clone();
            let resource = resource_for_guard.clone();
            let connection = connection.clone();
            Box::pin(async move { handler.authorize_bounded(&resource, &connection).await })
        });
        let mut transport = AuthorizedTransport {
            transport: IrohTransport::new(send, recv),
            authorize,
        };
        sync_timeout::run(
            SYNC_OPERATION_TIMEOUT,
            "database sync operation timed out",
            async {
                database
                    .synchronize(
                        &mut transport,
                        &SessionConfig::default(),
                        SyncRole::Initiator,
                    )
                    .await
                    .map_err(io::Error::other)?;
                ofdb_kv_sync::synchronize(
                    &kv_store,
                    &mut KvAuthorizedTransport {
                        transport: &mut transport,
                    },
                    ofdb_kv_sync::SyncRole::Initiator,
                    ofdb_kv_sync::Config {
                        max_frame_bytes: MAX_SYNC_FRAME_BYTES,
                        ..ofdb_kv_sync::Config::default()
                    },
                )
                .await
                .map_err(|error| io::Error::other(format!("database KV sync failed: {error:?}")))
            },
        )
        .await?;
        Ok(())
    }

    async fn authorize_bounded(
        &self,
        resource: &DatabaseResourceDescriptor,
        connection: &Connection,
    ) -> bool {
        authorize_with_timeout(POLICY_CHECK_TIMEOUT, self.authorize(resource, connection)).await
    }

    async fn authorize(
        &self,
        resource: &DatabaseResourceDescriptor,
        connection: &Connection,
    ) -> bool {
        if resource
            .application_id
            .parse::<idp_model::model::Id>()
            .is_err()
            || resource.database_id.parse::<DatabaseId>().is_err()
        {
            return false;
        }
        if resource.owner_subject.trim().is_empty() {
            return false;
        }
        let local_endpoint_id = self.server.endpoint().id().to_string();
        let Ok(selected) = self.management.selected_resources(&local_endpoint_id).await else {
            return false;
        };
        if !selected
            .resources
            .iter()
            .any(|candidate| descriptor_matches_selection(resource, candidate))
        {
            return false;
        }
        self.management
            .admit_peer_replication(
                &self.server,
                connection,
                &resource.application_id,
                "database",
                &resource.database_id,
            )
            .await
            .is_ok()
    }
}

fn descriptor_matches_selection(
    descriptor: &DatabaseResourceDescriptor,
    selected: &SelectedResource,
) -> bool {
    selected.owner_subject == descriptor.owner_subject
        && selected.application_id == descriptor.application_id
        && selected.kind == "database"
        && selected.resource_id == descriptor.database_id
}

impl core::fmt::Debug for DatabaseProtocolHandler {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("DatabaseProtocolHandler")
            .finish_non_exhaustive()
    }
}

impl DatabaseProtocolHandler {
    pub(crate) async fn accept_stream(
        &self,
        connection: Connection,
        mut send: iroh::endpoint::SendStream,
        mut recv: iroh::endpoint::RecvStream,
    ) {
        let handshake =
            match tokio::time::timeout(HANDSHAKE_TIMEOUT, read_handshake(&mut recv)).await {
                Ok(Ok(handshake)) => handshake,
                Ok(Err(error)) => {
                    log::warn!("rejected database sync handshake: {error}");
                    return;
                }
                Err(_) => {
                    log::warn!("rejected database sync handshake: timed out");
                    return;
                }
            };
        if !self
            .authorize_bounded(&handshake.resource, &connection)
            .await
        {
            log::warn!("rejected unauthorized database sync stream");
            return;
        }
        let Ok(application_id) = handshake.resource.application_id.parse() else {
            return;
        };
        let Ok(database_id) = handshake.resource.database_id.parse::<DatabaseId>() else {
            return;
        };
        let namespace = Namespace {
            owner_subject: handshake.resource.owner_subject.clone(),
            application_id,
        };
        if handshake.deleted {
            if let Err(error) = self.databases.apply_tombstone(&namespace, database_id) {
                log::warn!("failed to apply database tombstone: {error}");
                return;
            }
            if let Err(error) = write_frame(&mut send, b"OK").await {
                log::warn!("failed to acknowledge database tombstone: {error}");
            }
            return;
        }
        let Some(database) = self
            .databases
            .open_selected(&namespace, database_id)
            .ok()
            .flatten()
        else {
            return;
        };
        let Some(kv_store) = self
            .databases
            .open_kv_selected(&namespace, database_id)
            .ok()
            .flatten()
        else {
            return;
        };
        if let Err(error) = write_frame(&mut send, b"OK").await {
            log::warn!("failed to acknowledge database sync stream: {error}");
            return;
        }
        let handler = self.clone();
        tokio::spawn(async move {
            let resource_for_guard = handshake.resource.clone();
            let authorize: FrameAuthorizer = Arc::new(move || {
                let handler = handler.clone();
                let resource = resource_for_guard.clone();
                let connection = connection.clone();
                Box::pin(async move { handler.authorize_bounded(&resource, &connection).await })
            });
            let mut transport = AuthorizedTransport {
                transport: IrohTransport::new(send, recv),
                authorize,
            };
            let result = sync_timeout::run(
                SYNC_OPERATION_TIMEOUT,
                "database sync operation timed out",
                async {
                    database
                        .synchronize(
                            &mut transport,
                            &SessionConfig::default(),
                            SyncRole::Responder,
                        )
                        .await
                        .map_err(io::Error::other)?;
                    ofdb_kv_sync::synchronize(
                        &kv_store,
                        &mut KvAuthorizedTransport {
                            transport: &mut transport,
                        },
                        ofdb_kv_sync::SyncRole::Responder,
                        ofdb_kv_sync::Config {
                            max_frame_bytes: MAX_SYNC_FRAME_BYTES,
                            ..ofdb_kv_sync::Config::default()
                        },
                    )
                    .await
                    .map_err(|error| {
                        io::Error::other(format!("database KV sync failed: {error:?}"))
                    })
                },
            )
            .await;
            match result {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::TimedOut => {
                    log::warn!("database sync operation timed out")
                }
                Err(error) => log::warn!("database sync session ended: {error}"),
            }
        });
    }
}

impl ProtocolHandler for DatabaseProtocolHandler {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        loop {
            let (send, mut recv) = connection.accept_bi().await?;
            let mut kind = [0; 1];
            if !matches!(
                tokio::time::timeout(HANDSHAKE_TIMEOUT, recv.read_exact(&mut kind)).await,
                Ok(Ok(()))
            ) {
                continue;
            }
            if kind[0] != DATABASE_STREAM_KIND {
                continue;
            }
            self.accept_stream(connection.clone(), send, recv).await;
        }
    }
}

async fn authorize_with_timeout<F>(timeout: Duration, authorization: F) -> bool
where
    F: Future<Output = bool>,
{
    tokio::time::timeout(timeout, authorization)
        .await
        .unwrap_or(false)
}

fn descriptor(resource: &SelectedResource) -> DatabaseResourceDescriptor {
    DatabaseResourceDescriptor {
        owner_subject: resource.owner_subject.clone(),
        application_id: resource.application_id.clone(),
        database_id: resource.resource_id.clone(),
    }
}

struct AuthorizedTransport<T = IrohTransport> {
    transport: T,
    authorize: FrameAuthorizer,
}

struct KvAuthorizedTransport<'a> {
    transport: &'a mut AuthorizedTransport,
}

impl ofdb_kv_sync::SyncTransport for KvAuthorizedTransport<'_> {
    type Error = io::Error;

    async fn receive(&mut self) -> Result<Vec<u8>, Self::Error> {
        self.transport.receive().await
    }

    async fn send(&mut self, frame: Vec<u8>) -> Result<(), Self::Error> {
        self.transport.send(frame).await
    }
}

impl<T> SyncTransport for AuthorizedTransport<T>
where
    T: SyncTransport<Error = io::Error>,
{
    type Error = io::Error;

    async fn receive(&mut self) -> Result<Vec<u8>, Self::Error> {
        if !(self.authorize)().await {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "database sync access revoked",
            ));
        }
        let frame = self.transport.receive().await?;
        if !(self.authorize)().await {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "database sync access revoked",
            ));
        }
        Ok(frame)
    }

    async fn send(&mut self, frame: Vec<u8>) -> Result<(), Self::Error> {
        if !(self.authorize)().await {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "database sync access revoked",
            ));
        }
        self.transport.send(frame).await
    }
}

async fn read_handshake(
    recv: &mut iroh::endpoint::RecvStream,
) -> io::Result<DatabaseSyncHandshake> {
    let frame = read_frame(recv, MAX_HANDSHAKE_BYTES).await?;
    serde_json::from_slice(&frame).map_err(io::Error::other)
}

async fn read_frame(recv: &mut iroh::endpoint::RecvStream, max: usize) -> io::Result<Vec<u8>> {
    let mut length = [0; 4];
    recv.read_exact(&mut length)
        .await
        .map_err(io::Error::other)?;
    let length = u32::from_be_bytes(length) as usize;
    if length > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "database sync handshake too large",
        ));
    }
    let mut frame = vec![0; length];
    recv.read_exact(&mut frame)
        .await
        .map_err(io::Error::other)?;
    Ok(frame)
}

async fn write_frame(send: &mut iroh::endpoint::SendStream, frame: &[u8]) -> io::Result<()> {
    if frame.len() > MAX_HANDSHAKE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "database sync handshake too large",
        ));
    }
    send.write_all(&(frame.len() as u32).to_be_bytes())
        .await
        .map_err(io::Error::other)?;
    send.write_all(frame).await.map_err(io::Error::other)
}

struct Namespace {
    owner_subject: String,
    application_id: idp_model::model::Id,
}

impl StorageNamespace for Namespace {
    fn user_sub(&self) -> &str {
        &self.owner_subject
    }
    fn application_id(&self) -> idp_model::model::Id {
        self.application_id
    }
}

#[cfg(test)]
#[path = "database_protocol_tests.rs"]
mod tests;

#[cfg(test)]
mod authorization_tests {
    use model::contract::SelectedResource;

    use super::{DatabaseResourceDescriptor, descriptor_matches_selection};

    fn descriptor() -> DatabaseResourceDescriptor {
        DatabaseResourceDescriptor {
            owner_subject: "owner-a".to_owned(),
            application_id: "app-a".to_owned(),
            database_id: "db-a".to_owned(),
        }
    }

    fn selection() -> SelectedResource {
        SelectedResource {
            owner_subject: "owner-a".to_owned(),
            application_id: "app-a".to_owned(),
            kind: "database".to_owned(),
            resource_id: "db-a".to_owned(),
        }
    }

    #[test]
    fn accepts_only_exact_management_selection() {
        let descriptor = descriptor();
        let selection = selection();
        assert!(descriptor_matches_selection(&descriptor, &selection));

        let mut spoofed_descriptor = descriptor.clone();
        spoofed_descriptor.owner_subject = "owner-b".to_owned();
        assert!(!descriptor_matches_selection(
            &spoofed_descriptor,
            &selection
        ));
        let mut spoofed_descriptor = descriptor.clone();
        spoofed_descriptor.application_id = "app-b".to_owned();
        assert!(!descriptor_matches_selection(
            &spoofed_descriptor,
            &selection
        ));
        let mut spoofed_descriptor = descriptor.clone();
        spoofed_descriptor.database_id = "db-b".to_owned();
        assert!(!descriptor_matches_selection(
            &spoofed_descriptor,
            &selection
        ));

        let mut spoofed = selection.clone();
        spoofed.owner_subject = "owner-b".to_owned();
        assert!(!descriptor_matches_selection(&descriptor, &spoofed));
        let mut spoofed = selection.clone();
        spoofed.application_id = "app-b".to_owned();
        assert!(!descriptor_matches_selection(&descriptor, &spoofed));
        let mut spoofed = selection.clone();
        spoofed.kind = "filesystem".to_owned();
        assert!(!descriptor_matches_selection(&descriptor, &spoofed));
        let mut spoofed = selection;
        spoofed.resource_id = "db-b".to_owned();
        assert!(!descriptor_matches_selection(&descriptor, &spoofed));
    }
}
