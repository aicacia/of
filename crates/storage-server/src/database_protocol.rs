use std::{future::Future, io, path::PathBuf, pin::Pin, sync::Arc};

use iroh::{
    EndpointId,
    endpoint::Connection,
    protocol::{AcceptError, ProtocolHandler},
};
use iroh_chain::{DATA_ALPN, Server};
use model::contract::SelectedResource;
use ofdb_sql::{SessionConfig, SyncRole, SyncTransport};
use serde::{Deserialize, Serialize};
use storage_model::StorageNamespace;
use storage_service::{DatabaseId, DatabaseRuntime};
use tokio_util::sync::CancellationToken;

use crate::{
    ManagementClient, data_protocol::DATABASE_STREAM_KIND, database_transport::DatabaseTransport,
};

type FrameAuthorizer = Arc<dyn Fn() -> Pin<Box<dyn Future<Output = bool> + Send>> + Send + Sync>;
const MAX_HANDSHAKE_BYTES: usize = 4096;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DatabaseResourceDescriptor {
    pub(crate) owner_subject: String,
    pub(crate) application_id: String,
    pub(crate) database_id: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DatabaseSyncHandshake {
    resource: DatabaseResourceDescriptor,
    deleted: bool,
}

#[derive(Clone)]
pub(crate) struct DatabaseProtocolHandler {
    server: Server,
    management: ManagementClient,
    databases: Arc<DatabaseRuntime>,
    staging_directory: PathBuf,
    cancellation_token: CancellationToken,
}

impl DatabaseProtocolHandler {
    pub(crate) fn new(
        server: Server,
        management: ManagementClient,
        databases: Arc<DatabaseRuntime>,
        staging_directory: PathBuf,
        cancellation_token: CancellationToken,
    ) -> Self {
        Self {
            server,
            management,
            databases,
            staging_directory,
            cancellation_token,
        }
    }

    pub(crate) async fn synchronize_selected_peers(&self) {
        let Some(local) = self.management.local_replication_authorizer() else {
            return;
        };
        let Ok(selected) = local.selected_resources(self.server.endpoint().id()).await else {
            return;
        };
        for peer in self.server.peers().ids() {
            if self.server.endpoint().id().to_string() >= peer.to_string() {
                continue;
            }
            for resource in selected
                .iter()
                .filter(|resource| resource.kind == "database")
            {
                if let Err(error) = self.synchronize_peer(peer, descriptor(resource)).await {
                    log::debug!("database sync with {peer} failed: {error}");
                }
            }
        }
    }

    pub(crate) async fn synchronize_peer(
        &self,
        peer: EndpointId,
        resource: DatabaseResourceDescriptor,
    ) -> io::Result<()> {
        tokio::select! {
            biased;
            () = self.cancellation_token.cancelled() => Err(io::Error::new(io::ErrorKind::Interrupted, "database sync cancelled")),
            result = self.synchronize_peer_active(peer, resource) => result,
        }
    }

    async fn synchronize_peer_active(
        &self,
        peer: EndpointId,
        resource: DatabaseResourceDescriptor,
    ) -> io::Result<()> {
        let connection = self
            .server
            .connect_direct_with_alpn(peer, DATA_ALPN)
            .await
            .map_err(io::Error::other)?;
        self.require_authorized(&resource, &connection).await?;
        let database_id = resource
            .database_id
            .parse::<DatabaseId>()
            .map_err(io::Error::other)?;
        let namespace = Namespace {
            owner_subject: resource.owner_subject.clone(),
            application_id: resource.application_id.parse().map_err(io::Error::other)?,
        };
        let deleted = self.databases.is_tombstoned(&namespace, database_id)?;
        let (mut send, mut recv) = connection.open_bi().await.map_err(io::Error::other)?;
        self.require_authorized(&resource, &connection).await?;
        send.write_all(&[DATABASE_STREAM_KIND])
            .await
            .map_err(io::Error::other)?;
        self.require_authorized(&resource, &connection).await?;
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
        if deleted {
            return Ok(());
        }
        self.exchange(connection, resource, send, recv, SyncRole::Initiator)
            .await
    }

    async fn authorize(
        &self,
        resource: &DatabaseResourceDescriptor,
        connection: &Connection,
    ) -> bool {
        if self.cancellation_token.is_cancelled() {
            return false;
        }
        let Some(local) = self.management.local_replication_authorizer() else {
            return false;
        };
        local
            .authorize(
                self.server.endpoint().id(),
                connection.remote_id(),
                &SelectedResource {
                    owner_subject: resource.owner_subject.clone(),
                    application_id: resource.application_id.clone(),
                    kind: "database".into(),
                    resource_id: resource.database_id.clone(),
                },
            )
            .await
    }

    async fn require_authorized(
        &self,
        resource: &DatabaseResourceDescriptor,
        connection: &Connection,
    ) -> io::Result<()> {
        if self.authorize(resource, connection).await {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "database resource is not locally authorized",
            ))
        }
    }

    pub(crate) async fn accept_stream(
        &self,
        connection: Connection,
        mut send: iroh::endpoint::SendStream,
        mut recv: iroh::endpoint::RecvStream,
    ) {
        let result = tokio::select! {
            biased;
            () = self.cancellation_token.cancelled() => return,
            result = async {
                let handshake: DatabaseSyncHandshake = serde_json::from_slice(&read_frame(&mut recv, MAX_HANDSHAKE_BYTES).await?).map_err(io::Error::other)?;
                self.require_authorized(&handshake.resource, &connection).await?;
                let database_id = handshake.resource.database_id.parse::<DatabaseId>().map_err(io::Error::other)?;
                let namespace = Namespace { owner_subject: handshake.resource.owner_subject.clone(), application_id: handshake.resource.application_id.parse().map_err(io::Error::other)? };
                if handshake.deleted {
                    self.require_authorized(&handshake.resource, &connection).await?;
                    self.databases.apply_tombstone(&namespace, database_id)?;
                    self.require_authorized(&handshake.resource, &connection).await?;
                    return write_frame(&mut send, b"OK").await;
                }
                self.require_authorized(&handshake.resource, &connection).await?;
                write_frame(&mut send, b"OK").await?;
                self.exchange(connection, handshake.resource, send, recv, SyncRole::Responder).await
            } => result,
        };
        if let Err(error) = result {
            log::debug!("database sync session ended: {error}");
        }
    }

    async fn exchange(
        &self,
        connection: Connection,
        resource: DatabaseResourceDescriptor,
        send: iroh::endpoint::SendStream,
        recv: iroh::endpoint::RecvStream,
        role: SyncRole,
    ) -> io::Result<()> {
        self.require_authorized(&resource, &connection).await?;
        let database_id = resource
            .database_id
            .parse::<DatabaseId>()
            .map_err(io::Error::other)?;
        let namespace = Namespace {
            owner_subject: resource.owner_subject.clone(),
            application_id: resource.application_id.parse().map_err(io::Error::other)?,
        };
        let database = self
            .databases
            .open_selected(&namespace, database_id)?
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "database resource not found")
            })?;
        self.require_authorized(&resource, &connection).await?;
        let kv = self
            .databases
            .open_kv_selected(&namespace, database_id)?
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "database KV resource not found")
            })?;
        let handler = self.clone();
        let authorize: FrameAuthorizer = Arc::new(move || {
            let handler = handler.clone();
            let resource = resource.clone();
            let connection = connection.clone();
            Box::pin(async move { handler.authorize(&resource, &connection).await })
        });
        let mut transport = AuthorizedTransport {
            transport: DatabaseTransport::new(send, recv),
            authorize: authorize.clone(),
        };
        database
            .synchronize_with_stage_directory_checked(
                &mut transport,
                &SessionConfig::default(),
                role,
                &self.staging_directory,
                || check_apply(authorize.clone(), self.cancellation_token.clone()),
            )
            .await
            .map_err(sql_sync_error)?;
        kv.synchronize_checked(
            &mut KvAuthorizedTransport {
                transport: &mut transport,
            },
            match role {
                SyncRole::Initiator => ofdb_kv::SyncRole::Initiator,
                SyncRole::Responder => ofdb_kv::SyncRole::Responder,
            },
            ofdb_kv::SyncConfig::default(),
            || check_apply(authorize.clone(), self.cancellation_token.clone()),
        )
        .await
        .map_err(kv_sync_error)
    }
}

impl core::fmt::Debug for DatabaseProtocolHandler {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DatabaseProtocolHandler")
            .finish_non_exhaustive()
    }
}

impl ProtocolHandler for DatabaseProtocolHandler {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        loop {
            let (send, mut recv) = tokio::select! {
                () = self.cancellation_token.cancelled() => return Ok(()),
                result = connection.accept_bi() => result?,
            };
            let mut kind = [0];
            tokio::select! {
                () = self.cancellation_token.cancelled() => return Ok(()),
                result = recv.read_exact(&mut kind) => if result.is_err() { continue; },
            }
            if kind[0] == DATABASE_STREAM_KIND {
                self.accept_stream(connection.clone(), send, recv).await;
            }
        }
    }
}

fn descriptor(resource: &SelectedResource) -> DatabaseResourceDescriptor {
    DatabaseResourceDescriptor {
        owner_subject: resource.owner_subject.clone(),
        application_id: resource.application_id.clone(),
        database_id: resource.resource_id.clone(),
    }
}

struct AuthorizedTransport<T = DatabaseTransport> {
    transport: T,
    authorize: FrameAuthorizer,
}
struct KvAuthorizedTransport<'a> {
    transport: &'a mut AuthorizedTransport,
}
impl ofdb_kv::SyncTransport for KvAuthorizedTransport<'_> {
    type Error = io::Error;
    async fn receive(&mut self) -> io::Result<Vec<u8>> {
        self.transport.receive().await
    }
    async fn send(&mut self, frame: Vec<u8>) -> io::Result<()> {
        self.transport.send(frame).await
    }
}
impl<T: SyncTransport<Error = io::Error>> SyncTransport for AuthorizedTransport<T> {
    type Error = io::Error;
    async fn receive(&mut self) -> io::Result<Vec<u8>> {
        require_frame(&self.authorize).await?;
        let frame = self.transport.receive().await?;
        require_frame(&self.authorize).await?;
        Ok(frame)
    }
    async fn send(&mut self, frame: Vec<u8>) -> io::Result<()> {
        require_frame(&self.authorize).await?;
        self.transport.send(frame).await
    }
}
async fn require_frame(authorize: &FrameAuthorizer) -> io::Result<()> {
    if authorize().await {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "database sync access revoked",
        ))
    }
}
async fn check_apply(
    authorize: FrameAuthorizer,
    cancellation: CancellationToken,
) -> Result<(), String> {
    let permitted = tokio::select! { biased;
        () = cancellation.cancelled() => return Err("database sync cancelled".into()),
        permitted = authorize() => permitted,
    };
    if cancellation.is_cancelled() {
        Err("database sync cancelled".into())
    } else if permitted {
        Ok(())
    } else {
        Err("database sync access revoked before apply".into())
    }
}
fn sql_sync_error(error: ofdb_sql::SyncError<io::Error>) -> io::Error {
    match error {
        ofdb_sql::SyncError::PreApply(detail) => {
            io::Error::new(io::ErrorKind::PermissionDenied, detail)
        }
        error => io::Error::other(error),
    }
}
fn kv_sync_error(error: ofdb_kv::SyncError<io::Error>) -> io::Error {
    match error {
        ofdb_kv::SyncError::PreApply(detail) => {
            io::Error::new(io::ErrorKind::PermissionDenied, detail)
        }
        error => io::Error::other(format!("database KV sync failed: {error:?}")),
    }
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
#[path = "database_execution_tests.rs"]
mod execution_tests;

#[cfg(test)]
#[path = "database_protocol_tests.rs"]
mod tests;
