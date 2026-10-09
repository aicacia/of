use std::sync::Arc;

use file_system::{
    FileHandle, FileOperation, FileSessionService, FileSystemId, MAX_FILE_READ_LENGTH, OpenRequest,
    OperationControl, RemoteOperation, Residency,
};
use iroh::{
    EndpointId,
    endpoint::{Connection, RecvStream, SendStream},
    protocol::{AcceptError, ProtocolHandler},
};
use iroh_chain::{DATA_ALPN, Server};
use model::contract::SelectedResource;
use storage_model::StorageNamespace;
use storage_service::ScopedFileSystemRuntime;
use tokio_util::sync::CancellationToken;

use crate::{
    ManagementClient,
    filesystem_transport::{FILESYSTEM_STREAM_KIND, IrohFileTransport, IrohResourceDescriptor},
};

#[derive(Clone)]
pub(crate) struct StorageProtocolHandler {
    server: Server,
    management: ManagementClient,
    file_systems: Arc<ScopedFileSystemRuntime<EndpointId>>,
    cancellation_token: CancellationToken,
}

impl StorageProtocolHandler {
    pub(crate) fn new(
        server: Server,
        management: ManagementClient,
        file_systems: Arc<ScopedFileSystemRuntime<EndpointId>>,
        cancellation_token: CancellationToken,
    ) -> Self {
        Self {
            server,
            management,
            file_systems,
            cancellation_token,
        }
    }

    pub(crate) fn install_passthrough_reader(&self) -> Result<(), String> {
        let files = Arc::downgrade(&self.file_systems);
        let server = self.server.clone();
        let management = self.management.clone();
        let cancellation = self.cancellation_token.clone();
        self.file_systems.set_content_reader(move |owner, app, id, path| {
            let files = files.clone(); let server = server.clone(); let management = management.clone(); let cancellation_token = cancellation.clone();
            async move {
                let handler = Self { server, management, file_systems: files.upgrade().ok_or("Storage runtime is unavailable")?, cancellation_token };
                let resource = IrohResourceDescriptor { owner_subject: owner, application_id: app.to_string(), filesystem_id: id.as_uuid().to_string() };
                let mut failure = "no configured peers".to_owned();
                for peer in handler.server.peers().ids() {
                    let connected = tokio::select! { () = handler.cancellation_token.cancelled() => return Err("Storage is shutting down".into()), result = handler.server.connect_direct_with_alpn(peer, DATA_ALPN) => result };
                    let connection = match connected { Ok(connection) => connection, Err(error) => { failure = format!("peer connection failed: {error}"); continue; } };
                    match handler.read_remote_connection(&connection, resource.clone(), &path).await { Ok(content) => return Ok(content), Err(error) => failure = format!("peer content denied/unavailable: {error}") }
                }
                Err(format!("no authorized reachable Full peer supplies this content: {failure}"))
            }
        })
    }

    pub(crate) async fn read_remote_connection(
        &self,
        connection: &Connection,
        resource: IrohResourceDescriptor,
        path: &str,
    ) -> std::io::Result<Vec<u8>> {
        self.require_authorized(&resource, connection).await?;
        let handler = self.clone();
        let peer_connection = connection.clone();
        let transport = IrohFileTransport::open_authorized(connection, resource, move |resource| {
            let handler = handler.clone();
            let connection = peer_connection.clone();
            async move { handler.authorize(&resource, &connection).await }
        })
        .await?;
        let mut handle = transport
            .open(
                connection.remote_id(),
                OpenRequest {
                    path: path.to_owned(),
                    revision: None,
                },
            )
            .await
            .map_err(|error| {
                std::io::Error::new(
                    error.kind(),
                    format!("Passthrough peer Open failed: {error}"),
                )
            })?;
        let mut content = Vec::new();
        let mut offset = 0_u64;
        loop {
            let bytes = tokio::select! { () = self.cancellation_token.cancelled() => return Err(std::io::Error::new(std::io::ErrorKind::Interrupted, "Storage is shutting down")), result = handle.read(offset, MAX_FILE_READ_LENGTH) => result.map_err(|error| std::io::Error::new(error.kind(), format!("Passthrough peer Read at {offset} failed: {error}")))? };
            if bytes.is_empty() {
                break;
            }
            offset = offset
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| std::io::Error::other("content offset overflow"))?;
            content.extend_from_slice(&bytes);
        }
        Box::new(handle).close().await?;
        transport.close();
        Ok(content)
    }

    pub(crate) async fn synchronize_selected_peers(&self) {
        let Some(local) = self.management.local_replication_authorizer() else {
            return;
        };
        let Ok(selected) = local.selected_resources(self.server.endpoint().id()).await else {
            return;
        };
        let selected_filesystems = selected
            .iter()
            .filter(|resource| resource.kind == "filesystem")
            .filter_map(|resource| {
                Some((
                    resource.owner_subject.clone(),
                    resource.application_id.parse().ok()?,
                    FileSystemId::parse(&resource.resource_id).ok()?,
                ))
            })
            .collect::<Vec<_>>();
        if let Err(error) = self
            .file_systems
            .remove_unselected_projected_resources(&selected_filesystems)
            .await
        {
            log::warn!("failed to evict deselected filesystem copies: {error}");
        }
        for peer in self.server.peers().ids() {
            if self.server.endpoint().id().to_string() >= peer.to_string() {
                continue;
            }
            for resource in selected
                .iter()
                .filter(|resource| resource.kind == "filesystem")
            {
                if let Err(error) = self.synchronize_peer(peer, descriptor(resource)).await {
                    log::debug!("filesystem sync with {peer} failed: {error}");
                }
            }
        }
    }

    async fn synchronize_peer(
        &self,
        peer: EndpointId,
        resource: IrohResourceDescriptor,
    ) -> std::io::Result<()> {
        let connection = tokio::select! {
            () = self.cancellation_token.cancelled() => return Ok(()),
            result = self.server.connect_direct_with_alpn(peer, DATA_ALPN) => result.map_err(std::io::Error::other)?,
        };
        self.require_authorized(&resource, &connection).await?;
        let namespace = Namespace {
            owner_subject: resource.owner_subject.clone(),
            application_id: resource
                .application_id
                .parse()
                .map_err(std::io::Error::other)?,
        };
        let filesystem_id =
            FileSystemId::parse(&resource.filesystem_id).map_err(std::io::Error::other)?;
        let deleted = self
            .file_systems
            .is_tombstoned(&namespace, filesystem_id)
            .await
            .map_err(std::io::Error::other)?;
        let control = self.operation_control(resource.clone(), connection.clone());
        let handler = self.clone();
        let connection_for_guard = connection.clone();
        let authorize = move |resource| {
            let handler = handler.clone();
            let connection = connection_for_guard.clone();
            async move { handler.authorize(&resource, &connection).await }
        };
        let transport = tokio::select! {
            () = self.cancellation_token.cancelled() => return Ok(()),
            result = async {
                if deleted { IrohFileTransport::open_tombstone_authorized(&connection, resource.clone(), authorize).await }
                else { IrohFileTransport::open_authorized(&connection, resource.clone(), authorize).await }
            } => result?,
        };
        if deleted {
            transport.close();
            return Ok(());
        }
        self.require_authorized(&resource, &connection).await?;
        let file_system = self
            .file_systems
            .open_resource(&namespace, filesystem_id)
            .await
            .map_err(std::io::Error::other)?;
        self.run_sync(file_system, transport, control).await
    }

    async fn run_sync(
        &self,
        file_system: Arc<file_system::FileSystem<EndpointId>>,
        transport: IrohFileTransport,
        control: OperationControl<EndpointId>,
    ) -> std::io::Result<()> {
        let sync = file_system
            .metadata_sync(transport)
            .with_operation_control(control.clone());
        let run = sync.run();
        tokio::pin!(run);
        tokio::select! {
            result = &mut run => result.map_err(std::io::Error::other),
            () = self.cancellation_token.cancelled() => {
                control.cancel();
                run.await.map_err(std::io::Error::other)
            }
        }
    }

    pub(crate) async fn accept_stream(
        &self,
        connection: Connection,
        send: SendStream,
        recv: RecvStream,
    ) {
        let handler = self.clone();
        let connection_for_guard = connection.clone();
        let accepted = tokio::select! {
            () = self.cancellation_token.cancelled() => return,
            result = IrohFileTransport::accept_authorized_after_marker(&connection, send, recv, move |resource| {
                let handler = handler.clone();
                let connection = connection_for_guard.clone();
                async move { handler.authorize(&resource, &connection).await }
            }) => result,
        };
        let (transport, resource, deleted) = match accepted {
            Ok(accepted) => accepted,
            Err(error) => {
                log::debug!("rejected filesystem sync stream: {error}");
                return;
            }
        };
        let result = async {
            let namespace = Namespace {
                owner_subject: resource.owner_subject.clone(),
                application_id: resource
                    .application_id
                    .parse()
                    .map_err(std::io::Error::other)?,
            };
            let filesystem_id =
                FileSystemId::parse(&resource.filesystem_id).map_err(std::io::Error::other)?;
            self.require_authorized(&resource, &connection).await?;
            if deleted {
                self.file_systems
                    .apply_deletion_tombstone(&namespace, filesystem_id)
                    .await
                    .map_err(std::io::Error::other)?;
                transport.close();
                return Ok(());
            }
            self.file_systems
                .register_selected_resource(&namespace, filesystem_id)
                .await
                .map_err(std::io::Error::other)?;
            self.require_authorized(&resource, &connection).await?;
            let filesystem = self
                .file_systems
                .open_resource(&namespace, filesystem_id)
                .await
                .map_err(std::io::Error::other)?;
            let control = self.operation_control(resource, connection);
            self.run_sync(filesystem, transport, control).await
        }
        .await;
        if let Err(error) = result {
            log::debug!("filesystem sync session ended: {error}");
        }
    }

    fn operation_control(
        &self,
        resource: IrohResourceDescriptor,
        connection: Connection,
    ) -> OperationControl<EndpointId> {
        let handler = self.clone();
        OperationControl::new(move |peer, operation| {
            let handler = handler.clone();
            let resource = resource.clone();
            let connection = connection.clone();
            Box::pin(async move {
                if peer != connection.remote_id()
                    || !handler.authorize(&resource, &connection).await
                {
                    return false;
                }
                if let RemoteOperation::Session {
                    operation: FileOperation::Open(_) | FileOperation::Read { .. },
                    path,
                } = operation
                {
                    let Some(path) = path else {
                        return false;
                    };
                    let (Ok(app), Ok(id)) = (
                        resource.application_id.parse(),
                        FileSystemId::parse(&resource.filesystem_id),
                    ) else {
                        return false;
                    };
                    let scope = Namespace {
                        owner_subject: resource.owner_subject.clone(),
                        application_id: app,
                    };
                    let Ok(filesystem) = handler.file_systems.open_resource(&scope, id).await
                    else {
                        return false;
                    };
                    return filesystem
                        .residency(&path)
                        .is_ok_and(|mode| mode == Residency::Full);
                }
                true
            })
        })
    }

    async fn authorize(&self, resource: &IrohResourceDescriptor, connection: &Connection) -> bool {
        if self.cancellation_token.is_cancelled() {
            return false;
        }
        let (Ok(application_id), Ok(filesystem_id)) = (
            resource.application_id.parse(),
            FileSystemId::parse(&resource.filesystem_id),
        ) else {
            return false;
        };
        let scope = Namespace {
            owner_subject: resource.owner_subject.clone(),
            application_id,
        };
        if self
            .file_systems
            .require_local_copy(&scope, filesystem_id)
            .is_err()
        {
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
                    kind: "filesystem".into(),
                    resource_id: resource.filesystem_id.clone(),
                },
            )
            .await
    }

    async fn require_authorized(
        &self,
        resource: &IrohResourceDescriptor,
        connection: &Connection,
    ) -> std::io::Result<()> {
        if self.authorize(resource, connection).await {
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "filesystem resource is not locally authorized",
            ))
        }
    }
}

impl core::fmt::Debug for StorageProtocolHandler {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StorageProtocolHandler")
            .finish_non_exhaustive()
    }
}
impl ProtocolHandler for StorageProtocolHandler {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        loop {
            let (send, mut recv) = tokio::select! { () = self.cancellation_token.cancelled() => return Ok(()), result = connection.accept_bi() => result? };
            let mut kind = [0];
            tokio::select! { () = self.cancellation_token.cancelled() => return Ok(()), result = recv.read_exact(&mut kind) => if result.is_err() { continue; } }
            if kind[0] == FILESYSTEM_STREAM_KIND {
                self.accept_stream(connection.clone(), send, recv).await;
            }
        }
    }
}
fn descriptor(resource: &SelectedResource) -> IrohResourceDescriptor {
    IrohResourceDescriptor {
        owner_subject: resource.owner_subject.clone(),
        application_id: resource.application_id.clone(),
        filesystem_id: resource.resource_id.clone(),
    }
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
