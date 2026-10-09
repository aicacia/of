use std::sync::Arc;

use file_system::{FileSystemId, OperationControl};
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
        OperationControl::new(move |peer, _operation| {
            let handler = handler.clone();
            let resource = resource.clone();
            let connection = connection.clone();
            Box::pin(async move {
                peer == connection.remote_id() && handler.authorize(&resource, &connection).await
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
