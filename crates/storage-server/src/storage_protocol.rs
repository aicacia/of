use std::{sync::Arc, time::Duration};

use file_system::{FileSystemId, IrohFileTransport, IrohResourceDescriptor};
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

use crate::{ManagementClient, sync_timeout};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const POLICY_CHECK_TIMEOUT: Duration = Duration::from_secs(10);
const SYNC_OPERATION_TIMEOUT: Duration = Duration::from_secs(30);

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
        let local_public_key = self.server.endpoint().id().to_string();
        let selected = match self.management.selected_resources(&local_public_key).await {
            Ok(response) => response.resources,
            Err(error) => {
                log::warn!("failed to list selected filesystems: {error}");
                return;
            }
        };
        let selected_filesystems = selected
            .iter()
            .filter(|resource| resource.kind == "filesystem")
            .filter_map(|resource| {
                let application_id = resource.application_id.parse().ok()?;
                let resource_id = FileSystemId::parse(&resource.resource_id).ok()?;
                Some((resource.owner_subject.clone(), application_id, resource_id))
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
            let remote_public_key = peer.to_string();
            if local_public_key >= remote_public_key {
                continue;
            }
            for resource in selected
                .iter()
                .filter(|resource| resource.kind == "filesystem")
            {
                let descriptor = descriptor(resource);
                if let Err(error) = self.synchronize_peer(peer, descriptor).await {
                    log::debug!("filesystem sync with {remote_public_key} failed: {error}");
                }
            }
        }
    }

    async fn synchronize_peer(
        &self,
        peer: EndpointId,
        resource: IrohResourceDescriptor,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let application_id = resource.application_id.parse()?;
        let filesystem_id = FileSystemId::parse(&resource.filesystem_id)?;
        let namespace = Namespace {
            owner_subject: resource.owner_subject.clone(),
            application_id,
        };
        let deleted = self
            .file_systems
            .is_tombstoned(&namespace, filesystem_id)
            .await
            .map_err(std::io::Error::other)?;
        let connection = tokio::time::timeout(
            HANDSHAKE_TIMEOUT,
            self.server.connect_direct_with_alpn(peer, DATA_ALPN),
        )
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "filesystem connection timed out",
            )
        })??;
        if !self.authorize_bounded(&resource, &connection).await {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "filesystem resource is not authorized for sync",
            )
            .into());
        }
        let handler = self.clone();
        let connection_for_guard = connection.clone();
        let transport = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
            if deleted {
                IrohFileTransport::open_tombstone_authorized(
                    &connection,
                    resource,
                    move |resource| {
                        let handler = handler.clone();
                        let connection = connection_for_guard.clone();
                        async move { handler.authorize_bounded(&resource, &connection).await }
                    },
                )
                .await
            } else {
                IrohFileTransport::open_authorized(&connection, resource, move |resource| {
                    let handler = handler.clone();
                    let connection = connection_for_guard.clone();
                    async move { handler.authorize_bounded(&resource, &connection).await }
                })
                .await
            }
        })
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "filesystem handshake timed out",
            )
        })??;
        if deleted {
            transport.close();
            return Ok(());
        }
        let file_system = self
            .file_systems
            .open_resource(&namespace, filesystem_id)
            .await
            .map_err(std::io::Error::other)?;
        sync_timeout::run(
            SYNC_OPERATION_TIMEOUT,
            "filesystem sync operation timed out",
            async {
                file_system
                    .sync_peer(transport)
                    .await
                    .map_err(std::io::Error::other)
            },
        )
        .await?;
        Ok(())
    }
}

impl core::fmt::Debug for StorageProtocolHandler {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("StorageProtocolHandler")
            .finish_non_exhaustive()
    }
}

impl StorageProtocolHandler {
    pub(crate) async fn accept_stream(
        &self,
        connection: Connection,
        send: SendStream,
        recv: RecvStream,
    ) {
        let handler = self.clone();
        let connection_for_authorization = connection.clone();
        let (transport, resource, deleted) = match tokio::time::timeout(
            HANDSHAKE_TIMEOUT,
            IrohFileTransport::accept_authorized_after_marker(
                &connection,
                send,
                recv,
                move |resource| {
                    let handler = handler.clone();
                    let connection = connection_for_authorization.clone();
                    async move { handler.authorize_bounded(&resource, &connection).await }
                },
            ),
        )
        .await
        {
            Ok(Ok(accepted)) => accepted,
            Ok(Err(error)) => {
                log::warn!("rejected filesystem sync stream: {error}");
                return;
            }
            Err(_) => {
                log::warn!("rejected filesystem sync stream: handshake timed out");
                return;
            }
        };

        let Ok(application_id) = resource.application_id.parse() else {
            return;
        };
        let Ok(filesystem_id) = FileSystemId::parse(&resource.filesystem_id) else {
            return;
        };
        let namespace = Namespace {
            owner_subject: resource.owner_subject,
            application_id,
        };
        if deleted {
            if let Err(error) = self
                .file_systems
                .apply_deletion_tombstone(&namespace, filesystem_id)
                .await
            {
                log::warn!("failed to apply filesystem deletion tombstone: {error}");
            }
            transport.close();
            return;
        }
        if let Err(error) = self
            .file_systems
            .register_selected_resource(&namespace, filesystem_id)
            .await
        {
            log::warn!("failed to register selected filesystem: {error}");
            return;
        }
        let file_system = match self
            .file_systems
            .open_resource(&namespace, filesystem_id)
            .await
        {
            Ok(file_system) => file_system,
            Err(error) => {
                log::warn!("failed to open selected filesystem: {error}");
                return;
            }
        };
        let cancellation_token = self.cancellation_token.clone();
        tokio::spawn(async move {
            let mut sync_task = tokio::spawn(async move {
                sync_timeout::run(
                    SYNC_OPERATION_TIMEOUT,
                    "filesystem sync operation timed out",
                    async {
                        file_system
                            .sync_peer(transport)
                            .await
                            .map_err(std::io::Error::other)
                    },
                )
                .await
            });
            let result = tokio::select! {
                () = cancellation_token.cancelled() => {
                    sync_task.abort();
                    let _ = sync_task.await;
                    return;
                }
                result = &mut sync_task => match result {
                    Ok(result) => result,
                    Err(error) => Err(std::io::Error::other(error)),
                },
            };
            match result {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::TimedOut => {
                    log::warn!("filesystem sync operation timed out")
                }
                Err(error) => log::warn!("filesystem sync session ended: {error}"),
            }
        });
    }
}

impl ProtocolHandler for StorageProtocolHandler {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        loop {
            let (send, mut recv) = connection.accept_bi().await?;
            let mut kind = [0; 1];
            if !matches!(
                tokio::time::timeout(HANDSHAKE_TIMEOUT, recv.read_exact(&mut kind)).await,
                Ok(Ok(()))
            ) || kind[0] != file_system::FILESYSTEM_STREAM_KIND
            {
                continue;
            }
            self.accept_stream(connection.clone(), send, recv).await;
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

impl StorageProtocolHandler {
    async fn authorize_bounded(
        &self,
        resource: &IrohResourceDescriptor,
        connection: &Connection,
    ) -> bool {
        tokio::time::timeout(POLICY_CHECK_TIMEOUT, self.authorize(resource, connection))
            .await
            .unwrap_or(false)
    }

    async fn authorize(&self, resource: &IrohResourceDescriptor, connection: &Connection) -> bool {
        let Ok(_application_id) = resource.application_id.parse::<idp_model::model::Id>() else {
            return false;
        };
        let Ok(_filesystem_id) = FileSystemId::parse(&resource.filesystem_id) else {
            return false;
        };
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
                "filesystem",
                &resource.filesystem_id,
            )
            .await
            .is_ok()
    }
}

fn descriptor_matches_selection(
    descriptor: &IrohResourceDescriptor,
    selected: &model::contract::SelectedResource,
) -> bool {
    selected.owner_subject == descriptor.owner_subject
        && selected.application_id == descriptor.application_id
        && selected.kind == "filesystem"
        && selected.resource_id == descriptor.filesystem_id
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
#[path = "storage_protocol_tests.rs"]
mod tests;

#[cfg(test)]
mod authorization_tests {
    use file_system::IrohResourceDescriptor;
    use model::contract::SelectedResource;

    use super::descriptor_matches_selection;

    fn descriptor() -> IrohResourceDescriptor {
        IrohResourceDescriptor {
            owner_subject: "owner-a".to_owned(),
            application_id: "app-a".to_owned(),
            filesystem_id: "fs-a".to_owned(),
        }
    }

    fn selection() -> SelectedResource {
        SelectedResource {
            owner_subject: "owner-a".to_owned(),
            application_id: "app-a".to_owned(),
            kind: "filesystem".to_owned(),
            resource_id: "fs-a".to_owned(),
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
        spoofed_descriptor.filesystem_id = "fs-b".to_owned();
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
        spoofed.kind = "database".to_owned();
        assert!(!descriptor_matches_selection(&descriptor, &spoofed));
        let mut spoofed = selection;
        spoofed.resource_id = "fs-b".to_owned();
        assert!(!descriptor_matches_selection(&descriptor, &spoofed));
    }
}
