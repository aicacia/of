use std::{future::Future, io, sync::Arc};

use idp_model::{
    contract::{PermissionEvaluationRequest, PermissionSubject, PermissionTarget},
    model::Id,
};
use idp_server::{NodeJoinApproval, NodeJoinStage, OwnerProvisioner};
use idp_service::{
    PasswordConfig,
    oauth2::NodeSignerBinding,
    replica::{DbReplicaSignerRepo, DbUserRepo},
    repo::{PrivateKeyRepo, UserRepo},
};
use iroh::endpoint::{Connection, RecvStream, SendStream};
use management_service::{
    DeviceRepo, LocalPermissions, PUBLIC_POLICY_TABLES, replica::DbDeviceRepo,
};
use ofdb_sql::{
    SessionConfig, SyncDirection, SyncError, SyncResult, SyncRole, SyncTransport,
    SyncValidationDirection,
};
use serde::{Deserialize, Serialize};
use storage_server::DatabaseTransport;

use super::{SecurityContext, SecurityProtocol, candidates, denied, now};

#[cfg(test)]
#[path = "node_bootstrap_interruption_tests.rs"]
mod interruption_tests;

pub(super) const BOOTSTRAP_STREAM_KIND: u8 = 4;
const PURPOSE: &str = "of.equal-node-public-bootstrap.v1";

#[derive(Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct BootstrapRequest {
    purpose: String,
    context: SecurityContext,
    approval: NodeJoinApproval,
}

impl SecurityProtocol {
    pub fn node_bootstrap_handler(&self) -> impl iroh::protocol::ProtocolHandler + use<> {
        NodeBootstrapHandler {
            protocol: self.clone(),
        }
    }

    pub async fn receive_node_bootstrap<P: PrivateKeyRepo + Send + Sync>(
        &self,
        connection: &Connection,
        owner: &OwnerProvisioner<P>,
        context: SecurityContext,
    ) -> io::Result<SyncResult> {
        let approval = owner.node_join_anchor()?;
        self.check_bootstrap_receiver(connection, owner, &approval)
            .await?;
        self.validate_local_schema(context).await?;
        let request = BootstrapRequest {
            purpose: PURPOSE.into(),
            context,
            approval: approval.clone(),
        };
        let (mut send, recv) = connection.open_bi().await.map_err(io::Error::other)?;
        self.check_bootstrap_receiver(connection, owner, &approval)
            .await?;
        send.write_all(&[BOOTSTRAP_STREAM_KIND])
            .await
            .map_err(io::Error::other)?;
        let mut transport = DatabaseTransport::new(send, recv);
        self.check_bootstrap_receiver(connection, owner, &approval)
            .await?;
        transport.send(serde_json::to_vec(&request)?).await?;
        let accepted: BootstrapRequest = serde_json::from_slice(&transport.receive().await?)?;
        if accepted != request {
            return Err(denied("bootstrap context/anchor reply mismatch"));
        }
        let mut transport = ReceiverTransport {
            inner: &mut transport,
            protocol: self,
            connection,
            owner,
            approval: &approval,
        };
        let result = self
            .node_bootstrap_session(
                &approval,
                context,
                SyncDirection::ReceiveOnly,
                &mut transport,
                || async {
                    self.check_bootstrap_receiver(connection, owner, &approval)
                        .await
                        .map_err(|_| "bootstrap receiver no longer authorized".into())
                },
            )
            .await?;
        self.check_bootstrap_receiver(connection, owner, &approval)
            .await?;
        owner.record_node_join_stage(stage(context))?;
        Ok(result)
    }

    pub(super) async fn accept_node_bootstrap(
        &self,
        connection: Connection,
        send: SendStream,
        recv: RecvStream,
    ) -> io::Result<()> {
        let mut transport = DatabaseTransport::new(send, recv);
        let request: BootstrapRequest = serde_json::from_slice(&transport.receive().await?)?;
        if request.purpose != PURPOSE {
            return Err(denied("invalid bootstrap purpose"));
        }
        self.authorize_bootstrap_source(&connection, &request.approval, request.context)
            .await?;
        self.validate_local_schema(request.context).await?;
        self.authorize_bootstrap_source(&connection, &request.approval, request.context)
            .await?;
        transport.send(serde_json::to_vec(&request)?).await?;
        let mut transport = SourceTransport {
            inner: &mut transport,
            protocol: self,
            connection: &connection,
            approval: &request.approval,
            context: request.context,
        };
        self.node_bootstrap_session(
            &request.approval,
            request.context,
            SyncDirection::SendOnly,
            &mut transport,
            || async {
                self.authorize_bootstrap_source(&connection, &request.approval, request.context)
                    .await
                    .map_err(|_| "bootstrap source no longer authorized".into())
            },
        )
        .await?;
        Ok(())
    }

    async fn authorize_bootstrap_source(
        &self,
        connection: &Connection,
        approval: &NodeJoinApproval,
        context: SecurityContext,
    ) -> io::Result<()> {
        if connection.alpn() != idp_server::BOOTSTRAP_ALPN {
            return Err(denied("bootstrap requires its purpose-specific ALPN"));
        }
        approval.verify(&approval.request).map_err(denied)?;
        let request = &approval.request;
        if request.installation != self.installation
            || request.approving_peer != self.server.endpoint().id().to_string()
            || request.endpoint_id != connection.remote_id().to_string()
        {
            return Err(denied(
                "bootstrap Installation or authenticated endpoint mismatch",
            ));
        }
        self.authorize(connection, request.member_id, context)
            .await?;
        self.check_exact_join_trust(approval).await?;
        let local = self.local_handshake(context).await?;
        let device = DbDeviceRepo::new(self.idp.clone())
            .find_approved_by_public_key(&self.server.endpoint().id().to_string())
            .await
            .map_err(denied)?
            .ok_or_else(|| denied("bootstrap source has no current approved Device"))?;
        let owner: Id = device.owner_subject.parse().map_err(denied)?;
        if device.id != local.member
            || owner.is_nil()
            || DbUserRepo::new(self.idp.clone(), PasswordConfig::default())
                .find_user_by_id(owner)
                .await
                .map_err(denied)?
                .is_none()
        {
            return Err(denied(
                "bootstrap source has no active conflict-clear Device owner",
            ));
        }
        if self.cancellation.is_cancelled() {
            return Err(denied("bootstrap is shutting down"));
        }
        Ok(())
    }

    async fn check_exact_join_trust(&self, approval: &NodeJoinApproval) -> io::Result<()> {
        let request = &approval.request;
        let key: Id = request.public_signer.kid.parse().map_err(denied)?;
        let trusted = DbReplicaSignerRepo::new(self.idp.clone())
            .trusted_signers(&self.installation, now()?)
            .await
            .map_err(denied)?;
        if trusted
            .iter()
            .filter(|(member, signer)| {
                member.member_id == request.member_id
                    && member.endpoint_id == request.endpoint_id
                    && signer.key_id == key
                    && signer.public_jwk == request.public_signer
            })
            .count()
            != 1
        {
            return Err(denied(
                "bootstrap requires exact current enrolled member and independent signer",
            ));
        }
        let device = DbDeviceRepo::new(self.idp.clone())
            .find_approved_by_public_key(&request.endpoint_id)
            .await
            .map_err(denied)?
            .ok_or_else(|| denied("bootstrap requires approved conflict-clear joining Device"))?;
        if device.id != request.member_id
            || device.owner_subject != approval.owner_subject.to_string()
            || device.name != request.name
        {
            return Err(denied(
                "bootstrap Device owner/name/endpoint binding changed",
            ));
        }
        if DbUserRepo::new(self.idp.clone(), PasswordConfig::default())
            .find_user_by_id(approval.owner_subject)
            .await
            .map_err(denied)?
            .is_none()
        {
            return Err(denied(
                "bootstrap owner is not a current conflict-clear User",
            ));
        }
        Ok(())
    }

    async fn check_bootstrap_receiver<P: PrivateKeyRepo + Send + Sync>(
        &self,
        connection: &Connection,
        owner: &OwnerProvisioner<P>,
        approval: &NodeJoinApproval,
    ) -> io::Result<()> {
        if connection.alpn() != idp_server::BOOTSTRAP_ALPN
            || self.cancellation.is_cancelled()
            || !Arc::ptr_eq(&self.idp, &owner.node_join_database())
            || owner.node_join_anchor()? != *approval
            || approval.request.installation != self.installation
            || approval.request.endpoint_id != self.server.endpoint().id().to_string()
            || approval.request.approving_peer != connection.remote_id().to_string()
        {
            return Err(denied(
                "bootstrap receiver requires persisted exact local anchor and pinned connection",
            ));
        }
        owner
            .check_node_join_local_binding()
            .await
            .map_err(denied)?;
        if owner.node_join_stage_recorded(NodeJoinStage::Idp)? {
            self.check_exact_join_trust(approval).await?;
        }
        if owner.node_join_stage_recorded(NodeJoinStage::Management)? {
            self.check_join_context_grants(approval).await?;
        }
        if self.cancellation.is_cancelled() {
            return Err(denied("bootstrap is shutting down"));
        }
        Ok(())
    }

    async fn node_bootstrap_session<T, Q, U>(
        &self,
        approval: &NodeJoinApproval,
        context: SecurityContext,
        direction: SyncDirection,
        transport: &mut T,
        check: Q,
    ) -> io::Result<SyncResult>
    where
        T: SyncTransport<Error = io::Error>,
        Q: FnMut() -> U + Send,
        U: Future<Output = Result<(), String>> + Send,
    {
        let (database, directory, tables) = match context {
            SecurityContext::Idp => (
                &self.idp,
                self.staging_directory.join("bootstrap-idp"),
                idp_service::security_sync::public_security_tables()
                    .into_iter()
                    .map(|table| table.name())
                    .collect::<Vec<_>>(),
            ),
            SecurityContext::Management => (
                &self.management,
                self.staging_directory.join("bootstrap-policy"),
                PUBLIC_POLICY_TABLES.to_vec(),
            ),
        };
        database
            .synchronize_tables_with_stage_directory_candidate_validated_checked(
                transport,
                &SessionConfig {
                    direction,
                    ..SessionConfig::default()
                },
                if direction == SyncDirection::ReceiveOnly {
                    SyncRole::Initiator
                } else {
                    SyncRole::Responder
                },
                directory,
                &tables,
                |table, column, value| {
                    context.validate_value(table, column, value)?;
                    if context == SecurityContext::Idp
                        && !candidates::permits_installation(
                            table,
                            column,
                            value,
                            &self.installation,
                        )
                    {
                        return Err("invalid public security historical value".into());
                    }
                    Ok(())
                },
                |view| {
                    if (direction == SyncDirection::ReceiveOnly
                        && view.direction == SyncValidationDirection::Outgoing)
                        || (direction == SyncDirection::SendOnly
                            && view.direction == SyncValidationDirection::Incoming)
                    {
                        return Err("bootstrap reverse application history is prohibited".into());
                    }
                    match context {
                        SecurityContext::Idp => {
                            candidates::validate_node_join(view, &self.installation, approval)
                        }
                        SecurityContext::Management => {
                            for table in &view.tables {
                                let columns =
                                    management_service::public_policy_columns(&table.name)
                                        .ok_or("invalid public policy candidate")?;
                                if columns.len() != table.columns.len()
                                    || table
                                        .columns
                                        .iter()
                                        .any(|column| !columns.contains(&column.as_str()))
                                {
                                    return Err("invalid public policy candidate".into());
                                }
                            }
                            Ok(())
                        }
                    }
                },
                check,
            )
            .await
            .map_err(|error| match error {
                SyncError::PreApply(reason) => denied(reason),
                SyncError::Transport(error) => error,
                error => io::Error::other(error.to_string()),
            })
    }

    async fn verify_node_join_public_readiness<P: PrivateKeyRepo + Send + Sync>(
        &self,
        owner: &OwnerProvisioner<P>,
    ) -> io::Result<()> {
        let approval = owner.node_join_anchor()?;
        if self.cancellation.is_cancelled()
            || !Arc::ptr_eq(&self.idp, &owner.node_join_database())
            || approval.request.installation != self.installation
            || approval.request.endpoint_id != self.server.endpoint().id().to_string()
            || !owner.node_join_stage_recorded(NodeJoinStage::Idp)?
            || !owner.node_join_stage_recorded(NodeJoinStage::Management)?
        {
            return Err(denied("both durable public context imports are required"));
        }
        owner
            .check_node_join_local_binding()
            .await
            .map_err(denied)?;
        self.check_exact_join_trust(&approval).await?;
        let binding = NodeSignerBinding {
            member_id: approval.request.member_id,
            key_id: approval.request.public_signer.kid.parse().map_err(denied)?,
            endpoint_id: approval.request.endpoint_id.clone(),
        };
        if !self.binding.as_ref().is_some_and(|configured| {
            configured.member_id == binding.member_id
                && configured.key_id == binding.key_id
                && configured.endpoint_id == binding.endpoint_id
        }) || owner.verify_node_signer(&binding).await? != approval.request.public_signer
        {
            return Err(denied("local independent signing capability is not ready"));
        }
        self.check_join_context_grants(&approval).await
    }

    async fn check_join_context_grants(&self, approval: &NodeJoinApproval) -> io::Result<()> {
        for context in [SecurityContext::Idp, SecurityContext::Management] {
            let (action, resource) = context.permission();
            if !LocalPermissions::new(self.management.clone())
                .evaluate(&PermissionEvaluationRequest {
                    request_id: Id::now_v7(),
                    subject: PermissionSubject::User {
                        id: approval.owner_subject,
                    },
                    action,
                    target: PermissionTarget::Installation { resource },
                })
                .await
                .map_err(denied)?
            {
                return Err(denied("local owner lacks exact public context permission"));
            }
        }
        Ok(())
    }

    /// Completes public IdP/Management bootstrap, not Storage readiness or resource authorization.
    pub async fn complete_node_join_public_bootstrap<P: PrivateKeyRepo + Send + Sync>(
        &self,
        owner: &OwnerProvisioner<P>,
    ) -> io::Result<()> {
        self.verify_node_join_public_readiness(owner).await?;
        owner.record_node_join_stage(NodeJoinStage::PublicReady)
    }

    pub async fn node_join_public_ready<P: PrivateKeyRepo + Send + Sync>(
        &self,
        owner: &OwnerProvisioner<P>,
    ) -> io::Result<bool> {
        if !owner.node_join_stage_recorded(NodeJoinStage::PublicReady)? {
            return Ok(false);
        }
        Ok(self.verify_node_join_public_readiness(owner).await.is_ok())
    }
}

struct NodeBootstrapHandler {
    protocol: SecurityProtocol,
}

impl std::fmt::Debug for NodeBootstrapHandler {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("NodeBootstrapHandler")
    }
}

impl iroh::protocol::ProtocolHandler for NodeBootstrapHandler {
    async fn accept(&self, connection: Connection) -> Result<(), iroh::protocol::AcceptError> {
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                _ = self.protocol.cancellation.cancelled() => break,
                result = tasks.join_next(), if !tasks.is_empty() => { let _ = result; },
                streams = connection.accept_bi() => {
                    let Ok((send, mut recv)) = streams else { break; };
                    let protocol = self.protocol.clone();
                    let connection = connection.clone();
                    tasks.spawn(async move {
                        let mut kind = [0u8; 1];
                        recv.read_exact(&mut kind).await.map_err(io::Error::other)?;
                        if kind[0] != BOOTSTRAP_STREAM_KIND { return Err(denied("only purpose-specific bootstrap streams are allowed")); }
                        let result = protocol.accept_node_bootstrap(connection, send, recv).await;
                        #[cfg(test)]
                        if let Err(error) = &result { eprintln!("bootstrap source rejected: {error}"); }
                        result
                    });
                }
            }
        }
        tasks.shutdown().await;
        Ok(())
    }
}

fn stage(context: SecurityContext) -> NodeJoinStage {
    match context {
        SecurityContext::Idp => NodeJoinStage::Idp,
        SecurityContext::Management => NodeJoinStage::Management,
    }
}

struct SourceTransport<'a, T> {
    inner: &'a mut T,
    protocol: &'a SecurityProtocol,
    connection: &'a Connection,
    approval: &'a NodeJoinApproval,
    context: SecurityContext,
}
impl<T: SyncTransport<Error = io::Error>> SyncTransport for SourceTransport<'_, T> {
    type Error = io::Error;
    async fn send(&mut self, frame: Vec<u8>) -> io::Result<()> {
        self.protocol
            .authorize_bootstrap_source(self.connection, self.approval, self.context)
            .await?;
        self.inner.send(frame).await
    }
    async fn receive(&mut self) -> io::Result<Vec<u8>> {
        self.inner.receive().await
    }
}

struct ReceiverTransport<'a, T, P: PrivateKeyRepo + Send + Sync> {
    inner: &'a mut T,
    protocol: &'a SecurityProtocol,
    connection: &'a Connection,
    owner: &'a OwnerProvisioner<P>,
    approval: &'a NodeJoinApproval,
}
impl<T: SyncTransport<Error = io::Error>, P: PrivateKeyRepo + Send + Sync> SyncTransport
    for ReceiverTransport<'_, T, P>
{
    type Error = io::Error;
    async fn send(&mut self, frame: Vec<u8>) -> io::Result<()> {
        self.protocol
            .check_bootstrap_receiver(self.connection, self.owner, self.approval)
            .await?;
        self.inner.send(frame).await
    }
    async fn receive(&mut self) -> io::Result<Vec<u8>> {
        self.inner.receive().await
    }
}
