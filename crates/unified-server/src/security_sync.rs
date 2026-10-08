use std::{
    io,
    path::PathBuf,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use db::Database;
use idp_model::{
    contract::{
        IdentityAction, IdentityResource, PermissionEvaluationRequest, PermissionSubject,
        PermissionTarget,
    },
    model::Id,
};
use idp_service::{
    PasswordConfig,
    oauth2::NodeSignerBinding,
    replica::{DbReplicaSignerRepo, DbUserRepo},
    repo::UserRepo,
    security_sync::public_security_tables,
};
use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh_chain::Server;
use management_service::{
    DeviceRepo, LocalPermissions, PUBLIC_POLICY_TABLES, replica::DbDeviceRepo,
};
use ofdb_sql::{SessionConfig, SyncError, SyncResult, SyncRole, SyncTransport};
use serde::{Deserialize, Serialize};
use storage_server::{DataProtocolHandler, DatabaseTransport};
use tokio_util::sync::CancellationToken;

const SECURITY_STREAM_KIND: u8 = 3;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityContext {
    Idp,
    Management,
}

impl SecurityContext {
    fn permission(self) -> (IdentityAction, IdentityResource) {
        match self {
            Self::Idp => (
                IdentityAction::IdpSecuritySync,
                IdentityResource::IdpSecurity,
            ),
            Self::Management => (
                IdentityAction::ManagementSecuritySync,
                IdentityResource::ManagementSecurity,
            ),
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Handshake {
    version: u8,
    installation: String,
    member: Id,
    context: SecurityContext,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
enum Response {
    Accepted(Handshake),
    Denied,
}

#[derive(Clone)]
pub struct SecurityProtocol {
    server: Server,
    idp: Arc<Database>,
    management: Arc<Database>,
    installation: String,
    binding: Option<NodeSignerBinding>,
    staging_directory: PathBuf,
    cancellation: CancellationToken,
}

impl SecurityProtocol {
    pub fn new(
        server: Server,
        idp: Arc<Database>,
        management: Arc<Database>,
        installation: String,
        binding: Option<NodeSignerBinding>,
        staging_directory: PathBuf,
        cancellation: CancellationToken,
    ) -> Self {
        Self {
            server,
            idp,
            management,
            installation,
            binding,
            staging_directory,
            cancellation,
        }
    }

    pub fn attach(&self, handler: DataProtocolHandler) -> DataProtocolHandler {
        let protocol = self.clone();
        handler.with_additional_stream(move |kind, connection, send, recv| {
            let protocol = protocol.clone();
            async move {
                if kind != SECURITY_STREAM_KIND {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unknown DATA stream kind",
                    ));
                }
                protocol.accept_stream(connection, send, recv).await
            }
        })
    }

    pub async fn synchronize(
        &self,
        connection: &Connection,
        context: SecurityContext,
    ) -> io::Result<SyncResult> {
        self.validate_local_schema(context).await?;
        let handshake = self.local_handshake(context).await?;

        let trusted = DbReplicaSignerRepo::new(self.idp.clone())
            .trusted_signers(&self.installation, now()?)
            .await
            .map_err(denied)?;
        let remote_member = trusted
            .iter()
            .find(|(member, _)| member.endpoint_id == connection.remote_id().to_string())
            .map(|(member, _)| member.member_id)
            .ok_or_else(|| denied("remote endpoint has no local trusted member"))?;
        self.authorize(connection, remote_member, context).await?;

        let (mut send, recv) = connection.open_bi().await.map_err(io::Error::other)?;
        send.write_all(&[SECURITY_STREAM_KIND])
            .await
            .map_err(io::Error::other)?;
        let mut transport = DatabaseTransport::new(send, recv);
        transport
            .send(serde_json::to_vec(&handshake).map_err(io::Error::other)?)
            .await?;
        let response: Response =
            serde_json::from_slice(&transport.receive().await?).map_err(io::Error::other)?;
        let Response::Accepted(remote) = response else {
            return Err(denied("peer denied security synchronization"));
        };
        self.validate_handshake(&remote, context)?;
        if remote.member != remote_member {
            return Err(denied("peer member does not match local endpoint binding"));
        }
        self.authorize(connection, remote.member, context).await?;
        self.exchange(
            connection,
            remote.member,
            context,
            &mut transport,
            SyncRole::Initiator,
        )
        .await
    }

    async fn accept_stream(
        &self,
        connection: Connection,
        send: SendStream,
        recv: RecvStream,
    ) -> io::Result<()> {
        let mut transport = DatabaseTransport::new(send, recv);
        let remote: Handshake =
            serde_json::from_slice(&transport.receive().await?).map_err(io::Error::other)?;
        let admission = async {
            self.validate_handshake(&remote, remote.context)?;
            self.validate_local_schema(remote.context).await?;
            let local = self.local_handshake(remote.context).await?;
            self.authorize(&connection, remote.member, remote.context)
                .await?;
            Ok::<_, io::Error>(local)
        }
        .await;
        let local = match admission {
            Ok(local) => local,
            Err(error) => {
                transport
                    .send(serde_json::to_vec(&Response::Denied).map_err(io::Error::other)?)
                    .await?;
                return Err(error);
            }
        };
        transport
            .send(serde_json::to_vec(&Response::Accepted(local)).map_err(io::Error::other)?)
            .await?;
        self.exchange(
            &connection,
            remote.member,
            remote.context,
            &mut transport,
            SyncRole::Responder,
        )
        .await
        .map(|_| ())
    }

    async fn validate_local_schema(&self, context: SecurityContext) -> io::Result<()> {
        let (database, tables) = match context {
            SecurityContext::Idp => (
                &self.idp,
                public_security_tables()
                    .into_iter()
                    .map(|table| (table.name(), table.columns()))
                    .collect::<Vec<_>>(),
            ),
            SecurityContext::Management => (
                &self.management,
                PUBLIC_POLICY_TABLES
                    .iter()
                    .map(|table| {
                        (
                            *table,
                            management_service::public_policy_columns(table)
                                .expect("reviewed public policy table"),
                        )
                    })
                    .collect::<Vec<_>>(),
            ),
        };
        for (table, expected) in tables {
            let result = database
                .client()
                .translate_and_execute(
                    &format!("SELECT * FROM {table} LIMIT 0"),
                    &db::SqlTranslator,
                )
                .await
                .map_err(io::Error::other)?;
            let columns = &result
                .first()
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "missing public schema result")
                })?
                .columns;
            if columns.len() != expected.len()
                || columns
                    .iter()
                    .any(|column| !expected.contains(&column.name.as_str()))
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unreviewed public security schema: {table}"),
                ));
            }
        }
        Ok(())
    }

    fn validate_handshake(&self, remote: &Handshake, context: SecurityContext) -> io::Result<()> {
        if remote.version != 1
            || remote.installation != self.installation
            || remote.context != context
            || remote.member.is_nil()
        {
            return Err(denied(
                "security synchronization Installation/context/member mismatch",
            ));
        }
        Ok(())
    }

    async fn local_handshake(&self, context: SecurityContext) -> io::Result<Handshake> {
        if self.cancellation.is_cancelled() {
            return Err(denied("security synchronization is shutting down"));
        }
        let binding = self
            .binding
            .as_ref()
            .ok_or_else(|| denied("local node signer is not configured"))?;
        let endpoint = self.server.endpoint().id().to_string();
        let trusted = DbReplicaSignerRepo::new(self.idp.clone())
            .trusted_signers(&self.installation, now()?)
            .await
            .map_err(denied)?;
        if binding.endpoint_id != endpoint
            || !trusted.iter().any(|(member, signer)| {
                member.member_id == binding.member_id
                    && member.endpoint_id == endpoint
                    && signer.key_id == binding.key_id
            })
        {
            return Err(denied("local node signer/member is not currently trusted"));
        }
        Ok(Handshake {
            version: 1,
            installation: self.installation.clone(),
            member: binding.member_id,
            context,
        })
    }

    async fn authorize(
        &self,
        connection: &Connection,
        member: Id,
        context: SecurityContext,
    ) -> io::Result<()> {
        self.local_handshake(context).await?;
        let endpoint = connection.remote_id().to_string();
        if !DbReplicaSignerRepo::new(self.idp.clone())
            .is_trusted_peer(&self.installation, member, &endpoint, now()?)
            .await
            .map_err(denied)?
        {
            return Err(denied(
                "remote member is not currently trusted for this authenticated endpoint",
            ));
        }
        let device = DbDeviceRepo::new(self.idp.clone())
            .find_approved_by_public_key(&endpoint)
            .await
            .map_err(denied)?
            .ok_or_else(|| denied("remote endpoint has no approved local Device"))?;
        if device.id != member {
            return Err(denied("Device and Installation member differ"));
        }
        let actor: Id = device.owner_subject.parse().map_err(denied)?;
        if actor.is_nil()
            || DbUserRepo::new(self.idp.clone(), PasswordConfig::default())
                .find_user_by_id(actor)
                .await
                .map_err(denied)?
                .is_none()
        {
            return Err(denied(
                "Device owner is not a current conflict-clear local User",
            ));
        }
        let (action, resource) = context.permission();
        if !LocalPermissions::new(self.management.clone())
            .evaluate(&PermissionEvaluationRequest {
                request_id: Id::now_v7(),
                subject: PermissionSubject::User { id: actor },
                action,
                target: PermissionTarget::Installation { resource },
            })
            .await
            .map_err(denied)?
        {
            return Err(denied(
                "local actor lacks this context's security sync permission",
            ));
        }
        Ok(())
    }

    async fn exchange(
        &self,
        connection: &Connection,
        member: Id,
        context: SecurityContext,
        transport: &mut DatabaseTransport,
        role: SyncRole,
    ) -> io::Result<SyncResult> {
        self.authorize(connection, member, context).await?;
        log::debug!("starting scoped security session: {context:?} {role:?}");
        let (database, directory, tables) = match context {
            SecurityContext::Idp => (
                &self.idp,
                self.staging_directory.join("idp"),
                public_security_tables()
                    .into_iter()
                    .map(|table| table.name())
                    .collect::<Vec<_>>(),
            ),
            SecurityContext::Management => (
                &self.management,
                self.staging_directory.join("management"),
                PUBLIC_POLICY_TABLES.to_vec(),
            ),
        };
        database
            .synchronize_tables_with_stage_directory_checked(
                transport,
                &SessionConfig::default(),
                role,
                directory,
                &tables,
                || async {
                    log::debug!("checking scoped security apply: {context:?} {role:?}");
                    self.authorize(connection, member, context)
                        .await
                        .map_err(|error| error.to_string())
                },
            )
            .await
            .map_err(|error| match error {
                SyncError::PreApply(reason) => denied(reason),
                error => io::Error::other(error.to_string()),
            })
    }
}

fn denied(reason: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, reason.to_string())
}

fn now() -> io::Result<i64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_secs()
        .try_into()
        .map_err(io::Error::other)
}
