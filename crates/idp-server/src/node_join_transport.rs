use std::{
    io,
    path::PathBuf,
    sync::{Arc, OnceLock},
};

use idp_service::repo::{PrivateKeyKeyringRepo, PrivateKeyRepo};
use iroh::{
    Endpoint, EndpointAddr, EndpointId, SecretKey,
    endpoint::{
        AfterHandshakeOutcome, BeforeConnectOutcome, Connection, EndpointHooks, presets::Preset,
    },
};
use iroh_chain::{AllowlistHook, EndpointIdStore, Server};

use super::{NodeJoinApproval, NodeJoinRequest, read_optional};
use crate::{AppConfig, BOOTSTRAP_ALPN};

struct JoinHook {
    ordinary: Arc<OnceLock<AllowlistHook>>,
    data_dir: PathBuf,
    issuer: String,
    namespace: String,

    local_endpoint: EndpointId,
}

impl std::fmt::Debug for JoinHook {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("JoinHook")
    }
}

impl JoinHook {
    fn pinned_peer(&self) -> io::Result<Option<EndpointId>> {
        let Some(request) =
            read_optional::<NodeJoinRequest>(&self.data_dir.join("node-join-request.json"))?
        else {
            return Ok(None);
        };
        let Some(approval) =
            read_optional::<NodeJoinApproval>(&self.data_dir.join("node-join-approval.json"))?
        else {
            return Ok(None);
        };
        approval.verify(&request)?;
        if request.installation != self.issuer
            || request.endpoint_id != self.local_endpoint.to_string()
        {
            return Ok(None);
        }
        let namespace = format!(
            "{}:node:{}:{}",
            self.namespace, request.member_id, request.public_signer.kid
        );
        if PrivateKeyKeyringRepo::new(&self.issuer)
            .map_err(io::Error::other)?
            .load(&namespace, &key::DerivationPath::default())
            .map_err(io::Error::other)?
            .is_none()
        {
            return Ok(None);
        }
        Ok(Some(
            request.approving_peer.parse().map_err(io::Error::other)?,
        ))
    }
}

impl EndpointHooks for JoinHook {
    async fn before_connect<'a>(
        &'a self,
        remote: &'a EndpointAddr,
        alpn: &'a [u8],
    ) -> BeforeConnectOutcome {
        if alpn == BOOTSTRAP_ALPN && self.pinned_peer().ok().flatten() == Some(remote.id) {
            return BeforeConnectOutcome::Accept;
        }
        match self.ordinary.get() {
            Some(hook) => hook.before_connect(remote, alpn).await,
            None => BeforeConnectOutcome::Reject,
        }
    }

    async fn after_handshake<'a>(&'a self, connection: &'a Connection) -> AfterHandshakeOutcome {
        if connection.alpn() == BOOTSTRAP_ALPN
            && self.pinned_peer().ok().flatten() == Some(connection.remote_id())
        {
            return AfterHandshakeOutcome::Accept;
        }
        match self.ordinary.get() {
            Some(hook) => hook.after_handshake(connection).await,
            None => AfterHandshakeOutcome::Reject {
                error_code: 1u32.into(),
                reason: b"local admission not initialized".to_vec(),
            },
        }
    }
}

/// Adds only persisted pinned bootstrap-ALPN admission; ordinary trust/pairing hooks are unchanged.
pub async fn bind_node_join_endpoint<P: Preset>(
    config: &AppConfig,
    preset: P,
    secret: SecretKey,
    allowed: EndpointIdStore,
) -> io::Result<Server> {
    let ordinary = Arc::new(OnceLock::new());
    let endpoint = Endpoint::builder(preset)
        .secret_key(secret.clone())
        .hooks(JoinHook {
            ordinary: ordinary.clone(),
            data_dir: config.data_dir.clone().into(),
            issuer: config.oauth2.issuer.clone(),
            namespace: config.key_namespace.clone(),

            local_endpoint: secret.public(),
        })
        .bind()
        .await
        .map_err(io::Error::other)?;
    let server = Server::new(endpoint, allowed);
    ordinary
        .set(server.allowlist_hook())
        .map_err(|_| io::Error::other("local admission already initialized"))?;
    Ok(server)
}
