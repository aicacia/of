use std::{
    io,
    path::PathBuf,
    sync::{Arc, OnceLock},
};

use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use idp_model::contract::{JwkPublic, JwkPublicParameters, JwsAlgorithm, KeyUse};
use idp_service::repo::{PrivateKeyKeyringRepo, PrivateKeyRepo};
use iroh::{
    Endpoint, EndpointAddr, EndpointId, SecretKey,
    endpoint::{
        AfterHandshakeOutcome, BeforeConnectOutcome, Connection, EndpointHooks, presets::Preset,
    },
};
use iroh_chain::{AllowlistHook, EndpointIdStore, PAIRING_ALPN, Server};

use super::{NodeJoinApproval, NodeJoinRequest, read_optional};
use crate::{AppConfig, BOOTSTRAP_ALPN};

#[cfg(test)]
#[path = "node_join_transport_tests.rs"]
mod tests;

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
    fn pinned_peer_for(&self, alpn: &[u8]) -> io::Result<Option<EndpointId>> {
        if alpn != PAIRING_ALPN && alpn != BOOTSTRAP_ALPN {
            return Ok(None);
        }
        let Some(request) =
            read_optional::<NodeJoinRequest>(&self.data_dir.join("node-join-request.json"))?
        else {
            return Ok(None);
        };
        request.validate()?;
        if request.installation != self.issuer
            || request.endpoint_id != self.local_endpoint.to_string()
        {
            return Ok(None);
        }
        let namespace = format!(
            "{}:node:{}:{}",
            self.namespace, request.member_id, request.public_signer.kid
        );
        let Some(private) = PrivateKeyKeyringRepo::new(&self.issuer)
            .map_err(io::Error::other)?
            .load(&namespace, &key::DerivationPath::default())
            .map_err(io::Error::other)?
        else {
            return Ok(None);
        };
        let (x, y) = private.to_xy().map_err(io::Error::other)?;
        let public = JwkPublic {
            kid: request.public_signer.kid.clone(),
            r#use: KeyUse::Signature,
            alg: JwsAlgorithm::ES256K,
            params: JwkPublicParameters::Ec {
                crv: "secp256k1".into(),
                x: STANDARD_NO_PAD.encode(x),
                y: STANDARD_NO_PAD.encode(y),
            },
        };
        if public != request.public_signer {
            return Ok(None);
        }
        if alpn == BOOTSTRAP_ALPN {
            let Some(approval) =
                read_optional::<NodeJoinApproval>(&self.data_dir.join("node-join-approval.json"))?
            else {
                return Ok(None);
            };
            approval.verify(&request)?;
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
        if self.pinned_peer_for(alpn).ok().flatten() == Some(remote.id) {
            return BeforeConnectOutcome::Accept;
        }
        match self.ordinary.get() {
            Some(hook) => hook.before_connect(remote, alpn).await,
            None => BeforeConnectOutcome::Reject,
        }
    }

    async fn after_handshake<'a>(&'a self, connection: &'a Connection) -> AfterHandshakeOutcome {
        if self.pinned_peer_for(connection.alpn()).ok().flatten() == Some(connection.remote_id()) {
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

/// Adds pinned pairing admission for prepared joins and bootstrap admission for approved joins.
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
