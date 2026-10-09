use std::{fs, io, io::Write, path::Path};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use idp_model::{contract::JwkPublic, model::Id};
use idp_service::{oauth2::NodeSignerBinding, repo::PrivateKeyRepo};
use iroh::{EndpointAddr, EndpointId, Signature};
use iroh_chain::Server;
use serde::{Deserialize, Serialize};

use crate::OwnerProvisioner;

#[path = "node_join_bootstrap.rs"]
mod bootstrap_state;
pub use bootstrap_state::NodeJoinStage;
#[path = "node_join_transport.rs"]
mod transport;
pub use transport::bind_node_join_endpoint;

const PURPOSE: &str = "of.equal-node-join.v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeJoinRequest {
    purpose: String,
    pub installation: String,
    pub member_id: Id,
    pub endpoint_id: String,
    pub name: String,
    pub public_signer: JwkPublic,
    pub approving_peer: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeJoinApproval {
    pub request: NodeJoinRequest,
    pub owner_subject: Id,
    pub signature: String,
}

impl NodeJoinRequest {
    pub fn validate_trusted_peer(peer: &str) -> io::Result<()> {
        let endpoint: EndpointId = peer.parse().map_err(io::Error::other)?;
        if endpoint.to_string() != peer {
            return Err(invalid("trusted peer endpoint ID must be canonical"));
        }
        Ok(())
    }

    pub(crate) fn validate(&self) -> io::Result<()> {
        let endpoint: EndpointId = self.endpoint_id.parse().map_err(io::Error::other)?;
        let peer: EndpointId = self.approving_peer.parse().map_err(io::Error::other)?;
        let key_id: Id = self.public_signer.kid.parse().map_err(io::Error::other)?;
        if self.purpose != PURPOSE
            || self.installation.trim().is_empty()
            || self.member_id.get_version_num() != 7
            || key_id.get_version_num() != 7
            || self.name.trim().is_empty()
            || self.name.len() > 256
            || endpoint.to_string() != self.endpoint_id
            || peer.to_string() != self.approving_peer
            || endpoint == peer
        {
            return Err(invalid("invalid equal-Node join binding"));
        }

        Ok(())
    }

    pub async fn send(&self, server: &Server, peer: EndpointAddr) -> io::Result<NodeJoinApproval> {
        self.validate()?;
        if server.endpoint().id().to_string() != self.endpoint_id
            || peer.id.to_string() != self.approving_peer
        {
            return Err(invalid(
                "join endpoint or pinned peer does not match request",
            ));
        }
        let reply = server
            .send_pairing_offer(peer, &serde_json::to_vec(self)?)
            .await?;
        let approval: NodeJoinApproval = serde_json::from_slice(&reply)?;
        approval.verify(self)?;
        Ok(approval)
    }
}

impl NodeJoinApproval {
    pub(crate) fn payload(request: &NodeJoinRequest, owner: Id) -> io::Result<Vec<u8>> {
        Ok(serde_json::to_vec(&(
            "of.equal-node-join-approval.v1",
            request,
            owner,
        ))?)
    }

    pub fn verify(&self, expected: &NodeJoinRequest) -> io::Result<()> {
        expected.validate()?;
        if self.request != *expected || self.owner_subject.is_nil() {
            return Err(invalid(
                "approval does not bind the exact persisted join request and owner",
            ));
        }
        let peer: EndpointId = expected.approving_peer.parse().map_err(io::Error::other)?;
        let signature = URL_SAFE_NO_PAD
            .decode(&self.signature)
            .map_err(io::Error::other)?;
        let signature = Signature::try_from(signature.as_slice()).map_err(io::Error::other)?;
        peer.verify(&Self::payload(expected, self.owner_subject)?, &signature)
            .map_err(io::Error::other)
    }
}

impl<P: PrivateKeyRepo + Send + Sync> OwnerProvisioner<P> {
    /// The peer must be explicitly trusted by the local setup operator, never taken from discovery.
    pub fn prepare_node_join(
        &self,
        binding: &NodeSignerBinding,
        name: &str,
        peer: EndpointId,
    ) -> io::Result<NodeJoinRequest> {
        let path = self.data_dir.join("node-join-request.json");
        let previous: Option<NodeJoinRequest> = read_optional(&path)?;
        if previous.is_some() {
            let namespace = format!(
                "{}:node:{}:{}",
                self.key_namespace, binding.member_id, binding.key_id
            );
            if self
                .oauth2
                .key_service
                .private_key_repo()
                .load(&namespace, &key::DerivationPath::default())
                .map_err(io::Error::other)?
                .is_none()
            {
                return Err(invalid(
                    "persisted join private signer is unavailable; explicit reset required",
                ));
            }
        }
        let request = NodeJoinRequest {
            purpose: PURPOSE.into(),
            installation: self.oauth2.oauth_config.issuer.clone(),
            member_id: binding.member_id,
            endpoint_id: binding.endpoint_id.clone(),
            name: name.into(),
            public_signer: self.prepare_node_signer(binding)?,
            approving_peer: peer.to_string(),
        };
        request.validate()?;
        if previous.as_ref().is_some_and(|value| value != &request) {
            return Err(invalid("join request conflicts with persisted setup"));
        }
        persist_exact(&path, &request)?;
        Ok(request)
    }

    /// Receipt persistence is not local membership, owner-policy bootstrap or completed readiness.
    pub fn record_node_join_approval(&self, approval: &NodeJoinApproval) -> io::Result<()> {
        let request: NodeJoinRequest =
            read_optional(&self.data_dir.join("node-join-request.json"))?
                .ok_or_else(|| invalid("no persisted join request"))?;
        approval.verify(&request)?;
        let binding = NodeSignerBinding {
            member_id: request.member_id,
            key_id: request
                .public_signer
                .kid
                .parse()
                .map_err(io::Error::other)?,
            endpoint_id: request.endpoint_id.clone(),
        };
        if self.prepare_node_join(
            &binding,
            &request.name,
            request.approving_peer.parse().map_err(io::Error::other)?,
        )? != request
        {
            return Err(invalid("local independent signer does not match approval"));
        }
        persist_exact(&self.data_dir.join("node-join-approval.json"), approval)
    }

    pub fn node_join_approval(&self) -> io::Result<Option<NodeJoinApproval>> {
        let approval: Option<NodeJoinApproval> =
            read_optional(&self.data_dir.join("node-join-approval.json"))?;
        if let Some(approval) = &approval {
            let request = read_optional(&self.data_dir.join("node-join-request.json"))?
                .ok_or_else(|| invalid("approval has no persisted request"))?;
            approval.verify(&request)?;
        }
        Ok(approval)
    }
}

fn read_optional<T: serde::de::DeserializeOwned>(path: &Path) -> io::Result<Option<T>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            serde_json::from_slice(&fs::read(path)?)
                .map(Some)
                .map_err(io::Error::other)
        }
        Ok(_) => Err(invalid("join journal must be a regular file")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn persist_exact<T: Serialize + serde::de::DeserializeOwned + PartialEq>(
    path: &Path,
    value: &T,
) -> io::Result<()> {
    if let Some(previous) = read_optional::<T>(path)? {
        return if previous == *value {
            fs::File::open(
                path.parent()
                    .ok_or_else(|| invalid("join journal has no parent"))?,
            )?
            .sync_all()
        } else {
            Err(invalid("persisted join journal conflicts"))
        };
    }
    let temporary = path.with_extension(format!("{}.tmp", Id::now_v7()));
    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(&serde_json::to_vec(value)?)?;
        file.sync_all()?;
        match fs::hard_link(&temporary, path) {
            Ok(()) => (),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                if read_optional::<T>(path)?.as_ref() != Some(value) {
                    return Err(invalid("concurrent join journal conflicts"));
                }
            }
            Err(error) => return Err(error),
        }
        fs::File::open(
            path.parent()
                .ok_or_else(|| invalid("join journal has no parent"))?,
        )?
        .sync_all()
    })();
    let cleanup = fs::remove_file(&temporary);
    result.and(cleanup)
}

#[cfg(test)]
mod setup_peer_tests {
    use super::NodeJoinRequest;

    #[test]
    fn trusted_peer_input_requires_a_canonical_endpoint_identity() {
        let peer = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        NodeJoinRequest::validate_trusted_peer(peer).expect("known Ed25519 endpoint identity");
        for invalid in [
            "",
            "discovered-peer",
            "https://peer.test",
            &peer.to_uppercase(),
        ] {
            assert!(NodeJoinRequest::validate_trusted_peer(invalid).is_err());
        }
    }
}

pub(crate) fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
