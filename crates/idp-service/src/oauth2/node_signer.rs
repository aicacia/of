use alloc::{
    format,
    string::{String, ToString},
};

use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use idp_model::{
    contract::{JwkPrivate, JwkPrivateParameters, JwkPublic, JwsAlgorithm, KeyUse},
    model::Id,
};
use key::{DerivationPath, DerivedKey};

use crate::repo::{KeyRepo, KeyService, PrivateKeyRepo, RepoError, RepoResult};

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeSignerBinding {
    pub member_id: Id,
    pub key_id: Id,
    pub endpoint_id: String,
}

impl<R: KeyRepo, P: PrivateKeyRepo> KeyService<R, P> {
    fn node_namespace(&self, binding: &NodeSignerBinding) -> String {
        format!(
            "{}:node:{}:{}",
            self.namespace(),
            binding.member_id,
            binding.key_id
        )
    }

    pub fn prepare_node_signer(&self, binding: &NodeSignerBinding) -> RepoResult<JwkPublic> {
        if binding.member_id.is_nil()
            || binding.key_id.is_nil()
            || binding.endpoint_id.trim().is_empty()
        {
            return Err(RepoError::InvalidInput(
                "node signer binding is incomplete".into(),
            ));
        }
        let private = self
            .private_key_repo()
            .ensure_master_key(&self.node_namespace(binding))?;
        Ok(private_jwk(binding, &private)?.into())
    }

    pub async fn load_node_signer(
        &self,
        binding: &NodeSignerBinding,
        issuer: &str,
        now: i64,
    ) -> RepoResult<JwkPrivate> {
        let trusted = self.key_repo().trusted_node_signers(issuer, now).await?;
        let record = trusted
            .iter()
            .find(|(member, signer)| {
                member.matches(issuer, binding.member_id, &binding.endpoint_id)
                    && signer.matches(binding.member_id, binding.key_id, issuer, now)
            })
            .ok_or_else(|| {
                RepoError::InvalidInput("local node signer is not approved and active".into())
            })?;
        let private = self
            .private_key_repo()
            .load(&self.node_namespace(binding), &DerivationPath::default())?
            .ok_or_else(|| {
                RepoError::InvalidInput("local node private signer is missing".into())
            })?;
        let jwk = private_jwk(binding, &private)?;
        if JwkPublic::from(jwk.clone()) != record.1.public_jwk {
            return Err(RepoError::InvalidInput(
                "local node private signer does not match approved public material".into(),
            ));
        }
        Ok(jwk)
    }
}

fn private_jwk(binding: &NodeSignerBinding, private: &DerivedKey) -> RepoResult<JwkPrivate> {
    let (x, y, d) = private.to_xyd()?;
    Ok(JwkPrivate {
        kid: binding.key_id.to_string(),
        r#use: KeyUse::Signature,
        alg: JwsAlgorithm::ES256K,
        params: JwkPrivateParameters::Ec {
            crv: "secp256k1".into(),
            x: STANDARD_NO_PAD.encode(x),
            y: STANDARD_NO_PAD.encode(y),
            d: STANDARD_NO_PAD.encode(d),
        },
    })
}
