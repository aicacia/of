use std::io;

use db::{SqlTranslator, Value};
use idp_model::contract::{
    IdentityAction, IdentityResource, IdpSignerRecord, PermissionTarget, ReplicaMembership,
};
use iroh_chain::PairingOffer;

use super::middleware::require_identity_permission;
use crate::{NodeJoinApproval, NodeJoinRequest, RouterState, authorize_bearer, node_join::invalid};

impl RouterState {
    /// Approves only an authenticated pairing offer using a locally authenticated User session.
    /// A successful reply proves enrollment, not bootstrap of all contexts on the joining Node.
    pub async fn approve_node_join(
        &self,
        offer: &PairingOffer,
        bearer: &str,
    ) -> io::Result<NodeJoinApproval> {
        let actor = authorize_bearer(self, bearer).await.map_err(auth_error)?;
        for (action, resource) in [
            (
                IdentityAction::DevicePairingUpdate,
                IdentityResource::DevicePairing,
            ),
            (
                IdentityAction::ReplicaSignersEnroll,
                IdentityResource::ReplicaSigner { member_id: None },
            ),
        ] {
            require_identity_permission(
                self,
                &actor,
                action,
                PermissionTarget::Installation { resource },
            )
            .await
            .map_err(auth_error)?;
        }
        let request: NodeJoinRequest = serde_json::from_slice(&offer.payload)?;
        request.validate()?;
        let issuer = self.oauth2_service.metadata().issuer;
        if request.installation != issuer
            || request.endpoint_id != offer.remote_id.to_string()
            || request.approving_peer != self.device_identity.endpoint_id().to_string()
        {
            return Err(invalid(
                "join Installation or authenticated endpoint binding mismatch",
            ));
        }
        let now: i64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_secs()
            .try_into()
            .map_err(io::Error::other)?;
        if !self
            .replica_signers
            .trusted_signers(&issuer, now)
            .await
            .map_err(io::Error::other)?
            .iter()
            .any(|(member, _)| member.endpoint_id == request.approving_peer)
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "approving endpoint is not a locally trusted Node",
            ));
        }
        let owner = actor.principal.get_entity_id();
        // A signer-only interruption is not admission; persist the exact owner intent before enrollment.
        self.ensure_join_device(&request, owner, false, now).await?;
        self.persist_join_intent(&request, owner).await?;
        self.replica_signers
            .enroll(
                &ReplicaMembership {
                    installation_id: issuer.clone(),
                    member_id: request.member_id,
                    endpoint_id: request.endpoint_id.clone(),
                    issuer: issuer.clone(),
                    approved_at: now,
                    revoked_at: None,
                },
                &IdpSignerRecord {
                    member_id: request.member_id,
                    key_id: request
                        .public_signer
                        .kid
                        .parse()
                        .map_err(io::Error::other)?,
                    issuer: issuer.clone(),
                    public_jwk: request.public_signer.clone(),
                    approved_at: Some(now),
                    revoked_at: None,
                    expires_at: None,
                },
            )
            .await
            .map_err(io::Error::other)?;
        self.ensure_join_device(&request, owner, true, now).await?;
        if !self
            .replica_signers
            .is_trusted_peer(&issuer, request.member_id, &request.endpoint_id, now)
            .await
            .map_err(io::Error::other)?
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "join enrollment is not conflict-clear trusted state",
            ));
        }
        let approval = self.device_identity.node_join_approval(request, owner)?;
        offer.reply(&serde_json::to_vec(&approval)?).await?;
        Ok(approval)
    }

    async fn persist_join_intent(
        &self,
        request: &NodeJoinRequest,
        owner: idp_model::model::Id,
    ) -> io::Result<()> {
        self.engine.client().translate_and_execute(
            "CREATE TABLE IF NOT EXISTS local_node_join_intents (id UUID PRIMARY KEY, binding TEXT NOT NULL)",
            &SqlTranslator,
        ).await.map_err(io::Error::other)?;
        let binding = String::from_utf8(NodeJoinApproval::payload(request, owner)?)
            .map_err(io::Error::other)?;
        let mut transaction = self
            .engine
            .client()
            .transaction()
            .await
            .map_err(io::Error::other)?;
        let result = async {
            let rows = transaction.translate_and_execute(&format!(
                "SELECT binding FROM local_node_join_intents WHERE id = CAST('{}' AS UUID)", request.member_id,
            ), &SqlTranslator).await.map_err(io::Error::other)?;
            match rows[0].rows.as_slice() {
                [] => {
                    transaction.translate_and_execute(&format!(
                        "INSERT INTO local_node_join_intents (id, binding) VALUES (CAST('{}' AS UUID), {})", request.member_id, text(&binding),
                    ), &SqlTranslator).await.map_err(io::Error::other)?;
                    Ok(())
                }
                [row] if row.values == [Value::Text(binding)] => Ok(()),
                _ => Err(invalid("join request or owner conflicts with persisted approval intent")),
            }
        }.await;
        match result {
            Ok(()) => transaction.commit().await.map_err(io::Error::other),
            Err(error) => {
                transaction.rollback().await.map_err(io::Error::other)?;
                Err(error)
            }
        }
    }

    async fn ensure_join_device(
        &self,
        request: &NodeJoinRequest,
        owner: idp_model::model::Id,
        create: bool,
        now: i64,
    ) -> io::Result<()> {
        let mut transaction = self
            .engine
            .client()
            .transaction()
            .await
            .map_err(io::Error::other)?;
        let result = async {
            let rows = transaction.translate_and_execute(&format!(
                "SELECT id, owner_subject, name, public_key, state, revoked_at FROM devices WHERE id = CAST('{}' AS UUID) OR public_key = {}",
                request.member_id, text(&request.endpoint_id)), &SqlTranslator).await.map_err(io::Error::other)?;
            if !rows[0].rows.is_empty() {
                if rows[0].rows.len() != 1 || rows[0].rows[0].values != [
                    Value::Uuid(request.member_id), Value::Text(owner.to_string()),
                    Value::Text(request.name.clone()), Value::Text(request.endpoint_id.clone()),
                    Value::Integer(1), Value::Null,
                ] { return Err(invalid("join Device conflicts with current approved owner state")); }
                let row = idp_model::replica::SecurityRow::new(idp_model::replica::SecurityTable::Device, request.member_id);

                Ok(Some(row))
            } else {
                if create {
                    transaction.translate_and_execute(&format!(
                        "INSERT INTO devices (id, owner_subject, name, public_key, address, state, approved_at, revoked_at, created_at, updated_at) VALUES (CAST('{}' AS UUID), {}, {}, {}, '', 1, {now}, NULL, {now}, {now})",
                        request.member_id, text(&owner.to_string()), text(&request.name), text(&request.endpoint_id)), &SqlTranslator).await.map_err(io::Error::other)?;
                }
                Ok(None)
            }
        }.await;
        match result {
            Ok(row) => {
                transaction.commit().await.map_err(io::Error::other)?;
                if let Some(row) = row
                    && !idp_model::replica::allows_authorization(&self.engine, &[row])
                        .await
                        .map_err(io::Error::other)?
                {
                    return Err(invalid("join Device has unresolved owner conflicts"));
                }
                Ok(())
            }
            Err(error) => {
                transaction.rollback().await.map_err(io::Error::other)?;
                Err(error)
            }
        }
    }
}

fn text(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}
fn auth_error(error: idp_model::contract::ErrorResponse) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("join authorization denied: {:?}", error.error),
    )
}
