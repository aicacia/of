use std::io;

use db::{Row, SqlTranslator, Transaction, Value};
use idp_model::{
    contract::{
        IdentityAction, IdentityResource, IdpSignerRecord, PermissionTarget, ReplicaMembership,
    },
    model::Id,
};
use idp_service::replica::DbReplicaSignerRepo;
use iroh_chain::{MAX_PAIRING_PAYLOAD_LENGTH, PairingOffer};

use super::middleware::require_identity_permission;
use crate::{NodeJoinApproval, NodeJoinRequest, RouterState, authorize_bearer, node_join::invalid};

impl RouterState {
    /// Approves only an authenticated pairing offer using a locally authenticated User session.
    /// A successful reply proves enrollment, not bootstrap of all contexts on the joining Node.
    pub async fn authorize_node_join_approver(&self, bearer: &str) -> io::Result<Id> {
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
        Ok(actor.principal.get_entity_id())
    }

    pub async fn approve_node_join(
        &self,
        offer: &PairingOffer,
        bearer: &str,
    ) -> io::Result<NodeJoinApproval> {
        let owner = self.authorize_node_join_approver(bearer).await?;
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
        let approval = self.device_identity.node_join_approval(request, owner)?;
        let reply = serde_json::to_vec(&approval)?;
        if reply.len() > MAX_PAIRING_PAYLOAD_LENGTH {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "signed join approval exceeds the pairing payload limit",
            ));
        }
        #[cfg(test)]
        if let Some((reached, resume)) = &self.before_node_join_activation {
            reached.notify_one();
            resume.notified().await;
        }
        self.enroll_node_join(&approval.request, owner, now).await?;
        offer.reply(&reply).await?;
        Ok(approval)
    }

    async fn enroll_node_join(
        &self,
        request: &NodeJoinRequest,
        owner: Id,
        now: i64,
    ) -> io::Result<()> {
        let membership = ReplicaMembership {
            installation_id: request.installation.clone(),
            member_id: request.member_id,
            endpoint_id: request.endpoint_id.clone(),
            issuer: request.installation.clone(),
            approved_at: now,
            revoked_at: None,
        };
        let signer = IdpSignerRecord {
            member_id: request.member_id,
            key_id: request
                .public_signer
                .kid
                .parse()
                .map_err(io::Error::other)?,
            issuer: request.installation.clone(),
            public_jwk: request.public_signer.clone(),
            approved_at: Some(now),
            revoked_at: None,
            expires_at: None,
        };
        let mut transaction = self
            .engine
            .client()
            .transaction()
            .await
            .map_err(io::Error::other)?;
        let result = async {
            ensure_join_device(&mut transaction, request, owner, now).await?;
            persist_join_intent(&mut transaction, request, owner).await?;
            DbReplicaSignerRepo::enroll_in_transaction(&mut transaction, &membership, &signer)
                .await
                .map_err(io::Error::other)?;
            for (table, query) in [
                (
                    "idp_replica_members",
                    format!(
                        "SELECT id FROM idp_replica_members WHERE member_id = CAST('{}' AS UUID)",
                        request.member_id
                    ),
                ),
                (
                    "idp_replica_signers",
                    format!(
                        "SELECT id FROM idp_replica_signers WHERE active_member_id = CAST('{}' AS UUID)",
                        request.member_id
                    ),
                ),
            ] {
                let results = transaction
                    .translate_and_execute(&query, &SqlTranslator)
                    .await
                    .map_err(io::Error::other)?;
                let [row] = results[0].rows.as_slice() else {
                    return Err(invalid("join enrollment is not unique"));
                };
                require_clear(&transaction, table, row).await?;
            }
            Ok(())
        }
        .await;
        match result {
            Ok(()) => transaction.commit().await.map_err(io::Error::other),
            Err(error) => {
                transaction.rollback().await.map_err(io::Error::other)?;
                Err(error)
            }
        }
    }
}

async fn persist_join_intent(
    transaction: &mut Transaction,
    request: &NodeJoinRequest,
    owner: Id,
) -> io::Result<()> {
    transaction.translate_and_execute(
        "CREATE TABLE IF NOT EXISTS local_node_join_intents (id UUID PRIMARY KEY, binding TEXT NOT NULL)",
        &SqlTranslator,
    ).await.map_err(io::Error::other)?;
    let binding =
        String::from_utf8(NodeJoinApproval::payload(request, owner)?).map_err(io::Error::other)?;
    let rows = transaction
        .translate_and_execute(
            &format!(
                "SELECT binding FROM local_node_join_intents WHERE id = CAST('{}' AS UUID)",
                request.member_id,
            ),
            &SqlTranslator,
        )
        .await
        .map_err(io::Error::other)?;
    match rows[0].rows.as_slice() {
        [] => {
            transaction.translate_and_execute(&format!(
                "INSERT INTO local_node_join_intents (id, binding) VALUES (CAST('{}' AS UUID), {})", request.member_id, text(&binding),
            ), &SqlTranslator).await.map_err(io::Error::other)?;
        }
        [row] if row.values == [Value::Text(binding)] => (),
        _ => {
            return Err(invalid(
                "join request or owner conflicts with persisted approval intent",
            ));
        }
    }
    require_clear(
        transaction,
        "local_node_join_intents",
        &Row::new(vec![Value::Uuid(request.member_id)]),
    )
    .await
}

async fn ensure_join_device(
    transaction: &mut Transaction,
    request: &NodeJoinRequest,
    owner: Id,
    now: i64,
) -> io::Result<()> {
    let rows = transaction.translate_and_execute(&format!(
        "SELECT id, owner_subject, name, public_key, state, revoked_at FROM devices WHERE id = CAST('{}' AS UUID) OR public_key = {}",
        request.member_id, text(&request.endpoint_id)), &SqlTranslator).await.map_err(io::Error::other)?;
    if rows[0].rows.is_empty() {
        transaction.translate_and_execute(&format!(
            "INSERT INTO devices (id, owner_subject, name, public_key, address, state, approved_at, revoked_at, created_at, updated_at) VALUES (CAST('{}' AS UUID), {}, {}, {}, '', 1, {now}, NULL, {now}, {now})",
            request.member_id, text(&owner.to_string()), text(&request.name), text(&request.endpoint_id)), &SqlTranslator).await.map_err(io::Error::other)?;
    } else if rows[0].rows.len() != 1
        || rows[0].rows[0].values
            != [
                Value::Uuid(request.member_id),
                Value::Text(owner.to_string()),
                Value::Text(request.name.clone()),
                Value::Text(request.endpoint_id.clone()),
                Value::Integer(1),
                Value::Null,
            ]
    {
        return Err(invalid(
            "join Device conflicts with current approved owner state",
        ));
    }
    require_clear(
        transaction,
        "devices",
        &Row::new(vec![Value::Uuid(request.member_id)]),
    )
    .await
}

async fn require_clear(transaction: &Transaction, table: &str, key: &Row) -> io::Result<()> {
    if !transaction
        .row_conflicts(table, key)
        .await
        .map_err(io::Error::other)?
        .is_empty()
    {
        return Err(invalid("join enrollment has unresolved owner conflicts"));
    }
    Ok(())
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
