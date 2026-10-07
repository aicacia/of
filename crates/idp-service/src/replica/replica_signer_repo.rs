use std::sync::Arc;

use db::{Engine, EngineError, Kernel, RowCodec, SqlTranslator, Value};
use idp_model::contract::{IdpSignerRecord, JwsAlgorithm, KeyUse, ReplicaMembership};

use crate::repo::{RepoError, RepoResult};

pub struct DbReplicaSignerRepo<K, R>
where
    K: Kernel,
    R: RowCodec<K::Transaction> + Send + Sync,
{
    engine: Arc<Engine<K, R>>,
}

impl<K, R> DbReplicaSignerRepo<K, R>
where
    K: Kernel,
    R: RowCodec<K::Transaction> + Send + Sync,
{
    #[must_use]
    pub const fn new(engine: Arc<Engine<K, R>>) -> Self {
        Self { engine }
    }

    /// Store membership and its first approved signer as one unit. Returns `false` for an exact retry.
    pub async fn enroll(
        &self,
        membership: &ReplicaMembership,
        signer: &IdpSignerRecord,
    ) -> RepoResult<bool> {
        validate(membership, signer)?;
        let mut transaction = self.engine.transaction().await.map_err(db_error)?;
        let operation = async {
            let member_query = format!(
                "SELECT endpoint_id, issuer, approved_at, revoked_at FROM idp_replica_members WHERE installation_id = {} AND member_id = CAST('{}' AS UUID)",
                text(&membership.installation_id),
                membership.member_id,
            );
            let endpoint_query = format!(
                "SELECT member_id FROM idp_replica_members WHERE installation_id = {} AND endpoint_id = {}",
                text(&membership.installation_id),
                text(&membership.endpoint_id),
            );
            let signer_query = format!(
                "SELECT member_id, issuer, public_jwk, approved_at, revoked_at, expires_at FROM idp_replica_signers WHERE key_id = CAST('{}' AS UUID)",
                signer.key_id,
            );
            let active_signer_query = format!(
                "SELECT key_id FROM idp_replica_signers WHERE active_member_id = CAST('{}' AS UUID)",
                membership.member_id,
            );
            let mut query_results = transaction
                .translate_and_execute(
                    &format!(
                        "{member_query}; {endpoint_query}; {signer_query}; {active_signer_query}"
                    ),
                    &SqlTranslator,
                )
                .await
                .map_err(db_error)?;
            if query_results.len() != 4 {
                return Err(RepoError::InvalidInput(
                    "incomplete replica signer query results".into(),
                ));
            }
            let member = query_results.remove(0).rows.into_iter().next();
            let endpoint = query_results.remove(0).rows.into_iter().next();
            let signer_row = query_results.remove(0).rows.into_iter().next();
            let active_signer = query_results.remove(0).rows.into_iter().next();

            if let (Some(member), Some(signer_row)) = (member.as_ref(), signer_row.as_ref()) {
                if endpoint.as_ref().is_some_and(|row| {
                    matches!(row.values.first(), Some(Value::Uuid(id)) if *id == membership.member_id)
                }) && active_signer.as_ref().is_some_and(|row| {
                    matches!(row.values.first(), Some(Value::Uuid(id)) if *id == signer.key_id)
                }) && member_matches(member, membership)
                    && signer_matches(signer_row, signer)?
                {
                    return Ok(false);
                }
            }
            if member.is_some() || endpoint.is_some() || signer_row.is_some() || active_signer.is_some() {
                return Err(RepoError::InvalidInput(
                    "replica member, endpoint, or signer conflicts with approved state".into(),
                ));
            }

            let jwk = serde_json::to_string(&signer.public_jwk)
                .map_err(|error| RepoError::other(error))?;
            let insert_member = format!(
                "INSERT INTO idp_replica_members (id, installation_id, member_id, endpoint_id, issuer, approved_at, revoked_at) VALUES (CAST('{}' AS UUID), {}, CAST('{}' AS UUID), {}, {}, {}, NULL)",
                db::Uuid::now_v7(),
                text(&membership.installation_id),
                membership.member_id,
                text(&membership.endpoint_id),
                text(&membership.issuer),
                membership.approved_at,
            );
            let insert_signer = format!(
                "INSERT INTO idp_replica_signers (id, member_id, active_member_id, key_id, issuer, public_jwk, approved_at, revoked_at, expires_at) VALUES (CAST('{}' AS UUID), CAST('{}' AS UUID), CAST('{}' AS UUID), CAST('{}' AS UUID), {}, {}, {}, NULL, {})",
                db::Uuid::now_v7(),
                signer.member_id,
                signer.member_id,
                signer.key_id,
                text(&signer.issuer),
                text(&jwk),
                signer.approved_at.expect("validated approval timestamp"),
                signer.expires_at.map_or_else(|| "NULL".to_owned(), |expires| expires.to_string()),
            );
            transaction
                .translate_and_execute(&format!("{insert_member}; {insert_signer}"), &SqlTranslator)
                .await
                .map_err(db_error)?;
            Ok(true)
        }
        .await;

        match operation {
            Ok(created) => {
                transaction.commit().await.map_err(db_error)?;
                Ok(created)
            }
            Err(error) => {
                transaction.rollback().await.map_err(db_error)?;
                Err(error)
            }
        }
    }

    pub async fn rotate(
        &self,
        member_id: idp_model::model::Id,
        issuer: &str,
        signer: &IdpSignerRecord,
    ) -> RepoResult<bool> {
        let approved_at = validate_signer(signer, member_id, issuer)?;
        let mut transaction = self.engine.transaction().await.map_err(db_error)?;
        let operation = async {
            let mut results = transaction
                .translate_and_execute(
                    &format!(
                        "SELECT id FROM idp_replica_members WHERE installation_id = {} AND member_id = CAST('{}' AS UUID) AND revoked_at IS NULL; SELECT member_id, issuer, public_jwk, approved_at, revoked_at, expires_at FROM idp_replica_signers WHERE key_id = CAST('{}' AS UUID); SELECT key_id FROM idp_replica_signers WHERE active_member_id = CAST('{}' AS UUID)",
                        text(issuer), member_id, signer.key_id, member_id,
                    ),
                    &SqlTranslator,
                )
                .await
                .map_err(db_error)?;
            if results.len() != 3 {
                return Err(RepoError::InvalidInput("incomplete replica signer query results".into()));
            }
            let member_exists = !results.remove(0).rows.is_empty();
            let replacement = results.remove(0).rows.into_iter().next();
            let active = results.remove(0).rows.into_iter().next();
            if !member_exists {
                return Err(RepoError::InvalidInput("replica membership is not active".into()));
            }
            if let Some(active) = active.as_ref()
                && matches!(active.values.first(), Some(Value::Uuid(id)) if *id == signer.key_id)
                && let Some(replacement) = replacement.as_ref()
                && signer_matches(replacement, signer)?
            {
                return Ok(false);
            }
            if replacement.is_some() || active.is_none() {
                return Err(RepoError::InvalidInput("replacement signer conflicts with active state".into()));
            }
            transaction
                .translate_and_execute(
                    &format!(
                        "UPDATE idp_replica_signers SET revoked_at = {approved_at}, active_member_id = NULL WHERE active_member_id = CAST('{}' AS UUID)",
                        member_id,
                    ),
                    &SqlTranslator,
                )
                .await
                .map_err(db_error)?;
            let jwk = serde_json::to_string(&signer.public_jwk).map_err(RepoError::other)?;
            transaction
                .translate_and_execute(
                    &format!(
                        "INSERT INTO idp_replica_signers (id, member_id, active_member_id, key_id, issuer, public_jwk, approved_at, revoked_at, expires_at) VALUES (CAST('{}' AS UUID), CAST('{}' AS UUID), CAST('{}' AS UUID), CAST('{}' AS UUID), {}, {}, {}, NULL, {})",
                        db::Uuid::now_v7(), signer.member_id, signer.member_id, signer.key_id, text(&signer.issuer), text(&jwk), approved_at,
                        signer.expires_at.map_or_else(|| "NULL".to_owned(), |expires| expires.to_string()),
                    ),
                    &SqlTranslator,
                )
                .await
                .map_err(db_error)?;
            Ok(true)
        }
        .await;
        match operation {
            Ok(changed) => {
                transaction.commit().await.map_err(db_error)?;
                Ok(changed)
            }
            Err(error) => {
                transaction.rollback().await.map_err(db_error)?;
                Err(error)
            }
        }
    }

    pub async fn revoke(
        &self,
        member_id: idp_model::model::Id,
        issuer: &str,
        revoked_at: i64,
    ) -> RepoResult<bool> {
        let mut transaction = self.engine.transaction().await.map_err(db_error)?;
        let operation = async {
            let mut results = transaction
                .translate_and_execute(
                    &format!(
                        "SELECT id FROM idp_replica_members WHERE installation_id = {} AND member_id = CAST('{}' AS UUID) AND revoked_at IS NULL; SELECT key_id FROM idp_replica_signers WHERE active_member_id = CAST('{}' AS UUID)",
                        text(issuer), member_id, member_id,
                    ),
                    &SqlTranslator,
                )
                .await
                .map_err(db_error)?;
            if results.len() != 2 {
                return Err(RepoError::InvalidInput("incomplete replica signer query results".into()));
            }
            let member_exists = !results.remove(0).rows.is_empty();
            let active_exists = !results.remove(0).rows.is_empty();
            if !member_exists || !active_exists {
                return Ok(false);
            }
            transaction
                .translate_and_execute(
                    &format!(
                        "UPDATE idp_replica_signers SET revoked_at = {revoked_at}, active_member_id = NULL WHERE active_member_id = CAST('{}' AS UUID); UPDATE idp_replica_members SET revoked_at = {revoked_at} WHERE installation_id = {} AND member_id = CAST('{}' AS UUID) AND revoked_at IS NULL",
                        member_id, text(issuer), member_id,
                    ),
                    &SqlTranslator,
                )
                .await
                .map_err(db_error)?;
            Ok(true)
        }
        .await;
        match operation {
            Ok(changed) => {
                transaction.commit().await.map_err(db_error)?;
                Ok(changed)
            }
            Err(error) => {
                transaction.rollback().await.map_err(db_error)?;
                Err(error)
            }
        }
    }
}

fn validate(membership: &ReplicaMembership, signer: &IdpSignerRecord) -> RepoResult<()> {
    let approved_at = validate_signer(signer, membership.member_id, &membership.issuer)?;
    if membership.installation_id != membership.issuer
        || !membership.matches(
            &membership.installation_id,
            membership.member_id,
            &membership.endpoint_id,
        )
        || membership.approved_at != approved_at
    {
        return Err(RepoError::InvalidInput(
            "replica membership and signer binding is invalid".into(),
        ));
    }
    Ok(())
}

fn validate_signer(
    signer: &IdpSignerRecord,
    member_id: idp_model::model::Id,
    issuer: &str,
) -> RepoResult<i64> {
    let approved_at = signer
        .approved_at
        .ok_or_else(|| RepoError::InvalidInput("signer approval is required".into()))?;
    let valid_public_key = matches!(
        &signer.public_jwk.params,
        idp_model::contract::JwkPublicParameters::Ec { crv, .. } if crv == "secp256k1"
    ) && signer.public_jwk.r#use == KeyUse::Signature
        && signer.public_jwk.alg == JwsAlgorithm::EdDSA
        && crate::oauth2::verifing_key_from_jwt(&signer.public_jwk).is_ok();
    if signer.member_id != member_id
        || signer.issuer != issuer
        || signer.revoked_at.is_some()
        || signer.key_id.is_nil()
        || signer.public_jwk.kid != signer.key_id.to_string()
        || signer
            .expires_at
            .is_some_and(|expires| expires <= approved_at)
        || !valid_public_key
    {
        return Err(RepoError::InvalidInput(
            "replica signer binding or public key is invalid".into(),
        ));
    }
    Ok(approved_at)
}

fn member_matches(row: &db::Row, membership: &ReplicaMembership) -> bool {
    matches!(row.values.as_slice(), [Value::Text(endpoint), Value::Text(issuer), Value::Integer(_), Value::Null]
        if endpoint == &membership.endpoint_id && issuer == &membership.issuer)
}

fn signer_matches(row: &db::Row, signer: &IdpSignerRecord) -> RepoResult<bool> {
    let jwk = serde_json::to_string(&signer.public_jwk).map_err(RepoError::other)?;
    Ok(
        matches!(row.values.as_slice(), [Value::Uuid(member), Value::Text(issuer), Value::Text(saved_jwk), Value::Integer(_), Value::Null, expires]
        if *member == signer.member_id
            && issuer == &signer.issuer
            && saved_jwk == &jwk
            && match (expires, signer.expires_at) {
                (Value::Null, None) => true,
                (Value::Integer(saved), Some(expected)) => *saved == expected,
                _ => false,
            }),
    )
}

fn text(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn db_error(error: EngineError) -> RepoError {
    RepoError::other(error)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
    use db::{AutomergeRowCodec, Engine, InMemoryKernel, SqlTranslator, Value};
    use k256::ecdsa::SigningKey;

    use idp_model::{
        contract::{
            IdpSignerRecord, JwkPublic, JwkPublicParameters, JwsAlgorithm, KeyUse,
            ReplicaMembership,
        },
        model::Id,
        replica,
    };

    use super::DbReplicaSignerRepo;

    fn records() -> (ReplicaMembership, IdpSignerRecord) {
        let member_id = Id::from_u128(1);
        let key_id = Id::from_u128(2);
        let issuer = "https://installation.example".to_owned();
        let signing_key = SigningKey::from_slice(&[1_u8; 32])
            .expect("fixed test scalar is a valid secp256k1 key");
        let point = signing_key.verifying_key().to_encoded_point(false);
        let membership = ReplicaMembership {
            installation_id: issuer.clone(),
            member_id,
            endpoint_id: "endpoint-key".to_owned(),
            issuer: issuer.clone(),
            approved_at: 10,
            revoked_at: None,
        };
        let signer = IdpSignerRecord {
            member_id,
            key_id,
            issuer,
            public_jwk: JwkPublic {
                kid: key_id.to_string(),
                r#use: KeyUse::Signature,
                alg: JwsAlgorithm::EdDSA,
                params: JwkPublicParameters::Ec {
                    crv: "secp256k1".to_owned(),
                    x: STANDARD_NO_PAD.encode(point.x().expect("public point has x coordinate")),
                    y: STANDARD_NO_PAD.encode(point.y().expect("public point has y coordinate")),
                },
            },
            approved_at: Some(10),
            revoked_at: None,
            expires_at: None,
        };
        (membership, signer)
    }

    #[tokio::test]
    async fn enrollment_is_persistent_idempotent_and_rejects_conflicts() {
        let engine = Arc::new(Engine::new(InMemoryKernel::new(), AutomergeRowCodec::new()));
        replica::up(&engine).await.expect("initialize IdP schema");
        let repo = DbReplicaSignerRepo::new(engine.clone());
        let (membership, signer) = records();

        assert!(
            repo.enroll(&membership, &signer)
                .await
                .expect("enroll approved signer")
        );
        let mut retried_membership = membership.clone();
        retried_membership.approved_at = 11;
        let mut retried_signer = signer.clone();
        retried_signer.approved_at = Some(11);
        assert!(
            !repo
                .enroll(&retried_membership, &retried_signer)
                .await
                .expect("accept matching enrollment retry with a new server timestamp")
        );
        assert_eq!(
            engine
                .translate_and_execute("SELECT id FROM idp_replica_members", &SqlTranslator,)
                .await
                .expect("read membership rows")[0]
                .rows
                .len(),
            1
        );
        assert_eq!(
            engine
                .translate_and_execute("SELECT id FROM idp_replica_signers", &SqlTranslator,)
                .await
                .expect("read signer rows")[0]
                .rows
                .len(),
            1
        );

        let mut conflicting_endpoint = membership.clone();
        conflicting_endpoint.endpoint_id = "other-endpoint".to_owned();
        assert!(repo.enroll(&conflicting_endpoint, &signer).await.is_err());
        let mut conflicting_installation = membership.clone();
        conflicting_installation.installation_id = "https://other-installation.example".to_owned();
        assert!(
            repo.enroll(&conflicting_installation, &signer)
                .await
                .is_err()
        );

        let mut replacement = signer.clone();
        replacement.key_id = Id::from_u128(3);
        replacement.public_jwk.kid = replacement.key_id.to_string();
        replacement.approved_at = Some(20);
        assert!(
            repo.rotate(membership.member_id, &membership.issuer, &replacement)
                .await
                .expect("rotate signer")
        );
        assert!(
            !repo
                .rotate(membership.member_id, &membership.issuer, &replacement)
                .await
                .expect("accept matching rotation retry")
        );
        let signer_rows = engine
            .translate_and_execute(
                "SELECT key_id, revoked_at FROM idp_replica_signers ORDER BY key_id",
                &SqlTranslator,
            )
            .await
            .expect("read rotated signer trust")[0]
            .rows
            .clone();
        assert_eq!(signer_rows.len(), 2);
        assert!(matches!(
            signer_rows[0].values.get(1),
            Some(Value::Integer(20))
        ));
        assert!(matches!(signer_rows[1].values.get(1), Some(Value::Null)));
        assert!(
            repo.revoke(membership.member_id, &membership.issuer, 30)
                .await
                .expect("revoke member and signer")
        );
        assert!(
            !repo
                .revoke(membership.member_id, &membership.issuer, 31)
                .await
                .expect("accept repeated revocation")
        );
        let member_state = engine
            .translate_and_execute("SELECT revoked_at FROM idp_replica_members", &SqlTranslator)
            .await
            .expect("read revoked membership")[0]
            .rows
            .clone();
        assert!(matches!(
            member_state[0].values.first(),
            Some(Value::Integer(30))
        ));
    }
}
