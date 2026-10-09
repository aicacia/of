use std::{io, sync::Arc};

use db::{Database, Row, SqlTranslator, Value};
use idp_model::{contract::JwkPublic, model::Id};
use idp_service::{oauth2::NodeSignerBinding, repo::PrivateKeyRepo};

use super::{NodeJoinApproval, invalid, persist_exact, read_optional};
use crate::OwnerProvisioner;

#[derive(Clone, Copy)]
pub enum NodeJoinStage {
    Idp,
    Management,
    PublicReady,
}

impl NodeJoinStage {
    fn file(self) -> &'static str {
        match self {
            Self::Idp => "node-join-idp-import.json",
            Self::Management => "node-join-policy-import.json",
            Self::PublicReady => "node-join-public-ready.json",
        }
    }
}

impl<P: PrivateKeyRepo + Send + Sync> OwnerProvisioner<P> {
    pub fn node_join_database(&self) -> Arc<Database> {
        self.engine.clone()
    }

    pub fn node_join_anchor(&self) -> io::Result<NodeJoinApproval> {
        let approval = self
            .node_join_approval()?
            .ok_or_else(|| invalid("no verified persisted join approval"))?;
        let request = &approval.request;
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
        )? != *request
        {
            return Err(invalid(
                "join anchor does not match retained local private signer",
            ));
        }
        Ok(approval)
    }

    /// Owner-local import journal only; this is not permission or a readiness decision.
    pub fn record_node_join_stage(&self, stage: NodeJoinStage) -> io::Result<()> {
        let anchor = self.node_join_anchor()?;
        persist_exact(&self.data_dir.join(stage.file()), &anchor)
    }

    pub fn node_join_stage_recorded(&self, stage: NodeJoinStage) -> io::Result<bool> {
        let anchor = self.node_join_anchor()?;
        let previous: Option<NodeJoinApproval> = read_optional(&self.data_dir.join(stage.file()))?;
        match previous {
            Some(previous) if previous != anchor => Err(invalid(
                "join import journal conflicts with persisted anchor",
            )),
            previous => Ok(previous.is_some()),
        }
    }

    /// Missing public rows may be pending; present contradictions and learned revocation deny.
    pub async fn check_node_join_local_binding(&self) -> io::Result<()> {
        let anchor = self.node_join_anchor()?;
        let request = &anchor.request;
        let member = request.member_id;
        let key: Id = request
            .public_signer
            .kid
            .parse()
            .map_err(io::Error::other)?;
        let issuer = Value::Text(request.installation.clone());
        let mut transaction = self
            .engine
            .client()
            .transaction()
            .await
            .map_err(io::Error::other)?;
        let result = async {
            for (table, predicate, columns, expected) in [
                ("devices", format!("id = CAST('{member}' AS UUID)"),
                 vec!["owner_subject", "name", "public_key", "state", "revoked_at"],
                 vec![Value::Text(anchor.owner_subject.to_string()), Value::Text(request.name.clone()), Value::Text(request.endpoint_id.clone()), Value::Integer(1), Value::Null]),
                ("idp_replica_members", format!("member_id = CAST('{member}' AS UUID) OR endpoint_id = '{}'", request.endpoint_id),
                 vec!["installation_id", "member_id", "endpoint_id", "issuer", "revoked_at"],
                 vec![issuer.clone(), Value::Uuid(member), Value::Text(request.endpoint_id.clone()), issuer.clone(), Value::Null]),
                ("idp_replica_signers", format!("key_id = CAST('{key}' AS UUID) OR active_member_id = CAST('{member}' AS UUID)"),
                 vec!["member_id", "active_member_id", "key_id", "issuer", "public_jwk", "revoked_at"],
                 vec![Value::Uuid(member), Value::Uuid(member), Value::Uuid(key), issuer.clone(), Value::Text(serde_json::to_string(&request.public_signer)?), Value::Null]),
            ] {
                let results = transaction.translate_and_execute(&format!("SELECT id, {} FROM {table} WHERE {predicate}", columns.join(", ")), &SqlTranslator).await.map_err(io::Error::other)?;
                if results[0].rows.len() > 1 {
                    return Err(invalid("non-unique local join binding"));
                }
                for row in &results[0].rows {
                    let id = row.values.first().ok_or_else(|| invalid("missing join row identity"))?;
                    let conflicts = transaction.row_conflicts(table, &Row::new(vec![id.clone()])).await.map_err(io::Error::other)?;
                    if !conflicts.is_empty() {
                        return Err(invalid("conflicted local join binding"));
                    }
                    for ((column, value), expected) in columns.iter().zip(&row.values[1..]).zip(&expected) {
                        if *column == "public_jwk" {
                            if let Value::Text(text) = value {
                                let public: JwkPublic = serde_json::from_str(text)?;
                                if public != request.public_signer { return Err(invalid("local join public signer changed")); }
                            } else if value != &Value::Null { return Err(invalid("invalid local join public signer")); }
                        } else if (*column == "revoked_at" && value != &Value::Null)
                            || (value != &Value::Null && value != expected) {
                            return Err(invalid("local join binding changed or revoked"));
                        }
                    }
                }
            }
            Ok(())
        }.await;
        transaction.rollback().await.map_err(io::Error::other)?;
        result
    }
}
