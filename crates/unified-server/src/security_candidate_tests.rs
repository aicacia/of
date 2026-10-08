use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use db::{Database, Row, Value};
use idp_model::model::Id;
use ofdb_sql::{SyncMessage, SyncRole};

use super::{Pair, Poison, RecoveryAttack, public_jwk, sync_fixture, unvalidated_initiate};
use crate::{
    SecurityContext,
    security_sync_tests::{enroll, sql},
};

struct ExtraMember {
    member: Id,
    membership: Id,
    signer: Id,
}

async fn seed(database: &Arc<Database>) -> ExtraMember {
    let member = Id::now_v7();
    let key = Id::now_v7();
    let endpoint = iroh::SecretKey::generate().public().to_string();
    let owner = sql(database, "SELECT owner_subject FROM devices LIMIT 1").await[0].rows[0].values
        [0]
    .clone();
    let Value::Text(owner) = owner else {
        panic!("fixture owner")
    };
    sql(database, &format!("INSERT INTO devices (id, owner_subject, name, public_key, address, state, approved_at, created_at, updated_at) VALUES (CAST('{member}' AS UUID), '{owner}', 'extra', '{endpoint}', 'local', 1, 1, 1, 1)")).await;
    enroll(
        database.clone(),
        member,
        endpoint.parse().expect("fixture endpoint"),
        key,
    )
    .await;
    let Value::Uuid(signer) = sql(
        database,
        &format!("SELECT id FROM idp_replica_signers WHERE member_id = CAST('{member}' AS UUID)"),
    )
    .await[0]
        .rows[0]
        .values[0]
    else {
        panic!("fixture signer")
    };
    let Value::Uuid(membership) = sql(
        database,
        &format!("SELECT id FROM idp_replica_members WHERE member_id = CAST('{member}' AS UUID)"),
    )
    .await[0]
        .rows[0]
        .values[0]
    else {
        panic!("fixture membership")
    };
    ExtraMember {
        member,
        membership,
        signer,
    }
}

#[tokio::test]
async fn marker3_revalidates_semantic_recovery_and_preserves_local_contender() {
    tokio::time::timeout(Duration::from_secs(600), async {
        for contender in [false, true] {
            for outgoing in [true, false] {
                if contender && outgoing { continue; }
                for role in [SyncRole::Initiator, SyncRole::Responder] {
                    let mut pair = Pair::new().await;
                    let source_is_a = outgoing == matches!(role, SyncRole::Initiator);
                    let (source, target) = if source_is_a {
                        (pair.idp_a.clone(), pair.idp_b.clone())
                    } else {
                        (pair.idp_b.clone(), pair.idp_a.clone())
                    };
                    let extra = seed(&source).await;
                    sync_fixture(&source, &target).await;
                    let query = format!("SELECT * FROM idp_replica_signers WHERE id = CAST('{}' AS UUID)", extra.signer);
                    let before = sql(&target, &query).await[0].rows.clone();
                    if contender {
                        sql(&source, &format!("UPDATE idp_replica_signers SET expires_at = 9999999999 WHERE id = CAST('{}' AS UUID)", extra.signer)).await;
                    }
                    let statement = corruption(&extra, if contender { Attack::Endpoint } else { Attack::Kid });
                    let fired = Arc::new(AtomicBool::new(false));
                    pair.recovery = Some(RecoveryAttack {
                        source: if contender { target.clone() } else { source.clone() },
                        root: pair.root.clone(), row: extra.signer, variant: Poison::Current,
                        semantic: Some(("idp_replica_signers".into(), statement)),
                        before_payload: contender,
                        on_send: contender || outgoing, fired: fired.clone(),
                    });
                    pair.serve(matches!(role, SyncRole::Responder));
                    let connection = pair.connect().await;
                    let error = match role {
                        SyncRole::Initiator => pair.protocol_a.synchronize(&connection, SecurityContext::Idp).await,
                        SyncRole::Responder => unvalidated_initiate(&pair, &connection).await,
                    }.expect_err("late recovery candidate must reject");
                    assert!(fired.load(Ordering::SeqCst), "clean preflight reaches recovery {contender}/{outgoing}/{role:?}: {error}");
                    if matches!(role, SyncRole::Initiator) && (outgoing || contender) {
                        assert!(error.to_string().contains("invalid public security candidate"), "domain candidate gate: {error}");
                    }
                    if !outgoing && !contender && matches!(role, SyncRole::Initiator) {
                        assert!(error.to_string().contains("Unexpected or duplicate recovery snapshot"), "unsolicited incoming recovery is integrity rejection, not domain-gate proof: {error}");
                    }
                    assert_eq!(sql(&target, &query).await[0].rows, before, "invalid recovery batch rolls back");
                    if contender {
                        let device = sql(&target, &format!("SELECT public_key FROM devices WHERE id = CAST('{}' AS UUID)", extra.member)).await;
                        let member = sql(&source, &format!("SELECT endpoint_id FROM idp_replica_members WHERE id = CAST('{}' AS UUID)", extra.membership)).await;
                        assert_ne!(device[0].rows[0].values[0], member[0].rows[0].values[0], "independent local contender survives rollback");
                    }
                    if outgoing {
                        assert!(!pair.received.lock().expect("wire frames").iter().any(|frame| matches!(postcard::from_bytes::<SyncMessage>(frame), Ok(SyncMessage::State(_) | SyncMessage::Changes(_)))), "late invalid recovery never disclosed");
                    }
                    drop((source, target));
                    pair.close().await;
                }
            }
        }
    }).await.expect("bounded genuine recovery/current-contender matrix");
}

#[tokio::test]
async fn marker3_persists_pending_conflicts_and_tombstones_without_trust() {
    tokio::time::timeout(Duration::from_secs(180), async {
        let mut pair = Pair::new().await;
        let pending = seed(&pair.idp_a).await;
        let conflicted = seed(&pair.idp_a).await;
        let fork = Database::open(pair.root.join("candidate-fork.redb")).expect("independent native contender");
        idp_model::replica::up(&fork).await.expect("public schema");
        sync_fixture(&pair.idp_a, &fork).await;
        for database in [pair.idp_a.as_ref(), &fork] {
            let endpoint = iroh::SecretKey::generate().public();
            sql(database, &format!("UPDATE devices SET public_key = '{endpoint}' WHERE id = CAST('{}' AS UUID); UPDATE idp_replica_members SET endpoint_id = '{endpoint}' WHERE id = CAST('{}' AS UUID)", conflicted.member, conflicted.membership)).await;
        }
        sync_fixture(&pair.idp_a, &fork).await;
        sql(&pair.idp_a, &format!("DELETE FROM devices WHERE id = CAST('{}' AS UUID); DELETE FROM idp_replica_members WHERE id = CAST('{}' AS UUID); UPDATE idp_replica_signers SET active_member_id = NULL, revoked_at = 2 WHERE id = CAST('{}' AS UUID)", pending.member, pending.membership, pending.signer)).await;
        pair.serve(true);
        let connection = pair.connect().await;
        pair.protocol_a.synchronize(&connection, SecurityContext::Idp).await.expect("pending/conflicted/revoked history may persist");
        assert!(pair.idp_b.client().row_conflicts("devices", &Row::new(vec![Value::Uuid(conflicted.member)])).await.expect("public conflict inspection").contains(&"public_key".to_string()));
        for member in [pending.member, conflicted.member] {
            assert!(!idp_service::replica::DbReplicaSignerRepo::new(pair.idp_b.clone()).trusted_signers(super::INSTALLATION, 10).await.expect("durable local trust evaluation").iter().any(|(entry, _)| entry.member_id == member), "persistence does not grant trust/readiness");
        }
        assert!(sql(&pair.idp_b, &format!("SELECT * FROM devices WHERE id = CAST('{}' AS UUID)", pending.member)).await[0].rows.is_empty(), "tombstone retained");
        let signer = sql(&pair.idp_b, &format!("SELECT revoked_at FROM idp_replica_signers WHERE id = CAST('{}' AS UUID)", pending.signer)).await;
        assert_eq!(signer[0].rows[0].values[0], Value::Integer(2), "revocation retained");
        drop(fork);
        pair.close().await;
    }).await.expect("bounded genuine pending/conflict/revocation exchange");
}

#[tokio::test]
async fn marker3_rejects_correlated_rebinding_of_authenticated_session_peer() {
    tokio::time::timeout(Duration::from_secs(240), async {
        for endpoint in [false, true] {
            for role in [SyncRole::Initiator, SyncRole::Responder] {
                let mut pair = Pair::new().await;
                let (source, target, member) = match role {
                    SyncRole::Initiator => (pair.idp_b.clone(), pair.idp_a.clone(), pair.member_b),
                    SyncRole::Responder => (pair.idp_a.clone(), pair.idp_b.clone(), pair.member_a),
                };
                let query = format!("SELECT id, owner_subject, public_key FROM devices WHERE id = CAST('{member}' AS UUID)");
                let before = sql(&target, &query).await[0].rows.clone();
                if endpoint {
                    let replacement = iroh::SecretKey::generate().public();
                    sql(&source, &format!("UPDATE devices SET public_key = '{replacement}' WHERE id = CAST('{member}' AS UUID); UPDATE idp_replica_members SET endpoint_id = '{replacement}' WHERE member_id = CAST('{member}' AS UUID)")).await;
                } else {
                    let owner = Id::now_v7();
                    sql(&source, &format!("INSERT INTO users (id, handle, name, created_at, updated_at) VALUES (CAST('{owner}' AS UUID), 'replacement', 'Replacement', 1, 1); UPDATE devices SET owner_subject = '{owner}' WHERE id = CAST('{member}' AS UUID)")).await;
                }
                let source_before = source.sync_manifest().await.expect("source manifest");
                pair.serve(matches!(role, SyncRole::Responder));
                let connection = pair.connect().await;
                match role {
                    SyncRole::Initiator => pair.protocol_a.synchronize(&connection, SecurityContext::Idp).await,
                    SyncRole::Responder => unvalidated_initiate(&pair, &connection).await,
                }.expect_err("correlated rows cannot rebind authenticated session evidence");
                assert_eq!(sql(&target, &query).await[0].rows, before, "pinned Device batch rolls back");
                assert_eq!(source.sync_manifest().await.expect("unchanged source"), source_before);
                drop((source, target));
                pair.close().await;
            }
        }
    }).await.expect("bounded genuine pinned session binding matrix");
}

#[derive(Clone, Copy, Debug)]
enum Attack {
    Kid,
    ActiveMember,
    Endpoint,
    HistoricalIssuer,
}

fn corruption(extra: &ExtraMember, attack: Attack) -> String {
    match attack {
        Attack::Kid => format!(
            "UPDATE idp_replica_signers SET public_jwk = '{}' WHERE id = CAST('{}' AS UUID)",
            public_jwk(&Id::now_v7().to_string()),
            extra.signer
        ),
        Attack::ActiveMember => format!(
            "UPDATE idp_replica_signers SET active_member_id = CAST('{}' AS UUID) WHERE id = CAST('{}' AS UUID)",
            Id::now_v7(),
            extra.signer
        ),
        Attack::Endpoint => format!(
            "UPDATE devices SET public_key = '{}' WHERE id = CAST('{}' AS UUID)",
            iroh::SecretKey::generate().public(),
            extra.member
        ),
        Attack::HistoricalIssuer => format!(
            "UPDATE idp_replica_members SET issuer = 'https://foreign.example' WHERE id = CAST('{}' AS UUID); UPDATE idp_replica_members SET issuer = '{}' WHERE id = CAST('{}' AS UUID)",
            extra.membership,
            super::INSTALLATION,
            extra.membership
        ),
    }
}

async fn corrupt(database: &Database, extra: &ExtraMember, attack: Attack) {
    sql(database, &corruption(extra, attack)).await;
}

#[tokio::test]
async fn marker3_rejects_semantic_candidates_in_both_directions_and_roles() {
    reject_candidates(false).await;
}

#[tokio::test]
async fn marker3_rejects_semantic_candidates_in_known_row_deltas() {
    reject_candidates(true).await;
}

async fn reject_candidates(known: bool) {
    tokio::time::timeout(Duration::from_secs(600), async {
        for attack in [
            Attack::Kid,
            Attack::ActiveMember,
            Attack::Endpoint,
            Attack::HistoricalIssuer,
        ] {
            for outgoing in [true, false] {
                for role in [SyncRole::Initiator, SyncRole::Responder] {
                    let mut pair = Pair::new().await;
                    let source_is_a = outgoing == matches!(role, SyncRole::Initiator);
                    let (source, target) = if source_is_a {
                        (pair.idp_a.clone(), pair.idp_b.clone())
                    } else {
                        (pair.idp_b.clone(), pair.idp_a.clone())
                    };
                    let extra = seed(&source).await;
                    if known {
                        sync_fixture(&source, &target).await;
                    }
                    let offending_table = match attack {
                        Attack::Kid | Attack::ActiveMember => "idp_replica_signers",
                        Attack::Endpoint if known => "devices",
                        Attack::Endpoint => "idp_replica_members",
                        Attack::HistoricalIssuer => "idp_replica_members",
                    };
                    let offending_row = match offending_table {
                        "idp_replica_signers" => extra.signer,
                        "idp_replica_members" => extra.membership,
                        _ => extra.member,
                    };
                    let query = format!(
                        "SELECT * FROM {offending_table} WHERE id = CAST('{offending_row}' AS UUID)"
                    );
                    let before = sql(&target, &query).await[0].rows.clone();
                    corrupt(&source, &extra, attack).await;
                    let source_before = source.sync_manifest().await.expect("source manifest");
                    let baseline = sql(&target, "SELECT * FROM idp_replica_signers").await[0]
                        .rows
                        .clone();
                    pair.serve(matches!(role, SyncRole::Responder));
                    let connection = pair.connect().await;
                    let result = match role {
                        SyncRole::Initiator => {
                            pair.protocol_a
                                .synchronize(&connection, SecurityContext::Idp)
                                .await
                        }
                        SyncRole::Responder => unvalidated_initiate(&pair, &connection).await,
                    };
                    let error =
                        result.expect_err("semantic invalidity must reject at actual export/apply");
                    assert!(!error.to_string().contains("https://foreign.example"));
                    assert_eq!(
                        source.sync_manifest().await.expect("unchanged source"),
                        source_before
                    );
                    if outgoing {
                        assert_eq!(
                            sql(&target, "SELECT * FROM idp_replica_signers").await[0].rows,
                            baseline
                        );
                        assert!(
                            !pair.received.lock().expect("wire frames").iter().any(
                                |frame| matches!(
                                    postcard::from_bytes::<SyncMessage>(frame),
                                    Ok(SyncMessage::State(_) | SyncMessage::Changes(_))
                                )
                            ),
                            "no invalid history disclosure to even an unvalidated peer"
                        );
                    } else {
                        assert_eq!(
                            sql(&target, &query).await[0].rows,
                            before,
                            "offending batch rolls back; earlier legitimate pending rows may remain"
                        );
                    }
                    drop((source, target));
                    pair.close().await;
                }
            }
        }
    })
    .await
    .expect("bounded genuine semantic candidate matrix");
}
