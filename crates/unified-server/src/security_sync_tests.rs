use std::{
    io::ErrorKind,
    sync::Arc,
    time::{Duration, Instant},
};

use db::{Database, SqlTranslator, Value};
use idp_model::{
    contract::{
        IdentityAction, IdpSignerRecord, JwkPublic, JwkPublicParameters, JwsAlgorithm, KeyUse,
        ReplicaMembership,
    },
    model::Id,
};
use idp_service::{
    PasswordConfig,
    oauth2::NodeSignerBinding,
    replica::{DbReplicaSignerRepo, DbUserRepo},
    repo::UserRepo,
};
use iroh::{Endpoint, address_lookup::MemoryLookup, endpoint::presets, protocol::Router};
use iroh_chain::{DATA_ALPN, EndpointIdStore, Server};
use management_service::{
    ManagementService,
    replica::{DbPermissionRepo, DbRoleRepo},
};
use storage_server::{IdpClient, ManagementClient, RouterState, build_runtime};
use tokio_util::sync::CancellationToken;

use crate::{SecurityContext, SecurityProtocol};

const INSTALLATION: &str = "https://installation.example";

pub(super) async fn sql(database: &Database, statement: &str) -> Vec<db::QueryResult> {
    database
        .client()
        .translate_and_execute(statement, &SqlTranslator)
        .await
        .expect("public SQL fixture")
}

#[tokio::test]
async fn authenticated_equal_peers_exchange_scoped_history_without_local_verifiers() {
    // Seven sequential native sessions recheck current policy per frame; this bounds the whole fixture.
    tokio::time::timeout(Duration::from_secs(600), exchange_history())
        .await
        .expect("domain history exchange and shutdown complete");
}

pub(super) async fn enroll(idp: Arc<Database>, member: Id, endpoint: iroh::EndpointId, key: Id) {
    DbReplicaSignerRepo::new(idp)
        .enroll(
            &ReplicaMembership {
                installation_id: INSTALLATION.into(),
                member_id: member,
                endpoint_id: endpoint.to_string(),
                issuer: INSTALLATION.into(),
                approved_at: 1,
                revoked_at: None,
            },
            &IdpSignerRecord {
                member_id: member,
                key_id: key,
                issuer: INSTALLATION.into(),
                public_jwk: JwkPublic {
                    kid: key.to_string(),
                    r#use: KeyUse::Signature,
                    alg: JwsAlgorithm::ES256K,
                    params: JwkPublicParameters::Ec {
                        crv: "secp256k1".into(),
                        x: "eb5mfvncu6xVoGKVzocLBwKb/NstzijZWfKBWxb4F5g".into(),
                        y: "SDradyajxGVdpPv8DhEIqP0XtEimhVQZnEfQj/sQ1Lg".into(),
                    },
                },
                approved_at: Some(1),
                revoked_at: None,
                expires_at: None,
            },
        )
        .await
        .expect("persist public peer approval");
}

async fn exchange_history() {
    let started = Instant::now();
    let root = std::env::temp_dir().join(format!("of-security-history-{}", Id::now_v7()));
    std::fs::create_dir_all(&root).expect("create native stores");
    let lookup = MemoryLookup::new();
    let a = Endpoint::builder(presets::Minimal)
        .alpns(vec![DATA_ALPN.to_vec()])
        .address_lookup(lookup.clone())
        .bind()
        .await
        .expect("bind A");
    let b = Endpoint::builder(presets::Minimal)
        .alpns(vec![DATA_ALPN.to_vec()])
        .address_lookup(lookup.clone())
        .bind()
        .await
        .expect("bind B");
    lookup.add_endpoint_info(a.addr());
    lookup.add_endpoint_info(b.addr());
    let peers_a = EndpointIdStore::default();
    peers_a.add(b.id());
    let peers_b = EndpointIdStore::default();
    peers_b.add(a.id());
    let server_a = Server::new(a, peers_a);
    let server_b = Server::new(b, peers_b);
    let actor = Id::now_v7();
    let member_a = Id::now_v7();
    let member_b = Id::now_v7();
    let key_a = Id::now_v7();
    let key_b = Id::now_v7();
    {
        let idp = Arc::new(Database::open(root.join("a-idp.redb")).expect("seed IdP"));
        idp_model::replica::up(&idp)
            .await
            .expect("fresh secret-free schemas");
        sql(&idp, &format!("INSERT INTO users (id, handle, name, created_at, updated_at) VALUES (CAST('{actor}' AS UUID), 'administrator', 'Administrator', 1, 1)")).await;
        for (member, key, endpoint) in [
            (member_a, key_a, server_a.endpoint().id()),
            (member_b, key_b, server_b.endpoint().id()),
        ] {
            sql(&idp, &format!("INSERT INTO devices (id, owner_subject, name, public_key, address, state, approved_at, created_at, updated_at) VALUES (CAST('{member}' AS UUID), '{actor}', 'node', '{endpoint}', 'local', 1, 1, 1, 1)")).await;
            enroll(idp.clone(), member, endpoint, key).await;
        }
        let management =
            Arc::new(Database::open(root.join("a-management.redb")).expect("seed Management"));
        management_service::replica::up(&management)
            .await
            .expect("Management schemas");
        ManagementService::new(
            DbPermissionRepo::new(management.clone()),
            DbRoleRepo::new(management.clone()),
        )
        .provision_initial_administrator(
            actor,
            Id::now_v7(),
            &[
                (Id::now_v7(), IdentityAction::DevicePairingRead),
                (Id::now_v7(), IdentityAction::DevicePairingUpdate),
                (Id::now_v7(), IdentityAction::IdpSecuritySync),
                (Id::now_v7(), IdentityAction::ManagementSecuritySync),
            ],
        )
        .await
        .expect("explicit local context sync grants");
    }
    // Both approved Nodes start with the same provisioned public baseline, containing no verifiers.
    std::fs::copy(root.join("a-idp.redb"), root.join("b-idp.redb"))
        .expect("provision public baseline");
    std::fs::copy(
        root.join("a-management.redb"),
        root.join("b-management.redb"),
    )
    .expect("provision policy baseline");
    let idp_a = Arc::new(Database::open(root.join("a-idp.redb")).expect("open A IdP"));
    let idp_b = Arc::new(Database::open(root.join("b-idp.redb")).expect("open B IdP"));
    let management_a =
        Arc::new(Database::open(root.join("a-management.redb")).expect("open A Management"));
    let management_b =
        Arc::new(Database::open(root.join("b-management.redb")).expect("open B Management"));
    let learned_member = Id::now_v7();
    let learned_endpoint = iroh::SecretKey::generate().public();
    sql(&idp_a, &format!("INSERT INTO devices (id, owner_subject, name, public_key, address, state, approved_at, created_at, updated_at) VALUES (CAST('{learned_member}' AS UUID), '{actor}', 'new-approved-peer', '{learned_endpoint}', 'local', 1, 1, 1, 1)")).await;
    enroll(
        idp_a.clone(),
        learned_member,
        learned_endpoint,
        Id::now_v7(),
    )
    .await;
    let users_a = DbUserRepo::new(idp_a.clone(), PasswordConfig::default());
    let users_b = DbUserRepo::new(idp_b.clone(), PasswordConfig::default());
    let user_a = users_a
        .create_user_with_password("only-a", "secret-a")
        .await
        .expect("local A verifier");
    let user_b = users_b
        .create_user_with_password("only-b", "secret-b")
        .await
        .expect("local B verifier");
    let local_client_a = Id::now_v7();
    let local_client_b = Id::now_v7();
    for (database, client, device, label) in [
        (&*idp_a, local_client_a, member_a, "a"),
        (&*idp_b, local_client_b, member_b, "b"),
    ] {
        sql(database, &format!("INSERT INTO local_client_credentials (client_id, credential_id, secret_hash) VALUES (CAST('{client}' AS UUID), CAST('{}' AS UUID), 'private-client-{label}'); INSERT INTO local_device_enrollments (device_id, pairing_accepting_public_key) VALUES (CAST('{device}' AS UUID), 'private-enrollment-{label}')", Id::now_v7())).await;
    }
    let grant_client = Id::now_v7();
    let grant = |token: &str| idp_service::repo::OAuth2RefreshToken {
        token: token.into(),
        client_id: grant_client,
        user_id: user_a.id,
        scopes: vec!["openid".into()],
        resource: None,
        authorization_details: None,
        expires_at: 200,
        created_at: 100,
    };
    use idp_service::repo::OAuth2RefreshTokenRepo;
    let grants_a = idp_service::replica::DbOAuth2RefreshTokenRepo::new(idp_a.clone());
    let grants_b = idp_service::replica::DbOAuth2RefreshTokenRepo::new(idp_b.clone());
    grants_a
        .issue_refresh_token(grant("private-bearer-original"), None)
        .await
        .expect("store hash and public grant state only");
    let cancellation = CancellationToken::new();
    let protocol_a = SecurityProtocol::new(
        server_a.clone(),
        idp_a.clone(),
        management_a.clone(),
        INSTALLATION.into(),
        Some(NodeSignerBinding {
            member_id: member_a,
            key_id: key_a,
            endpoint_id: server_a.endpoint().id().to_string(),
        }),
        root.join("a-stage"),
        cancellation.clone(),
    );
    let protocol_b = SecurityProtocol::new(
        server_b.clone(),
        idp_b.clone(),
        management_b.clone(),
        INSTALLATION.into(),
        Some(NodeSignerBinding {
            member_id: member_b,
            key_id: key_b,
            endpoint_id: server_b.endpoint().id().to_string(),
        }),
        root.join("b-stage"),
        cancellation.clone(),
    );
    let storage = build_runtime(
        RouterState::new("http://localhost/storage")
            .with_idp_client(
                IdpClient::new(
                    "http://127.0.0.1:1/idp",
                    "storage",
                    "local",
                    INSTALLATION,
                    "idp",
                )
                .expect("IdP client"),
            )
            .with_management_client(
                ManagementClient::new(
                    "http://127.0.0.1:1/management",
                    "http://127.0.0.1:1/idp",
                    "storage",
                    "local",
                    INSTALLATION,
                    "management",
                )
                .expect("Management client"),
            ),
        &root.join("storage"),
        "/storage",
        "",
        Some(server_b.clone()),
        cancellation.clone(),
    )
    .expect("existing Storage DATA handler");
    let router = Router::builder(server_b.endpoint().clone())
        .accept(
            DATA_ALPN,
            protocol_b.attach(storage.data_handler().expect("shared DATA handler")),
        )
        .spawn();
    let connection = server_a
        .connect_direct_with_alpn(server_b.endpoint().id(), DATA_ALPN)
        .await
        .expect("authenticated existing endpoint");
    eprintln!(
        "security fixture {:?}: initial IdP exchange starting",
        started.elapsed()
    );
    tokio::time::timeout(
        Duration::from_secs(60),
        protocol_a.synchronize(&connection, SecurityContext::Idp),
    )
    .await
    .expect("bounded test exchange")
    .expect("trusted scoped history exchange");
    eprintln!(
        "security fixture {:?}: initial IdP exchange complete",
        started.elapsed()
    );
    assert!(
        users_b
            .find_user_by_id(user_a.id)
            .await
            .expect("learned public User")
            .is_some()
    );
    assert!(
        users_a
            .find_user_by_id(user_b.id)
            .await
            .expect("equal reverse User")
            .is_some()
    );
    assert!(
        users_b
            .find_user_password_by_user_id(user_a.id)
            .await
            .expect("no remote verifier")
            .is_none()
    );
    assert!(
        users_a
            .find_user_password_by_user_id(user_b.id)
            .await
            .expect("no remote verifier")
            .is_none()
    );
    assert!(
        users_a
            .find_user_password_by_user_id(user_a.id)
            .await
            .expect("own verifier retained")
            .is_some()
    );
    assert!(
        users_b
            .find_user_password_by_user_id(user_b.id)
            .await
            .expect("own verifier retained")
            .is_some()
    );
    assert!(
        DbReplicaSignerRepo::new(idp_b.clone())
            .is_trusted_peer(
                INSTALLATION,
                learned_member,
                &learned_endpoint.to_string(),
                100
            )
            .await
            .expect("learn approved public Device/member/signer history")
    );
    grants_b
        .issue_refresh_token(
            grant("private-bearer-replacement"),
            Some("private-bearer-original"),
        )
        .await
        .expect("approved peer consumes learned grant locally");
    protocol_a
        .synchronize(&connection, SecurityContext::Idp)
        .await
        .expect("learn consumed history in reverse direction");
    assert!(
        grants_a
            .issue_refresh_token(
                grant("private-bearer-replay"),
                Some("private-bearer-original")
            )
            .await
            .is_err(),
        "learned consumption denies replay without raw bearer transfer"
    );
    for (database, own_client, other_client, own_device, other_device, label) in [
        (
            &*idp_a,
            local_client_a,
            local_client_b,
            member_a,
            member_b,
            "a",
        ),
        (
            &*idp_b,
            local_client_b,
            local_client_a,
            member_b,
            member_a,
            "b",
        ),
    ] {
        assert_eq!(sql(database, &format!("SELECT secret_hash FROM local_client_credentials WHERE client_id = CAST('{own_client}' AS UUID)")).await[0].rows[0].values, vec![Value::Text(format!("private-client-{label}"))]);
        assert!(sql(database, &format!("SELECT secret_hash FROM local_client_credentials WHERE client_id = CAST('{other_client}' AS UUID)")).await[0].rows.is_empty());
        assert_eq!(sql(database, &format!("SELECT pairing_accepting_public_key FROM local_device_enrollments WHERE device_id = CAST('{own_device}' AS UUID)")).await[0].rows[0].values, vec![Value::Text(format!("private-enrollment-{label}"))]);
        assert!(sql(database, &format!("SELECT device_id FROM local_device_enrollments WHERE device_id = CAST('{other_device}' AS UUID)")).await[0].rows.is_empty());
    }
    let unsigned = SecurityProtocol::new(
        server_a.clone(),
        idp_a.clone(),
        management_a.clone(),
        INSTALLATION.into(),
        None,
        root.join("unsigned-stage"),
        cancellation.clone(),
    );
    assert_eq!(
        unsigned
            .synchronize(&connection, SecurityContext::Idp)
            .await
            .expect_err("missing local signer denies")
            .kind(),
        ErrorKind::PermissionDenied
    );
    drop(unsigned);

    eprintln!(
        "security fixture {:?}: valid identity/replay/secret checks complete",
        started.elapsed()
    );
    for request in [
        serde_json::json!({"version": 1, "installation": "https://foreign.example", "member": member_a, "context": "idp"}),
        serde_json::json!({"version": 1, "installation": INSTALLATION, "member": member_b, "context": "idp"}),
        serde_json::json!({"version": 2, "installation": INSTALLATION, "member": member_a, "context": "management"}),
    ] {
        use ofdb_sql::SyncTransport;
        let before = security_manifests(&idp_a, &idp_b, &management_a, &management_b).await;
        let (mut send, recv) = connection
            .open_bi()
            .await
            .expect("fresh untrusted-claim stream");
        send.write_all(&[3]).await.expect("existing DATA marker");
        let mut transport = storage_server::DatabaseTransport::new(send, recv);
        transport
            .send(serde_json::to_vec(&request).expect("encode claim"))
            .await
            .expect("send claim");
        assert!(
            transport.receive().await.is_err(),
            "bad admission closes without any response/history frame"
        );
        assert_eq!(
            security_manifests(&idp_a, &idp_b, &management_a, &management_b).await,
            before,
            "bad claims neither import nor mutate either context"
        );
    }
    sql(&idp_b, &format!("UPDATE devices SET owner_subject = 'unverified-endpoint-subject' WHERE id = CAST('{member_a}' AS UUID)")).await;
    let before = security_manifests(&idp_a, &idp_b, &management_a, &management_b).await;
    protocol_a
        .synchronize(&connection, SecurityContext::Idp)
        .await
        .expect_err("receiver denies unverified owner without an unchecked reply");
    assert_admission_closed(&connection, member_a, SecurityContext::Idp).await;
    assert_eq!(
        security_manifests(&idp_a, &idp_b, &management_a, &management_b).await,
        before,
        "unverified owner imports no history and preserves source data"
    );
    sql(
        &idp_b,
        &format!(
            "UPDATE devices SET owner_subject = '{actor}' WHERE id = CAST('{member_a}' AS UUID)"
        ),
    )
    .await;

    eprintln!(
        "security fixture {:?}: rejected claims/owner complete; Management exchange starting",
        started.elapsed()
    );
    let restricted = Id::now_v7();
    let ambiguous = Id::now_v7();
    let selection_a = management_service::replica::DbSelectionPolicyRepo::new(management_a.clone());
    let selection_b = management_service::replica::DbSelectionPolicyRepo::new(management_b.clone());
    for device_id in [restricted, ambiguous] {
        selection_a
            .set_prevalidated(management_service::replica::SelectionPolicy {
                device_id,
                owner_subject: actor.to_string(),
                application_id: None,
                selected_kind: None,
                selected_id: None,
                admin_allowed: true,
            })
            .await
            .expect("public unselected policy");
    }
    let policy = Id::now_v7();
    sql(&management_a, &format!("INSERT INTO roles (id, application_id, name, created_at, updated_at) VALUES (CAST('{policy}' AS UUID), CAST('{actor}' AS UUID), 'shared-policy', 1, 1)")).await;
    protocol_a
        .synchronize(&connection, SecurityContext::Management)
        .await
        .expect("separate policy exchange");
    eprintln!(
        "security fixture {:?}: Management namespace exchange complete",
        started.elapsed()
    );
    assert_eq!(
        sql(
            &management_b,
            &format!("SELECT name FROM roles WHERE id = CAST('{policy}' AS UUID)")
        )
        .await[0]
            .rows[0]
            .values,
        vec![Value::Text("shared-policy".into())]
    );
    assert!(
        sql(
            &idp_b,
            &format!("SELECT name FROM roles WHERE id = CAST('{policy}' AS UUID)")
        )
        .await[0]
            .rows
            .is_empty(),
        "Management never leaks into IdP repository"
    );

    for (database, updates) in [
        (
            &*management_a,
            vec![
                (restricted, "admin_allowed", "false"),
                (ambiguous, "owner_subject", "'alice'"),
            ],
        ),
        (
            &*management_b,
            vec![
                (restricted, "admin_allowed", "false"),
                (restricted, "admin_allowed", "true"),
                (ambiguous, "owner_subject", "'bob'"),
            ],
        ),
    ] {
        for (device, column, value) in updates {
            sql(database, &format!("UPDATE device_selection_policies SET {column} = {value} WHERE device_id = CAST('{device}' AS UUID)")).await;
        }
    }
    protocol_a
        .synchronize(&connection, SecurityContext::Management)
        .await
        .expect("preserve concurrent restriction histories");
    eprintln!(
        "security fixture {:?}: concurrent restriction history exchange complete",
        started.elapsed()
    );

    assert!(
        selection_a.get(ambiguous, "alice", actor).await.is_err(),
        "ambiguous ownership denies"
    );
    assert!(
        !selection_a
            .get(restricted, &actor.to_string(), actor)
            .await
            .expect("restrictive resolution")
            .expect("policy exists")
            .admin_allowed
    );

    protocol_a
        .synchronize(&connection, SecurityContext::Management)
        .await
        .expect("resolution delta exchange");
    eprintln!(
        "security fixture {:?}: restrictive resolution delta exchange complete",
        started.elapsed()
    );

    assert!(
        !selection_b
            .get(restricted, &actor.to_string(), actor)
            .await
            .expect("peer retains explicit restrictive resolution")
            .expect("policy exists")
            .admin_allowed
    );

    sql(
        &management_a,
        &format!("DELETE FROM roles WHERE id = CAST('{policy}' AS UUID)"),
    )
    .await;

    protocol_a
        .synchronize(&connection, SecurityContext::Management)
        .await
        .expect("policy tombstone transfer");
    eprintln!(
        "security fixture {:?}: policy tombstone transfer complete",
        started.elapsed()
    );

    protocol_a
        .synchronize(&connection, SecurityContext::Management)
        .await
        .expect("repeated history exchange cannot resurrect tombstone");
    assert!(
        sql(
            &management_b,
            &format!("SELECT name FROM roles WHERE id = CAST('{policy}' AS UUID)")
        )
        .await[0]
            .rows
            .is_empty()
    );
    eprintln!(
        "security fixture {:?}: conflicts/resolution/tombstones complete",
        started.elapsed()
    );
    sql(
        &management_b,
        "UPDATE permissions SET revoked_at = 2 WHERE name = 'idp.security.sync'",
    )
    .await;
    let before = security_manifests(&idp_a, &idp_b, &management_a, &management_b).await;
    protocol_a
        .synchronize(&connection, SecurityContext::Idp)
        .await
        .expect_err("current receiver permission denies existing connection");
    assert_admission_closed(&connection, member_a, SecurityContext::Idp).await;
    assert_eq!(
        security_manifests(&idp_a, &idp_b, &management_a, &management_b).await,
        before,
        "learned permission denial imports no history and preserves source data"
    );

    sql(
        &idp_a,
        "ALTER TABLE clients ADD COLUMN client_secret_hash TEXT",
    )
    .await;
    assert_eq!(
        protocol_a
            .synchronize(&connection, SecurityContext::Idp)
            .await
            .expect_err("unreviewed local public schema must reject before export")
            .kind(),
        ErrorKind::InvalidData
    );
    sql(
        &management_a,
        "ALTER TABLE roles ADD COLUMN private_note TEXT",
    )
    .await;
    assert_eq!(
        protocol_a
            .synchronize(&connection, SecurityContext::Management)
            .await
            .expect_err("unreviewed Management layout rejects before export")
            .kind(),
        ErrorKind::InvalidData
    );
    cancellation.cancel();
    router.shutdown().await.expect("shared router shutdown");
    server_a.endpoint().close().await;
    server_b.endpoint().close().await;
    drop((
        protocol_a,
        protocol_b,
        storage,
        users_a,
        users_b,
        idp_a,
        idp_b,
        management_a,
        management_b,
        selection_a,
        selection_b,
        grants_a,
        grants_b,
    ));
    let reopened_idp =
        Arc::new(Database::open(root.join("b-idp.redb")).expect("native IdP reopen"));
    let reopened_users = DbUserRepo::new(reopened_idp.clone(), PasswordConfig::default());
    assert!(
        reopened_users
            .find_user_by_id(user_a.id)
            .await
            .expect("learned public identity durable")
            .is_some()
    );
    assert!(
        reopened_users
            .find_user_password_by_user_id(user_a.id)
            .await
            .expect("still no remote secret after restart")
            .is_none()
    );
    assert!(
        reopened_users
            .find_user_password_by_user_id(user_b.id)
            .await
            .expect("own verifier durable")
            .is_some()
    );
    let reopened_management =
        Arc::new(Database::open(root.join("b-management.redb")).expect("native Management reopen"));
    let reopened_selection =
        management_service::replica::DbSelectionPolicyRepo::new(reopened_management.clone());
    assert!(
        !reopened_selection
            .get(restricted, &actor.to_string(), actor)
            .await
            .expect("durable restrictive resolution")
            .expect("policy exists")
            .admin_allowed
    );
    assert!(
        reopened_selection
            .get(ambiguous, "alice", actor)
            .await
            .is_err()
    );
    assert!(
        sql(
            &reopened_management,
            &format!("SELECT name FROM roles WHERE id = CAST('{policy}' AS UUID)")
        )
        .await[0]
            .rows
            .is_empty()
    );
    drop((
        reopened_users,
        reopened_idp,
        reopened_selection,
        reopened_management,
    ));
    std::fs::remove_dir_all(root).expect("remove native fixture");
    eprintln!(
        "security fixture {:?}: native reopen/shutdown complete",
        started.elapsed()
    );
}

async fn security_manifests(
    idp_a: &Database,
    idp_b: &Database,
    management_a: &Database,
    management_b: &Database,
) -> impl PartialEq + std::fmt::Debug + use<> {
    (
        idp_a.sync_manifest().await.expect("source IdP manifest"),
        idp_b.sync_manifest().await.expect("recipient IdP manifest"),
        management_a
            .sync_manifest()
            .await
            .expect("source Management manifest"),
        management_b
            .sync_manifest()
            .await
            .expect("recipient Management manifest"),
    )
}

async fn assert_admission_closed(
    connection: &iroh::endpoint::Connection,
    member: Id,
    context: SecurityContext,
) {
    use ofdb_sql::SyncTransport;
    let (mut send, recv) = connection
        .open_bi()
        .await
        .expect("fresh stream on same connection");
    send.write_all(&[3]).await.expect("security marker");
    let mut transport = storage_server::DatabaseTransport::new(send, recv);
    transport.send(serde_json::to_vec(&serde_json::json!({"version": 1, "installation": INSTALLATION, "member": member, "context": context})).expect("authenticated claim")).await.expect("send admission probe");
    assert!(
        transport.receive().await.is_err(),
        "denied receiver discloses no response/history frame"
    );
}
