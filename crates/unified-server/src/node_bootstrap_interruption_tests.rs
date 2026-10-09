use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use db::Database;
use idp_model::{contract::IdentityAction, model::Id};
use idp_server::{AppConfig, OwnerProvisioner};
use idp_service::{oauth2::NodeSignerBinding, replica::DbReplicaSignerRepo};
use iroh::{SecretKey, endpoint::presets::Minimal};
use iroh_chain::{DATA_ALPN, EndpointIdStore, Server};
use management_service::{
    ManagementService,
    replica::{DbPermissionRepo, DbRoleRepo},
};
use tokio_util::sync::CancellationToken;

use crate::permission_http_tests::{seed_idp, seed_permissions, user_token};

use super::{
    BOOTSTRAP_STREAM_KIND, BootstrapRequest, PURPOSE, ReceiverTransport, SecurityContext,
    SecurityProtocol,
};
use crate::security_sync_tests::sql;
use ofdb_sql::{SyncDirection, SyncMessage, SyncTransport};
use storage_server::DatabaseTransport;

#[tokio::test]
async fn bootstrap_current_boundaries_preserve_admitted_import_and_native_retry() {
    tokio::time::timeout(Duration::from_secs(360), interruption_boundary())
        .await
        .expect("dedicated bootstrap interruption completes");
}

async fn interruption_boundary() {
    let root = std::env::temp_dir().join(format!("of-node-join-bootstrap-{}", Id::now_v7()));
    let issuer = format!("https://join-{}.example", Id::now_v7());
    let source_secret = SecretKey::generate();
    let joining_secret = SecretKey::generate();
    let source_root = root.join("source");
    let joining_root = root.join("joining");
    let mut fixture = seed_idp(
        &source_root,
        &issuer,
        &source_secret.public().to_string(),
        &SecretKey::generate().public().to_string(),
    )
    .await;
    seed_permissions(&source_root, &mut fixture).await;
    let source_idp =
        Arc::new(Database::open(source_root.join("idp/idp.redb")).expect("source IdP"));
    let source_policy = Arc::new(
        Database::open(source_root.join("management/management.redb")).expect("source policy"),
    );
    let policy = ManagementService::new(
        DbPermissionRepo::new(source_policy.clone()),
        DbRoleRepo::new(source_policy.clone()),
    );
    let role = policy
        .create_role(
            idp_model::contract::INSTALLATION_POLICY_ID,
            "Explicit join approval",
            None,
        )
        .await
        .expect("purpose-specific source role");
    policy
        .add_role_to_user(
            idp_model::contract::INSTALLATION_POLICY_ID,
            fixture.administrator,
            role.id,
        )
        .await
        .expect("source User role");
    for action in [
        IdentityAction::ReplicaSignersEnroll,
        IdentityAction::IdpSecuritySync,
    ] {
        let permission = policy
            .create_permission(
                idp_model::contract::INSTALLATION_POLICY_ID,
                action.permission(),
                None,
            )
            .await
            .expect("explicit Installation permission");
        policy
            .add_permission_to_role(
                idp_model::contract::INSTALLATION_POLICY_ID,
                role.id,
                permission.id,
            )
            .await
            .expect("explicit source grant");
    }
    source_idp
        .client()
        .translate_and_execute(
            &format!(
                "UPDATE devices SET owner_subject = '{}'",
                fixture.administrator
            ),
            &db::SqlTranslator,
        )
        .await
        .expect("all source fixture Devices bind a real active User, not invalid placeholders");

    let source_allowed = EndpointIdStore::default();
    let source =
        Server::bind_with_secret_key(Minimal, source_secret.clone(), source_allowed.clone())
            .await
            .expect("ordinary source admission hooks");
    let config = AppConfig {
        data_dir: joining_root.to_string_lossy().into_owned(),
        oauth2: idp_service::oauth2::OAuth2Config {
            issuer: issuer.clone(),
            ..Default::default()
        },
        ..Default::default()
    };
    let joining = idp_server::bind_node_join_endpoint(
        &config,
        Minimal,
        joining_secret.clone(),
        EndpointIdStore::default(),
    )
    .await
    .expect("shared endpoint with purpose-only persisted join admission");
    source.set_pairing_enabled(true);
    joining.set_pairing_enabled(true);
    let mut offers = source.subscribe_pairing_offers();
    let cancellation = CancellationToken::new();
    let storage = storage_server::build_runtime(
        storage_server::RouterState::new("http://localhost/storage")
            .with_idp_client(
                storage_server::IdpClient::new(
                    "http://127.0.0.1:1/idp",
                    "storage",
                    "local",
                    &issuer,
                    "idp",
                )
                .expect("unused resource client"),
            )
            .with_management_client(
                storage_server::ManagementClient::new(
                    "http://127.0.0.1:1/management",
                    "http://127.0.0.1:1/idp",
                    "storage",
                    "local",
                    &issuer,
                    "management",
                )
                .expect("unused resource policy client"),
            ),
        &source_root.join("storage"),
        "/storage",
        "",
        Some(source.clone()),
        cancellation.clone(),
    )
    .expect("existing DATA dispatcher; no resource access authorized");
    let source_security = SecurityProtocol::new(
        source.clone(),
        source_idp.clone(),
        source_policy.clone(),
        issuer.clone(),
        Some(fixture.local_signer.clone()),
        source_root.join("security-staging"),
        cancellation.clone(),
    );
    let peer_router = source.router_with_protocol(
        source_security.attach(storage.data_handler().expect("DATA handler")),
        idp_server::BOOTSTRAP_ALPN,
        source_security.node_bootstrap_handler(),
    );
    let mut source_config = AppConfig::default();
    source_config.oauth2.issuer = issuer.clone();
    source_config.oauth2.local_signer = Some(fixture.local_signer.clone());
    source_config.service_audience = Some("idp-services".into());
    source_config.server.prefix = Some("/idp".into());
    let runtime = idp_server::build_runtime(
        &source_config,
        source_idp.clone(),
        Arc::new(
            idp_server::device_identity_from_server(&source, source_secret)
                .expect("source identity"),
        ),
        source.clone(),
        Some(management_service::LocalPermissions::new(
            source_policy.clone(),
        )),
    )
    .await
    .expect("production approving owner runtime");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("source HTTP listener");
    let base = format!(
        "http://{}",
        listener.local_addr().expect("source HTTP address")
    );
    let router = runtime.router();
    let http = tokio::spawn(async move {
        axum::serve(listener, router).await.expect("source HTTP");
    });
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .expect("HTTP client");
    let bearer = user_token(&client, &base, "administrator", "idp-services").await;
    let binding = NodeSignerBinding {
        member_id: Id::now_v7(),
        key_id: Id::now_v7(),
        endpoint_id: joining.endpoint().id().to_string(),
    };
    let provisioner = OwnerProvisioner::open(&config)
        .await
        .expect("fresh native joining owner with injected keyring");
    let request = provisioner
        .prepare_node_join(&binding, "Joining Node", source.endpoint().id())
        .expect("durable independent private signer");
    let sending = tokio::spawn({
        let joining = joining.clone();
        let address = source.endpoint().addr();
        let request = request.clone();
        async move { request.send(&joining, address).await }
    });
    let offer = offers
        .recv()
        .await
        .expect("real authenticated pairing offer");
    assert!(
        joining
            .endpoint()
            .connect(source.endpoint().addr(), idp_server::BOOTSTRAP_ALPN)
            .await
            .is_err(),
        "no bootstrap admission before verified persisted receipt"
    );
    let approved = runtime
        .approve_node_join(&offer, &bearer)
        .await
        .expect("purpose-specific authorized enrollment");
    let received = sending
        .await
        .expect("pairing sender")
        .expect("pinned peer signed reply");
    assert_eq!(approved, received);
    source_allowed.replace(
        runtime
            .approved_peer_ids()
            .await
            .expect("source admission restored only from real durable trust"),
    );
    provisioner
        .record_node_join_approval(&received)
        .expect("persist receipt");
    provisioner
        .record_node_join_approval(&received)
        .expect("exact receipt retry");
    assert!(
        provisioner.verify_node_signer(&binding).await.is_err(),
        "receipt is not local signer trust"
    );
    let joining_idp = provisioner.node_join_database();
    let joining_policy = Arc::new(
        Database::open(joining_root.join("management.redb")).expect("joining policy owner"),
    );
    management_service::replica::up(&joining_policy)
        .await
        .expect("empty fixed public policy schema");
    let protocol = SecurityProtocol::new(
        joining.clone(),
        joining_idp.clone(),
        joining_policy.clone(),
        issuer.clone(),
        Some(binding.clone()),
        joining_root.join("security-staging"),
        CancellationToken::new(),
    );
    assert!(
        joining
            .endpoint()
            .connect(source.endpoint().addr(), DATA_ALPN)
            .await
            .is_err(),
        "receipt/pairing cannot allow ordinary DATA"
    );
    let connection = joining
        .endpoint()
        .connect(source.endpoint().addr(), idp_server::BOOTSTRAP_ALPN)
        .await
        .expect("authenticated purpose-specific bootstrap connection");

    let mut transport = begin(&protocol, &connection, &provisioner).await;
    let mut gated = RevokeAfterHello {
        inner: &mut transport,
        policy: &source_policy,
        learned: false,
        application_frames_after_denial: 0,
    };
    let mut receiver = ReceiverTransport {
        inner: &mut gated,
        protocol: &protocol,
        connection: &connection,
        owner: &provisioner,
        approval: &received,
    };
    let denied = protocol
        .node_bootstrap_session(
            &received,
            SecurityContext::Idp,
            SyncDirection::ReceiveOnly,
            &mut receiver,
            || async {
                protocol
                    .check_bootstrap_receiver(&connection, &provisioner, &received)
                    .await
                    .map_err(|error| error.to_string())
            },
        )
        .await;
    drop(receiver);
    assert!(
        denied.is_err(),
        "learned source grant removal interrupts the existing stream"
    );
    assert!(
        gated.learned,
        "the real source Hello reached the deterministic gate"
    );
    assert_eq!(
        gated.application_frames_after_denial, 0,
        "no public history after learned source denial"
    );
    assert!(
        sql(&joining_idp, "SELECT id FROM users").await[0]
            .rows
            .is_empty()
    );
    assert!(
        !provisioner
            .node_join_stage_recorded(idp_server::NodeJoinStage::Idp)
            .expect("no import journal")
    );
    assert!(
        !protocol
            .node_join_public_ready(&provisioner)
            .await
            .expect("incomplete bootstrap")
    );
    drop(gated);
    drop(transport);
    let permission = policy
        .list_permissions(idp_model::contract::INSTALLATION_POLICY_ID, 0, 100)
        .await
        .expect("existing explicit permissions")
        .into_iter()
        .find(|permission| permission.name == IdentityAction::IdpSecuritySync.permission())
        .expect("existing IdP context permission");
    {
        policy
            .add_permission_to_role(
                idp_model::contract::INSTALLATION_POLICY_ID,
                role.id,
                permission.id,
            )
            .await
            .expect("restore source current permission");
    }

    let mut transport = begin(&protocol, &connection, &provisioner).await;
    let mut receiver = ReceiverTransport {
        inner: &mut transport,
        protocol: &protocol,
        connection: &connection,
        owner: &provisioner,
        approval: &received,
    };
    let source_users = sql(&source_idp, "SELECT id FROM users ORDER BY id").await[0]
        .rows
        .clone();
    let calls = AtomicUsize::new(0);
    let interrupted = protocol
        .node_bootstrap_session(
            &received,
            SecurityContext::Idp,
            SyncDirection::ReceiveOnly,
            &mut receiver,
            || async {
                protocol
                    .check_bootstrap_receiver(&connection, &provisioner, &received)
                    .await
                    .map_err(|error| error.to_string())?;
                if calls.fetch_add(1, Ordering::SeqCst) == 1 {
                    protocol.cancellation.cancel();
                }
                Ok(())
            },
        )
        .await;
    assert!(
        interrupted.is_err(),
        "next operation denies learned receiver cancellation"
    );
    assert!(
        calls.load(Ordering::SeqCst) >= 2,
        "catalog then application apply were admitted"
    );
    let retained = sql(&joining_idp, "SELECT id FROM users").await[0]
        .rows
        .clone();
    assert!(
        !retained.is_empty(),
        "already admitted application write finishes despite cancellation"
    );
    assert_eq!(
        provisioner
            .verify_node_signer(&binding)
            .await
            .expect("admitted batch may already contain the pinned trust tuple"),
        request.public_signer,
        "local signer trust alone does not publish context completion or public readiness"
    );
    assert_eq!(
        sql(&source_idp, "SELECT id FROM users ORDER BY id").await[0].rows,
        source_users,
        "interruption preserves source Users as well as the admitted receiver batch"
    );
    assert!(
        protocol
            .check_bootstrap_receiver(&connection, &provisioner, &received)
            .await
            .is_err(),
        "the next actual boundary denies"
    );
    assert!(
        !provisioner
            .node_join_stage_recorded(idp_server::NodeJoinStage::Idp)
            .expect("interruption has no completed import journal")
    );
    assert!(
        !protocol
            .node_join_public_ready(&provisioner)
            .await
            .expect("no premature readiness")
    );
    assert!(
        protocol
            .complete_node_join_public_bootstrap(&provisioner)
            .await
            .is_err()
    );
    drop(receiver);
    drop(transport);
    drop(protocol);
    drop(provisioner);
    drop(joining_idp);
    let provisioner = OwnerProvisioner::open(&config)
        .await
        .expect("native partial-import reopen");
    assert_eq!(
        sql(&provisioner.node_join_database(), "SELECT id FROM users").await[0].rows,
        retained,
        "native progress survives incomplete import"
    );
    assert_eq!(
        provisioner
            .node_join_approval()
            .expect("persisted signed receipt"),
        Some(received.clone())
    );
    assert_eq!(
        provisioner
            .prepare_node_join(&binding, "Joining Node", source.endpoint().id())
            .expect("same independent key and stable request"),
        request
    );
    let protocol = SecurityProtocol::new(
        joining.clone(),
        provisioner.node_join_database(),
        joining_policy.clone(),
        issuer.clone(),
        Some(binding.clone()),
        joining_root.join("security-staging"),
        CancellationToken::new(),
    );
    let retry = protocol
        .receive_node_bootstrap(&connection, &provisioner, SecurityContext::Idp)
        .await
        .expect("production retry from retained partial native import");
    assert_eq!(
        (retry.sent_units, retry.sent_changes),
        (0, 0),
        "retained history is never reverse-published"
    );
    assert!(
        provisioner
            .node_join_stage_recorded(idp_server::NodeJoinStage::Idp)
            .expect("successful retry records import")
    );
    assert!(
        !protocol
            .node_join_public_ready(&provisioner)
            .await
            .expect("IdP alone is not public readiness")
    );
    assert_eq!(
        sql(
            &provisioner.node_join_database(),
            &format!(
                "SELECT id FROM idp_replica_members WHERE member_id = CAST('{}' AS UUID)",
                binding.member_id
            )
        )
        .await[0]
            .rows
            .len(),
        1,
        "retry does not duplicate membership"
    );
    DbReplicaSignerRepo::new(provisioner.node_join_database())
        .revoke(binding.member_id, &issuer, 11)
        .await
        .expect("receiver learns membership revocation");
    assert!(
        protocol
            .receive_node_bootstrap(&connection, &provisioner, SecurityContext::Idp)
            .await
            .is_err(),
        "receipt retry cannot undo learned receiver revocation"
    );
    connection.close(0u32.into(), b"interruption test complete");
    http.abort();
    let _ = http.await;
    cancellation.cancel();
    peer_router
        .shutdown()
        .await
        .expect("shutdown bootstrap streams");
    joining.endpoint().close().await;
    drop(protocol);
    drop(provisioner);
    drop(joining_policy);
    drop(runtime);
    drop(storage);
    drop(policy);
    drop(source_security);
    drop(source_idp);
    drop(source_policy);
    let reopened = OwnerProvisioner::open(&config)
        .await
        .expect("native revoked reopen");
    assert!(
        reopened.verify_node_signer(&binding).await.is_err(),
        "retained receipt/journal cannot resurrect revoked signer"
    );
    drop(reopened);
    std::fs::remove_dir_all(root).expect("remove isolated native stores");
}

async fn begin(
    protocol: &SecurityProtocol,
    connection: &iroh::endpoint::Connection,
    owner: &OwnerProvisioner,
) -> DatabaseTransport {
    let approval = owner
        .node_join_anchor()
        .expect("persisted verified approval");
    protocol
        .check_bootstrap_receiver(connection, owner, &approval)
        .await
        .expect("current receiver admission");
    protocol
        .validate_local_schema(SecurityContext::Idp)
        .await
        .expect("fixed public schema");
    let request = BootstrapRequest {
        purpose: PURPOSE.into(),
        context: SecurityContext::Idp,
        approval,
    };
    let (mut send, recv) = connection.open_bi().await.expect("bootstrap stream");
    send.write_all(&[BOOTSTRAP_STREAM_KIND])
        .await
        .expect("purpose-specific stream marker");
    let mut transport = DatabaseTransport::new(send, recv);
    transport
        .send(serde_json::to_vec(&request).expect("request JSON"))
        .await
        .expect("bootstrap request");
    let accepted: BootstrapRequest =
        serde_json::from_slice(&transport.receive().await.expect("authorized source reply"))
            .expect("reply JSON");
    assert!(accepted == request, "exact context and pinned anchor");
    transport
}

struct RevokeAfterHello<'a> {
    inner: &'a mut DatabaseTransport,
    policy: &'a Database,
    learned: bool,
    application_frames_after_denial: usize,
}

impl SyncTransport for RevokeAfterHello<'_> {
    type Error = io::Error;
    async fn send(&mut self, frame: Vec<u8>) -> io::Result<()> {
        self.inner.send(frame).await
    }
    async fn receive(&mut self) -> io::Result<Vec<u8>> {
        let frame = self.inner.receive().await?;
        let Ok(message) = postcard::from_bytes::<SyncMessage>(&frame) else {
            assert!(!self.learned, "no undecodable frame after denial");
            return Ok(frame);
        };
        let application = match &message {
            SyncMessage::State(units) => units.iter().any(|unit| {
                let ofdb_sql::SyncKey::Row { table, .. } = &unit.key;
                idp_service::security_sync::public_security_tables()
                    .into_iter()
                    .any(|public| public.name() == table)
            }),
            SyncMessage::Changes(changes) => changes.iter().any(|change| {
                idp_service::security_sync::public_security_tables()
                    .into_iter()
                    .any(|public| public.name() == change.table)
            }),
            _ => false,
        };
        if self.learned && application {
            self.application_frames_after_denial += 1;
        }
        if !self.learned && matches!(message, SyncMessage::Hello(_)) {
            sql(self.policy, "DELETE FROM role_permissions").await;
            self.learned = true;
        }
        Ok(frame)
    }
}
