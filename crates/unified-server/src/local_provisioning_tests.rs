use std::{
    collections::HashMap,
    fs,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use idp_model::model::Id;
use idp_service::repo::PrivateKeyKeyringRepo;

use crate::{LocalProvisioner, ServiceClientCredentials, UnifiedConfig};

struct SecretStore {
    store: Arc<keyring_core::mock::Store>,
    fail_node_readback: Arc<AtomicBool>,
}
impl keyring_core::api::CredentialStoreApi for SecretStore {
    fn vendor(&self) -> String {
        self.store.vendor()
    }
    fn id(&self) -> String {
        self.store.id()
    }
    fn build(
        &self,
        service: &str,
        user: &str,
        _: Option<&HashMap<&str, &str>>,
    ) -> keyring_core::Result<keyring_core::Entry> {
        let entry =
            keyring_core::api::CredentialStoreApi::build(&*self.store, service, user, None)?;
        if user.contains(":node:")
            && entry.get_secret().is_ok()
            && self.fail_node_readback.swap(false, Ordering::SeqCst)
        {
            return Err(keyring_core::Error::NoEntry);
        }
        Ok(entry)
    }
    fn search(&self, spec: &HashMap<&str, &str>) -> keyring_core::Result<Vec<keyring_core::Entry>> {
        self.store.search(spec)
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

struct Fixture {
    root: PathBuf,
    config: UnifiedConfig,
    password: PathBuf,
    store: Arc<keyring_core::CredentialStore>,
    fail_node_readback: Arc<AtomicBool>,
}

impl Fixture {
    fn new() -> Self {
        use std::io::Write;
        let root =
            std::env::temp_dir().join(format!("unified-local-provisioning-{}", Id::now_v7()));
        fs::create_dir(&root).expect("isolated host parent");
        let password = root.join("initial-password");
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&password)
            .expect("protected password input")
            .write_all(b"fixture-initial-password\n")
            .expect("write test password");
        let mut idp = idp_server::AppConfig::default();
        idp.data_dir = root.join("idp").to_string_lossy().into_owned();
        idp.oauth2.issuer = format!("https://installation-{}.test/idp", Id::now_v7());
        idp.api_public_uri = "https://identity.test".into();
        idp.service_audience = Some("https://identity.test/service".into());
        idp.password.memory_mib = 1;
        idp.password.iterations = 1;
        let management = management_server::AppConfig {
            data_dir: root.join("management").to_string_lossy().into_owned(),
            api_public_uri: "https://management.test".into(),
            storage_audience: "https://storage.test".into(),
            ..Default::default()
        };
        let storage = storage_server::AppConfig {
            data_dir: root.join("storage").to_string_lossy().into_owned(),
            api_public_uri: "https://storage.test".into(),
            ..Default::default()
        };
        let credentials = |secret: &str, audience: &str| ServiceClientCredentials {
            client_id: Id::now_v7().to_string(),
            client_secret: secret.into(),
            audience: audience.into(),
        };
        let config = UnifiedConfig {
            listen_addr: "127.0.0.1:0".parse().expect("local ephemeral listener"),
            endpoint_data_dir: root.join("endpoint"),
            idp,
            management,
            storage,
            management_idp_client: credentials(
                "fixture-management-idp-secret",
                "https://identity.test/service",
            ),
            storage_idp_client: credentials(
                "fixture-storage-idp-secret",
                "https://identity.test/service",
            ),
            storage_management_client: credentials(
                "fixture-storage-management-secret",
                "https://storage.test",
            ),
            idp_management_client: Some(credentials(
                "fixture-idp-management-secret",
                "idp-management",
            )),
        };
        let fail_node_readback = Arc::new(AtomicBool::new(false));
        let store: Arc<keyring_core::CredentialStore> = Arc::new(SecretStore {
            store: keyring_core::mock::Store::new().expect("credential adapter"),
            fail_node_readback: fail_node_readback.clone(),
        });
        let _ = PrivateKeyKeyringRepo::new_with_store(&config.idp.oauth2.issuer, store.clone());
        Self {
            root,
            config,
            password,
            store,
            fail_node_readback,
        }
    }

    fn journal(&self) -> serde_json::Value {
        serde_json::from_slice(
            &fs::read(
                self.config
                    .local_provisioning_directory()
                    .join("intent.json"),
            )
            .expect("retained host intent"),
        )
        .expect("public intent format")
    }

    fn secrets(&self) -> Vec<Vec<u8>> {
        let mut secrets = self
            .store
            .search(&HashMap::new())
            .expect("fixture provider inventory")
            .into_iter()
            .filter_map(|entry| entry.get_secret().ok())
            .collect::<Vec<_>>();
        secrets.sort();
        secrets
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).expect("remove only isolated fixture");
    }
}

fn secret_files_absent(root: &Path) {
    assert!(
        !root.join("endpoint/endpoint.key").exists(),
        "no private endpoint production before explicit provision"
    );
    assert!(
        !root.join("idp/idp.redb").exists(),
        "no owner writes before explicit provision"
    );
}

async fn exercise_running_host(runtime: crate::UnifiedRuntime, config: &UnifiedConfig, user: Id) {
    use idp_model::contract::{
        IdentityAction, IdentityResource, PermissionEvaluationRequest, PermissionSubject,
        PermissionTarget,
    };
    let base = format!("http://{}", runtime.local_addr());
    let cancellation = runtime.cancellation_token();
    let task = tokio::spawn(runtime.serve());
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("local authenticated owner API client");
    let mut healthy = false;
    for _ in 0..100 {
        if http
            .get(format!("{base}/idp/health"))
            .send()
            .await
            .is_ok_and(|response| response.status().is_success())
        {
            healthy = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(healthy, "actual host listener starts without peer contact");
    let mut evaluator = String::new();
    for (credentials, scopes) in [
        (
            &config.management_idp_client,
            "idp.token.validate idp.device.lookup",
        ),
        (
            &config.storage_idp_client,
            "idp.token.validate idp.device.lookup idp.device.list",
        ),
        (
            &config.storage_management_client,
            "management.replication.read management.replication.admit",
        ),
        (
            config
                .idp_management_client
                .as_ref()
                .expect("explicit evaluator relationship"),
            "management.permission.evaluate",
        ),
    ] {
        let response = http
            .post(format!("{base}/idp/oauth2/token"))
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", credentials.client_id.as_str()),
                ("client_secret", credentials.client_secret.as_str()),
                ("audience", credentials.audience.as_str()),
                ("scope", scopes),
            ])
            .send()
            .await
            .expect("ordinary authenticated service Client issuance");
        assert_eq!(
            response.status(),
            reqwest::StatusCode::OK,
            "exact local Client scopes/audience work through real listener"
        );
        let body: serde_json::Value = response.json().await.expect("token response");
        let token = body["access_token"]
            .as_str()
            .expect("normal service bearer");
        if scopes == "management.permission.evaluate" {
            evaluator = token.to_owned();
        }
    }
    for (action, resource) in [
        (
            IdentityAction::InfrastructureClientsCreate,
            IdentityResource::Client { client_id: None },
        ),
        (
            IdentityAction::DevicePairingUpdate,
            IdentityResource::DevicePairing,
        ),
        (
            IdentityAction::ReplicaSignersEnroll,
            IdentityResource::ReplicaSigner { member_id: None },
        ),
        (
            IdentityAction::IdpSecuritySync,
            IdentityResource::IdpSecurity,
        ),
        (
            IdentityAction::ManagementSecuritySync,
            IdentityResource::ManagementSecurity,
        ),
    ] {
        for (subject, expected) in [(user, true), (Id::now_v7(), false)] {
            let request = PermissionEvaluationRequest {
                request_id: Id::now_v7(),
                subject: PermissionSubject::User { id: subject },
                action,
                target: PermissionTarget::Installation {
                    resource: resource.clone(),
                },
            };
            let response = http
                .post(format!("{base}/management/permissions/evaluate"))
                .bearer_auth(&evaluator)
                .header("content-type", "application/json")
                .body(serde_json::to_vec(&request).expect("public permission request"))
                .send()
                .await
                .expect("normal registered evaluator API");
            assert_eq!(
                response.status(),
                reqwest::StatusCode::OK,
                "local permission evaluation uses real authenticated context composition"
            );
            let decision: serde_json::Value = response.json().await.expect("permission decision");
            assert_eq!(
                decision["allowed"], expected,
                "grants belong only to the retained initial User"
            );
        }
    }
    let request = PermissionEvaluationRequest {
        request_id: Id::now_v7(),
        subject: PermissionSubject::User { id: user },
        action: IdentityAction::ClientsCreate,
        target: PermissionTarget::Application {
            application_id: Id::now_v7(),
            resource: IdentityResource::Client { client_id: None },
        },
    };
    let response = http
        .post(format!("{base}/management/permissions/evaluate"))
        .bearer_auth(&evaluator)
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&request).expect("application-scoped request"))
        .send()
        .await
        .expect("normal application-scoped evaluation");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let decision: serde_json::Value = response.json().await.expect("application-scoped decision");
    assert_eq!(
        decision["allowed"], false,
        "initial Installation grants are not a global application role"
    );
    let credentials = &config.management_idp_client;
    let denied = http
        .post(format!("{base}/idp/oauth2/token"))
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", credentials.client_id.as_str()),
            ("client_secret", credentials.client_secret.as_str()),
            ("audience", credentials.audience.as_str()),
            ("scope", "idp.device.list"),
        ])
        .send()
        .await
        .expect("scope escalation request");
    assert!(
        !denied.status().is_success(),
        "Management to IdP cannot obtain Storage-only list scope"
    );
    cancellation.cancel();
    tokio::time::timeout(Duration::from_secs(60), task)
        .await
        .expect("bounded actual host shutdown")
        .expect("host task")
        .expect("host serve/shutdown");
}

#[tokio::test]
async fn local_provisioning_creates_exact_host_and_reopens_offline() {
    let fixture = Fixture::new();
    let mut host = LocalProvisioner::create(
        fixture.config.clone(),
        "operator",
        "Local Node",
        &fixture.password,
    )
    .expect("explicit local fresh intent");
    secret_files_absent(&fixture.root);
    assert!(
        host.build_runtime().await.is_err(),
        "incomplete setup is not startup readiness"
    );
    host.provision(&fixture.password)
        .await
        .expect("public local provisioning seam");
    let intent = fixture.journal();
    assert_eq!(
        intent["complete"], true,
        "completion follows actual local readiness"
    );
    let manifest = fs::read_to_string(
        fixture
            .config
            .local_provisioning_directory()
            .join("intent.json"),
    )
    .expect("public-only manifest");
    for secret in [
        "fixture-initial-password",
        "fixture-management-idp-secret",
        "fixture-storage-idp-secret",
        "fixture-storage-management-secret",
        "fixture-idp-management-secret",
    ] {
        assert!(
            !manifest.contains(secret),
            "raw credentials must not enter retained intent"
        );
    }
    let secrets = fixture.secrets();
    let runtime = host
        .build_runtime()
        .await
        .expect("actual composed host startup");
    assert!(
        runtime
            .node_public_ready()
            .await
            .expect("local trust and context grants")
    );
    let endpoint = runtime.endpoint_id();
    exercise_running_host(
        runtime,
        &fixture.config,
        intent["user"]
            .as_str()
            .expect("initial User")
            .parse()
            .expect("User ID"),
    )
    .await;
    drop(host);
    let host =
        LocalProvisioner::open(fixture.config.clone()).expect("existing-only journal reopen");
    let runtime = host
        .build_runtime()
        .await
        .expect("actual offline host reopen");
    assert_eq!(
        endpoint,
        runtime.endpoint_id(),
        "canonical endpoint survives restart"
    );
    assert!(
        runtime
            .node_public_ready()
            .await
            .expect("current readiness without a peer")
    );
    exercise_running_host(
        runtime,
        &fixture.config,
        intent["user"]
            .as_str()
            .expect("initial User")
            .parse()
            .expect("User ID"),
    )
    .await;
    assert!(
        secrets == fixture.secrets(),
        "host startup/reopen must not produce replacement private material"
    );
    assert!(
        intent == fixture.journal(),
        "startup must preserve exact completed intent"
    );
    fs::remove_file(fixture.root.join("endpoint/endpoint.key"))
        .expect("simulate canonical identity loss");
    assert!(
        host.build_runtime().await.is_err(),
        "completed startup never falls back to fresh identity"
    );
    assert!(
        !fixture.root.join("endpoint/endpoint.key").exists(),
        "missing identity stays missing"
    );
}

#[tokio::test]
async fn local_provisioning_continues_retained_attempt_and_refuses_changed_credentials() {
    let mut fixture = Fixture::new();
    let occupied = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("occupied listener fixture");
    fixture.config.listen_addr = occupied.local_addr().expect("retained listener address");
    let mut host = LocalProvisioner::create(
        fixture.config.clone(),
        "operator",
        "Local Node",
        &fixture.password,
    )
    .expect("fresh intent");
    assert!(
        host.provision(&fixture.password).await.is_err(),
        "later context failure leaves setup incomplete"
    );
    let retained = fixture.journal();
    assert_eq!(retained["complete"], false);
    assert!(
        retained["public_signer"].is_object(),
        "exact signer retained before failed composition"
    );
    assert!(
        host.build_runtime().await.is_err(),
        "partial owner setup is not host completion"
    );
    assert!(
        LocalProvisioner::open(fixture.config.clone()).is_err(),
        "one local operation owns this host"
    );
    let secrets = fixture.secrets();
    drop(host);
    let mut changed = fixture.config.clone();
    changed.storage_idp_client.client_secret = "changed-fixture-secret".into();
    assert!(
        LocalProvisioner::open(changed).is_err(),
        "env credential drift never rotates retained Client"
    );
    let mut changed = fixture.config.clone();
    changed.idp.oauth2.issuer = "https://different-installation.test/idp".into();
    assert!(
        LocalProvisioner::open(changed).is_err(),
        "Canonical Issuer drift is not a new Installation"
    );
    assert!(
        LocalProvisioner::create(
            fixture.config.clone(),
            "operator",
            "Local Node",
            &fixture.password
        )
        .is_err(),
        "retained attempt cannot be redeclared fresh"
    );
    drop(occupied);
    let mut host =
        LocalProvisioner::open(fixture.config.clone()).expect("exact offline continuation");
    fs::write(&fixture.password, b"wrong-fixture-password\n").expect("wrong protected input");
    assert!(
        host.provision(&fixture.password).await.is_err(),
        "wrong password denies before owner writes"
    );
    assert!(retained == fixture.journal());
    fs::write(&fixture.password, b"fixture-initial-password\n")
        .expect("restore exact fixture password");
    host.provision(&fixture.password)
        .await
        .expect("continue original public-owner preparation and compose contexts");
    let completed = fixture.journal();
    for field in [
        "installation",
        "user",
        "credential",
        "member",
        "key",
        "role",
        "permissions",
        "intent",
        "endpoint",
        "public_signer",
    ] {
        assert!(
            retained[field] == completed[field],
            "continuation must retain each original identity/request"
        );
    }
    assert!(
        secrets == fixture.secrets(),
        "exact continuation never replaces retained private secrets"
    );
}

#[tokio::test]
async fn local_provisioning_existing_cli_host_without_journal_starts_and_reopens() {
    use std::os::unix::fs::PermissionsExt;

    use idp_service::oauth2::NodeSignerBinding;
    let mut fixture = Fixture::new();
    let mut host = LocalProvisioner::create(
        fixture.config.clone(),
        "operator",
        "Local Node",
        &fixture.password,
    )
    .expect("explicit public owner provisioning");
    host.provision(&fixture.password)
        .await
        .expect("actual current host");
    let retained = fixture.journal();
    fixture.config.idp.oauth2.local_signer = Some(NodeSignerBinding {
        endpoint_id: retained["endpoint"].as_str().expect("endpoint").to_owned(),
        member_id: retained["member"]
            .as_str()
            .expect("member")
            .parse()
            .expect("ID"),
        key_id: retained["key"].as_str().expect("key").parse().expect("ID"),
    });
    let user = retained["user"]
        .as_str()
        .expect("User")
        .parse()
        .expect("ID");
    let secrets = fixture.secrets();
    drop(host);
    let directory = fixture.config.local_provisioning_directory();
    let journal_path = directory.join("intent.json");
    let mut incomplete = retained.clone();
    incomplete["complete"] = false.into();
    fs::write(
        &journal_path,
        serde_json::to_vec(&incomplete).expect("incomplete intent"),
    )
    .expect("retained incomplete fixture");
    assert!(
        LocalProvisioner::open_runtime(fixture.config.clone())
            .await
            .is_err(),
        "present incomplete journal is authoritative despite ready owner state"
    );
    fs::write(&journal_path, b"{}").expect("malformed journal");
    assert!(
        LocalProvisioner::open_runtime(fixture.config.clone())
            .await
            .is_err(),
        "present malformed journal cannot fall through"
    );
    fs::remove_file(&journal_path).expect("lost journal within present directory");
    assert!(
        LocalProvisioner::open_runtime(fixture.config.clone())
            .await
            .is_err(),
        "present directory with missing intent cannot fall through"
    );
    fs::remove_dir_all(&directory).expect("host retains owner state, not a CLI journal");
    let storage_root = Path::new(&fixture.config.storage.data_dir);
    fs::set_permissions(storage_root, fs::Permissions::from_mode(0o755))
        .expect("retained Storage permissions from ordinary 0022 umask");
    let runtime = crate::UnifiedRuntime::build(fixture.config.clone())
        .await
        .expect("public runtime supports retained 0755 Storage");
    assert!(
        runtime
            .node_public_ready()
            .await
            .expect("retained public readiness")
    );
    runtime.shutdown().await.expect("retained runtime shutdown");
    for _ in 0..2 {
        let (runtime, guard) = LocalProvisioner::open_runtime(fixture.config.clone())
            .await
            .expect("CLI existing-only decision accepts current explicit evidence");
        assert!(guard.is_none(), "no synthesized journal guard");
        assert!(
            runtime
                .node_public_ready()
                .await
                .expect("current readiness")
        );
        exercise_running_host(runtime, &fixture.config, user).await;
        assert!(!directory.exists(), "no journal migration or synthesis");
        assert!(secrets == fixture.secrets(), "no private replacement");
        assert_eq!(
            fs::metadata(storage_root)
                .expect("retained Storage root")
                .permissions()
                .mode()
                & 0o777,
            0o755,
            "existing startup must not chmod retained Storage"
        );
    }
    // The desktop's public composition seam remains independent of CLI intent.
    let runtime = crate::UnifiedRuntime::build(fixture.config.clone())
        .await
        .expect("desktop composition remains public");
    assert!(
        runtime
            .node_public_ready()
            .await
            .expect("preprovisioned readiness")
    );
    runtime.shutdown().await.expect("joined shutdown");
    let mut optional = fixture.config.clone();
    optional.idp_management_client = None;
    let (runtime, _) = LocalProvisioner::open_runtime(optional)
        .await
        .expect("existing composition does not require fresh command's fourth relationship");
    runtime
        .shutdown()
        .await
        .expect("optional relationship shutdown");
    let endpoint = fs::read(fixture.root.join("endpoint/endpoint.key")).expect("retained endpoint");

    let management_before = fs::read(fixture.root.join("management/management.redb"))
        .expect("retained Management database");
    let mut unbound = fixture.config.clone();
    unbound.idp.oauth2.local_signer = None;
    assert!(
        LocalProvisioner::open_runtime(unbound).await.is_err(),
        "missing explicit signer is never inferred"
    );
    let mut untrusted = fixture.config.clone();
    untrusted
        .idp
        .oauth2
        .local_signer
        .as_mut()
        .expect("binding")
        .key_id = Id::now_v7();
    assert!(
        LocalProvisioner::open_runtime(untrusted.clone())
            .await
            .is_err(),
        "missing trust cannot provision a new signer"
    );
    assert_eq!(
        endpoint,
        fs::read(fixture.root.join("endpoint/endpoint.key")).expect("unchanged endpoint")
    );
    assert!(secrets == fixture.secrets());
    let owner = idp_server::OwnerProvisioner::open(&fixture.config.idp)
        .await
        .expect("retained owner");
    let public = owner
        .verify_node_signer(
            fixture
                .config
                .idp
                .oauth2
                .local_signer
                .as_ref()
                .expect("binding"),
        )
        .await
        .expect("original approved signer survives denied startup");
    assert_eq!(
        serde_json::to_value(public).expect("public signer"),
        retained["public_signer"]
    );
    assert!(
        owner
            .verify_node_signer(
                untrusted
                    .idp
                    .oauth2
                    .local_signer
                    .as_ref()
                    .expect("missing binding")
            )
            .await
            .is_err()
    );
    drop(owner);
    assert_eq!(
        management_before,
        fs::read(fixture.root.join("management/management.redb"))
            .expect("Management unchanged on missing trust")
    );
    let endpoint_path = fixture.root.join("endpoint/endpoint.key");
    fs::set_permissions(&endpoint_path, fs::Permissions::from_mode(0o644))
        .expect("unprotected endpoint fixture");
    assert!(
        LocalProvisioner::open_runtime(fixture.config.clone())
            .await
            .is_err(),
        "retained directory policy must not weaken endpoint key security"
    );
    assert_eq!(
        fs::metadata(&endpoint_path)
            .expect("retained endpoint")
            .permissions()
            .mode()
            & 0o777,
        0o644
    );
    fs::remove_file(endpoint_path).expect("lost endpoint");
    assert!(
        LocalProvisioner::open_runtime(fixture.config.clone())
            .await
            .is_err()
    );
    assert!(!fixture.root.join("endpoint/endpoint.key").exists());
    assert!(!directory.exists());
}

#[tokio::test]
async fn local_provisioning_lost_management_after_late_failure_denies_without_recreation() {
    let mut fixture = Fixture::new();
    let occupied = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("occupied listener");
    fixture.config.listen_addr = occupied.local_addr().expect("listener address");
    let mut host = LocalProvisioner::create(
        fixture.config.clone(),
        "operator",
        "Local Node",
        &fixture.password,
    )
    .expect("fresh intent");
    assert!(host.provision(&fixture.password).await.is_err());
    let retained = fixture.journal();
    assert_eq!(retained["complete"], false);
    let database = fixture.root.join("management/management.redb");
    assert!(
        database.is_file(),
        "real Management initialization precedes late failure"
    );
    let secrets = fixture.secrets();
    let database_before = fs::read(&database).expect("retained Management bytes");
    let mut unacknowledged = retained.clone();
    unacknowledged["management_complete"] = false.into();
    unacknowledged["storage_attempted"] = false.into();
    unacknowledged["storage_initialized"] = false.into();
    let journal_path = fixture
        .config
        .local_provisioning_directory()
        .join("intent.json");
    fs::write(
        &journal_path,
        serde_json::to_vec(&unacknowledged).expect("unacknowledged Management intent"),
    )
    .expect("simulate interruption before Management acknowledgement");
    let error = host
        .provision(&fixture.password)
        .await
        .expect_err("attempted unacknowledged authority requires explicit recovery");
    assert!(
        error.to_string().contains("unacknowledged Management"),
        "{error}"
    );
    assert_eq!(
        database_before,
        fs::read(&database).expect("unchanged Management")
    );
    assert!(unacknowledged == fixture.journal());
    assert!(secrets == fixture.secrets());
    fs::write(
        &journal_path,
        serde_json::to_vec(&retained).expect("acknowledged original intent"),
    )
    .expect("restore original retained acknowledgement");
    fs::remove_file(&database).expect("lose attempted Management database");
    drop(occupied);
    assert!(
        host.provision(&fixture.password).await.is_err(),
        "lost authority requires recovery"
    );
    assert!(
        !database.exists(),
        "retry must not reconstruct grants or Device policy"
    );
    fs::remove_dir_all(fixture.root.join("management")).expect("lose Management root too");
    assert!(host.provision(&fixture.password).await.is_err());
    assert!(
        !fixture.root.join("management").exists(),
        "no replacement root"
    );
    assert!(
        retained == fixture.journal(),
        "retain exact incomplete evidence"
    );
    assert!(secrets == fixture.secrets(), "no new private production");
}

#[tokio::test]
async fn local_provisioning_lost_storage_after_runtime_initialization_denies_without_recreation() {
    let fixture = Fixture::new();
    let mut host = LocalProvisioner::create(
        fixture.config.clone(),
        "operator",
        "Local Node",
        &fixture.password,
    )
    .expect("fresh intent");
    host.provision(&fixture.password)
        .await
        .expect("actual initialized Storage runtime");
    let mut retained = fixture.journal();
    retained["complete"] = false.into();
    let journal_path = fixture
        .config
        .local_provisioning_directory()
        .join("intent.json");
    fs::write(
        &journal_path,
        serde_json::to_vec(&retained).expect("incomplete intent"),
    )
    .expect("interruption before final completion acknowledgement");
    let mut unacknowledged = retained.clone();
    unacknowledged["storage_initialized"] = false.into();
    fs::write(
        &journal_path,
        serde_json::to_vec(&unacknowledged).expect("unacknowledged Storage"),
    )
    .expect("interruption before Storage acknowledgement");
    assert!(
        host.provision(&fixture.password).await.is_err(),
        "unacknowledged Storage requires recovery even with retained roots"
    );
    assert!(unacknowledged == fixture.journal());
    fs::write(
        &journal_path,
        serde_json::to_vec(&retained).expect("acknowledged Storage"),
    )
    .expect("restore retained acknowledgement");
    let root = fixture.root.join("storage");
    assert!(root.is_dir(), "real runtime initialized Storage");
    fs::rename(&root, fixture.root.join("lost-storage")).expect("lose retained Storage root");
    assert!(
        host.provision(&fixture.password).await.is_err(),
        "lost attempted Storage is not fresh"
    );
    assert!(!root.exists(), "no empty replacement context");
    assert!(retained == fixture.journal());
    fs::rename(fixture.root.join("lost-storage"), &root).expect("restore exact retained root");
    host.provision(&fixture.password)
        .await
        .expect("exact acknowledged Storage continuation");
    fs::remove_dir_all(root.join("databases")).expect("lose acknowledged Storage runtime root");
    assert!(
        host.build_runtime().await.is_err(),
        "acknowledged Storage root loss requires recovery"
    );
    assert!(
        !root.join("databases").exists(),
        "no runtime scaffold recreation after acknowledgement"
    );
}

#[tokio::test]
async fn local_provisioning_missing_attempted_signer_denies_without_replacement() {
    let mut fixture = Fixture::new();
    let occupied = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("occupied listener fixture");
    fixture.config.listen_addr = occupied.local_addr().expect("retained listener address");
    let mut host = LocalProvisioner::create(
        fixture.config.clone(),
        "operator",
        "Local Node",
        &fixture.password,
    )
    .expect("fresh intent");
    assert!(host.provision(&fixture.password).await.is_err());
    let journal = fixture.journal();
    let selector = format!(
        "node:{}:{}",
        journal["member"].as_str().expect("member ID"),
        journal["key"].as_str().expect("key ID")
    );
    let spec = HashMap::from([("user", selector.as_str())]);
    let entries = fixture
        .store
        .search(&spec)
        .expect("exact test-only Node credential selection");
    assert_eq!(entries.len(), 1, "one captured Node root");
    entries[0]
        .delete_credential()
        .expect("simulate attempted signer loss");
    let secrets = fixture.secrets();
    drop(host);
    let mut host = LocalProvisioner::open(fixture.config.clone()).expect("retained host intent");
    assert!(
        host.provision(&fixture.password).await.is_err(),
        "existing-only prepared verification refuses missing signer"
    );
    assert!(
        host.build_runtime().await.is_err(),
        "incomplete host remains unready"
    );
    assert!(
        secrets == fixture.secrets(),
        "no replacement provider writes"
    );
    assert!(
        journal == fixture.journal(),
        "failed continuation preserves exact retry/recovery evidence"
    );
}

#[tokio::test]
async fn local_provisioning_reuses_pre_enrollment_signer_after_readback_interruption() {
    let fixture = Fixture::new();
    let mut host = LocalProvisioner::create(
        fixture.config.clone(),
        "operator",
        "Local Node",
        &fixture.password,
    )
    .expect("fresh intent");
    fixture.fail_node_readback.store(true, Ordering::SeqCst);
    assert!(
        host.provision(&fixture.password).await.is_err(),
        "post-store error leaves captured preparation but no enrollment"
    );
    assert!(
        !fixture.fail_node_readback.load(Ordering::SeqCst),
        "actual Node store/readback boundary exercised"
    );
    let retained = fixture.journal();
    assert_eq!(retained["node_attempted"], true);
    assert_eq!(
        retained["management_attempted"], false,
        "Management phase has genuinely never started"
    );
    assert_eq!(retained["storage_attempted"], false);
    assert!(!fixture.root.join("management").exists());
    assert!(!fixture.root.join("storage").exists());
    assert!(
        retained["public_signer"].is_null(),
        "caller has not acknowledged public signer capture yet"
    );
    let snapshot = fixture.secrets();
    drop(host);
    let mut host =
        LocalProvisioner::open(fixture.config.clone()).expect("same durable local intent");
    host.provision(&fixture.password)
        .await
        .expect("existing-only prepared verification before exact enrollment");
    let current = fixture.journal();
    assert_eq!(current["complete"], true);
    assert_eq!(current["management_attempted"], true);
    assert_eq!(current["management_complete"], true);
    assert!(
        fixture.root.join("management/management.redb").is_file(),
        "first authorized Management initialization succeeds"
    );
    for field in [
        "installation",
        "user",
        "credential",
        "member",
        "key",
        "role",
        "permissions",
        "intent",
        "endpoint",
    ] {
        assert!(
            retained[field] == current[field],
            "pre-enrollment continuation retains original IDs and requests"
        );
    }
    let current_secrets = fixture.secrets();
    assert!(
        snapshot
            .iter()
            .all(|secret| current_secrets.contains(secret)),
        "retained User/Node material is reused while untouched Client slots complete"
    );
}

#[test]
fn local_provisioning_rejects_fifo_password_before_opening_it() {
    let fixture = Fixture::new();
    let fifo = fixture.root.join("password-fifo");
    assert!(
        std::process::Command::new("mkfifo")
            .args(["-m", "600"])
            .arg(&fifo)
            .status()
            .expect("native FIFO fixture")
            .success()
    );
    let config = fixture.config.clone();
    let input = fifo.clone();
    let (send, receive) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        send.send(LocalProvisioner::create(config, "operator", "Local Node", &input).is_err())
            .expect("send invalid-input decision");
    });
    let decision = receive.recv_timeout(Duration::from_secs(1));
    if matches!(decision, Err(std::sync::mpsc::RecvTimeoutError::Timeout)) {
        fs::OpenOptions::new()
            .write(true)
            .open(&fifo)
            .expect("unblock only the failing FIFO reader fixture");
    }
    worker.join().expect("invalid-input worker terminates");
    assert!(
        matches!(decision, Ok(true)),
        "nonregular password input must refuse without blocking on open"
    );
    secret_files_absent(&fixture.root);
}

#[test]
fn local_provisioning_rejects_unprotected_input_and_missing_or_conflicting_intent() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let fixture = Fixture::new();
    assert!(
        LocalProvisioner::open(fixture.config.clone()).is_err(),
        "startup cannot synthesize fresh intent"
    );
    secret_files_absent(&fixture.root);
    fs::set_permissions(&fixture.password, fs::Permissions::from_mode(0o644))
        .expect("unsafe input fixture");
    assert!(
        LocalProvisioner::create(
            fixture.config.clone(),
            "operator",
            "Local Node",
            &fixture.password
        )
        .is_err()
    );
    assert!(
        !fixture.config.local_provisioning_directory().exists(),
        "unsafe input denies before intent publication"
    );
    fs::set_permissions(&fixture.password, fs::Permissions::from_mode(0o600))
        .expect("protect input");
    let link = fixture.root.join("password-link");
    symlink(&fixture.password, &link).expect("symlink input fixture");
    assert!(
        LocalProvisioner::create(fixture.config.clone(), "operator", "Local Node", &link).is_err()
    );
    let host = LocalProvisioner::create(
        fixture.config.clone(),
        "operator",
        "Local Node",
        &fixture.password,
    )
    .expect("explicit intent");
    secret_files_absent(&fixture.root);
    drop(host);
    let journal = fixture
        .config
        .local_provisioning_directory()
        .join("intent.json");
    let mut unknown_request = fixture.journal();
    unknown_request["intent"]["clients"][0]["unrecognized_request_field"] = true.into();
    fs::write(
        &journal,
        serde_json::to_vec(&unknown_request).expect("unknown request fixture"),
    )
    .expect("write unknown request field");
    assert!(
        LocalProvisioner::open(fixture.config.clone()).is_err(),
        "unknown nested request fields must not be silently normalized or migrated"
    );
    fs::write(&journal, b"{}").expect("corrupt intent fixture");
    assert!(LocalProvisioner::open(fixture.config.clone()).is_err());
    fs::remove_file(journal).expect("lost intent fixture");
    assert!(LocalProvisioner::open(fixture.config.clone()).is_err());
    assert!(
        LocalProvisioner::create(
            fixture.config.clone(),
            "operator",
            "Local Node",
            &fixture.password
        )
        .is_err(),
        "lost prior intent is not fresh authorization"
    );
    secret_files_absent(&fixture.root);
}
