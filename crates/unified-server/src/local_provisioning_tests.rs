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
