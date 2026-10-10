use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender},
    },
};

use idp_model::{
    contract::{
        ApplicationRegistration, ClientCredentialsGrantRequest, ClientProfile, ClientRegistration,
        ClientType, GrantType, OAuth2ClientAuth, TokenEndpointAuthMethod, TokenRequest,
    },
    model::Id,
};
use idp_service::{
    oauth2::NodeSignerBinding,
    repo::{ClientRepo, KeyRepo, PrivateKeyRepo, RepoError, RepoResult},
};
use key::{DerivationPath, DerivedKey};
use model::contract::StandardClaims;

use crate::{AppConfig, OwnerProvisioner};

#[derive(Clone, Default)]
pub(crate) struct Secrets {
    values: Arc<Mutex<HashMap<(String, String), String>>>,
    pub(crate) fail: Arc<AtomicBool>,
    fail_delete: Arc<AtomicBool>,
    retain_on_delete: Arc<AtomicBool>,
    discard_write: Arc<AtomicBool>,
    pause_store: Arc<Mutex<Option<StorePause>>>,
}

struct StorePause {
    entered: SyncSender<()>,
    resume: Receiver<()>,
}

impl PrivateKeyRepo for Secrets {
    fn load(&self, namespace: &str, path: &DerivationPath) -> RepoResult<Option<DerivedKey>> {
        Ok(self
            .values
            .lock()
            .expect("secret map")
            .get(&(namespace.into(), path.to_string()))
            .map(|value| DerivedKey::from_xprv(value.clone(), path.clone()))
            .transpose()?)
    }
    fn store(&self, namespace: &str, key: &DerivedKey) -> RepoResult<()> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(RepoError::InvalidInput(
                "injected secure-store failure".into(),
            ));
        }
        if self.discard_write.load(Ordering::SeqCst) {
            return Ok(());
        }
        let pause = self.pause_store.lock().expect("store pause").take();
        if let Some(pause) = pause {
            pause.entered.send(()).expect("store observer");
            pause
                .resume
                .recv_timeout(std::time::Duration::from_secs(30))
                .expect("release paused store");
        }
        self.values.lock().expect("secret map").insert(
            (namespace.into(), key.derivation_path().to_string()),
            key.to_xprv_string().to_string(),
        );
        Ok(())
    }
    fn delete(&self, namespace: &str, path: &DerivationPath) -> RepoResult<()> {
        if self.fail_delete.load(Ordering::SeqCst) {
            return Err(RepoError::InvalidInput(
                "injected secure-store deletion failure".into(),
            ));
        }
        if self.retain_on_delete.load(Ordering::SeqCst) {
            return Ok(());
        }
        self.values
            .lock()
            .expect("secret map")
            .remove(&(namespace.into(), path.to_string()));
        Ok(())
    }
}

#[cfg(unix)]
#[tokio::test]
async fn inventory_cleanup_retry_requires_durable_resetting_fence() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let root = std::env::temp_dir().join(format!("inventory-fence-sync-{}", Id::now_v7()));
    let config = AppConfig {
        data_dir: root.to_string_lossy().into_owned(),
        ..AppConfig::default()
    };
    let secrets = Secrets::default();
    let owner = OwnerProvisioner::open_with_private_keys(&config, secrets.clone())
        .await
        .expect("owner");
    let user = Id::now_v7();
    let binding = NodeSignerBinding {
        member_id: Id::now_v7(),
        key_id: Id::now_v7(),
        endpoint_id: iroh::SecretKey::generate().public().to_string(),
    };
    owner
        .prepare_fresh_setup_secret_inventory(user, &[])
        .await
        .expect("fresh inventory");
    owner
        .prepare_setup_client_slots(&[])
        .await
        .expect("complete slots");
    owner
        .prepare_node_signer(&binding)
        .expect("actual private Node root");
    let before = secrets.values.lock().expect("secrets").clone();
    assert_eq!(
        before.len(),
        1,
        "the fixture must contain a deletable credential"
    );
    let manifest = root.join("setup-secret-inventory.json");
    let reference = root
        .join("local-client-key-references")
        .join(format!("user-{user}.json"));
    let retained_reference = std::fs::read(&reference).expect("retained User reference");
    let lock = root.join("setup-secret-operation.lock");
    let lock_inode = std::fs::metadata(&lock).expect("operation lock").ino();
    let permissions = std::fs::metadata(&root)
        .expect("owner directory")
        .permissions();

    // Renaming remains allowed, but opening the directory for sync must fail.
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o300))
        .expect("deny directory read");
    let first = owner
        .delete_local_secrets(binding.member_id, binding.key_id, user, &[])
        .await;
    let visible_fence = std::fs::read(&manifest);
    let after_first = secrets.values.lock().expect("secrets").clone();
    let retry = owner
        .delete_local_secrets(binding.member_id, binding.key_id, user, &[])
        .await;
    let after_retry = secrets.values.lock().expect("secrets").clone();
    let failed_reference = std::fs::read(&reference);
    let retained_lock = std::fs::metadata(&lock);
    let lock_probe = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&lock)
        .map(|file| file.try_lock());
    std::fs::set_permissions(&root, permissions).expect("restore directory access");

    let completed = owner
        .delete_local_secrets(binding.member_id, binding.key_id, user, &[])
        .await;
    let final_fence = std::fs::read(&manifest);
    let final_reference = std::fs::read(&reference);
    let remaining = secrets.values.lock().expect("secrets").clone();
    drop(owner);
    std::fs::remove_dir_all(root).expect("remove owned fixture");

    assert_eq!(
        first.expect_err("post-rename sync must fail").kind(),
        std::io::ErrorKind::PermissionDenied
    );
    let visible_fence = visible_fence.expect("canonical fence remains readable after failed sync");
    let record: serde_json::Value = serde_json::from_slice(&visible_fence).expect("visible fence");
    assert_eq!(
        record["phase"], "resetting",
        "the injected failure must be after rename"
    );
    assert_eq!(
        after_first, before,
        "failed fence must not delete any credential"
    );
    assert_eq!(
        retry
            .expect_err("existing resetting must repeat the durability boundary")
            .kind(),
        std::io::ErrorKind::PermissionDenied
    );
    assert_eq!(
        after_retry, before,
        "retry must not delete before successful fence sync"
    );
    assert_eq!(
        failed_reference.expect("failed cleanup retains references"),
        retained_reference
    );
    assert_eq!(
        retained_lock
            .expect("failed cleanup retains lock inode")
            .ino(),
        lock_inode
    );
    lock_probe
        .expect("lock file remains accessible")
        .expect("failed operation releases exclusion");
    completed.expect("successful fence sync permits exact cleanup retry");
    assert_eq!(final_fence.expect("durable fence retained"), visible_fence);
    assert_eq!(
        final_reference.expect("cleanup retains references"),
        retained_reference
    );
    assert!(
        remaining.is_empty(),
        "successful cleanup deletes the actual credential"
    );
}

#[tokio::test]
async fn inventory_concurrent_public_operations_preserve_capture() {
    let root = std::env::temp_dir().join(format!("inventory-concurrent-{}", Id::now_v7()));
    let config = AppConfig {
        data_dir: root.to_string_lossy().into_owned(),
        ..AppConfig::default()
    };
    let secrets = Secrets::default();
    let owner = Arc::new(
        OwnerProvisioner::open_with_private_keys(&config, secrets.clone())
            .await
            .expect("owner"),
    );
    let user = Id::now_v7();
    let client = Id::now_v7();
    owner
        .prepare_fresh_setup_secret_inventory(user, &[client])
        .await
        .expect("fresh authorization");
    owner
        .prepare_setup_client_slots(&[client])
        .await
        .expect("slots");
    owner
        .ensure_initial_user(user, Id::now_v7(), "concurrent-user", "valid-password")
        .await
        .expect("User");
    let (entered_tx, entered_rx) = mpsc::sync_channel(1);
    let (resume_tx, resume_rx) = mpsc::sync_channel(1);
    *secrets.pause_store.lock().expect("install pause") = Some(StorePause {
        entered: entered_tx,
        resume: resume_rx,
    });
    let worker_owner = Arc::clone(&owner);
    let worker = std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("worker runtime")
            .block_on(worker_owner.ensure_desktop_client(client))
    });
    entered_rx
        .recv_timeout(std::time::Duration::from_secs(30))
        .expect("actual store boundary");
    let reference_path = root
        .join("local-client-key-references")
        .join(format!("{client}.json"));
    let captured = std::fs::read(&reference_path).expect("capture before first private write");
    let inventory = std::fs::read(root.join("setup-secret-inventory.json")).expect("inventory");
    let reset = owner
        .delete_local_secrets(Id::now_v7(), Id::now_v7(), user, &[client])
        .await;
    let mut request = owner
        .oauth2
        .get_client(&client.to_string())
        .await
        .expect("committed Client metadata");
    request.client_type = ClientType::Confidential;
    request.allowed_grant_types = vec![GrantType::ClientCredentials];
    request.client_secret = Some("stable-service-secret".into());
    let service = owner.ensure_setup_infrastructure_client(request).await;
    let competing = [
        owner
            .prepare_fresh_setup_secret_inventory(Id::now_v7(), &[client])
            .await,
        owner.prepare_setup_client_slots(&[client]).await,
        owner.begin_client_provisioning(&client.to_string()).await,
        owner.ensure_initial_user_signing_key(user).await,
        owner.ensure_client_signing_key(&client.to_string()).await,
        owner.ensure_desktop_client(client).await.map(|_| ()),
    ];
    let binding = NodeSignerBinding {
        member_id: Id::now_v7(),
        key_id: Id::now_v7(),
        endpoint_id: iroh::SecretKey::generate().public().to_string(),
    };
    let node = owner.prepare_node_signer(&binding);
    let initial_node = owner
        .ensure_initial_node(&binding, user, "Concurrent Node")
        .await;
    let separate_descriptor = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(root.join("setup-secret-operation.lock"))
        .expect("independently opened lock inode");
    let descriptor_contention = separate_descriptor.try_lock();
    let retained = std::fs::read(&reference_path).expect("retained cleanup references");
    let contended_inventory =
        std::fs::read(root.join("setup-secret-inventory.json")).expect("contended inventory");
    resume_tx.send(()).expect("resume store");
    let creation = worker.join().expect("worker joined");
    owner
        .delete_local_secrets(Id::now_v7(), Id::now_v7(), user, &[client])
        .await
        .expect("cleanup after operation finishes");
    assert!(secrets.values.lock().expect("secrets").is_empty());
    let retained_inventory =
        std::fs::read(root.join("setup-secret-inventory.json")).expect("retained inventory");
    owner
        .prepare_setup_client_slots(&[client])
        .await
        .expect_err("reset fence bars ordinary preparation");
    owner
        .ensure_desktop_client(client)
        .await
        .expect_err("cleanup cannot be followed by provisioning");
    owner
        .ensure_initial_user_signing_key(user)
        .await
        .expect_err("reset fence bars User private work");
    assert_eq!(
        retained_inventory,
        std::fs::read(root.join("setup-secret-inventory.json")).expect("fence retained")
    );
    assert_eq!(
        captured,
        std::fs::read(&reference_path).expect("capture retained")
    );
    assert!(secrets.values.lock().expect("secrets").is_empty());
    drop(separate_descriptor);
    drop(owner);
    let reopened = OwnerProvisioner::open_with_private_keys(&config, secrets.clone())
        .await
        .expect("reopen reset inventory");
    reopened
        .ensure_desktop_client(client)
        .await
        .expect_err("reset fence survives native reopen");
    reopened
        .delete_local_secrets(Id::now_v7(), Id::now_v7(), user, &[client])
        .await
        .expect("explicit cleanup retry after reopen");
    assert_eq!(
        retained_inventory,
        std::fs::read(root.join("setup-secret-inventory.json")).expect("durable fence retained")
    );
    drop(reopened);
    std::fs::remove_dir_all(root).expect("fixture");
    assert!(
        reset.is_err_and(|error| error.kind() == std::io::ErrorKind::WouldBlock),
        "cleanup must not report success while an admitted private write is paused"
    );
    assert!(
        creation.is_ok(),
        "nested capture/signing helpers must not deadlock or lose metadata"
    );
    assert_eq!(captured, retained);
    assert_eq!(inventory, contended_inventory);
    for operation in
        competing
            .into_iter()
            .chain([initial_node, node.map(|_| ()), service.map(|_| ())])
    {
        assert!(operation.is_err_and(|error| error.kind() == std::io::ErrorKind::WouldBlock));
    }
    assert!(
        matches!(
            descriptor_contention,
            Err(std::fs::TryLockError::WouldBlock)
        ),
        "coordination is inode-based, not confined to one object"
    );
    assert_ne!(
        inventory, retained_inventory,
        "successful reset durably bars later provisioning"
    );
}

#[tokio::test]
async fn inventory_fresh_authorization_requires_exclusive_operation() {
    let root = std::env::temp_dir().join(format!("inventory-fresh-exclusive-{}", Id::now_v7()));
    let config = AppConfig {
        data_dir: root.to_string_lossy().into_owned(),
        ..AppConfig::default()
    };
    let owner = OwnerProvisioner::open_with_private_keys(&config, Secrets::default())
        .await
        .expect("owner");
    let held = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(root.join("setup-secret-operation.lock"))
        .expect("independent operation authority");
    held.lock().expect("exclusive operation");
    let user = Id::now_v7();
    let client = Id::now_v7();
    let fresh = owner
        .prepare_fresh_setup_secret_inventory(user, &[client])
        .await
        .expect_err("fresh authorization cannot race an admitted operation");
    assert_eq!(fresh.kind(), std::io::ErrorKind::WouldBlock);
    assert!(!root.join("setup-secret-inventory.json").exists());
    assert!(!root.join("local-client-key-references").exists());
    drop(held);
    owner
        .prepare_fresh_setup_secret_inventory(user, &[client])
        .await
        .expect("explicit fresh authorization after exclusion releases");
    let before = std::fs::read(root.join("setup-secret-inventory.json")).expect("manifest");
    owner
        .prepare_fresh_setup_secret_inventory(Id::now_v7(), &[Id::now_v7()])
        .await
        .expect_err("another fresh claim cannot replace existing evidence");
    assert_eq!(
        before,
        std::fs::read(root.join("setup-secret-inventory.json")).expect("retained evidence")
    );
    drop(owner);
    std::fs::remove_dir_all(root).expect("fixture");
}

#[tokio::test]
async fn inventory_captures_client_identity_and_paths_before_first_private_write() {
    let root = std::env::temp_dir().join(format!("inventory-capture-{}", Id::now_v7()));
    let config = AppConfig {
        data_dir: root.to_string_lossy().into_owned(),
        ..AppConfig::default()
    };
    let secrets = Secrets::default();
    let owner = OwnerProvisioner::open_with_private_keys(&config, secrets.clone())
        .await
        .expect("owner");
    let client = Id::now_v7();
    owner
        .prepare_fresh_setup_secret_inventory(Id::now_v7(), &[client])
        .await
        .expect("fresh");
    owner
        .prepare_setup_client_slots(&[client])
        .await
        .expect("prepare");
    secrets.fail.store(true, Ordering::SeqCst);
    owner
        .ensure_desktop_client(client)
        .await
        .expect_err("first private write fails");
    let record: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            root.join("local-client-key-references")
                .join(format!("{client}.json")),
        )
        .expect("reference"),
    )
    .expect("json");
    assert_eq!(record["state"], "resolved");
    assert!(record["entity_id"].is_string());
    assert!(!record["paths"].as_array().expect("paths").is_empty());
    assert!(secrets.values.lock().expect("secrets").is_empty());
    drop(owner);
    std::fs::remove_dir_all(root).expect("fixture");
}

#[tokio::test]
async fn inventory_pending_unknown_retry_is_denied() {
    let root = std::env::temp_dir().join(format!("inventory-pending-{}", Id::now_v7()));
    let config = AppConfig {
        data_dir: root.to_string_lossy().into_owned(),
        ..AppConfig::default()
    };
    let owner = OwnerProvisioner::open_with_private_keys(&config, Secrets::default())
        .await
        .expect("owner");
    let client = Id::now_v7();
    owner
        .prepare_fresh_setup_secret_inventory(Id::now_v7(), &[client])
        .await
        .expect("fresh");
    owner
        .prepare_setup_client_slots(&[client])
        .await
        .expect("prepare");
    owner
        .begin_client_provisioning(&client.to_string())
        .await
        .expect("begin");
    let path = root
        .join("local-client-key-references")
        .join(format!("{client}.json"));
    let before = std::fs::read(&path).expect("reference");
    owner
        .ensure_desktop_client(client)
        .await
        .expect_err("unknown pending history cannot register a replacement");
    assert_eq!(std::fs::read(&path).expect("reference"), before);
    std::fs::remove_file(&path).expect("lose references after attempt");
    owner
        .prepare_setup_client_slots(&[client])
        .await
        .expect_err("lost refs cannot become never-started");
    owner
        .prepare_fresh_setup_secret_inventory(Id::now_v7(), &[client])
        .await
        .expect_err("historical inventory cannot be replaced");
    assert!(!path.exists());
    drop(owner);
    let reopened = OwnerProvisioner::open_with_private_keys(&config, Secrets::default())
        .await
        .expect("reopen unknown history");
    reopened
        .ensure_desktop_client(client)
        .await
        .expect_err("denial survives native reopen");
    drop(reopened);
    std::fs::remove_dir_all(root).expect("fixture");
}

#[tokio::test]
async fn inventory_user_cleanup_survives_lost_key_metadata() {
    let root = std::env::temp_dir().join(format!("inventory-user-{}", Id::now_v7()));
    let config = AppConfig {
        data_dir: root.to_string_lossy().into_owned(),
        ..AppConfig::default()
    };
    let secrets = Secrets::default();
    let owner = OwnerProvisioner::open_with_private_keys(&config, secrets.clone())
        .await
        .expect("owner");
    let user = Id::now_v7();
    owner
        .prepare_fresh_setup_secret_inventory(user, &[])
        .await
        .expect("fresh");
    owner
        .prepare_setup_client_slots(&[])
        .await
        .expect("prepare");
    owner
        .ensure_initial_user(user, Id::now_v7(), "inventory-user", "valid-password")
        .await
        .expect("user");
    owner
        .ensure_initial_user_signing_key(user)
        .await
        .expect("signing key");
    owner
        .oauth2
        .key_service
        .key_repo()
        .delete_by_entity_type_and_id(idp_model::contract::EntityType::User, user)
        .await
        .expect("lose metadata");
    owner
        .ensure_initial_user_signing_key(user)
        .await
        .expect_err("missing metadata cannot mint another private path");
    owner
        .delete_local_secrets(Id::now_v7(), Id::now_v7(), user, &[])
        .await
        .expect("cleanup");
    assert!(
        secrets.values.lock().expect("secrets").is_empty(),
        "derived User credentials must not survive"
    );
    drop(owner);
    std::fs::remove_dir_all(root).expect("fixture");
}

#[tokio::test]
async fn inventory_partial_slot_preparation_can_reset() {
    let root = std::env::temp_dir().join(format!("inventory-preparation-{}", Id::now_v7()));
    let config = AppConfig {
        data_dir: root.to_string_lossy().into_owned(),
        ..AppConfig::default()
    };
    let owner = OwnerProvisioner::open_with_private_keys(&config, Secrets::default())
        .await
        .expect("owner");
    let clients = [Id::now_v7(), Id::now_v7()];
    let user = Id::now_v7();
    owner
        .prepare_fresh_setup_secret_inventory(user, &clients)
        .await
        .expect("fresh boundary");
    let blocked = root
        .join("local-client-key-references")
        .join(format!("{}.json", clients[1]));
    std::fs::create_dir_all(&blocked).expect("block second slot publication");
    owner
        .prepare_setup_client_slots(&clients)
        .await
        .expect_err("partial preparation");
    std::fs::remove_dir(&blocked).expect("unblock slot");
    let binding = NodeSignerBinding {
        member_id: Id::now_v7(),
        key_id: Id::now_v7(),
        endpoint_id: iroh::SecretKey::generate().public().to_string(),
    };
    owner
        .prepare_node_signer(&binding)
        .expect_err("preparing boundary bars private Node work");
    owner
        .ensure_desktop_client(clients[0])
        .await
        .expect_err("preparing boundary bars Client work");
    drop(owner);
    let owner = OwnerProvisioner::open_with_private_keys(&config, Secrets::default())
        .await
        .expect("reopen partial preparation");
    owner
        .delete_local_secrets(Id::now_v7(), Id::now_v7(), user, &clients)
        .await
        .expect("verified preparing boundary permits reset completion");
    drop(owner);
    std::fs::remove_dir_all(root).expect("fixture");
}

#[tokio::test]
async fn restricted_desktop_client_enables_local_user_signin_and_exact_retry() {
    let root = std::env::temp_dir().join(format!("desktop-client-{}", Id::now_v7()));
    let binding = NodeSignerBinding {
        member_id: Id::now_v7(),
        key_id: Id::now_v7(),
        endpoint_id: iroh::SecretKey::generate().public().to_string(),
    };
    let mut config = AppConfig {
        data_dir: root.to_string_lossy().into_owned(),
        ..AppConfig::default()
    };
    config.oauth2.local_signer = Some(binding.clone());
    let provisioner = OwnerProvisioner::open_with_private_keys(&config, Secrets::default())
        .await
        .expect("native owner");
    let user = Id::now_v7();
    let desktop_client = Id::now_v7();
    provisioner
        .prepare_fresh_setup_secret_inventory(user, &[desktop_client])
        .await
        .expect("fresh");
    provisioner
        .prepare_setup_client_slots(&[desktop_client])
        .await
        .expect("prepare");
    provisioner
        .ensure_initial_user(user, Id::now_v7(), "desktop-admin", "valid-password")
        .await
        .expect("restricted User setup");
    provisioner
        .ensure_initial_node(&binding, user, "Desktop Node")
        .await
        .expect("independent trusted local signer");
    provisioner
        .ensure_initial_user_signing_key(user)
        .await
        .expect("local User private/public key");
    provisioner
        .ensure_initial_user_signing_key(user)
        .await
        .expect("exact User key retry");
    let first = provisioner
        .ensure_desktop_client(desktop_client)
        .await
        .expect("restricted public desktop client");
    let retry = provisioner
        .ensure_desktop_client(desktop_client)
        .await
        .expect("exact client retry");
    assert_eq!(first.client_id, retry.client_id);
    assert_eq!(first.client_type, ClientType::Public);
    assert_eq!(
        first.token_endpoint_auth_method,
        TokenEndpointAuthMethod::None
    );
    assert!(first.client_secret.is_none());
    for (password, allowed) in [("wrong-password", false), ("valid-password", true)] {
        let result = provisioner
            .oauth2
            .token(
                TokenRequest::Password(idp_model::contract::PasswordGrantRequest {
                    client_id: desktop_client.to_string(),
                    username: "desktop-admin".into(),
                    password: password.into(),
                    scope: Some("openid profile email".into()),
                    resource: None,
                }),
                None,
            )
            .await;
        assert_eq!(
            result.is_ok(),
            allowed,
            "normal password verification is not bypassed: {:?}",
            result.as_ref().err()
        );
        if let Ok(token) = result {
            for audience in [config.oauth2.issuer.as_str(), "idp-management"] {
                let exchanged = provisioner
                    .oauth2
                    .token(
                        TokenRequest::TokenExchange(
                            idp_model::contract::TokenExchangeGrantRequest {
                                subject_token: token.access_token.0.clone(),
                                subject_token_type:
                                    idp_model::contract::SubjectTokenType::AccessToken,
                                actor_token: None,
                                actor_token_type: None,
                                resource: Some(audience.into()),
                                audience: None,
                                authorization_details: None,
                                scope: None,
                                requested_token_type: None,
                            },
                        ),
                        None,
                    )
                    .await
                    .expect("current owner audience exchange for ordinary desktop User");
                let claims = provisioner
                    .oauth2
                    .validate_access_token(&exchanged.access_token.0, audience)
                    .await
                    .expect("owner-specific User bearer");
                assert_eq!(claims.sub, user.to_string());
                assert_eq!(claims.aud, audience);
                assert_eq!(claims.scope, ["openid", "profile", "email"]);
                assert_eq!(claims.principal_type, model::contract::PrincipalType::User);
            }
        }
    }
    let keys = &provisioner.oauth2.key_service;
    let user_key = keys
        .key_repo()
        .find_by_entity_type_and_id(idp_model::contract::EntityType::User, user)
        .await
        .expect("retained public identity")
        .expect("User key");
    let namespace = keys.scoped_namespace(idp_model::contract::EntityType::User, user);
    keys.private_key_repo()
        .delete(&namespace, &user_key.derivation_path().expect("User path"))
        .expect("simulate lost private reference");
    let count = keys
        .private_key_repo()
        .values
        .lock()
        .expect("injected secure store")
        .len();
    assert!(
        provisioner
            .ensure_initial_user_signing_key(user)
            .await
            .expect_err("published trust must not regenerate private material")
            .to_string()
            .contains("explicit recovery")
    );
    assert_eq!(
        keys.private_key_repo()
            .values
            .lock()
            .expect("injected secure store")
            .len(),
        count
    );
    drop(provisioner);
    std::fs::remove_dir_all(root).expect("remove owned native fixture");
}

#[tokio::test]
async fn interrupted_desktop_client_retries_exact_key_and_reset_deletes_internal_namespace() {
    let root = std::env::temp_dir().join(format!("desktop-client-retry-{}", Id::now_v7()));
    let config = AppConfig {
        data_dir: root.to_string_lossy().into_owned(),
        ..AppConfig::default()
    };
    let secrets = Secrets::default();
    let provisioner = OwnerProvisioner::open_with_private_keys(&config, secrets.clone())
        .await
        .expect("native owner");
    let external_id = Id::now_v7();
    let user = Id::now_v7();
    provisioner
        .prepare_fresh_setup_secret_inventory(user, &[external_id])
        .await
        .expect("fresh");
    provisioner
        .prepare_setup_client_slots(&[external_id])
        .await
        .expect("prepare");
    secrets.fail.store(true, Ordering::SeqCst);
    provisioner
        .ensure_desktop_client(external_id)
        .await
        .expect_err("secure-store failure interrupts registration");
    let client = provisioner
        .oauth2
        .client_repo
        .find_client_by_client_id(&external_id.to_string())
        .await
        .expect("read interrupted client")
        .expect("durable client row");
    assert_ne!(
        client.id, external_id,
        "owner internal identity differs from OAuth client ID"
    );
    secrets.fail.store(false, Ordering::SeqCst);
    provisioner
        .ensure_desktop_client(external_id)
        .await
        .expect("complete interrupted registration");
    let keys = &provisioner.oauth2.key_service;
    let key = keys
        .key_repo()
        .find_by_entity_type_and_id(idp_model::contract::EntityType::Client, client.id)
        .await
        .expect("read client key")
        .expect("retry must complete missing key");
    assert!(key.public_jwk.is_some());
    let namespace = keys.scoped_namespace(idp_model::contract::EntityType::Client, client.id);
    let path = key.derivation_path().expect("client key path");
    let retained = secrets
        .load(&namespace, &path)
        .expect("read client secret")
        .expect("durable private key");
    provisioner
        .ensure_desktop_client(external_id)
        .await
        .expect("exact completed retry");
    assert_eq!(
        secrets
            .load(&namespace, &path)
            .expect("readback")
            .expect("key retained")
            .to_xprv_string(),
        retained.to_xprv_string()
    );
    secrets
        .delete(&namespace, &path)
        .expect("inject lost published private key");
    provisioner
        .ensure_desktop_client(external_id)
        .await
        .expect_err("published client identity must not rotate silently");
    assert!(
        secrets
            .load(&namespace, &path)
            .expect("no key recreation")
            .is_none()
    );
    secrets
        .store(&namespace, &retained)
        .expect("restore fixture's exact original key");
    provisioner
        .delete_local_secrets(Id::now_v7(), Id::now_v7(), user, &[external_id])
        .await
        .expect("offline reset resolves stable external reference through retained owner state");
    assert!(
        secrets.values.lock().expect("secret map").is_empty(),
        "reset removes internal Client namespace, not guessed external UUID namespace"
    );
    assert!(
        keys.key_repo()
            .list_by_entity_type_and_id(idp_model::contract::EntityType::Client, client.id)
            .await
            .expect("removed metadata")
            .is_empty()
    );
    drop(provisioner);
    std::fs::remove_dir_all(root).expect("remove owned native fixture");
}

#[tokio::test]
async fn reset_requires_verified_never_started_or_retained_client_references() {
    let root = std::env::temp_dir().join(format!("reset-client-intent-{}", Id::now_v7()));
    let config = AppConfig {
        data_dir: root.to_string_lossy().into_owned(),
        ..AppConfig::default()
    };
    let provisioner = OwnerProvisioner::open_with_private_keys(&config, Secrets::default())
        .await
        .expect("native owner");
    let member = Id::now_v7();
    let signer = Id::now_v7();
    let owner = Id::now_v7();
    let client = Id::now_v7();
    provisioner
        .delete_local_secrets(member, signer, owner, &[client])
        .await
        .expect_err("unknown namespaces cannot be silently skipped");
    provisioner
        .prepare_fresh_setup_secret_inventory(owner, &[client])
        .await
        .expect("fresh");
    provisioner
        .prepare_setup_client_slots(&[client])
        .await
        .expect("explicit never-started Client slot");
    provisioner
        .delete_local_secrets(member, signer, owner, &[client])
        .await
        .expect("never-started slot has no private Client namespace");
    provisioner
        .begin_client_provisioning(&client.to_string())
        .await
        .expect_err("completed reset bars later provisioning intent");
    provisioner
        .delete_local_secrets(member, signer, owner, &[client])
        .await
        .expect("explicit reset may retry its retained inventory");
    provisioner
        .ensure_desktop_client(client)
        .await
        .expect_err("reset fence cannot be overwritten by provisioning");
    provisioner
        .delete_local_secrets(member, signer, owner, &[client])
        .await
        .expect("terminal secret cleanup remains idempotent");
    drop(provisioner);
    std::fs::remove_dir_all(root).expect("remove native fixture");
}

#[tokio::test]
async fn reset_retains_deleted_client_namespace_across_native_reopen_and_secret_failure() {
    let root = std::env::temp_dir().join(format!("reset-deleted-client-{}", Id::now_v7()));
    let config = AppConfig {
        data_dir: root.to_string_lossy().into_owned(),
        ..AppConfig::default()
    };
    let secrets = Secrets::default();
    let external = Id::now_v7();
    let provisioner = OwnerProvisioner::open_with_private_keys(&config, secrets.clone())
        .await
        .expect("native owner");
    let user = Id::now_v7();
    provisioner
        .prepare_fresh_setup_secret_inventory(user, &[external])
        .await
        .expect("fresh");
    provisioner
        .prepare_setup_client_slots(&[external])
        .await
        .expect("prepare");
    provisioner
        .ensure_desktop_client(external)
        .await
        .expect("setup Client");
    let client = provisioner
        .oauth2
        .client_repo
        .find_client_by_client_id(&external.to_string())
        .await
        .expect("owner read")
        .expect("Client");
    let namespace = provisioner
        .oauth2
        .key_service
        .scoped_namespace(idp_model::contract::EntityType::Client, client.id);
    provisioner
        .oauth2
        .delete_client(&external.to_string())
        .await
        .expect("existing public Client deletion");
    assert!(
        secrets
            .load(&namespace, &DerivationPath::default())
            .expect("retained private root")
            .is_some()
    );
    drop(provisioner);
    let provisioner = OwnerProvisioner::open_with_private_keys(&config, secrets.clone())
        .await
        .expect("native reopen without public Client row");
    secrets.fail_delete.store(true, Ordering::SeqCst);
    provisioner
        .delete_local_secrets(Id::now_v7(), Id::now_v7(), user, &[external])
        .await
        .expect_err("reset cannot succeed with orphaned private keys");
    assert!(
        secrets
            .load(&namespace, &DerivationPath::default())
            .expect("failure preserves key")
            .is_some()
    );
    secrets.fail_delete.store(false, Ordering::SeqCst);
    provisioner
        .delete_local_secrets(Id::now_v7(), Id::now_v7(), user, &[external])
        .await
        .expect("exact retained reference retry");
    assert!(secrets.values.lock().expect("secret map").is_empty());
    provisioner
        .delete_local_secrets(Id::now_v7(), Id::now_v7(), user, &[external])
        .await
        .expect("idempotent secret deletion");
    drop(provisioner);
    std::fs::remove_dir_all(root).expect("remove native fixture");
}

#[tokio::test]
async fn secure_store_failure_keeps_initial_setup_incomplete_and_retryable() {
    let root = std::env::temp_dir().join(format!("node-interrupted-{}", Id::now_v7()));
    let config = AppConfig {
        data_dir: root.to_string_lossy().into_owned(),
        ..AppConfig::default()
    };
    let secrets = Secrets::default();
    let owner = Id::now_v7();
    let binding = NodeSignerBinding {
        member_id: Id::now_v7(),
        key_id: Id::now_v7(),
        endpoint_id: iroh::SecretKey::generate().public().to_string(),
    };
    let provisioner = OwnerProvisioner::open_with_private_keys(&config, secrets.clone())
        .await
        .expect("open interrupted setup");
    provisioner
        .prepare_fresh_setup_secret_inventory(owner, &[])
        .await
        .expect("fresh");
    provisioner
        .prepare_setup_client_slots(&[])
        .await
        .expect("prepare");
    provisioner
        .ensure_initial_user(owner, Id::now_v7(), "admin", "valid-password")
        .await
        .expect("initial User stage");
    secrets.fail.store(true, Ordering::SeqCst);
    assert!(
        provisioner
            .ensure_initial_node(&binding, owner, "Local Node")
            .await
            .expect_err("secure store must fail closed")
            .to_string()
            .contains("secure-store")
    );
    assert!(provisioner.verify_node_signer(&binding).await.is_err());
    secrets.fail.store(false, Ordering::SeqCst);
    secrets.discard_write.store(true, Ordering::SeqCst);
    assert!(
        provisioner.prepare_node_signer(&binding).is_err(),
        "acknowledged but lost private signer must not be published"
    );
    secrets.discard_write.store(false, Ordering::SeqCst);
    provisioner
        .ensure_initial_node(&binding, owner, "Local Node")
        .await
        .expect("resume signer stage");
    let public = provisioner
        .verify_node_signer(&binding)
        .await
        .expect("ready signer");
    secrets.fail_delete.store(true, Ordering::SeqCst);
    assert!(
        provisioner
            .delete_local_secrets(binding.member_id, binding.key_id, owner, &[])
            .await
            .is_err()
    );
    assert_eq!(
        provisioner
            .verify_node_signer(&binding)
            .await
            .expect("failed reset retains signer"),
        public
    );
    secrets.fail_delete.store(false, Ordering::SeqCst);
    secrets.retain_on_delete.store(true, Ordering::SeqCst);
    assert!(
        provisioner
            .delete_local_secrets(binding.member_id, binding.key_id, owner, &[])
            .await
            .is_err(),
        "successful deletion must be independently verified before discarding reset references"
    );
    secrets.retain_on_delete.store(false, Ordering::SeqCst);
    provisioner
        .delete_local_secrets(binding.member_id, binding.key_id, owner, &[])
        .await
        .expect("offline reset secrets");
    provisioner
        .delete_local_secrets(binding.member_id, binding.key_id, owner, &[])
        .await
        .expect("offline reset exact retry");
    assert!(
        provisioner
            .ensure_initial_node(&binding, owner, "Local Node")
            .await
            .is_err(),
        "approved missing private key must not be replaced"
    );
    assert!(
        secrets.values.lock().expect("secret map").is_empty(),
        "retry must not mint a replacement approved secret"
    );
    assert!(!public.kid.is_empty());
    drop(provisioner);
    std::fs::remove_dir_all(root).expect("remove isolated owner");
}

#[tokio::test]
#[ignore = "uses isolated real OS private-key credentials and native stores"]
async fn real_os_initial_node_signer_survives_native_reopen_and_offline_reset() {
    let root = std::env::temp_dir().join(format!("of04-real-os-signer-{}", Id::now_v7()));
    let mut config = AppConfig {
        data_dir: root.to_string_lossy().into_owned(),
        ..AppConfig::default()
    };
    config.oauth2.issuer = format!("https://of04-{}.test/idp", Id::now_v7());
    let owner = Id::now_v7();
    let credential = Id::now_v7();
    let binding = NodeSignerBinding {
        member_id: Id::now_v7(),
        key_id: Id::now_v7(),
        endpoint_id: iroh::SecretKey::generate().public().to_string(),
    };
    let public = {
        let provisioner = OwnerProvisioner::open(&config)
            .await
            .expect("real OS private-key provider");
        provisioner
            .prepare_fresh_setup_secret_inventory(owner, &[])
            .await
            .expect("fresh");
        provisioner
            .prepare_setup_client_slots(&[])
            .await
            .expect("prepare");
        provisioner
            .ensure_initial_user(
                owner,
                credential,
                "isolated-of04-admin",
                "isolated-of04-test-password",
            )
            .await
            .expect("real OS initial User credentials");
        provisioner
            .ensure_initial_node(&binding, owner, "Isolated real OS Node")
            .await
            .expect("readback before initial enrollment");
        provisioner
            .ensure_initial_node(&binding, owner, "Isolated real OS Node")
            .await
            .expect("real OS exact initial-node retry");
        provisioner
            .verify_node_signer(&binding)
            .await
            .expect("real OS current signer")
    };
    let reopened = OwnerProvisioner::open(&config)
        .await
        .expect("native owner reopen with real OS keys");
    assert_eq!(
        reopened
            .verify_node_signer(&binding)
            .await
            .expect("offline retained real OS signer"),
        public
    );
    reopened
        .delete_local_secrets(binding.member_id, binding.key_id, owner, &[])
        .await
        .expect("real OS local reset deletion and readback");
    reopened
        .delete_local_secrets(binding.member_id, binding.key_id, owner, &[])
        .await
        .expect("real OS offline idempotent reset retry");
    assert!(reopened.verify_node_signer(&binding).await.is_err());
    assert!(
        reopened
            .ensure_initial_node(&binding, owner, "Isolated real OS Node")
            .await
            .is_err(),
        "missing approved signer is not silently regenerated"
    );
    drop(reopened);
    std::fs::remove_dir_all(root).expect("real OS native fixture cleanup after key deletion");
}

#[tokio::test]
async fn native_initial_node_retries_and_reopens_with_independent_signing_capability() {
    let root = std::env::temp_dir().join(format!("node-setup-{}", Id::now_v7()));
    let mut config = AppConfig {
        data_dir: root.to_string_lossy().into_owned(),
        ..AppConfig::default()
    };
    config.oauth2.issuer = "https://installation.test/idp".into();
    let secrets = Secrets::default();
    let owner = Id::now_v7();
    let credential = Id::now_v7();
    let binding = NodeSignerBinding {
        member_id: Id::now_v7(),
        key_id: Id::now_v7(),
        endpoint_id: iroh::SecretKey::generate().public().to_string(),
    };
    config.oauth2.local_signer = Some(binding.clone());
    let client_id = Id::now_v7().to_string();
    let registration = ClientRegistration {
        application: ApplicationRegistration {
            name: Some("Local service".into()),
            uri: "https://service.test".into(),
            description: None,
        },
        client_id: Some(client_id.clone()),
        client_secret: Some("stable-local-secret".into()),
        client_id_issued_at: None,
        client_secret_expires_at: None,
        client_name: "Local service".into(),
        client_uri: None,
        logo_uri: None,
        contacts: vec![],
        terms_of_service_uri: None,
        policy_uri: None,
        client_type: ClientType::Confidential,
        profile: ClientProfile::Web,
        redirect_uris: vec![],
        allowed_grant_types: vec![GrantType::ClientCredentials],
        response_types: vec![],
        allowed_scopes: vec!["idp.token.validate".into()],
        allowed_audiences: vec!["https://service.test".into()],
        token_endpoint_auth_method: TokenEndpointAuthMethod::ClientSecretBasic,
        software_statement: None,
        software_id: None,
        software_version: None,
    };
    let request = TokenRequest::ClientCredentials(ClientCredentialsGrantRequest {
        client_id: client_id.clone(),
        client_secret: String::new(),
        scope: Some("idp.token.validate".into()),
        audience: Some("https://service.test".into()),
        resource: None,
    });
    let auth = OAuth2ClientAuth {
        client_id: client_id.clone(),
        client_secret: Some("stable-local-secret".into()),
        method: TokenEndpointAuthMethod::ClientSecretBasic,
    };
    let (public, token) = {
        let provisioner = OwnerProvisioner::open_with_private_keys(&config, secrets.clone())
            .await
            .expect("open native owner");
        let slot = client_id.parse().expect("client identity");
        provisioner
            .prepare_fresh_setup_secret_inventory(owner, &[slot])
            .await
            .expect("fresh");
        provisioner
            .prepare_setup_client_slots(&[slot])
            .await
            .expect("prepare");
        provisioner
            .ensure_initial_user(owner, credential, "admin", "valid-password")
            .await
            .expect("initial owner");
        let public = provisioner
            .prepare_node_signer(&binding)
            .expect("persist private preparation");
        assert!(
            provisioner.verify_node_signer(&binding).await.is_err(),
            "private preparation is not public approval"
        );
        provisioner
            .ensure_initial_node(&binding, owner, "Local Node")
            .await
            .expect("approve restricted initial node");
        provisioner
            .ensure_initial_node(&binding, owner, "Local Node")
            .await
            .expect("exact interrupted retry");
        assert_eq!(
            provisioner
                .verify_node_signer(&binding)
                .await
                .expect("approved signer"),
            public
        );
        provisioner
            .ensure_setup_infrastructure_client(registration.clone())
            .await
            .expect("local service relationship");
        provisioner
            .ensure_setup_infrastructure_client(registration)
            .await
            .expect("exact service retry");
        let token = provisioner
            .oauth2
            .token(request.clone(), Some(auth.clone()))
            .await
            .expect("production local token issuance");
        let (header, claims) =
            idp_service::oauth2::verify_jwt::<StandardClaims>(&public, &token.access_token.0)
                .expect("verify production signature");
        assert_eq!(header.kid, binding.key_id.to_string());
        assert_eq!(claims.iss, "https://installation.test/idp");
        assert_ne!(claims.sub, binding.member_id.to_string());
        (public, token)
    };
    let provisioner = OwnerProvisioner::open_with_private_keys(&config, secrets.clone())
        .await
        .expect("reopen native owner offline");
    assert_eq!(
        provisioner
            .verify_node_signer(&binding)
            .await
            .expect("offline persisted signer"),
        public
    );
    let claims = provisioner
        .oauth2
        .validate_access_token(&token.access_token.0, "https://service.test")
        .await
        .expect("persisted public trust validates before any peer contact");
    let reopened_token = provisioner
        .oauth2
        .token(request, Some(auth))
        .await
        .expect("offline issuance after native reopen");
    let (_, reopened_claims) =
        idp_service::oauth2::verify_jwt::<StandardClaims>(&public, &reopened_token.access_token.0)
            .expect("reopened production signer");
    assert_eq!(reopened_claims.sub, claims.sub);
    assert_eq!(reopened_claims.iss, claims.iss);
    let forged = NodeSignerBinding {
        endpoint_id: iroh::SecretKey::generate().public().to_string(),
        ..binding.clone()
    };
    assert!(
        provisioner
            .ensure_initial_node(&forged, owner, "Local Node")
            .await
            .is_err()
    );
    assert!(
        provisioner
            .ensure_initial_node(&binding, Id::now_v7(), "Local Node")
            .await
            .is_err()
    );
    assert_eq!(
        provisioner
            .verify_node_signer(&binding)
            .await
            .expect("forgery leaves original intact"),
        public
    );
    drop(provisioner);
    let missing = OwnerProvisioner::open_with_private_keys(&config, Secrets::default())
        .await
        .expect("owner with unavailable secret");
    assert!(
        missing.verify_node_signer(&binding).await.is_err(),
        "must not create replacement at restart"
    );
    drop(missing);
    std::fs::remove_dir_all(root).expect("remove isolated owner store");
}
