use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
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
    repo::{PrivateKeyRepo, RepoError, RepoResult},
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
            .ensure_infrastructure_client(registration.clone())
            .await
            .expect("local service relationship");
        provisioner
            .ensure_infrastructure_client(registration)
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
