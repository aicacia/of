use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    path::Path,
    sync::Arc,
};

use db::open_native_engine;
use idp_model::contract::{
    ApplicationRegistration, ClientProfile, ClientRegistration, ClientType, EntityType, GrantType,
    TokenEndpointAuthMethod,
};
use idp_service::{
    generate_random_string,
    replica::{DbApplicationRepo, DbClientRepo, DbKeyRepo},
    repo::{
        ApplicationRepo, ClientRepo, KeyRepo, KeyService, PrivateKeyKeyringRepo, PrivateKeyRepo,
    },
};
use serde::Serialize;

use crate::AppConfig;

#[derive(Serialize)]
struct ClientCredentials {
    client_id: String,
    client_secret: String,
}

pub async fn run(
    app_config: &AppConfig,
    application_uri: &str,
    client_name: &str,
    audiences: Vec<String>,
    scopes: Vec<String>,
    credentials_path: &Path,
) -> io::Result<()> {
    validate_values(application_uri, client_name, &audiences, &scopes)?;
    #[cfg(not(unix))]
    return Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "service-client credential files require Unix owner-only permissions",
    ));

    let database_path = Path::new(&app_config.data_dir).join("idp.redb");
    if !database_path.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("IdP database does not exist: {}", database_path.display()),
        ));
    }
    if credentials_path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "credential output file already exists",
        ));
    }

    let engine = Arc::new(open_native_engine(database_path).map_err(io::Error::other)?);

    let key_service = Arc::new(KeyService::new(
        DbKeyRepo::new(Arc::clone(&engine)),
        PrivateKeyKeyringRepo::new(&app_config.oauth2.issuer),
        app_config.key_namespace.clone(),
    ));
    let client_repo = DbClientRepo::new(Arc::clone(&engine), Arc::clone(&key_service));
    provision(
        &DbApplicationRepo::new(Arc::clone(&engine)),
        &client_repo,
        &key_service,
        application_uri,
        client_name,
        audiences,
        scopes,
        credentials_path,
    )
    .await
}

async fn provision<A, C, K, P>(
    application_repo: &A,
    client_repo: &C,
    key_service: &KeyService<K, P>,
    application_uri: &str,
    client_name: &str,
    audiences: Vec<String>,
    scopes: Vec<String>,
    credentials_path: &Path,
) -> io::Result<()>
where
    A: ApplicationRepo,
    C: ClientRepo,
    K: KeyRepo,
    P: PrivateKeyRepo,
{
    let application = application_repo
        .find_by_uri(application_uri)
        .await
        .map_err(io::Error::other)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "application not found"))?;

    let client_id = generate_random_string::<32>();
    let client_secret = generate_random_string::<64>();
    if client_repo
        .find_client_by_client_id(&client_id)
        .await
        .map_err(io::Error::other)?
        .is_some()
    {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "generated client ID already exists; retry provisioning",
        ));
    }

    let credentials = ClientCredentials {
        client_id: client_id.clone(),
        client_secret: client_secret.clone(),
    };
    let credential_bytes = serde_json::to_vec(&credentials).map_err(io::Error::other)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut credentials_file = options.open(credentials_path)?;
    if let Err(error) = credentials_file
        .write_all(&credential_bytes)
        .and_then(|()| credentials_file.sync_all())
    {
        drop(credentials_file);
        fs::remove_file(credentials_path)?;
        return Err(error);
    }
    drop(credentials_file);
    #[cfg(unix)]
    {
        let parent = credentials_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        if let Err(error) = std::fs::File::open(parent).and_then(|directory| directory.sync_all()) {
            fs::remove_file(credentials_path)?;
            return Err(error);
        }
    }

    let registration = ClientRegistration {
        application: ApplicationRegistration {
            name: Some(application.name),
            uri: application.uri,
            description: application.description,
        },
        client_id: Some(client_id.clone()),
        client_secret: Some(client_secret),
        client_id_issued_at: None,
        client_secret_expires_at: None,
        client_name: client_name.to_owned(),
        client_uri: None,
        logo_uri: None,
        contacts: Vec::new(),
        terms_of_service_uri: None,
        policy_uri: None,
        client_type: ClientType::Confidential,
        profile: ClientProfile::Web,
        redirect_uris: Vec::new(),
        allowed_grant_types: vec![GrantType::ClientCredentials],
        response_types: Vec::new(),
        allowed_scopes: scopes,
        allowed_audiences: audiences,
        token_endpoint_auth_method: TokenEndpointAuthMethod::ClientSecretPost,
        software_statement: None,
        software_id: None,
        software_version: None,
    };

    match client_repo.create_client(registration).await {
        Ok(_) => Ok(()),
        Err(error) => {
            let partial_client = client_repo
                .find_client_by_client_id(&client_id)
                .await
                .map_err(|cleanup_error| {
                    io::Error::other(format!(
                        "provisioning failed ({error}); could not verify client cleanup ({cleanup_error}); credentials retained at {}",
                        credentials_path.display()
                    ))
                })?;
            if let Some(partial_client) = partial_client {
                key_service
                    .delete_entity_key_material(EntityType::Client, partial_client.id)
                    .await
                    .map_err(|cleanup_error| {
                        io::Error::other(format!(
                            "provisioning failed ({error}); key cleanup failed ({cleanup_error}); credentials retained at {}",
                            credentials_path.display()
                        ))
                    })?;
                client_repo
                    .delete_client_by_client_id(&client_id)
                    .await
                    .map_err(|cleanup_error| {
                        io::Error::other(format!(
                            "provisioning failed ({error}); client cleanup failed ({cleanup_error}); credentials retained at {}",
                            credentials_path.display()
                        ))
                    })?;
            }
            fs::remove_file(credentials_path)?;
            Err(io::Error::other(error))
        }
    }
}

fn validate_values(
    application_uri: &str,
    client_name: &str,
    audiences: &[String],
    scopes: &[String],
) -> io::Result<()> {
    if application_uri.trim().is_empty()
        || client_name.trim().is_empty()
        || audiences.is_empty()
        || scopes.is_empty()
        || audiences
            .iter()
            .chain(scopes)
            .any(|value| value.trim().is_empty() || value.trim() != value)
        || has_duplicates(audiences)
        || has_duplicates(scopes)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "application, client name, unique audiences, and unique scopes are required",
        ));
    }
    Ok(())
}

fn has_duplicates(values: &[String]) -> bool {
    values
        .iter()
        .enumerate()
        .any(|(index, value)| values[..index].contains(value))
}

#[cfg(test)]
mod tests {
    use std::{
        any::Any,
        collections::HashMap,
        fs,
        io::{Read, Write},
        net::TcpStream,
        os::unix::fs::PermissionsExt,
        sync::{Arc, Mutex},
    };

    use db::open_native_engine;
    use idp_model::contract::{
        ClientCredentialsGrantRequest, EntityType, IntrospectionRequest, OAuth2ClientAuth,
        TokenRequest,
    };
    use idp_service::{
        PasswordConfig,
        oauth2::{OAuth2Config, OAuth2Service, decode_jwt},
        replica::{
            DbApplicationRepo, DbClientRepo, DbKeyRepo, DbOAuth2AuthorizationCodeRepo,
            DbOAuth2RefreshTokenRepo, DbOAuth2UserConsentRepo, DbUserRepo,
        },
        repo::{
            ApplicationRepo, ClientRepo, KeyRepo, KeyService, OAuth2AuthorizationCodeRepo,
            PrivateKeyKeyringRepo, PrivateKeyRepo, RepoResult, UserRepo,
        },
    };
    use iroh::{Endpoint, SecretKey, endpoint::presets};
    use key::{DerivationPath, DerivedKey};
    use model::contract::{PrincipalType, StandardClaims, TokenType, TokenUse};

    struct ModifierTolerantTestStore {
        inner: Arc<keyring_core::mock::Store>,
    }

    impl keyring_core::api::CredentialStoreApi for ModifierTolerantTestStore {
        fn vendor(&self) -> String {
            self.inner.vendor()
        }

        fn id(&self) -> String {
            self.inner.id()
        }

        fn build(
            &self,
            service: &str,
            user: &str,
            _modifiers: Option<&HashMap<&str, &str>>,
        ) -> keyring_core::Result<keyring_core::Entry> {
            keyring_core::api::CredentialStoreApi::build(&*self.inner, service, user, None)
        }

        fn search(
            &self,
            spec: &HashMap<&str, &str>,
        ) -> keyring_core::Result<Vec<keyring_core::Entry>> {
            keyring_core::api::CredentialStoreApi::search(&*self.inner, spec)
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    fn test_keyring_store() -> Arc<keyring_core::CredentialStore> {
        Arc::new(ModifierTolerantTestStore {
            inner: keyring_core::mock::Store::new().expect("create mock credential store"),
        })
    }

    use super::{has_duplicates, provision, validate_values};

    #[derive(Clone)]
    struct TestPrivateKeyRepo {
        keys: Arc<Mutex<HashMap<(String, String), String>>>,
        store_calls: Arc<Mutex<usize>>,
        fail_on_store: Option<usize>,
    }

    impl TestPrivateKeyRepo {
        fn new(fail_on_store: Option<usize>) -> Self {
            Self {
                keys: Arc::new(Mutex::new(HashMap::new())),
                store_calls: Arc::new(Mutex::new(0)),
                fail_on_store,
            }
        }
    }

    impl PrivateKeyRepo for TestPrivateKeyRepo {
        fn load(
            &self,
            namespace: &str,
            derivation_path: &DerivationPath,
        ) -> RepoResult<Option<DerivedKey>> {
            let keys = self.keys.lock().expect("test key map lock");
            Ok(keys
                .get(&(namespace.to_owned(), derivation_path.to_string()))
                .map(|key| DerivedKey::from_xprv(key.clone(), derivation_path.clone()))
                .transpose()?)
        }

        fn store(&self, namespace: &str, derived_key: &DerivedKey) -> RepoResult<()> {
            let mut store_calls = self.store_calls.lock().expect("test store count lock");
            *store_calls += 1;
            if self.fail_on_store == Some(*store_calls) {
                return Err(idp_service::repo::RepoError::InvalidInput(
                    "injected keyring write failure".to_owned(),
                ));
            }
            self.keys.lock().expect("test key map lock").insert(
                (
                    namespace.to_owned(),
                    derived_key.derivation_path().to_string(),
                ),
                derived_key.to_xprv_string().to_string(),
            );
            Ok(())
        }

        fn delete(&self, namespace: &str, derivation_path: &DerivationPath) -> RepoResult<()> {
            self.keys
                .lock()
                .expect("test key map lock")
                .remove(&(namespace.to_owned(), derivation_path.to_string()));
            Ok(())
        }
    }

    #[test]
    fn service_client_inputs_require_unique_non_empty_audiences_and_scopes() {
        assert!(
            validate_values(
                "app",
                "service",
                &["idp".to_owned()],
                &["idp.token.validate".to_owned()]
            )
            .is_ok()
        );
        assert!(validate_values("app", "service", &[], &["scope".to_owned()]).is_err());
        assert!(
            validate_values(
                "app",
                "service",
                &["audience".to_owned(), "audience".to_owned()],
                &["scope".to_owned()]
            )
            .is_err()
        );
        assert!(
            validate_values(
                "app",
                "service",
                &["audience".to_owned()],
                &["scope".to_owned(), "scope".to_owned()]
            )
            .is_err()
        );
    }

    #[test]
    fn duplicate_check_handles_unique_values() {
        assert!(!has_duplicates(&["one".to_owned(), "two".to_owned()]));
    }

    #[test]
    fn failed_child_keyring_write_removes_partial_client_and_key_material() {
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .build()
                    .expect("build test runtime")
                    .block_on(async {
                        let root = std::env::temp_dir().join(format!(
                            "idp-service-client-failure-{}-{}",
                            std::process::id(),
                            idp_model::model::Id::now_v7()
                        ));
                        fs::create_dir_all(&root).expect("create temporary test directory");
                        let database_path = root.join("idp.redb");
                        let credentials_path = root.join("credentials.json");
                        let engine = Arc::new(
                            open_native_engine(&database_path).expect("open test database"),
                        );
                        idp_model::replica::up(&engine)
                            .await
                            .expect("initialize current IdP schema");
                        let applications = DbApplicationRepo::new(Arc::clone(&engine));
                        applications
                            .create_application(
                                "Test application".to_owned(),
                                "https://example.test/app".to_owned(),
                                None,
                            )
                            .await
                            .expect("create canonical application");
                        let private_keys = TestPrivateKeyRepo::new(Some(2));
                        let key_service = Arc::new(KeyService::new(
                            DbKeyRepo::new(Arc::clone(&engine)),
                            private_keys.clone(),
                            "test-namespace".to_owned(),
                        ));
                        let clients =
                            DbClientRepo::new(Arc::clone(&engine), Arc::clone(&key_service));

                        let error = provision(
                            &applications,
                            &clients,
                            &key_service,
                            "https://example.test/app",
                            "Test service",
                            vec!["https://management.example.test".to_owned()],
                            vec!["management.replication.read".to_owned()],
                            &credentials_path,
                        )
                        .await
                        .expect_err("injected keyring write failure must fail provisioning");
                        assert!(error.to_string().contains("injected keyring write failure"));
                        assert!(!credentials_path.exists());
                        assert!(
                            private_keys
                                .keys
                                .lock()
                                .expect("test key map lock")
                                .is_empty()
                        );
                        assert!(
                            key_service
                                .key_repo()
                                .list_active()
                                .await
                                .expect("list keys after rollback")
                                .is_empty()
                        );
                        assert!(
                            clients
                                .list_clients(0, 100)
                                .await
                                .expect("list clients after rollback")
                                .is_empty()
                        );

                        drop(clients);
                        drop(applications);
                        drop(engine);
                        fs::remove_dir_all(root).expect("remove temporary test directory");
                    });
            })
            .expect("spawn test thread")
            .join()
            .expect("test thread did not panic");
    }

    #[test]
    fn live_idp_listener_issues_and_introspects_service_tokens() {
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .thread_stack_size(16 * 1024 * 1024)
                    .enable_all()
                    .build()
                    .expect("build test runtime")
                    .block_on(run_live_idp_listener_test());
            })
            .expect("spawn large-stack test thread")
            .join()
            .expect("test thread did not panic");
    }

    async fn run_live_idp_listener_test() {
        use management_service::{DeviceRepo, replica::DbDeviceRepo};

        let root = std::env::temp_dir().join(format!(
            "idp-live-service-client-{}-{}",
            std::process::id(),
            idp_model::model::Id::now_v7()
        ));
        fs::create_dir_all(&root).expect("create temporary test directory");
        let engine =
            Arc::new(open_native_engine(root.join("idp.redb")).expect("open test database"));
        idp_model::replica::up(&engine)
            .await
            .expect("initialize current IdP schema");
        let applications = DbApplicationRepo::new(Arc::clone(&engine));
        applications
            .create_application(
                "Test application".to_owned(),
                "https://example.test/app".to_owned(),
                None,
            )
            .await
            .expect("create canonical application");
        let key_service = Arc::new(KeyService::new(
            DbKeyRepo::new(Arc::clone(&engine)),
            PrivateKeyKeyringRepo::new_with_store("idp-live-test", test_keyring_store()),
            "live-test-namespace".to_owned(),
        ));
        let clients = DbClientRepo::new(Arc::clone(&engine), Arc::clone(&key_service));
        let credentials_path = root.join("service-credentials.json");
        provision(
            &applications,
            &clients,
            &key_service,
            "https://example.test/app",
            "management-to-idp",
            vec![
                "https://idp.example.test".to_owned(),
                "https://management.example.test".to_owned(),
            ],
            vec![
                "idp.token.validate".to_owned(),
                "idp.device.lookup".to_owned(),
            ],
            &credentials_path,
        )
        .await
        .expect("provision test service client");
        let credentials: serde_json::Value =
            serde_json::from_slice(&fs::read(&credentials_path).expect("read service credentials"))
                .expect("parse service credentials");
        let client_id = credentials["client_id"]
            .as_str()
            .expect("service client ID is a string");
        let client_secret = credentials["client_secret"]
            .as_str()
            .expect("service client secret is a string");
        let application_id = clients
            .find_client_by_client_id(client_id)
            .await
            .expect("read provisioned service client")
            .expect("service client exists")
            .application_id
            .to_string();
        let storage_idp_credentials_path = root.join("storage-idp-credentials.json");
        provision(
            &applications,
            &clients,
            &key_service,
            "https://example.test/app",
            "storage-to-idp",
            vec!["https://idp.example.test".to_owned()],
            vec![
                "idp.token.validate".to_owned(),
                "idp.device.lookup".to_owned(),
                "idp.device.list".to_owned(),
            ],
            &storage_idp_credentials_path,
        )
        .await
        .expect("provision test Storage IdP client");
        let storage_idp_credentials: serde_json::Value = serde_json::from_slice(
            &fs::read(&storage_idp_credentials_path).expect("read Storage IdP credentials"),
        )
        .expect("parse Storage IdP credentials");
        let storage_idp_client_id = storage_idp_credentials["client_id"]
            .as_str()
            .expect("Storage IdP client ID is a string");
        let storage_idp_client_secret = storage_idp_credentials["client_secret"]
            .as_str()
            .expect("Storage IdP client secret is a string");
        let issuer = "https://idp.example.test";
        let oauth2_service = Arc::new(OAuth2Service::new(
            DbApplicationRepo::new(Arc::clone(&engine)),
            DbClientRepo::new(Arc::clone(&engine), Arc::clone(&key_service)),
            DbOAuth2AuthorizationCodeRepo::new(Arc::clone(&engine)),
            DbOAuth2RefreshTokenRepo::new(Arc::clone(&engine)),
            DbUserRepo::new(Arc::clone(&engine), PasswordConfig::default()),
            DbOAuth2UserConsentRepo::new(Arc::clone(&engine)),
            key_service,
            OAuth2Config {
                issuer: issuer.to_owned(),
                ..OAuth2Config::default()
            },
        ));
        let refresh_client = oauth2_service
            .client_repo
            .create_client(
                serde_json::from_value(serde_json::json!({
                    "application": { "uri": "https://example.test/app" },
                    "client_id": "live-refresh-client",
                    "client_secret": "live-refresh-secret",
                    "client_name": "Refresh client",
                    "client_type": "confidential",
                    "profile": "web_application",
                    "redirect_uris": ["https://example.test/callback"],
                    "allowed_grant_types": ["authorization_code", "refresh_token"],
                    "response_types": ["code"],
                    "allowed_scopes": ["openid"],
                    "token_endpoint_auth_method": "client_secret_basic"
                }))
                .expect("build refresh client registration"),
            )
            .await
            .expect("create live refresh client");
        let refresh_user = oauth2_service
            .user_repo
            .create_user_with_password("refresh-user", "refresh-password")
            .await
            .expect("create refresh user");
        oauth2_service
            .key_service
            .ensure_entity_master_key(EntityType::User, refresh_user.id, "refresh-password")
            .expect("create refresh user master key");
        let (refresh_key, _) = oauth2_service
            .key_service
            .create_key(
                None,
                EntityType::User,
                refresh_user.id,
                true,
                "refresh key".into(),
                None,
            )
            .await
            .expect("create refresh signing key");
        let refresh_code = oauth2_service
            .authorization_code_repo
            .create_authorization_code(
                refresh_client.client_id.clone(),
                refresh_key.id,
                "https://example.test/callback".into(),
                vec!["openid".into()],
                None,
                None,
                None,
                None,
                (std::time::SystemTime::now() + std::time::Duration::from_secs(300)).into(),
            )
            .await
            .expect("persist live authorization code");
        let secret_key = SecretKey::generate();
        let endpoint = Endpoint::builder(presets::N0)
            .secret_key(secret_key.clone())
            .bind()
            .await
            .expect("bind temporary IdP Iroh endpoint");
        let devices = Arc::new(DbDeviceRepo::new(Arc::clone(&engine)));
        let endpoint_id = endpoint.id().to_string();
        let approved_device = devices
            .create(
                "test-owner".to_owned(),
                "approved-storage".to_owned(),
                endpoint_id.clone(),
                "test-address".to_owned(),
                Vec::new(),
                0,
            )
            .await
            .expect("create approved endpoint identity");
        let secondary_endpoint_id = SecretKey::generate().public().to_string();
        let secondary_device = devices
            .create_pairing(
                "secondary-storage".to_owned(),
                secondary_endpoint_id.clone(),
                "test-address".to_owned(),
                endpoint_id.clone(),
            )
            .await
            .expect("create secondary device enrollment");
        devices
            .approve_pairing(secondary_device.id)
            .await
            .expect("approve secondary device")
            .expect("secondary device exists");
        let state = crate::RouterState::new(
            issuer,
            issuer,
            Arc::clone(&engine),
            oauth2_service,
            Arc::clone(&devices),
            Arc::new(crate::DeviceIdentity::new(endpoint.clone(), secret_key)),
        );
        let app = crate::openapi_router(state, "/").split_for_parts().0;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind IdP HTTP listener");
        let address = listener.local_addr().expect("read IdP HTTP address");
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve IdP test router");
        });

        for (method, path, body) in [
            ("GET", "/oauth2/register/test-client", ""),
            ("POST", "/oauth2/register", "{}"),
            ("PUT", "/oauth2/register/test-client", "{}"),
            ("DELETE", "/oauth2/register/test-client", ""),
        ] {
            let response =
                loopback_http_request(address, method, path, "application/json", body, None);
            assert!(
                response.starts_with("HTTP/1.1 401"),
                "{method} {path}: {response}"
            );
        }
        let removed_sign_route = loopback_http_request(
            address,
            "POST",
            "/device/sign",
            "application/json",
            "{}",
            None,
        );
        assert!(
            removed_sign_route.starts_with("HTTP/1.1 404"),
            "{removed_sign_route}"
        );

        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let refresh_auth = format!(
            "Basic {}",
            STANDARD.encode("live-refresh-client:live-refresh-secret")
        );
        let code_form = format!(
            "grant_type=authorization_code&code={}&code_verifier=test-verifier&client_id=live-refresh-client&redirect_uri={}",
            form_encode(&refresh_code.code),
            form_encode("https://example.test/callback"),
        );
        let issued = loopback_http_authorized_request(
            address,
            "POST",
            "/oauth2/token",
            "application/x-www-form-urlencoded",
            &code_form,
            Some(&refresh_auth),
        );
        assert!(issued.starts_with("HTTP/1.1 200"), "{issued}");
        let issued: model::contract::TokenResponse =
            serde_json::from_str(http_response_body(&issued)).expect("parse user token response");
        let refresh = issued.refresh_token.expect("issued refresh token").0;
        let refresh_form = format!(
            "grant_type=refresh_token&refresh_token={}",
            form_encode(&refresh)
        );
        let wrong_auth = format!(
            "Basic {}",
            STANDARD.encode("live-refresh-client:wrong-secret")
        );
        let wrong_client_auth = format!(
            "Basic {}",
            STANDARD.encode(format!("{client_id}:{client_secret}"))
        );
        for authorization in [&wrong_auth, &wrong_client_auth] {
            let rejected = loopback_http_authorized_request(
                address,
                "POST",
                "/oauth2/token",
                "application/x-www-form-urlencoded",
                &refresh_form,
                Some(authorization),
            );
            assert!(rejected.starts_with("HTTP/1.1 400"), "{rejected}");
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(http_response_body(&rejected))
                    .expect("parse wrong-client rejection")["error"],
                "invalid_client"
            );
        }
        let forged = format!("{refresh}x");
        let forged_form = format!(
            "grant_type=refresh_token&refresh_token={}",
            form_encode(&forged)
        );
        let rejected = loopback_http_authorized_request(
            address,
            "POST",
            "/oauth2/token",
            "application/x-www-form-urlencoded",
            &forged_form,
            Some(&refresh_auth),
        );
        assert!(rejected.starts_with("HTTP/1.1 400"), "{rejected}");
        let rotated = loopback_http_authorized_request(
            address,
            "POST",
            "/oauth2/token",
            "application/x-www-form-urlencoded",
            &refresh_form,
            Some(&refresh_auth),
        );
        assert!(rotated.starts_with("HTTP/1.1 200"), "{rotated}");
        let rotated: model::contract::TokenResponse =
            serde_json::from_str(http_response_body(&rotated))
                .expect("parse rotated token response");
        let replacement = rotated.refresh_token.expect("rotated refresh token").0;
        assert_ne!(refresh, replacement);
        let reuse = loopback_http_authorized_request(
            address,
            "POST",
            "/oauth2/token",
            "application/x-www-form-urlencoded",
            &refresh_form,
            Some(&refresh_auth),
        );
        assert!(reuse.starts_with("HTTP/1.1 400"), "{reuse}");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(http_response_body(&reuse))
                .expect("parse refresh reuse rejection")["error"],
            "invalid_grant"
        );
        let revoke_form = format!(
            "token={}&token_type_hint=refresh_token",
            form_encode(&replacement)
        );
        for authorization in [
            None,
            Some(wrong_auth.as_str()),
            Some(wrong_client_auth.as_str()),
        ] {
            let denied = loopback_http_authorized_request(
                address,
                "POST",
                "/oauth2/revoke",
                "application/x-www-form-urlencoded",
                &revoke_form,
                authorization,
            );
            assert!(denied.starts_with("HTTP/1.1 400"), "{denied}");
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(http_response_body(&denied))
                    .expect("parse revoke authentication rejection")["error"],
                "invalid_client"
            );
        }
        for _ in 0..2 {
            let revoked = loopback_http_authorized_request(
                address,
                "POST",
                "/oauth2/revoke",
                "application/x-www-form-urlencoded",
                &revoke_form,
                Some(&refresh_auth),
            );
            assert!(revoked.starts_with("HTTP/1.1 200"), "{revoked}");
        }
        let replacement_form = format!(
            "grant_type=refresh_token&refresh_token={}",
            form_encode(&replacement)
        );
        let revoked = loopback_http_authorized_request(
            address,
            "POST",
            "/oauth2/token",
            "application/x-www-form-urlencoded",
            &replacement_form,
            Some(&refresh_auth),
        );
        assert!(revoked.starts_with("HTTP/1.1 400"), "{revoked}");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(http_response_body(&revoked))
                .expect("parse revoked refresh rejection")["error"],
            "invalid_grant"
        );

        let form = format!(
            "grant_type=client_credentials&client_id={}&client_secret={}&scope=idp.token.validate%20idp.device.lookup&audience={}",
            form_encode(client_id),
            form_encode(client_secret),
            form_encode(issuer),
        );
        let wrong_secret_form = format!(
            "grant_type=client_credentials&client_id={}&client_secret=wrong-secret&scope=idp.token.validate%20idp.device.lookup&audience={}",
            form_encode(client_id),
            form_encode(issuer),
        );
        let rejected_token = loopback_http_request(
            address,
            "POST",
            "/oauth2/token",
            "application/x-www-form-urlencoded",
            &wrong_secret_form,
            None,
        );
        assert!(
            rejected_token.starts_with("HTTP/1.1 400"),
            "{rejected_token}"
        );
        let rejected_body: serde_json::Value =
            serde_json::from_str(http_response_body(&rejected_token))
                .expect("parse rejected client authentication response");
        assert_eq!(rejected_body["error"], "invalid_client");

        let token_response = loopback_http_request(
            address,
            "POST",
            "/oauth2/token",
            "application/x-www-form-urlencoded",
            &form,
            None,
        );
        assert!(
            token_response.starts_with("HTTP/1.1 200"),
            "{token_response}"
        );
        let token_body = http_response_body(&token_response);
        let token: serde_json::Value =
            serde_json::from_str(token_body).expect("parse live token response");
        assert!(token["id_token"].is_null());
        assert!(token["refresh_token"].is_null());
        let access_token = token["access_token"]
            .as_str()
            .expect("access token is a string");

        let introspection_body = serde_json::to_string(&IntrospectionRequest {
            token: access_token.to_owned(),
            token_type_hint: None,
        })
        .expect("serialize introspection request");
        let introspection_response = loopback_http_request(
            address,
            "POST",
            "/oauth2/introspect",
            "application/json",
            &introspection_body,
            Some(access_token),
        );
        assert!(
            introspection_response.starts_with("HTTP/1.1 200"),
            "{introspection_response}"
        );
        let introspected: idp_model::contract::IntrospectionResponse =
            serde_json::from_str(http_response_body(&introspection_response))
                .expect("parse live introspection response");
        assert_eq!(introspected.claims.principal_type, PrincipalType::Client);
        assert_eq!(introspected.claims.client_id, client_id);
        assert_eq!(introspected.claims.aud, issuer);
        assert_eq!(
            introspected.claims.scope,
            vec!["idp.token.validate", "idp.device.lookup"]
        );
        assert_eq!(introspected.application_id, application_id);

        let device_list_form = format!(
            "grant_type=client_credentials&client_id={}&client_secret={}&scope=idp.device.list&audience={}",
            form_encode(storage_idp_client_id),
            form_encode(storage_idp_client_secret),
            form_encode(issuer),
        );
        let device_list_token_response = loopback_http_request(
            address,
            "POST",
            "/oauth2/token",
            "application/x-www-form-urlencoded",
            &device_list_form,
            None,
        );
        assert!(
            device_list_token_response.starts_with("HTTP/1.1 200"),
            "{device_list_token_response}"
        );
        let device_list_token: serde_json::Value =
            serde_json::from_str(http_response_body(&device_list_token_response))
                .expect("parse Storage endpoint-list token");
        let device_list_access_token = device_list_token["access_token"]
            .as_str()
            .expect("Storage endpoint-list token is a string");
        let endpoint_list_response = loopback_http_request(
            address,
            "GET",
            "/devices/endpoints",
            "application/json",
            "",
            Some(device_list_access_token),
        );
        assert!(
            endpoint_list_response.starts_with("HTTP/1.1 200"),
            "{endpoint_list_response}"
        );
        let endpoint_list: idp_model::contract::ApprovedDeviceEndpoints =
            serde_json::from_str(http_response_body(&endpoint_list_response))
                .expect("parse approved endpoint list");
        assert_eq!(endpoint_list.endpoint_ids.len(), 2);
        assert!(endpoint_list.endpoint_ids.contains(&endpoint_id));
        assert!(endpoint_list.endpoint_ids.contains(&secondary_endpoint_id));
        let lookup_client_list_response = loopback_http_request(
            address,
            "GET",
            "/devices/endpoints",
            "application/json",
            "",
            Some(access_token),
        );
        assert!(
            lookup_client_list_response.starts_with("HTTP/1.1 403"),
            "{lookup_client_list_response}"
        );
        let endpoint_identity_response = loopback_http_request(
            address,
            "GET",
            &format!("/devices/endpoints/{endpoint_id}"),
            "application/json",
            "",
            Some(access_token),
        );
        assert!(
            endpoint_identity_response.starts_with("HTTP/1.1 200"),
            "{endpoint_identity_response}"
        );
        let endpoint_identity: idp_model::contract::DeviceEndpointIdentity =
            serde_json::from_str(http_response_body(&endpoint_identity_response))
                .expect("parse approved endpoint identity");
        assert_eq!(endpoint_identity.device_id, approved_device.id);
        assert_eq!(endpoint_identity.owner_subject, "test-owner");
        assert_eq!(endpoint_identity.endpoint_id, endpoint_id);

        server.abort();
        let _ = server.await;
        endpoint.close().await;
        drop(clients);
        drop(applications);
        drop(engine);
        fs::remove_dir_all(root).expect("remove test database directory");
    }

    fn loopback_http_request(
        address: std::net::SocketAddr,
        method: &str,
        path: &str,
        content_type: &str,
        body: &str,
        bearer: Option<&str>,
    ) -> String {
        let authorization = bearer.map(|token| format!("Bearer {token}"));
        loopback_http_authorized_request(
            address,
            method,
            path,
            content_type,
            body,
            authorization.as_deref(),
        )
    }

    fn loopback_http_authorized_request(
        address: std::net::SocketAddr,
        method: &str,
        path: &str,
        content_type: &str,
        body: &str,
        authorization: Option<&str>,
    ) -> String {
        let mut stream = TcpStream::connect(address).expect("connect to IdP HTTP listener");
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .expect("set HTTP read timeout");
        stream
            .set_write_timeout(Some(std::time::Duration::from_secs(10)))
            .expect("set HTTP write timeout");
        let authorization = authorization
            .map(|value| format!("Authorization: {value}\r\n"))
            .unwrap_or_default();
        write!(
            stream,
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n{authorization}Connection: close\r\n\r\n{body}",
            body.len(),
        )
        .expect("write request to IdP listener");
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .expect("read response from IdP listener");
        response
    }

    fn http_response_body(response: &str) -> &str {
        response
            .split_once("\r\n\r\n")
            .expect("HTTP response has a body separator")
            .1
    }

    fn form_encode(value: &str) -> String {
        let mut encoded = String::new();
        for byte in value.bytes() {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
                encoded.push(char::from(byte));
            } else {
                use std::fmt::Write as _;
                write!(encoded, "%{byte:02X}").expect("write percent-encoded form value");
            }
        }
        encoded
    }

    #[test]
    fn provisioning_creates_scoped_client_and_private_credentials_file() {
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .build()
                    .expect("build test runtime")
                    .block_on(async {
                        let root = std::env::temp_dir().join(format!(
                            "idp-service-client-{}-{}",
                            std::process::id(),
                            idp_model::model::Id::now_v7()
                        ));
                        fs::create_dir_all(&root).expect("create temporary test directory");
                        let database_path = root.join("idp.redb");
                        let credentials_path = root.join("credentials.json");
                        let engine = Arc::new(
                            open_native_engine(&database_path).expect("open test database"),
                        );
                        idp_model::replica::up(&engine)
                            .await
                            .expect("initialize current IdP schema");

                        let applications = DbApplicationRepo::new(Arc::clone(&engine));
                        applications
                            .create_application(
                                "Test application".to_owned(),
                                "https://example.test/app".to_owned(),
                                None,
                            )
                            .await
                            .expect("create canonical application");
                        let key_service = Arc::new(KeyService::new(
                            DbKeyRepo::new(Arc::clone(&engine)),
                            TestPrivateKeyRepo::new(None),
                            "test-namespace".to_owned(),
                        ));
                        let clients =
                            DbClientRepo::new(Arc::clone(&engine), Arc::clone(&key_service));

                        provision(
                            &applications,
                            &clients,
                            &key_service,
                            "https://example.test/app",
                            "management-to-idp",
                            vec![
                                "https://idp.example.test".to_owned(),
                                "https://user-api.example.test".to_owned(),
                            ],
                            vec![
                                "idp.token.validate".to_owned(),
                                "idp.device.lookup".to_owned(),
                            ],
                            &credentials_path,
                        )
                        .await
                        .expect("provision service client");

                        let credentials: serde_json::Value = serde_json::from_slice(
                            &fs::read(&credentials_path).expect("read credentials"),
                        )
                        .expect("parse credentials");
                        let client_id = credentials["client_id"]
                            .as_str()
                            .expect("credential client ID is a string");
                        let client_secret = credentials["client_secret"]
                            .as_str()
                            .expect("credential secret is a string");
                        let client = clients
                            .find_client_by_client_id(client_id)
                            .await
                            .expect("read created client")
                            .expect("client exists");
                        assert_ne!(client.client_secret_hash, client_secret);
                        assert!(client.client_secret_hash.starts_with("$argon2id$"));
                        assert_eq!(client.client_name, "management-to-idp");
                        assert_eq!(
                            client.allowed_audiences,
                            vec!["https://idp.example.test", "https://user-api.example.test"]
                        );
                        assert_eq!(
                            client.allowed_scopes,
                            vec!["idp.token.validate", "idp.device.lookup"]
                        );
                        assert_eq!(
                            client.allowed_grant_types,
                            vec![idp_model::contract::GrantType::ClientCredentials]
                        );
                        assert_eq!(
                            fs::metadata(&credentials_path)
                                .expect("read credential file metadata")
                                .permissions()
                                .mode()
                                & 0o777,
                            0o600
                        );

                        assert!(
                            provision(
                                &applications,
                                &clients,
                                &key_service,
                                "https://example.test/app",
                                "Second service",
                                vec!["audience".to_owned()],
                                vec!["scope".to_owned()],
                                &credentials_path,
                            )
                            .await
                            .is_err()
                        );
                        assert_eq!(
                            fs::read(&credentials_path)
                                .expect("existing credentials stay unchanged"),
                            serde_json::to_vec(&credentials).expect("serialize credentials")
                        );

                        let first_client_id = client_id.to_owned();
                        let registrations = [
                            (
                                "storage-to-idp",
                                vec![
                                    "https://idp.example.test".to_owned(),
                                    "https://user-api.example.test".to_owned(),
                                ],
                                vec![
                                    "idp.token.validate".to_owned(),
                                    "idp.device.lookup".to_owned(),
                                    "idp.device.list".to_owned(),
                                ],
                                "storage-idp.json",
                            ),
                            (
                                "storage-to-management",
                                vec!["https://management.example.test".to_owned()],
                                vec![
                                    "management.replication.read".to_owned(),
                                    "management.replication.admit".to_owned(),
                                ],
                                "storage-management.json",
                            ),
                        ];
                        for (name, audiences, scopes, file_name) in registrations {
                            let service_credentials_path = root.join(file_name);
                            provision(
                                &applications,
                                &clients,
                                &key_service,
                                "https://example.test/app",
                                name,
                                audiences.clone(),
                                scopes.clone(),
                                &service_credentials_path,
                            )
                            .await
                            .expect("provision distinct service client");
                            let service_credentials: serde_json::Value = serde_json::from_slice(
                                &fs::read(&service_credentials_path)
                                    .expect("read service credentials"),
                            )
                            .expect("parse service credentials");
                            let service_client_id = service_credentials["client_id"]
                                .as_str()
                                .expect("service client ID is a string");
                            let service_client = clients
                                .find_client_by_client_id(service_client_id)
                                .await
                                .expect("read service client")
                                .expect("service client exists");
                            assert_ne!(service_client.client_id, first_client_id);
                            assert_eq!(service_client.client_name, name);
                            assert_eq!(service_client.allowed_audiences, audiences);
                            assert_eq!(service_client.allowed_scopes, scopes);
                            assert_eq!(
                                service_client.allowed_grant_types,
                                vec![idp_model::contract::GrantType::ClientCredentials]
                            );
                        }

                        let oauth2_service = OAuth2Service::new(
                            DbApplicationRepo::new(Arc::clone(&engine)),
                            DbClientRepo::new(Arc::clone(&engine), Arc::clone(&key_service)),
                            DbOAuth2AuthorizationCodeRepo::new(Arc::clone(&engine)),
                            DbOAuth2RefreshTokenRepo::new(Arc::clone(&engine)),
                            DbUserRepo::new(Arc::clone(&engine), PasswordConfig::default()),
                            DbOAuth2UserConsentRepo::new(Arc::clone(&engine)),
                            Arc::clone(&key_service),
                            OAuth2Config {
                                issuer: "https://idp.example.test".to_owned(),
                                ..OAuth2Config::default()
                            },
                        );
                        for (file_name, audience, scope) in [
                            (
                                "credentials.json",
                                "https://idp.example.test",
                                "idp.token.validate idp.device.lookup",
                            ),
                            (
                                "storage-idp.json",
                                "https://idp.example.test",
                                "idp.token.validate idp.device.list",
                            ),
                            (
                                "storage-management.json",
                                "https://management.example.test",
                                "management.replication.read management.replication.admit",
                            ),
                        ] {
                            let service_credentials: serde_json::Value = serde_json::from_slice(
                                &fs::read(root.join(file_name)).expect("read provisioned secrets"),
                            )
                            .expect("parse provisioned secrets");
                            let client_id = service_credentials["client_id"]
                                .as_str()
                                .expect("credential client ID is a string")
                                .to_owned();
                            let client_secret = service_credentials["client_secret"]
                                .as_str()
                                .expect("credential secret is a string")
                                .to_owned();
                            let response = oauth2_service
                                .token(
                                    TokenRequest::ClientCredentials(
                                        ClientCredentialsGrantRequest {
                                            client_id: client_id.clone(),
                                            client_secret: client_secret.clone(),
                                            scope: Some(scope.to_owned()),
                                            audience: Some(audience.to_owned()),
                                            resource: None,
                                        },
                                    ),
                                    Some(OAuth2ClientAuth {
                                        client_id: client_id.clone(),
                                        client_secret: Some(client_secret.clone()),
                                        method: idp_model::contract::TokenEndpointAuthMethod::ClientSecretPost,
                                    }),
                                )
                                .await
                                .expect("issue scoped service access token");
                            assert_eq!(response.id_token, None);
                            assert_eq!(response.refresh_token, None);
                            let (_, claims) =
                                decode_jwt::<StandardClaims>(&response.access_token.0)
                                    .expect("decode issued service token");
                            assert_eq!(claims.principal_type, PrincipalType::Client);
                            assert_eq!(claims.client_id, client_id);
                            assert_eq!(claims.aud, audience);
                            assert_eq!(
                                claims.scope,
                                scope.split(' ').map(str::to_owned).collect::<Vec<_>>()
                            );
                            assert_eq!(claims.r#type, TokenType::Bearer);
                            assert_eq!(claims.r#use, TokenUse::Access);
                            for (requested_audience, requested_scope) in [
                                ("https://unauthorized.example.test", scope),
                                (audience, "ungranted.scope"),
                            ] {
                                assert!(
                                    oauth2_service
                                        .token(
                                            TokenRequest::ClientCredentials(
                                                ClientCredentialsGrantRequest {
                                                    client_id: client_id.clone(),
                                                    client_secret: client_secret.clone(),
                                                    scope: Some(requested_scope.to_owned()),
                                                    audience: Some(requested_audience.to_owned()),
                                                    resource: None,
                                                },
                                            ),
                                            Some(OAuth2ClientAuth {
                                                client_id: client_id.clone(),
                                                client_secret: Some(client_secret.clone()),
                                                method: idp_model::contract::TokenEndpointAuthMethod::ClientSecretPost,
                                            }),
                                        )
                                        .await
                                        .is_err(),
                                    "service token issuance must reject ungranted audience or scope"
                                );
                            }
                        }

                        drop(clients);
                        drop(applications);
                        drop(engine);
                        fs::remove_dir_all(root).expect("remove temporary test directory");
                    });
            })
            .expect("spawn test thread")
            .join()
            .expect("test thread did not panic");
    }
}
