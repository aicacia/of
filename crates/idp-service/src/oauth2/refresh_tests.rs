use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use base64::{Engine as Base64Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use db::{
    AutomergeRowCodec, Engine, InMemoryKernel, Query, QueryColumn, QueryFrom, QuerySelect,
    Statement, Value,
};
use idp_model::{
    contract::{
        ApplicationRegistration, ClientProfile, ClientRegistration, ClientType, EntityType,
        ErrorCode, GrantType, OAuth2ClientAuth, RefreshTokenGrantRequest, ResponseType,
        RevocationRequest, TokenEndpointAuthMethod, TokenRequest,
    },
    model::{Client, Id},
    replica::up,
};
use key::{DerivationPath, DerivedKey};
use model::contract::{RefreshToken, StandardClaims, TokenResponse};

use crate::{
    PasswordConfig,
    oauth2::{OAuth2Config, OAuth2Service, UserPrincipal, decode_jwt, encode_jwt},
    replica::{
        DbApplicationRepo, DbClientRepo, DbKeyRepo, DbOAuth2AuthorizationCodeRepo,
        DbOAuth2RefreshTokenRepo, DbOAuth2UserConsentRepo, DbUserRepo,
    },
    repo::{
        ClientRepo, KeyService, OAuth2RefreshToken, OAuth2RefreshTokenRepo, PrivateKeyRepo,
        RepoResult, UserRepo,
    },
};

#[path = "public_key_tests.rs"]
mod public_key_tests;

#[derive(Clone, Default)]
struct TestPrivateKeyRepo(Arc<Mutex<HashMap<(String, String), DerivedKey>>>);

impl PrivateKeyRepo for TestPrivateKeyRepo {
    fn load(&self, namespace: &str, path: &DerivationPath) -> RepoResult<Option<DerivedKey>> {
        Ok(self
            .0
            .lock()
            .expect("test key store lock")
            .get(&(namespace.into(), path.to_string()))
            .cloned())
    }
    fn store(&self, namespace: &str, key: &DerivedKey) -> RepoResult<()> {
        self.0.lock().expect("test key store lock").insert(
            (namespace.into(), key.derivation_path().to_string()),
            key.clone(),
        );
        Ok(())
    }
    fn delete(&self, namespace: &str, path: &DerivationPath) -> RepoResult<()> {
        self.0
            .lock()
            .expect("test key store lock")
            .remove(&(namespace.into(), path.to_string()));
        Ok(())
    }
}

type TestEngine = Engine<InMemoryKernel, AutomergeRowCodec>;
type TestService = OAuth2Service<
    DbApplicationRepo<InMemoryKernel, AutomergeRowCodec>,
    DbClientRepo<InMemoryKernel, AutomergeRowCodec, TestPrivateKeyRepo>,
    DbOAuth2AuthorizationCodeRepo<InMemoryKernel, AutomergeRowCodec>,
    DbOAuth2RefreshTokenRepo<InMemoryKernel, AutomergeRowCodec>,
    DbUserRepo<InMemoryKernel, AutomergeRowCodec>,
    DbOAuth2UserConsentRepo<InMemoryKernel, AutomergeRowCodec>,
    DbKeyRepo<InMemoryKernel, AutomergeRowCodec>,
    TestPrivateKeyRepo,
>;

async fn setup() -> (Arc<TestEngine>, TestService, Client, UserPrincipal) {
    let engine = Arc::new(Engine::new(InMemoryKernel::new(), AutomergeRowCodec::new()));
    up(&engine).await.expect("initialize IdP schema");
    let keys = Arc::new(KeyService::new(
        DbKeyRepo::new(Arc::clone(&engine)),
        TestPrivateKeyRepo::default(),
        "refresh-test",
    ));
    let mut service = OAuth2Service::new(
        DbApplicationRepo::new(Arc::clone(&engine)),
        DbClientRepo::new(Arc::clone(&engine), Arc::clone(&keys)),
        DbOAuth2AuthorizationCodeRepo::new(Arc::clone(&engine)),
        DbOAuth2RefreshTokenRepo::new(Arc::clone(&engine)),
        DbUserRepo::new(Arc::clone(&engine), PasswordConfig::default()),
        DbOAuth2UserConsentRepo::new(Arc::clone(&engine)),
        keys,
        OAuth2Config::default(),
    );
    let binding = crate::oauth2::NodeSignerBinding {
        member_id: Id::now_v7(),
        key_id: Id::now_v7(),
        endpoint_id: "node-endpoint".into(),
    };
    let public_jwk = service
        .key_service
        .prepare_node_signer(&binding)
        .expect("prepare independent local signer");
    engine.translate_and_execute(&format!("INSERT INTO devices (id, public_key, owner_subject, state, approved_at, revoked_at) VALUES (CAST('{}' AS UUID), 'node-endpoint', 'node-owner', 1, 1, NULL)", binding.member_id), &db::SqlTranslator).await.expect("approved local Device");
    let member = idp_model::contract::ReplicaMembership {
        installation_id: service.oauth_config.issuer.clone(),
        issuer: service.oauth_config.issuer.clone(),
        member_id: binding.member_id,
        endpoint_id: binding.endpoint_id.clone(),
        approved_at: 1,
        revoked_at: None,
    };
    let signer = idp_model::contract::IdpSignerRecord {
        member_id: binding.member_id,
        key_id: binding.key_id,
        issuer: member.issuer.clone(),
        public_jwk,
        approved_at: Some(1),
        revoked_at: None,
        expires_at: None,
    };
    crate::replica::DbReplicaSignerRepo::new(Arc::clone(&engine))
        .enroll(&member, &signer)
        .await
        .expect("approve local node signer");
    service.oauth_config.local_signer = Some(binding);
    let client = service
        .client_repo
        .create_client(ClientRegistration {
            application: ApplicationRegistration {
                name: Some("Refresh test".into()),
                uri: "https://refresh.example".into(),
                description: None,
            },
            client_id: Some("refresh-client".into()),
            client_secret: Some("test-secret".into()),
            client_id_issued_at: None,
            client_secret_expires_at: None,
            client_name: "Refresh client".into(),
            client_uri: None,
            logo_uri: None,
            contacts: vec![],
            terms_of_service_uri: None,
            policy_uri: None,
            client_type: ClientType::Confidential,
            profile: ClientProfile::Web,
            redirect_uris: vec!["https://refresh.example/callback".into()],
            allowed_grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
            response_types: vec![ResponseType::Code],
            allowed_scopes: vec!["openid".into(), "profile".into()],
            allowed_audiences: vec![],
            token_endpoint_auth_method: TokenEndpointAuthMethod::ClientSecretBasic,
            software_statement: None,
            software_id: None,
            software_version: None,
        })
        .await
        .expect("create refresh client");
    let user = service
        .user_repo
        .create_user_with_password("refresh-user", "test-password")
        .await
        .expect("create user");
    service
        .key_service
        .ensure_entity_master_key(EntityType::User, user.id, "test-password")
        .expect("create user master key");
    let (key, _) = service
        .key_service
        .create_key(
            None,
            EntityType::User,
            user.id,
            true,
            "refresh key".into(),
            None,
        )
        .await
        .expect("create user signing key");
    (engine, service, client, UserPrincipal { user, key })
}

#[tokio::test]
async fn initial_user_provisioning_is_stable_and_conflict_safe() {
    let (engine, authority, _, _) = setup().await;
    let user_id = Id::now_v7();
    let credential_id = Id::now_v7();
    let created = authority
        .ensure_initial_user(user_id, credential_id, "administrator", "strong-password")
        .await
        .expect("provision initial user");
    let retried = authority
        .ensure_initial_user(user_id, credential_id, "administrator", "strong-password")
        .await
        .expect("retry initial user");
    assert_eq!(created, retried);
    assert_eq!(created.id, user_id);

    assert!(
        authority
            .ensure_initial_user(user_id, credential_id, "other-name", "strong-password")
            .await
            .is_err()
    );
    assert!(
        authority
            .ensure_initial_user(
                user_id,
                credential_id,
                "administrator",
                "different-password"
            )
            .await
            .is_err()
    );

    let replica = reopened_service(&engine, &authority);
    replica
        .ensure_initial_user(Id::now_v7(), Id::now_v7(), "local-user", "password")
        .await
        .expect("local provisioning needs no peer");
}

fn infrastructure_client_registration() -> ClientRegistration {
    ClientRegistration {
        application: ApplicationRegistration {
            name: Some("Storage service".into()),
            uri: "https://storage.example/".into(),
            description: Some("Storage API service identity".into()),
        },
        client_id: Some("storage-service".into()),
        client_secret: Some("stable-secret".into()),
        client_id_issued_at: None,
        client_secret_expires_at: None,
        client_name: "Storage service".into(),
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
        allowed_scopes: vec![],
        allowed_audiences: vec![],
        token_endpoint_auth_method: TokenEndpointAuthMethod::ClientSecretBasic,
        software_statement: None,
        software_id: None,
        software_version: None,
    }
}

#[tokio::test]
async fn infrastructure_client_provisioning_is_retry_safe_on_each_node() {
    let (engine, authority, _, _) = setup().await;
    let created = authority
        .ensure_infrastructure_client(infrastructure_client_registration())
        .await
        .expect("provision service client");
    let retried = authority
        .ensure_infrastructure_client(infrastructure_client_registration())
        .await
        .expect("retry service client");
    assert_eq!(created.client_id, retried.client_id);
    assert_eq!(created.client_secret, retried.client_secret);

    let mut conflict = infrastructure_client_registration();
    conflict.client_secret = Some("different-secret".into());
    assert!(
        authority
            .ensure_infrastructure_client(conflict)
            .await
            .is_err()
    );

    let replica = reopened_service(&engine, &authority);
    replica
        .ensure_infrastructure_client(infrastructure_client_registration())
        .await
        .expect("local retry");
}

fn auth(client: &Client) -> OAuth2ClientAuth {
    OAuth2ClientAuth {
        client_id: client.client_id.clone(),
        client_secret: Some("test-secret".into()),
        method: TokenEndpointAuthMethod::ClientSecretBasic,
    }
}
fn grant(token: &str, scope: Option<&str>) -> TokenRequest {
    TokenRequest::RefreshToken(RefreshTokenGrantRequest {
        refresh_token: RefreshToken(token.into()),
        scope: scope.map(str::to_owned),
    })
}
async fn issue(service: &TestService, client: &Client, principal: &UserPrincipal) -> TokenResponse {
    service
        .issue_tokens_for_client(
            client,
            principal,
            &["openid".into(), "profile".into()],
            Some("https://storage.example"),
            None,
            None,
        )
        .await
        .expect("issue persisted tokens")
}
async fn states(engine: &TestEngine) -> Vec<db::Row> {
    engine
        .execute(vec![Statement::Query(Query::Select(QuerySelect {
            from: QueryFrom {
                table: "oauth2_refresh_tokens".into(),
                joins: vec![],
            },
            projection: ["token_hash", "consumed_at", "revoked_at"]
                .into_iter()
                .map(|name| QueryColumn::new("oauth2_refresh_tokens".into(), name.into()))
                .collect(),
            distinct: false,
            predicate: None,
            aggregates: vec![],
            text_concats: vec![],
            group_by: vec![],
            order_by: vec![],
            limit: None,
            offset: None,
            having: None,
        }))])
        .await
        .expect("read refresh state")
        .remove(0)
        .rows
}

fn reopened_service(engine: &Arc<TestEngine>, authority: &TestService) -> TestService {
    OAuth2Service::new(
        DbApplicationRepo::new(Arc::clone(engine)),
        DbClientRepo::new(Arc::clone(engine), Arc::clone(&authority.key_service)),
        DbOAuth2AuthorizationCodeRepo::new(Arc::clone(engine)),
        DbOAuth2RefreshTokenRepo::new(Arc::clone(engine)),
        DbUserRepo::new(Arc::clone(engine), PasswordConfig::default()),
        DbOAuth2UserConsentRepo::new(Arc::clone(engine)),
        Arc::clone(&authority.key_service),
        OAuth2Config {
            ..authority.oauth_config.clone()
        },
    )
}

#[tokio::test]
async fn reopened_local_node_can_issue_and_rotate_user_grants_offline() {
    let (engine, first, client, principal) = setup().await;
    let tokens = issue(&first, &client, &principal).await;
    let reopened = reopened_service(&engine, &first);
    let replacement = reopened
        .token(
            grant(&tokens.refresh_token.expect("refresh grant").0, None),
            Some(auth(&client)),
        )
        .await
        .expect("local state survives service reopen without peer contact");
    assert!(replacement.refresh_token.is_some());
    assert!(
        reopened
            .find_public_jwk(
                first
                    .oauth_config
                    .local_signer
                    .as_ref()
                    .expect("node binding")
                    .key_id
            )
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn refresh_issuance_rotation_reuse_and_revocation() {
    let (engine, service, client, principal) = setup().await;
    let first = issue(&service, &client, &principal)
        .await
        .refresh_token
        .expect("refresh token")
        .0;
    let second = issue(&service, &client, &principal)
        .await
        .refresh_token
        .expect("second refresh token")
        .0;
    assert_ne!(first, second, "each issuance has a unique token ID");
    let rows = states(&engine).await;
    assert_eq!(rows.len(), 2);
    assert!(
        rows.iter()
            .all(|row| row.values[0] != Value::Text(first.clone()) && row.values[1] == Value::Null)
    );
    let mut wrong = auth(&client);
    wrong.client_id = "wrong-client".into();
    assert_eq!(
        service
            .token(grant(&first, None), Some(wrong))
            .await
            .expect_err("wrong client")
            .error,
        ErrorCode::InvalidClient
    );
    let mut wrong_secret = auth(&client);
    wrong_secret.client_secret = Some("wrong-secret".into());
    assert_eq!(
        service
            .token(grant(&first, None), Some(wrong_secret))
            .await
            .expect_err("wrong secret")
            .error,
        ErrorCode::InvalidClient
    );
    assert_eq!(
        service
            .token(grant(&first, None), None)
            .await
            .expect_err("missing auth")
            .error,
        ErrorCode::InvalidClient
    );
    assert_eq!(
        service
            .token(grant(&first, Some("other")), Some(auth(&client)))
            .await
            .expect_err("scope expansion")
            .error,
        ErrorCode::InvalidScope
    );
    assert!(
        states(&engine)
            .await
            .iter()
            .all(|row| row.values[1] == Value::Null)
    );
    let rotated = service
        .token(grant(&first, Some("openid")), Some(auth(&client)))
        .await
        .expect("rotate persisted token");
    let replacement = rotated.refresh_token.expect("replacement token").0;
    assert_ne!(first, replacement);
    let (_, claims) = decode_jwt::<StandardClaims>(&replacement).expect("decode replacement");
    assert_eq!(claims.scope, vec!["openid"]);
    assert_eq!(claims.resource.as_deref(), Some("https://storage.example"));
    assert_eq!(states(&engine).await.len(), 3);
    assert_eq!(
        service
            .token(grant(&first, None), Some(auth(&client)))
            .await
            .expect_err("reuse")
            .error,
        ErrorCode::InvalidGrant
    );
    let request = RevocationRequest {
        token: replacement.clone(),
        token_type_hint: Some("refresh_token".into()),
    };
    assert_eq!(
        service
            .revoke(request.clone(), None)
            .await
            .expect_err("revoke requires client auth")
            .error,
        ErrorCode::InvalidClient
    );
    service
        .revoke(request.clone(), Some(auth(&client)))
        .await
        .expect("revoke replacement");
    service
        .revoke(request, Some(auth(&client)))
        .await
        .expect("idempotent revocation");
    assert_eq!(
        service
            .token(grant(&replacement, None), Some(auth(&client)))
            .await
            .expect_err("revoked")
            .error,
        ErrorCode::InvalidGrant
    );
    service
        .token(grant(&second, None), Some(auth(&client)))
        .await
        .expect("separate token remains valid");
}

#[tokio::test]
async fn refresh_redemption_has_one_winner() {
    let (engine, service, client, principal) = setup().await;
    let token = issue(&service, &client, &principal)
        .await
        .refresh_token
        .expect("refresh token")
        .0;
    let (first, second) = tokio::join!(
        service.token(grant(&token, None), Some(auth(&client))),
        service.token(grant(&token, None), Some(auth(&client))),
    );
    assert_ne!(first.is_ok(), second.is_ok());
    let winner = first.or(second).expect("one redemption winner");
    assert_eq!(states(&engine).await.len(), 2);
    service
        .token(
            grant(
                &winner.refresh_token.expect("persisted replacement").0,
                None,
            ),
            Some(auth(&client)),
        )
        .await
        .expect("replacement is redeemable");
}

#[tokio::test]
async fn refresh_verification_precedes_consumption() {
    let (engine, service, client, principal) = setup().await;
    let original = issue(&service, &client, &principal)
        .await
        .refresh_token
        .expect("refresh token")
        .0;
    let (header, claims) = decode_jwt::<StandardClaims>(&original).expect("decode token");
    let signing_key = service.local_signing_jwk().await.expect("load signing key");
    let mut invalid_claims = Vec::new();
    let mut expired = claims.clone();
    expired.exp = expired.iat;
    invalid_claims.push(expired);
    let mut issuer = claims.clone();
    issuer.iss = "https://wrong.example".into();
    invalid_claims.push(issuer);
    let mut audience = claims.clone();
    audience.aud = "wrong-client".into();
    invalid_claims.push(audience);
    let mut subject = claims.clone();
    subject.sub = Id::now_v7().to_string();
    invalid_claims.push(subject);
    let mut future = claims.clone();
    future.nbf += 3600;
    invalid_claims.push(future);
    let mut issued = claims.clone();
    issued.iat += 3600;
    invalid_claims.push(issued);
    let mut use_claim = claims.clone();
    use_claim.r#use = model::contract::TokenUse::Access;
    invalid_claims.push(use_claim);
    let mut principal_type = claims.clone();
    principal_type.principal_type = model::contract::PrincipalType::Client;
    invalid_claims.push(principal_type);
    let mut tokens: Vec<String> = invalid_claims
        .iter()
        .map(|claims| {
            encode_jwt(
                &signing_key,
                &crate::oauth2::token::PrincipalBoundClaims {
                    standard_claims: claims.clone(),
                    principal_key_id: principal.key.id,
                },
            )
            .expect("sign invalid claims")
        })
        .collect();
    let mut parts: Vec<String> = original.split('.').map(str::to_owned).collect();
    let mut signature = URL_SAFE_NO_PAD.decode(&parts[2]).expect("decode signature");
    signature[0] ^= 1;
    parts[2] = URL_SAFE_NO_PAD.encode(signature);
    tokens.push(parts.join("."));
    let forged_header = serde_json::json!({ "alg": "ES256K", "typ": "JWT", "kid": header.kid });
    tokens.push(format!(
        "{}.{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&forged_header).expect("header")),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("claims")),
        URL_SAFE_NO_PAD.encode([0u8; 64])
    ));
    for token in &tokens {
        service
            .refresh_token_repo
            .issue_refresh_token(
                OAuth2RefreshToken {
                    token: token.clone(),
                    client_id: client.id,
                    user_id: principal.user.id,
                    scopes: claims.scope.clone(),
                    resource: claims.resource.clone(),
                    authorization_details: None,
                    expires_at: claims.exp,
                    created_at: claims.iat,
                },
                None,
            )
            .await
            .expect("persist invalid token to prove validation precedes consumption");
        assert!(
            service
                .token(grant(token, None), Some(auth(&client)))
                .await
                .is_err()
        );
    }
    assert_eq!(states(&engine).await.len(), tokens.len() + 1);
    assert!(
        states(&engine)
            .await
            .iter()
            .all(|row| row.values[1] == Value::Null)
    );
    let unpersisted = encode_jwt(
        &signing_key,
        &super::super::token::RefreshClaims {
            standard_claims: claims,
            principal_key_id: principal.key.id,
            jti: Id::now_v7().to_string(),
        },
    )
    .expect("sign unpersisted token");
    assert_eq!(
        service
            .token(grant(&unpersisted, None), Some(auth(&client)))
            .await
            .expect_err("unpersisted token")
            .error,
        ErrorCode::InvalidGrant
    );
    service
        .token(grant(&original, None), Some(auth(&client)))
        .await
        .expect("invalid requests did not consume original");
}

#[tokio::test]
async fn user_token_signer_is_not_the_user_principal() {
    let (_, service, client, principal) = setup().await;
    let tokens = issue(&service, &client, &principal).await;
    let (header, claims) =
        decode_jwt::<StandardClaims>(&tokens.access_token.0).expect("decode token");
    assert_eq!(claims.sub, principal.user.id.to_string());
    assert_ne!(header.kid, principal.key.id.to_string());
}

#[tokio::test]
async fn missing_local_signer_does_not_consume_authorization_code() {
    use crate::repo::OAuth2AuthorizationCodeRepo;
    use idp_model::contract::AuthorizationCodeGrantRequest;
    let (_, mut service, client, principal) = setup().await;
    let code = service
        .authorization_code_repo
        .create_authorization_code(
            client.client_id.clone(),
            principal.key.id,
            client.redirect_uris[0].clone(),
            vec!["openid".into()],
            None,
            None,
            None,
            None,
            chrono::Utc::now() + chrono::Duration::minutes(1),
        )
        .await
        .expect("create local code");
    service.oauth_config.local_signer = None;
    let request = TokenRequest::AuthorizationCode(AuthorizationCodeGrantRequest {
        code: code.code.clone(),
        client_id: Some(client.client_id.clone()),
        redirect_uri: Some(client.redirect_uris[0].clone()),
        code_verifier: "fixture-verifier".into(),
    });
    let error = service
        .token(request, Some(auth(&client)))
        .await
        .expect_err("missing local signer denies");
    assert_eq!(
        error.error_description.as_deref(),
        Some("local node signer is not configured")
    );
    assert!(
        service
            .authorization_code_repo
            .find_authorization_code_by_code(&code.code)
            .await
            .expect("read code after denial")
            .expect("code remains")
            .consumed_at
            .is_none()
    );
}

#[tokio::test]
async fn approved_local_node_signer_survives_native_reopen_without_peer_or_trust_lease() {
    let (source, service, client, principal) = setup().await;
    let token = issue(&service, &client, &principal).await.access_token.0;
    let binding = service
        .oauth_config
        .local_signer
        .clone()
        .expect("node binding");
    let private_store = service.key_service.private_key_repo().clone();
    let path = std::env::temp_dir().join(format!("local-node-{}.redb", Id::now_v7()));
    {
        let engine = Arc::new(db::open_native_engine(&path).expect("persist Node identity"));
        up(&engine).await.expect("initialize local trust schema");
        for table in ["devices", "idp_replica_members", "idp_replica_signers"] {
            let rows = source
                .translate_and_execute(&format!("SELECT * FROM {table}"), &db::SqlTranslator)
                .await
                .expect("read local fixture trust")
                .remove(0)
                .rows;
            for row in rows {
                engine
                    .execute(vec![Statement::Query(Query::Insert(db::QueryInsert {
                        table: table.into(),
                        row,
                        returning: None,
                    }))])
                    .await
                    .expect("persist local trust");
            }
        }
    }
    {
        let engine = Arc::new(db::open_native_engine(&path).expect("reopen offline Node trust"));
        let keys = KeyService::new(
            DbKeyRepo::new(Arc::clone(&engine)),
            private_store,
            "refresh-test",
        );
        let signing = keys
            .load_node_signer(
                &binding,
                &service.oauth_config.issuer,
                chrono::Utc::now().timestamp(),
            )
            .await
            .expect("no live peer or lease needed");
        let renewed = encode_jwt(
            &signing,
            &serde_json::json!({"sub": principal.user.id.to_string()}),
        )
        .expect("issue with restored local private signer");
        let public = idp_model::contract::JwkPublic::from(signing);
        crate::oauth2::verify_jwt::<StandardClaims>(&public, &token)
            .expect("verify earlier token after reopen");
        crate::oauth2::verify_jwt::<serde_json::Value>(&public, &renewed)
            .expect("verify new offline issuance");
        let peers = crate::replica::DbReplicaSignerRepo::new(engine);
        assert!(
            peers
                .is_trusted_peer(
                    &service.oauth_config.issuer,
                    binding.member_id,
                    &binding.endpoint_id,
                    chrono::Utc::now().timestamp()
                )
                .await
                .expect("persistent peer trust")
        );
        assert!(
            !peers
                .is_trusted_peer(
                    &service.oauth_config.issuer,
                    binding.member_id,
                    "forged-endpoint",
                    chrono::Utc::now().timestamp()
                )
                .await
                .expect("endpoint impersonation denial")
        );
    }
    std::fs::remove_file(path).expect("remove trust fixture");
}
