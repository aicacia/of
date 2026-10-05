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

#[derive(Default)]
struct TestPrivateKeyRepo(Mutex<HashMap<(String, String), DerivedKey>>);

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
    let service = OAuth2Service::new(
        DbApplicationRepo::new(Arc::clone(&engine)),
        DbClientRepo::new(Arc::clone(&engine), Arc::clone(&keys)),
        DbOAuth2AuthorizationCodeRepo::new(Arc::clone(&engine)),
        DbOAuth2RefreshTokenRepo::new(Arc::clone(&engine)),
        DbUserRepo::new(Arc::clone(&engine), PasswordConfig::default()),
        DbOAuth2UserConsentRepo::new(Arc::clone(&engine)),
        keys,
        OAuth2Config::default(),
    );
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
async fn initial_user_provisioning_is_stable_authority_only_and_conflict_safe() {
    let (engine, authority, _, _) = setup().await;
    let user_id = Id::from_u128(101);
    let credential_id = Id::from_u128(102);
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

    let replica = replica_service(&engine, &authority);
    assert_eq!(
        replica
            .ensure_initial_user(
                Id::from_u128(103),
                Id::from_u128(104),
                "replica-user",
                "password"
            )
            .await
            .expect_err("replica must not provision users")
            .error,
        ErrorCode::AccessDenied
    );
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
async fn infrastructure_client_provisioning_is_retry_safe_and_authority_only() {
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

    let replica = replica_service(&engine, &authority);
    assert_eq!(
        replica
            .ensure_infrastructure_client(infrastructure_client_registration())
            .await
            .expect_err("replica must not provision service clients")
            .error,
        ErrorCode::AccessDenied
    );
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

fn replica_service(engine: &Arc<TestEngine>, authority: &TestService) -> TestService {
    OAuth2Service::new(
        DbApplicationRepo::new(Arc::clone(engine)),
        DbClientRepo::new(Arc::clone(engine), Arc::clone(&authority.key_service)),
        DbOAuth2AuthorizationCodeRepo::new(Arc::clone(engine)),
        DbOAuth2RefreshTokenRepo::new(Arc::clone(engine)),
        DbUserRepo::new(Arc::clone(engine), PasswordConfig::default()),
        DbOAuth2UserConsentRepo::new(Arc::clone(engine)),
        Arc::clone(&authority.key_service),
        OAuth2Config {
            role: idp_model::contract::IdpRole::Replica,
            ..authority.oauth_config.clone()
        },
    )
}

#[tokio::test]
async fn replica_readiness_blocks_before_database_work_and_restart() {
    use idp_model::contract::ClientCredentialsGrantRequest;

    let (_, authority, _, _) = setup().await;
    // No schema: any repository access would fail instead of returning access_denied.
    let empty = Arc::new(Engine::new(InMemoryKernel::new(), AutomergeRowCodec::new()));
    for _ in 0..2 {
        let mut replica = replica_service(&empty, &authority);
        replica.oauth_config.role = idp_model::contract::IdpRole::Authority;
        for _ in 0..3 {
            assert_eq!(
                replica
                    .require_security_ready()
                    .expect_err("restart is unready")
                    .error,
                ErrorCode::AccessDenied
            );
            assert_eq!(
                replica
                    .find_principal(Id::from_u128(1))
                    .await
                    .err()
                    .expect("deny before DB")
                    .error,
                ErrorCode::AccessDenied
            );
            assert_eq!(
                replica
                    .find_public_jwk(Id::from_u128(1))
                    .await
                    .expect_err("deny before DB")
                    .error,
                ErrorCode::AccessDenied
            );
            assert_eq!(
                replica.list_jwks().await.expect_err("deny before DB").error,
                ErrorCode::AccessDenied
            );
            assert_eq!(
                replica
                    .token(
                        TokenRequest::ClientCredentials(ClientCredentialsGrantRequest {
                            client_id: "absent".into(),
                            client_secret: String::new(),
                            scope: None,
                            audience: None,
                            resource: None,
                        }),
                        None
                    )
                    .await
                    .expect_err("deny before client lookup or password/signature work")
                    .error,
                ErrorCode::AccessDenied
            );
        }
    }
    authority
        .require_security_ready()
        .expect("authority unaffected");
}

#[tokio::test]
async fn replica_role_rejects_user_grants_without_consuming_state() {
    use crate::repo::OAuth2UserConsentRepo;
    use idp_model::contract::{
        ApproveForUserRequest, AuthorizationCodeGrantRequest, AuthorizationRequest,
        PasswordGrantRequest, SubjectTokenType, TokenExchangeGrantRequest,
    };

    let (engine, authority, client, principal) = setup().await;
    let approval = ApproveForUserRequest {
        client_id: client.client_id.clone(),
        redirect_uri: client.redirect_uris[0].clone(),
        scope: "openid profile".into(),
    };
    let mut replica = replica_service(&engine, &authority);
    // Editing public token settings must not promote an existing service.
    replica.oauth_config.role = idp_model::contract::IdpRole::Authority;
    assert_eq!(
        replica
            .approve_for_user(approval.clone(), &principal)
            .await
            .expect_err("replica cannot approve")
            .error,
        ErrorCode::AccessDenied
    );
    assert!(
        authority
            .oauth2_user_consent_repo
            .list_user_consents(principal.user.id, 0, 100)
            .await
            .expect("read consents")
            .is_empty()
    );
    authority
        .approve_for_user(approval, &principal)
        .await
        .expect("authority approves");
    let request = AuthorizationRequest {
        response_type: ResponseType::Code,
        client_id: client.client_id.clone(),
        redirect_uri: Some(client.redirect_uris[0].clone()),
        scope: Some("openid profile".into()),
        state: None,
        resource: None,
        code_challenge: None,
        code_challenge_method: None,
        nonce: None,
        prompt: None,
        response_mode: None,
        login_hint: None,
        id_token_hint: None,
        ui_locales: None,
    };
    assert_eq!(
        replica
            .authorize(request.clone(), &principal)
            .await
            .expect_err("replica cannot create code")
            .error,
        ErrorCode::AccessDenied
    );
    let mut authority = authority;
    authority.oauth_config.require_pkce = false;
    let response = authority
        .authorize(request, &principal)
        .await
        .expect("authority creates code");
    let idp_model::contract::AuthorizationCodeResponse::Success { code, .. } = response else {
        panic!("authority returns a code");
    };
    let code_grant = TokenRequest::AuthorizationCode(AuthorizationCodeGrantRequest {
        client_id: Some(client.client_id.clone()),
        code,
        code_verifier: "a".repeat(43),
        redirect_uri: Some(client.redirect_uris[0].clone()),
    });
    let tokens = issue(&authority, &client, &principal).await;
    let refresh = tokens.refresh_token.expect("refresh token").0;
    let requests = [
        code_grant.clone(),
        grant(&refresh, None),
        TokenRequest::Password(PasswordGrantRequest {
            client_id: client.client_id.clone(),
            username: "refresh-user".into(),
            password: "test-password".into(),
            scope: None,
            resource: None,
        }),
        TokenRequest::TokenExchange(TokenExchangeGrantRequest {
            subject_token: tokens.access_token.0,
            subject_token_type: SubjectTokenType::AccessToken,
            actor_token: None,
            actor_token_type: None,
            resource: None,
            audience: None,
            authorization_details: None,
            scope: None,
            requested_token_type: None,
        }),
    ];
    let before = states(&engine).await;
    for request in requests {
        assert_eq!(
            replica
                .token(request, Some(auth(&client)))
                .await
                .expect_err("replica rejects user grant")
                .error,
            ErrorCode::AccessDenied
        );
    }
    assert_eq!(
        replica
            .revoke(
                RevocationRequest {
                    token: refresh.clone(),
                    token_type_hint: None
                },
                Some(auth(&client))
            )
            .await
            .expect_err("replica cannot revoke")
            .error,
        ErrorCode::AccessDenied
    );
    assert_eq!(
        states(&engine).await,
        before,
        "denials leave refresh state unchanged"
    );
    authority
        .token(code_grant, Some(auth(&client)))
        .await
        .expect("rejected code remains redeemable");
    authority
        .token(grant(&refresh, None), Some(auth(&client)))
        .await
        .expect("rejected refresh remains redeemable");
}

#[tokio::test]
async fn replica_role_denies_client_credentials_until_signer_readiness() {
    use idp_model::contract::ClientCredentialsGrantRequest;
    let (engine, authority, mut client, _) = setup().await;
    client
        .allowed_grant_types
        .push(GrantType::ClientCredentials);
    client
        .allowed_audiences
        .push("https://service.example".into());
    let client = authority
        .client_repo
        .update_client(client)
        .await
        .expect("enable machine grant");
    let replica = replica_service(&engine, &authority);
    let request = TokenRequest::ClientCredentials(ClientCredentialsGrantRequest {
        client_id: client.client_id.clone(),
        client_secret: String::new(),
        scope: Some("profile".into()),
        audience: Some("https://service.example".into()),
        resource: None,
    });
    assert_eq!(
        replica
            .token(request.clone(), Some(auth(&client)))
            .await
            .expect_err("shared subject private keys do not establish replica readiness")
            .error,
        ErrorCode::AccessDenied
    );
    let tokens = authority
        .token(request, Some(auth(&client)))
        .await
        .expect("authority still permits machine grant");
    assert!(tokens.refresh_token.is_none());
    let (header, _) = decode_jwt::<StandardClaims>(&tokens.access_token.0).expect("decode token");
    let key_id = Id::parse_str(&header.kid).expect("key ID");
    assert_eq!(
        replica
            .find_public_jwk(key_id)
            .await
            .expect_err("unready replica cannot verify")
            .error,
        ErrorCode::AccessDenied
    );
    assert_eq!(
        replica
            .find_principal(key_id)
            .await
            .err()
            .expect("unready replica cannot resolve principal")
            .error,
        ErrorCode::AccessDenied
    );
    assert_eq!(
        replica
            .list_jwks()
            .await
            .expect_err("unready replica cannot publish eligible keys")
            .error,
        ErrorCode::AccessDenied
    );
    let key = authority
        .find_public_jwk(key_id)
        .await
        .expect("authority reads verification key");
    super::verify_jwt::<StandardClaims>(&key, &tokens.access_token.0).expect("validate signature");
    assert!(states(&engine).await.is_empty());
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
    let signing_key = service
        .load_signing_jwk(&principal.key)
        .await
        .expect("load signing key");
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
        .map(|claims| encode_jwt(&signing_key, claims).expect("sign invalid claims"))
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
