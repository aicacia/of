use super::{
    DbApplicationRepo, DbClientRepo, DbKeyRepo, DbOAuth2AuthorizationCodeRepo,
    DbOAuth2RefreshTokenRepo, DbOAuth2UserConsentRepo, DbUserRepo, KeyService, OAuth2Config,
    OAuth2Service, PasswordConfig, TestEngine, TestPrivateKeyRepo, TestService, auth, grant, issue,
    setup, up,
};
use crate::{
    oauth2::{NodeSignerBinding, decode_jwt, encode_jwt, verify_jwt},
    repo::{ClientRepo, KeyRepo, OAuth2AuthorizationCodeRepo, UserRepo},
};
use db::{
    Query, QueryColumn, QueryExpr, QueryExprValue, QueryFrom, QueryUpdate, QueryUpdateAssignment,
    SqlTranslator, Statement, Value,
};
use idp_model::{
    contract::{EntityType, IdpSignerRecord, ReplicaMembership},
    model::Id,
};
use model::contract::StandardClaims;
use std::sync::Arc;

async fn public_verifier(source: &TestEngine) -> (Arc<TestEngine>, TestService) {
    let engine = Arc::new(db::Database::in_memory());
    up(&engine).await.expect("initialize independent schema");
    for table in [
        "applications",
        "clients",
        "users",
        "keys",
        "devices",
        "idp_replica_members",
        "idp_replica_signers",
        "oauth2_refresh_tokens",
        "oauth2_authorization_codes",
    ] {
        let rows = source
            .client()
            .translate_and_execute(&format!("SELECT * FROM {table}"), &SqlTranslator)
            .await
            .expect("copy trusted fixture records")
            .remove(0)
            .rows;
        for row in rows {
            engine
                .client()
                .execute(vec![Statement::Query(Query::Insert(db::QueryInsert {
                    table: table.into(),
                    row,
                    returning: None,
                }))])
                .await
                .expect("copy records without private signer");
        }
    }
    let keys = Arc::new(KeyService::new(
        DbKeyRepo::new(Arc::clone(&engine)),
        TestPrivateKeyRepo::default(),
        "independent-node",
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
    (engine, service)
}

async fn set(engine: &TestEngine, table: &str, id: Id, name: &str, value: Value) {
    let column = |name: &str| QueryColumn::new(table.into(), name.into());
    engine
        .client()
        .execute(vec![Statement::Query(Query::Update(QueryUpdate {
            from: QueryFrom {
                table: table.into(),
                joins: vec![],
            },
            assignments: vec![QueryUpdateAssignment {
                column: column(name),
                value: QueryExprValue::Value(value),
            }],
            predicate: Some(QueryExpr::Equals(
                Box::new(QueryExpr::Value(QueryExprValue::Column(column("id")))),
                Box::new(QueryExpr::Value(QueryExprValue::Value(Value::Uuid(id)))),
            )),
            returning: None,
        }))])
        .await
        .expect("change security fixture");
}

async fn approve_independent_signer(engine: &Arc<TestEngine>, service: &mut TestService) {
    let binding = NodeSignerBinding {
        member_id: Id::now_v7(),
        key_id: Id::now_v7(),
        endpoint_id: "independent-endpoint".into(),
    };
    let public_jwk = service
        .key_service
        .prepare_node_signer(&binding)
        .expect("prepare independent private signer");
    engine.client().translate_and_execute(&format!("INSERT INTO devices (id, public_key, owner_subject, state, approved_at, revoked_at) VALUES (CAST('{}' AS UUID), 'independent-endpoint', 'owner', 1, 1, NULL)", binding.member_id), &SqlTranslator).await.expect("approve Device fixture");
    let member = ReplicaMembership {
        installation_id: service.oauth_config.issuer.clone(),
        issuer: service.oauth_config.issuer.clone(),
        member_id: binding.member_id,
        endpoint_id: binding.endpoint_id.clone(),
        approved_at: 1,
        revoked_at: None,
    };
    let signer = IdpSignerRecord {
        member_id: binding.member_id,
        key_id: binding.key_id,
        issuer: member.issuer.clone(),
        public_jwk,
        approved_at: Some(1),
        revoked_at: None,
        expires_at: None,
    };
    crate::replica::DbReplicaSignerRepo::new(Arc::clone(engine))
        .enroll(&member, &signer)
        .await
        .expect("approve public signer fixture");
    service.oauth_config.local_signer = Some(binding);
}

#[tokio::test]
async fn public_node_signers_verify_without_private_material_or_principal_impersonation() {
    let (engine, service, client, principal) = setup().await;
    let token = issue(&service, &client, &principal).await.access_token.0;
    let (_, verifier) = public_verifier(&engine).await;
    let claims = verifier
        .validate_access_token(&token, &client.client_id)
        .await
        .expect("verify offline with public trust");
    assert_eq!(claims.sub, principal.user.id.to_string());
    assert!(
        verifier
            .key_service
            .private_key_repo()
            .0
            .lock()
            .expect("local key store")
            .is_empty()
    );
    assert!(
        verifier
            .validate_access_token(&token, "wrong-audience")
            .await
            .is_err()
    );
    assert!(
        verifier.find_public_jwk(principal.key.id).await.is_err(),
        "User authentication key is not an issuer signer"
    );
    assert_eq!(
        verifier
            .list_jwks()
            .await
            .expect("public node JWKS")
            .keys
            .len(),
        1
    );
    let binding = service
        .oauth_config
        .local_signer
        .as_ref()
        .expect("source binding");
    assert!(
        verifier
            .key_service
            .load_node_signer(
                binding,
                &service.oauth_config.issuer,
                chrono::Utc::now().timestamp()
            )
            .await
            .is_err(),
        "approved public trust is not private capability"
    );
    let different_public = verifier
        .key_service
        .prepare_node_signer(binding)
        .expect("prepare independent local material without approving it");
    assert_ne!(
        different_public,
        service
            .find_public_jwk(binding.key_id)
            .await
            .expect("approved public material")
    );
    assert!(
        verifier
            .key_service
            .load_node_signer(
                binding,
                &service.oauth_config.issuer,
                chrono::Utc::now().timestamp()
            )
            .await
            .is_err(),
        "a different local private signer cannot impersonate an approved signer"
    );

    let approved = service
        .find_public_jwk(binding.key_id)
        .await
        .expect("approved signer");
    let mut public_record = serde_json::json!({
        "id": binding.key_id, "member_id": binding.member_id, "active_member_id": binding.member_id,
        "key_id": binding.key_id, "issuer": service.oauth_config.issuer,
        "public_jwk": serde_json::to_string(&approved).expect("SQL public JWK"),
        "approved_at": 1, "revoked_at": null, "expires_at": null,
    });
    assert!(
        crate::security_sync::PublicSecurityTable::Signers
            .permits_record(public_record.as_object().expect("public record"))
    );
    public_record["public_jwk"] = serde_json::to_value(&approved).expect("public JWK object");
    public_record["public_jwk"]["d"] = "private-scalar-must-not-synchronize".into();
    assert!(
        !crate::security_sync::PublicSecurityTable::Signers
            .permits_record(public_record.as_object().expect("private injection record"))
    );
    public_record["public_jwk"] =
        serde_json::Value::String(public_record["public_jwk"].to_string());
    assert!(
        !crate::security_sync::PublicSecurityTable::Signers.permits_record(
            public_record
                .as_object()
                .expect("serialized private injection record")
        )
    );
    let (_, original) = decode_jwt::<StandardClaims>(&token).expect("claims");
    for field in [
        "subject", "type", "issuer", "use", "scope", "lifetime", "client",
    ] {
        let mut claims = original.clone();
        match field {
            "subject" => claims.sub = Id::now_v7().to_string(),
            "type" => claims.principal_type = model::contract::PrincipalType::Client,
            "issuer" => claims.iss = "https://other-installation.example".into(),
            "use" => claims.r#use = model::contract::TokenUse::Id,
            "scope" => claims.scope.push("ungranted".into()),
            "lifetime" => claims.exp = 0,
            _ => claims.client_id = "other-client".into(),
        }
        let invalid = encode_jwt(
            &service.local_signing_jwk().await.expect("local signer"),
            &crate::oauth2::token::PrincipalBoundClaims {
                standard_claims: claims,
                principal_key_id: principal.key.id,
            },
        )
        .expect("sign invalid claims");
        assert!(
            verifier
                .validate_access_token(&invalid, &client.client_id)
                .await
                .is_err(),
            "accepted {field}"
        );
    }
}

#[tokio::test]
async fn learned_device_signer_client_and_principal_revocations_deny_locally() {
    let (source, service, client, principal) = setup().await;
    let token = issue(&service, &client, &principal).await.access_token.0;
    for kind in ["device", "signer", "client", "principal", "corrupt-key"] {
        let (engine, verifier) = public_verifier(&source).await;
        assert!(
            verifier
                .validate_access_token(&token, &client.client_id)
                .await
                .is_ok()
        );
        match kind {
            "device" => {
                set(
                    &engine,
                    "devices",
                    service
                        .oauth_config
                        .local_signer
                        .as_ref()
                        .expect("binding")
                        .member_id,
                    "revoked_at",
                    Value::Integer(1),
                )
                .await
            }
            "signer" => {
                let row = engine
                    .client()
                    .translate_and_execute("SELECT id FROM idp_replica_signers", &SqlTranslator)
                    .await
                    .expect("signer rows")
                    .remove(0)
                    .rows
                    .remove(0);
                let Value::Uuid(id) = row.values[0] else {
                    panic!("signer row ID")
                };
                set(
                    &engine,
                    "idp_replica_signers",
                    id,
                    "revoked_at",
                    Value::Integer(1),
                )
                .await;
            }
            "client" => {
                set(
                    &engine,
                    "clients",
                    client.id,
                    "revoked_at",
                    Value::Integer(1),
                )
                .await
            }
            "principal" => {
                verifier
                    .user_repo
                    .delete_user_by_id(principal.user.id)
                    .await
                    .expect("remove locally active Principal");
            }
            _ => {
                set(
                    &engine,
                    "keys",
                    principal.key.id,
                    "public_jwk",
                    Value::Text("invalid".into()),
                )
                .await
            }
        }
        assert!(
            verifier
                .validate_access_token(&token, &client.client_id)
                .await
                .is_err(),
            "accepted {kind}"
        );
    }
}

#[tokio::test]
async fn partitioned_nodes_rotate_same_grant_independently_without_global_single_use() {
    let (source, first, client, principal) = setup().await;
    let refresh = issue(&first, &client, &principal)
        .await
        .refresh_token
        .expect("refresh grant")
        .0;
    let (second_engine, mut second) = public_verifier(&source).await;
    approve_independent_signer(&second_engine, &mut second).await;
    let (left, right) = tokio::join!(
        first.token(grant(&refresh, None), Some(auth(&client))),
        second.token(grant(&refresh, None), Some(auth(&client)))
    );
    let left = left.expect("first local winner");
    let right = right.expect("independent partition local winner");
    let (a, ac) = decode_jwt::<StandardClaims>(&left.access_token.0).expect("first claims");
    let (b, bc) = decode_jwt::<StandardClaims>(&right.access_token.0).expect("second claims");
    assert_ne!(a.kid, b.kid);
    assert_eq!(ac.sub, bc.sub);
    assert_eq!(ac.iss, bc.iss);
    assert!(
        first
            .token(grant(&refresh, None), Some(auth(&client)))
            .await
            .is_err()
    );
    assert!(
        second
            .token(grant(&refresh, None), Some(auth(&client)))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn public_keys_survive_native_reopen_without_secret_store() {
    let path = std::env::temp_dir().join(format!("of-public-key-{}.redb", Id::now_v7()));
    let entity_id = Id::now_v7();
    let (id, public, token) = {
        let engine = Arc::new(db::Database::open(&path).expect("open temporary database"));
        up(&engine).await.expect("initialize current schema");
        let keys = KeyService::new(
            DbKeyRepo::new(engine),
            TestPrivateKeyRepo::default(),
            "native-signer",
        );
        keys.ensure_entity_master_key(EntityType::User, entity_id, "local-test-passphrase")
            .expect("create local master key");
        let (key, private) = keys
            .create_key(
                None,
                EntityType::User,
                entity_id,
                true,
                "native".into(),
                None,
            )
            .await
            .expect("persist key and public material");
        let token = encode_jwt(
            &key.to_jwk_private(&private).expect("private signing JWK"),
            &serde_json::json!({"sub": entity_id.to_string()}),
        )
        .expect("sign test token");
        (key.id, key.public_jwk.expect("public material"), token)
    };
    {
        let engine =
            Arc::new(db::Database::open(&path).expect("reopen database without private store"));
        let repo = DbKeyRepo::new(engine);
        let key = repo
            .find_by_id(id)
            .await
            .expect("read persisted key")
            .expect("active key");
        let stored = key.public_jwk.expect("public material survives reopen");
        assert_eq!(stored, public);
        let (_, claims) = verify_jwt::<serde_json::Value>(&stored, &token)
            .expect("verify with persisted public material only");
        assert_eq!(claims["sub"], entity_id.to_string());
        let json = serde_json::to_value(&stored).expect("serialize public material");
        assert!(
            json.get("d").is_none(),
            "public record must not contain private scalar"
        );
    }
    std::fs::remove_file(path).expect("remove temporary database");
}

#[tokio::test]
async fn id_tokens_bind_the_principal_root_for_owner_local_verification() {
    let (engine, service, client, principal) = setup().await;
    let tokens = issue(&service, &client, &principal).await;
    let token = tokens.id_token.expect("issued ID token").0;
    let (header, claims) = decode_jwt::<serde_json::Value>(&token).expect("ID claims");
    assert_eq!(claims["principal_key_id"], principal.key.id.to_string());
    assert_ne!(header.kid, principal.key.id.to_string());
    let (_, typed) =
        decode_jwt::<idp_model::contract::IdTokenClaims>(&token).expect("typed bound ID claims");
    assert_eq!(typed.principal_key_id, principal.key.id);
    assert_eq!(
        typed.user_info.as_ref().expect("OIDC profile").sub,
        principal.user.id.to_string()
    );
    assert_eq!(
        serde_json::to_value(&typed).expect("roundtrip profile"),
        claims
    );
    let (verifier_engine, verifier) = public_verifier(&engine).await;
    let (verified, _) = verifier
        .verify_token_principal(&token)
        .await
        .expect("owner verifies ID Principal");
    assert_eq!(verified.r#use, model::contract::TokenUse::Id);
    assert_eq!(verified.sub, principal.user.id.to_string());
    assert!(
        verifier
            .validate_access_token(&token, &client.client_id)
            .await
            .is_err(),
        "ID token is not an access token"
    );
    for binding in [None, Some(Id::now_v7())] {
        let mut altered = claims.clone();
        if let Some(binding) = binding {
            altered["principal_key_id"] = binding.to_string().into();
        } else {
            altered
                .as_object_mut()
                .expect("claims object")
                .remove("principal_key_id");
        }
        let invalid = encode_jwt(
            &service.local_signing_jwk().await.expect("Node signer"),
            &altered,
        )
        .expect("sign altered binding");
        assert!(
            verifier.verify_token_principal(&invalid).await.is_err(),
            "missing/wrong signed root must deny"
        );
    }
    service
        .key_service
        .rotate_active_entity_root_key(
            EntityType::User,
            principal.user.id,
            "rotated root".into(),
            None,
        )
        .await
        .expect("rotate local Principal root");
    assert!(
        service.verify_token_principal(&token).await.is_err(),
        "owner learns root rotation"
    );
    assert!(
        verifier.verify_token_principal(&token).await.is_ok(),
        "disconnected verifier has not learned root rotation"
    );
    set(
        &verifier_engine,
        "keys",
        principal.key.id,
        "revoked_at",
        Value::Integer(chrono::Utc::now().timestamp()),
    )
    .await;
    assert!(
        verifier.verify_token_principal(&token).await.is_err(),
        "locally learned root revocation denies ID Principal verification"
    );
}

#[tokio::test]
async fn partitioned_nodes_consume_same_code_once_per_local_store() {
    use idp_model::contract::{AuthorizationCodeGrantRequest, TokenRequest};
    let (source, first, client, principal) = setup().await;
    let code = first
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
            chrono::Utc::now() + chrono::Duration::minutes(5),
        )
        .await
        .expect("create local code");
    let (engine, mut second) = public_verifier(&source).await;
    approve_independent_signer(&engine, &mut second).await;
    let request = TokenRequest::AuthorizationCode(AuthorizationCodeGrantRequest {
        code: code.code,
        client_id: Some(client.client_id.clone()),
        redirect_uri: Some(client.redirect_uris[0].clone()),
        code_verifier: "fixture-verifier".into(),
    });
    assert!(
        first
            .token(request.clone(), Some(auth(&client)))
            .await
            .is_ok()
    );
    assert!(
        second
            .token(request.clone(), Some(auth(&client)))
            .await
            .is_ok()
    );
    assert!(
        first
            .token(request.clone(), Some(auth(&client)))
            .await
            .is_err()
    );
    assert!(second.token(request, Some(auth(&client))).await.is_err());
}

#[tokio::test]
async fn independent_nodes_issue_client_tokens_with_distinct_local_signers() {
    use idp_model::contract::{ClientCredentialsGrantRequest, TokenRequest};
    let (source, first, _, _) = setup().await;
    let mut registration = super::infrastructure_client_registration();
    registration.allowed_audiences = vec!["https://service.example".into()];
    registration.allowed_scopes = vec!["idp.token.validate".into()];
    first
        .ensure_infrastructure_client(registration)
        .await
        .expect("provision local client credentials");
    let client = first
        .client_repo
        .find_client_by_client_id("storage-service")
        .await
        .expect("local client lookup")
        .expect("active client");
    let (engine, mut second) = public_verifier(&source).await;
    approve_independent_signer(&engine, &mut second).await;
    let request = TokenRequest::ClientCredentials(ClientCredentialsGrantRequest {
        client_id: client.client_id.clone(),
        client_secret: String::new(),
        scope: Some("idp.token.validate".into()),
        audience: Some("https://service.example".into()),
        resource: None,
    });
    let mut client_auth = auth(&client);
    client_auth.client_secret = Some("stable-secret".into());
    let left = first
        .token(request.clone(), Some(client_auth.clone()))
        .await
        .expect("first offline client issuance");
    let right = second
        .token(request, Some(client_auth))
        .await
        .expect("second offline client issuance");
    let (a, ac) = decode_jwt::<StandardClaims>(&left.access_token.0).expect("first client claims");
    let (b, bc) =
        decode_jwt::<StandardClaims>(&right.access_token.0).expect("second client claims");
    assert_ne!(a.kid, b.kid);
    assert_eq!(ac.sub, client.id.to_string());
    assert_eq!(bc.sub, ac.sub);
    assert_eq!(ac.principal_type, model::contract::PrincipalType::Client);
    assert!(
        first
            .validate_access_token(&left.access_token.0, "https://service.example")
            .await
            .is_ok()
    );
    assert!(
        second
            .validate_access_token(&right.access_token.0, "https://service.example")
            .await
            .is_ok()
    );
    first
        .rotate_client_key(&client.client_id)
        .await
        .expect("rotate local Client authentication root");
    assert!(
        first
            .validate_access_token(&left.access_token.0, "https://service.example")
            .await
            .is_err(),
        "locally learned Principal root rotation invalidates the old binding"
    );
    assert!(
        second
            .validate_access_token(&left.access_token.0, "https://service.example")
            .await
            .is_ok(),
        "partitioned Node retains its earlier trusted Principal view"
    );
}
