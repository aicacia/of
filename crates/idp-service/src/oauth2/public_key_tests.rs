use std::sync::Arc;

use chrono::Utc;
use db::{
    Query, QueryColumn, QueryExpr, QueryExprValue, QueryFrom, QueryUpdate, QueryUpdateAssignment,
    SqlTranslator, Statement, Value,
};
use idp_model::{
    contract::{EntityType, JwkPublic, JwkPublicParameters, KeyUse},
    model::Id,
};
use model::contract::StandardClaims;

use crate::{
    oauth2::{decode_jwt, encode_jwt, verify_jwt},
    repo::{KeyRepo, PrivateKeyRepo},
};

use super::{
    AutomergeRowCodec, DbApplicationRepo, DbClientRepo, DbKeyRepo, DbOAuth2AuthorizationCodeRepo,
    DbOAuth2RefreshTokenRepo, DbOAuth2UserConsentRepo, DbUserRepo, Engine, InMemoryKernel,
    KeyService, OAuth2Config, OAuth2Service, PasswordConfig, TestEngine, TestPrivateKeyRepo,
    TestService, auth, grant, issue, setup, up,
};

async fn public_verifier(source: &TestEngine) -> (Arc<TestEngine>, TestService) {
    let engine = Arc::new(Engine::new(InMemoryKernel::new(), AutomergeRowCodec::new()));
    up(&engine).await.expect("initialize independent schema");
    for table in ["applications", "clients", "users", "keys"] {
        let rows = source
            .translate_and_execute(&format!("SELECT * FROM {table}"), &SqlTranslator)
            .await
            .expect("read public identity records")
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
                .expect("copy identity records without private keys");
        }
    }
    let keys = Arc::new(KeyService::new(
        DbKeyRepo::new(Arc::clone(&engine)),
        TestPrivateKeyRepo::default(),
        "independent-verifier",
    ));
    let service = OAuth2Service::new(
        DbApplicationRepo::new(Arc::clone(&engine)),
        DbClientRepo::new(Arc::clone(&engine), Arc::clone(&keys)),
        DbOAuth2AuthorizationCodeRepo::new(Arc::clone(&engine)),
        DbOAuth2RefreshTokenRepo::new(Arc::clone(&engine)),
        DbUserRepo::new(Arc::clone(&engine), PasswordConfig::default()),
        DbOAuth2UserConsentRepo::new(Arc::clone(&engine)),
        keys,
        OAuth2Config {
            role: idp_model::contract::IdpRole::Authority,
            ..OAuth2Config::default()
        },
    );
    (engine, service)
}

async fn set(engine: &TestEngine, table: &str, id: Id, name: &str, value: Value) {
    let column = |name: &str| QueryColumn::new(table.into(), name.into());
    engine
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
        .expect("change security record for rejection test");
}

#[tokio::test]
async fn public_keys_verify_with_independent_empty_local_stores() {
    let (engine, authority, client, principal) = setup().await;
    let tokens = issue(&authority, &client, &principal).await;
    let user_token = tokens.access_token.0;
    let (_, mut claims) = decode_jwt::<StandardClaims>(&user_token).expect("decode issued claims");
    let client_key = authority
        .key_service
        .key_repo()
        .find_active_entity_root_key(EntityType::Client, client.id)
        .await
        .expect("query client key")
        .expect("client root key");
    claims.sub = client.id.to_string();
    claims.principal_type = model::contract::PrincipalType::Client;
    let client_token = encode_jwt(
        &authority
            .load_signing_jwk(&client_key)
            .await
            .expect("load local client signer"),
        &claims,
    )
    .expect("sign client claims");
    let (_, verifier) = public_verifier(&engine).await;
    assert!(!Arc::ptr_eq(&authority.key_service, &verifier.key_service));
    assert!(
        verifier
            .key_service
            .private_key_repo()
            .0
            .lock()
            .expect("key store lock")
            .is_empty()
    );
    for (id, token, entity_id, entity_type) in [
        (
            principal.key.id,
            &user_token,
            principal.user.id,
            EntityType::User,
        ),
        (client_key.id, &client_token, client.id, EntityType::Client),
    ] {
        let public = verifier
            .find_public_jwk(id)
            .await
            .expect("public-only lookup");
        let (_, claims) = verify_jwt::<StandardClaims>(&public, token)
            .expect("public-only signature verification");
        let bound = verifier
            .find_principal(id)
            .await
            .expect("principal lookup")
            .expect("live principal");
        assert_eq!(bound.get_entity_type(), entity_type);
        assert_eq!(bound.get_entity_id(), entity_id);
        assert_eq!(claims.sub, entity_id.to_string());
    }
    assert_eq!(
        authority.list_jwks().await.expect("authority JWKS").keys,
        verifier.list_jwks().await.expect("public-only JWKS").keys
    );
    assert_eq!(verifier.list_jwks().await.expect("JWKS").keys.len(), 2);
    assert!(
        verifier.load_signing_jwk(&principal.key).await.is_err(),
        "verification does not provide signing capability"
    );
    authority
        .key_service
        .private_key_repo()
        .0
        .lock()
        .expect("key store lock")
        .clear();
    let public = authority
        .find_public_jwk(principal.key.id)
        .await
        .expect("missing private key still verifies");
    verify_jwt::<StandardClaims>(&public, &user_token).expect("verify after secret deletion");
    assert_eq!(
        authority
            .list_jwks()
            .await
            .expect("JWKS without secrets")
            .keys
            .len(),
        2
    );
}

#[tokio::test]
async fn public_keys_reject_inactive_unbound_and_invalid_material() {
    let (engine, authority, client, principal) = setup().await;
    let token = issue(&authority, &client, &principal).await.access_token.0;
    let public = principal
        .key
        .public_jwk
        .clone()
        .expect("creation publishes public material");
    let mut wrong_id = public.clone();
    wrong_id.kid = client.id.to_string();
    let mut encryption = public.clone();
    encryption.r#use = KeyUse::Encryption;
    let mut wrong_curve = public.clone();
    if let JwkPublicParameters::Ec { crv, .. } = &mut wrong_curve.params {
        *crv = "P-256".into();
    }
    let mut malformed = public.clone();
    if let JwkPublicParameters::Ec { x, .. } = &mut malformed.params {
        *x = "invalid!".into();
    }
    let mut wrong_algorithm = public.clone();
    wrong_algorithm.alg = idp_model::contract::JwsAlgorithm::ES256;
    let json =
        |jwk: &JwkPublic| Value::Text(serde_json::to_string(jwk).expect("serialize public JWK"));
    for (name, value) in [
        ("revoked_at", Value::Integer(Utc::now().timestamp() - 1)),
        ("expires_at", Value::Integer(Utc::now().timestamp() - 1)),
        ("parent_id", Value::Uuid(client.id)),
        ("entity_id", Value::Uuid(Id::now_v7())),
        ("entity_type", Value::Integer(EntityType::Client as i64)),
        ("public_jwk", Value::Null),
        ("public_jwk", json(&wrong_id)),
        ("public_jwk", json(&encryption)),
        ("public_jwk", json(&wrong_curve)),
        ("public_jwk", json(&malformed)),
        ("public_jwk", json(&wrong_algorithm)),
    ] {
        let (replica_engine, verifier) = public_verifier(&engine).await;
        set(&replica_engine, "keys", principal.key.id, name, value).await;
        assert!(
            verifier.find_public_jwk(principal.key.id).await.is_err(),
            "reject invalid {name}"
        );
        assert!(
            !verifier
                .list_jwks()
                .await
                .expect("filtered JWKS")
                .keys
                .iter()
                .any(|jwk| jwk.kid == principal.key.id.to_string()),
            "omit invalid {name}"
        );
    }
    let (replica_engine, verifier) = public_verifier(&engine).await;
    set(
        &replica_engine,
        "clients",
        client.id,
        "revoked_at",
        Value::Integer(Utc::now().timestamp() - 1),
    )
    .await;
    let client_key = authority
        .key_service
        .key_repo()
        .find_active_entity_root_key(EntityType::Client, client.id)
        .await
        .expect("client root lookup")
        .expect("client key");
    assert!(
        verifier
            .find_principal(client_key.id)
            .await
            .expect("revoked principal lookup")
            .is_none()
    );
    assert!(verifier.find_public_jwk(client_key.id).await.is_err());
    assert!(
        !verifier
            .list_jwks()
            .await
            .expect("JWKS")
            .keys
            .iter()
            .any(|jwk| jwk.kid == client_key.id.to_string())
    );

    let mut other_public = client_key.public_jwk.expect("client public material");
    other_public.kid = principal.key.id.to_string();
    set(
        &replica_engine,
        "keys",
        principal.key.id,
        "public_jwk",
        json(&other_public),
    )
    .await;
    let wrong = verifier
        .find_public_jwk(principal.key.id)
        .await
        .expect("structurally valid but wrong public point");
    assert!(
        verify_jwt::<StandardClaims>(&wrong, &token).is_err(),
        "wrong public point cannot verify token"
    );
}

#[tokio::test]
async fn public_keys_are_write_once_and_signing_checks_local_material() {
    let (engine, authority, client, principal) = setup().await;
    let stored = DbKeyRepo::new(Arc::clone(&engine))
        .find_by_id(principal.key.id)
        .await
        .expect("read through separate repository")
        .expect("persisted key");
    assert_eq!(stored.public_jwk, principal.key.public_jwk);
    let public = stored.public_jwk.expect("persisted public material");
    assert!(
        authority
            .key_service
            .key_repo()
            .set_public_jwk(principal.key.id, public.clone())
            .await
            .is_err(),
        "cannot overwrite public material"
    );
    let pending = authority
        .key_service
        .key_repo()
        .create_key(
            None,
            EntityType::User,
            Id::now_v7(),
            true,
            "pending".into(),
            None,
        )
        .await
        .expect("create metadata only");
    assert!(
        authority
            .key_service
            .key_repo()
            .set_public_jwk(pending.id, public)
            .await
            .is_err(),
        "reject mismatched public key ID"
    );
    assert!(
        authority.find_public_jwk(pending.id).await.is_err(),
        "metadata alone is not trusted"
    );
    let path = principal.key.derivation_path().expect("user key path");
    let client_key = authority
        .key_service
        .key_repo()
        .find_active_entity_root_key(EntityType::Client, client.id)
        .await
        .expect("client root lookup")
        .expect("client key");
    let client_private = authority
        .key_service
        .private_key_repo()
        .load(
            &authority
                .key_service
                .scoped_namespace(EntityType::Client, client.id),
            &client_key
                .derivation_path()
                .expect("client derivation path"),
        )
        .expect("read client secret")
        .expect("local client secret");
    authority
        .key_service
        .private_key_repo()
        .0
        .lock()
        .expect("authority key store")
        .insert(
            (
                authority
                    .key_service
                    .scoped_namespace(EntityType::User, principal.user.id),
                path.to_string(),
            ),
            client_private,
        );
    assert!(
        authority.load_signing_jwk(&principal.key).await.is_err(),
        "wrong local key must not issue unverifiable tokens"
    );
}

#[tokio::test]
async fn public_keys_preserve_subject_binding_and_filter_superseded_roots() {
    let (engine, authority, client, principal) = setup().await;
    let tokens = issue(&authority, &client, &principal).await;
    let signing = authority
        .load_signing_jwk(&principal.key)
        .await
        .expect("local signer");
    let refresh = tokens.refresh_token.expect("refresh token").0;
    let (_, mut claims) = decode_jwt::<StandardClaims>(&refresh).expect("refresh claims");
    claims.sub = client.id.to_string();
    let mismatched = encode_jwt(&signing, &claims).expect("sign wrong subject");
    let error = authority
        .token(grant(&mismatched, None), Some(auth(&client)))
        .await
        .expect_err("reject wrong subject");
    assert_eq!(
        error.error_description.as_deref(),
        Some("refresh token subject does not match principal")
    );
    set(
        &engine,
        "keys",
        principal.key.id,
        "created_at",
        Value::Integer(Utc::now().timestamp() - 10),
    )
    .await;
    let (replacement, _) = authority
        .key_service
        .rotate_active_entity_root_key(
            EntityType::User,
            principal.user.id,
            "replacement".into(),
            None,
        )
        .await
        .expect("create replacement with public material");
    let (child, _) = authority
        .key_service
        .create_key(
            Some(replacement.id),
            EntityType::User,
            principal.user.id,
            false,
            "child".into(),
            None,
        )
        .await
        .expect("create derived child with public material");
    let (_, verifier) = public_verifier(&engine).await;
    assert!(
        verifier.find_public_jwk(principal.key.id).await.is_err(),
        "superseded root rejected"
    );
    assert!(
        verifier.find_public_jwk(child.id).await.is_err(),
        "derived child is not active root signer"
    );
    let published = verifier.list_jwks().await.expect("filtered root JWKS").keys;
    assert!(
        published
            .iter()
            .any(|jwk| jwk.kid == replacement.id.to_string())
    );
    assert!(
        !published
            .iter()
            .any(|jwk| jwk.kid == principal.key.id.to_string() || jwk.kid == child.id.to_string())
    );
}

#[tokio::test]
async fn public_keys_survive_native_reopen_without_secret_store() {
    let path = std::env::temp_dir().join(format!("of-public-key-{}.redb", Id::now_v7()));
    let entity_id = Id::now_v7();
    let (id, public, token) = {
        let engine = Arc::new(db::open_native_engine(&path).expect("open temporary database"));
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
            Arc::new(db::open_native_engine(&path).expect("reopen database without private store"));
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
