use std::sync::Arc;

use db::{AutomergeRowCodec, Engine, InMemoryKernel, open_native_engine};
use idp_model::{model::Id, replica::up};

use crate::repo::{OAuth2RefreshToken, OAuth2RefreshTokenRepo};

use super::{DbOAuth2RefreshTokenRepo, equals, select, token_hash};
use db::Value;

fn token(value: &str, client_id: Id, user_id: Id) -> OAuth2RefreshToken {
    OAuth2RefreshToken {

        token: value.into(),
        client_id,
        user_id,
        scopes: vec!["openid".into()],
        resource: Some("https://storage.example".into()),
        authorization_details: None,
        expires_at: 200,
        created_at: 100,
    }
}

#[tokio::test]
async fn concurrent_refresh_rotations_have_one_winner() {
    let engine = Arc::new(Engine::new(InMemoryKernel::new(), AutomergeRowCodec::new()));
    up(&engine).await.expect("initialize IdP schema");
    let repo = DbOAuth2RefreshTokenRepo::new(Arc::clone(&engine));
    let client = Id::now_v7();
    let user = Id::now_v7();
    repo.issue_refresh_token(token("old", client, user), None)
        .await.expect("persist original token");
    let (first, second) = tokio::join!(
        repo.issue_refresh_token(token("first", client, user), Some("old")),
        repo.issue_refresh_token(token("second", client, user), Some("old")),
    );
    assert_ne!(first.is_ok(), second.is_ok());
    let rows = engine.execute(vec![select(&["token_hash", "consumed_at"], None)])
        .await.expect("read token state").remove(0).rows;
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().any(|row| row.values == vec![
        Value::Text(token_hash("old")), Value::Integer(100),
    ]));
    let winner = if first.is_ok() { "first" } else { "second" };
    repo.issue_refresh_token(token("next", client, user), Some(winner))
        .await.expect("winner replacement is persisted and redeemable");
    assert!(repo.issue_refresh_token(token("reuse", client, user), Some("old")).await.is_err());
}

#[tokio::test]
async fn refresh_rotation_rejects_expired_revoked_and_wrong_bindings() {
    let engine = Arc::new(Engine::new(InMemoryKernel::new(), AutomergeRowCodec::new()));
    up(&engine).await.expect("initialize IdP schema");
    let repo = DbOAuth2RefreshTokenRepo::new(Arc::clone(&engine));
    let client = Id::now_v7();
    let user = Id::now_v7();
    repo.issue_refresh_token(token("valid", client, user), None)
        .await.expect("persist token");
    assert!(repo.issue_refresh_token(token("wrong-client", Id::now_v7(), user), Some("valid")).await.is_err());
    assert!(repo.issue_refresh_token(token("wrong-user", client, Id::now_v7()), Some("valid")).await.is_err());
    assert!(repo.issue_refresh_token(token("missing", client, user), Some("unknown")).await.is_err());
    let mut expired = token("expired", client, user);
    expired.expires_at = 100;
    repo.issue_refresh_token(expired, None).await.expect("persist expired token");
    assert!(repo.issue_refresh_token(token("expired-child", client, user), Some("expired")).await.is_err());
    repo.revoke_refresh_token("valid", Id::now_v7(), 100).await.expect("wrong client changes no rows");
    repo.issue_refresh_token(token("replacement", client, user), Some("valid"))
        .await.expect("wrong bindings did not consume or revoke original");
    repo.revoke_refresh_token("replacement", client, 100).await.expect("revoke replacement");
    repo.revoke_refresh_token("replacement", client, 101).await.expect("repeat revocation");
    assert!(repo.issue_refresh_token(token("revoked-child", client, user), Some("replacement")).await.is_err());
    let rows = engine.execute(vec![select(&["id"], None)])
        .await.expect("read tokens").remove(0).rows;
    assert_eq!(rows.len(), 3);
}

#[tokio::test]
async fn failed_refresh_replacement_rolls_back_consumption() {
    let engine = Arc::new(Engine::new(InMemoryKernel::new(), AutomergeRowCodec::new()));
    up(&engine).await.expect("initialize IdP schema");
    let repo = DbOAuth2RefreshTokenRepo::new(Arc::clone(&engine));
    let client = Id::now_v7();
    let user = Id::now_v7();
    repo.issue_refresh_token(token("old", client, user), None).await.expect("persist original");
    repo.issue_refresh_token(token("collision", client, user), None).await.expect("persist collision");
    assert!(repo.issue_refresh_token(token("collision", client, user), Some("old")).await.is_err());
    repo.issue_refresh_token(token("retry", client, user), Some("old"))
        .await.expect("failed insert did not consume original");
}

#[tokio::test]
async fn refresh_rotation_and_revocation_survive_database_reopen() {
    let path = std::env::temp_dir().join(format!("of-refresh-{}.redb", Id::now_v7()));
    let client = Id::now_v7();
    let user = Id::now_v7();
    {
        let engine = Arc::new(open_native_engine(&path).expect("open temporary database"));
        up(&engine).await.expect("initialize IdP schema");
        let repo = DbOAuth2RefreshTokenRepo::new(Arc::clone(&engine));
        repo.issue_refresh_token(token("old", client, user), None).await.expect("persist original");
        repo.issue_refresh_token(token("replacement", client, user), Some("old"))
            .await.expect("persist rotation");
        repo.issue_refresh_token(token("revoked", client, user), None).await.expect("persist revocable token");
        repo.revoke_refresh_token("revoked", client, 100).await.expect("persist revocation");
    }
    {
        let engine = Arc::new(open_native_engine(&path).expect("reopen database"));
        let repo = DbOAuth2RefreshTokenRepo::new(Arc::clone(&engine));
        assert!(repo.issue_refresh_token(token("reuse", client, user), Some("old")).await.is_err());
        assert!(repo.issue_refresh_token(token("revoked-child", client, user), Some("revoked")).await.is_err());
        repo.issue_refresh_token(token("next", client, user), Some("replacement"))
            .await.expect("replacement survives restart");
        let rows = engine.execute(vec![select(&["token_hash", "client_id", "user_id", "scopes", "resource"],
            Some(equals("token_hash", Value::Text(token_hash("next")))))]).await.expect("read persisted grant").remove(0).rows;
        assert_eq!(rows[0].values, vec![Value::Text(token_hash("next")), Value::Uuid(client),
            Value::Uuid(user), Value::Text("[\"openid\"]".into()), Value::Text("https://storage.example".into())]);
    }
    std::fs::remove_file(path).expect("remove temporary database");
}
