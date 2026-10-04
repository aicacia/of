use alloc::{string::String, vec::Vec};

use idp_model::model::Id;
use model::contract::AuthorizationDetail;

use super::RepoResult;

pub struct OAuth2RefreshToken {

    pub token: String,
    pub client_id: Id,
    pub user_id: Id,
    pub scopes: Vec<String>,
    pub resource: Option<String>,
    pub authorization_details: Option<Vec<AuthorizationDetail>>,
    pub expires_at: i64,
    pub created_at: i64,
}

pub trait OAuth2RefreshTokenRepo {
    fn issue_refresh_token(
        &self,
        token: OAuth2RefreshToken,
        previous: Option<&str>,
    ) -> impl Future<Output = RepoResult<()>>;

    fn revoke_refresh_token(
        &self,
        token: &str,
        client_id: Id,
        revoked_at: i64,
    ) -> impl Future<Output = RepoResult<()>>;
}
