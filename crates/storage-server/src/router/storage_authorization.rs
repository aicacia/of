use std::sync::Arc;

use axum::Router;
use idp_model::{contract::IntrospectionResponse, model::Id};
use iroh::EndpointId;
use model::contract::{
    AuthorizationDetail, PrincipalType, StorageAuthorizationAction, TokenType, TokenUse,
};

use crate::{
    IdpClient, IdpIntrospectionError, StorageSocketAccess, StorageSocketAuthorizationError,
    StorageSocketAuthorizer, storage_router,
};
use storage_model::StorageNamespace as StorageNamespaceContract;
use storage_service::{FileSystemId, ScopedFileSystemRuntime, ScopedStorageService};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageAuthorizationError {
    InvalidToken,
    ServiceUnavailable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StorageAuthorization {
    pub subject: String,
    pub application_id: String,
    pub resource: String,
    pub expires_at: i64,
    pub can_read: bool,
    pub can_write: bool,
}

pub async fn authorize_storage_token(
    idp_client: &IdpClient,
    token: &str,
) -> Result<StorageAuthorization, StorageAuthorizationError> {
    let response = idp_client
        .introspect(token)
        .await
        .map_err(|error| match error {
            IdpIntrospectionError::InvalidToken => StorageAuthorizationError::InvalidToken,
            IdpIntrospectionError::ServiceUnavailable => {
                StorageAuthorizationError::ServiceUnavailable
            }
        })?;
    storage_authorization(response)
}

pub fn scoped_file_system_socket_router(
    idp_client: IdpClient,
    file_systems: Arc<ScopedFileSystemRuntime<EndpointId>>,
) -> Router {
    storage_router(Arc::new(scoped_file_system_socket_authorizer(
        idp_client,
        file_systems,
    )))
}

pub fn scoped_file_system_socket_authorizer(
    idp_client: IdpClient,
    file_systems: Arc<ScopedFileSystemRuntime<EndpointId>>,
) -> impl StorageSocketAuthorizer {
    ScopedFileSystemSocketAuthorizer {
        idp_client,
        file_systems,
    }
}

struct ScopedFileSystemSocketAuthorizer {
    idp_client: IdpClient,
    file_systems: Arc<ScopedFileSystemRuntime<EndpointId>>,
}

impl StorageSocketAuthorizer for ScopedFileSystemSocketAuthorizer {
    type Session = ScopedStorageService<EndpointId, StorageNamespace>;

    async fn authorize(
        &self,
        token: String,
        resource_id: String,
    ) -> Result<StorageSocketAccess<Self::Session>, StorageSocketAuthorizationError> {
        let resource_id = FileSystemId::parse(&resource_id)
            .map_err(|_| StorageSocketAuthorizationError::InvalidToken)?;
        let authorization = authorize_storage_token(&self.idp_client, &token)
            .await
            .map_err(|error| match error {
                StorageAuthorizationError::InvalidToken => {
                    StorageSocketAuthorizationError::InvalidToken
                }
                StorageAuthorizationError::ServiceUnavailable => {
                    StorageSocketAuthorizationError::ServiceUnavailable
                }
            })?;
        if authorization.resource != "storage:filesystems" {
            return Err(StorageSocketAuthorizationError::InvalidToken);
        }
        let application_id = authorization
            .application_id
            .parse::<Id>()
            .map_err(|_| StorageSocketAuthorizationError::InvalidToken)?;
        let scope = StorageNamespace {
            user_sub: authorization.subject,
            application_id,
        };
        let session = ScopedStorageService::open_resource(&self.file_systems, scope, resource_id)
            .await
            .map_err(|_| StorageSocketAuthorizationError::InvalidToken)?;
        Ok(StorageSocketAccess {
            read: authorization.can_read,
            write: authorization.can_write,
            expires_at: authorization.expires_at,
            session,
        })
    }
}

#[derive(Debug, Eq, PartialEq)]
struct StorageNamespace {
    user_sub: String,
    application_id: Id,
}

impl StorageNamespaceContract for StorageNamespace {
    fn user_sub(&self) -> &str {
        &self.user_sub
    }

    fn application_id(&self) -> Id {
        self.application_id
    }
}

fn unix_time_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs().min(i64::MAX as u64) as i64)
}

fn storage_authorization(
    response: IntrospectionResponse,
) -> Result<StorageAuthorization, StorageAuthorizationError> {
    let claims = response.claims;
    if claims.r#type != TokenType::Bearer
        || claims.r#use != TokenUse::Access
        || claims.principal_type != PrincipalType::User
        || claims.exp <= unix_time_seconds()
    {
        return Err(StorageAuthorizationError::InvalidToken);
    }
    let resource = claims
        .resource
        .filter(|resource| claims.aud == *resource)
        .ok_or(StorageAuthorizationError::InvalidToken)?;
    let [AuthorizationDetail::Storage(detail)] = claims
        .authorization_details
        .as_deref()
        .ok_or(StorageAuthorizationError::InvalidToken)?
    else {
        return Err(StorageAuthorizationError::InvalidToken);
    };
    let can_read = detail.actions.contains(&StorageAuthorizationAction::Read);
    let can_write = detail.actions.contains(&StorageAuthorizationAction::Write);
    if !can_read && !can_write {
        return Err(StorageAuthorizationError::InvalidToken);
    }
    Ok(StorageAuthorization {
        subject: claims.sub,
        application_id: response.application_id,
        resource,
        expires_at: claims.exp,
        can_read,
        can_write,
    })
}

#[cfg(test)]
mod tests {
    use idp_model::contract::IntrospectionResponse;
    use model::contract::{
        AuthorizationDetail, PrincipalType, StandardClaims, StorageAuthorizationAction,
        StorageAuthorizationDetail, TokenType, TokenUse,
    };

    use super::{StorageAuthorizationError, storage_authorization};

    fn response() -> IntrospectionResponse {
        IntrospectionResponse {
            claims: StandardClaims {
                r#type: TokenType::Bearer,
                r#use: TokenUse::Access,
                exp: i64::MAX,
                iat: 1,
                nbf: 1,
                iss: "https://idp.example".to_owned(),
                aud: "storage:filesystems".to_owned(),
                client_id: "desktop".to_owned(),
                sub: "user-1".to_owned(),
                principal_type: PrincipalType::User,
                resource: Some("storage:filesystems".to_owned()),
                authorization_details: Some(vec![AuthorizationDetail::Storage(
                    StorageAuthorizationDetail {
                        actions: vec![StorageAuthorizationAction::Read],
                    },
                )]),
                scope: Vec::new(),
            },
            application_id: "application-1".to_owned(),
        }
    }

    #[test]
    fn accepts_user_storage_access_and_preserves_namespace_fields() {
        let authorization =
            storage_authorization(response()).expect("valid user storage access must be accepted");
        assert_eq!(authorization.subject, "user-1");
        assert_eq!(authorization.application_id, "application-1");
        assert_eq!(authorization.resource, "storage:filesystems");
        assert_eq!(authorization.expires_at, i64::MAX);
        assert!(authorization.can_read);
        assert!(!authorization.can_write);
    }

    #[test]
    fn rejects_expired_access_tokens() {
        let mut response = response();
        response.claims.exp = 0;
        assert_eq!(
            storage_authorization(response),
            Err(StorageAuthorizationError::InvalidToken)
        );
    }

    #[test]
    fn rejects_client_principals_for_user_storage_access() {
        let mut response = response();
        response.claims.principal_type = PrincipalType::Client;
        assert!(storage_authorization(response).is_err());
    }

    #[test]
    fn rejects_mismatched_resource_audience() {
        let mut response = response();
        response.claims.aud = "another-resource".to_owned();
        assert!(storage_authorization(response).is_err());
    }

    #[test]
    fn rejects_empty_storage_actions() {
        let mut response = response();
        response.claims.authorization_details = Some(vec![AuthorizationDetail::Storage(
            StorageAuthorizationDetail {
                actions: Vec::new(),
            },
        )]);
        assert!(storage_authorization(response).is_err());
    }
}
