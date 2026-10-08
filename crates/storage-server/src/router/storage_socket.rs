use std::{future::Future, sync::Arc};

use axum::{
    Router,
    extract::{
        Query, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use storage_model::{StorageErrorCode, StorageRequest, StorageResponse, StorageSession};

pub struct StorageSocketAccess<S> {
    pub read: bool,
    pub write: bool,
    pub expires_at: i64,
    pub session: S,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageSocketAuthorizationError {
    InvalidToken,
    ServiceUnavailable,
}

pub trait StorageSocketAuthorizer: Send + Sync + 'static {
    type Session: StorageSession + 'static;

    fn authorize(
        &self,
        token: String,
        resource_id: String,
    ) -> impl Future<
        Output = Result<StorageSocketAccess<Self::Session>, StorageSocketAuthorizationError>,
    > + Send;
}

#[derive(serde::Deserialize)]
pub(super) struct StorageQuery {
    access_token: String,
    filesystem_id: String,
}

pub fn storage_router<A>(authorizer: Arc<A>) -> Router
where
    A: StorageSocketAuthorizer,
{
    Router::new()
        .route("/storage", get(upgrade_socket::<A>))
        .with_state(authorizer)
}

#[utoipa::path(
    get,
    path = "/storage",
    params(
        ("access_token" = String, Query, description = "User access token"),
        ("filesystem_id" = String, Query, description = "Filesystem resource ID")
    ),
    responses(
        (status = 101, description = "WebSocket connection upgraded"),
        (status = 401, description = "Invalid storage authorization"),
        (status = 503, description = "IdP validation service unavailable")
    )
)]
pub(super) async fn upgrade_socket<A>(
    upgrade: WebSocketUpgrade,
    Query(query): Query<StorageQuery>,
    State(authorizer): State<Arc<A>>,
) -> Response
where
    A: StorageSocketAuthorizer,
{
    let token = query.access_token;
    let resource_id = query.filesystem_id;
    let access = match authorizer
        .authorize(token.clone(), resource_id.clone())
        .await
    {
        Ok(access) => access,
        Err(StorageSocketAuthorizationError::InvalidToken) => {
            return StatusCode::UNAUTHORIZED.into_response();
        }
        Err(StorageSocketAuthorizationError::ServiceUnavailable) => {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    upgrade.on_upgrade(move |socket| serve_socket(socket, access, authorizer, token, resource_id))
}

async fn serve_socket<A>(
    mut socket: WebSocket,
    mut access: StorageSocketAccess<A::Session>,
    authorizer: Arc<A>,
    token: String,
    resource_id: String,
) where
    A: StorageSocketAuthorizer,
{
    loop {
        if unix_time_seconds() >= access.expires_at {
            return;
        }
        let Some(Ok(Message::Text(message))) = socket.recv().await else {
            return;
        };
        access = match authorizer
            .authorize(token.clone(), resource_id.clone())
            .await
        {
            Ok(access) if unix_time_seconds() < access.expires_at => access,
            Ok(_) | Err(_) => return,
        };
        let request = serde_json::from_str::<StorageRequest>(&message);
        let response = match &request {
            Ok(request) if allows(&access, request) => {
                access.session.execute_session(request.clone()).await
            }
            Ok(_) => StorageResponse::Error {
                code: StorageErrorCode::OperationFailed,
            },
            Err(_) => StorageResponse::Error {
                code: StorageErrorCode::InvalidRequest,
            },
        };
        let current = match authorizer
            .authorize(token.clone(), resource_id.clone())
            .await
        {
            Ok(current) if unix_time_seconds() < current.expires_at => current,
            Ok(_) | Err(_) => return,
        };
        if !(current.read || current.write)
            || (!matches!(response, StorageResponse::Error { .. })
                && !request
                    .as_ref()
                    .is_ok_and(|request| allows(&current, request)))
        {
            return;
        }
        if send_response(&mut socket, response).await.is_err() {
            return;
        }
    }
}

fn allows<S>(access: &StorageSocketAccess<S>, request: &StorageRequest) -> bool {
    match request {
        StorageRequest::Read { .. }
        | StorageRequest::Entry { .. }
        | StorageRequest::List { .. } => access.read,
        StorageRequest::Write { .. }
        | StorageRequest::Append { .. }
        | StorageRequest::Delete { .. }
        | StorageRequest::CreateDir { .. }
        | StorageRequest::Rename { .. } => access.write,
    }
}

fn unix_time_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs().min(i64::MAX as u64) as i64)
}

async fn send_response(socket: &mut WebSocket, response: StorageResponse) -> Result<(), ()> {
    let response = serde_json::to_string(&response).map_err(|_| ())?;
    socket
        .send(Message::Text(response.into()))
        .await
        .map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::{StorageSocketAccess, allows};
    use storage_model::{StorageRequest, StorageResponse, StorageSession};

    struct Session;

    impl StorageSession for Session {
        fn execute_session(
            &self,
            _: StorageRequest,
        ) -> impl std::future::Future<Output = StorageResponse> + Send {
            async { StorageResponse::Deleted }
        }
    }

    #[test]
    fn authorization_is_resource_wide_and_action_bounded() {
        let access = StorageSocketAccess {
            read: true,
            write: false,
            expires_at: i64::MAX,
            session: Session,
        };
        assert!(allows(
            &access,
            &StorageRequest::Read {
                path: "any/file".into()
            }
        ));
        assert!(!allows(
            &access,
            &StorageRequest::Write {
                path: "a/file".into(),
                content: Vec::new()
            }
        ));
        assert!(!allows(
            &access,
            &StorageRequest::Rename {
                from: "any/file".into(),
                to: "any/renamed".into()
            }
        ));
    }
}
