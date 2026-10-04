use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, header::AUTHORIZATION},
};
use idp_model::{
    contract::{ErrorCode, ErrorResponse},
    model::Id,
};
use management_service::replica::SelectedResource as StoredSelectedResource;
use model::contract::{
    MANAGEMENT_REPLICATION_ADMIT_SCOPE, MANAGEMENT_REPLICATION_READ_SCOPE, PrincipalType,
    ReplicationAdmissionRequest, SelectedResource, SelectedResourcesResponse, StandardClaims,
};

use crate::router::RouterState;

#[utoipa::path(
    get,
    path = "/replication/devices/{endpoint_id}/selections",
    params(("endpoint_id" = String, Path, description = "Iroh endpoint public key")),
    responses(
        (status = OK, description = "Selected resources", body = SelectedResourcesResponse),
        (status = 401, description = "Invalid bearer token"),
        (status = 403, description = "Token lacks replication-read permission"),
        (status = 503, description = "Authorization authority unavailable")
    ),
    security(("authorization" = []))
)]
pub(crate) async fn selected_resources(
    State(state): State<RouterState>,
    Path(endpoint_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<SelectedResourcesResponse>, ErrorResponse> {
    authorize_storage(&state, &headers, MANAGEMENT_REPLICATION_READ_SCOPE).await?;
    let identity = state
        .control_plane
        .get_storage_endpoint_identity(&endpoint_id)
        .await
        .map_err(|error| {
            log::warn!("Management endpoint identity lookup failed: {error}");
            unavailable()
        })?;
    let selected = state
        .selection_policies
        .selected_resources_for_device(identity.device_id)
        .await
        .map_err(|error| {
            log::warn!("failed to read selected replication resources: {error}");
            unavailable()
        })?;
    let resources = selected
        .into_iter()
        .filter(|resource| resource.owner_subject == identity.owner_subject)
        .map(selected_resource_response)
        .collect();
    Ok(Json(SelectedResourcesResponse { resources }))
}

#[utoipa::path(
    post,
    path = "/replication/admission",
    request_body = ReplicationAdmissionRequest,
    responses(
        (status = 204, description = "Replication admitted"),
        (status = 403, description = "Replication denied"),
        (status = 401, description = "Invalid bearer token"),
        (status = 503, description = "Authorization authority unavailable")
    ),
    security(("authorization" = []))
)]
pub(crate) async fn replication_admission(
    State(state): State<RouterState>,
    headers: HeaderMap,
    Json(request): Json<ReplicationAdmissionRequest>,
) -> Result<axum::http::StatusCode, ErrorResponse> {
    authorize_storage(&state, &headers, MANAGEMENT_REPLICATION_ADMIT_SCOPE).await?;
    let application_id = request
        .application_id
        .parse::<Id>()
        .map_err(|_| ErrorResponse::new(ErrorCode::InvalidRequest))?;
    let resource_id = request
        .resource_id
        .parse::<Id>()
        .map_err(|_| ErrorResponse::new(ErrorCode::InvalidRequest))?;
    if !matches!(request.kind.as_str(), "database" | "filesystem")
        || request.operation != "synchronize"
    {
        return Err(denied());
    }
    let source = state
        .control_plane
        .get_storage_endpoint_identity(&request.source_endpoint_id)
        .await
        .map_err(|_| unavailable())?;
    let target = state
        .control_plane
        .get_storage_endpoint_identity(&request.target_endpoint_id)
        .await
        .map_err(|_| unavailable())?;
    if source.device_id == target.device_id || source.owner_subject != target.owner_subject {
        return Err(denied());
    }

    for identity in [&source, &target] {
        let policy = state
            .selection_policies
            .get(identity.device_id, &identity.owner_subject, application_id)
            .await
            .map_err(|_| unavailable())?;
        if !policy.is_some_and(|policy| policy.admin_allowed) {
            return Err(denied());
        }
        let selected = state
            .selection_policies
            .selected_resources_for_device(identity.device_id)
            .await
            .map_err(|_| unavailable())?;
        if !resource_is_selected(
            &selected,
            identity.device_id,
            &identity.owner_subject,
            application_id,
            &request.kind,
            resource_id,
        ) {
            return Err(denied());
        }
    }
    Ok(axum::http::StatusCode::NO_CONTENT)
}

async fn authorize_storage(
    state: &RouterState,
    headers: &HeaderMap,
    required_scope: &str,
) -> Result<(), ErrorResponse> {
    let token = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|token| !token.is_empty())
        .ok_or_else(|| ErrorResponse::new(ErrorCode::NotAuthorized))?;
    let (claims, _) = state
        .control_plane
        .validate_actor_token(token)
        .await
        .map_err(|error| {
            if error == "actor token was rejected by IdP" {
                ErrorResponse::new(ErrorCode::NotAuthorized)
            } else {
                unavailable()
            }
        })?;
    if !replication_client_authorized(&claims, &state.storage_audience, required_scope) {
        return Err(denied());
    }
    Ok(())
}

fn replication_client_authorized(
    claims: &StandardClaims,
    storage_audience: &str,
    required_scope: &str,
) -> bool {
    claims.principal_type == PrincipalType::Client
        && claims.aud == storage_audience
        && claims.scope.iter().any(|scope| scope == required_scope)
}

fn resource_is_selected(
    resources: &[StoredSelectedResource],
    device_id: Id,
    owner_subject: &str,
    application_id: Id,
    kind: &str,
    resource_id: Id,
) -> bool {
    resources.iter().any(|resource| {
        resource.device_id == device_id
            && resource.owner_subject == owner_subject
            && resource.application_id == application_id
            && resource.kind == kind
            && resource.resource_id == resource_id
    })
}

fn selected_resource_response(resource: StoredSelectedResource) -> SelectedResource {
    SelectedResource {
        owner_subject: resource.owner_subject,
        application_id: resource.application_id.to_string(),
        kind: resource.kind,
        resource_id: resource.resource_id.to_string(),
    }
}

fn denied() -> ErrorResponse {
    ErrorResponse::new(ErrorCode::AccessDenied)
}

fn unavailable() -> ErrorResponse {
    ErrorResponse::new(ErrorCode::TemporarilyUnavailable)
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "cli")]
    use std::{
        fs,
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        path::Path,
        sync::Arc,
        thread,
    };

    #[cfg(feature = "cli")]
    use axum::{
        extract::{Path as AxumPath, State},
        http::{HeaderMap, HeaderValue, header::AUTHORIZATION},
    };
    #[cfg(feature = "cli")]
    use idp_model::contract::IntrospectionResponse;
    use idp_model::model::Id;
    use management_service::replica::SelectedResource as StoredSelectedResource;
    #[cfg(feature = "cli")]
    use management_service::{
        HostedControlPlane, ManagementService,
        replica::{DbPermissionRepo, DbRoleRepo, DbSelectionPolicyRepo},
    };
    use model::contract::{
        MANAGEMENT_REPLICATION_ADMIT_SCOPE, MANAGEMENT_REPLICATION_READ_SCOPE, PrincipalType,
        StandardClaims, TokenType, TokenUse,
    };

    #[cfg(feature = "cli")]
    use crate::router::RouterState;

    #[cfg(feature = "cli")]
    use super::selected_resources;
    use super::{replication_client_authorized, resource_is_selected, selected_resource_response};

    #[test]
    fn replication_authorization_requires_client_storage_audience_and_exact_scope() {
        let mut claims = StandardClaims {
            r#type: TokenType::Bearer,
            r#use: TokenUse::Access,
            exp: i64::MAX,
            iat: 0,
            nbf: 0,
            iss: "issuer".into(),
            aud: "storage-service".into(),
            client_id: "storage".into(),
            sub: "storage".into(),
            principal_type: PrincipalType::Client,
            resource: None,
            authorization_details: None,
            scope: vec![
                MANAGEMENT_REPLICATION_READ_SCOPE.into(),
                MANAGEMENT_REPLICATION_ADMIT_SCOPE.into(),
            ],
        };
        assert!(replication_client_authorized(
            &claims,
            "storage-service",
            MANAGEMENT_REPLICATION_READ_SCOPE
        ));
        assert!(replication_client_authorized(
            &claims,
            "storage-service",
            MANAGEMENT_REPLICATION_ADMIT_SCOPE
        ));
        assert!(!replication_client_authorized(
            &claims,
            "other-service",
            MANAGEMENT_REPLICATION_READ_SCOPE
        ));
        claims.principal_type = PrincipalType::User;
        assert!(!replication_client_authorized(
            &claims,
            "storage-service",
            MANAGEMENT_REPLICATION_READ_SCOPE
        ));
        claims.principal_type = PrincipalType::Client;
        claims.scope = vec!["management.replication.reader".into()];
        assert!(!replication_client_authorized(
            &claims,
            "storage-service",
            MANAGEMENT_REPLICATION_READ_SCOPE
        ));
    }

    #[test]
    fn selected_resource_match_is_bound_to_device_owner_application_kind_and_id() {
        let device_id = parse_id("00000000-0000-0000-0000-000000000001");
        let application_id = parse_id("00000000-0000-0000-0000-000000000002");
        let resource_id = parse_id("00000000-0000-0000-0000-000000000003");
        let selected = [StoredSelectedResource {
            device_id,
            owner_subject: "owner".to_owned(),
            application_id,
            kind: "database".to_owned(),
            resource_id,
        }];

        assert!(resource_is_selected(
            &selected,
            device_id,
            "owner",
            application_id,
            "database",
            resource_id,
        ));
        assert!(!resource_is_selected(
            &selected,
            device_id,
            "other-owner",
            application_id,
            "database",
            resource_id,
        ));
        assert!(!resource_is_selected(
            &selected,
            device_id,
            "owner",
            application_id,
            "filesystem",
            resource_id,
        ));

        let response = selected_resource_response(selected[0].clone());
        assert_eq!(response.owner_subject, "owner");
        assert_eq!(response.application_id, application_id.to_string());
    }

    #[cfg(feature = "cli")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn live_listener_rejects_unscoped_client_after_idp_introspection() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind IdP test server");
        let address = listener.local_addr().expect("read IdP test address");
        let claims = StandardClaims {
            r#type: TokenType::Bearer,
            r#use: TokenUse::Access,
            exp: i64::MAX,
            iat: 0,
            nbf: 0,
            iss: "https://issuer.example".to_owned(),
            aud: "storage-api".to_owned(),
            client_id: "storage-client".to_owned(),
            sub: "storage-client".to_owned(),
            principal_type: PrincipalType::Client,
            resource: None,
            authorization_details: None,
            scope: vec![MANAGEMENT_REPLICATION_ADMIT_SCOPE.to_owned()],
        };
        let introspection = serde_json::to_string(&IntrospectionResponse {
            claims,
            application_id: "00000000-0000-0000-0000-000000000001".to_owned(),
        })
        .expect("serialize IdP introspection response");
        let http_server = thread::spawn(move || {
            let (mut token_stream, _) = listener.accept().expect("accept token request");
            let mut token_request = [0; 4096];
            let token_length = token_stream
                .read(&mut token_request)
                .expect("read token request");
            let token_request =
                String::from_utf8_lossy(&token_request[..token_length]).into_owned();
            let token_response = r#"{"access_token":"management-token","token_type":"Bearer","expires_in":300,"scope":"idp.token.validate idp.device.lookup","iss":"https://issuer.example"}"#;
            write!(token_stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{token_response}", token_response.len()).expect("write token response");

            let (mut introspection_stream, _) =
                listener.accept().expect("accept introspection request");
            let mut introspection_request = [0; 4096];
            let introspection_length = introspection_stream
                .read(&mut introspection_request)
                .expect("read introspection request");
            let introspection_request =
                String::from_utf8_lossy(&introspection_request[..introspection_length])
                    .into_owned();
            write!(introspection_stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{introspection}", introspection.len()).expect("write introspection response");
            (token_request, introspection_request)
        });

        let root =
            std::env::temp_dir().join(format!("management-replication-auth-{}", Id::now_v7()));
        fs::create_dir_all(&root).expect("create test database directory");
        let engine = Arc::new(
            db::open_native_engine(Path::new(&root).join("management.redb"))
                .expect("open management test engine"),
        );
        let base_url = format!("http://{address}");
        let control_plane = Arc::new(
            HostedControlPlane::new_with_services(&base_url, &base_url, "https://issuer.example")
                .expect("create hosted control plane")
                .with_idp_service_client("management-client", "management-secret", "idp-audience")
                .expect("configure IdP service client"),
        );
        let state = RouterState::new(
            "http://management.example",
            Arc::new(ManagementService::new(
                DbPermissionRepo::new(Arc::clone(&engine)),
                DbRoleRepo::new(Arc::clone(&engine)),
            )),
            Arc::new(DbSelectionPolicyRepo::new(Arc::clone(&engine))),
            control_plane,
            "storage-api",
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind Management test listener");
        let management_address = listener.local_addr().expect("read Management address");
        let router = crate::router::openapi_router(state.clone(), "/")
            .split_for_parts()
            .0;
        let management_server = tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("serve Management test router");
        });
        let response = thread::spawn(move || {
            let mut stream = TcpStream::connect(management_address)
                .expect("connect to Management listener");
            write!(
                stream,
                "GET /replication/devices/endpoint-key/selections HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer storage-token\r\nConnection: close\r\n\r\n"
            )
            .expect("write Management request");
            let mut response = String::new();
            stream
                .read_to_string(&mut response)
                .expect("read Management response");
            response
        })
        .join()
        .expect("join Management request thread");
        assert!(response.starts_with("HTTP/1.1 403"), "{response}");
        management_server.abort();
        let _ = management_server.await;
        let (token_request, introspection_request) =
            http_server.join().expect("join IdP test server");
        assert!(token_request.starts_with("POST /oauth2/token HTTP/1.1"));
        assert!(introspection_request.starts_with("POST /oauth2/introspect HTTP/1.1"));
        assert!(introspection_request.contains("storage-token"));
        assert!(
            introspection_request
                .to_ascii_lowercase()
                .contains("authorization: bearer management-token")
        );

        drop(state);
        drop(engine);
        fs::remove_dir_all(root).expect("remove test database directory");
    }

    #[cfg(feature = "cli")]
    #[tokio::test]
    async fn selections_route_rejects_user_principal_and_wrong_audience() {
        for (principal_type, audience) in [
            (PrincipalType::User, "storage-api"),
            (PrincipalType::Client, "other-api"),
        ] {
            let claims = StandardClaims {
                r#type: TokenType::Bearer,
                r#use: TokenUse::Access,
                exp: i64::MAX,
                iat: 0,
                nbf: 0,
                iss: "https://issuer.example".to_owned(),
                aud: audience.to_owned(),
                client_id: "storage-client".to_owned(),
                sub: "storage-client".to_owned(),
                principal_type,
                resource: None,
                authorization_details: None,
                scope: vec![MANAGEMENT_REPLICATION_READ_SCOPE.to_owned()],
            };
            verify_selection_rejection(Some(claims)).await;
        }
    }

    #[cfg(feature = "cli")]
    #[tokio::test]
    async fn selections_route_rejects_token_denied_by_idp() {
        verify_selection_rejection(None).await;
    }

    #[cfg(feature = "cli")]
    async fn verify_selection_rejection(claims: Option<StandardClaims>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind IdP test server");
        let address = listener.local_addr().expect("read IdP test address");
        let token_was_introspected = claims.is_some();
        let introspection = claims
            .map(|claims| {
                serde_json::to_string(&IntrospectionResponse {
                    claims,
                    application_id: "00000000-0000-0000-0000-000000000001".to_owned(),
                })
                .expect("serialize IdP introspection response")
            })
            .unwrap_or_else(|| r#"{"error":"invalid_token"}"#.to_owned());
        let status = if token_was_introspected {
            "200 OK"
        } else {
            "401 Unauthorized"
        };
        let http_server = thread::spawn(move || {
            let (mut token_stream, _) = listener.accept().expect("accept token request");
            let mut token_request = [0; 4096];
            token_stream
                .read(&mut token_request)
                .expect("read token request");
            let token_response = r#"{"access_token":"management-token","token_type":"Bearer","expires_in":300,"scope":"idp.token.validate idp.device.lookup","iss":"https://issuer.example"}"#;
            write!(token_stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{token_response}", token_response.len()).expect("write token response");

            let (mut introspection_stream, _) =
                listener.accept().expect("accept introspection request");
            let mut introspection_request = [0; 4096];
            introspection_stream
                .read(&mut introspection_request)
                .expect("read introspection request");
            write!(introspection_stream, "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{introspection}", introspection.len()).expect("write introspection response");
        });

        let root =
            std::env::temp_dir().join(format!("management-replication-rejected-{}", Id::now_v7()));
        fs::create_dir_all(&root).expect("create test database directory");
        let engine = Arc::new(
            db::open_native_engine(Path::new(&root).join("management.redb"))
                .expect("open management test engine"),
        );
        let base_url = format!("http://{address}");
        let control_plane = Arc::new(
            HostedControlPlane::new_with_services(&base_url, &base_url, "https://issuer.example")
                .expect("create hosted control plane")
                .with_idp_service_client("management-client", "management-secret", "idp-audience")
                .expect("configure IdP service client"),
        );
        let state = RouterState::new(
            "http://management.example",
            Arc::new(ManagementService::new(
                DbPermissionRepo::new(Arc::clone(&engine)),
                DbRoleRepo::new(Arc::clone(&engine)),
            )),
            Arc::new(DbSelectionPolicyRepo::new(Arc::clone(&engine))),
            control_plane,
            "storage-api",
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer storage-token"),
        );

        let error = selected_resources(
            State(state.clone()),
            AxumPath("endpoint-key".to_owned()),
            headers,
        )
        .await
        .expect_err("unauthorized token must not authorize selection reads");
        let expected_error = if token_was_introspected {
            idp_model::contract::ErrorCode::AccessDenied
        } else {
            idp_model::contract::ErrorCode::NotAuthorized
        };
        assert_eq!(error.error, expected_error);
        http_server.join().expect("join IdP test server");

        drop(state);
        drop(engine);
        fs::remove_dir_all(root).expect("remove test database directory");
    }

    fn parse_id(value: &str) -> Id {
        value.parse().expect("valid fixture ID")
    }
}
