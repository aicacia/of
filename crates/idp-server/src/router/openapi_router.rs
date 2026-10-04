use api::SecurityAddon;
use utoipa::OpenApi;
use utoipa::openapi::{Paths, RefOr, Schema, Server};
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::RouterState;

use super::openapi::{__path_openapi_json, openapi_json};
use super::routes::administration::{
    __path_create_application, __path_delete_application, __path_delete_user,
    __path_get_application, __path_get_user, __path_list_applications, __path_list_client_keys,
    __path_list_consents, __path_reset_password, __path_revoke_client_keys, __path_revoke_consent,
    __path_rotate_client_key, __path_update_application, __path_update_user, create_application,
    delete_application, delete_user, get_application, get_user, list_applications,
    list_client_keys, list_consents, reset_password, revoke_client_keys, revoke_consent,
    rotate_client_key, update_application, update_user,
};
use super::routes::device::{__path_device, device};
use super::routes::device_self_revocation::{__path_revoke_self, revoke_self};
use super::routes::devices::{
    __path_enroll_device, __path_list_approved_device_endpoints, __path_list_devices,
    __path_lookup_device_endpoint, __path_pairing_acceptance, __path_revoke_device,
    __path_set_pairing_acceptance, __path_trusted_devices, __path_update_device, enroll_device,
    list_approved_device_endpoints, list_devices, lookup_device_endpoint, pairing_acceptance,
    revoke_device, set_pairing_acceptance, trusted_devices, update_device,
};
use super::routes::health::{__path_health, health};

use super::routes::oauth2::approvals::{
    __path_approve_for_user, __path_is_allowed_for_user, approve_for_user, is_allowed_for_user,
};
use super::routes::oauth2::auth::{
    __path_authorize_json, __path_authorize_query, authorize_json, authorize_query,
};
use super::routes::oauth2::device::{
    __path_device_auth, __path_device_verify, device_auth, device_verify,
};
use super::routes::oauth2::introspect::{__path_introspect, introspect};
use super::routes::oauth2::register::{
    __path_delete_register, __path_get_register, __path_put_register, __path_register,
    delete_register, get_register, put_register, register,
};
use super::routes::oauth2::revoke::{__path_revoke, revoke};
use super::routes::oauth2::sessions::{__path_sessions_logout, sessions_logout};
use super::routes::oauth2::token::{__path_token, token};
use super::routes::setup::{__path_register_bootstrap, register_bootstrap};

use super::routes::userinfo::{__path_userinfo, userinfo};
use super::routes::version::{__path_version, version};
use super::routes::well_known::{
    __path_jwks, __path_openid_configuration, jwks, openid_configuration,
};

#[derive(OpenApi)]
#[openapi(
    paths(
        super::routes::oauth2::introspect::introspect,
        super::routes::setup::register_bootstrap,

        super::routes::devices::lookup_device_endpoint,
        super::routes::devices::list_approved_device_endpoints,

    ),
    info(title = "OAuth Server", version = env!("CARGO_PKG_VERSION")),
    modifiers(&SecurityAddon)
)]
pub(crate) struct ApiDoc;

pub fn openapi_router(router_state: RouterState, prefix: &str) -> OpenApiRouter {
    let prefix = if prefix == "/" { "" } else { prefix };
    let api_base_uri = router_state.api_base_uri.clone();

    let routes = || {
        OpenApiRouter::new()
            .routes(routes!(health))
            .routes(routes!(list_applications))
            .routes(routes!(create_application))
            .routes(routes!(get_application))
            .routes(routes!(update_application))
            .routes(routes!(delete_application))
            .routes(routes!(get_user))
            .routes(routes!(update_user))
            .routes(routes!(delete_user))
            .routes(routes!(reset_password))
            .routes(routes!(list_consents))
            .routes(routes!(revoke_consent))
            .routes(routes!(list_client_keys))
            .routes(routes!(rotate_client_key))
            .routes(routes!(revoke_client_keys))
            .routes(routes!(register_bootstrap))
            .routes(routes!(device))
            .routes(routes!(revoke_self))
            .routes(routes!(trusted_devices))
            .routes(routes!(enroll_device))
            .routes(routes!(pairing_acceptance))
            .routes(routes!(set_pairing_acceptance))
            .routes(routes!(list_devices))
            .routes(routes!(lookup_device_endpoint))
            .routes(routes!(list_approved_device_endpoints))
            .routes(routes!(update_device))
            .routes(routes!(revoke_device))
            .routes(routes!(authorize_json))
            .routes(routes!(authorize_query))
            .routes(routes!(is_allowed_for_user))
            .routes(routes!(approve_for_user))
            .routes(routes!(device_auth))
            .routes(routes!(device_verify))
            .routes(routes!(introspect))
            .routes(routes!(register))
            .routes(routes!(get_register))
            .routes(routes!(delete_register))
            .routes(routes!(put_register))
            .routes(routes!(token))
            .routes(routes!(revoke))
            .routes(routes!(sessions_logout))
            .routes(routes!(version))
            .routes(routes!(jwks))
            .routes(routes!(openid_configuration))
            .routes(routes!(userinfo))
    };

    let spec_router = OpenApiRouter::with_openapi(ApiDoc::openapi()).merge(routes());

    let mut openapi_spec = spec_router.get_openapi().clone();

    openapi_spec.servers = Some(vec![Server::new(format!("{}{}", api_base_uri, prefix))]);

    if !prefix.is_empty() {
        let mut paths = Paths::new();

        for (path, item) in openapi_spec.paths.paths {
            let path = path.strip_prefix(prefix).unwrap_or(&path).to_owned();

            paths.paths.insert(path, item);
        }

        openapi_spec.paths = paths;
    }

    let mut schemas = Vec::<(String, RefOr<Schema>)>::new();
    let (openapi_json_path, openapi_json_item, openapi_json_types) =
        routes!(@resolve_types openapi_json : schemas);

    openapi_spec.paths.add_path_operation(
        &openapi_json_path,
        openapi_json_types,
        openapi_json_item,
    );

    let runtime_router = if prefix.is_empty() {
        OpenApiRouter::with_openapi(ApiDoc::openapi()).merge(routes().with_state(router_state))
    } else {
        OpenApiRouter::with_openapi(ApiDoc::openapi())
            .nest(prefix, routes().with_state(router_state))
    };

    let openapi_json_routes = OpenApiRouter::new()
        .routes(routes!(openapi_json))
        .with_state(openapi_spec);

    if prefix.is_empty() {
        runtime_router.merge(openapi_json_routes)
    } else {
        runtime_router.nest(prefix, openapi_json_routes)
    }
}

#[cfg(test)]
mod tests {
    use utoipa::OpenApi;

    use super::ApiDoc;

    #[test]
    fn documents_setup_and_excludes_storage_routes() {
        let document = ApiDoc::openapi();
        for path in ["/setup/bootstrap"] {
            assert!(document.paths.paths.contains_key(path), "missing {path}");
        }
        assert!(
            document
                .paths
                .paths
                .keys()
                .all(|path| !path.starts_with("/internal/") && !path.starts_with("/storage/")),
            "IdP must not publish internal or Storage routes"
        );
    }
}
