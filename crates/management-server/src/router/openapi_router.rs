use api::SecurityAddon;
use utoipa::OpenApi;
use utoipa::openapi::{Paths, RefOr, Schema, Server};
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::RouterState;

use super::openapi::{__path_openapi_json, openapi_json};

use super::routes::device_selection::{
    __path_delete_device_resource_selection, __path_delete_device_selection,
    __path_put_device_selection, delete_device_resource_selection, delete_device_selection,
    put_device_selection,
};
use super::routes::health::{__path_health, health};

use super::routes::permission_evaluation::{__path_evaluate_permission, evaluate_permission};
use super::routes::permissions::{
    __path_assign_permission_to_role, __path_create_permission, __path_delete_permission,
    __path_list_permissions, __path_list_role_permissions, __path_revoke_permission_from_role,
    assign_permission_to_role, create_permission, delete_permission, list_permissions,
    list_role_permissions, revoke_permission_from_role,
};
use super::routes::replication::{
    __path_replication_admission, __path_selected_resources, replication_admission,
    selected_resources,
};
use super::routes::roles::{
    __path_assign_role_to_user, __path_create_role, __path_delete_role, __path_list_roles,
    __path_list_user_roles, __path_revoke_role_from_user, assign_role_to_user, create_role,
    delete_role, list_roles, list_user_roles, revoke_role_from_user,
};
use super::routes::users::{
    __path_list_user_roles_across_applications, list_user_roles_across_applications,
};
use super::routes::version::{__path_version, version};

#[derive(OpenApi)]
#[openapi(
    info(title = "LIDP Management API", version = env!("CARGO_PKG_VERSION")),
    paths(
        super::routes::replication::selected_resources,
        super::routes::replication::replication_admission
    ),
    modifiers(&SecurityAddon)
)]
pub(crate) struct ApiDoc;

pub fn openapi_router(router_state: RouterState, prefix: &str) -> OpenApiRouter {
    let prefix = if prefix == "/" { "" } else { prefix };
    let api_base_uri = router_state.api_base_uri.clone();

    let routes = || {
        OpenApiRouter::new()
            .routes(routes!(health))
            .routes(routes!(version))
            .routes(routes!(list_user_roles_across_applications))
            .routes(routes!(put_device_selection))
            .routes(routes!(delete_device_selection))
            .routes(routes!(delete_device_resource_selection))
            .routes(routes!(selected_resources))
            .routes(routes!(replication_admission))
            .routes(routes!(evaluate_permission))
            .routes(routes!(list_roles))
            .routes(routes!(create_role))
            .routes(routes!(delete_role))
            .routes(routes!(list_user_roles))
            .routes(routes!(assign_role_to_user))
            .routes(routes!(revoke_role_from_user))
            .routes(routes!(list_permissions))
            .routes(routes!(create_permission))
            .routes(routes!(delete_permission))
            .routes(routes!(list_role_permissions))
            .routes(routes!(assign_permission_to_role))
            .routes(routes!(revoke_permission_from_role))
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
