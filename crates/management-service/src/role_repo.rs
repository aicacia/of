use alloc::vec::Vec;

use idp_model::model::{Id, Permission, Role};

use crate::ManagementResult;

pub trait RoleRepo {
    fn list_roles(
        &self,
        application_id: Id,
        offset: u32,
        limit: u32,
    ) -> impl Future<Output = ManagementResult<Vec<Role>>>;

    fn create_role(
        &self,
        application_id: Id,
        name: &str,
        description: Option<&str>,
    ) -> impl Future<Output = ManagementResult<Role>>;

    fn create_role_with_id(
        &self,
        id: Id,
        application_id: Id,
        name: &str,
        description: Option<&str>,
    ) -> impl Future<Output = ManagementResult<Role>>;

    fn find_role_by_id(
        &self,
        application_id: Id,
        role_id: Id,
    ) -> impl Future<Output = ManagementResult<Option<Role>>>;

    fn delete_role_by_id(
        &self,
        application_id: Id,
        role_id: Id,
    ) -> impl Future<Output = ManagementResult<()>>;

    fn add_role_to_user(
        &self,
        application_id: Id,
        user_id: Id,
        role_id: Id,
    ) -> impl Future<Output = ManagementResult<()>>;

    fn remove_role_from_user(
        &self,
        application_id: Id,
        user_id: Id,
        role_id: Id,
    ) -> impl Future<Output = ManagementResult<()>>;

    fn list_user_roles(
        &self,
        application_id: Id,
        user_id: Id,
    ) -> impl Future<Output = ManagementResult<Vec<Role>>>;

    fn list_user_roles_across_applications(
        &self,
        user_id: Id,
    ) -> impl Future<Output = ManagementResult<Vec<Role>>>;

    fn list_user_permissions(
        &self,
        application_id: Id,
        user_id: Id,
    ) -> impl Future<Output = ManagementResult<Vec<Permission>>>;

    fn has_user_application_permission(
        &self,
        user_id: Id,
        application_id: Id,
        permission_name: &str,
    ) -> impl Future<Output = ManagementResult<bool>>;
}
