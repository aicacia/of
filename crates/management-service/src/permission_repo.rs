use alloc::vec::Vec;

use idp_model::model::{Id, Permission};

use crate::ManagementResult;

pub trait PermissionRepo {
    fn list_permissions(
        &self,
        application_id: Id,
        offset: u32,
        limit: u32,
    ) -> impl Future<Output = ManagementResult<Vec<Permission>>>;

    fn create_permission(
        &self,
        application_id: Id,
        name: &str,
        description: Option<&str>,
    ) -> impl Future<Output = ManagementResult<Permission>>;

    fn create_permission_with_id(
        &self,
        id: Id,
        application_id: Id,
        name: &str,
        description: Option<&str>,
    ) -> impl Future<Output = ManagementResult<Permission>>;

    fn find_permission_by_id(
        &self,
        application_id: Id,
        permission_id: Id,
    ) -> impl Future<Output = ManagementResult<Option<Permission>>>;

    fn delete_permission_by_id(
        &self,
        application_id: Id,
        permission_id: Id,
    ) -> impl Future<Output = ManagementResult<()>>;

    fn add_permission_to_role(
        &self,
        application_id: Id,
        role_id: Id,
        permission_id: Id,
    ) -> impl Future<Output = ManagementResult<()>>;

    fn remove_permission_from_role(
        &self,
        application_id: Id,
        role_id: Id,
        permission_id: Id,
    ) -> impl Future<Output = ManagementResult<()>>;

    fn list_role_permissions(
        &self,
        application_id: Id,
        role_id: Id,
    ) -> impl Future<Output = ManagementResult<Vec<Permission>>>;
}
