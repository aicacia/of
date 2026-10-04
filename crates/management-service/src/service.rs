use alloc::vec::Vec;

use idp_model::{
    contract::{PermissionEvaluationRequest, PermissionSubject},
    model::{Permission, Role},
};

use crate::{ManagementError, PermissionRepo, RoleRepo};

pub const MANAGEMENT_APPLICATION_URI: &str = "idp-management";

pub struct ManagementService<P, R> {
    permission_repo: P,
    role_repo: R,
}

impl<P, R> ManagementService<P, R>
where
    P: PermissionRepo,
    R: RoleRepo,
{
    pub fn new(permission_repo: P, role_repo: R) -> Self {
        Self {
            permission_repo,
            role_repo,
        }
    }

    pub async fn has_user_application_permission(
        &self,
        user_id: idp_model::model::Id,
        application_id: idp_model::model::Id,
        permission_name: &str,
    ) -> Result<bool, ManagementError> {
        if application_id.is_nil() || user_id.is_nil() {
            return Ok(false);
        }
        self.role_repo
            .has_user_application_permission(user_id, application_id, permission_name)
            .await
    }

    pub async fn evaluate_permission(
        &self,
        request: &PermissionEvaluationRequest,
    ) -> Result<bool, ManagementError> {
        let Some(namespace) = request.policy_namespace() else {
            return Ok(false);
        };
        let PermissionSubject::User { id } = request.subject;
        if id.is_nil() {
            return Ok(false);
        }
        self.role_repo
            .has_user_application_permission(id, namespace, request.action.permission())
            .await
    }

    pub async fn list_roles(
        &self,
        application_id: idp_model::model::Id,
        offset: u32,
        limit: u32,
    ) -> Result<Vec<Role>, ManagementError> {
        self.role_repo
            .list_roles(application_id, offset, limit)
            .await
    }

    pub async fn create_role(
        &self,
        application_id: idp_model::model::Id,
        name: &str,
        description: Option<&str>,
    ) -> Result<Role, ManagementError> {
        self.role_repo
            .create_role(application_id, name, description)
            .await
    }

    pub async fn find_role_by_id(
        &self,
        application_id: idp_model::model::Id,
        role_id: idp_model::model::Id,
    ) -> Result<Option<Role>, ManagementError> {
        self.role_repo
            .find_role_by_id(application_id, role_id)
            .await
    }

    pub async fn delete_role_by_id(
        &self,
        application_id: idp_model::model::Id,
        role_id: idp_model::model::Id,
    ) -> Result<(), ManagementError> {
        self.role_repo
            .delete_role_by_id(application_id, role_id)
            .await
    }

    pub async fn add_role_to_user(
        &self,
        application_id: idp_model::model::Id,
        user_id: idp_model::model::Id,
        role_id: idp_model::model::Id,
    ) -> Result<(), ManagementError> {
        self.role_repo
            .add_role_to_user(application_id, user_id, role_id)
            .await
    }

    pub async fn remove_role_from_user(
        &self,
        application_id: idp_model::model::Id,
        user_id: idp_model::model::Id,
        role_id: idp_model::model::Id,
    ) -> Result<(), ManagementError> {
        self.role_repo
            .remove_role_from_user(application_id, user_id, role_id)
            .await
    }

    pub async fn list_user_roles(
        &self,
        application_id: idp_model::model::Id,
        user_id: idp_model::model::Id,
    ) -> Result<Vec<Role>, ManagementError> {
        self.role_repo
            .list_user_roles(application_id, user_id)
            .await
    }

    pub async fn list_user_roles_across_applications(
        &self,
        user_id: idp_model::model::Id,
    ) -> Result<Vec<Role>, ManagementError> {
        self.role_repo
            .list_user_roles_across_applications(user_id)
            .await
    }

    pub async fn list_permissions(
        &self,
        application_id: idp_model::model::Id,
        offset: u32,
        limit: u32,
    ) -> Result<Vec<Permission>, ManagementError> {
        self.permission_repo
            .list_permissions(application_id, offset, limit)
            .await
    }

    pub async fn create_permission(
        &self,
        application_id: idp_model::model::Id,
        name: &str,
        description: Option<&str>,
    ) -> Result<Permission, ManagementError> {
        self.permission_repo
            .create_permission(application_id, name, description)
            .await
    }

    pub async fn find_permission_by_id(
        &self,
        application_id: idp_model::model::Id,
        permission_id: idp_model::model::Id,
    ) -> Result<Option<Permission>, ManagementError> {
        self.permission_repo
            .find_permission_by_id(application_id, permission_id)
            .await
    }

    pub async fn delete_permission_by_id(
        &self,
        application_id: idp_model::model::Id,
        permission_id: idp_model::model::Id,
    ) -> Result<(), ManagementError> {
        self.permission_repo
            .delete_permission_by_id(application_id, permission_id)
            .await
    }

    pub async fn list_role_permissions(
        &self,
        application_id: idp_model::model::Id,
        role_id: idp_model::model::Id,
    ) -> Result<Vec<Permission>, ManagementError> {
        self.permission_repo
            .list_role_permissions(application_id, role_id)
            .await
    }

    pub async fn add_permission_to_role(
        &self,
        application_id: idp_model::model::Id,
        role_id: idp_model::model::Id,
        permission_id: idp_model::model::Id,
    ) -> Result<(), ManagementError> {
        self.permission_repo
            .add_permission_to_role(application_id, role_id, permission_id)
            .await
    }

    pub async fn remove_permission_from_role(
        &self,
        application_id: idp_model::model::Id,
        role_id: idp_model::model::Id,
        permission_id: idp_model::model::Id,
    ) -> Result<(), ManagementError> {
        self.permission_repo
            .remove_permission_from_role(application_id, role_id, permission_id)
            .await
    }
}
