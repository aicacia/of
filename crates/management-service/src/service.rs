use alloc::vec::Vec;

use idp_model::{
    contract::{
        INSTALLATION_POLICY_ID, IdentityAction, PermissionEvaluationRequest, PermissionSubject,
    },
    model::{Id, Permission, Role},
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

    pub async fn provision_initial_administrator(
        &self,
        user_id: Id,
        role_id: Id,
        permissions: &[(Id, IdentityAction)],
    ) -> Result<Role, ManagementError> {
        let mut action_names = alloc::vec::Vec::new();
        let mut permission_ids = alloc::vec::Vec::new();
        for (permission_id, action) in permissions {
            let name = action.permission();
            if permission_id.is_nil()
                || action.application_scoped()
                || name == "*"
                || action_names.contains(&name)
                || permission_ids.contains(permission_id)
            {
                return Err(ManagementError::InvalidInput(
                    "administrator permissions must be unique explicit installation actions".into(),
                ));
            }
            action_names.push(name);
            permission_ids.push(*permission_id);
        }
        if user_id.is_nil()
            || role_id.is_nil()
            || !action_names.contains(&IdentityAction::DevicePairingRead.permission())
            || !action_names.contains(&IdentityAction::DevicePairingUpdate.permission())
        {
            return Err(ManagementError::InvalidInput(
                "administrator requires valid IDs and both device-pairing permissions".into(),
            ));
        }

        let role = self
            .ensure_role(
                role_id,
                INSTALLATION_POLICY_ID,
                "installation-administrator",
                None,
            )
            .await?;
        let existing_permissions = self
            .list_role_permissions(INSTALLATION_POLICY_ID, role.id)
            .await?;
        if existing_permissions.iter().any(|existing| {
            !permissions.iter().any(|(permission_id, action)| {
                *permission_id == existing.id && action.permission() == existing.name
            })
        }) {
            return Err(ManagementError::InvalidInput(
                "administrator role has permissions outside the explicit grant list".into(),
            ));
        }
        for (permission_id, action) in permissions {
            let permission = self
                .ensure_permission(
                    *permission_id,
                    INSTALLATION_POLICY_ID,
                    action.permission(),
                    None,
                )
                .await?;
            self.add_permission_to_role(INSTALLATION_POLICY_ID, role.id, permission.id)
                .await?;
        }
        self.add_role_to_user(INSTALLATION_POLICY_ID, user_id, role.id)
            .await?;
        Ok(role)
    }

    pub async fn ensure_role(
        &self,
        id: idp_model::model::Id,
        application_id: idp_model::model::Id,
        name: &str,
        description: Option<&str>,
    ) -> Result<Role, ManagementError> {
        if id.is_nil() || name.is_empty() {
            return Err(ManagementError::InvalidInput(
                "role ID and name must not be empty".into(),
            ));
        }
        if let Some(role) = self.role_repo.find_role_by_id(application_id, id).await? {
            return if role.name == name && role.description.as_deref() == description {
                Ok(role)
            } else {
                Err(ManagementError::InvalidInput(
                    "stable role ID already has different data".into(),
                ))
            };
        }
        match self
            .role_repo
            .create_role_with_id(id, application_id, name, description)
            .await
        {
            Ok(role) => Ok(role),
            Err(error) => match self.role_repo.find_role_by_id(application_id, id).await? {
                Some(role) if role.name == name && role.description.as_deref() == description => {
                    Ok(role)
                }
                _ => Err(error),
            },
        }
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

    pub async fn ensure_permission(
        &self,
        id: idp_model::model::Id,
        application_id: idp_model::model::Id,
        name: &str,
        description: Option<&str>,
    ) -> Result<Permission, ManagementError> {
        if id.is_nil() || name.is_empty() {
            return Err(ManagementError::InvalidInput(
                "permission ID and name must not be empty".into(),
            ));
        }
        if let Some(permission) = self
            .permission_repo
            .find_permission_by_id(application_id, id)
            .await?
        {
            return if permission.name == name && permission.description.as_deref() == description {
                Ok(permission)
            } else {
                Err(ManagementError::InvalidInput(
                    "stable permission ID already has different data".into(),
                ))
            };
        }
        match self
            .permission_repo
            .create_permission_with_id(id, application_id, name, description)
            .await
        {
            Ok(permission) => Ok(permission),
            Err(error) => match self
                .permission_repo
                .find_permission_by_id(application_id, id)
                .await?
            {
                Some(permission)
                    if permission.name == name
                        && permission.description.as_deref() == description =>
                {
                    Ok(permission)
                }
                _ => Err(error),
            },
        }
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

#[cfg(all(test, feature = "replica"))]
mod tests {
    use std::sync::Arc;

    use db::{AutomergeRowCodec, Engine, InMemoryKernel};
    use idp_model::{contract::INSTALLATION_POLICY_ID, model::Id};

    use crate::{
        ManagementService,
        replica::{DbPermissionRepo, DbRoleRepo, up},
    };

    #[tokio::test]
    async fn ensure_rbac_records_retry_by_stable_id_and_reject_conflicts() {
        let engine = Arc::new(Engine::new(InMemoryKernel::new(), AutomergeRowCodec::new()));
        up(&engine).await.expect("initialize management schema");
        let service = ManagementService::new(
            DbPermissionRepo::new(Arc::clone(&engine)),
            DbRoleRepo::new(engine),
        );
        let role_id = Id::now_v7();
        let application_id = Id::now_v7();
        assert!(
            service
                .ensure_role(Id::nil(), application_id, "administrator", None)
                .await
                .is_err()
        );

        let created = service
            .ensure_role(role_id, application_id, "administrator", None)
            .await
            .expect("create role with stable ID");
        let retried = service
            .ensure_role(role_id, application_id, "administrator", None)
            .await
            .expect("retry returns the same role");
        assert_eq!(created, retried);
        let permission_id = Id::now_v7();
        let permission = service
            .ensure_permission(permission_id, application_id, "users.read", None)
            .await
            .expect("create permission with stable ID");
        assert_eq!(
            service
                .ensure_permission(permission_id, application_id, "users.read", None)
                .await
                .expect("retry returns the same permission"),
            permission
        );
        assert!(
            service
                .ensure_permission(permission_id, application_id, "users.write", None)
                .await
                .is_err()
        );
        assert!(
            service
                .ensure_role(role_id, application_id, "different", None)
                .await
                .is_err()
        );
        assert_eq!(
            service
                .list_roles(application_id, 0, 10)
                .await
                .expect("list the single provisioned role")
                .len(),
            1
        );

        let admin_id = Id::now_v7();
        let admin_role_id = Id::now_v7();
        let admin_permissions = [
            (
                Id::now_v7(),
                idp_model::contract::IdentityAction::DevicePairingRead,
            ),
            (
                Id::now_v7(),
                idp_model::contract::IdentityAction::DevicePairingUpdate,
            ),
            (Id::now_v7(), idp_model::contract::IdentityAction::UsersRead),
        ];
        assert!(
            service
                .provision_initial_administrator(admin_id, admin_role_id, &admin_permissions[..1],)
                .await
                .is_err()
        );
        let admin_role = service
            .provision_initial_administrator(admin_id, admin_role_id, &admin_permissions)
            .await
            .expect("provision administrator with explicit grants");
        assert_eq!(
            service
                .provision_initial_administrator(admin_id, admin_role_id, &admin_permissions)
                .await
                .expect("retry initial administrator provisioning"),
            admin_role
        );
        assert_eq!(
            service
                .list_role_permissions(INSTALLATION_POLICY_ID, admin_role.id)
                .await
                .expect("list explicitly assigned permissions")
                .len(),
            admin_permissions.len()
        );
        assert_eq!(
            service
                .list_user_roles_across_applications(admin_id)
                .await
                .expect("list installation administrator role")
                .len(),
            1
        );
        let extra_permission = service
            .ensure_permission(
                Id::now_v7(),
                INSTALLATION_POLICY_ID,
                idp_model::contract::IdentityAction::UsersDelete.permission(),
                None,
            )
            .await
            .expect("create an extra explicit permission");
        service
            .add_permission_to_role(INSTALLATION_POLICY_ID, admin_role.id, extra_permission.id)
            .await
            .expect("add extra permission to test role");
        assert!(
            service
                .provision_initial_administrator(admin_id, admin_role_id, &admin_permissions)
                .await
                .is_err()
        );
    }
}
