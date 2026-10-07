use std::sync::Arc;

use db::NativeEngine;
use idp_model::contract::PermissionEvaluationRequest;

use crate::{
    ManagementResult, ManagementService,
    replica::{DbPermissionRepo, DbRoleRepo},
};

#[derive(Clone)]
pub struct LocalPermissions {
    engine: Arc<NativeEngine>,
}

impl LocalPermissions {
    #[must_use]
    pub fn new(engine: Arc<NativeEngine>) -> Self {
        Self { engine }
    }

    pub async fn evaluate(&self, request: &PermissionEvaluationRequest) -> ManagementResult<bool> {
        ManagementService::new(
            DbPermissionRepo::new(Arc::clone(&self.engine)),
            DbRoleRepo::new(Arc::clone(&self.engine)),
        )
        .evaluate_permission(request)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::LocalPermissions;
    use crate::{
        ManagementService,
        replica::{DbPermissionRepo, DbRoleRepo, up},
    };
    use db::open_native_engine;
    use idp_model::{
        contract::{
            IdentityAction, IdentityResource, PermissionEvaluationRequest, PermissionSubject,
            PermissionTarget,
        },
        model::Id,
    };
    use std::sync::Arc;

    #[tokio::test]
    async fn local_policy_survives_reopen_and_denies_wrong_actor_action_and_target() {
        let path = std::env::temp_dir().join(format!("local-policy-{}.redb", Id::now_v7()));
        let user = Id::now_v7();
        let mut request = PermissionEvaluationRequest {
            request_id: Id::now_v7(),
            subject: PermissionSubject::User { id: user },
            action: IdentityAction::DevicePairingRead,
            target: PermissionTarget::Installation {
                resource: IdentityResource::DevicePairing,
            },
        };
        {
            let engine = Arc::new(open_native_engine(&path).expect("open local policy"));
            up(&engine).await.expect("initialize policy only");
            let local = LocalPermissions::new(Arc::clone(&engine));
            assert!(!local.evaluate(&request).await.expect("missing grants deny"));
            ManagementService::new(
                DbPermissionRepo::new(Arc::clone(&engine)),
                DbRoleRepo::new(Arc::clone(&engine)),
            )
            .provision_initial_administrator(
                user,
                Id::now_v7(),
                &[
                    (Id::now_v7(), IdentityAction::DevicePairingRead),
                    (Id::now_v7(), IdentityAction::DevicePairingUpdate),
                ],
            )
            .await
            .expect("explicit local grants");
            assert!(
                local
                    .evaluate(&request)
                    .await
                    .expect("local permission allows")
            );
        }
        {
            let engine = Arc::new(open_native_engine(&path).expect("reopen offline policy"));
            let local = LocalPermissions::new(engine);
            assert!(
                local
                    .evaluate(&request)
                    .await
                    .expect("persisted permission without any network")
            );
            request.subject = PermissionSubject::User { id: Id::now_v7() };
            assert!(!local.evaluate(&request).await.expect("wrong actor denies"));
            request.subject = PermissionSubject::User { id: user };
            request.action = IdentityAction::ClientsRead;
            assert!(
                !local
                    .evaluate(&request)
                    .await
                    .expect("wrong action/target denies")
            );
        }
        std::fs::remove_file(path).expect("remove policy fixture");
    }
}
