#[cfg(not(feature = "std"))]
use alloc::string::String;

use serde::{Deserialize, Serialize};

use crate::model::Id;

pub const MANAGEMENT_PERMISSION_EVALUATE_SCOPE: &str = "management.permission.evaluate";
// Reserved policy namespace, never an IdP Application. Application APIs must reject it.
pub const INSTALLATION_POLICY_ID: Id = Id::nil();

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(tag = "type", rename_all = "camelCase", deny_unknown_fields)]
pub enum PermissionSubject {
    User {
        #[cfg_attr(feature = "utoipa", schema(value_type = String))]
        id: Id,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum IdentityAction {
    ClientsRead,
    ClientsCreate,
    ClientsUpdate,
    ClientsDelete,
    InfrastructureClientsRead,
    InfrastructureClientsCreate,
    InfrastructureClientsUpdate,
    InfrastructureClientsDelete,
    ApplicationsRead,
    ApplicationsCreate,
    ApplicationsUpdate,
    ApplicationsDelete,
    UsersRead,
    UsersUpdate,
    UsersDelete,
    UsersResetPassword,
    ConsentsRead,
    ConsentsRevoke,
    KeysRead,
    KeysRotate,
    KeysRevoke,
    DevicePairingRead,
    DevicePairingUpdate,
    ReplicaSignersEnroll,
    ReplicaSignersRotate,
    ReplicaSignersRevoke,
}

impl IdentityAction {
    pub const fn permission(self) -> &'static str {
        match self {
            Self::ClientsRead => "idp.clients.read",
            Self::ClientsCreate => "idp.clients.create",
            Self::ClientsUpdate => "idp.clients.update",
            Self::ClientsDelete => "idp.clients.delete",
            Self::InfrastructureClientsRead => "idp.infrastructure_clients.read",
            Self::InfrastructureClientsCreate => "idp.infrastructure_clients.create",
            Self::InfrastructureClientsUpdate => "idp.infrastructure_clients.update",
            Self::InfrastructureClientsDelete => "idp.infrastructure_clients.delete",
            Self::ApplicationsRead => "idp.applications.read",
            Self::ApplicationsCreate => "idp.applications.create",
            Self::ApplicationsUpdate => "idp.applications.update",
            Self::ApplicationsDelete => "idp.applications.delete",
            Self::UsersRead => "idp.users.read",
            Self::UsersUpdate => "idp.users.update",
            Self::UsersDelete => "idp.users.delete",
            Self::UsersResetPassword => "idp.users.reset_password",
            Self::ConsentsRead => "idp.consents.read",
            Self::ConsentsRevoke => "idp.consents.revoke",
            Self::KeysRead => "idp.keys.read",
            Self::KeysRotate => "idp.keys.rotate",
            Self::KeysRevoke => "idp.keys.revoke",
            Self::DevicePairingRead => "idp.device_pairing.read",
            Self::DevicePairingUpdate => "idp.device_pairing.update",
            Self::ReplicaSignersEnroll => "idp.replica_signers.enroll",
            Self::ReplicaSignersRotate => "idp.replica_signers.rotate",
            Self::ReplicaSignersRevoke => "idp.replica_signers.revoke",
        }
    }

    pub const fn application_scoped(self) -> bool {
        matches!(
            self,
            Self::ClientsRead | Self::ClientsCreate | Self::ClientsUpdate | Self::ClientsDelete
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(tag = "scope", rename_all = "camelCase", deny_unknown_fields)]
pub enum PermissionTarget {
    Application {
        #[serde(rename = "applicationId")]
        #[cfg_attr(feature = "utoipa", schema(value_type = String))]
        application_id: Id,
        resource: IdentityResource,
    },
    Installation {
        resource: IdentityResource,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(tag = "type", rename_all = "camelCase", deny_unknown_fields)]
pub enum IdentityResource {
    Client {
        #[serde(rename = "clientId")]
        client_id: Option<String>,
    },
    Application {
        #[cfg_attr(feature = "utoipa", schema(value_type = Option<String>))]
        id: Option<Id>,
    },
    User {
        #[cfg_attr(feature = "utoipa", schema(value_type = String))]
        id: Id,
    },
    Consent {
        #[serde(rename = "userId")]
        #[cfg_attr(feature = "utoipa", schema(value_type = String))]
        user_id: Id,
        #[cfg_attr(feature = "utoipa", schema(value_type = Option<String>))]
        id: Option<Id>,
    },
    ClientKeys {
        #[serde(rename = "clientId")]
        client_id: String,
    },
    DevicePairing,
    ReplicaSigner {
        #[cfg_attr(feature = "utoipa", schema(value_type = Option<String>))]
        member_id: Option<Id>,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionEvaluationRequest {
    #[cfg_attr(feature = "utoipa", schema(value_type = String))]
    pub request_id: Id,
    pub subject: PermissionSubject,
    pub action: IdentityAction,
    pub target: PermissionTarget,
}

impl PermissionEvaluationRequest {
    pub fn policy_namespace(&self) -> Option<Id> {
        use IdentityAction as A;
        let resource = match &self.target {
            PermissionTarget::Application { resource, .. }
            | PermissionTarget::Installation { resource } => resource,
        };
        let valid = match (self.action, resource) {
            (
                A::ClientsCreate | A::InfrastructureClientsCreate,
                IdentityResource::Client { client_id: None },
            ) => true,
            (
                A::ClientsRead
                | A::ClientsUpdate
                | A::ClientsDelete
                | A::InfrastructureClientsRead
                | A::InfrastructureClientsUpdate
                | A::InfrastructureClientsDelete,
                IdentityResource::Client {
                    client_id: Some(id),
                },
            ) => !id.is_empty(),
            (
                A::ApplicationsRead | A::ApplicationsCreate,
                IdentityResource::Application { id: None },
            ) => true,
            (
                A::ApplicationsRead | A::ApplicationsUpdate | A::ApplicationsDelete,
                IdentityResource::Application { id: Some(id) },
            ) => !id.is_nil(),
            (
                A::UsersRead | A::UsersUpdate | A::UsersDelete | A::UsersResetPassword,
                IdentityResource::User { id },
            ) => !id.is_nil(),
            (A::ConsentsRead, IdentityResource::Consent { user_id, id: None }) => !user_id.is_nil(),
            (
                A::ConsentsRevoke,
                IdentityResource::Consent {
                    user_id,
                    id: Some(id),
                },
            ) => !user_id.is_nil() && !id.is_nil(),
            (
                A::KeysRead | A::KeysRotate | A::KeysRevoke,
                IdentityResource::ClientKeys { client_id },
            ) => !client_id.is_empty(),
            (A::DevicePairingRead | A::DevicePairingUpdate, IdentityResource::DevicePairing) => {
                true
            }
            (A::ReplicaSignersEnroll, IdentityResource::ReplicaSigner { member_id: None }) => true,
            (
                A::ReplicaSignersRotate | A::ReplicaSignersRevoke,
                IdentityResource::ReplicaSigner {
                    member_id: Some(id),
                },
            ) => !id.is_nil(),
            _ => false,
        };
        if !valid {
            return None;
        }
        match self.target {
            PermissionTarget::Application { application_id, .. }
                if self.action.application_scoped() && !application_id.is_nil() =>
            {
                Some(application_id)
            }
            PermissionTarget::Installation { .. } if !self.action.application_scoped() => {
                Some(INSTALLATION_POLICY_ID)
            }
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionAuditIdentity {
    #[cfg_attr(feature = "utoipa", schema(value_type = String))]
    pub service_subject: Id,
    pub service_client_id: String,
    pub actor: PermissionSubject,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionEvaluationResponse {
    pub request: PermissionEvaluationRequest,
    pub audit: PermissionAuditIdentity,
    pub allowed: bool,
}

#[cfg(test)]
mod tests {
    use super::{
        IdentityAction, IdentityResource, PermissionEvaluationRequest, PermissionSubject,
        PermissionTarget,
    };
    use crate::model::Id;

    #[test]
    fn replica_signer_permissions_are_installation_scoped_and_exact() {
        let mut request = PermissionEvaluationRequest {
            request_id: Id::from_u128(1),
            subject: PermissionSubject::User {
                id: Id::from_u128(2),
            },
            action: IdentityAction::ReplicaSignersEnroll,
            target: PermissionTarget::Installation {
                resource: IdentityResource::ReplicaSigner { member_id: None },
            },
        };
        assert_eq!(request.policy_namespace(), Some(Id::nil()));
        assert_eq!(request.action.permission(), "idp.replica_signers.enroll");

        request.action = IdentityAction::ReplicaSignersRotate;
        request.target = PermissionTarget::Installation {
            resource: IdentityResource::ReplicaSigner {
                member_id: Some(Id::from_u128(3)),
            },
        };
        assert_eq!(request.policy_namespace(), Some(Id::nil()));
        request.action = IdentityAction::ReplicaSignersRevoke;
        assert_eq!(request.action.permission(), "idp.replica_signers.revoke");
        assert_eq!(request.policy_namespace(), Some(Id::nil()));

        request.target = PermissionTarget::Installation {
            resource: IdentityResource::ReplicaSigner { member_id: None },
        };
        assert!(request.policy_namespace().is_none());
        request.action = IdentityAction::ReplicaSignersEnroll;
        request.target = PermissionTarget::Installation {
            resource: IdentityResource::ReplicaSigner {
                member_id: Some(Id::from_u128(3)),
            },
        };
        assert!(request.policy_namespace().is_none());
        request.action = IdentityAction::ReplicaSignersRotate;
        request.target = PermissionTarget::Installation {
            resource: IdentityResource::ReplicaSigner {
                member_id: Some(Id::nil()),
            },
        };
        assert!(request.policy_namespace().is_none());

        request.target = PermissionTarget::Application {
            application_id: Id::from_u128(4),
            resource: IdentityResource::ReplicaSigner { member_id: None },
        };
        assert!(request.policy_namespace().is_none());
    }

    #[test]
    fn permission_scope_cannot_escalate() {
        let mut request = PermissionEvaluationRequest {
            request_id: Id::nil(),
            subject: PermissionSubject::User { id: Id::nil() },
            action: IdentityAction::ClientsCreate,
            target: PermissionTarget::Installation {
                resource: IdentityResource::Client { client_id: None },
            },
        };
        assert!(request.policy_namespace().is_none());
        request.target = PermissionTarget::Application {
            application_id: Id::nil(),
            resource: IdentityResource::Client { client_id: None },
        };
        assert!(request.policy_namespace().is_none());
        request.action = IdentityAction::UsersDelete;
        assert!(request.policy_namespace().is_none());
        request.target = PermissionTarget::Installation {
            resource: IdentityResource::User {
                id: Id::from_u128(1),
            },
        };
        assert_eq!(request.policy_namespace(), Some(Id::nil()));
        request.action = IdentityAction::DevicePairingUpdate;
        request.target = PermissionTarget::Installation {
            resource: IdentityResource::DevicePairing,
        };
        assert_eq!(request.policy_namespace(), Some(Id::nil()));
        request.target = PermissionTarget::Application {
            application_id: Id::from_u128(1),
            resource: IdentityResource::DevicePairing,
        };
        assert!(request.policy_namespace().is_none());
    }
}
