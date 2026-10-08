use std::{future::Future, pin::Pin, sync::Arc};

use idp_model::{contract::DeviceState, model::Id};
use iroh::EndpointId;
use model::contract::SelectedResource;

/// Current evidence supplied by the local IdP and Management services, not by a peer.
#[derive(Clone, Debug)]
pub struct DeviceReplicationPolicy {
    pub device_id: Id,
    pub endpoint_id: EndpointId,
    pub owner_subject: String,
    pub state: DeviceState,
    pub owner_active: bool,
    pub admin_allowed: bool,
    pub resources: Vec<SelectedResource>,
}

type ResolvePolicy = Arc<
    dyn Fn(
            EndpointId,
        ) -> Pin<Box<dyn Future<Output = Result<DeviceReplicationPolicy, String>> + Send>>
        + Send
        + Sync,
>;

#[derive(Clone)]
pub struct LocalReplicationAuthorizer {
    resolve: ResolvePolicy,
}

impl LocalReplicationAuthorizer {
    /// The callback must evaluate current, conflict-clear owner-service state on each call.
    pub fn new<F, U>(resolve: F) -> Self
    where
        F: Fn(EndpointId) -> U + Send + Sync + 'static,
        U: Future<Output = Result<DeviceReplicationPolicy, String>> + Send + 'static,
    {
        Self {
            resolve: Arc::new(move |endpoint| Box::pin(resolve(endpoint))),
        }
    }

    pub async fn selected_resources(
        &self,
        endpoint: EndpointId,
    ) -> Result<Vec<SelectedResource>, String> {
        let policy = self.policy(endpoint).await?;
        Ok(policy
            .resources
            .into_iter()
            .filter(|resource| {
                valid_resource(resource) && resource.owner_subject == policy.owner_subject
            })
            .collect())
    }

    pub async fn authorize(
        &self,
        local: EndpointId,
        remote: EndpointId,
        resource: &SelectedResource,
    ) -> bool {
        if local == remote || !valid_resource(resource) {
            return false;
        }
        let Ok(local_policy) = self.policy(local).await else {
            return false;
        };
        let Ok(remote_policy) = self.policy(remote).await else {
            return false;
        };
        local_policy.device_id != remote_policy.device_id
            && [&local_policy, &remote_policy].into_iter().all(|policy| {
                policy.owner_subject == resource.owner_subject
                    && policy.resources.iter().any(|selected| {
                        selected.owner_subject == resource.owner_subject
                            && selected.application_id == resource.application_id
                            && selected.kind == resource.kind
                            && selected.resource_id == resource.resource_id
                    })
            })
    }

    async fn policy(&self, endpoint: EndpointId) -> Result<DeviceReplicationPolicy, String> {
        let policy = (self.resolve)(endpoint).await?;
        if policy.endpoint_id != endpoint
            || policy.device_id.is_nil()
            || policy.state != DeviceState::Approved
            || !policy.owner_active
            || !policy.admin_allowed
            || !policy
                .owner_subject
                .parse::<Id>()
                .is_ok_and(|owner| !owner.is_nil())
        {
            return Err("local Device/owner policy denied".into());
        }
        Ok(policy)
    }
}

fn valid_resource(resource: &SelectedResource) -> bool {
    matches!(resource.kind.as_str(), "database" | "filesystem")
        && [
            &resource.owner_subject,
            &resource.application_id,
            &resource.resource_id,
        ]
        .into_iter()
        .all(|id| id.parse::<Id>().is_ok_and(|id| !id.is_nil()))
}

#[cfg(test)]
#[path = "local_replication_authorizer_tests.rs"]
mod native_tests;

#[cfg(test)]
mod tests {
    use super::{DeviceReplicationPolicy, LocalReplicationAuthorizer};
    use idp_model::{contract::DeviceState, model::Id};
    use model::contract::SelectedResource;

    #[tokio::test]
    async fn learned_denial_and_failed_local_evaluation_are_checked_on_either_peer() {
        let local = iroh::SecretKey::generate().public();
        let remote = iroh::SecretKey::generate().public();
        let owner = Id::now_v7().to_string();
        for kind in ["database", "filesystem"] {
            let resource = SelectedResource {
                owner_subject: owner.clone(),
                application_id: Id::now_v7().to_string(),
                kind: kind.into(),
                resource_id: Id::now_v7().to_string(),
            };
            let policies = std::sync::Arc::new(std::sync::Mutex::new([
                DeviceReplicationPolicy {
                    device_id: Id::now_v7(),
                    endpoint_id: local,
                    owner_subject: owner.clone(),
                    state: DeviceState::Approved,
                    owner_active: true,
                    admin_allowed: true,
                    resources: vec![resource.clone()],
                },
                DeviceReplicationPolicy {
                    device_id: Id::now_v7(),
                    endpoint_id: remote,
                    owner_subject: owner.clone(),
                    state: DeviceState::Approved,
                    owner_active: true,
                    admin_allowed: true,
                    resources: vec![resource.clone()],
                },
            ]));
            let source = policies.clone();
            let authorizer = LocalReplicationAuthorizer::new(move |endpoint| {
                let policy =
                    source.lock().expect("policy lock")[usize::from(endpoint == remote)].clone();
                async move { Ok(policy) }
            });
            let baseline = policies.lock().expect("policy lock").clone();
            assert_eq!(
                authorizer
                    .selected_resources(local)
                    .await
                    .expect("selected resources")
                    .len(),
                1
            );
            for peer in 0..2 {
                for mutation in 0..6 {
                    *policies.lock().expect("policy lock") = baseline.clone();
                    assert!(authorizer.authorize(local, remote, &resource).await);
                    {
                        let mut current = policies.lock().expect("policy lock");
                        let policy = &mut current[peer];
                        match mutation {
                            0 => policy.state = DeviceState::Revoked,
                            1 => policy.resources.clear(),
                            2 => policy.admin_allowed = false,
                            3 => policy.owner_subject = Id::now_v7().to_string(),
                            4 => policy.endpoint_id = iroh::SecretKey::generate().public(),
                            _ => policy.owner_active = false,
                        }
                    }
                    assert!(
                        !authorizer.authorize(local, remote, &resource).await,
                        "{kind}: peer {peer}, denial {mutation}"
                    );
                }
            }
            let failed = LocalReplicationAuthorizer::new(|_| async {
                Err("local owner-service failure".into())
            });
            assert!(!failed.authorize(local, remote, &resource).await);
            assert!(failed.selected_resources(local).await.is_err());
        }
    }

    #[tokio::test]
    async fn current_policy_requires_both_exact_selected_owners_and_restrictions() {
        let local = iroh::SecretKey::generate().public();
        let remote = iroh::SecretKey::generate().public();
        let resource = SelectedResource {
            owner_subject: Id::now_v7().to_string(),
            application_id: Id::now_v7().to_string(),
            kind: "database".into(),
            resource_id: Id::now_v7().to_string(),
        };
        let selected = resource.clone();
        let authorizer = LocalReplicationAuthorizer::new(move |endpoint| {
            let resource = selected.clone();
            async move {
                Ok(DeviceReplicationPolicy {
                    device_id: if endpoint == local {
                        Id::from_u128(0x01900000000070008000000000000001)
                    } else {
                        Id::from_u128(0x01900000000070008000000000000002)
                    },
                    endpoint_id: endpoint,
                    owner_subject: resource.owner_subject.clone(),
                    state: DeviceState::Approved,
                    owner_active: true,
                    admin_allowed: true,
                    resources: vec![resource],
                })
            }
        });
        assert!(authorizer.authorize(local, remote, &resource).await);
        let mut forged = resource.clone();
        forged.owner_subject = Id::now_v7().to_string();
        assert!(!authorizer.authorize(local, remote, &forged).await);
        forged = resource.clone();
        forged.application_id = Id::now_v7().to_string();
        assert!(!authorizer.authorize(local, remote, &forged).await);
        forged = resource.clone();
        forged.kind = "filesystem".into();
        assert!(!authorizer.authorize(local, remote, &forged).await);
        forged = resource.clone();
        forged.resource_id = Id::now_v7().to_string();
        assert!(!authorizer.authorize(local, remote, &forged).await);
        assert!(!authorizer.authorize(local, local, &resource).await);
    }
}
