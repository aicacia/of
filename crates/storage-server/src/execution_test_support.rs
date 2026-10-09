use std::{path::PathBuf, sync::Arc};

use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use db::{Database, SqlTranslator};
use idp_model::{
    contract::{
        IdpSignerRecord, JwkPublic, JwkPublicParameters, JwsAlgorithm, KeyUse, ReplicaMembership,
    },
    model::Id,
};
use idp_service::{
    PasswordConfig,
    replica::{DbReplicaSignerRepo, DbUserRepo},
    repo::UserRepo,
};
use iroh::{
    Endpoint, EndpointId,
    address_lookup::MemoryLookup,
    endpoint::{Connection, presets},
};
use management_service::{
    DeviceRepo,
    replica::{DbDeviceRepo, DbSelectionPolicyRepo, SelectionPolicy},
};
use model::contract::SelectedResource;
use tokio::sync::Notify;

use crate::{DeviceReplicationPolicy, LocalReplicationAuthorizer};

pub(crate) struct TestDirectory(pub PathBuf);
impl TestDirectory {
    pub fn new() -> Self {
        let path = std::env::temp_dir().join(format!("of03-domain-{}", Id::now_v7()));
        std::fs::create_dir_all(&path).expect("isolated Node stores");
        Self(path)
    }
}
impl Drop for TestDirectory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).expect("remove isolated Node stores");
    }
}

pub(crate) struct IrohPair {
    pub endpoints: [Endpoint; 2],
    pub connections: [Connection; 2],
}
impl IrohPair {
    pub async fn new() -> Self {
        let lookup = MemoryLookup::new();
        let left = Endpoint::builder(presets::Minimal)
            .alpns(vec![iroh_chain::DATA_ALPN.to_vec()])
            .address_lookup(lookup.clone())
            .bind()
            .await
            .expect("left endpoint");
        let right = Endpoint::builder(presets::Minimal)
            .alpns(vec![iroh_chain::DATA_ALPN.to_vec()])
            .address_lookup(lookup.clone())
            .bind()
            .await
            .expect("right endpoint");
        lookup.add_endpoint_info(right.addr());
        let (outgoing, incoming) =
            tokio::join!(left.connect(right.id(), iroh_chain::DATA_ALPN), async {
                right
                    .accept()
                    .await
                    .expect("incoming")
                    .accept()
                    .expect("accept")
                    .await
            });
        let connections = [outgoing.expect("connect"), incoming.expect("authenticate")];
        assert_eq!(connections[0].remote_id(), right.id());
        assert_eq!(connections[1].remote_id(), left.id());
        Self {
            endpoints: [left, right],
            connections,
        }
    }
    pub fn ids(&self) -> [EndpointId; 2] {
        [self.endpoints[0].id(), self.endpoints[1].id()]
    }
    pub async fn streams(&self) -> [crate::DatabaseTransport; 2] {
        let (mut send, recv) = self.connections[0]
            .open_bi()
            .await
            .expect("fresh stream on existing connection");
        send.write_all(&[1]).await.expect("stream marker");
        let (incoming_send, mut incoming_recv) = self.connections[1]
            .accept_bi()
            .await
            .expect("accept stream");
        incoming_recv.read_exact(&mut [0]).await.expect("marker");
        [
            crate::DatabaseTransport::new(send, recv),
            crate::DatabaseTransport::new(incoming_send, incoming_recv),
        ]
    }
    pub async fn reconnect(&mut self) {
        self.connections[0].close(0u32.into(), b"reconnect");
        self.connections[1].close(0u32.into(), b"reconnect");
        let (outgoing, incoming) = tokio::join!(
            self.endpoints[0].connect(self.endpoints[1].id(), iroh_chain::DATA_ALPN),
            async {
                self.endpoints[1]
                    .accept()
                    .await
                    .expect("reconnecting peer")
                    .accept()
                    .expect("accept reconnect")
                    .await
            }
        );
        self.connections = [
            outgoing.expect("reconnect"),
            incoming.expect("authenticate reconnect"),
        ];
        assert_eq!(self.connections[0].remote_id(), self.endpoints[1].id());
        assert_eq!(self.connections[1].remote_id(), self.endpoints[0].id());
    }
    pub async fn close(&self) {
        self.connections[0].close(0u32.into(), b"test complete");
        self.connections[1].close(0u32.into(), b"test complete");
        self.endpoints[0].close().await;
        self.endpoints[1].close().await;
    }
}

#[derive(Clone, Default)]
pub(crate) struct Gate {
    reached: Arc<Notify>,
    resume: Arc<Notify>,
}
impl Gate {
    pub async fn pause(&self) {
        self.reached.notify_one();
        self.resume.notified().await;
    }
    pub async fn reached(&self) {
        self.reached.notified().await;
    }
    pub fn release(&self) {
        self.resume.notify_one();
    }
}

const INSTALLATION: &str = "https://of03-installation.example";

pub(crate) fn approved_signers(devices: [Id; 2]) -> [IdpSignerRecord; 2] {
    devices.map(|member_id| {
        let entropy = key::MasterKey::entropy().expect("independent signer entropy");
        let master =
            key::MasterKey::from_entropy(entropy.as_ref()).expect("independent private signer");
        let (x, y) = master
            .derive_from_index_and_hardened(0, false)
            .expect("signer derivation")
            .to_xy()
            .expect("public signer point");
        let key_id = Id::now_v7();
        IdpSignerRecord {
            member_id,
            key_id,
            issuer: INSTALLATION.into(),
            public_jwk: JwkPublic {
                kid: key_id.to_string(),
                r#use: KeyUse::Signature,
                alg: JwsAlgorithm::ES256K,
                params: JwkPublicParameters::Ec {
                    crv: "secp256k1".into(),
                    x: STANDARD_NO_PAD.encode(x),
                    y: STANDARD_NO_PAD.encode(y),
                },
            },
            approved_at: Some(1),
            revoked_at: None,
            expires_at: None,
        }
    })
}

pub(crate) struct DomainNode {
    pub idp: Arc<Database>,
    pub management: Arc<Database>,
    pub root: PathBuf,
    pub owner: Id,
    pub devices: [Id; 2],
}
impl DomainNode {
    pub async fn new(
        root: PathBuf,
        owner: Id,
        devices: [Id; 2],
        endpoints: [EndpointId; 2],
        signers: &[IdpSignerRecord; 2],
    ) -> Self {
        std::fs::create_dir_all(&root).expect("Node root");
        let idp = Arc::new(Database::open(root.join("idp.redb")).expect("IdP store"));
        let management =
            Arc::new(Database::open(root.join("management.redb")).expect("Management store"));
        idp_model::replica::up(&idp).await.expect("IdP schema");
        management_service::replica::up(&management)
            .await
            .expect("Management schema");
        sql(&idp, &format!("INSERT INTO users (id, handle, name, created_at, updated_at) VALUES (CAST('{owner}' AS UUID), 'owner', 'Owner', 1, 1)")).await;
        for ((device, endpoint), signer) in devices.into_iter().zip(endpoints).zip(signers) {
            sql(&idp, &format!("INSERT INTO devices (id, owner_subject, name, public_key, address, state, approved_at, created_at, updated_at) VALUES (CAST('{device}' AS UUID), '{owner}', 'node', '{endpoint}', 'local', 1, 1, 1, 1)")).await;
            DbReplicaSignerRepo::new(idp.clone())
                .enroll(
                    &ReplicaMembership {
                        installation_id: INSTALLATION.into(),
                        member_id: device,
                        endpoint_id: endpoint.to_string(),
                        issuer: INSTALLATION.into(),
                        approved_at: 1,
                        revoked_at: None,
                    },
                    signer,
                )
                .await
                .expect("owner-approved Installation/Device/signer binding");
        }
        Self {
            idp,
            management,
            root,
            owner,
            devices,
        }
    }
    pub async fn select(&self, resource: &SelectedResource) {
        for device_id in self.devices {
            DbSelectionPolicyRepo::new(self.management.clone())
                .set_prevalidated(SelectionPolicy {
                    device_id,
                    owner_subject: self.owner.to_string(),
                    application_id: Some(resource.application_id.parse().expect("application ID")),
                    selected_kind: Some(resource.kind.clone()),
                    selected_id: Some(resource.resource_id.parse().expect("resource ID")),
                    admin_allowed: true,
                })
                .await
                .expect("real stable selected-resource row");
        }
    }
    pub async fn restrict(&self, device: usize, allowed: bool) {
        assert!(
            DbSelectionPolicyRepo::new(self.management.clone())
                .set_admin_allowed_prevalidated(
                    self.devices[device],
                    &self.owner.to_string(),
                    allowed
                )
                .await
                .expect("persist current restriction")
        );
    }
    pub async fn revoke(&self, device: usize) {
        assert!(
            DbDeviceRepo::new(self.idp.clone())
                .revoke(&self.owner.to_string(), self.devices[device], "")
                .await
                .expect("learn Device revocation")
        );
    }
    pub async fn revoke_signer(&self, device: usize) {
        assert!(
            DbReplicaSignerRepo::new(self.idp.clone())
                .revoke(self.devices[device], INSTALLATION, 2)
                .await
                .expect("persist signer/member revocation")
        );
    }
    pub fn authorizer(&self) -> LocalReplicationAuthorizer {
        self.authorizer_retaining(Arc::new(()))
    }
    pub fn authorizer_retaining(
        &self,
        retained: Arc<dyn Send + Sync>,
    ) -> LocalReplicationAuthorizer {
        let idp = self.idp.clone();
        let management = self.management.clone();
        LocalReplicationAuthorizer::new(move |endpoint: EndpointId| {
            let idp = idp.clone();
            let management = management.clone();
            let retained = retained.clone();
            async move {
                let _retained = retained;
                let device = DbDeviceRepo::new(idp.clone())
                    .find_approved_by_public_key(&endpoint.to_string())
                    .await
                    .map_err(|error| error.to_string())?
                    .ok_or("unknown or unapproved Device")?;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|_| "invalid clock")?
                    .as_secs()
                    .try_into()
                    .map_err(|_| "clock overflow")?;
                if !DbReplicaSignerRepo::new(idp.clone())
                    .is_trusted_peer(INSTALLATION, device.id, &endpoint.to_string(), now)
                    .await
                    .map_err(|error| error.to_string())?
                {
                    return Err("missing current signer-backed Installation membership".into());
                }
                let owner_id = device.owner_subject.parse().map_err(|_| "invalid owner")?;
                let owner_active = DbUserRepo::new(idp, PasswordConfig::default())
                    .find_user_by_id(owner_id)
                    .await
                    .map_err(|error| error.to_string())?
                    .is_some();
                let policies = DbSelectionPolicyRepo::new(management);
                let policy = policies
                    .get(device.id, &device.owner_subject, Id::nil())
                    .await
                    .map_err(|error| error.to_string())?
                    .ok_or("missing local policy")?;
                let resources = policies
                    .selected_resources_for_device(device.id)
                    .await
                    .map_err(|error| error.to_string())?
                    .into_iter()
                    .map(|resource| SelectedResource {
                        owner_subject: resource.owner_subject,
                        application_id: resource.application_id.to_string(),
                        kind: resource.kind,
                        resource_id: resource.resource_id.to_string(),
                    })
                    .collect();
                Ok(DeviceReplicationPolicy {
                    device_id: device.id,
                    endpoint_id: endpoint,
                    owner_subject: device.owner_subject,
                    state: device.state,
                    owner_active,
                    admin_allowed: policy.admin_allowed,
                    resources,
                })
            }
        })
    }
}

pub(crate) async fn sql(database: &Database, sql: &str) {
    database
        .client()
        .translate_and_execute(sql, &SqlTranslator)
        .await
        .expect("public SQL fixture");
}
