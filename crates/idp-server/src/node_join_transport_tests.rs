use std::{fs, path::PathBuf, time::Duration};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use idp_model::model::Id;
use idp_service::{
    oauth2::NodeSignerBinding,
    repo::{PrivateKeyKeyringRepo, PrivateKeyRepo, RawKeyringRepo},
};
use iroh::{Endpoint, SecretKey, endpoint::presets::Minimal};
use iroh_chain::{DATA_ALPN, EndpointIdStore, MESH_ALPN, PAIRING_ALPN, Server};

use crate::{AppConfig, BOOTSTRAP_ALPN, NodeJoinApproval, NodeJoinRequest, OwnerProvisioner};

use super::bind_node_join_endpoint;

struct Fixture {
    root: PathBuf,
    config: AppConfig,
    owner: OwnerProvisioner,
    binding: NodeSignerBinding,
    request: NodeJoinRequest,
    joining: Server,
    peer: Server,
    peer_secret: SecretKey,
}

impl Fixture {
    async fn new() -> Self {
        let root = std::env::temp_dir().join(format!("node-join-transport-{}", Id::now_v7()));
        let mut config = AppConfig {
            data_dir: root.to_string_lossy().into_owned(),
            ..Default::default()
        };
        config.oauth2.issuer = format!("https://join-transport-{}.test/idp", Id::now_v7());
        let owner = OwnerProvisioner::open(&config)
            .await
            .expect("OS keyring owner");
        owner
            .prepare_fresh_setup_secret_inventory(Id::now_v7(), &[])
            .await
            .expect("fresh local preparation");
        owner
            .prepare_setup_client_slots(&[])
            .await
            .expect("ready inventory");
        let secret = SecretKey::generate();
        let binding = NodeSignerBinding {
            member_id: Id::now_v7(),
            key_id: Id::now_v7(),
            endpoint_id: secret.public().to_string(),
        };
        let peer_secret = SecretKey::generate();
        let request = owner
            .prepare_node_join(&binding, "Joining Node", peer_secret.public())
            .expect("persist prepared request and independent signer");
        let allowed = EndpointIdStore::default();
        allowed.add(secret.public());
        let joining = bind_node_join_endpoint(&config, Minimal, secret, allowed)
            .await
            .expect("real domain joining endpoint");
        let peer_allowed = EndpointIdStore::default();
        peer_allowed.add(joining.endpoint().id());
        let peer = Server::bind_with_secret_key(Minimal, peer_secret.clone(), peer_allowed)
            .await
            .expect("hooked approving peer");
        Self {
            root,
            config,
            owner,
            binding,
            request,
            joining,
            peer,
            peer_secret,
        }
    }

    fn approval(&self) -> NodeJoinApproval {
        let owner_subject = Id::now_v7();
        NodeJoinApproval {
            request: self.request.clone(),
            owner_subject,
            signature: URL_SAFE_NO_PAD.encode(
                self.peer_secret
                    .sign(
                        &NodeJoinApproval::payload(&self.request, owner_subject)
                            .expect("approval payload"),
                    )
                    .to_bytes(),
            ),
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        PrivateKeyKeyringRepo::new(&self.config.oauth2.issuer)
            .expect("OS keyring")
            .delete(
                &format!(
                    "{}:node:{}:{}",
                    self.config.key_namespace, self.binding.member_id, self.binding.key_id
                ),
                &key::DerivationPath::default(),
            )
            .expect("remove fixture private signer");
        fs::remove_dir_all(&self.root).expect("remove isolated public owner state");
    }
}

async fn handshake_admitted(client: &Endpoint, server: &Endpoint, alpn: &[u8]) -> bool {
    tokio::time::timeout(Duration::from_secs(15), async {
        let (outgoing, incoming) = tokio::join!(client.connect(server.addr(), alpn), async {
            server.accept().await.expect("incoming connection").await
        },);
        let Ok(incoming) = incoming else {
            return false;
        };
        let outgoing = outgoing.expect("outgoing handshake");
        let mut send = outgoing.open_uni().await.expect("authenticated stream");
        send.write_all(b"admitted").await.expect("write probe");
        send.finish().expect("finish probe");
        let mut recv = incoming.accept_uni().await.expect("admitted stream");
        assert_eq!(recv.read_to_end(8).await.expect("read probe"), b"admitted");
        outgoing.close(0u32.into(), b"probe complete");
        true
    })
    .await
    .expect("bounded hook handshake")
}

fn join_alpns(endpoint: &Endpoint) {
    endpoint.set_alpns(vec![
        PAIRING_ALPN.to_vec(),
        BOOTSTRAP_ALPN.to_vec(),
        DATA_ALPN.to_vec(),
        MESH_ALPN.to_vec(),
        b"other/1".to_vec(),
    ]);
}

#[tokio::test]
#[ignore = "requires an unlocked OS keyring; run explicitly in isolation"]
async fn prepared_join_can_send_pairing_without_global_pairing_or_peer_trust() {
    let fixture = Fixture::new().await;
    assert!(!fixture.joining.pairing_enabled());
    assert!(
        !fixture
            .joining
            .is_allowed(fixture.peer.endpoint().id())
            .await
    );
    fixture.peer.set_pairing_enabled(true);
    let mut offers = fixture.peer.subscribe_pairing_offers();
    let router = fixture.peer.router(crate::BootstrapProtocolHandler);
    let approval = fixture.approval();
    let expected = fixture.request.clone();
    let response = tokio::spawn(async move {
        let offer = offers.recv().await.expect("real pairing offer");
        assert_eq!(
            serde_json::from_slice::<NodeJoinRequest>(&offer.payload).expect("request"),
            expected
        );
        offer
            .reply(&serde_json::to_vec(&approval).expect("public approval"))
            .await
            .expect("reply");
        offer
    });
    let received = tokio::time::timeout(
        Duration::from_secs(15),
        fixture
            .request
            .send(&fixture.joining, fixture.peer.endpoint().addr()),
    )
    .await
    .expect("bounded real pairing")
    .expect("prepared join pairing must be admitted before approval");
    let _offer = response.await.expect("offer exchange");
    received
        .verify(&fixture.request)
        .expect("verified matching approval");
    assert!(
        fixture
            .owner
            .node_join_approval()
            .expect("approval state")
            .is_none()
    );
    for alpn in [BOOTSTRAP_ALPN, DATA_ALPN, MESH_ALPN, b"other/1"] {
        assert!(
            fixture
                .joining
                .endpoint()
                .connect(fixture.peer.endpoint().addr(), alpn)
                .await
                .is_err(),
            "preapproval must not admit {alpn:?}"
        );
    }
    let other = Server::bind(Minimal, EndpointIdStore::default())
        .await
        .expect("hooked other peer");
    assert!(
        fixture
            .joining
            .endpoint()
            .connect(other.endpoint().addr(), PAIRING_ALPN)
            .await
            .is_err()
    );
    assert!(!fixture.joining.pairing_enabled());
    assert!(
        !fixture
            .joining
            .is_allowed(fixture.peer.endpoint().id())
            .await
    );
    other.endpoint().close().await;
    fixture.joining.endpoint().close().await;
    router.shutdown().await.expect("stop approving peer");
}

#[tokio::test]
#[ignore = "requires an unlocked OS keyring; run explicitly in isolation"]
async fn incoming_join_admission_is_pinned_and_bootstrap_requires_matching_verified_approval() {
    let fixture = Fixture::new().await;
    join_alpns(fixture.joining.endpoint());
    join_alpns(fixture.peer.endpoint());
    assert!(
        handshake_admitted(
            fixture.peer.endpoint(),
            fixture.joining.endpoint(),
            PAIRING_ALPN
        )
        .await
    );
    for alpn in [BOOTSTRAP_ALPN, DATA_ALPN, MESH_ALPN, b"other/1"] {
        assert!(
            !handshake_admitted(fixture.peer.endpoint(), fixture.joining.endpoint(), alpn).await,
            "incoming preapproval must not admit {alpn:?}"
        );
    }
    let allowed = EndpointIdStore::default();
    allowed.add(fixture.joining.endpoint().id());
    let other = Server::bind(Minimal, allowed)
        .await
        .expect("hooked unpinned peer");
    assert!(!handshake_admitted(other.endpoint(), fixture.joining.endpoint(), PAIRING_ALPN).await);
    let approval_path = fixture.root.join("node-join-approval.json");
    let approval = fixture.approval();
    let mut forged = approval.clone();
    forged.signature = URL_SAFE_NO_PAD.encode(
        SecretKey::generate()
            .sign(
                &NodeJoinApproval::payload(&fixture.request, forged.owner_subject)
                    .expect("payload"),
            )
            .to_bytes(),
    );
    let mut mismatch = approval.clone();
    mismatch.request.name = "Another Node".into();
    mismatch.signature = URL_SAFE_NO_PAD.encode(
        fixture
            .peer_secret
            .sign(
                &NodeJoinApproval::payload(&mismatch.request, mismatch.owner_subject)
                    .expect("payload"),
            )
            .to_bytes(),
    );
    for invalid in [
        b"malformed".to_vec(),
        serde_json::to_vec(&forged).expect("forged approval"),
        serde_json::to_vec(&mismatch).expect("mismatched approval"),
    ] {
        fs::write(&approval_path, invalid).expect("inject invalid public approval");
        assert!(
            fixture
                .joining
                .endpoint()
                .connect(fixture.peer.endpoint().addr(), BOOTSTRAP_ALPN)
                .await
                .is_err()
        );
        assert!(
            !handshake_admitted(
                fixture.peer.endpoint(),
                fixture.joining.endpoint(),
                BOOTSTRAP_ALPN
            )
            .await
        );
    }
    fs::remove_file(&approval_path).expect("remove invalid approval");
    fixture
        .owner
        .record_node_join_approval(&approval)
        .expect("persist verified exact approval");
    assert!(
        handshake_admitted(
            fixture.joining.endpoint(),
            fixture.peer.endpoint(),
            BOOTSTRAP_ALPN
        )
        .await
    );
    assert!(
        handshake_admitted(
            fixture.peer.endpoint(),
            fixture.joining.endpoint(),
            BOOTSTRAP_ALPN
        )
        .await
    );
    assert!(
        !handshake_admitted(other.endpoint(), fixture.joining.endpoint(), BOOTSTRAP_ALPN).await
    );
    for alpn in [DATA_ALPN, MESH_ALPN, b"other/1"] {
        assert!(
            fixture
                .joining
                .endpoint()
                .connect(fixture.peer.endpoint().addr(), alpn)
                .await
                .is_err()
        );
        assert!(
            !handshake_admitted(fixture.peer.endpoint(), fixture.joining.endpoint(), alpn).await
        );
    }
    assert!(!fixture.joining.pairing_enabled());
    assert!(
        !fixture
            .joining
            .is_allowed(fixture.peer.endpoint().id())
            .await
    );
    other.endpoint().close().await;
    fixture.joining.endpoint().close().await;
    fixture.peer.endpoint().close().await;
}

async fn assert_join_denied(fixture: &Fixture, evidence: &str) {
    for alpn in [PAIRING_ALPN, BOOTSTRAP_ALPN] {
        assert!(
            fixture
                .joining
                .endpoint()
                .connect(fixture.peer.endpoint().addr(), alpn)
                .await
                .is_err(),
            "outgoing {alpn:?} admitted with {evidence}"
        );
        assert!(
            !handshake_admitted(fixture.peer.endpoint(), fixture.joining.endpoint(), alpn).await,
            "incoming {alpn:?} admitted with {evidence}"
        );
    }
}

#[tokio::test]
#[ignore = "requires an unlocked OS keyring; run explicitly in isolation"]
async fn join_admission_fails_closed_without_exact_valid_local_request_and_private_signer() {
    let fixture = Fixture::new().await;
    join_alpns(fixture.joining.endpoint());
    join_alpns(fixture.peer.endpoint());
    fixture
        .owner
        .record_node_join_approval(&fixture.approval())
        .expect("verified approval baseline");
    assert!(
        handshake_admitted(
            fixture.peer.endpoint(),
            fixture.joining.endpoint(),
            PAIRING_ALPN
        )
        .await
    );
    assert!(
        handshake_admitted(
            fixture.peer.endpoint(),
            fixture.joining.endpoint(),
            BOOTSTRAP_ALPN
        )
        .await
    );
    let path = fixture.root.join("node-join-request.json");
    let original = serde_json::to_vec(&fixture.request).expect("public request");
    fs::remove_file(&path).expect("remove request evidence");
    assert_join_denied(&fixture, "missing request").await;
    fs::write(&path, b"malformed").expect("corrupt public request");
    assert_join_denied(&fixture, "malformed request JSON").await;
    for (field, value) in [
        ("purpose", serde_json::json!("other-purpose")),
        ("name", serde_json::json!(" ")),
        ("name", serde_json::json!("x".repeat(257))),
        ("member_id", serde_json::json!(Id::nil())),
        (
            "installation",
            serde_json::json!("https://wrong-issuer.test/idp"),
        ),
        (
            "endpoint_id",
            serde_json::json!(SecretKey::generate().public().to_string()),
        ),
        ("endpoint_id", serde_json::json!("malformed-endpoint")),
        (
            "approving_peer",
            serde_json::json!(fixture.joining.endpoint().id().to_string()),
        ),
        ("approving_peer", serde_json::json!("malformed-peer")),
        (
            "approving_peer",
            serde_json::json!(fixture.peer.endpoint().id().to_string().to_uppercase()),
        ),
    ] {
        let mut invalid = serde_json::to_value(&fixture.request).expect("request");
        invalid[field] = value;
        fs::write(
            &path,
            serde_json::to_vec(&invalid).expect("invalid request"),
        )
        .expect("inject invalid binding");
        assert_join_denied(&fixture, field).await;
    }
    for (field, value) in [
        ("kid", serde_json::json!(Id::nil())),
        ("kid", serde_json::json!(Id::now_v7())),
        ("x", serde_json::json!("malformed-public-point")),
        ("crv", serde_json::json!("P-256")),
        ("use", serde_json::json!("enc")),
        ("alg", serde_json::json!("ES256")),
    ] {
        let mut invalid = serde_json::to_value(&fixture.request).expect("request");
        invalid["public_signer"][field] = value;
        fs::write(&path, serde_json::to_vec(&invalid).expect("invalid signer"))
            .expect("inject invalid public signer");
        assert_join_denied(&fixture, field).await;
    }
    fs::write(&path, &original).expect("restore exact public request");
    let keys = PrivateKeyKeyringRepo::new(&fixture.config.oauth2.issuer).expect("OS keyring");
    let namespace = format!(
        "{}:node:{}:{}",
        fixture.config.key_namespace, fixture.binding.member_id, fixture.binding.key_id
    );
    let derivation = key::DerivationPath::default();
    let retained = keys
        .load(&namespace, &derivation)
        .expect("load retained key")
        .expect("existing independent signer");
    keys.delete(&namespace, &derivation)
        .expect("inject missing private signer");
    assert_join_denied(&fixture, "missing private signer").await;
    let replacement: key::DerivedKey =
        key::MasterKey::from_entropy(key::MasterKey::entropy().expect("entropy"))
            .expect("different private signer")
            .into();
    keys.store(&namespace, &replacement)
        .expect("inject conflicting key in OS keyring only");
    assert_join_denied(&fixture, "conflicting private signer").await;
    RawKeyringRepo::new(&fixture.config.oauth2.issuer)
        .expect("OS keyring")
        .store(
            "",
            "",
            &format!("{namespace}:{derivation}"),
            b"malformed-private-key",
        )
        .expect("inject malformed keyring evidence");
    assert_join_denied(&fixture, "malformed private signer").await;
    keys.store(&namespace, &retained)
        .expect("restore private signer in OS keyring only");
    assert!(
        handshake_admitted(
            fixture.peer.endpoint(),
            fixture.joining.endpoint(),
            PAIRING_ALPN
        )
        .await
    );
    assert!(
        handshake_admitted(
            fixture.peer.endpoint(),
            fixture.joining.endpoint(),
            BOOTSTRAP_ALPN
        )
        .await
    );
    assert!(!fixture.joining.pairing_enabled());
    assert!(
        !fixture
            .joining
            .is_allowed(fixture.peer.endpoint().id())
            .await
    );
    fixture.joining.endpoint().close().await;
    fixture.peer.endpoint().close().await;
}
