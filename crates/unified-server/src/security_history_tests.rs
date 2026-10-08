use std::{
    io,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use db::{Database, Row, Value};
use idp_model::{contract::IdentityAction, model::Id};
use idp_service::{oauth2::NodeSignerBinding, security_sync::public_security_tables};
use iroh::{
    Endpoint,
    address_lookup::MemoryLookup,
    endpoint::{Connection, presets},
    protocol::Router,
};
use iroh_chain::{DATA_ALPN, EndpointIdStore, Server};
use management_service::{
    ManagementService,
    replica::{DbPermissionRepo, DbRoleRepo},
};
use ofdb_sql::{SessionConfig, SyncMessage, SyncRole, SyncTransport};
use storage_server::{
    DatabaseTransport, IdpClient, ManagementClient, RouterState, StorageRuntime, build_runtime,
};
use tokio_util::sync::CancellationToken;

use crate::{
    SecurityContext, SecurityProtocol,
    security_sync_tests::{enroll, sql},
};

const INSTALLATION: &str = "https://installation.example";

fn public_jwk(kid: &str) -> String {
    serde_json::json!({"kid": kid, "use": "sig", "alg": "ES256K", "kty": "Ec", "crv": "secp256k1",
        "x": "eb5mfvncu6xVoGKVzocLBwKb/NstzijZWfKBWxb4F5g", "y": "SDradyajxGVdpPv8DhEIqP0XtEimhVQZnEfQj/sQ1Lg"}).to_string()
}

#[derive(Clone, Copy, Debug)]
enum Poison {
    Current,
    Overwritten,
    Deleted,
    LosingConflict,
}

struct RecordedTransport {
    inner: DatabaseTransport,
    received: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl SyncTransport for RecordedTransport {
    type Error = io::Error;
    async fn send(&mut self, frame: Vec<u8>) -> io::Result<()> {
        self.inner.send(frame).await
    }
    async fn receive(&mut self) -> io::Result<Vec<u8>> {
        let frame = self.inner.receive().await?;
        self.received
            .lock()
            .expect("wire recorder lock")
            .push(frame.clone());
        Ok(frame)
    }
}

struct Pair {
    root: PathBuf,
    a: Server,
    b: Server,
    member_a: Id,
    member_b: Id,
    row: Id,
    idp_a: Arc<Database>,
    idp_b: Arc<Database>,
    protocol_a: SecurityProtocol,
    protocol_b: SecurityProtocol,
    storage: StorageRuntime,
    cancellation: CancellationToken,
    router: Option<Router>,
    received: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl Pair {
    async fn new() -> Self {
        let root = std::env::temp_dir().join(format!("of-history-value-{}", Id::now_v7()));
        std::fs::create_dir_all(&root).expect("create native history fixture");
        let lookup = MemoryLookup::new();
        let a = Endpoint::builder(presets::Minimal)
            .alpns(vec![DATA_ALPN.to_vec()])
            .address_lookup(lookup.clone())
            .bind()
            .await
            .expect("bind A");
        let b = Endpoint::builder(presets::Minimal)
            .alpns(vec![DATA_ALPN.to_vec()])
            .address_lookup(lookup.clone())
            .bind()
            .await
            .expect("bind B");
        lookup.add_endpoint_info(a.addr());
        lookup.add_endpoint_info(b.addr());
        let peers_a = EndpointIdStore::default();
        peers_a.add(b.id());
        let peers_b = EndpointIdStore::default();
        peers_b.add(a.id());
        let a = Server::new(a, peers_a);
        let b = Server::new(b, peers_b);
        let actor = Id::now_v7();
        let member_a = Id::now_v7();
        let member_b = Id::now_v7();
        let key_a = Id::now_v7();
        let key_b = Id::now_v7();
        let row = Id::now_v7();
        {
            let idp = Arc::new(
                Database::open(root.join("baseline-idp.redb")).expect("open public baseline"),
            );
            idp_model::replica::up(&idp)
                .await
                .expect("declare secret-free schema");
            sql(&idp, &format!("INSERT INTO users (id, handle, name, created_at, updated_at) VALUES (CAST('{actor}' AS UUID), 'owner', 'Owner', 1, 1)")).await;
            for (member, key, endpoint) in [
                (member_a, key_a, a.endpoint().id()),
                (member_b, key_b, b.endpoint().id()),
            ] {
                sql(&idp, &format!("INSERT INTO devices (id, owner_subject, name, public_key, address, state, approved_at, created_at, updated_at) VALUES (CAST('{member}' AS UUID), '{actor}', 'node', '{endpoint}', 'local', 1, 1, 1, 1)")).await;
                enroll(idp.clone(), member, endpoint, key).await;
            }
            sql(&idp, &format!("INSERT INTO keys (id, derivation_index, public_jwk) VALUES (CAST('{row}' AS UUID), 0, '{}')", public_jwk("baseline"))).await;
            let management = Arc::new(
                Database::open(root.join("baseline-management.redb")).expect("open local policy"),
            );
            management_service::replica::up(&management)
                .await
                .expect("declare Management schema");
            ManagementService::new(
                DbPermissionRepo::new(management.clone()),
                DbRoleRepo::new(management.clone()),
            )
            .provision_initial_administrator(
                actor,
                Id::now_v7(),
                &[
                    (Id::now_v7(), IdentityAction::DevicePairingRead),
                    (Id::now_v7(), IdentityAction::DevicePairingUpdate),
                    (Id::now_v7(), IdentityAction::IdpSecuritySync),
                ],
            )
            .await
            .expect("explicit current local sync grant");
        }
        for node in ["a", "b", "fork"] {
            std::fs::copy(
                root.join("baseline-idp.redb"),
                root.join(format!("{node}-idp.redb")),
            )
            .expect("copy secret-free provisioned baseline");
            std::fs::copy(
                root.join("baseline-management.redb"),
                root.join(format!("{node}-management.redb")),
            )
            .expect("copy explicit policy baseline");
        }
        let idp_a = Arc::new(Database::open(root.join("a-idp.redb")).expect("A native IdP"));
        let idp_b = Arc::new(Database::open(root.join("b-idp.redb")).expect("B native IdP"));
        let management_a =
            Arc::new(Database::open(root.join("a-management.redb")).expect("A native Management"));
        let management_b =
            Arc::new(Database::open(root.join("b-management.redb")).expect("B native Management"));
        let cancellation = CancellationToken::new();
        let protocol_a = SecurityProtocol::new(
            a.clone(),
            idp_a.clone(),
            management_a,
            INSTALLATION.into(),
            Some(NodeSignerBinding {
                member_id: member_a,
                key_id: key_a,
                endpoint_id: a.endpoint().id().to_string(),
            }),
            root.join("a-stage"),
            cancellation.clone(),
        );
        let protocol_b = SecurityProtocol::new(
            b.clone(),
            idp_b.clone(),
            management_b,
            INSTALLATION.into(),
            Some(NodeSignerBinding {
                member_id: member_b,
                key_id: key_b,
                endpoint_id: b.endpoint().id().to_string(),
            }),
            root.join("b-stage"),
            cancellation.clone(),
        );
        let storage = build_runtime(
            RouterState::new("http://localhost/storage")
                .with_idp_client(
                    IdpClient::new(
                        "http://127.0.0.1:1/idp",
                        "storage",
                        "local",
                        INSTALLATION,
                        "idp",
                    )
                    .expect("IdP client"),
                )
                .with_management_client(
                    ManagementClient::new(
                        "http://127.0.0.1:1/management",
                        "http://127.0.0.1:1/idp",
                        "storage",
                        "local",
                        INSTALLATION,
                        "management",
                    )
                    .expect("Management client"),
                ),
            &root.join("storage"),
            "/storage",
            "",
            Some(b.clone()),
            cancellation.clone(),
        )
        .expect("existing shared DATA dispatcher");
        Self {
            root,
            a,
            b,
            member_a,
            member_b,
            row,
            idp_a,
            idp_b,
            protocol_a,
            protocol_b,
            storage,
            cancellation,
            router: None,
            received: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn serve(&mut self, validated: bool) {
        let handler = self.storage.data_handler().expect("shared DATA handler");
        let handler = if validated {
            self.protocol_b.attach(handler)
        } else {
            let database = self.idp_b.clone();
            let member = self.member_b;
            let received = self.received.clone();
            let expected_endpoint = self.a.endpoint().id();
            let expected_member = self.member_a;
            handler.with_additional_stream(move |kind, connection, send, recv| {
                let database = database.clone();
                let received = received.clone();
                async move {
                    assert_eq!(kind, 3, "actual security marker on shared DATA router");
                    assert_eq!(connection.remote_id(), expected_endpoint, "real authenticated endpoint");
                    let mut inner = DatabaseTransport::new(send, recv);
                    let handshake: serde_json::Value = serde_json::from_slice(&inner.receive().await?).map_err(io::Error::other)?;
                    assert_eq!(handshake["member"], serde_json::json!(expected_member));
                    inner.send(serde_json::to_vec(&serde_json::json!({"Accepted": {"version": 1, "installation": INSTALLATION, "member": member, "context": "idp"}})).map_err(io::Error::other)?).await?;
                    let mut transport = RecordedTransport { inner, received };
                    let tables = public_security_tables().into_iter().map(|table| table.name()).collect::<Vec<_>>();
                    // A deliberately unvalidated peer proves that the production sender prevents disclosure itself.
                    database.synchronize_tables_checked(&mut transport, &SessionConfig::default(), SyncRole::Responder, &tables, || async { Ok(()) }).await.map(|_| ()).map_err(|error| io::Error::other(error.to_string()))
                }
            })
        };
        self.router = Some(
            Router::builder(self.b.endpoint().clone())
                .accept(DATA_ALPN, handler)
                .spawn(),
        );
    }

    async fn connect(&self) -> Connection {
        self.a
            .connect_direct_with_alpn(self.b.endpoint().id(), DATA_ALPN)
            .await
            .expect("connect existing authenticated endpoint")
    }

    async fn poison(&self, database: &Database, variant: Poison) {
        let mut private: serde_json::Value =
            serde_json::from_str(&public_jwk("poison")).expect("fixture JWK");
        private["d"] = serde_json::json!("must-never-leave-this-node");
        sql(
            database,
            &format!(
                "UPDATE keys SET public_jwk = '{}' WHERE id = CAST('{}' AS UUID)",
                private, self.row
            ),
        )
        .await;
        match variant {
            Poison::Current => {}
            Poison::Overwritten => {
                sql(
                    database,
                    &format!(
                        "UPDATE keys SET public_jwk = '{}' WHERE id = CAST('{}' AS UUID)",
                        public_jwk("replaced"),
                        self.row
                    ),
                )
                .await;
            }
            Poison::Deleted => {
                sql(
                    database,
                    &format!("DELETE FROM keys WHERE id = CAST('{}' AS UUID)", self.row),
                )
                .await;
            }
            Poison::LosingConflict => {
                let fork = Database::open(self.root.join("fork-idp.redb"))
                    .expect("independent offline fork");
                for revision in 0..10 {
                    sql(&fork, &format!("UPDATE keys SET name = 'approved revision {revision}' WHERE id = CAST('{}' AS UUID)", self.row)).await;
                }
                let approved = public_jwk("approved-fork");
                sql(
                    &fork,
                    &format!(
                        "UPDATE keys SET public_jwk = '{approved}' WHERE id = CAST('{}' AS UUID)",
                        self.row
                    ),
                )
                .await;
                sync_fixture(database, &fork).await;
                let conflicts = database
                    .client()
                    .row_conflict_values("keys", &Row::new(vec![Value::Uuid(self.row)]))
                    .await
                    .expect("public conflict values");
                assert!(
                    conflicts
                        .iter()
                        .any(|(column, values)| column == "public_jwk"
                            && values.contains(&Value::Text(private.to_string()))),
                    "fixture retains private losing value"
                );
                assert_eq!(
                    sql(
                        database,
                        &format!(
                            "SELECT public_jwk FROM keys WHERE id = CAST('{}' AS UUID)",
                            self.row
                        )
                    )
                    .await[0]
                        .rows[0]
                        .values,
                    vec![Value::Text(approved)],
                    "private JWK is not the visible winner"
                );
            }
        }
    }

    async fn close(mut self) {
        self.cancellation.cancel();
        if let Some(router) = self.router.take() {
            router.shutdown().await.expect("shared router shutdown");
        }
        self.a.endpoint().close().await;
        self.b.endpoint().close().await;
        let root = self.root.clone();
        drop(self);
        std::fs::remove_dir_all(root).expect("remove native history fixture");
    }
}

async fn sync_fixture(a: &Database, b: &Database) {
    struct Channel {
        sender: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
        receiver: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    }
    impl SyncTransport for Channel {
        type Error = &'static str;
        async fn send(&mut self, frame: Vec<u8>) -> Result<(), Self::Error> {
            self.sender.send(frame).map_err(|_| "closed fixture")
        }
        async fn receive(&mut self) -> Result<Vec<u8>, Self::Error> {
            self.receiver.recv().await.ok_or("closed fixture")
        }
    }
    let (a_tx, a_rx) = tokio::sync::mpsc::unbounded_channel();
    let (b_tx, b_rx) = tokio::sync::mpsc::unbounded_channel();
    let mut left = Channel {
        sender: a_tx,
        receiver: b_rx,
    };
    let mut right = Channel {
        sender: b_tx,
        receiver: a_rx,
    };
    let tables = public_security_tables()
        .into_iter()
        .map(|table| table.name())
        .collect::<Vec<_>>();
    let config = SessionConfig::default();
    let (a, b) = tokio::join!(
        a.synchronize_tables_checked(&mut left, &config, SyncRole::Initiator, &tables, || async {
            Ok(())
        }),
        b.synchronize_tables_checked(
            &mut right,
            &config,
            SyncRole::Responder,
            &tables,
            || async { Ok(()) }
        )
    );
    a.expect("construct conflict fixture through public owner session");
    b.expect("receive conflict fixture through public owner session");
}

async fn unvalidated_initiate(
    pair: &Pair,
    connection: &Connection,
) -> io::Result<ofdb_sql::SyncResult> {
    let (mut send, recv) = connection.open_bi().await.map_err(io::Error::other)?;
    send.write_all(&[3]).await.map_err(io::Error::other)?;
    let mut inner = DatabaseTransport::new(send, recv);
    inner.send(serde_json::to_vec(&serde_json::json!({"version": 1, "installation": INSTALLATION, "member": pair.member_a, "context": "idp"})).map_err(io::Error::other)?).await?;
    let response: serde_json::Value =
        serde_json::from_slice(&inner.receive().await?).map_err(io::Error::other)?;
    assert_eq!(
        response["Accepted"]["member"],
        serde_json::json!(pair.member_b),
        "production receiver admitted the real trusted member before history validation"
    );
    let mut transport = RecordedTransport {
        inner,
        received: pair.received.clone(),
    };
    let tables = public_security_tables()
        .into_iter()
        .map(|table| table.name())
        .collect::<Vec<_>>();
    pair.idp_a
        .synchronize_tables_checked(
            &mut transport,
            &SessionConfig::default(),
            SyncRole::Initiator,
            &tables,
            || async { Ok(()) },
        )
        .await
        .map_err(|error| io::Error::other(error.to_string()))
}

fn assert_no_history_disclosure(pair: &Pair, variant: Poison, role: SyncRole) {
    let frames = pair.received.lock().expect("captured actual wire frames");
    assert!(
        !frames.iter().any(|frame| matches!(
            postcard::from_bytes::<SyncMessage>(frame),
            Ok(SyncMessage::State(_) | SyncMessage::Changes(_))
        )),
        "{variant:?}/{role:?}: poisoned history must not be disclosed as state/delta"
    );
    assert!(
        !frames.iter().any(|frame| frame
            .windows(b"must-never-leave-this-node".len())
            .any(|bytes| bytes == b"must-never-leave-this-node")),
        "rejection must not echo confidential content"
    );
}

#[tokio::test]
async fn private_jwk_remains_in_a_losing_conflict_behind_a_valid_public_projection() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let pair = Pair::new().await;
        pair.poison(&pair.idp_a, Poison::LosingConflict).await;
        pair.close().await;
    })
    .await
    .expect("bounded native losing-conflict fixture");
}

#[tokio::test]
async fn marker3_rejects_private_jwk_history_before_disclosing_to_unvalidated_peer() {
    tokio::time::timeout(Duration::from_secs(240), async {
        for variant in [
            Poison::Current,
            Poison::Overwritten,
            Poison::Deleted,
            Poison::LosingConflict,
        ] {
            for role in [SyncRole::Initiator, SyncRole::Responder] {
                let mut pair = Pair::new().await;
                let (source, recipient) = match role {
                    SyncRole::Initiator => (pair.idp_a.clone(), pair.idp_b.clone()),
                    SyncRole::Responder => (pair.idp_b.clone(), pair.idp_a.clone()),
                };
                pair.poison(&source, variant).await;
                let before = sql(&recipient, "SELECT * FROM keys").await[0].rows.clone();
                pair.serve(matches!(role, SyncRole::Responder));
                let connection = pair.connect().await;
                let error = match role {
                    SyncRole::Initiator => {
                        pair.protocol_a
                            .synchronize(&connection, SecurityContext::Idp)
                            .await
                    }
                    SyncRole::Responder => unvalidated_initiate(&pair, &connection).await,
                }
                .expect_err("private JWK history must reject before disclosure");
                assert!(
                    !error.to_string().contains("must-never-leave-this-node"),
                    "no secret in error"
                );
                assert_eq!(
                    sql(&recipient, "SELECT * FROM keys").await[0].rows,
                    before,
                    "{variant:?}/{role:?}: no private import even by unvalidated recipient"
                );
                assert_no_history_disclosure(&pair, variant, role);
                drop((source, recipient));
                pair.close().await;
            }
        }
    })
    .await
    .expect("bounded real marker3 history regressions");
}

#[tokio::test]
async fn marker3_rejects_unvalidated_incoming_private_jwk_history_before_apply() {
    tokio::time::timeout(Duration::from_secs(240), async {
        for variant in [
            Poison::Current,
            Poison::Overwritten,
            Poison::Deleted,
            Poison::LosingConflict,
        ] {
            for role in [SyncRole::Initiator, SyncRole::Responder] {
                let mut pair = Pair::new().await;
                let (source, recipient) = match role {
                    SyncRole::Initiator => (pair.idp_b.clone(), pair.idp_a.clone()),
                    SyncRole::Responder => (pair.idp_a.clone(), pair.idp_b.clone()),
                };
                pair.poison(&source, variant).await;
                let before = sql(&recipient, "SELECT * FROM keys").await[0].rows.clone();
                pair.serve(matches!(role, SyncRole::Responder));
                let connection = pair.connect().await;
                let error = match role {
                    SyncRole::Initiator => {
                        pair.protocol_a
                            .synchronize(&connection, SecurityContext::Idp)
                            .await
                    }
                    SyncRole::Responder => unvalidated_initiate(&pair, &connection).await,
                }
                .expect_err("malicious peer history must reject before apply");
                assert!(!error.to_string().contains("must-never-leave-this-node"));
                assert_eq!(
                    sql(&recipient, "SELECT * FROM keys").await[0].rows,
                    before,
                    "{variant:?}/{role:?}: poisoned history cannot enter the protected receiver"
                );
                drop((source, recipient));
                pair.close().await;
            }
        }
    })
    .await
    .expect("bounded authenticated incoming history denial");
}

#[tokio::test]
async fn marker3_rejects_private_jwk_in_an_unvalidated_full_state() {
    tokio::time::timeout(Duration::from_secs(120), async {
        let mut pair = Pair::new().await;
        let row = Id::now_v7();
        let mut private: serde_json::Value = serde_json::from_str(&public_jwk("unseen-key")).expect("fixture JWK");
        private["d"] = serde_json::json!("must-never-leave-this-node");
        sql(&pair.idp_a, &format!("INSERT INTO keys (id, derivation_index, public_jwk) VALUES (CAST('{row}' AS UUID), 1, '{private}')")).await;
        let before = sql(&pair.idp_b, "SELECT * FROM keys").await[0].rows.clone();
        pair.serve(true);
        let connection = pair.connect().await;
        unvalidated_initiate(&pair, &connection).await.expect_err("new unseen row's full state must be guarded before apply");
        assert_eq!(sql(&pair.idp_b, "SELECT * FROM keys").await[0].rows, before);
        pair.close().await;
    }).await.expect("bounded authenticated full-state denial");
}

#[tokio::test]
async fn marker3_valid_public_key_and_hash_histories_remain_syncable() {
    tokio::time::timeout(Duration::from_secs(120), async {
        let mut pair = Pair::new().await;
        let approved = public_jwk("rotated-public");
        sql(&pair.idp_a, &format!("UPDATE keys SET public_jwk = '{approved}' WHERE id = CAST('{}' AS UUID); INSERT INTO oauth2_authorization_codes (id, code_hash) VALUES (CAST('{}' AS UUID), '{}'); INSERT INTO oauth2_refresh_tokens (id, token_hash) VALUES (CAST('{}' AS UUID), '{}')", pair.row, Id::now_v7(), "a".repeat(64), Id::now_v7(), "b".repeat(64))).await;
        pair.serve(true);
        let connection = pair.connect().await;
        pair.protocol_a.synchronize(&connection, SecurityContext::Idp).await.expect("valid public key/history/hash values pass the same production validator");
        assert_eq!(sql(&pair.idp_b, &format!("SELECT public_jwk FROM keys WHERE id = CAST('{}' AS UUID)", pair.row)).await[0].rows[0].values, vec![Value::Text(approved)]);
        let before = sql(&pair.idp_b, "SELECT token_hash FROM oauth2_refresh_tokens").await[0].rows.clone();
        sql(&pair.idp_a, "UPDATE oauth2_refresh_tokens SET token_hash = 'raw-bearer-value'").await;
        pair.protocol_a.synchronize(&connection, SecurityContext::Idp).await.expect_err("raw grant value in allowed Text must not be exported");
        assert_eq!(sql(&pair.idp_b, "SELECT token_hash FROM oauth2_refresh_tokens").await[0].rows, before);
        pair.close().await;
    }).await.expect("bounded valid history/hash exchange");
}
