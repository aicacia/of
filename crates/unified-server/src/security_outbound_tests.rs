use std::{io, path::PathBuf, sync::Arc, time::Duration};

use db::Database;
use idp_model::{contract::IdentityAction, model::Id};
use idp_service::{oauth2::NodeSignerBinding, security_sync::public_security_tables};
use iroh::{Endpoint, address_lookup::MemoryLookup, endpoint::presets};
use iroh_chain::{DATA_ALPN, EndpointIdStore, Server};
use management_service::{
    ManagementService, PUBLIC_POLICY_TABLES,
    replica::{DbPermissionRepo, DbRoleRepo},
};
use ofdb_sql::{SessionConfig, SyncMessage, SyncRole, SyncTransport};
use storage_server::DatabaseTransport;
use tokio_util::sync::CancellationToken;

use super::{
    AuthorizedSecurityTransport, Handshake, Response, SECURITY_STREAM_KIND, SecurityContext,
    SecurityProtocol,
};
use crate::security_sync_tests::{enroll, sql};

const INSTALLATION: &str = "https://installation.example";

struct Fixture {
    root: PathBuf,
    source: SecurityProtocol,
    peer: Server,
    peer_member: Id,
    actor: Id,
    payload: Id,
    peer_idp: Arc<Database>,
    peer_management: Arc<Database>,
}

impl Fixture {
    async fn new() -> Self {
        let root = std::env::temp_dir().join(format!("of-security-outbound-{}", Id::now_v7()));
        std::fs::create_dir_all(&root).expect("create native stores");
        let lookup = MemoryLookup::new();
        let source = Endpoint::builder(presets::Minimal)
            .alpns(vec![DATA_ALPN.to_vec()])
            .address_lookup(lookup.clone())
            .bind()
            .await
            .expect("source endpoint");
        let peer = Endpoint::builder(presets::Minimal)
            .alpns(vec![DATA_ALPN.to_vec()])
            .address_lookup(lookup.clone())
            .bind()
            .await
            .expect("peer endpoint");
        lookup.add_endpoint_info(source.addr());
        lookup.add_endpoint_info(peer.addr());
        let allowed = EndpointIdStore::default();
        allowed.add(peer.id());
        let source = Server::new(source, allowed);
        let allowed = EndpointIdStore::default();
        allowed.add(source.endpoint().id());
        let peer = Server::new(peer, allowed);
        let actor = Id::now_v7();
        let member = Id::now_v7();
        let peer_member = Id::now_v7();
        let key = Id::now_v7();
        {
            let idp = Arc::new(Database::open(root.join("source-idp.redb")).expect("native IdP"));
            idp_model::replica::up(&idp).await.expect("IdP schema");
            sql(&idp, &format!("INSERT INTO users (id, handle, name, created_at, updated_at) VALUES (CAST('{actor}' AS UUID), 'owner', 'Owner', 1, 1)")).await;
            for (member, key, endpoint) in [
                (member, key, source.endpoint().id()),
                (peer_member, Id::now_v7(), peer.endpoint().id()),
            ] {
                sql(&idp, &format!("INSERT INTO devices (id, owner_subject, name, public_key, address, state, approved_at, created_at, updated_at) VALUES (CAST('{member}' AS UUID), '{actor}', 'node', '{endpoint}', 'local', 1, 1, 1, 1)")).await;
                enroll(idp.clone(), member, endpoint, key).await;
            }
            let management = Arc::new(
                Database::open(root.join("source-management.redb")).expect("native Management"),
            );
            management_service::replica::up(&management)
                .await
                .expect("Management schema");
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
                    (Id::now_v7(), IdentityAction::ManagementSecuritySync),
                ],
            )
            .await
            .expect("explicit local context grants");
        }
        std::fs::copy(root.join("source-idp.redb"), root.join("peer-idp.redb"))
            .expect("copy verifier-free approved baseline");
        std::fs::copy(
            root.join("source-management.redb"),
            root.join("peer-management.redb"),
        )
        .expect("copy policy baseline");
        let idp = Arc::new(Database::open(root.join("source-idp.redb")).expect("source IdP"));
        let management = Arc::new(
            Database::open(root.join("source-management.redb")).expect("source Management"),
        );
        let peer_idp = Arc::new(Database::open(root.join("peer-idp.redb")).expect("peer IdP"));
        let peer_management =
            Arc::new(Database::open(root.join("peer-management.redb")).expect("peer Management"));
        let payload = Id::now_v7();
        sql(&idp, &format!("INSERT INTO users (id, handle, name, created_at, updated_at) VALUES (CAST('{payload}' AS UUID), 'outbound-payload', 'Outbound Payload', 1, 1)")).await;
        sql(&management, &format!("INSERT INTO roles (id, application_id, name, created_at, updated_at) VALUES (CAST('{payload}' AS UUID), CAST('{payload}' AS UUID), 'outbound-payload', 1, 1)")).await;
        let source = SecurityProtocol::new(
            source,
            idp,
            management,
            INSTALLATION.into(),
            Some(NodeSignerBinding {
                member_id: member,
                key_id: key,
                endpoint_id: String::new(),
            }),
            root.join("stage"),
            CancellationToken::new(),
        );
        let mut source = source;
        source.binding.as_mut().expect("fixture signer").endpoint_id =
            source.server.endpoint().id().to_string();
        Self {
            root,
            source,
            peer,
            peer_member,
            actor,
            payload,
            peer_idp,
            peer_management,
        }
    }

    async fn close(self) {
        self.source.server.endpoint().close().await;
        self.peer.endpoint().close().await;
        let root = self.root.clone();
        drop(self);
        std::fs::remove_dir_all(root).expect("remove fixture native stores");
    }
}

#[derive(Clone, Copy, Debug)]
enum Revoke {
    Keep,
    Grant,
    User,
    Membership,
    Cancel,
    PolicyFailure,
}

struct GatedPeer<'a> {
    transport: DatabaseTransport,
    fixture: &'a Fixture,
    revoke: Revoke,
    learned: bool,
    after_denial: Vec<SyncMessage>,
}

impl SyncTransport for GatedPeer<'_> {
    type Error = io::Error;
    async fn send(&mut self, frame: Vec<u8>) -> io::Result<()> {
        self.transport.send(frame).await
    }
    async fn receive(&mut self) -> io::Result<Vec<u8>> {
        let frame = self.transport.receive().await?;
        let Ok(message) = postcard::from_bytes::<SyncMessage>(&frame) else {
            assert!(!self.learned, "no undecodable frame after denial");
            return Ok(frame);
        };
        if self.learned {
            self.after_denial.push(message.clone());
        }
        if matches!(message, SyncMessage::Hello(_)) && !self.learned {
            match self.revoke {
                Revoke::Keep => {}
                Revoke::Grant => {
                    sql(
                        &self.fixture.source.management,
                        "DELETE FROM role_permissions",
                    )
                    .await;
                }
                Revoke::User => {
                    sql(
                        &self.fixture.source.idp,
                        &format!(
                            "DELETE FROM users WHERE id = CAST('{}' AS UUID)",
                            self.fixture.actor
                        ),
                    )
                    .await;
                }
                Revoke::Membership => {
                    sql(&self.fixture.source.idp, &format!("UPDATE idp_replica_members SET revoked_at = 2 WHERE member_id = CAST('{}' AS UUID)", self.fixture.peer_member)).await;
                }
                Revoke::Cancel => self.fixture.source.cancellation.cancel(),
                Revoke::PolicyFailure => {
                    sql(
                        &self.fixture.source.management,
                        "DROP TABLE role_permissions",
                    )
                    .await;
                }
            }
            self.learned = true;
            eprintln!("learned {:?} after Hello", self.revoke);
        }
        Ok(frame)
    }
}

async fn peer_exchange(
    fixture: &Fixture,
    context: SecurityContext,
    role: SyncRole,
    revoke: Revoke,
) -> (io::Result<()>, bool, Vec<SyncMessage>) {
    let (connection, source_side) = if matches!(role, SyncRole::Initiator) {
        let (source_side, incoming) = tokio::join!(
            fixture
                .source
                .server
                .connect_direct_with_alpn(fixture.peer.endpoint().id(), DATA_ALPN),
            async {
                fixture
                    .peer
                    .endpoint()
                    .accept()
                    .await
                    .expect("peer incoming")
                    .await
                    .expect("authenticated peer connection")
            }
        );
        (incoming, source_side.expect("source connection"))
    } else {
        let (connection, incoming) = tokio::join!(
            fixture
                .peer
                .connect_direct_with_alpn(fixture.source.server.endpoint().id(), DATA_ALPN),
            async {
                fixture
                    .source
                    .server
                    .endpoint()
                    .accept()
                    .await
                    .expect("source incoming")
                    .await
                    .expect("authenticated source connection")
            }
        );
        (connection.expect("peer connection"), incoming)
    };
    fixture
        .source
        .authorize(&source_side, fixture.peer_member, context)
        .await
        .expect("fixture is genuinely authorized before the gate");
    let source = async {
        if matches!(role, SyncRole::Initiator) {
            fixture
                .source
                .synchronize(&source_side, context)
                .await
                .map(|_| ())
        } else {
            let (send, mut recv) = source_side
                .accept_bi()
                .await
                .expect("source security stream");
            let mut marker = [0];
            recv.read_exact(&mut marker).await.expect("security marker");
            assert_eq!(marker[0], SECURITY_STREAM_KIND);
            fixture
                .source
                .accept_stream(source_side.clone(), send, recv)
                .await
        }
    };
    let peer = async {
        let (send, recv) = if matches!(role, SyncRole::Initiator) {
            let (send, mut recv) = connection.accept_bi().await.expect("peer security stream");
            let mut marker = [0];
            recv.read_exact(&mut marker).await.expect("source marker");
            assert_eq!(marker[0], SECURITY_STREAM_KIND);
            (send, recv)
        } else {
            let (mut send, recv) = connection.open_bi().await.expect("peer security stream");
            send.write_all(&[SECURITY_STREAM_KIND])
                .await
                .expect("peer marker");
            (send, recv)
        };
        let mut transport = DatabaseTransport::new(send, recv);
        let hello = Handshake {
            version: 1,
            installation: INSTALLATION.into(),
            member: fixture.peer_member,
            context,
        };
        if matches!(role, SyncRole::Initiator) {
            let remote: Handshake =
                serde_json::from_slice(&transport.receive().await.expect("source handshake"))
                    .expect("source handshake JSON");
            assert_eq!(
                remote.member,
                fixture
                    .source
                    .binding
                    .as_ref()
                    .expect("local signer")
                    .member_id
            );
            transport
                .send(serde_json::to_vec(&Response::Accepted(hello)).expect("peer approval"))
                .await
                .expect("send approval");
        } else {
            transport
                .send(serde_json::to_vec(&hello).expect("peer handshake"))
                .await
                .expect("send handshake");
            assert!(matches!(
                serde_json::from_slice::<Response>(
                    &transport.receive().await.expect("source approval")
                )
                .expect("source approval JSON"),
                Response::Accepted(_)
            ));
        }
        let mut transport = GatedPeer {
            transport,
            fixture,
            revoke,
            learned: false,
            after_denial: Vec::new(),
        };
        let (database, tables) = match context {
            SecurityContext::Idp => (
                &fixture.peer_idp,
                public_security_tables()
                    .into_iter()
                    .map(|table| table.name())
                    .collect::<Vec<_>>(),
            ),
            SecurityContext::Management => {
                (&fixture.peer_management, PUBLIC_POLICY_TABLES.to_vec())
            }
        };
        let peer_role = if matches!(role, SyncRole::Initiator) {
            SyncRole::Responder
        } else {
            SyncRole::Initiator
        };
        let peer_result = database
            .synchronize_tables_checked(
                &mut transport,
                &SessionConfig::default(),
                peer_role,
                &tables,
                || async { Ok(()) },
            )
            .await;
        eprintln!("peer finished: {peer_result:?}");
        (transport.learned, transport.after_denial)
    };
    let source = async {
        let result = source.await;
        eprintln!("source finished: {result:?}");
        result
    };
    let (result, (learned, frames)) = tokio::join!(source, peer);
    (result, learned, frames)
}

#[tokio::test]
async fn learned_denial_blocks_next_security_disclosure_on_existing_connection() {
    tokio::time::timeout(Duration::from_secs(360), async {
        for context in [SecurityContext::Idp, SecurityContext::Management] {
            for role in [SyncRole::Initiator, SyncRole::Responder] {
                let fixture = Fixture::new().await;
                let (source_database, peer_database, table) = match context {
                    SecurityContext::Idp => (&fixture.source.idp, &fixture.peer_idp, "users"),
                    SecurityContext::Management => (
                        &fixture.source.management,
                        &fixture.peer_management,
                        "roles",
                    ),
                };
                let query = format!(
                    "SELECT * FROM {table} WHERE id = CAST('{}' AS UUID)",
                    fixture.payload
                );
                let before = sql(source_database, &query).await[0].rows.clone();
                assert!(
                    !before.is_empty(),
                    "actual source-only payload awaits disclosure"
                );
                assert!(sql(peer_database, &query).await[0].rows.is_empty());
                let (result, learned, frames) =
                    peer_exchange(&fixture, context, role, Revoke::Grant).await;
                assert!(learned, "peer gates after admitted owner Hello");
                let error = result
                    .expect_err("learned role removal must deny subsequent outbound disclosure");
                assert_eq!(
                    error.kind(),
                    io::ErrorKind::PermissionDenied,
                    "{context:?}/{role:?}: {error}"
                );
                assert!(
                    frames.is_empty(),
                    "no owner frame may be sent after learned denial: {frames:?}"
                );
                assert_eq!(
                    sql(source_database, &query).await[0].rows,
                    before,
                    "denial leaves source data untouched"
                );
                assert!(
                    sql(peer_database, &query).await[0].rows.is_empty(),
                    "denied source payload never imported"
                );
                fixture.close().await;
            }
        }
    })
    .await
    .expect("bounded native outbound matrix");
}

#[tokio::test]
async fn learned_actor_membership_cancellation_and_policy_failure_deny_outbound() {
    tokio::time::timeout(Duration::from_secs(600), async {
        for revoke in [
            Revoke::User,
            Revoke::Membership,
            Revoke::Cancel,
            Revoke::PolicyFailure,
        ] {
            for role in [SyncRole::Initiator, SyncRole::Responder] {
                eprintln!("checking outbound denial: {role:?}/{revoke:?}");
                let fixture = Fixture::new().await;
                let before = sql(
                    &fixture.source.idp,
                    &format!(
                        "SELECT * FROM users WHERE id = CAST('{}' AS UUID)",
                        fixture.payload
                    ),
                )
                .await[0]
                    .rows
                    .clone();
                let (result, learned, frames) =
                    peer_exchange(&fixture, SecurityContext::Idp, role, revoke).await;
                assert!(learned);
                assert_eq!(
                    result
                        .expect_err("missing current evidence denies outgoing frames")
                        .kind(),
                    io::ErrorKind::PermissionDenied,
                    "{role:?}/{revoke:?}"
                );
                assert!(frames.is_empty(), "no outbound frames after learned denial");
                assert_eq!(
                    sql(
                        &fixture.source.idp,
                        &format!(
                            "SELECT * FROM users WHERE id = CAST('{}' AS UUID)",
                            fixture.payload
                        )
                    )
                    .await[0]
                        .rows,
                    before
                );
                assert!(
                    sql(
                        &fixture.peer_idp,
                        &format!(
                            "SELECT * FROM users WHERE id = CAST('{}' AS UUID)",
                            fixture.payload
                        )
                    )
                    .await[0]
                        .rows
                        .is_empty()
                );
                fixture.close().await;
            }
        }
    })
    .await
    .expect("bounded current local evidence matrix");
}

#[tokio::test]
async fn currently_authorized_security_payloads_exchange_on_both_roles_and_contexts() {
    tokio::time::timeout(Duration::from_secs(240), async {
        for context in [SecurityContext::Idp, SecurityContext::Management] {
            for role in [SyncRole::Initiator, SyncRole::Responder] {
                let fixture = Fixture::new().await;
                let (source, peer, table) = match context {
                    SecurityContext::Idp => (&fixture.source.idp, &fixture.peer_idp, "users"),
                    SecurityContext::Management => (
                        &fixture.source.management,
                        &fixture.peer_management,
                        "roles",
                    ),
                };
                let query = format!(
                    "SELECT * FROM {table} WHERE id = CAST('{}' AS UUID)",
                    fixture.payload
                );
                let before = sql(source, &query).await[0].rows.clone();
                assert!(!before.is_empty());
                assert!(sql(peer, &query).await[0].rows.is_empty());
                let (result, admitted, frames) =
                    peer_exchange(&fixture, context, role, Revoke::Keep).await;
                result.expect("current local evidence permits actual security exchange");
                assert!(admitted);
                assert!(
                    frames.iter().any(|frame| matches!(
                        frame,
                        SyncMessage::State(_) | SyncMessage::Changes(_)
                    )),
                    "real owner payload was exported"
                );
                assert_eq!(sql(peer, &query).await[0].rows, before);
                assert_eq!(sql(source, &query).await[0].rows, before);
                fixture.close().await;
            }
        }
    })
    .await
    .expect("bounded positive native security exchange");
}

struct AdmittedWrite {
    transport: DatabaseTransport,
    admitted: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
}

impl SyncTransport for AdmittedWrite {
    type Error = io::Error;
    async fn send(&mut self, frame: Vec<u8>) -> io::Result<()> {
        self.admitted.notify_one();
        self.release.notified().await;
        self.transport.send(frame).await
    }
    async fn receive(&mut self) -> io::Result<Vec<u8>> {
        self.transport.receive().await
    }
}

#[tokio::test]
async fn admitted_security_write_finishes_then_next_write_denies() {
    tokio::time::timeout(Duration::from_secs(120), async {
        for revoke in [Revoke::Grant, Revoke::Cancel] {
            let fixture = Fixture::new().await;
            let (source, peer) = tokio::join!(
                fixture
                    .source
                    .server
                    .connect_direct_with_alpn(fixture.peer.endpoint().id(), DATA_ALPN),
                async {
                    fixture
                        .peer
                        .endpoint()
                        .accept()
                        .await
                        .expect("incoming connection")
                        .await
                        .expect("authenticated peer")
                }
            );
            let source = source.expect("existing authenticated source connection");
            let (send, recv) = source.open_bi().await.expect("outbound write stream");
            let admitted = Arc::new(tokio::sync::Notify::new());
            let release = Arc::new(tokio::sync::Notify::new());
            let before = sql(&fixture.source.idp, "SELECT * FROM devices").await[0]
                .rows
                .clone();
            let writer = async {
                let mut inner = AdmittedWrite {
                    transport: DatabaseTransport::new(send, recv),
                    admitted: admitted.clone(),
                    release: release.clone(),
                };
                let mut transport = AuthorizedSecurityTransport {
                    transport: &mut inner,
                    protocol: &fixture.source,
                    connection: &source,
                    member: fixture.peer_member,
                    context: SecurityContext::Idp,
                };
                transport
                    .send(b"admitted-disclosure".to_vec())
                    .await
                    .expect("already-authorized write is allowed to finish");
                assert_eq!(
                    transport
                        .send(b"denied-next-disclosure".to_vec())
                        .await
                        .expect_err("next operation uses learned policy")
                        .kind(),
                    io::ErrorKind::PermissionDenied
                );
            };
            let reader = async {
                admitted.notified().await;
                match revoke {
                    Revoke::Grant => {
                        sql(&fixture.source.management, "DELETE FROM role_permissions").await;
                    }
                    Revoke::Cancel => fixture.source.cancellation.cancel(),
                    _ => unreachable!("only grant removal/cancellation in this fixture"),
                }
                release.notify_one();
                let (send, recv) = peer
                    .accept_bi()
                    .await
                    .expect("admitted stream reaches authenticated peer");
                let mut transport = DatabaseTransport::new(send, recv);
                assert_eq!(
                    transport.receive().await.expect("actual admitted bytes"),
                    b"admitted-disclosure"
                );
                assert!(
                    transport.receive().await.is_err(),
                    "no subsequent bytes on this existing stream"
                );
            };
            tokio::join!(writer, reader);
            assert_eq!(
                sql(&fixture.source.idp, "SELECT * FROM devices").await[0].rows,
                before
            );
            fixture.close().await;
        }
    })
    .await
    .expect("bounded admitted-write interleaving");
}
