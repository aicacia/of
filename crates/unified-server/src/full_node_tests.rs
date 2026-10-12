use std::{collections::HashMap, sync::Arc, time::Duration};

use futures_util::{SinkExt, StreamExt};
use idp_model::{
    contract::{GrantType, INSTALLATION_POLICY_ID, IdentityAction},
    model::Id,
};
use idp_service::{oauth2::NodeSignerBinding, repo::PrivateKeyKeyringRepo};
use iroh_chain::DATA_ALPN;
use management_service::{
    ManagementService,
    replica::{DbPermissionRepo, DbRoleRepo, DbSelectionPolicyRepo, SelectionPolicy},
};
use model::contract::TokenResponse;
use storage_model::{StorageRequest, StorageResponse};
use tokio::{net::TcpStream, task::JoinHandle};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, tungstenite::Message};

use super::{Fixture, rotation_login_client};
use crate::{LocalProvisioner, SecurityContext, SecurityProtocol, UnifiedEndpoint, UnifiedRuntime};

struct NodeStores {
    stores: [(String, Arc<keyring_core::CredentialStore>); 2],
}

impl keyring_core::api::CredentialStoreApi for NodeStores {
    fn vendor(&self) -> String {
        "isolated-full-node-test-stores".into()
    }

    fn id(&self) -> String {
        self.vendor()
    }

    fn build(
        &self,
        service: &str,
        user: &str,
        modifiers: Option<&HashMap<&str, &str>>,
    ) -> keyring_core::Result<keyring_core::Entry> {
        let (_, store) = self
            .stores
            .iter()
            .find(|(namespace, _)| user.starts_with(&format!("{namespace}:")))
            .ok_or(keyring_core::Error::NoEntry)?;
        keyring_core::api::CredentialStoreApi::build(&**store, service, user, modifiers)
    }

    fn search(&self, spec: &HashMap<&str, &str>) -> keyring_core::Result<Vec<keyring_core::Entry>> {
        let mut entries = Vec::new();
        for (_, store) in &self.stores {
            entries.extend(store.search(spec)?);
        }
        Ok(entries)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

struct Host {
    runtime: Option<UnifiedRuntime>,
    listener: Option<JoinHandle<()>>,
    base: String,
}

impl Host {
    async fn start(mut runtime: UnifiedRuntime) -> Self {
        assert!(
            runtime
                .node_public_ready()
                .await
                .expect("current local readiness")
        );
        let base = format!("http://{}", runtime.local_addr());
        let listener = runtime
            .take_listener()
            .expect("one production host listener");
        let router = runtime.router();
        let cancellation = runtime.cancellation_token();
        let task = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(cancellation.cancelled_owned())
                .await
                .expect("serve composed owner APIs");
        });
        let mut host = Self {
            runtime: Some(runtime),
            listener: Some(task),
            base,
        };
        host.runtime
            .as_mut()
            .expect("owned host runtime")
            .start_background_tasks()
            .await
            .expect("one shared production protocol router");
        let health = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("bounded local context readiness check");
        for context in ["idp", "management", "storage"] {
            assert_eq!(
                health
                    .get(format!("{}/{context}/health", host.base))
                    .send()
                    .await
                    .expect("real local context listener")
                    .status(),
                reqwest::StatusCode::OK,
                "{context} must be locally ready before declaring a full host"
            );
        }
        host
    }

    fn runtime(&self) -> &UnifiedRuntime {
        self.runtime.as_ref().expect("running full host")
    }

    async fn stop(mut self) {
        self.runtime
            .take()
            .expect("running full host")
            .shutdown()
            .await
            .expect("ordinary managed shutdown");
        self.listener
            .take()
            .expect("host listener task")
            .await
            .expect("listener joined");
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        if let Some(runtime) = &self.runtime {
            runtime.cancellation_token().cancel();
        }
        if let Some(listener) = &self.listener {
            listener.abort();
        }
    }
}

async fn json(response: reqwest::Response, expected: reqwest::StatusCode) -> serde_json::Value {
    let status = response.status();
    let url = response.url().to_string();
    let body = response.text().await.expect("owner response body");
    assert_eq!(status, expected, "{url}: {body}");
    serde_json::from_str(&body).expect("public owner JSON")
}

async fn token(http: &reqwest::Client, host: &Host, form: &[(&str, &str)]) -> TokenResponse {
    let body = json(
        http.post(format!("{}/idp/oauth2/token", host.base))
            .form(form)
            .send()
            .await
            .expect("real local OAuth request"),
        reqwest::StatusCode::OK,
    )
    .await;
    serde_json::from_value(body).expect("public OAuth token response")
}

async fn exchange(
    http: &reqwest::Client,
    host: &Host,
    client: &str,
    subject: &str,
    audience: &str,
) -> String {
    let details = r#"[{"type":"storage","actions":["read","write"]}]"#;
    let mut form = vec![
        (
            "grant_type",
            "urn:ietf:params:oauth:grant-type:token-exchange",
        ),
        ("client_id", client),
        ("subject_token", subject),
        (
            "subject_token_type",
            "urn:ietf:params:oauth:token-type:access_token",
        ),
        ("resource", audience),
    ];
    if audience == "storage:filesystems" {
        form.push(("authorization_details", details));
    }
    token(http, host, &form).await.access_token.0
}

async fn refresh(
    http: &reqwest::Client,
    host: &Host,
    client: &str,
    grant: &str,
) -> reqwest::Response {
    let started = std::time::Instant::now();
    let result = http
        .post(format!("{}/idp/oauth2/token", host.base))
        .form(&[
            ("grant_type", "refresh_token"),
            ("client_id", client),
            ("refresh_token", grant),
        ])
        .send()
        .await;
    match result {
        Ok(response) => {
            eprintln!(
                "08 refresh: node={} status={} elapsed={:?}",
                host.runtime().endpoint_id(),
                response.status(),
                started.elapsed()
            );
            response
        }
        Err(error) => panic!(
            "local refresh transport failure: node={} timeout={} elapsed={:?}",
            host.runtime().endpoint_id(),
            error.is_timeout(),
            started.elapsed()
        ),
    }
}

async fn denied_grant(response: reqwest::Response) {
    let status = response.status();
    assert!(
        status.is_client_error(),
        "grant denial must not be outage/server failure: {status}"
    );
    let body: serde_json::Value = response.json().await.expect("OAuth denial");
    assert_eq!(body["error"], "invalid_grant");
}

async fn local_winner(http: &reqwest::Client, host: &Host, client: &str, grant: &str) {
    let (left, right) = tokio::join!(
        refresh(http, host, client, grant),
        refresh(http, host, client, grant)
    );
    let (winner, loser) = if left.status() == reqwest::StatusCode::OK {
        (left, right)
    } else {
        (right, left)
    };
    let winner = json(winner, reqwest::StatusCode::OK).await;
    assert_ne!(
        winner["refresh_token"]
            .as_str()
            .expect("durable replacement"),
        grant
    );
    denied_grant(loser).await;
    denied_grant(refresh(http, host, client, grant).await).await;
}

async fn restriction(http: &reqwest::Client, host: &Host, actor: &str, device: Id, allowed: bool) {
    let response = http
        .put(format!(
            "{}/management/devices/{device}/restriction",
            host.base
        ))
        .bearer_auth(actor)
        .json(&serde_json::json!({"adminAllowed": allowed}))
        .send()
        .await
        .expect("real Management policy mutation");
    assert_eq!(
        response.status(),
        reqwest::StatusCode::NO_CONTENT,
        "{}",
        response.text().await.expect("policy response")
    );
}

async fn assert_restriction(
    http: &reqwest::Client,
    host: &Host,
    actor: &str,
    device: Id,
    allowed: bool,
) {
    let body = json(
        http.get(format!(
            "{}/management/devices/{device}/restriction",
            host.base
        ))
        .bearer_auth(actor)
        .send()
        .await
        .expect("local policy read"),
        reqwest::StatusCode::OK,
    )
    .await;
    assert_eq!(body["adminAllowed"], allowed);
}

type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

async fn socket(host: &Host, bearer: &str, resource: &str) -> Socket {
    let mut url =
        reqwest::Url::parse(&host.base.replace("http:", "ws:")).expect("local socket URL");
    url.set_path("/storage");
    url.query_pairs_mut()
        .append_pair("access_token", bearer)
        .append_pair("filesystem_id", resource);
    tokio_tungstenite::connect_async(url.as_str())
        .await
        .expect("real authorized resource connection")
        .0
}

async fn send(socket: &mut Socket, request: StorageRequest) {
    socket
        .send(Message::Text(
            serde_json::to_string(&request)
                .expect("Storage request")
                .into(),
        ))
        .await
        .expect("retained socket request");
}

async fn response(socket: &mut Socket) -> StorageResponse {
    let frame = socket
        .next()
        .await
        .expect("resource response")
        .expect("valid resource frame");
    serde_json::from_str(frame.to_text().expect("text response")).expect("Storage response")
}

async fn create_written_resource(
    http: &reqwest::Client,
    host: &Host,
    bearer: &str,
) -> (String, Socket) {
    let resource = json(
        http.post(format!("{}/storage/filesystems", host.base))
            .bearer_auth(bearer)
            .json(&serde_json::json!({"name": "offline local copy"}))
            .send()
            .await
            .expect("real independent resource creation"),
        reqwest::StatusCode::CREATED,
    )
    .await;
    let resource = resource["id"]
        .as_str()
        .expect("stable resource ID")
        .to_owned();
    let mut connection = socket(host, bearer, &resource).await;
    send(
        &mut connection,
        StorageRequest::Write {
            path: "retained.txt".into(),
            content: b"committed offline".to_vec(),
        },
    )
    .await;
    assert!(matches!(
        response(&mut connection).await,
        StorageResponse::Written { .. }
    ));
    send(
        &mut connection,
        StorageRequest::Read {
            path: "retained.txt".into(),
        },
    )
    .await;
    assert_eq!(
        response(&mut connection).await,
        StorageResponse::Read {
            content: b"committed offline".to_vec()
        }
    );
    (resource, connection)
}

async fn join_host(
    source: &Host,
    b: &mut Fixture,
    owner: Id,
    journal: &serde_json::Value,
    approving: &str,
) -> Host {
    let joining_started = std::time::Instant::now();
    let endpoint_a = source.runtime().endpoint_id();
    let endpoint = UnifiedEndpoint::open_fresh(&b.config.endpoint_data_dir, &b.config.idp)
        .await
        .expect("independent joining endpoint");
    let binding = NodeSignerBinding {
        member_id: Id::now_v7(),
        key_id: Id::now_v7(),
        endpoint_id: endpoint.endpoint_id().to_string(),
    };
    let (protocol, joining_owner) = SecurityProtocol::open_node_bootstrap(
        &endpoint,
        &b.config.idp,
        std::path::Path::new(&b.config.management.data_dir),
        binding.clone(),
    )
    .await
    .expect("production public bootstrap owner");
    let credentials = [
        &b.config.management_idp_client,
        &b.config.storage_idp_client,
        &b.config.storage_management_client,
        b.config
            .idp_management_client
            .as_ref()
            .expect("local evaluator"),
    ];
    let client_ids = credentials
        .iter()
        .map(|credential| {
            credential
                .client_id
                .parse::<Id>()
                .expect("local relationship ID")
        })
        .collect::<Vec<_>>();
    joining_owner
        .prepare_fresh_setup_secret_inventory(owner, &client_ids)
        .await
        .expect("fresh independent private inventory");
    joining_owner
        .prepare_setup_client_slots(&client_ids)
        .await
        .expect("capture independent service slots before private writes");
    let request = joining_owner
        .prepare_node_join(&binding, "Node B", endpoint_a)
        .expect("durable independent signer request");
    assert_ne!(
        request.public_signer.kid,
        journal["key"].as_str().expect("source signer ID")
    );
    let mut offers = source
        .runtime()
        .full_node_test_server()
        .subscribe_pairing_offers();
    let sender = tokio::spawn({
        let server = endpoint.server().clone();
        let address = source.runtime().full_node_test_server().endpoint().addr();
        async move { request.send(&server, address).await }
    });
    let offered = offers.recv().await.expect("authenticated pairing delivery");
    assert_eq!(offered.remote_id, endpoint.endpoint_id());
    let pending = source
        .runtime()
        .pending_node_joins(approving)
        .await
        .expect("authorized host pending offer API");
    let offer: Id = pending[0]["offer_id"]
        .as_str()
        .expect("purpose-bound offer ID")
        .parse()
        .expect("offer ID");
    assert!(
        source
            .runtime()
            .approve_pending_node_join("forged-bearer", offer)
            .await
            .is_err(),
        "forged approval cannot enroll a Node"
    );
    let approval = source
        .runtime()
        .approve_pending_node_join(approving, offer)
        .await
        .expect("real authorized approval");
    assert_eq!(
        sender
            .await
            .expect("pairing sender joined")
            .expect("pinned authenticated approval"),
        approval
    );
    assert_eq!(approval.owner_subject, owner);
    assert_eq!(approval.request.member_id, binding.member_id);
    assert_eq!(approval.request.endpoint_id, binding.endpoint_id);
    let policies = DbSelectionPolicyRepo::new(source.runtime().full_node_test_management());
    assert!(
        policies
            .get(binding.member_id, &owner.to_string(), Id::nil())
            .await
            .expect("public existing Device policy lookup")
            .is_none()
    );
    policies
        .set_prevalidated(SelectionPolicy {
            device_id: binding.member_id,
            owner_subject: owner.to_string(),
            application_id: None,
            selected_kind: None,
            selected_id: None,
            admin_allowed: true,
        })
        .await
        .expect("existing owner initializes the actually approved Device's empty policy");
    drop(policies);
    joining_owner
        .record_node_join_approval(&approval)
        .expect("durable receipt");
    assert!(
        !protocol
            .node_join_public_ready(&joining_owner)
            .await
            .expect("receipt alone is incomplete")
    );
    assert!(
        endpoint
            .server()
            .endpoint()
            .connect(
                source.runtime().full_node_test_server().endpoint().addr(),
                DATA_ALPN
            )
            .await
            .is_err(),
        "pairing is not general resource admission"
    );
    let bootstrap = endpoint
        .server()
        .endpoint()
        .connect(
            source.runtime().full_node_test_server().endpoint().addr(),
            idp_server::BOOTSTRAP_ALPN,
        )
        .await
        .expect("authenticated purpose-bound bootstrap");
    for context in [SecurityContext::Idp, SecurityContext::Management] {
        eprintln!(
            "08 join: importing {context:?} at {:?}",
            joining_started.elapsed()
        );
        protocol
            .receive_node_bootstrap(&bootstrap, &joining_owner, context)
            .await
            .expect("real public owner import");
        eprintln!(
            "08 join: imported {context:?} at {:?}",
            joining_started.elapsed()
        );
    }
    protocol
        .complete_node_join_public_bootstrap(&joining_owner)
        .await
        .expect("both public contexts durably complete");
    assert!(
        protocol
            .node_join_public_ready(&joining_owner)
            .await
            .expect("completed public join")
    );
    assert_ne!(
        joining_owner
            .verify_node_signer(&binding)
            .await
            .expect("independent trusted local signer"),
        serde_json::from_value::<idp_model::contract::JwkPublic>(journal["public_signer"].clone())
            .expect("source public signer")
    );
    let registrations: Vec<idp_model::contract::ClientRegistration> =
        serde_json::from_value(journal["intent"]["clients"].clone())
            .expect("public relationship registration templates");
    for (mut registration, credential) in registrations.into_iter().zip(credentials) {
        registration.client_id = Some(credential.client_id.clone());
        registration.client_secret = Some(credential.client_secret.clone());
        joining_owner
            .ensure_setup_infrastructure_client(registration)
            .await
            .expect("independently provisioned local service secret, not imported private stores");
    }
    bootstrap.close(0u32.into(), b"public bootstrap completed");
    drop(bootstrap);
    drop(protocol);
    drop(joining_owner);
    endpoint.close().await;
    drop(endpoint);
    b.config.idp.oauth2.local_signer = Some(binding.clone());
    management_server::provision_initial_device(&b.config.management, binding.member_id, owner)
        .await
        .expect("explicit ready local Device policy");
    let joined_runtime = UnifiedRuntime::build(b.config.clone())
        .await
        .expect("complete joined IdP Management Storage composition");
    assert!(
        joined_runtime
            .node_join_public_ready()
            .await
            .expect("durable actual join receipt")
    );
    let joined = Host::start(joined_runtime).await;
    assert_eq!(
        joined.runtime().endpoint_id().to_string(),
        binding.endpoint_id
    );
    joined
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Slice {
    Offline,
    Grants,
    Restrictions,
}

struct Pair {
    source: Host,
    joined: Host,
    a: Fixture,
    b: Fixture,
    http: reqwest::Client,
    owner: Id,
    member_a: Id,
    key_a: Id,
    login_id: String,
    shared: TokenResponse,
    grants: Option<(TokenResponse, TokenResponse)>,
    started: std::time::Instant,
}

impl Pair {
    async fn new(slice: Slice) -> Self {
        let started = std::time::Instant::now();
        let mut a = Fixture::new();
        let mut b = Fixture::new();
        for credential in [
            &mut b.config.management_idp_client,
            &mut b.config.storage_idp_client,
            &mut b.config.storage_management_client,
            b.config
                .idp_management_client
                .as_mut()
                .expect("local evaluator"),
        ] {
            credential.client_secret = format!("node-b-{}", Id::now_v7());
        }
        b.config.idp.oauth2.issuer = a.config.idp.oauth2.issuer.clone();
        a.config.idp.key_namespace = format!("full-node-a-{}", Id::now_v7());
        b.config.idp.key_namespace = format!("full-node-b-{}", Id::now_v7());
        let stores = Arc::new(NodeStores {
            stores: [
                (a.config.idp.key_namespace.clone(), a.store.clone()),
                (b.config.idp.key_namespace.clone(), b.store.clone()),
            ],
        });
        let _ = PrivateKeyKeyringRepo::new_with_store(&a.config.idp.oauth2.issuer, stores);
        let roots = [
            &a.config.idp.data_dir,
            &a.config.management.data_dir,
            &a.config.storage.data_dir,
            &b.config.idp.data_dir,
            &b.config.management.data_dir,
            &b.config.storage.data_dir,
        ];
        for (index, root) in roots.iter().enumerate() {
            assert!(
                !roots[..index].contains(root),
                "each context has its own root"
            );
        }
        assert_ne!(a.config.endpoint_data_dir, b.config.endpoint_data_dir);
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("bounded loopback owner HTTP client");
        let mut local =
            LocalProvisioner::create(a.config.clone(), "operator", "Node A", &a.password)
                .expect("one fresh Installation");
        local
            .provision(&a.password)
            .await
            .expect("production restricted local provisioning");
        let journal = a.journal();
        assert_eq!(journal["complete"], true);
        let owner = journal["user"]
            .as_str()
            .expect("initial User")
            .parse()
            .expect("User ID");
        let member_a = journal["member"]
            .as_str()
            .expect("initial member")
            .parse()
            .expect("member ID");
        let key_a = journal["key"]
            .as_str()
            .expect("initial signer")
            .parse()
            .expect("key ID");
        let login = rotation_login_client(
            &a,
            vec![
                GrantType::Password,
                GrantType::RefreshToken,
                GrantType::TokenExchange,
            ],
            vec![
                a.config.storage_idp_client.audience.clone(),
                management_service::MANAGEMENT_APPLICATION_URI.into(),
                "storage:filesystems".into(),
            ],
        )
        .await;
        let login_id = login.client_id.expect("public login Client");
        if slice != Slice::Grants {
            let management = Arc::new(
                db::Database::open(a.root.join("management/management.redb"))
                    .expect("public Management fixture owner"),
            );
            let policy = ManagementService::new(
                DbPermissionRepo::new(management.clone()),
                DbRoleRepo::new(management),
            );
            let role = journal["role"]
                .as_str()
                .expect("retained administrator role")
                .parse()
                .expect("role ID");
            for action in [
                IdentityAction::DeviceRestrictionsRead,
                IdentityAction::DeviceRestrictionsUpdate,
            ] {
                let permission = policy
                    .create_permission(INSTALLATION_POLICY_ID, action.permission(), None)
                    .await
                    .expect("explicit Installation restriction permission");
                policy
                    .add_permission_to_role(INSTALLATION_POLICY_ID, role, permission.id)
                    .await
                    .expect("attach exact requested permission to existing administrator role");
            }
        }
        eprintln!(
            "08 {slice:?}: source fixture ready at {:?}",
            started.elapsed()
        );
        let source = Host::start(local.build_runtime().await.expect("completed source host")).await;
        drop(local);
        let password_form = [
            ("grant_type", "password"),
            ("client_id", login_id.as_str()),
            ("username", "operator"),
            ("password", "fixture-initial-password"),
            ("scope", "openid"),
        ];
        let shared = token(&http, &source, &password_form).await;
        let grants = if slice == Slice::Grants {
            Some((
                token(&http, &source, &password_form).await,
                token(&http, &source, &password_form).await,
            ))
        } else {
            None
        };
        let approving = exchange(
            &http,
            &source,
            &login_id,
            &shared.access_token.0,
            &a.config.storage_idp_client.audience,
        )
        .await;
        source
            .runtime()
            .node_join_accepting(&approving, Some(true))
            .await
            .expect("authorized purpose-specific join acceptance");
        eprintln!(
            "08 {slice:?}: entering authenticated join at {:?}",
            started.elapsed()
        );
        let joined = join_host(&source, &mut b, owner, &journal, &approving).await;
        source
            .runtime()
            .node_join_accepting(&approving, Some(false))
            .await
            .expect("close purpose-specific pairing acceptance");
        let secrets_a = a.secrets();
        let secrets_b = b.secrets();
        assert!(!secrets_a.is_empty() && !secrets_b.is_empty());
        assert!(
            secrets_a.iter().all(|secret| !secrets_b.contains(secret)),
            "no copied/shared private material"
        );
        eprintln!(
            "08 {slice:?}: two completed full hosts; no DATA session at {:?}",
            started.elapsed()
        );
        Self {
            source,
            joined,
            a,
            b,
            http,
            owner,
            member_a,
            key_a,
            login_id,
            shared,
            grants,
            started,
        }
    }

    fn binding(&self) -> &NodeSignerBinding {
        self.b
            .config
            .idp
            .oauth2
            .local_signer
            .as_ref()
            .expect("retained joined binding")
    }

    async fn reconnect(&self, context: SecurityContext) {
        eprintln!(
            "08: reconnecting {context:?} at {:?}",
            self.started.elapsed()
        );
        let connection = self
            .joined
            .runtime()
            .full_node_test_server()
            .endpoint()
            .connect(
                self.source
                    .runtime()
                    .full_node_test_server()
                    .endpoint()
                    .addr(),
                DATA_ALPN,
            )
            .await
            .expect("authenticated reconnect using persisted independent identities");
        assert_eq!(connection.remote_id(), self.source.runtime().endpoint_id());
        self.joined
            .runtime()
            .synchronize_security(&connection, context)
            .await
            .expect("learn current public owner state");
        connection.close(0u32.into(), b"focused reconciliation complete");
        eprintln!("08: reconciled {context:?} at {:?}", self.started.elapsed());
    }

    async fn stop(self) {
        tokio::join!(self.source.stop(), self.joined.stop());
        eprintln!("08: focused slice stopped at {:?}", self.started.elapsed());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_completed_full_hosts_join_partition_reopen_and_learn_denial() {
    tokio::time::timeout(Duration::from_secs(360), offline_reopen())
        .await
        .expect("bounded full-host offline slice");
}

async fn offline_reopen() {
    let pair = Pair::new(Slice::Offline).await;
    let grant = pair
        .shared
        .refresh_token
        .as_ref()
        .expect("shared learned refresh")
        .0
        .as_str();
    for (label, host) in [("source-A", &pair.source), ("joined-B", &pair.joined)] {
        eprintln!(
            "08 Offline: starting local concurrent race/replay for {label} at {:?}",
            pair.started.elapsed()
        );
        local_winner(&pair.http, host, &pair.login_id, grant).await;
        eprintln!(
            "08 Offline: finished local concurrent race/replay for {label} at {:?}",
            pair.started.elapsed()
        );
    }
    let endpoint_a = pair.source.runtime().endpoint_id();
    let endpoint_b = pair.joined.runtime().endpoint_id();
    let secrets_a = pair.a.secrets();
    let secrets_b = pair.b.secrets();
    let Pair {
        source,
        joined,
        a,
        b,
        http,
        owner,
        member_a,
        key_a,
        login_id,
        shared,
        started,
        ..
    } = pair;
    tokio::join!(source.stop(), joined.stop());
    eprintln!(
        "08 Offline: stopped; opening retained hosts at {:?}",
        started.elapsed()
    );
    let (reopened_a, reopened_b) = tokio::join!(
        LocalProvisioner::open_runtime(a.config.clone()),
        LocalProvisioner::open_runtime(b.config.clone())
    );
    let (runtime_a, guard_a) = reopened_a.expect("completed source offline reopen");
    let (runtime_b, guard_b) = reopened_b.expect("completed joined existing-only offline reopen");
    assert!(guard_a.is_some());
    assert!(
        guard_b.is_none(),
        "joining does not invent an unrelated Installation journal"
    );
    assert_eq!(runtime_a.endpoint_id(), endpoint_a);
    assert_eq!(runtime_b.endpoint_id(), endpoint_b);
    assert!(
        runtime_b
            .node_join_public_ready()
            .await
            .expect("joined completion survives offline restart")
    );
    assert_eq!(secrets_a, a.secrets());
    assert_eq!(secrets_b, b.secrets());
    let source = Host::start(runtime_a).await;
    let joined = Host::start(runtime_b).await;
    drop(guard_a);
    eprintln!(
        "08 Offline: both reopened without DATA sessions at {:?}",
        started.elapsed()
    );
    let grant = shared
        .refresh_token
        .as_ref()
        .expect("shared learned refresh")
        .0
        .as_str();
    for host in [&source, &joined] {
        denied_grant(refresh(&http, host, &login_id, grant).await).await;
        let jwks = json(
            http.get(format!("{}/idp/.well-known/jwks.json", host.base))
                .send()
                .await
                .expect("local approved JWKS"),
            reqwest::StatusCode::OK,
        )
        .await;
        for key in [
            key_a.to_string(),
            b.config
                .idp
                .oauth2
                .local_signer
                .as_ref()
                .expect("joined signer")
                .key_id
                .to_string(),
        ] {
            assert!(
                jwks["keys"]
                    .as_array()
                    .expect("JWKS keys")
                    .iter()
                    .any(|jwk| jwk["kid"] == key)
            );
        }
    }
    for (host, fixture, remote, local, label) in [
        (
            &source,
            &a,
            b.config
                .idp
                .oauth2
                .local_signer
                .as_ref()
                .expect("joined member")
                .member_id,
            member_a,
            "offline-a",
        ),
        (
            &joined,
            &b,
            member_a,
            b.config
                .idp
                .oauth2
                .local_signer
                .as_ref()
                .expect("joined member")
                .member_id,
            "offline-b",
        ),
    ] {
        let actor = exchange(
            &http,
            host,
            &login_id,
            &shared.access_token.0,
            &fixture.config.storage_idp_client.audience,
        )
        .await;
        let updated = json(
            http.put(format!("{}/idp/users/{owner}", host.base))
                .bearer_auth(&actor)
                .json(&serde_json::json!({"name": label}))
                .send()
                .await
                .expect("independent offline identity mutation"),
            reqwest::StatusCode::OK,
        )
        .await;
        assert_eq!(updated["name"], label);
        let credential = &fixture.config.storage_idp_client;
        let issued = token(
            &http,
            host,
            &[
                ("grant_type", "client_credentials"),
                ("client_id", &credential.client_id),
                ("client_secret", &credential.client_secret),
                ("audience", &credential.audience),
                (
                    "scope",
                    "idp.token.validate idp.device.lookup idp.device.list",
                ),
            ],
        )
        .await;
        assert_eq!(
            issued.issuer.as_deref(),
            Some(a.config.idp.oauth2.issuer.as_str())
        );
        let policy = exchange(
            &http,
            host,
            &login_id,
            &shared.access_token.0,
            management_service::MANAGEMENT_APPLICATION_URI,
        )
        .await;
        restriction(&http, host, &policy, remote, false).await;
        assert_restriction(&http, host, &policy, local, true).await;
        let storage = exchange(
            &http,
            host,
            &login_id,
            &shared.access_token.0,
            "storage:filesystems",
        )
        .await;
        let (resource, mut connection) = create_written_resource(&http, host, &storage).await;
        connection
            .close(None)
            .await
            .expect("close offline resource connection");
        delete_resource(&http, host, &storage, &resource).await;
        eprintln!(
            "08 Offline: identity/policy/resource/user+client issuance completed for {label} at {:?}",
            started.elapsed()
        );
    }
    tokio::join!(source.stop(), joined.stop());
    eprintln!("08 Offline: complete at {:?}", started.elapsed());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_completed_full_hosts_reconcile_consumption_and_revocation() {
    tokio::time::timeout(Duration::from_secs(360), learned_grants())
        .await
        .expect("bounded full-host IdP reconciliation slice");
}

async fn learned_grants() {
    let pair = Pair::new(Slice::Grants).await;
    let (consumed, revoked) = pair.grants.as_ref().expect("pre-bootstrap public grants");
    let shared_grant = pair
        .shared
        .refresh_token
        .as_ref()
        .expect("shared learned refresh")
        .0
        .as_str();
    let consumed_grant = consumed
        .refresh_token
        .as_ref()
        .expect("consumption target")
        .0
        .as_str();
    let revoked_grant = revoked
        .refresh_token
        .as_ref()
        .expect("revocation target")
        .0
        .as_str();
    assert_ne!(shared_grant, consumed_grant);
    assert_ne!(consumed_grant, revoked_grant);
    for host in [&pair.source, &pair.joined] {
        json(
            refresh(&pair.http, host, &pair.login_id, shared_grant).await,
            reqwest::StatusCode::OK,
        )
        .await;
        denied_grant(refresh(&pair.http, host, &pair.login_id, shared_grant).await).await;
    }
    json(
        refresh(&pair.http, &pair.source, &pair.login_id, consumed_grant).await,
        reqwest::StatusCode::OK,
    )
    .await;
    let revocation = pair
        .http
        .post(format!("{}/idp/oauth2/revoke", pair.source.base))
        .form(&[
            ("client_id", pair.login_id.as_str()),
            ("token", revoked_grant),
            ("token_type_hint", "refresh_token"),
        ])
        .send()
        .await
        .expect("real local refresh revocation");
    assert!(revocation.status().is_success());
    denied_grant(refresh(&pair.http, &pair.source, &pair.login_id, consumed_grant).await).await;
    denied_grant(refresh(&pair.http, &pair.source, &pair.login_id, revoked_grant).await).await;
    pair.reconnect(SecurityContext::Idp).await;
    denied_grant(refresh(&pair.http, &pair.joined, &pair.login_id, consumed_grant).await).await;
    denied_grant(refresh(&pair.http, &pair.joined, &pair.login_id, revoked_grant).await).await;
    pair.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_completed_full_hosts_learn_restrictions_on_retained_sockets() {
    tokio::time::timeout(Duration::from_secs(360), learned_restrictions())
        .await
        .expect("bounded full-host Management reconciliation slice");
}

async fn learned_restrictions() {
    let pair = Pair::new(Slice::Restrictions).await;
    let mut retained = Vec::new();
    for (host, local, remote) in [
        (&pair.source, pair.member_a, pair.binding().member_id),
        (&pair.joined, pair.binding().member_id, pair.member_a),
    ] {
        let policy = exchange(
            &pair.http,
            host,
            &pair.login_id,
            &pair.shared.access_token.0,
            management_service::MANAGEMENT_APPLICATION_URI,
        )
        .await;
        restriction(&pair.http, host, &policy, remote, false).await;
        assert_restriction(&pair.http, host, &policy, local, true).await;
        let storage = exchange(
            &pair.http,
            host,
            &pair.login_id,
            &pair.shared.access_token.0,
            "storage:filesystems",
        )
        .await;
        let (resource, connection) = create_written_resource(&pair.http, host, &storage).await;
        retained.push((policy, storage, resource, connection));
    }
    pair.reconnect(SecurityContext::Management).await;
    for ((host, member), (policy, storage, resource, mut connection)) in [
        (&pair.source, pair.member_a),
        (&pair.joined, pair.binding().member_id),
    ]
    .into_iter()
    .zip(retained)
    {
        assert_restriction(&pair.http, host, &policy, member, false).await;
        send(
            &mut connection,
            StorageRequest::Write {
                path: "retained.txt".into(),
                content: b"must deny after learned restriction".to_vec(),
            },
        )
        .await;
        loop {
            match connection.next().await {
                Some(Ok(Message::Text(body))) => {
                    assert!(matches!(
                        serde_json::from_str::<StorageResponse>(&body)
                            .expect("subsequent-operation response"),
                        StorageResponse::Error { .. }
                    ));
                    break;
                }
                Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
                frame => panic!("unexpected denied operation frame: {frame:?}"),
            }
        }
        drop(connection);
        restriction(&pair.http, host, &policy, member, true).await;
        let mut reader = socket(host, &storage, &resource).await;
        send(
            &mut reader,
            StorageRequest::Read {
                path: "retained.txt".into(),
            },
        )
        .await;
        assert_eq!(
            response(&mut reader).await,
            StorageResponse::Read {
                content: b"committed offline".to_vec()
            }
        );
        reader
            .close(None)
            .await
            .expect("close restored resource connection");
        delete_resource(&pair.http, host, &storage, &resource).await;
    }
    pair.stop().await;
}

async fn delete_resource(http: &reqwest::Client, host: &Host, bearer: &str, resource: &str) {
    let url = format!("{}/storage/filesystems/{resource}", host.base);
    assert_eq!(
        http.delete(&url)
            .bearer_auth(bearer)
            .send()
            .await
            .expect("ordinary public owner resource cleanup")
            .status(),
        reqwest::StatusCode::NO_CONTENT
    );
    assert_eq!(
        http.get(url)
            .bearer_auth(bearer)
            .send()
            .await
            .expect("local deletion receipt")
            .status(),
        reqwest::StatusCode::NOT_FOUND
    );
}
