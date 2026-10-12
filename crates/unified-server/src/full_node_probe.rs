use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use idp_model::{
    contract::{GrantType, INSTALLATION_POLICY_ID, IdentityAction},
    model::Id,
};
use management_service::{
    ManagementService,
    replica::{DbPermissionRepo, DbRoleRepo},
};

use super::{
    Fixture, Host, LocalProvisioner, denied_grant, exchange, refresh, rotation_login_client, token,
};

#[tokio::test]
async fn single_full_host_refresh_replay_and_restriction_put() {
    tokio::time::timeout(Duration::from_secs(120), probe())
        .await
        .expect("bounded single full-host request-path probe");
}

async fn probe() {
    let started = Instant::now();
    let fixture = Fixture::new();
    let mut provisioner = LocalProvisioner::create(
        fixture.config.clone(),
        "operator",
        "Local probe",
        &fixture.password,
    )
    .expect("fresh native Installation");
    provisioner
        .provision(&fixture.password)
        .await
        .expect("production local provisioning");
    let journal = fixture.journal();
    let member: Id = journal["member"]
        .as_str()
        .expect("local approved Device")
        .parse()
        .expect("Device ID");
    let role: Id = journal["role"]
        .as_str()
        .expect("administrator role")
        .parse()
        .expect("role ID");
    let login = rotation_login_client(
        &fixture,
        vec![
            GrantType::Password,
            GrantType::RefreshToken,
            GrantType::TokenExchange,
        ],
        vec![management_service::MANAGEMENT_APPLICATION_URI.into()],
    )
    .await;
    let client = login.client_id.expect("public login Client ID");
    {
        let engine = Arc::new(
            db::Database::open(fixture.root.join("management/management.redb"))
                .expect("stopped native Management owner"),
        );
        let service = ManagementService::new(
            DbPermissionRepo::new(engine.clone()),
            DbRoleRepo::new(engine),
        );
        for action in [
            IdentityAction::DeviceRestrictionsRead,
            IdentityAction::DeviceRestrictionsUpdate,
        ] {
            let permission = service
                .create_permission(INSTALLATION_POLICY_ID, action.permission(), None)
                .await
                .expect("explicit restriction grant");
            service
                .add_permission_to_role(INSTALLATION_POLICY_ID, role, permission.id)
                .await
                .expect("attach restriction grant to retained administrator");
        }
    }
    let host = Host::start(
        provisioner
            .build_runtime()
            .await
            .expect("production composed native runtime"),
    )
    .await;
    drop(provisioner);
    eprintln!(
        "08 probe: completed local full host at {:?}",
        started.elapsed()
    );
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("unchanged bounded owner HTTP client");
    let initial = token(
        &http,
        &host,
        &[
            ("grant_type", "password"),
            ("client_id", &client),
            ("username", "operator"),
            ("password", "fixture-initial-password"),
            ("scope", "openid"),
        ],
    )
    .await;
    let grant = initial
        .refresh_token
        .as_ref()
        .expect("issued refresh grant");
    let redeemed = refresh(&http, &host, &client, &grant.0).await;
    assert_eq!(redeemed.status(), reqwest::StatusCode::OK);
    let replacement: model::contract::TokenResponse =
        redeemed.json().await.expect("refresh replacement response");
    assert_ne!(
        replacement
            .refresh_token
            .expect("replacement refresh grant")
            .0,
        grant.0
    );
    eprintln!(
        "08 probe: redeem complete; entering replay at {:?}",
        started.elapsed()
    );
    denied_grant(refresh(&http, &host, &client, &grant.0).await).await;
    eprintln!(
        "08 probe: replay denied; entering Management token exchange at {:?}",
        started.elapsed()
    );
    let actor = exchange(
        &http,
        &host,
        &client,
        &initial.access_token.0,
        management_service::MANAGEMENT_APPLICATION_URI,
    )
    .await;
    let put_started = Instant::now();
    let result = http
        .put(format!(
            "{}/management/devices/{member}/restriction",
            host.base
        ))
        .bearer_auth(actor)
        .json(&serde_json::json!({"adminAllowed": false}))
        .send()
        .await;
    match &result {
        Ok(response) => eprintln!(
            "08 probe: local Device restriction PUT status={} elapsed={:?}",
            response.status(),
            put_started.elapsed()
        ),
        Err(error) => eprintln!(
            "08 probe: local Device restriction PUT transport failure timeout={} elapsed={:?}",
            error.is_timeout(),
            put_started.elapsed()
        ),
    }
    let response = result.expect("real composed Management restriction PUT");
    assert_eq!(response.status(), reqwest::StatusCode::NO_CONTENT);
    eprintln!(
        "08 probe: completed request assertions at {:?}",
        started.elapsed()
    );
    host.stop().await;
    eprintln!(
        "08 probe: managed shutdown complete at {:?}",
        started.elapsed()
    );
}
