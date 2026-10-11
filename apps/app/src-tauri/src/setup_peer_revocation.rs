use std::path::Path;

use idp_model::model::Id;
use serde_json::Value;

use super::{parse_setup_ids, reset};

pub(super) fn client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(15))
}

pub(super) async fn revoke(
    data: &Path,
    local_api: &str,
    peer_api: &str,
    bearer: &str,
    member_id: Id,
    client: &reqwest::Client,
) -> Result<(), String> {
    if let Ok(references) = reset::recovery_references(data) {
        let ids = parse_setup_ids(&references["ids"]).map_err(|error| error.to_string())?;
        if ids.member_id == member_id {
            reset::queue_revocation(data, &references).map_err(|error| error.to_string())?;
        }
    }
    let target = reset::revocations(data)
        .map_err(|error| error.to_string())?
        .into_iter()
        .find(|target| target["member_id"] == member_id.to_string())
        .ok_or("no retained public revocation target for this member")?;
    if peer_api == local_api {
        return Err(
            "revocation must be acknowledged by a surviving peer, not this local Node".into(),
        );
    }
    let url = reqwest::Url::parse(peer_api).map_err(|error| error.to_string())?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/idp"
        || url.as_str() != peer_api
        || bearer.trim().is_empty()
    {
        return Err(
            "select a trusted HTTPS peer IdP base URL and an authorized User session".into(),
        );
    }
    let metadata: Value = client
        .get(format!("{peer_api}/.well-known/openid-configuration"))
        .send()
        .await
        .map_err(|error| error.to_string())?
        .error_for_status()
        .map_err(|error| error.to_string())?
        .json()
        .await
        .map_err(|error| error.to_string())?;
    if metadata["issuer"] != target["issuer"] {
        return Err("peer belongs to a different Installation; no bearer was sent".into());
    }
    let token: Value = client
        .post(format!("{peer_api}/oauth2/token"))
        .form(&[
            (
                "grant_type",
                "urn:ietf:params:oauth:grant-type:token-exchange",
            ),
            (
                "subject_token_type",
                "urn:ietf:params:oauth:token-type:access_token",
            ),
            ("subject_token", bearer),
            ("resource", peer_api),
        ])
        .send()
        .await
        .map_err(|error| error.to_string())?
        .error_for_status()
        .map_err(|error| format!("peer User audience exchange denied; target retained: {error}"))?
        .json()
        .await
        .map_err(|error| error.to_string())?;
    let access_token = token["access_token"]
        .as_str()
        .filter(|token| !token.is_empty())
        .ok_or("peer did not return an authorized User access token; target retained")?;
    for path in [
        format!("replica-signers/{member_id}"),
        format!("devices/{member_id}"),
    ] {
        client.delete(format!("{peer_api}/{path}")).bearer_auth(access_token).send().await
            .map_err(|error| error.to_string())?.error_for_status().map_err(|error| {
                format!("peer revocation incomplete; public target retained for later authorized retry: {error}")
            })?;
    }
    reset::acknowledge_revocation(data, &target).map_err(|error| error.to_string())
}
