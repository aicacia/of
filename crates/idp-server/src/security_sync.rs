use std::io;

use idp_model::model::Id;
use idp_service::{replica::DbReplicaSignerRepo, security_sync::PublicSecurityTable};
use iroh::endpoint::Connection;

/// Preflight a public projection from an authenticated peer. This is not apply
/// authorization or permission to exchange opaque CRDT documents/history.
pub async fn validate_public_security_record(
    trusted_local: &DbReplicaSignerRepo,
    connection: &Connection,
    local_installation: &str,
    claimed_member: Id,
    table: PublicSecurityTable,
    record: &serde_json::Map<String, serde_json::Value>,
    now: i64,
) -> io::Result<()> {
    if !trusted_local
        .is_trusted_peer(
            local_installation,
            claimed_member,
            &connection.remote_id().to_string(),
            now,
        )
        .await
        .map_err(io::Error::other)?
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "security record source is not a locally trusted Installation member",
        ));
    }
    if !table.permits_record(record) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "security record is not an allowlisted public projection",
        ));
    }
    if matches!(
        table,
        PublicSecurityTable::Members | PublicSecurityTable::Signers
    ) && (record.get("issuer").and_then(serde_json::Value::as_str) != Some(local_installation)
        || (table == PublicSecurityTable::Members
            && record
                .get("installation_id")
                .and_then(serde_json::Value::as_str)
                != Some(local_installation)))
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "security record belongs to another Installation",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{io::ErrorKind, sync::Arc};

    use idp_model::{
        contract::{
            IdpSignerRecord, JwkPublic, JwkPublicParameters, JwsAlgorithm, KeyUse,
            ReplicaMembership,
        },
        model::Id,
    };
    use idp_service::{replica::DbReplicaSignerRepo, security_sync::PublicSecurityTable};
    use iroh::{Endpoint, address_lookup::MemoryLookup, endpoint::presets};
    use iroh_chain::{DATA_ALPN, EndpointIdStore, Server};
    use management_service::{DeviceRepo, replica::DbDeviceRepo};

    use super::validate_public_security_record;

    #[tokio::test]
    async fn authenticated_security_projection_rechecks_local_trust_and_rejects_secrets() {
        let lookup = MemoryLookup::new();
        let local_endpoint = Endpoint::builder(presets::Minimal)
            .alpns(vec![DATA_ALPN.to_vec()])
            .address_lookup(lookup.clone())
            .bind()
            .await
            .expect("bind local endpoint");
        let remote = Endpoint::builder(presets::Minimal)
            .address_lookup(lookup.clone())
            .bind()
            .await
            .expect("bind remote endpoint");
        lookup.add_endpoint_info(local_endpoint.addr());
        let peers = EndpointIdStore::default();
        peers.add(remote.id());
        let server = Server::new(local_endpoint, peers);
        let (outgoing, incoming) =
            tokio::join!(remote.connect(server.endpoint().id(), DATA_ALPN), async {
                server
                    .endpoint()
                    .accept()
                    .await
                    .expect("incoming connection")
                    .accept()
                    .expect("accept authenticated connection")
                    .await
            });
        let outgoing = outgoing.expect("remote connects");
        let incoming = incoming.expect("local accepts");
        assert_eq!(incoming.remote_id(), remote.id());

        let root = std::env::temp_dir().join(format!("of-security-source-{}", Id::now_v7()));
        std::fs::create_dir_all(&root).expect("create isolated IdP store");
        let engine = Arc::new(db::Database::open(root.join("idp.redb")).expect("open IdP store"));
        idp_model::replica::up(&engine)
            .await
            .expect("initialize IdP");
        let devices = DbDeviceRepo::new(Arc::clone(&engine));
        let device = devices
            .create(
                "owner".into(),
                "peer".into(),
                remote.id().to_string(),
                "address".into(),
                Vec::new(),
                0,
            )
            .await
            .expect("approve initial local Device");
        let repo = DbReplicaSignerRepo::new(Arc::clone(&engine));
        let installation = "https://installation.example";
        let mut record: serde_json::Map<String, serde_json::Value> =
            PublicSecurityTable::Applications
                .columns()
                .iter()
                .map(|column| ((*column).into(), serde_json::Value::Null))
                .collect();
        record.insert("id".into(), serde_json::json!(Id::now_v7()));
        let error = validate_public_security_record(
            &repo,
            &incoming,
            installation,
            device.id,
            PublicSecurityTable::Applications,
            &record,
            20,
        )
        .await
        .expect_err("connection admission alone is not trusted domain provenance");
        assert_eq!(error.kind(), ErrorKind::PermissionDenied);

        let key_id = Id::now_v7();
        let member = ReplicaMembership {
            installation_id: installation.into(),
            member_id: device.id,
            endpoint_id: remote.id().to_string(),
            issuer: installation.into(),
            approved_at: 10,
            revoked_at: None,
        };
        let signer = IdpSignerRecord {
            member_id: device.id,
            key_id,
            issuer: installation.into(),
            public_jwk: JwkPublic {
                kid: key_id.to_string(),
                r#use: KeyUse::Signature,
                alg: JwsAlgorithm::ES256K,
                params: JwkPublicParameters::Ec {
                    crv: "secp256k1".into(),
                    x: "eb5mfvncu6xVoGKVzocLBwKb/NstzijZWfKBWxb4F5g".into(),
                    y: "SDradyajxGVdpPv8DhEIqP0XtEimhVQZnEfQj/sQ1Lg".into(),
                },
            },
            approved_at: Some(10),
            revoked_at: None,
            expires_at: None,
        };
        repo.enroll(&member, &signer)
            .await
            .expect("persist approved public member/signer");
        validate_public_security_record(
            &repo,
            &incoming,
            installation,
            device.id,
            PublicSecurityTable::Applications,
            &record,
            20,
        )
        .await
        .expect("approved peer may supply a valid public projection");
        for secret in [
            "password",
            "client_secret",
            "private_key",
            "client_secret_hash",
            "enrollment_code_hash",
            "history",
        ] {
            let mut injected = record.clone();
            injected.insert(secret.into(), serde_json::json!("secret"));
            assert_eq!(
                validate_public_security_record(
                    &repo,
                    &incoming,
                    installation,
                    device.id,
                    PublicSecurityTable::Applications,
                    &injected,
                    20
                )
                .await
                .expect_err("secret or opaque history must not enter projected records")
                .kind(),
                ErrorKind::InvalidData
            );
        }
        for (issuer, member_id) in [
            ("https://other.example", device.id),
            (installation, Id::now_v7()),
        ] {
            assert_eq!(
                validate_public_security_record(
                    &repo,
                    &incoming,
                    issuer,
                    member_id,
                    PublicSecurityTable::Applications,
                    &record,
                    20
                )
                .await
                .expect_err("forged Installation/member claims must not establish provenance")
                .kind(),
                ErrorKind::PermissionDenied
            );
        }
        drop(repo);
        drop(devices);
        drop(engine);
        let engine =
            Arc::new(db::Database::open(root.join("idp.redb")).expect("reopen isolated IdP store"));
        let repo = DbReplicaSignerRepo::new(engine);
        validate_public_security_record(
            &repo,
            &incoming,
            installation,
            device.id,
            PublicSecurityTable::Applications,
            &record,
            20,
        )
        .await
        .expect("trust survives local store reopen on the same authenticated connection");
        repo.revoke(device.id, installation, 21)
            .await
            .expect("learn local revocation");
        assert_eq!(
            validate_public_security_record(
                &repo,
                &incoming,
                installation,
                device.id,
                PublicSecurityTable::Applications,
                &record,
                22
            )
            .await
            .expect_err("learned revocation denies subsequent records on an existing connection")
            .kind(),
            ErrorKind::PermissionDenied
        );
        drop(repo);
        outgoing.close(0u32.into(), b"test complete");
        server.endpoint().close().await;
        remote.close().await;
        std::fs::remove_dir_all(root).expect("remove isolated IdP store");
    }
}
