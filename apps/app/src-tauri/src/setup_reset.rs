use std::{fs, future::Future, io, io::Write, path::Path};

use serde_json::{Value, json};

use super::{SetupIds, parse_setup_ids, read_setup_ids, read_setup_intent};

pub(super) const JOURNAL: &str = "reset-state.json";
const TEMPORARY: &str = ".reset-state.tmp";
const REFERENCES: &str = "setup-reference-backup.json";
const PROVISIONING: &str = "setup-provisioning.json";
const DATA_PATHS: [&str; 10] = [
    "lidp.redb",
    "vaults",
    "storage-residency.json",
    "services",
    "setup-ready",
    "device-setup-ready",
    "https-port",
    "node-setup.json",
    "setup-ids.json",
    "reset-pending",
];

pub(super) struct ResetSecrets {
    pub ids: SetupIds,
    pub issuer: String,
}

fn optional_json(path: &Path) -> io::Result<Option<Value>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => {
            Ok(Some(serde_json::from_slice(&fs::read(path)?)?))
        }
        Ok(_) => Err(io::Error::other(
            "reset references must be regular files; explicit recovery required",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn exists(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn validate(record: &Value) -> io::Result<()> {
    let fields = record
        .as_object()
        .ok_or_else(|| io::Error::other("invalid reset journal"))?;
    if fields.len() != 4
        || !["version", "phase", "issuer", "ids"]
            .iter()
            .all(|key| fields.contains_key(*key))
        || record["version"] != 1
        || !matches!(
            record["phase"].as_str(),
            Some("secrets-pending" | "data-pending" | "complete")
        )
    {
        return Err(io::Error::other(
            "invalid reset journal; explicit recovery required",
        ));
    }
    if !record["ids"].is_null() {
        parse_setup_ids(&record["ids"])?;
    }
    if let Some(issuer) = record["issuer"].as_str() {
        super::validate_setup_intent(&json!({"purpose": "create", "issuer": issuer}))?;
        if record["ids"].is_null() {
            return Err(io::Error::other(
                "reset issuer has no retained secret references",
            ));
        }
    } else if !record["issuer"].is_null() || record["phase"] == "secrets-pending" {
        return Err(io::Error::other(
            "pending secret deletion requires a retained canonical issuer",
        ));
    }
    Ok(())
}

fn sync_directory(path: &Path) -> io::Result<()> {
    match fs::File::open(path) {
        Ok(directory) => directory.sync_all(),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn write(
    record: &Value,
    directory: &Path,
    checkpoint: &mut impl FnMut(&str) -> io::Result<()>,
) -> io::Result<()> {
    validate(record)?;
    let phase = record["phase"].as_str().expect("validated reset phase");
    let temporary = directory.join(TEMPORARY);
    if exists(&temporary)? {
        if !fs::symlink_metadata(&temporary)?.file_type().is_file() {
            return Err(io::Error::other(
                "reset temporary journal is not a regular file",
            ));
        }
        checkpoint(&format!("{phase}:temporary-before-unlink"))?;
        fs::remove_file(&temporary)?;
        checkpoint(&format!("{phase}:temporary-unlinked"))?;
        sync_directory(directory)?;
        checkpoint(&format!("{phase}:temporary-directory-synced"))?;
    }
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    checkpoint(&format!("{phase}:created"))?;
    file.write_all(&serde_json::to_vec(record)?)?;
    checkpoint(&format!("{phase}:written"))?;
    file.sync_all()?;
    checkpoint(&format!("{phase}:file-synced"))?;
    fs::rename(&temporary, directory.join(JOURNAL))?;
    checkpoint(&format!("{phase}:published"))?;
    sync_directory(directory)?;
    checkpoint(&format!("{phase}:directory-synced"))
}

fn begin_with(
    data: &Path,
    config: &Path,
    checkpoint: &mut impl FnMut(&str) -> io::Result<()>,
) -> io::Result<Value> {
    if let Some(record) = optional_json(&data.join(JOURNAL))? {
        validate(&record)?;
        // Publication may have been interrupted before its parent directory sync.
        sync_directory(data)?;
        return Ok(record);
    }
    let ids = optional_json(&data.join("setup-ids.json"))?;
    if ids.is_some() {
        read_setup_ids(&data.join("setup-ids.json"))?;
    }
    let intent = optional_json(&data.join("node-setup.json"))?;
    let issuer = match intent {
        Some(_) => {
            if ids.is_none() {
                return Err(io::Error::other(
                    "setup intent has lost secret references; explicit recovery required",
                ));
            }
            Some(
                read_setup_intent(data)?["issuer"]
                    .as_str()
                    .expect("validated issuer")
                    .to_owned(),
            )
        }
        None => {
            if exists(&data.join(REFERENCES))? || owner_state_exists(data, config)? {
                return Err(io::Error::other(
                    "owner state or retained references without canonical setup intent; explicit recovery required",
                ));
            }
            if let Some(stage) = optional_json(&data.join(PROVISIONING))? {
                let checked = read_provisioning(data, &stage["intent"])?
                    .expect("present provisioning record");
                if checked["phase"] != "not-started" {
                    return Err(io::Error::other(
                        "attempted provisioning without intent; explicit recovery required",
                    ));
                }
            }
            None
        }
    };
    let never_started = if issuer.is_some() {
        provisioning_never_started(data, config)?
    } else {
        true
    };
    let record = json!({"version": 1, "phase": if never_started { "data-pending" } else { "secrets-pending" }, "issuer": issuer, "ids": ids});
    fs::create_dir_all(data)?;
    if issuer.is_some() {
        retain(data)?;
    }
    write(&record, data, checkpoint)?;
    Ok(record)
}

fn provisioning_never_started(data: &Path, config: &Path) -> io::Result<bool> {
    Ok(read_provisioning(data, &read_setup_intent(data)?)?
        .is_some_and(|record| record["phase"] == "not-started")
        && !owner_state_exists(data, config)?)
}

fn owner_state_exists(data: &Path, config: &Path) -> io::Result<bool> {
    for path in [
        data.join("services"),
        data.join("vaults"),
        data.join("storage-residency.json"),
        data.join("setup-ready"),
        data.join("device-setup-ready"),
        data.join("lidp.redb"),
        config.join("lidp.redb"),
    ] {
        if exists(&path)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn provisioning_record(data: &Path, intent: &Value) -> io::Result<Value> {
    super::validate_setup_intent(intent)?;
    let ids = optional_json(&data.join("setup-ids.json"))?
        .ok_or_else(|| io::Error::other("missing provisioning identities"))?;
    parse_setup_ids(&ids)?;
    Ok(json!({"version": 1, "phase": "not-started", "ids": ids, "intent": intent}))
}

fn read_provisioning(data: &Path, intent: &Value) -> io::Result<Option<Value>> {
    let Some(record) = optional_json(&data.join(PROVISIONING))? else {
        return Ok(None);
    };
    let mut expected = provisioning_record(data, intent)?;
    if !matches!(record["phase"].as_str(), Some("not-started" | "attempted")) {
        return Err(io::Error::other(
            "invalid provisioning stage; explicit recovery required",
        ));
    }
    expected["phase"] = record["phase"].clone();
    if record != expected {
        return Err(io::Error::other(
            "provisioning references conflict; explicit recovery required",
        ));
    }
    sync_directory(data)?;
    Ok(Some(record))
}

fn publish_provisioning(data: &Path, record: &Value) -> io::Result<()> {
    let temporary = data.join(format!(
        ".setup-provisioning-{}.tmp",
        idp_model::model::Id::now_v7()
    ));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    file.write_all(&serde_json::to_vec(record)?)?;
    file.sync_all()?;
    fs::rename(temporary, data.join(PROVISIONING))?;
    sync_directory(data)?;
    if optional_json(&data.join(PROVISIONING))?.as_ref() != Some(record) {
        return Err(io::Error::other("provisioning stage readback failed"));
    }
    Ok(())
}

pub(super) fn prepare_provisioning(data: &Path, intent: &Value) -> io::Result<()> {
    if read_provisioning(data, intent)?.is_some() {
        return Ok(());
    }
    if exists(&data.join(REFERENCES))? || owner_state_exists(data, data)? {
        return Err(io::Error::other(
            "owner state without provisioning evidence; explicit recovery required",
        ));
    }
    publish_provisioning(data, &provisioning_record(data, intent)?)
}

pub(super) fn start_provisioning(data: &Path) -> io::Result<()> {
    if exists(&data.join(JOURNAL))? {
        return Err(io::Error::other(
            "local reset is pending; retry reset before provisioning",
        ));
    }
    let intent = read_setup_intent(data)?;
    let Some(mut record) = read_provisioning(data, &intent)? else {
        // Existing intents have no proof that owner work never started.
        if !fs::symlink_metadata(data.join("services/idp/idp.redb"))
            .map(|metadata| metadata.file_type().is_file())
            .unwrap_or(false)
        {
            return Err(io::Error::other(
                "unknown provisioning progress and missing owner metadata; restore independently verified metadata before reset",
            ));
        }
        return Ok(());
    };
    if record["phase"] == "not-started" && owner_state_exists(data, data)? {
        return Err(io::Error::other(
            "owner state conflicts with never-started provisioning; explicit recovery required",
        ));
    }
    if record["phase"] == "attempted"
        && !fs::symlink_metadata(data.join("services/idp/idp.redb"))
            .map(|metadata| metadata.file_type().is_file())
            .unwrap_or(false)
    {
        return Err(io::Error::other(
            "attempted provisioning has missing owner metadata; explicit recovery required",
        ));
    }
    record["phase"] = json!("attempted");
    publish_provisioning(data, &record)
}

pub(super) fn retain(data: &Path) -> io::Result<()> {
    let ids = optional_json(&data.join("setup-ids.json"))?
        .ok_or_else(|| io::Error::other("cannot retain missing setup identities"))?;
    parse_setup_ids(&ids)?;
    let intent = read_setup_intent(data)?;
    let record =
        json!({"version": 1, "phase": "secrets-pending", "issuer": intent["issuer"], "ids": ids});
    validate(&record)?;
    if let Some(existing) = optional_json(&data.join(REFERENCES))? {
        validate(&existing)?;
        if existing != record {
            return Err(io::Error::other(
                "retained reset references conflict; explicit recovery required",
            ));
        }
        return sync_directory(data);
    }
    let temporary = data.join(format!(
        ".setup-references-{}.tmp",
        idp_model::model::Id::now_v7()
    ));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    file.write_all(&serde_json::to_vec(&record)?)?;
    file.sync_all()?;
    fs::hard_link(&temporary, data.join(REFERENCES))?;
    sync_directory(data)?;
    fs::remove_file(temporary)?;
    sync_directory(data)
}

fn validate_revocation(record: &Value) -> io::Result<()> {
    if record.as_object().map(|fields| fields.len()) != Some(4)
        || record["version"] != 1
        || !matches!(record["status"].as_str(), Some("pending" | "acknowledged"))
    {
        return Err(io::Error::other("invalid retained revocation target"));
    }
    super::validate_setup_intent(&json!({"purpose": "create", "issuer": record["issuer"]}))?;
    super::parse_setup_id(&record["member_id"], "revoked member ID")?;
    Ok(())
}

pub(super) fn revocations(data: &Path) -> io::Result<Vec<Value>> {
    let directory = data.join("reset-revocations");
    if !exists(&directory)? {
        return Ok(Vec::new());
    }
    if !fs::symlink_metadata(&directory)?.file_type().is_dir() {
        return Err(io::Error::other(
            "revocation targets must be a local directory",
        ));
    }
    let mut records = Vec::new();
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path
            .extension()
            .is_some_and(|extension| extension == "json")
        {
            let record =
                optional_json(&path)?.ok_or_else(|| io::Error::other("lost revocation target"))?;
            validate_revocation(&record)?;
            if path.file_stem().and_then(|name| name.to_str()) != record["member_id"].as_str() {
                return Err(io::Error::other(
                    "revocation target filename conflicts with member",
                ));
            }
            records.push(record);
        }
    }
    Ok(records)
}

fn publish_revocation(data: &Path, record: &Value) -> io::Result<()> {
    validate_revocation(record)?;
    let directory = data.join("reset-revocations");
    fs::create_dir_all(&directory)?;
    if !fs::symlink_metadata(&directory)?.file_type().is_dir() {
        return Err(io::Error::other(
            "revocation targets must be a local directory",
        ));
    }
    let member = record["member_id"].as_str().expect("validated member ID");
    let path = directory.join(format!("{member}.json"));
    if let Some(existing) = optional_json(&path)? {
        validate_revocation(&existing)?;
        if existing["issuer"] != record["issuer"] || existing["member_id"] != record["member_id"] {
            return Err(io::Error::other("retained revocation target conflicts"));
        }
        if existing["status"] == "acknowledged" {
            return sync_directory(&directory);
        }
    }
    let temporary = directory.join(format!(".{}.tmp", idp_model::model::Id::now_v7()));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    file.write_all(&serde_json::to_vec(record)?)?;
    file.sync_all()?;
    fs::rename(temporary, path)?;
    sync_directory(&directory)?;
    sync_directory(data)
}

pub(super) fn queue_revocation(data: &Path, references: &Value) -> io::Result<()> {
    validate(references)?;
    if references["issuer"].is_null() {
        return Ok(());
    }
    let ids = parse_setup_ids(&references["ids"])?;
    publish_revocation(
        data,
        &json!({"version":1,"issuer": references["issuer"],"member_id":ids.member_id.to_string(),"status":"pending"}),
    )
}

pub(super) fn acknowledge_revocation(data: &Path, target: &Value) -> io::Result<()> {
    let mut record = target.clone();
    record["status"] = json!("acknowledged");
    publish_revocation(data, &record)
}

pub(super) fn recovery_references(data: &Path) -> io::Result<Value> {
    let record = optional_json(&data.join(REFERENCES))?
        .ok_or_else(|| io::Error::other("no durable reference backup; supply independently verified owner references before reset; no keys or journals were removed"))?;
    validate(&record)?;
    if record["phase"] != "secrets-pending" {
        return Err(io::Error::other("invalid reference backup phase"));
    }
    Ok(record)
}

pub(super) fn recover(data: &Path, config: &Path) -> io::Result<()> {
    let mut record = recovery_references(data)?;
    if let Ok(Some(ids)) = optional_json(&data.join("setup-ids.json"))
        && parse_setup_ids(&ids).is_ok()
        && ids != record["ids"]
    {
        return Err(io::Error::other(
            "valid setup identities conflict with backup; recovery refused",
        ));
    }
    if let Ok(intent) = read_setup_intent(data)
        && intent["issuer"] != record["issuer"]
    {
        return Err(io::Error::other(
            "valid Installation issuer conflicts with backup; recovery refused",
        ));
    }
    if let Ok(Some(current)) = optional_json(&data.join(JOURNAL))
        && validate(&current).is_ok()
    {
        if current["issuer"] != record["issuer"] || current["ids"] != record["ids"] {
            return Err(io::Error::other(
                "valid reset journal conflicts with backup; recovery refused",
            ));
        }
        return sync_directory(data);
    }
    if optional_json(&data.join("setup-ids.json"))
        .is_ok_and(|ids| ids.as_ref() == Some(&record["ids"]))
        && read_setup_intent(data).is_ok_and(|intent| intent["issuer"] == record["issuer"])
        && provisioning_never_started(data, config).unwrap_or(false)
    {
        record["phase"] = json!("data-pending");
    }
    let archive = data.join("reset-recovery");
    fs::create_dir_all(&archive)?;
    if !fs::symlink_metadata(&archive)?.file_type().is_dir() {
        return Err(io::Error::other(
            "recovery archive must be a local directory",
        ));
    }
    let attempt = archive.join(idp_model::model::Id::now_v7().to_string());
    fs::create_dir(&attempt)?;
    for name in [JOURNAL, TEMPORARY, "setup-ids.json", "node-setup.json"] {
        let path = data.join(name);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_file() => {
                let bytes = fs::read(&path)?;
                let mut copy = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(attempt.join(name))?;
                copy.write_all(&bytes)?;
                copy.sync_all()?;
            }
            Ok(_) => return Err(io::Error::other("recovery refuses non-regular references")),
            Err(error) if error.kind() == io::ErrorKind::NotFound => (),
            Err(error) => return Err(error),
        }
    }
    sync_directory(&attempt)?;
    sync_directory(&archive)?;
    sync_directory(data)?;
    write(&record, data, &mut |_| Ok(()))
}

pub(super) fn begin(data: &Path, config: &Path) -> io::Result<()> {
    begin_with(data, config, &mut |_| Ok(())).map(|_| ())
}

fn remove(
    path: &Path,
    label: &str,
    checkpoint: &mut impl FnMut(&str) -> io::Result<()>,
) -> io::Result<()> {
    checkpoint(&format!("{label}:before-unlink"))?;
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => fs::remove_dir_all(path)?,
        Ok(_) => fs::remove_file(path)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => (),
        Err(error) => return Err(error),
    }
    checkpoint(&format!("{label}:unlinked"))?;
    sync_directory(path.parent().expect("local reset path has a parent"))?;
    checkpoint(&format!("{label}:directory-synced"))
}

pub(super) async fn run<F: Future<Output = io::Result<()>>>(
    data: &Path,
    config: &Path,
    delete_secrets: impl FnOnce(ResetSecrets) -> F,
) -> io::Result<()> {
    run_with(data, config, delete_secrets, |_| Ok(())).await
}

async fn run_with<F: Future<Output = io::Result<()>>>(
    data: &Path,
    config: &Path,
    delete_secrets: impl FnOnce(ResetSecrets) -> F,
    mut checkpoint: impl FnMut(&str) -> io::Result<()>,
) -> io::Result<()> {
    let mut record = begin_with(data, config, &mut checkpoint)?;
    checkpoint("revocation:before-retain")?;
    queue_revocation(data, &record)?;
    checkpoint("revocation:retained")?;
    if record["phase"] == "secrets-pending" {
        let database = data.join("services/idp/idp.redb");
        if !fs::symlink_metadata(&database)
            .map(|metadata| metadata.file_type().is_file())
            .unwrap_or(false)
        {
            return Err(io::Error::other(
                "local IdP owner metadata is missing or non-regular; internal Client key references cannot be guessed. No database was recreated or secrets removed. Restore independently verified owner metadata before retrying reset",
            ));
        }
        checkpoint("secrets:before-delete")?;
        delete_secrets(ResetSecrets {
            ids: parse_setup_ids(&record["ids"])?,
            issuer: record["issuer"]
                .as_str()
                .expect("validated reset issuer")
                .to_owned(),
        })
        .await?;
        checkpoint("secrets:deleted")?;
        record["phase"] = json!("data-pending");
        write(&record, data, &mut checkpoint)?;
    }
    if record["phase"] == "data-pending" {
        for name in DATA_PATHS {
            remove(&data.join(name), name, &mut checkpoint)?;
        }
        remove(
            &config.join("lidp.redb"),
            "config/lidp.redb",
            &mut checkpoint,
        )?;
        record["phase"] = json!("complete");
        write(&record, data, &mut checkpoint)?;
    }
    remove(&data.join(PROVISIONING), PROVISIONING, &mut checkpoint)?;
    remove(&data.join(REFERENCES), REFERENCES, &mut checkpoint)?;
    remove(&data.join(JOURNAL), JOURNAL, &mut checkpoint)
}

#[cfg(test)]
mod tests {
    use std::{fs, process::Command};

    use idp_model::model::Id;
    use serde_json::json;

    use super::{DATA_PATHS, JOURNAL, run, run_with};

    fn fixture(root: &std::path::Path) -> super::Value {
        let data = root.join("data");
        let config = root.join("config");
        fs::create_dir_all(&config).expect("reset config");
        super::super::load_or_create_setup_ids(&data).expect("stable reset identities");
        super::super::persist_setup_intent(
            &data,
            &json!({"purpose":"create", "issuer":"https://reset.test/idp"}),
        )
        .expect("canonical issuer before owners");
        super::start_provisioning(&data).expect("durable attempt before owner work");
        fs::create_dir_all(data.join("services/idp")).expect("owner data");
        fs::write(data.join("services/idp/retained"), b"owner data").expect("owner fixture");
        fs::write(
            data.join("services/idp/idp.redb"),
            b"injected owner metadata",
        )
        .expect("retained metadata fixture, not a real database");
        for name in [
            "vaults",
            "storage-residency.json",
            "setup-ready",
            "device-setup-ready",
            "https-port",
            "reset-pending",
            "lidp.redb",
        ] {
            fs::write(data.join(name), b"local data").expect("unlink fixture");
        }
        fs::write(config.join("lidp.redb"), b"local legacy data").expect("config unlink fixture");
        fs::write(root.join("secret"), b"injected secret, not OS evidence")
            .expect("secret fixture");
        serde_json::from_slice(&fs::read(data.join("setup-ids.json")).expect("retained IDs"))
            .expect("ID snapshot")
    }

    #[tokio::test]
    async fn intent_before_owner_reset_reopens_and_completes_without_secret_deletion() {
        for intent in [
            json!({"purpose":"create", "issuer":"https://reset.test/idp"}),
            json!({"purpose":"join", "issuer":"https://reset.test/idp", "peer":"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "name":"Local Node"}),
        ] {
            let root = std::env::temp_dir().join(format!("reset-intent-only-{}", Id::now_v7()));
            let data = root.join("data");
            let config = root.join("config");
            super::super::load_or_create_setup_ids(&data).expect("stable setup identities");
            super::super::persist_setup_intent(&data, &intent)
                .expect("intent before owner opening");
            let references = super::recovery_references(&data).expect("durable backup");
            super::begin(&data, &config).expect("explicit reset publication");
            super::recover(&data, &config).expect("reopen exact reset references");
            assert_eq!(
                super::recovery_references(&data).expect("same identities"),
                references
            );
            run(&data, &config, |_| async {
                panic!("verified never-started provisioning must not open owners or delete secrets")
            })
            .await
            .expect("explicit intent-only reset must complete after reopen");
            assert!(!data.join(JOURNAL).exists());
            assert!(!data.join("services").exists());
            assert!(!data.join("node-setup.json").exists());
            super::super::load_or_create_setup_ids(&data)
                .expect("setup is available after explicit reset");
            super::super::persist_setup_intent(&data, &intent)
                .expect("normal provisioning seam accepts new setup");
            fs::remove_dir_all(root).expect("owned intent-only fixture cleanup");
        }
    }

    #[tokio::test]
    async fn intent_only_reset_recovers_absent_and_corrupt_journals_without_secret_deletion() {
        for corrupt in [false, true] {
            for intent in [
                json!({"purpose":"create", "issuer":"https://reset.test/idp"}),
                json!({"purpose":"join", "issuer":"https://reset.test/idp", "peer":"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "name":"Local Node"}),
            ] {
                let root =
                    std::env::temp_dir().join(format!("reset-journal-recovery-{}", Id::now_v7()));
                let data = root.join("data");
                let config = root.join("config");
                let ids = super::super::load_or_create_setup_ids(&data).expect("stable identities");
                super::super::persist_setup_intent(&data, &intent)
                    .expect("intent before owner work");
                let references = super::recovery_references(&data).expect("exact durable backup");
                super::begin(&data, &config).expect("explicit data-only reset");
                if corrupt {
                    fs::write(data.join(JOURNAL), b"corrupt reset journal")
                        .expect("corrupt journal");
                } else {
                    fs::remove_file(data.join(JOURNAL)).expect("lost journal");
                }
                super::recover(&data, &config).expect("explicit journal recovery");
                let recovered = super::optional_json(&data.join(JOURNAL))
                    .expect("read recovered journal")
                    .expect("durable journal");
                assert_eq!(
                    recovered["phase"], "data-pending",
                    "intact never-started proof must retain data-only disposition"
                );
                assert_eq!(recovered["ids"], references["ids"]);
                assert_eq!(recovered["issuer"], references["issuer"]);
                assert_eq!(
                    super::recovery_references(&data).expect("backup unchanged"),
                    references
                );
                assert_eq!(
                    super::super::load_or_create_setup_ids(&data)
                        .expect("same identities")
                        .installation_id,
                    ids.installation_id
                );
                assert!(super::start_provisioning(&data).is_err());
                let archives: Vec<_> = fs::read_dir(data.join("reset-recovery"))
                    .expect("recovery archive")
                    .map(|entry| entry.expect("archive entry").path())
                    .collect();
                assert_eq!(archives.len(), 1);
                if corrupt {
                    assert_eq!(
                        fs::read(archives[0].join(JOURNAL)).expect("corruption preserved"),
                        b"corrupt reset journal"
                    );
                } else {
                    assert!(!archives[0].join(JOURNAL).exists());
                }
                super::recover(&data, &config).expect("idempotent recovered journal reopen");
                run(&data, &config, |_| async {
                    panic!("verified never-started recovery must not open owners or delete secrets")
                })
                .await
                .expect("recovered explicit reset completes");
                assert!(!data.join(JOURNAL).exists());
                assert!(!data.join("services").exists());
                assert!(!data.join(super::REFERENCES).exists());
                super::super::load_or_create_setup_ids(&data)
                    .expect("fresh setup after explicit reset");
                super::super::persist_setup_intent(&data, &intent)
                    .expect("setup seam available again");
                fs::remove_dir_all(root).expect("owned journal-recovery fixture cleanup");
            }
        }
    }

    #[tokio::test]
    async fn journal_recovery_never_downgrades_attempted_unknown_or_contradictory_state() {
        for corrupt in [false, true] {
            for case in [
                "attempted",
                "missing-stage",
                "corrupt-stage",
                "conflicting-stage",
                "missing-ids",
                "corrupt-ids",
                "missing-intent",
                "corrupt-intent",
                "changed-purpose",
                "data-artifacts",
                "config-artifacts",
            ] {
                let root =
                    std::env::temp_dir().join(format!("reset-journal-unknown-{}", Id::now_v7()));
                let data = root.join("data");
                let config = root.join("config");
                super::super::load_or_create_setup_ids(&data).expect("stable identities");
                super::super::persist_setup_intent(
                    &data,
                    &json!({"purpose":"create", "issuer":"https://reset.test/idp"}),
                )
                .expect("retained intent");
                if case == "attempted" {
                    super::start_provisioning(&data).expect("durable attempt before reset");
                }
                super::begin(&data, &config).expect("explicit reset");
                match case {
                    "attempted" => (),
                    "missing-stage" => fs::remove_file(data.join(super::PROVISIONING)).expect("lost stage"),
                    "corrupt-stage" => fs::write(data.join(super::PROVISIONING), b"corrupt stage").expect("corrupt stage"),
                    "conflicting-stage" => {
                        let mut stage = super::optional_json(&data.join(super::PROVISIONING)).expect("stage JSON").expect("stage present");
                        stage["ids"]["member_id"] = json!(Id::now_v7().to_string());
                        fs::write(data.join(super::PROVISIONING), serde_json::to_vec(&stage).expect("conflict JSON")).expect("conflicting stage");
                    }
                    "missing-ids" => fs::remove_file(data.join("setup-ids.json")).expect("lost IDs"),
                    "corrupt-ids" => fs::write(data.join("setup-ids.json"), b"corrupt IDs").expect("corrupt IDs"),
                    "missing-intent" => fs::remove_file(data.join("node-setup.json")).expect("lost intent"),
                    "corrupt-intent" => fs::write(data.join("node-setup.json"), b"corrupt intent").expect("corrupt intent"),
                    "changed-purpose" => fs::write(data.join("node-setup.json"), serde_json::to_vec(&json!({"purpose":"join", "issuer":"https://reset.test/idp", "peer":"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "name":"Other intent"})).expect("changed intent JSON")).expect("changed intent"),
                    "data-artifacts" => fs::create_dir_all(data.join("services/idp")).expect("contradictory owner artifacts"),
                    "config-artifacts" => {
                        fs::create_dir_all(&config).expect("config directory");
                        fs::write(config.join("lidp.redb"), b"unknown owner metadata").expect("contradictory config artifacts");
                    }
                    _ => unreachable!(),
                }
                if corrupt {
                    fs::write(data.join(JOURNAL), b"corrupt reset journal")
                        .expect("corrupt journal");
                } else {
                    fs::remove_file(data.join(JOURNAL)).expect("lost journal");
                }
                let backup = fs::read(data.join(super::REFERENCES)).expect("backup bytes");
                super::recover(&data, &config)
                    .expect("reset-only reference recovery must remain conservative");
                let recovered = super::optional_json(&data.join(JOURNAL))
                    .expect("recovered JSON")
                    .expect("recovered journal");
                assert_eq!(
                    recovered["phase"], "secrets-pending",
                    "uncertain state must not become data-only: {case}, corrupt={corrupt}"
                );
                assert_eq!(
                    fs::read(data.join(super::REFERENCES)).expect("preserved backup"),
                    backup
                );
                assert!(super::start_provisioning(&data).is_err());
                run(&data, &config, |_| async {
                    panic!("lost owner metadata must not be recreated or guessed")
                })
                .await
                .expect_err("unknown secret cleanup still requires verified owner metadata");
                assert!(!data.join("services/idp/idp.redb").exists());
                assert!(data.join(JOURNAL).is_file());
                if case == "config-artifacts" {
                    assert_eq!(
                        fs::read(config.join("lidp.redb")).expect("config preserved"),
                        b"unknown owner metadata"
                    );
                }
                fs::remove_dir_all(root).expect("owned uncertain-journal fixture cleanup");
            }
        }
    }

    #[test]
    fn recovery_preserves_valid_reset_phases_even_with_never_started_proof() {
        for phase in ["secrets-pending", "data-pending", "complete"] {
            let root = std::env::temp_dir().join(format!("reset-journal-valid-{}", Id::now_v7()));
            let data = root.join("data");
            let config = root.join("config");
            super::super::load_or_create_setup_ids(&data).expect("stable identities");
            super::super::persist_setup_intent(
                &data,
                &json!({"purpose":"create", "issuer":"https://reset.test/idp"}),
            )
            .expect("retained intent");
            let mut record = super::recovery_references(&data).expect("same references");
            record["phase"] = json!(phase);
            let bytes = serde_json::to_vec(&record).expect("valid journal JSON");
            fs::write(data.join(JOURNAL), &bytes).expect("existing durable journal fixture");
            super::recover(&data, &config).expect("valid journal is authoritative");
            assert_eq!(
                fs::read(data.join(JOURNAL)).expect("journal unchanged"),
                bytes
            );
            assert!(!data.join("reset-recovery").exists());
            fs::remove_dir_all(root).expect("owned valid-journal fixture cleanup");
        }
    }

    #[tokio::test]
    async fn uncertain_provisioning_preserves_references_and_blocks_setup() {
        for case in [
            "attempted",
            "missing-stage",
            "corrupt-stage",
            "conflicting-stage",
            "unknown-owner",
        ] {
            let root = std::env::temp_dir().join(format!("reset-uncertain-{}", Id::now_v7()));
            let data = root.join("data");
            let config = root.join("config");
            super::super::load_or_create_setup_ids(&data).expect("stable identities");
            super::super::persist_setup_intent(
                &data,
                &json!({"purpose":"create", "issuer":"https://reset.test/idp"}),
            )
            .expect("intent before owners");
            match case {
                "attempted" => super::start_provisioning(&data).expect("attempt before owner open"),
                "missing-stage" => {
                    fs::remove_file(data.join(super::PROVISIONING)).expect("lost stage")
                }
                "corrupt-stage" => {
                    fs::write(data.join(super::PROVISIONING), b"corrupt").expect("corrupt stage")
                }
                "conflicting-stage" => {
                    let mut record = super::optional_json(&data.join(super::PROVISIONING))
                        .expect("stage")
                        .expect("present stage");
                    record["ids"]["member_id"] = json!(Id::now_v7().to_string());
                    fs::write(
                        data.join(super::PROVISIONING),
                        serde_json::to_vec(&record).expect("conflict JSON"),
                    )
                    .expect("conflict stage");
                }
                "unknown-owner" => {
                    fs::create_dir_all(data.join("services/idp")).expect("unexplained owner state")
                }
                _ => unreachable!(),
            }
            assert!(
                super::start_provisioning(&data).is_err(),
                "unknown progress must not recreate owner metadata before reset: {case}"
            );
            let before = fs::read(data.join("setup-ids.json")).expect("retained IDs");
            run(&data, &config, |_| async {
                panic!("uncertain metadata must not reach secret deletion")
            })
            .await
            .expect_err("uncertain state cannot use data-only reset");
            assert!(
                super::start_provisioning(&data).is_err(),
                "setup must not recreate unknown owner stores: {case}"
            );
            assert_eq!(
                fs::read(data.join("setup-ids.json")).expect("preserved IDs"),
                before
            );
            assert!(data.join(super::REFERENCES).is_file());
            assert!(!data.join("services/idp/idp.redb").exists());
            fs::remove_dir_all(root).expect("owned uncertainty fixture cleanup");
        }
    }

    #[tokio::test]
    async fn pending_client_without_row_reset_refuses_and_does_not_resume_provisioning() {
        let root = std::env::temp_dir().join(format!("reset-pending-client-{}", Id::now_v7()));
        let data = root.join("data");
        let config = root.join("config");
        let ids = super::super::load_or_create_setup_ids(&data).expect("stable identities");
        super::super::persist_setup_intent(
            &data,
            &json!({"purpose":"create", "issuer":"https://reset.test/idp"}),
        )
        .expect("retained intent");
        super::start_provisioning(&data).expect("durable owner attempt");
        let mut owner_config = idp_server::AppConfig {
            data_dir: data.join("services/idp").to_string_lossy().into_owned(),
            ..idp_server::AppConfig::default()
        };
        owner_config.oauth2.issuer = "https://reset.test/idp".into();
        let owner = idp_server::OwnerProvisioner::open(&owner_config)
            .await
            .expect("native owner metadata");
        owner
            .prepare_setup_client_slots(&super::super::setup_client_ids(&ids))
            .await
            .expect("durable Client slots");
        owner
            .begin_client_provisioning(&ids.installation_id.to_string())
            .await
            .expect("pending internal identity, no Client row");
        drop(owner);
        super::begin(&data, &config).expect("explicit reset");
        let error = run(&data, &config, |references| async move {
            let owner = idp_server::OwnerProvisioner::open(&owner_config).await?;
            owner
                .delete_local_secrets(
                    references.ids.member_id,
                    references.ids.signer_key_id,
                    references.ids.administrator_id,
                    &super::super::setup_client_ids(&references.ids),
                )
                .await
        })
        .await
        .expect_err("pending identity cannot be guessed or silently skipped");
        assert!(
            error
                .to_string()
                .contains("pending Client has lost internal key references")
        );
        assert!(super::start_provisioning(&data).is_err());
        assert!(data.join(JOURNAL).is_file());
        assert!(data.join(super::REFERENCES).is_file());
        assert!(data.join("services/idp/idp.redb").is_file());
        fs::remove_dir_all(root).expect("owned pending-Client fixture cleanup");
    }

    #[tokio::test]
    async fn lost_intent_after_attempt_is_not_reclassified_as_no_secrets() {
        let root = std::env::temp_dir().join(format!("reset-lost-intent-{}", Id::now_v7()));
        let data = root.join("data");
        let config = root.join("config");
        super::super::load_or_create_setup_ids(&data).expect("stable identities");
        super::super::persist_setup_intent(
            &data,
            &json!({"purpose":"create", "issuer":"https://reset.test/idp"}),
        )
        .expect("retained intent");
        super::start_provisioning(&data).expect("attempt published before any owner operation");
        fs::remove_file(data.join("node-setup.json")).expect("lost intent");
        run(&data, &config, |_| async {
            panic!("unknown secrets cannot be deleted")
        })
        .await
        .expect_err("lost intent cannot erase attempted provisioning evidence");
        assert!(data.join(super::REFERENCES).is_file());
        assert!(data.join(super::PROVISIONING).is_file());
        assert!(data.join("setup-ids.json").is_file());
        assert!(!data.join("services").exists());
        fs::remove_dir_all(root).expect("owned lost-intent fixture cleanup");
    }

    #[tokio::test]
    async fn lost_owner_metadata_preserves_secret_references_without_recreating_a_database() {
        let root = std::env::temp_dir().join(format!("reset-owner-loss-{}", Id::now_v7()));
        fixture(&root);
        let data = root.join("data");
        let config = root.join("config");
        super::begin(&data, &config).expect("capture reset prerequisites");
        fs::remove_file(data.join("services/idp/idp.redb")).expect("lose owner metadata");
        run(&data, &config, |_| async {
            panic!("lost owner metadata must not reach secret deletion or database creation")
        })
        .await
        .expect_err("unknown internal Client key namespaces require verified metadata recovery");
        assert!(data.join(JOURNAL).is_file());
        assert!(data.join("setup-reference-backup.json").is_file());
        assert!(!data.join("services/idp/idp.redb").exists());
        assert!(root.join("secret").is_file());
        fs::remove_dir_all(root).expect("remove owned loss fixture");
    }

    #[tokio::test]
    async fn explicit_recovery_preserves_corruption_and_never_restores_trust() {
        let root = std::env::temp_dir().join(format!("reset-reference-recovery-{}", Id::now_v7()));
        let ids = fixture(&root);
        let data = root.join("data");
        let config = root.join("config");
        super::begin(&data, &config).expect("retain durable deletion prerequisites");
        let mut wrong = ids.clone();
        wrong["member_id"] = json!(Id::now_v7().to_string());
        fs::write(
            data.join("setup-ids.json"),
            serde_json::to_vec(&wrong).expect("conflicting identities"),
        )
        .expect("conflicting valid references");
        assert!(super::recover(&data, &config).is_err());
        fs::write(
            data.join("setup-ids.json"),
            serde_json::to_vec(&ids).expect("exact backup"),
        )
        .expect("restore fixture references");
        fs::write(data.join("setup-ids.json"), b"corrupt ids").expect("corrupt references");
        fs::remove_file(data.join("node-setup.json")).expect("lose issuer reference");
        fs::write(data.join(JOURNAL), b"corrupt journal").expect("corrupt journal");
        assert!(super::begin(&data, &config).is_err());
        super::recover(&data, &config).expect("explicit reset-only recovery");
        assert_eq!(
            fs::read(data.join("setup-ids.json")).expect("original preserved"),
            b"corrupt ids"
        );
        assert!(!data.join("node-setup.json").exists());
        let record: super::Value = serde_json::from_slice(
            &fs::read(data.join(JOURNAL)).expect("recovered deletion journal"),
        )
        .expect("valid reset-only recovery");
        assert_eq!(record["ids"], ids);
        assert_eq!(record["phase"], "secrets-pending");
        assert!(data.join("reset-recovery").is_dir());
        let expected_ids = ids.clone();
        run(&data, &config, |references| async move {
            assert_eq!(
                references.ids.member_id.to_string(),
                expected_ids["member_id"].as_str().expect("member")
            );
            assert_eq!(references.issuer, "https://reset.test/idp");
            Ok(())
        })
        .await
        .expect("delete with recovered references, not new keys");
        assert!(!data.join("setup-reference-backup.json").exists());
        let targets = super::revocations(&data)
            .expect("public targets survive local secret and reference deletion");
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0]["member_id"], ids["member_id"]);
        assert_eq!(targets[0]["status"], "pending");
        assert_eq!(targets[0].as_object().expect("public fields only").len(), 4);
        super::acknowledge_revocation(&data, &targets[0])
            .expect("record later authorized peer acknowledgement");
        assert_eq!(
            super::revocations(&data).expect("retained acknowledgement")[0]["status"],
            "acknowledged"
        );
        assert!(data.join("reset-recovery").is_dir());
        fs::write(data.join(JOURNAL), b"unknown journal without backup")
            .expect("lost backup boundary");
        assert!(super::recover(&data, &config).is_err());
        assert_eq!(
            fs::read(data.join(JOURNAL)).expect("unknown journal preserved"),
            b"unknown journal without backup"
        );
        fs::remove_dir_all(root).expect("remove owned recovery fixture");
    }

    #[tokio::test]
    async fn ids_before_intent_reset_is_safe_but_unknown_owner_secrets_are_not_skipped() {
        let root = std::env::temp_dir().join(format!("reset-before-intent-{}", Id::now_v7()));
        let data = root.join("data");
        let config = root.join("config");
        super::super::load_or_create_setup_ids(&data).expect("interrupted before intent");
        run(&data, &config, |_| async {
            panic!("no owner/secure-store operation preceded intent")
        })
        .await
        .expect("safe explicit reset of ID-only preparation");
        assert!(!data.join("setup-ids.json").exists());
        super::super::load_or_create_setup_ids(&data).expect("new interrupted preparation");
        fs::create_dir_all(data.join("services/idp")).expect("unknown owner state");
        assert!(
            run(&data, &config, |_| async {
                panic!("cannot guess canonical issuer")
            })
            .await
            .is_err()
        );
        assert!(data.join("setup-ids.json").exists());
        fs::remove_dir_all(root).expect("reset fixture cleanup");
    }

    #[tokio::test]
    async fn reset_process_crash_at_every_journal_and_unlink_boundary_resumes() {
        let mut boundaries = Vec::new();
        for phase in ["secrets-pending", "data-pending", "complete"] {
            for point in [
                "created",
                "written",
                "file-synced",
                "published",
                "directory-synced",
            ] {
                boundaries.push(format!("{phase}:{point}"));
            }
        }
        boundaries.extend(["secrets:before-delete".into(), "secrets:deleted".into()]);
        for name in DATA_PATHS
            .into_iter()
            .chain(["config/lidp.redb", super::PROVISIONING, JOURNAL])
        {
            for point in ["before-unlink", "unlinked", "directory-synced"] {
                boundaries.push(format!("{name}:{point}"));
            }
        }
        assert_eq!(boundaries.len(), 56);
        for phase in ["secrets-pending", "data-pending", "complete"] {
            for point in [
                "temporary-before-unlink",
                "temporary-unlinked",
                "temporary-directory-synced",
            ] {
                boundaries.push(format!("{phase}:{point}"));
            }
        }
        assert_eq!(boundaries.len(), 65);
        for boundary in boundaries {
            let root = std::env::temp_dir().join(format!("reset-process-{}", Id::now_v7()));
            let expected_ids = fixture(&root);
            if boundary.contains(":temporary-") {
                let phase = boundary.split(':').next().expect("temporary cleanup phase");
                let first = Command::new(std::env::current_exe().expect("test executable"))
                    .args([
                        "--exact",
                        "app::reset::tests::crash_child",
                        "--ignored",
                        "--nocapture",
                        "--test-threads=1",
                    ])
                    .env("OF04_RESET_ROOT", &root)
                    .env("OF04_RESET_BOUNDARY", format!("{phase}:written"))
                    .status()
                    .expect("leave interrupted temporary journal");
                assert_eq!(first.code(), Some(73));
            }
            let status = Command::new(std::env::current_exe().expect("test executable"))
                .args([
                    "--exact",
                    "app::reset::tests::crash_child",
                    "--ignored",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env("OF04_RESET_ROOT", &root)
                .env("OF04_RESET_BOUNDARY", &boundary)
                .status()
                .expect("spawn reset process");
            assert_eq!(
                status.code(),
                Some(73),
                "production boundary must be reached: {boundary}"
            );
            let data = root.join("data");
            let secret = root.join("secret");
            let secret_ref = &secret;
            let boundary_ref = &boundary;
            let needs_secret_deletion = super::optional_json(&data.join(JOURNAL))
                .expect("authoritative journal")
                .is_none_or(|record| record["phase"] == "secrets-pending");
            run(&data, &root.join("config"), |references| async move {
                assert!(needs_secret_deletion, "data cleanup retry must not reopen owners or call secret deletion after {boundary_ref}");
                assert_eq!(references.issuer, "https://reset.test/idp");
                assert_eq!(
                    references.ids.installation_id.to_string(),
                    expected_ids["installation_id"]
                        .as_str()
                        .expect("expected stable installation")
                );
                if secret_ref.exists() {
                    fs::remove_file(secret_ref)?;
                }
                Ok(())
            })
            .await
            .unwrap_or_else(|error| panic!("retry after {boundary}: {error}"));
            assert!(
                !secret.exists(),
                "secret must be deleted before reset completes"
            );
            assert!(!data.join(JOURNAL).exists());
            assert!(!data.join("setup-ids.json").exists());
            assert!(!data.join("node-setup.json").exists());
            assert!(!data.join("services").exists());
            fs::remove_dir_all(root).expect("completed process fixture cleanup");
        }
    }

    #[tokio::test]
    #[ignore = "child process used by the reset crash boundary regression"]
    async fn crash_child() {
        let root = std::path::PathBuf::from(
            std::env::var_os("OF04_RESET_ROOT").expect("child reset root"),
        );
        let boundary = std::env::var("OF04_RESET_BOUNDARY").expect("child reset boundary");
        let root_ref = &root;
        run_with(
            &root.join("data"),
            &root.join("config"),
            |references| async move {
                assert_eq!(references.issuer, "https://reset.test/idp");
                if root_ref.join("secret").exists() {
                    fs::remove_file(root_ref.join("secret"))?;
                }
                Ok(())
            },
            |point| {
                if point == boundary {
                    std::process::exit(73);
                }
                Ok(())
            },
        )
        .await
        .expect("requested boundary must terminate the reset process");
        panic!("reset boundary was not visited");
    }
}
