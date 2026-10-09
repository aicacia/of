use std::{fs, future::Future, io, io::Write, path::Path};

use serde_json::{Value, json};

use super::{SetupIds, parse_setup_ids, read_setup_ids, read_setup_intent};

pub(super) const JOURNAL: &str = "reset-state.json";
const TEMPORARY: &str = ".reset-state.tmp";
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
                    return Err(io::Error::other(
                        "owner state without canonical reset references; explicit recovery required",
                    ));
                }
            }
            // Setup publishes intent before any owner or secure-store operation.
            None
        }
    };
    let record = json!({"version": 1, "phase": if issuer.is_some() { "secrets-pending" } else { "data-pending" }, "issuer": issuer, "ids": ids});
    fs::create_dir_all(data)?;
    write(&record, data, checkpoint)?;
    Ok(record)
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
    if record["phase"] == "secrets-pending" {
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
        fs::create_dir_all(data.join("services/idp")).expect("owner data");
        fs::write(data.join("services/idp/retained"), b"owner data").expect("owner fixture");
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
        for name in DATA_PATHS.into_iter().chain(["config/lidp.redb", JOURNAL]) {
            for point in ["before-unlink", "unlinked", "directory-synced"] {
                boundaries.push(format!("{name}:{point}"));
            }
        }
        assert_eq!(boundaries.len(), 53);
        for phase in ["secrets-pending", "data-pending", "complete"] {
            for point in [
                "temporary-before-unlink",
                "temporary-unlinked",
                "temporary-directory-synced",
            ] {
                boundaries.push(format!("{phase}:{point}"));
            }
        }
        assert_eq!(boundaries.len(), 62);
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
