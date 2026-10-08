use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    path::Path,
};

pub fn read(directory: &Path, name: &str, installation: &str) -> io::Result<bool> {
    let path = directory.join(name);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    if !metadata.file_type().is_file() || fs::read_to_string(path)?.trim() != installation {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "setup completion does not match the Installation",
        ));
    }
    Ok(true)
}

pub fn write(directory: &Path, name: &str, installation: &str) -> io::Result<()> {
    if read(directory, name, installation)? {
        return Ok(());
    }
    let temporary = directory.join(format!(".{name}-{installation}.tmp"));
    match fs::symlink_metadata(&temporary) {
        Ok(metadata) if !metadata.file_type().is_file() => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "setup completion temporary path is not a regular file",
            ));
        }
        Ok(_) => {
            // Only the unfinished temporary marker can be discarded on retry.
            fs::remove_file(&temporary)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    writeln!(file, "{installation}")?;
    file.sync_all()?;
    fs::rename(temporary, directory.join(name))?;
    fs::File::open(directory)?.sync_all()
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::{read, write};

    #[test]
    fn interrupted_completion_resumes_and_corruption_is_preserved() {
        let root = std::env::temp_dir().join(format!(
            "setup-completion-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos()
        ));
        fs::create_dir_all(&root).expect("completion fixture");
        for name in ["setup-ready", "device-setup-ready"] {
            assert!(!read(&root, name, "installation").expect("incomplete stage"));
            let temporary = root.join(format!(".{name}-installation.tmp"));
            fs::write(&temporary, b"instal").expect("interrupted write");
            write(&root, name, "installation").expect("resume interrupted stage");
            assert!(read(&root, name, "installation").expect("completed stage"));
            write(&root, name, "installation").expect("exact retry");
            assert!(read(&root, name, "other-installation").is_err());
            fs::write(root.join(name), b"corrupt").expect("corrupt final marker");
            assert!(write(&root, name, "installation").is_err());
            assert_eq!(
                fs::read(root.join(name)).expect("retained corrupt marker"),
                b"corrupt"
            );
        }
        fs::remove_dir_all(root).expect("remove completion fixture");
    }

    #[cfg(unix)]
    #[test]
    fn completion_never_follows_a_symlink() {
        use std::os::unix::fs::symlink;
        let root = std::env::temp_dir().join(format!(
            "setup-completion-link-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos()
        ));
        fs::create_dir_all(&root).expect("completion fixture");
        let target = root.join("target");
        fs::write(&target, b"installation").expect("symlink target");
        let temporary = root.join(".device-setup-ready-installation.tmp");
        symlink(&target, &temporary).expect("temporary symlink");
        assert!(write(&root, "device-setup-ready", "installation").is_err());
        fs::remove_file(temporary).expect("remove temporary link");
        symlink(&target, root.join("device-setup-ready")).expect("final symlink");
        assert!(read(&root, "device-setup-ready", "installation").is_err());
        assert!(write(&root, "device-setup-ready", "installation").is_err());
        assert_eq!(fs::read(target).expect("unchanged target"), b"installation");
        fs::remove_dir_all(root).expect("remove completion fixture");
    }
}
