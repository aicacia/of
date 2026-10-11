use std::{io, path::Path};

#[cfg(any(not(test), not(any(target_os = "macos", target_os = "windows"))))]
use std::process::{Command, Stdio};

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn linux_ca_trust_identifiers(ca_pem: &[u8]) -> io::Result<(String, String)> {
    use std::fmt::Write;

    use rustls::pki_types::{CertificateDer, pem::PemObject};

    let certificate = CertificateDer::from_pem_slice(ca_pem).map_err(io::Error::other)?;
    let digest = rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256
        .tls13()
        .expect("TLS13_AES_128_GCM_SHA256 is a TLS 1.3 suite")
        .common
        .hash_provider
        .hash(certificate.as_ref());
    let mut fingerprint = String::with_capacity(64);
    for byte in digest.as_ref() {
        write!(fingerprint, "{byte:02x}").expect("writing to a String cannot fail");
    }
    Ok((
        format!("/usr/local/share/ca-certificates/aicacia-localhost-ca-{fingerprint}.crt"),
        format!("Aicacia Localhost CA {fingerprint}"),
    ))
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn linux_ca_install_command(ca_pem_path: &Path, system_cert: &str) -> Command {
    let mut command = Command::new("pkexec");
    command
        .args(["install", "-m", "0644"])
        .arg(ca_pem_path)
        .arg(system_cert)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn linux_ca_nss_command(database: &Path, ca_pem_path: &Path, nickname: &str) -> Command {
    let mut command = Command::new("certutil");
    command
        .args([
            "-d",
            &format!("sql:{}", database.display()),
            "-A",
            "-t",
            "C,,",
            "-n",
            nickname,
            "-i",
        ])
        .arg(ca_pem_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

pub fn install_ca_to_user_trust_store(ca_pem_path: &Path) -> io::Result<()> {
    #[cfg(test)]
    {
        let _ = ca_pem_path;
        Ok(())
    }

    #[cfg(not(test))]
    match install_ca_to_user_trust_store_impl(ca_pem_path) {
        Ok(()) => {
            log::info!("installed localhost CA into the operating system trust store");
            Ok(())
        }
        Err(err) => {
            log::warn!(
                "failed to install localhost CA into user trust store: {err}. open the trust page in your browser to accept the certificate manually."
            );
            Err(err)
        }
    }
}

#[cfg(not(test))]
fn install_ca_to_user_trust_store_impl(ca_pem_path: &Path) -> io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        return install_ca_macos(ca_pem_path);
    }

    #[cfg(target_os = "windows")]
    {
        return install_ca_windows(ca_pem_path);
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        install_ca_linux(ca_pem_path)
    }
}

#[cfg(all(not(test), target_os = "macos"))]
fn install_ca_macos(ca_pem_path: &Path) -> io::Result<()> {
    let home = std::env::var("HOME").map_err(io::Error::other)?;
    let keychain = format!("{home}/Library/Keychains/login.keychain-db");
    let status = Command::new("security")
        .args([
            "add-trusted-cert",
            "-r",
            "trustRoot",
            "-p",
            "ssl",
            "-k",
            &keychain,
            &ca_pem_path.to_string_lossy(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;

    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(
            "security add-trusted-cert failed for localhost CA",
        ))
    }
}

#[cfg(all(not(test), target_os = "windows"))]
fn install_ca_windows(ca_pem_path: &Path) -> io::Result<()> {
    let status = Command::new("certutil")
        .args(["-addstore", "-user", "Root", &ca_pem_path.to_string_lossy()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;

    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(
            "certutil failed to install localhost CA into user Root store",
        ))
    }
}

#[cfg(all(not(test), not(any(target_os = "macos", target_os = "windows"))))]
fn install_ca_linux(ca_pem_path: &Path) -> io::Result<()> {
    if command_succeeds("trust", &["anchor", &ca_pem_path.to_string_lossy()]) {
        return Ok(());
    }

    let (system_cert, _) = linux_ca_trust_identifiers(&std::fs::read(ca_pem_path)?)?;
    if linux_ca_install_command(ca_pem_path, &system_cert)
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
        && (command_succeeds("pkexec", &["update-ca-certificates"])
            || command_succeeds("pkexec", &["update-ca-trust", "extract"]))
    {
        return Ok(());
    }

    install_ca_linux_nss_fallback(ca_pem_path).map_err(|_| {
        io::Error::other(
            "could not install the CA into the Linux OS trust store; approve the elevation prompt or install it manually",
        )
    })
}

#[cfg(all(not(test), not(any(target_os = "macos", target_os = "windows"))))]
fn command_succeeds(command: &str, args: &[&str]) -> bool {
    Command::new(command)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

#[cfg(all(not(test), not(any(target_os = "macos", target_os = "windows"))))]
fn install_ca_linux_nss_fallback(ca_pem_path: &Path) -> io::Result<()> {
    if !command_succeeds("certutil", &["-H"]) {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "certutil unavailable",
        ));
    }

    let home = std::env::var("HOME").map_err(io::Error::other)?;
    let home = Path::new(&home);
    let candidates = [
        home.join(".pki/nssdb"),
        home.join(".var/app/com.brave.Browser/.pki/nssdb"),
        home.join(".var/app/com.google.Chrome/data/pki/nssdb"),
        home.join(".var/app/org.chromium.Chromium/.pki/nssdb"),
    ];

    for database in candidates {
        if database.is_dir() && install_ca_in_nss_database(&database, ca_pem_path).is_ok() {
            return Ok(());
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "no NSS database available",
    ))
}

#[cfg(all(not(test), not(any(target_os = "macos", target_os = "windows"))))]
fn install_ca_in_nss_database(database: &Path, ca_pem_path: &Path) -> io::Result<()> {
    let (_, nickname) = linux_ca_trust_identifiers(&std::fs::read(ca_pem_path)?)?;
    let status = linux_ca_nss_command(database, ca_pem_path, &nickname).status()?;

    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other("certutil failed to install localhost CA"))
    }
}

#[cfg(all(test, not(any(target_os = "macos", target_os = "windows"))))]
mod tests {
    use std::{ffi::OsStr, path::Path};

    use super::{linux_ca_install_command, linux_ca_nss_command, linux_ca_trust_identifiers};

    #[test]
    fn trust_identifiers_use_full_sha256_of_decoded_der() {
        let (system_cert, nickname) = linux_ca_trust_identifiers(
            b"-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n",
        )
        .expect("decode PEM containing the SHA-256 abc test vector");
        assert_eq!(
            system_cert,
            "/usr/local/share/ca-certificates/aicacia-localhost-ca-ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad.crt"
        );
        assert_eq!(
            nickname,
            "Aicacia Localhost CA ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert!(linux_ca_trust_identifiers(b"not a PEM certificate").is_err());
    }

    #[test]
    fn different_profile_certificates_have_distinct_trust_entries() {
        let first = rcgen::CertificateParams::new(Vec::<String>::new())
            .expect("valid certificate parameters")
            .self_signed(&rcgen::KeyPair::generate().expect("generate first profile key"))
            .expect("generate first profile certificate");
        let second = rcgen::CertificateParams::new(Vec::<String>::new())
            .expect("valid certificate parameters")
            .self_signed(&rcgen::KeyPair::generate().expect("generate second profile key"))
            .expect("generate second profile certificate");
        let first_ids = linux_ca_trust_identifiers(first.pem().as_bytes())
            .expect("first profile trust identifiers");
        let second_ids = linux_ca_trust_identifiers(second.pem().as_bytes())
            .expect("second profile trust identifiers");

        assert_ne!(first_ids.0, second_ids.0);
        assert_ne!(first_ids.1, second_ids.1);
        assert_ne!(first_ids.1, "Localhost CA");
        for (system_cert, nickname) in [&first_ids, &second_ids] {
            let source = Path::new("profile/localhost-ca.pem");
            let install = linux_ca_install_command(source, system_cert);
            assert_eq!(install.get_program(), "pkexec");
            assert_eq!(
                install.get_args().collect::<Vec<_>>(),
                [
                    "install",
                    "-m",
                    "0644",
                    "profile/localhost-ca.pem",
                    system_cert
                ]
                .map(OsStr::new),
            );
            let nss = linux_ca_nss_command(Path::new("browser/nssdb"), source, nickname);
            assert_eq!(nss.get_program(), "certutil");
            assert_eq!(
                nss.get_args().collect::<Vec<_>>(),
                [
                    "-d",
                    "sql:browser/nssdb",
                    "-A",
                    "-t",
                    "C,,",
                    "-n",
                    nickname,
                    "-i",
                    "profile/localhost-ca.pem"
                ]
                .map(OsStr::new),
            );
        }
        assert_eq!(
            first_ids,
            linux_ca_trust_identifiers(first.pem().replace("\n", "\r\n").as_bytes())
                .expect("same certificate with different PEM line endings"),
        );
    }
}
