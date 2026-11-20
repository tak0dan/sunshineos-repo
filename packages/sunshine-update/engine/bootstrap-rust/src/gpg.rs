//! Detached OpenPGP verification and receipt signing through `gpg`.
//!
//! The bootstrap has no crypto dependency of its own: it shells out to the
//! system `gpg`/`gpgv` implementation with a dedicated keyring. This keeps the
//! binary tiny while preserving the rule that a key downloaded from the same
//! server as the code is never trusted automatically.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn normalize_fingerprint(value: &str) -> String {
    value.chars().filter(|c| !c.is_whitespace()).collect::<String>().to_uppercase()
}

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    let clean: String = value.chars().filter(|c| !c.is_whitespace()).collect();
    if clean.len() % 2 != 0 {
        return Err("signature hex has an odd number of digits".to_owned());
    }
    (0..clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean[i..i + 2], 16)
            .map_err(|_| format!("invalid hex signature at byte {}", i / 2)))
        .collect()
}

fn temp_dir() -> Result<PathBuf, String> {
    let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "sunshine-bootstrap-{}-{}",
        std::process::id(),
        unique
    ));
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700).recursive(true).create(&path)
        .map_err(|e| format!("cannot create secure temporary directory: {}", e))?;
    Ok(path)
}

fn write_secret(path: &Path, contents: &[u8]) -> Result<(), String> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("cannot create {}: {}", path.display(), e))?;
    file.write_all(contents)
        .map_err(|e| format!("cannot write {}: {}", path.display(), e))
}

pub fn verify_detached(
    keyring: &Path,
    expected_fingerprint: &str,
    payload: &[u8],
    signature_hex: &str,
    gpg: &str,
) -> Result<(), String> {
    if !keyring.is_file() {
        return Err(format!("trust keyring not found: {}", keyring.display()));
    }
    let expected = normalize_fingerprint(expected_fingerprint);
    if expected.is_empty() {
        return Err("signature has no expected fingerprint".to_owned());
    }
    let signature = decode_hex(signature_hex)?;
    let dir = temp_dir()?;
    let payload_path = dir.join("payload");
    let sig_path = dir.join("payload.sig");
    write_secret(&payload_path, payload)?;
    write_secret(&sig_path, &signature)?;

    let output = Command::new(gpg)
        .args([
            "--no-default-keyring",
            "--keyring",
            keyring.to_string_lossy().as_ref(),
            "--batch",
            "--status-fd",
            "1",
            "--verify",
            sig_path.to_string_lossy().as_ref(),
            payload_path.to_string_lossy().as_ref(),
        ])
        .output()
        .map_err(|e| format!("cannot run {}: {}", gpg, e))?;
    let status = String::from_utf8_lossy(&output.stdout);
    let _ = fs::remove_dir_all(&dir);

    if !output.status.success() {
        return Err(format!(
            "invalid signature from {}: {}",
            expected,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    // gpg selects the key from the signature. Requiring the VALIDSIG status to
    // name the declared signer prevents a different pinned key from being used
    // while metadata claims another fingerprint.
    let valid = status.lines().any(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        fields.first().copied() == Some("[GNUPG:]")
            && fields.get(1).copied() == Some("VALIDSIG")
            && fields.iter().skip(2).any(|f| normalize_fingerprint(f) == expected)
    });
    if !valid {
        return Err(format!("signature was not made by declared key {}", expected));
    }
    Ok(())
}

pub fn sign_detached(
    gpg_home: &Path,
    fingerprint: &str,
    payload: &[u8],
    gpg: &str,
) -> Result<String, String> {
    if !gpg_home.is_dir() {
        return Err(format!("receipt signing home not found: {}", gpg_home.display()));
    }
    let dir = temp_dir()?;
    let payload_path = dir.join("receipt");
    let sig_path = dir.join("receipt.sig");
    write_secret(&payload_path, payload)?;
    let output = Command::new(gpg)
        .env("GNUPGHOME", gpg_home)
        .args([
            "--batch",
            "--yes",
            "--detach-sign",
            "--no-armor",
            "--local-user",
            fingerprint,
            "--output",
            sig_path.to_string_lossy().as_ref(),
            payload_path.to_string_lossy().as_ref(),
        ])
        .output()
        .map_err(|e| format!("cannot run {}: {}", gpg, e))?;
    if !output.status.success() {
        let _ = fs::remove_dir_all(&dir);
        return Err(format!(
            "receipt signing failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let signature = fs::read(&sig_path)
        .map_err(|e| format!("cannot read receipt signature: {}", e))?;
    let _ = fs::remove_dir_all(&dir);
    Ok(crate::sha256::hex(&signature))
}

pub fn ensure_keyring_permissions(keyring: &Path) -> Result<(), String> {
    if !keyring.is_file() {
        return Err(format!("trust keyring not found: {}", keyring.display()));
    }
    let metadata = fs::metadata(keyring)
        .map_err(|e| format!("cannot inspect keyring: {}", e))?;
    if metadata.permissions().mode() & 0o022 != 0 {
        return Err(format!(
            "trust keyring is group/world writable: {}",
            keyring.display()
        ));
    }
    Ok(())
}
