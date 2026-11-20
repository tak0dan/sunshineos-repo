//! Stage A verification: signed index, chained rotation, artifacts, handoff.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::gpg;
use crate::json::{self, Value};
use crate::sha256;

#[derive(Clone, Debug)]
pub struct TrustPolicy {
    pub pinned_roots: Vec<String>,
    pub local_protocol: i64,
    pub local_bootstrap_version: String,
    pub require_artifact_signatures: bool,
    pub allow_key_rotation: bool,
    pub required_privileged_channel: String,
    pub receipt_signing_fingerprint: String,
    pub receipt_signing_home: Option<PathBuf>,
}

impl TrustPolicy {
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read trust policy {}: {}", path.display(), e))?;
        let value = json::parse(&text)?;
        let receipt = value.get("receipt_signing");
        Ok(Self {
            pinned_roots: string_list(value.get("pinned_roots")),
            local_protocol: value.int_at("local_protocol", 1),
            local_bootstrap_version: value.str_at("local_bootstrap_version", "1.0.0"),
            require_artifact_signatures: value.bool_at("require_artifact_signatures", true),
            allow_key_rotation: value.bool_at("allow_key_rotation", true),
            required_privileged_channel: value.str_at("required_privileged_channel", "polkit"),
            receipt_signing_fingerprint: receipt
                .map(|r| r.str_at("fingerprint", ""))
                .unwrap_or_default(),
            receipt_signing_home: receipt
                .and_then(|r| r.get("gpg_home"))
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(PathBuf::from),
        })
    }
}

#[derive(Clone, Debug)]
struct Rotation {
    new_fingerprint: String,
    signed_by: String,
    signature: String,
    valid_after: String,
    revokes: Vec<String>,
    reason: String,
}

impl Rotation {
    fn signable(&self) -> Value {
        json::object(vec![
            ("new_fingerprint", self.new_fingerprint.clone().into()),
            ("valid_after", self.valid_after.clone().into()),
            ("revokes", json::strings(&self.revokes)),
            ("reason", self.reason.clone().into()),
        ])
    }
}

#[derive(Clone, Debug)]
pub struct VerifiedArtifact {
    pub name: String,
    pub path: PathBuf,
    pub sha256: String,
    pub signed_by: String,
}

#[derive(Clone, Debug)]
pub struct StageA {
    pub report: Value,
    pub passed: bool,
    pub target_release: String,
    pub repository_generation: i64,
    pub handoff_artifact: String,
    pub core: VerifiedArtifact,
}

fn string_list(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(normalize)
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn normalize(value: &str) -> String {
    value.chars().filter(|c| !c.is_whitespace()).collect::<String>().to_uppercase()
}

fn version_tuple(value: &str) -> Vec<i64> {
    value
        .replace('-', ".")
        .split('.')
        .map(|token| {
            let digits: String = token.chars().filter(|c| c.is_ascii_digit()).collect();
            digits.parse::<i64>().unwrap_or(0)
        })
        .collect()
}

fn version_at_least(current: &str, minimum: &str) -> bool {
    let a = version_tuple(current);
    let b = version_tuple(minimum);
    let len = a.len().max(b.len());
    for index in 0..len {
        let left = *a.get(index).unwrap_or(&0);
        let right = *b.get(index).unwrap_or(&0);
        if left != right {
            return left > right;
        }
    }
    true
}

fn date_to_days(value: &str) -> Option<i64> {
    let date = value.split(['T', ' ']).next().unwrap_or(value);
    let parts: Vec<&str> = date.split('-').collect();
    if parts.len() != 3 {
        return None;
    }
    let year: i64 = parts[0].parse().ok()?;
    let month: i64 = parts[1].parse().ok()?;
    let day: i64 = parts[2].parse().ok()?;
    if !(1..=12).contains(&month) {
        return None;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days_in_month = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    if !(1..=days_in_month).contains(&day) {
        return None;
    }
    let adjusted_year = year - if month <= 2 { 1 } else { 0 };
    let era = if adjusted_year >= 0 { adjusted_year } else { adjusted_year - 399 } / 400;
    let year_of_era = adjusted_year - era * 400;
    let month_prime = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * month_prime + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    Some(era * 146097 + day_of_era - 719468)
}

fn rotation_is_effective(valid_after: &str) -> Result<bool, String> {
    if valid_after.is_empty() {
        return Ok(true);
    }
    let Some(valid_day) = date_to_days(valid_after) else {
        return Err(format!("invalid rotation valid_after date '{}'", valid_after));
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| format!("system clock is before the Unix epoch: {}", error))?;
    Ok(valid_day <= (now.as_secs() / 86_400) as i64)
}

fn verify_document(
    payload: &Value,
    signature: &str,
    signed_by: &str,
    trusted: &BTreeSet<String>,
    keyring: &Path,
    gpg_bin: &str,
    errors: &mut Vec<String>,
    label: &str,
) -> bool {
    let signer = normalize(signed_by);
    if signer.is_empty() || !trusted.contains(&signer) {
        errors.push(format!("{}: signer {} is not in the pinned trust chain", label, signed_by));
        return false;
    }
    if signature.is_empty() {
        errors.push(format!("{}: missing signature", label));
        return false;
    }
    match gpg::verify_detached(keyring, &signer, payload.canonical().as_bytes(), signature, gpg_bin) {
        Ok(()) => true,
        Err(error) => {
            errors.push(format!("{}: {}", label, error));
            false
        }
    }
}

pub fn verify(
    index_path: &Path,
    policy: &TrustPolicy,
    keyring: &Path,
    gpg_bin: &str,
) -> Result<StageA, String> {
    gpg::ensure_keyring_permissions(keyring)?;
    if !index_path.is_file() {
        return Err(format!("trust index not found: {}", index_path.display()));
    }
    let mut errors: Vec<String> = Vec::new();
    if policy.pinned_roots.is_empty() {
        return Err("trust policy has no pinned roots".to_owned());
    }
    let envelope_text = std::fs::read_to_string(index_path)
        .map_err(|e| format!("cannot read trust index: {}", e))?;
    let envelope = json::parse(&envelope_text)?;
    let payload = envelope.get("payload")
        .cloned()
        .ok_or_else(|| "trust index has no payload".to_owned())?;
    let signature = envelope.str_at("signature", "");
    let signed_by = envelope.str_at("signed_by", "");
    let mut trusted: BTreeSet<String> = policy.pinned_roots.iter().cloned().collect();

    if !verify_document(&payload, &signature, &signed_by, &trusted, keyring, gpg_bin,
                        &mut errors, "repository index") {
        return Ok(failure(errors, &trusted, &[]));
    }

    let format_version = payload.int_at("format_version", 0);
    if format_version != 1 {
        errors.push(format!("unsupported trust index format: {}", format_version));
    }
    let repository_generation = payload.int_at("repository_generation", 0);
    if repository_generation <= 0 {
        errors.push("repository_generation must be positive".to_owned());
    }
    let target = payload.get("target");
    let target_release = target.map(|t| t.str_at("release", "")).unwrap_or_default();

    let mut rotated: Vec<String> = Vec::new();
    if let Some(rotations) = payload.get("key_rotations").and_then(Value::as_array) {
        if !rotations.is_empty() && !policy.allow_key_rotation {
            errors.push("key rotation present but disabled by trust policy".to_owned());
        }
        for value in rotations {
            let new_fingerprint = normalize(&value.str_at("new_fingerprint", ""));
            let signed_by = normalize(&value.str_at("signed_by", ""));
            let rotation = Rotation {
                new_fingerprint: new_fingerprint.clone(),
                signed_by: signed_by.clone(),
                signature: value.str_at("signature", ""),
                valid_after: value.str_at("valid_after", ""),
                revokes: string_list(value.get("revokes")),
                reason: value.str_at("reason", ""),
            };
            if rotation.new_fingerprint == rotation.signed_by {
                errors.push(format!("key rotation {} is self-signed", rotation.new_fingerprint));
                continue;
            }
            match rotation_is_effective(&rotation.valid_after) {
                Ok(true) => {}
                Ok(false) => {
                    errors.push(format!(
                        "key rotation {} is not valid until {}",
                        rotation.new_fingerprint, rotation.valid_after
                    ));
                    continue;
                }
                Err(error) => {
                    errors.push(error);
                    continue;
                }
            }
            if verify_document(&rotation.signable(), &rotation.signature, &rotation.signed_by,
                               &trusted, keyring, gpg_bin, &mut errors,
                               &format!("key rotation {}", rotation.new_fingerprint)) {
                trusted.insert(rotation.new_fingerprint.clone());
                for old in &rotation.revokes {
                    trusted.remove(&normalize(old));
                }
                rotated.push(rotation.new_fingerprint);
            }
        }
    }

    let bootstrap = payload.get("bootstrap");
    let min_protocol = bootstrap.map(|b| b.int_at("minimum_protocol", 1)).unwrap_or(1);
    if policy.local_protocol < min_protocol {
        errors.push(format!(
            "bootstrap protocol {} is older than required {}; upgrade the bootstrap before transforming",
            policy.local_protocol, min_protocol
        ));
    }
    let compatibility = payload.get("compatibility");
    let min_core = compatibility.map(|c| c.str_at("minimum_core", "")).unwrap_or_default();
    if !min_core.is_empty() && !version_at_least(&policy.local_bootstrap_version, &min_core) {
        errors.push(format!(
            "local bootstrap {} is older than minimum core {}",
            policy.local_bootstrap_version, min_core
        ));
    }
    let channel = bootstrap.map(|b| b.str_at("privileged_channel", "")).unwrap_or_default();
    if !policy.required_privileged_channel.is_empty()
        && channel != policy.required_privileged_channel {
        errors.push(format!(
            "privileged channel '{}'; policy requires '{}' (no broad sudoers rule)",
            channel, policy.required_privileged_channel
        ));
    }

    let base = index_path.parent().unwrap_or_else(|| Path::new("."));
    let mut verified: Vec<VerifiedArtifact> = Vec::new();
    let mut verified_names: BTreeSet<String> = BTreeSet::new();
    if let Some(artifacts) = payload.get("artifacts").and_then(Value::as_object) {
        for (name, value) in artifacts {
            let path_text = value.str_at("path", "");
            let expected = value.str_at("sha256", "").to_lowercase();
            let signature = value.str_at("signature", "");
            let signer = {
                let explicit = value.str_at("signed_by", "");
                if explicit.is_empty() { signed_by.clone() } else { normalize(&explicit) }
            };
            let artifact_path = PathBuf::from(&path_text);
            let artifact_path = if artifact_path.is_absolute() {
                artifact_path
            } else {
                base.join(artifact_path)
            };
            if !artifact_path.is_file() {
                errors.push(format!("artifact {}: file not found at {}", name, artifact_path.display()));
                continue;
            }
            let actual = match sha256::file_digest(&artifact_path) {
                Ok(value) => value,
                Err(error) => {
                    errors.push(format!("artifact {}: {}", name, error));
                    continue;
                }
            };
            if actual != expected {
                errors.push(format!("artifact {}: digest mismatch ({} != {})", name, actual, expected));
                continue;
            }
            if policy.require_artifact_signatures {
                let raw = std::fs::read(&artifact_path)
                    .map_err(|e| format!("cannot read artifact {}: {}", name, e))?;
                match gpg::verify_detached(keyring, &signer, &raw, &signature, gpg_bin) {
                    Ok(()) => {}
                    Err(error) => errors.push(format!("artifact {}: {}", name, error)),
                }
                if !trusted.contains(&signer) {
                    errors.push(format!("artifact {}: signer {} is not in the trust chain", name, signer));
                }
                if errors.iter().any(|e| e.starts_with(&format!("artifact {}:", name))) {
                    continue;
                }
            }
            verified_names.insert(name.clone());
            verified.push(VerifiedArtifact {
                name: name.clone(),
                path: artifact_path,
                sha256: actual,
                signed_by: signer,
            });
        }
    }

    let handoff = payload.get("handoff");
    let handoff_artifact = handoff.map(|h| h.str_at("artifact", "")).unwrap_or_default();
    if handoff_artifact.is_empty() {
        errors.push("handoff descriptor does not identify a verified artifact".to_owned());
    } else if !verified_names.contains(&handoff_artifact) {
        errors.push(format!("handoff artifact '{}' was not verified", handoff_artifact));
    }
    let handoff_protocol = handoff.map(|h| h.int_at("protocol", 0)).unwrap_or(0);
    if handoff_protocol <= 0 || handoff_protocol < policy.local_protocol {
        errors.push("handoff protocol is missing or older than the local bootstrap".to_owned());
    }

    let trusted_vec: Vec<String> = trusted.iter().cloned().collect();
    let report_payload = json::object(vec![
        ("passed", json::Value::Bool(errors.is_empty())),
        ("errors", json::strings(&errors)),
        ("trusted_keys", json::strings(&trusted_vec)),
        ("rotated_keys", json::strings(&rotated)),
        ("artifacts_verified", json::strings(&verified.iter().map(|a| a.name.clone()).collect::<Vec<_>>())),
        ("target_release", target_release.clone().into()),
        ("repository_generation", repository_generation.into()),
        ("handoff", handoff.cloned().unwrap_or(Value::Object(BTreeMap::new()))),
    ]);
    let passed = errors.is_empty();
    if !passed {
        return Ok(StageA {
            report: report_payload,
            passed,
            target_release,
            repository_generation,
            handoff_artifact,
            core: verified.first().cloned().unwrap_or_else(|| VerifiedArtifact {
                name: String::new(), path: PathBuf::new(), sha256: String::new(), signed_by: String::new(),
            }),
        });
    }
    let core = verified
        .iter()
        .find(|artifact| artifact.name == handoff_artifact)
        .cloned()
        .ok_or_else(|| "verified handoff artifact disappeared".to_owned())?;
    Ok(StageA {
        report: report_payload,
        passed,
        target_release,
        repository_generation,
        handoff_artifact,
        core,
    })
}

fn failure(errors: Vec<String>, trusted: &BTreeSet<String>, rotated: &[String]) -> StageA {
    let report = json::object(vec![
        ("passed", Value::Bool(false)),
        ("errors", json::strings(&errors)),
        ("trusted_keys", json::strings(&trusted.iter().cloned().collect::<Vec<_>>())),
        ("rotated_keys", json::strings(rotated)),
        ("artifacts_verified", Value::Array(vec![])),
        ("target_release", "".into()),
        ("repository_generation", 0i64.into()),
        ("handoff", Value::Object(BTreeMap::new())),
    ]);
    StageA {
        report,
        passed: false,
        target_release: String::new(),
        repository_generation: 0,
        handoff_artifact: String::new(),
        core: VerifiedArtifact {
            name: String::new(), path: PathBuf::new(), sha256: String::new(), signed_by: String::new(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotation_dates_use_utc_calendar_days() {
        assert_eq!(date_to_days("1970-01-01"), Some(0));
        assert_eq!(date_to_days("2026-01-01"), Some(20454));
        assert_eq!(date_to_days("2026-01-01T00:00:00Z"), Some(20454));
        assert_eq!(date_to_days("2026-02-30"), None);
        assert!(rotation_is_effective("2026-01-01").unwrap());
        assert!(!rotation_is_effective("2999-01-01").unwrap());
    }
}

pub fn build_receipt(stage: &StageA, policy: &TrustPolicy) -> Result<Value, String> {
    if !stage.passed {
        return Err("cannot sign a receipt for a failed Stage A".to_owned());
    }
    if policy.receipt_signing_fingerprint.is_empty() {
        return Err("trust policy has no receipt_signing.fingerprint".to_owned());
    }
    let signer = normalize(&policy.receipt_signing_fingerprint);
    let trusted: BTreeSet<String> = stage.report
        .get("trusted_keys")
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_str).map(normalize).collect())
        .unwrap_or_default();
    if !trusted.contains(&signer) {
        return Err(format!("receipt signing key {} is not in the Stage A trust chain", signer));
    }
    let stage_digest = sha256::hex(&sha256::digest(stage.report.canonical().as_bytes()));
    Ok(json::object(vec![
        ("bootstrap_version", policy.local_bootstrap_version.clone().into()),
        ("protocol", policy.local_protocol.into()),
        ("target_release", stage.target_release.clone().into()),
        ("repository_generation", stage.repository_generation.into()),
        ("core_artifact", stage.handoff_artifact.clone().into()),
        ("core_sha256", stage.core.sha256.clone().into()),
        ("core_signed_by", stage.core.signed_by.clone().into()),
        ("trusted_keys", json::strings(&trusted.iter().cloned().collect::<Vec<_>>())),
        ("stage_a_digest", stage_digest.into()),
    ]))
}
