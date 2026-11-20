//! Sunshine Stage A bootstrap.
//!
//! Small, self-sufficient trust root for the Evolution Engine. It verifies the
//! signed repository index, pinned key rotations, artifact digests and the
//! signed Core handoff, then writes a signed receipt and executes Core.

mod gpg;
mod json;
mod sha256;
mod trust;

use std::env;
use std::fs;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use json::Value;

#[derive(Debug)]
struct Options {
    command: String,
    policy: PathBuf,
    index: PathBuf,
    keyring: PathBuf,
    report: Option<PathBuf>,
    receipt: Option<PathBuf>,
    gpg: String,
    core_args: Vec<String>,
}

fn usage() -> ! {
    eprintln!("usage: sunshine-bootstrap <verify|handoff> --policy PATH --index PATH --keyring PATH [--report PATH] [--receipt PATH] [--gpg BIN] [-- CORE_ARGS...]");
    std::process::exit(2);
}

fn parse_args() -> Options {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        usage();
    }
    let command = args[0].clone();
    if command != "verify" && command != "handoff" {
        usage();
    }
    let mut options = Options {
        command,
        policy: PathBuf::new(),
        index: PathBuf::new(),
        keyring: PathBuf::new(),
        report: None,
        receipt: None,
        gpg: "gpg".to_owned(),
        core_args: Vec::new(),
    };
    let mut index = 1;
    let mut core_mode = false;
    while index < args.len() {
        let arg = &args[index];
        if core_mode {
            options.core_args.push(arg.clone());
            index += 1;
            continue;
        }
        if arg == "--" {
            core_mode = true;
            index += 1;
            continue;
        }
        let mut value = || -> String {
            index += 1;
            args.get(index).cloned().unwrap_or_else(|| {
                eprintln!("missing value for {}", arg);
                usage();
            })
        };
        match arg.as_str() {
            "--policy" => options.policy = PathBuf::from(value()),
            "--index" => options.index = PathBuf::from(value()),
            "--keyring" => options.keyring = PathBuf::from(value()),
            "--report" => options.report = Some(PathBuf::from(value())),
            "--receipt" => options.receipt = Some(PathBuf::from(value())),
            "--gpg" => options.gpg = value(),
            _ => {
                eprintln!("unknown option: {}", arg);
                usage();
            }
        }
        index += 1;
    }
    if options.policy.as_os_str().is_empty()
        || options.index.as_os_str().is_empty()
        || options.keyring.as_os_str().is_empty() {
        usage();
    }
    if options.command == "handoff" && (options.receipt.is_none() || options.report.is_none()) {
        eprintln!("handoff requires --receipt and --report");
        std::process::exit(2);
    }
    options
}

fn write_private(path: &Path, contents: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create {}: {}", parent.display(), e))?;
    }
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("cannot write {}: {}", path.display(), e))?;
    use std::io::Write;
    file.write_all(contents)
        .map_err(|e| format!("cannot write {}: {}", path.display(), e))
}

fn main() {
    let options = parse_args();
    let policy = match trust::TrustPolicy::load(&options.policy) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("Stage A policy error: {}", error);
            std::process::exit(3);
        }
    };
    let stage = match trust::verify(&options.index, &policy, &options.keyring, &options.gpg) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("Stage A verification error: {}", error);
            std::process::exit(3);
        }
    };
    let report_text = stage.report.canonical() + "\n";
    if let Some(path) = &options.report {
        if let Err(error) = write_private(path, report_text.as_bytes()) {
            eprintln!("Stage A report error: {}", error);
            std::process::exit(3);
        }
    } else {
        print!("{}", report_text);
    }

    if !stage.passed {
        if options.command == "handoff" {
            eprintln!("Stage A failed; refusing Core handoff");
        }
        std::process::exit(1);
    }
    if options.command == "verify" {
        return;
    }

    let receipt_payload = match trust::build_receipt(&stage, &policy) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("Stage A receipt error: {}", error);
            std::process::exit(3);
        }
    };
    let signing_home = match policy.receipt_signing_home.as_deref() {
        Some(path) => path,
        None => {
            eprintln!("Stage A receipt error: policy has no receipt_signing.gpg_home");
            std::process::exit(3);
        }
    };
    let signature = match gpg::sign_detached(
        signing_home,
        &policy.receipt_signing_fingerprint,
        receipt_payload.canonical().as_bytes(),
        &options.gpg,
    ) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("Stage A receipt error: {}", error);
            std::process::exit(3);
        }
    };
    let envelope = json::object(vec![
        ("payload", receipt_payload),
        ("signature", Value::Str(signature)),
        ("signed_by", Value::Str(policy.receipt_signing_fingerprint.clone())),
    ]);
    let receipt_path = options.receipt.as_ref().expect("handoff requires a receipt path");
    if let Err(error) = write_private(receipt_path, (envelope.canonical() + "\n").as_bytes()) {
        eprintln!("Stage A receipt error: {}", error);
        std::process::exit(3);
    }
    let report_path = options.report.as_ref().expect("handoff requires a report path");
    if let Err(error) = write_private(report_path, report_text.as_bytes()) {
        eprintln!("Stage A report error: {}", error);
        std::process::exit(3);
    }

    let core = &stage.core;
    if !core.path.is_file() {
        eprintln!("Stage A handoff error: Core artifact missing: {}", core.path.display());
        std::process::exit(3);
    }
    let metadata = match fs::metadata(&core.path) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("Stage A handoff error: cannot inspect Core artifact: {}", error);
            std::process::exit(3);
        }
    };
    if metadata.permissions().mode() & 0o111 == 0 {
        eprintln!("Stage A handoff error: Core artifact is not executable: {}", core.path.display());
        std::process::exit(3);
    }

    let error = Command::new(&core.path)
        .arg("--trust-report")
        .arg(report_path)
        .arg("--trust-receipt")
        .arg(receipt_path)
        .args(&options.core_args)
        .exec();
    eprintln!("Stage A handoff error: cannot execute Core: {}", error);
    std::process::exit(3);
}
