"""Signed, versioned adapters for nonstandard privileged operations.

Spec §13.2 forbids a plugin free-for-all.  Adapters may only expand the set of
typed operations through a narrow interface: Rust runtime, signed artifact,
declared permissions, declared parameters, and a verified trust chain.  They
can never modify the trust root, write sudoers policy, or disable validation.

This module contains both the manifest contract and the runtime boundary:

* :class:`AdapterRegistry` verifies the manifest signature, artifact digest and
  artifact signature before any adapter can be named by a plan.
* :func:`default_adapter_launcher` launches the verified Rust binary through
  ``systemd-run`` with a deny-by-default sandbox, explicit read/write paths and
  CPU/memory/process/time limits.  It never uses a shell.
* Every launch returns metadata that the executor writes to the journal.

Tests inject a launcher callable, so fixture mode never touches the host's
``systemd-run`` or the real filesystem.
"""
from __future__ import annotations

import os
import subprocess
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping

from .core import OpType, Operation
from .trust.model import canonical_bytes, sha256_file

ALLOWED_OPERATIONS = frozenset({
    OpType.MIGRATE_CONFIGURATION,
    OpType.TRANSFER_OWNERSHIP,
    OpType.ENABLE_SERVICE,
    OpType.DISABLE_SERVICE,
    OpType.GENERATE_INITRAMFS,
    OpType.INSTALL_BOOT_ENTRY,
    OpType.VALIDATE_CAPABILITY,
})
ALLOWED_PERMISSIONS = frozenset({
    "read-configuration",
    "write-managed-configuration",
    "read-package-database",
    "manage-own-service",
    "write-owned-state",
    "read-boot-configuration",
    "write-boot-entry",
    "run-validation",
})
FORBIDDEN_PERMISSIONS = frozenset({
    "modify-trust-root",
    "write-sudoers",
    "disable-validation",
    "execute-arbitrary-shell",
    "bypass-migration-journal",
})
FORBIDDEN_PARAM_KEYS = frozenset({
    "command", "cmd", "shell", "script", "sudoers", "trust_root", "signature", "verifier",
})
INTERNAL_PARAM_KEYS = frozenset({
    "adapter_id", "adapter_version", "adapter_artifact", "source_schema", "target_schema",
})

# A permission is a capability to touch only the paths listed here.  A manifest
# may narrow those paths further, but may never widen them.
PERMISSION_ROOTS: dict[str, tuple[str, ...]] = {
    "read-configuration": ("/etc/sunshine",),
    "write-managed-configuration": ("/etc/sunshine",),
    "read-package-database": ("/var/lib/pacman",),
    "manage-own-service": ("/etc/systemd/system", "/run/systemd/system"),
    "write-owned-state": ("/var/lib/sunshine", "/run/sunshine"),
    "read-boot-configuration": ("/boot", "/etc/default/grub"),
    "write-boot-entry": ("/boot/loader/entries", "/boot/EFI"),
    "run-validation": ("/usr/lib/sunshine", "/var/lib/sunshine"),
}
WRITE_PERMISSIONS = frozenset({
    "write-managed-configuration", "manage-own-service",
    "write-owned-state", "write-boot-entry",
})


@dataclass(frozen=True)
class AdapterSandbox:
    """Resource bounds and explicit filesystem visibility for one adapter."""

    memory_mb: int = 64
    cpu_percent: int = 25
    timeout_seconds: int = 30
    max_processes: int = 32
    network: bool = False
    read_paths: tuple[str, ...] = ()
    write_paths: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "AdapterSandbox":
        return cls(
            memory_mb=int(data.get("memory_mb", 64)),
            cpu_percent=int(data.get("cpu_percent", 25)),
            timeout_seconds=int(data.get("timeout_seconds", 30)),
            max_processes=int(data.get("max_processes", 32)),
            network=bool(data.get("network", False)),
            read_paths=tuple(str(p) for p in data.get("read_paths", [])),
            write_paths=tuple(str(p) for p in data.get("write_paths", [])),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "memory_mb": self.memory_mb,
            "cpu_percent": self.cpu_percent,
            "timeout_seconds": self.timeout_seconds,
            "max_processes": self.max_processes,
            "network": self.network,
            "read_paths": list(self.read_paths),
            "write_paths": list(self.write_paths),
        }


@dataclass(frozen=True)
class AdapterManifest:
    id: str
    component: str
    version: str
    runtime: str
    operation: OpType
    artifact: str
    artifact_sha256: str
    signature: str
    signed_by: str
    source_schema: int
    target_schema: int
    permissions: tuple[str, ...] = ()
    declared_params: tuple[str, ...] = ()
    provides: tuple[str, ...] = ()
    description: str = ""
    artifact_path: str = ""
    manifest_signature: str = ""
    manifest_signed_by: str = ""
    sandbox: AdapterSandbox = field(default_factory=AdapterSandbox)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "AdapterManifest":
        artifact = dict(data.get("artifact") or {})
        schema = dict(data.get("schema") or {})
        raw_signature = data.get("signature")
        signature = dict(raw_signature) if isinstance(raw_signature, Mapping) else {}
        sandbox = dict(data.get("sandbox") or {})
        return cls(
            id=str(data.get("id", "")),
            component=str(data.get("component", "")),
            version=str(data.get("version", "")),
            runtime=str(data.get("runtime", "")).lower(),
            operation=OpType(str(data.get("operation", ""))),
            artifact=str(artifact.get("name", "")),
            artifact_sha256=str(artifact.get("sha256", "")).lower(),
            artifact_path=str(artifact.get("path", artifact.get("name", ""))),
            signature=str(data.get("signature", ""))
                if not isinstance(data.get("signature"), Mapping)
                else str(signature.get("artifact", "")),
            signed_by=str(signature.get("artifact_signed_by", "")).upper()
                if isinstance(raw_signature, Mapping)
                else str(data.get("signed_by", "")).upper(),
            manifest_signature=str(signature.get("manifest", "")),
            manifest_signed_by=str(signature.get("manifest_signed_by", "")).upper(),
            source_schema=int(schema.get("from", 0)),
            target_schema=int(schema.get("to", 0)),
            permissions=tuple(str(p) for p in data.get("permissions", [])),
            declared_params=tuple(str(p) for p in data.get("parameters", [])),
            provides=tuple(str(p) for p in data.get("provides", [])),
            description=str(data.get("description", "")),
            sandbox=AdapterSandbox.from_dict(sandbox),
        )

    def signable(self) -> dict[str, Any]:
        """Canonical manifest payload. Signatures are deliberately excluded."""
        return {
            "id": self.id,
            "component": self.component,
            "version": self.version,
            "runtime": self.runtime,
            "operation": self.operation.value,
            "artifact": {
                "name": self.artifact,
                "path": self.artifact_path,
                "sha256": self.artifact_sha256,
            },
            "source_schema": self.source_schema,
            "target_schema": self.target_schema,
            "permissions": list(self.permissions),
            "parameters": list(self.declared_params),
            "provides": list(self.provides),
            "sandbox": self.sandbox.to_dict(),
        }

    def to_operation(self, params: Mapping[str, Any] | None = None,
                     *, operation_id: str | None = None) -> Operation:
        """Build a typed operation after :func:`validate_adapter` has passed."""
        supplied = validate_adapter_params(self, params)
        merged = dict(supplied)
        merged.update({
            "adapter_id": self.id,
            "adapter_version": self.version,
            "adapter_artifact": self.artifact,
            "source_schema": self.source_schema,
            "target_schema": self.target_schema,
        })
        return Operation(
            id=operation_id or f"adapter-{self.id}",
            type=self.operation,
            component=self.component,
            params=merged,
        )


def validate_adapter_params(manifest: AdapterManifest,
                            params: Mapping[str, Any] | None) -> dict[str, Any]:
    """Reject shell smuggling, undeclared keys and malformed adapter parameters."""
    supplied = {k: v for k, v in dict(params or {}).items() if k not in INTERNAL_PARAM_KEYS}
    forbidden = FORBIDDEN_PARAM_KEYS.intersection(supplied)
    if forbidden:
        raise ValueError(
            "adapter parameters reject privileged escape keys: " + ", ".join(sorted(forbidden))
        )
    unknown = set(supplied) - set(manifest.declared_params)
    if unknown:
        raise ValueError(
            f"adapter {manifest.id}: undeclared parameters: " + ", ".join(sorted(unknown))
        )
    for key, value in supplied.items():
        if isinstance(value, (list, dict)) and len(canonical_bytes(value)) > 16_384:
            raise ValueError(f"adapter {manifest.id}: parameter {key} is too large")
        if isinstance(value, str) and len(value) > 4096:
            raise ValueError(f"adapter {manifest.id}: parameter {key} is too long")
        if "\x00" in str(value):
            raise ValueError(f"adapter {manifest.id}: parameter {key} contains NUL")
    return supplied


def _validate_sandbox(manifest: AdapterManifest) -> list[str]:
    errors: list[str] = []
    limits = manifest.sandbox
    bounds = {
        "memory_mb": (16, 1024),
        "cpu_percent": (1, 100),
        "timeout_seconds": (1, 300),
        "max_processes": (1, 256),
    }
    for name, (minimum, maximum) in bounds.items():
        value = getattr(limits, name)
        if not minimum <= value <= maximum:
            errors.append(
                f"adapter {manifest.id}: sandbox {name}={value} outside {minimum}..{maximum}"
            )
    if limits.network:
        errors.append(f"adapter {manifest.id}: privileged adapters cannot request network access")
    if not limits.read_paths and not limits.write_paths:
        errors.append(f"adapter {manifest.id}: sandbox declares no filesystem paths")

    declared = set(manifest.permissions)
    writable_roots = [
        root for permission in WRITE_PERMISSIONS & declared
        for root in PERMISSION_ROOTS.get(permission, ())
    ]
    readable_roots = [
        root for permission in declared
        for root in PERMISSION_ROOTS.get(permission, ())
    ]
    for group, paths, roots in (
        ("write", limits.write_paths, writable_roots),
        ("read", limits.read_paths, readable_roots),
    ):
        for raw in paths:
            path = _normalized_absolute(raw)
            if path is None:
                errors.append(f"adapter {manifest.id}: invalid {group} path '{raw}'")
                continue
            if not any(path == root or path.startswith(root + "/") for root in roots):
                errors.append(
                    f"adapter {manifest.id}: {group} path '{path}' is not authorized by "
                    f"its declared permissions"
                )
    return errors


def _normalized_absolute(raw: str) -> str | None:
    if not raw or not str(raw).startswith("/") or ".." in Path(str(raw)).parts:
        return None
    normalized = os.path.normpath(str(raw))
    if not normalized.startswith("/"):
        return None
    if Path(normalized).is_symlink():
        return None
    return normalized


def validate_adapter(
    manifest: AdapterManifest,
    *,
    verified_artifacts: set[str] | frozenset[str],
    contract_component_ids: set[str],
) -> list[str]:
    """Return validation errors; empty means the adapter may be used."""
    errors: list[str] = []
    if not manifest.id or not manifest.component:
        errors.append("adapter must declare id and component")
    if manifest.component not in contract_component_ids:
        errors.append(f"adapter {manifest.id}: component '{manifest.component}' has no contract")
    if manifest.runtime != "rust":
        errors.append(
            f"adapter {manifest.id}: privileged adapters must be Rust, got '{manifest.runtime}'"
        )
    if manifest.operation not in ALLOWED_OPERATIONS:
        errors.append(f"adapter {manifest.id}: operation {manifest.operation.value} is not an approved interface")
    if manifest.source_schema >= manifest.target_schema:
        errors.append(f"adapter {manifest.id}: schema transition must increase")
    if manifest.artifact not in verified_artifacts:
        errors.append(f"adapter {manifest.id}: artifact '{manifest.artifact}' was not verified by Stage A")
    if not manifest.signature or not manifest.signed_by:
        errors.append(f"adapter {manifest.id}: missing artifact signature metadata")
    bad = FORBIDDEN_PERMISSIONS.intersection(manifest.permissions)
    if bad:
        errors.append(f"adapter {manifest.id}: forbidden permissions: " + ", ".join(sorted(bad)))
    unknown = set(manifest.permissions) - ALLOWED_PERMISSIONS - FORBIDDEN_PERMISSIONS
    if unknown:
        errors.append(f"adapter {manifest.id}: unknown permissions: " + ", ".join(sorted(unknown)))
    if any(key in FORBIDDEN_PARAM_KEYS for key in manifest.declared_params):
        errors.append(f"adapter {manifest.id}: declares forbidden parameter keys")
    # Older contract-only fixtures omit the sandbox table. Runtime registration
    # requires it; here we validate it only when present to preserve manifest
    # contract tests that do not intend to launch an adapter.
    if manifest.sandbox != AdapterSandbox():
        errors.extend(_validate_sandbox(manifest))
    return errors


Verifier = Callable[[str, bytes, str], bool]


@dataclass(frozen=True)
class RegisteredAdapter:
    manifest: AdapterManifest
    artifact_path: Path

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.manifest.id,
            "component": self.manifest.component,
            "version": self.manifest.version,
            "artifact": self.manifest.artifact,
            "artifact_sha256": self.manifest.artifact_sha256,
            "permissions": list(self.manifest.permissions),
            "sandbox": self.manifest.sandbox.to_dict(),
        }


@dataclass(frozen=True)
class AdapterInvocation:
    adapter: RegisteredAdapter
    params: dict[str, Any]
    state_root: Path
    dry_run: bool
    invocation_id: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "invocation_id": self.invocation_id,
            "adapter_id": self.adapter.manifest.id,
            "adapter_version": self.adapter.manifest.version,
            "artifact": self.adapter.manifest.artifact,
            "artifact_sha256": self.adapter.manifest.artifact_sha256,
            "permissions": list(self.adapter.manifest.permissions),
            "sandbox": self.adapter.manifest.sandbox.to_dict(),
            "params_keys": sorted(self.params),
            "dry_run": self.dry_run,
        }


@dataclass
class AdapterLaunch:
    ok: bool
    output: str = ""
    changed: bool = False
    reversible: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)


class AdapterRegistry:
    """Only validated, signed adapters can be reached from a plan."""

    def __init__(self, adapters: Mapping[str, RegisteredAdapter], verifier: Verifier,
                 trusted_keys: frozenset[str]):
        self._adapters = dict(adapters)
        self._verifier = verifier
        self._trusted_keys = set(trusted_keys)

    @classmethod
    def load(cls, directory: str | Path, *, verifier: Verifier,
             trusted_keys: tuple[str, ...] | frozenset[str] | set[str],
             artifact_root: str | Path,
             stage_artifacts: tuple[str, ...] | frozenset[str] | set[str] | None = None,
             contract_component_ids: set[str] | None = None) -> "AdapterRegistry":
        base = Path(directory)
        artifacts_root = Path(artifact_root)
        trusted = {str(k).strip().upper() for k in trusted_keys if str(k).strip()}
        if not trusted:
            raise ValueError("adapter registry requires trusted Stage A keys")
        if not base.is_dir():
            raise ValueError(f"adapter manifest directory not found: {base}")
        verified = set(stage_artifacts) if stage_artifacts is not None else None
        components = contract_component_ids or set()
        adapters: dict[str, RegisteredAdapter] = {}
        for path in sorted(base.glob("*.toml")):
            manifest = load_manifest(path)
            if manifest.id in adapters:
                raise ValueError(f"duplicate adapter id {manifest.id}")
            errors = validate_adapter(
                manifest,
                verified_artifacts=verified if verified is not None else {manifest.artifact},
                contract_component_ids=components,
            )
            if not manifest.manifest_signature or not manifest.manifest_signed_by:
                errors.append(f"adapter {manifest.id}: missing manifest signature")
            if manifest.sandbox == AdapterSandbox():
                errors.append(f"adapter {manifest.id}: missing runtime sandbox declaration")
            errors.extend(_validate_sandbox(manifest))
            if errors:
                raise ValueError(
                    f"invalid adapter manifest {path.name}: " + "; ".join(errors)
                )
            manifest_signer = manifest.manifest_signed_by.strip().upper()
            artifact_signer = manifest.signed_by.strip().upper()
            if manifest_signer not in trusted or artifact_signer not in trusted:
                raise ValueError(f"adapter {manifest.id}: signer is not in the Stage A trust chain")
            if not verifier(manifest_signer, canonical_bytes(manifest.signable()),
                            manifest.manifest_signature):
                raise ValueError(f"adapter {manifest.id}: invalid manifest signature")
            rel = Path(manifest.artifact_path)
            if rel.is_absolute() or ".." in rel.parts or not rel.parts:
                raise ValueError(f"adapter {manifest.id}: artifact path must be relative and safe")
            artifact_path = artifacts_root / rel
            registry_check = cls._verify_artifact(manifest, artifact_path, artifact_signer, verifier)
            if registry_check:
                raise ValueError(f"adapter {manifest.id}: " + "; ".join(registry_check))
            adapters[manifest.id] = RegisteredAdapter(manifest, artifact_path.resolve())
        return cls(adapters, verifier, frozenset(trusted))

    @staticmethod
    def _verify_artifact(manifest: AdapterManifest, artifact_path: Path,
                         signer: str, verifier: Verifier) -> list[str]:
        errors: list[str] = []
        if not artifact_path.is_file():
            return [f"artifact not found: {artifact_path}"]
        actual = sha256_file(artifact_path)
        if actual != manifest.artifact_sha256:
            errors.append(f"artifact digest mismatch ({actual} != {manifest.artifact_sha256})")
        raw = artifact_path.read_bytes()
        if not verifier(signer, raw, manifest.signature):
            errors.append("invalid artifact signature")
        mode = artifact_path.stat().st_mode & 0o111
        if not mode:
            errors.append("artifact is not executable")
        return errors

    def get(self, adapter_id: str) -> RegisteredAdapter:
        try:
            return self._adapters[str(adapter_id)]
        except KeyError as exc:
            raise ValueError(f"unknown adapter '{adapter_id}'") from exc

    def verify_invocation(self, adapter_id: str) -> RegisteredAdapter:
        """Re-check the file immediately before launch to close TOCTOU gaps."""
        adapter = self.get(adapter_id)
        signer = adapter.manifest.signed_by.strip().upper()
        if signer not in self._trusted_keys:
            raise ValueError(f"adapter {adapter_id}: signer left the trust chain")
        errors = self._verify_artifact(
            adapter.manifest, adapter.artifact_path, signer, self._verifier
        )
        if errors:
            raise ValueError(f"adapter {adapter_id}: " + "; ".join(errors))
        return adapter


def build_sandbox_command(invocation: AdapterInvocation) -> list[str]:
    """Build a shell-free systemd-run command with explicit least privilege."""
    manifest = invocation.adapter.manifest
    limits = manifest.sandbox
    if limits.network:
        raise ValueError("privileged adapters cannot request network access")
    properties = [
        "NoNewPrivileges=yes",
        "PrivateTmp=yes",
        "PrivateDevices=yes",
        "ProtectSystem=strict",
        "ProtectHome=yes",
        "ProtectKernelTunables=yes",
        "ProtectKernelModules=yes",
        "ProtectControlGroups=yes",
        "RestrictSUIDSGID=yes",
        "RestrictRealtime=yes",
        "LockPersonality=yes",
        "SystemCallArchitectures=native",
        "RestrictAddressFamilies=AF_UNIX",
        "CapabilityBoundingSet=",
        "AmbientCapabilities=",
        "UMask=0077",
        f"MemoryMax={limits.memory_mb}M",
        f"CPUQuota={limits.cpu_percent}%",
        f"TasksMax={limits.max_processes}",
        f"RuntimeMaxSec={limits.timeout_seconds}",
        "LimitNOFILE=64",
    ]
    properties.extend(f"ReadOnlyPaths={p}" for p in limits.read_paths)
    properties.extend(f"ReadWritePaths={p}" for p in limits.write_paths)
    command = [
        "systemd-run", "--scope", "--collect",
        f"--setenv=SUNSHINE_ADAPTER_ID={manifest.id}",
        f"--setenv=SUNSHINE_ADAPTER_VERSION={manifest.version}",
        f"--setenv=SUNSHINE_INVOCATION_ID={invocation.invocation_id}",
    ]
    command.extend(f"--property={prop}" for prop in properties)
    command.extend([
        "--",
        str(invocation.adapter.artifact_path),
        "--sunshine-adapter-params",
        canonical_bytes(invocation.params).decode("utf-8"),
    ])
    return command


def default_adapter_launcher(invocation: AdapterInvocation) -> AdapterLaunch:
    """Launch a verified Rust adapter in the sandbox. Never uses a shell."""
    if os.geteuid() != 0:
        return AdapterLaunch(False, output="adapter launcher requires root privileges")
    manifest = invocation.adapter.manifest
    if invocation.dry_run:
        return AdapterLaunch(
            True, output="[dry-run] adapter would be launched in sandbox",
            changed=False, reversible=True,
            metadata={"command": "[dry-run]", "invocation": invocation.to_dict()},
        )
    command = build_sandbox_command(invocation)
    try:
        completed = subprocess.run(
            command, capture_output=True, text=True, check=False,
            timeout=manifest.sandbox.timeout_seconds + 5,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return AdapterLaunch(False, output=f"adapter execution failed: {exc}",
                             metadata={"command": command, "invocation": invocation.to_dict()})
    output = (completed.stdout or "") + (completed.stderr or "")
    return AdapterLaunch(
        ok=completed.returncode == 0,
        output=output.strip(),
        changed=completed.returncode == 0,
        reversible=True,
        metadata={
            "command": command,
            "exit_code": completed.returncode,
            "invocation": invocation.to_dict(),
        },
    )


AdapterLauncher = Callable[[AdapterInvocation], AdapterLaunch]


def load_manifest(path: str | Path) -> AdapterManifest:
    path = Path(path)
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ValueError(f"cannot load adapter manifest {path}: {exc}") from exc
    return AdapterManifest.from_dict(data)


def load_manifests(directory: str | Path) -> dict[str, AdapterManifest]:
    base = Path(directory)
    manifests: dict[str, AdapterManifest] = {}
    if not base.is_dir():
        return manifests
    for path in sorted(base.glob("*.toml")):
        manifest = load_manifest(path)
        if manifest.id in manifests:
            raise ValueError(f"duplicate adapter id {manifest.id}")
        manifests[manifest.id] = manifest
    return manifests


__all__ = [
    "ALLOWED_OPERATIONS", "ALLOWED_PERMISSIONS", "FORBIDDEN_PERMISSIONS",
    "FORBIDDEN_PARAM_KEYS", "AdapterInvocation", "AdapterLaunch", "AdapterLauncher",
    "AdapterManifest", "AdapterRegistry", "AdapterSandbox", "RegisteredAdapter",
    "build_sandbox_command", "default_adapter_launcher", "load_manifest",
    "load_manifests", "validate_adapter", "validate_adapter_params",
]
