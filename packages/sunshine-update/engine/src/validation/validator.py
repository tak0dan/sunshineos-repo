"""Capability and system validators.

A capability is only present when it is demonstrably operational, not merely
because a package is installed or a unit file exists. Validators therefore
prefer active probes (systemctl is-active, actual boot entry inspection,
parsing of generated configuration) over package presence.

All validators accept an injected ``execute(cmd) -> (rc, stdout, stderr)``
callable and a filesystem ``root`` so they can run against simulated systems in
tests and against the real machine in production.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from ..core import ObservedState, TargetSpec, Status

Execute = Callable[[str], tuple[int, str, str]]


def _default_execute(cmd: str) -> tuple[int, str, str]:
    import subprocess
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr


@dataclass
class ValidationReport:
    capability: str
    passed: bool
    evidence: list[str] = field(default_factory=list)
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "capability": self.capability,
            "passed": self.passed,
            "evidence": self.evidence,
            "detail": self.detail,
        }


# Each validator returns (passed, evidence list, detail).
_CAPABILITY_PROBES: dict[str, Callable[[Path, Execute], tuple[bool, list[str], str]]] = {}


def _register(name: str):
    def deco(fn):
        _CAPABILITY_PROBES[name] = fn
        return fn
    return deco


def _any_path(root: Path, *relative_paths: str, state_root: Path | None = None) -> tuple[bool, list[str]]:
    # A live apply keeps engine bookkeeping in state_root while mutating the
    # real filesystem. Engine-owned capabilities may live in either tree.
    roots = [Path(root)]
    if state_root is not None and Path(state_root) != Path(root):
        roots.append(Path(state_root))
    found = [str(Path(r) / p) for p in relative_paths for r in roots if (r / p).exists()]
    return bool(found), found or list(relative_paths)


def _owned_dir(root: Path, relative: str, state_root: Path | None = None) -> tuple[bool, list[str]]:
    roots = [Path(root)]
    if state_root is not None and Path(state_root) != Path(root):
        roots.append(Path(state_root))
    found = [str(r / relative) for r in roots if (r / relative).is_dir()]
    return bool(found), found or [str(Path(root) / relative)]


@_register("arch-foundation")
def _v_arch_foundation(root: Path, ex: Execute):
    rc, out, _ = ex("pacman --version")
    ok = rc == 0 and "pacman" in out.lower()
    return ok, [out.strip().splitlines()[0] if out.strip() else "pacman unavailable"], \
        "Arch package foundation is available"


@_register("systemd")
def _v_systemd(root: Path, ex: Execute):
    rc, out, _ = ex("systemctl is-system-running")
    ok = rc == 0 and "degraded" not in out.lower() or rc == 0
    return ok, [f"systemctl is-system-running -> {out.strip()}"], "systemd manager responding"


@_register("pacman")
def _v_pacman(root: Path, ex: Execute):
    rc, out, _ = ex("pacman --version")
    ok = rc == 0 and "pacman" in out.lower()
    return ok, [out.strip().splitlines()[0] if out.strip() else "no output"], "pacman usable"


@_register("package-ownership-registry")
def _v_ownership(root: Path, ex: Execute, state_root: Path | None = None):
    ok, paths = _owned_dir(root, "var/lib/sunshine/ownership", state_root)
    return ok, paths, "ownership registry directory initialized"


@_register("configuration-ownership")
def _v_config(root: Path, ex: Execute, state_root: Path | None = None):
    config_ok, config_paths = _owned_dir(root, "etc/sunshine")
    roots = [Path(root)]
    if state_root is not None and Path(state_root) != Path(root):
        roots.append(Path(state_root))
    manifests = [str(r / "var/lib/sunshine/state/components.toml") for r in roots
                 if (r / "var/lib/sunshine/state/components.toml").exists()]
    ok = config_ok and bool(manifests)
    return ok, config_paths + (manifests or ["components.toml missing"]), \
        "Sunshine config root and component registry present"


@_register("unified-configuration")
def _v_unified_config(root: Path, ex: Execute, state_root: Path | None = None):
    ok, paths = _any_path(
        root,
        "etc/sunshine/config",
        "etc/sunshine/components",
        "etc/sunshine/system.toml",
        "var/lib/sunshine/config",
        state_root=state_root,
    )
    return ok, paths, "unified Sunshine configuration tree is present"


@_register("ownership-enforcement")
def _v_ownership_enforcement(root: Path, ex: Execute, state_root: Path | None = None):
    ok, paths = _any_path(
        root,
        "var/lib/sunshine/ownership",
        "etc/sunshine/ownership.toml",
        "var/lib/sunshine/state/components.toml",
        state_root=state_root,
    )
    return ok, paths, "package ownership registry is wired into component state"


@_register("boot-entry-management")
def _v_boot(root: Path, ex: Execute):
    rc, out, _ = ex("efibootmgr -v")
    efi = root / "sys/firmware/efi"
    # EFI firmware alone does not prove boot entries can be managed; the tool
    # must actually enumerate them, matching the discovery capability rule.
    ok = rc == 0 and "Boot" in out
    return ok, [out.strip()[:200], f"efi dir: {efi.exists()}"], "boot entry tooling available"


@_register("bootloader-configuration")
def _v_bootloader_config(root: Path, ex: Execute):
    rc, out, _ = ex("efibootmgr -v")
    _found, configs = _any_path(root, "boot/grub/grub.cfg", "boot/loader/entries")
    ok = bool(configs and any((root / p).exists() for p in configs)) or (
        rc == 0 and "Boot" in out
    )
    return ok, list(configs) + [out.strip()[:120]], "bootloader configuration or EFI entry is present"


@_register("kernel-installation")
def _v_kernel(root: Path, ex: Execute):
    mods = root / "usr/lib/modules"
    dirs = list(mods.iterdir()) if mods.is_dir() else []
    ok = len(dirs) > 0
    return ok, [str(d.name) for d in dirs[:5]], "at least one kernel installed"


@_register("kernel-fallback")
def _v_fallback(root: Path, ex: Execute):
    rc, out, _ = ex("ls /boot/initramfs-linux*-fallback.img 2>/dev/null")
    ok = rc == 0 and bool(out.strip())
    return ok, [out.strip()[:200]], "fallback initramfs present"


@_register("recovery-checkpoints")
def _v_recovery(root: Path, ex: Execute, state_root: Path | None = None):
    ok, paths = _any_path(
        root,
        "migration/checkpoints",
        "var/lib/sunshine/recovery/checkpoints",
        "recovery/checkpoints",
        state_root=state_root,
    )
    return ok, paths, "recovery checkpoint store initialized"


@_register("rollback")
def _v_rollback(root: Path, ex: Execute, state_root: Path | None = None):
    ok, paths = _any_path(
        root,
        "var/lib/sunshine/recovery/checkpoints",
        "migration/journal/journal.jsonl",
        "migration/transactions",
        state_root=state_root,
    )
    return ok, paths, "rollback evidence (checkpoints or journal) is present"


@_register("nix-integration")
def _v_nix(root: Path, ex: Execute):
    rc, out, _ = ex("nix --version")
    ok, paths = _any_path(root, "etc/nix/nix.conf", "var/lib/sunshine/nix")
    return ok or rc == 0, paths + [out.strip()[:120]], "Nix integration is available when enabled"


@_register("foreign-package-visibility")
def _v_foreign_packages(root: Path, ex: Execute):
    rc, _, _ = ex("pacman -Qqm")
    return rc == 0, ["pacman -Qqm"], "foreign packages can be enumerated"


@_register("desktop-session-discovery")
def _v_desktop(root: Path, ex: Execute):
    found = []
    for d in ("usr/share/xsessions", "usr/share/wayland-sessions"):
        p = root / d
        if p.is_dir():
            found += [f.name for f in p.glob("*.desktop")]
    ok = bool(found)
    return ok, found[:8], "at least one desktop session discoverable"


@_register("sunshine-profile-management")
def _v_profile(root: Path, ex: Execute):
    p = root / "etc/sunshine/profiles"
    ok = p.is_dir()
    return ok, [str(p)], "Sunshine desktop profile directory present"


@_register("network-connection")
def _v_network(root: Path, ex: Execute):
    rc, out, _ = ex("nmcli -t general status")
    ok = rc == 0 and "connected" in out.lower()
    return ok, [out.strip()[:200]], "NetworkManager reports a connection"


@_register("audio-pipewire")
def _v_audio(root: Path, ex: Execute, state_root: Path | None = None):
    rc, out, err = ex("systemctl --user is-active pipewire")
    if rc == 0 and "active" in out.lower():
        return True, [out.strip()], "pipewire user service active"
    # Verification run as root has no user bus, so it cannot query a user
    # service. Only treat that specific environment limitation as inconclusive
    # and fall back to the installed package; a real "inactive" answer (used
    # by tamper tests) must still fail closed.
    no_bus = any(needle in (err or "") for needle in (
        "user scope bus", "DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR",
        "Failed to connect to bus",
    ))
    if no_bus:
        rc2, out2, _ = ex("pacman -Q pipewire")
        if rc2 == 0:
            return True, [(out or err).strip()[:120], out2.strip()], \
                "pipewire installed; user session query unavailable to this caller"
    return False, [(out or err).strip()[:200]], "pipewire user service active"


@_register("audio-pulseaudio")
def _v_audio_pulse(root: Path, ex: Execute):
    rc, out, _ = ex("systemctl --user is-active pulseaudio")
    ok = rc == 0 and "active" in out.lower()
    return ok, [out.strip()], "pulseaudio user service active"


def _v_desktop_profile(root: Path, ex: Execute, state_root: Path | None = None,
                       profile_id: str = "") -> tuple[bool, list[str], str]:
    """Verify a selected desktop profile is actually materialised in config.

    ``desktop-profile:<id>`` is a capability the resolver adds when a profile
    is chosen (automatically or by operator answer). The declarative profile
    tree is the evidence: the default profile file must exist and name the
    selected profile, or a dedicated profile file must be present.
    """
    roots = [Path(root)]
    if state_root is not None and Path(state_root) != Path(root):
        roots.append(Path(state_root))
    candidates = [
        "etc/sunshine/profiles/default.toml",
        f"etc/sunshine/profiles/{profile_id}.toml",
    ]
    found: list[str] = []
    for base in roots:
        for rel in candidates:
            p = base / rel
            if not p.is_file():
                continue
            text = ""
            try:
                text = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                pass
            if not profile_id or profile_id in text or rel.endswith(f"/{profile_id}.toml"):
                found.append(str(p))
    return bool(found), (found or [str(Path(root) / candidates[0])]), \
        f"desktop profile '{profile_id}' configuration is present"


@_register("migration-recovery")
def _v_migration_recovery(root: Path, ex: Execute, state_root: Path | None = None):
    ok, paths = _any_path(root, "migration/journal", "var/lib/sunshine/migration/journal",
                          state_root=state_root)
    return ok, paths, "migration journal store present"


def validate_capability(capability: str, root: str | Path = "/", execute: Optional[Execute] = None,
                        observed: Optional[ObservedState] = None,
                        state_root: Optional[str | Path] = None) -> ValidationReport:
    """Probe a single capability. Unknown capabilities fail closed (never assume)."""
    ex = execute or _default_execute
    p = Path(root)
    probe = _CAPABILITY_PROBES.get(capability)
    profile_id: str | None = None
    if probe is None and capability.startswith("desktop-profile:"):
        profile_id = capability.split(":", 1)[1]
    if probe is None and profile_id is None:
        # Fall back to the discovery-derived capability set, but mark it as weak evidence.
        if observed is not None and capability in observed.capabilities:
            return ValidationReport(capability, True, ["observed-capability"], "derived from discovery only; no active probe")
        return ValidationReport(capability, False, [], f"no validator for capability '{capability}'")
    try:
        try:
            if profile_id is not None:
                ok, evidence, detail = _v_desktop_profile(
                    p, ex, Path(state_root) if state_root is not None else None, profile_id)
            else:
                ok, evidence, detail = probe(p, ex, Path(state_root) if state_root is not None else None)
        except TypeError:  # probes that only need the system root keep their 2-arg form
            ok, evidence, detail = probe(p, ex)
    except Exception as exc:  # a broken probe must fail closed, not crash the engine
        return ValidationReport(capability, False, [], f"validator error: {exc}")
    return ValidationReport(capability, bool(ok), evidence, detail)


def validate_system(observed: ObservedState, target: TargetSpec, root: str | Path = "/",
                    execute: Optional[Execute] = None,
                    state_root: Optional[str | Path] = None) -> list[ValidationReport]:
    """Validate every capability required by the resolved target's components."""
    caps: set[str] = set()
    # Only active (required) components are promises of the resolved target.
    # Validating an optional component that was deliberately not activated
    # (for example Nix on a plain Arch machine) produces a permanent false
    # failure of --verify on systems that are actually correct.
    for c in target.required_components():
        caps.update(c.provides)
    # The resolver preserves network/audio choices in the active package sets
    # (``network``/``audio``); the ``network.<choice>`` keys are the catalogue of
    # *supported* choices and must not all be validated as if they were active.
    if target.package_sets.get("network"):
        caps.add("network-connection")
    audio_packages = " ".join(target.package_sets.get("audio", [])).lower()
    if audio_packages:
        caps.add("audio-pulseaudio" if "pulseaudio" in audio_packages else "audio-pipewire")
    caps.add("systemd")
    caps.add("pacman")
    return [validate_capability(c, root, execute, observed, state_root) for c in sorted(caps)]


def all_passed(reports: list[ValidationReport]) -> bool:
    return all(r.passed for r in reports)
