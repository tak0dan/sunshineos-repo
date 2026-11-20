"""Parsing of declarative Sunshine target manifests.

A target manifest is the *desired state*: it says which components must exist,
at which schema version, which capabilities each component offers/consumes,
which preservation policies bind the engine, and which packages belong to each
logical set. It deliberately says nothing about how to converge a machine to
that state - that is the planner's job.

``load_target()`` works with no arguments by parsing ``DEFAULT_TARGET_TOML``, an
embedded copy of the currently published target (mirrored verbatim in
``current.toml`` so the engine remains usable even when installed as a single
module tree without data files). Passing a path loads an alternative manifest,
which is useful for testing future target generations before publishing them.

Only the standard library is used; ``tomllib`` is stdlib since Python 3.11.
"""
from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any, Mapping

from ..core import ComponentSpec, Lifecycle, TargetSpec

# Keep this text semantically identical to current.toml (tests enforce it).
DEFAULT_TARGET_TOML = """
format_version = 1

[target]
release = "sunshine-2026.1"
repository_generation = 7

[components.core]
schema = 3
required = true
software_version = "2026.1"
lifecycle = "evolve"
provides = ["arch-foundation", "systemd", "pacman"]
requires = []

[components.configuration]
schema = 4
required = true
software_version = "2026.1"
lifecycle = "evolve"
provides = ["unified-configuration", "configuration-ownership"]
requires = ["arch-foundation", "systemd"]

[components.ownership]
schema = 2
required = true
software_version = "2026.1"
lifecycle = "evolve"
provides = ["package-ownership-registry", "ownership-enforcement"]
requires = ["pacman", "unified-configuration"]

[components.kernel_management]
schema = 2
required = true
software_version = "2026.1"
lifecycle = "evolve"
provides = ["kernel-installation", "kernel-fallback"]
requires = ["arch-foundation", "pacman"]

[components.boot_integration]
schema = 2
required = true
software_version = "2026.1"
lifecycle = "evolve"
provides = ["boot-entry-management", "bootloader-configuration"]
requires = ["kernel-installation", "unified-configuration"]

[components.recovery]
schema = 3
required = true
software_version = "2026.1"
lifecycle = "evolve"
provides = ["recovery-checkpoints", "migration-recovery", "rollback"]
requires = ["unified-configuration", "ownership-enforcement", "boot-entry-management"]

[components.desktop_integration]
schema = 4
required = true
software_version = "2026.1"
lifecycle = "evolve"
provides = ["desktop-session-discovery", "sunshine-profile-management"]
requires = ["unified-configuration", "package-ownership-registry"]

[components.nix_integration]
schema = 2
required = false
software_version = "2026.1"
lifecycle = "introduce"
provides = ["nix-integration", "foreign-package-visibility"]
requires = ["pacman", "package-ownership-registry"]

[policies]
preserve_user_configuration = true
preserve_user_packages = true
require_signed_packages = true

[package_sets]
base = ["base", "systemd", "pacman", "dbus", "sudo"]
configuration = ["sunshine-base", "jq"]
ownership = ["sunshine-base"]
kernel_management = ["linux", "linux-headers", "linux-firmware", "mkinitcpio"]
boot_integration = ["os-prober"]
recovery = ["rsync", "btrfs-progs"]
desktop_integration = []
nix_integration = []

"bootloader.grub" = ["grub", "efibootmgr"]
"bootloader.systemd-boot" = ["systemd", "efibootmgr"]
"bootloader.refind" = ["refind"]
"network.networkmanager" = ["networkmanager"]
"network.systemd-networkd" = ["systemd"]
"audio.pipewire" = ["pipewire", "pipewire-pulse", "wireplumber"]
"audio.pulseaudio" = ["pulseaudio", "pulseaudio-alsa"]
"nix.optional" = ["nix"]
"""


def target_from_dict(data: Mapping[str, Any], source: str = "<dict>") -> TargetSpec:
    """Validate and convert parsed TOML data into the typed ``TargetSpec``.

    Unknown keys are ignored so a newer manifest can be read by an older engine
    without failing outright, but a mismatched ``format_version`` and invalid
    enum values are hard errors: silently accepting them could make the planner
    emit operations against a target it does not understand.
    """
    version = int(data.get("format_version", 1))
    if version != 1:
        raise ValueError(f"unsupported target format_version {version} in {source}")

    meta = data.get("target") or {}
    if not isinstance(meta, Mapping):
        raise ValueError(f"[target] must be a table in {source}")

    components: dict[str, ComponentSpec] = {}
    raw_components = data.get("components") or {}
    if not isinstance(raw_components, Mapping):
        raise ValueError(f"[components] must be a table in {source}")
    for component_id, raw in raw_components.items():
        if not isinstance(raw, Mapping):
            raise ValueError(f"component '{component_id}' must be a table in {source}")
        raw_lifecycle = raw.get("lifecycle", Lifecycle.EVOLVE.value)
        try:
            lifecycle = Lifecycle(raw_lifecycle)
        except ValueError as exc:
            raise ValueError(
                f"component '{component_id}' has invalid lifecycle {raw_lifecycle!r} in {source}"
            ) from exc
        components[str(component_id)] = ComponentSpec(
            id=str(component_id),
            schema=int(raw.get("schema", 0)),
            required=bool(raw.get("required", True)),
            software_version=str(raw.get("software_version", "")),
            lifecycle=lifecycle,
            provides=[str(c) for c in raw.get("provides", [])],
            requires=[str(c) for c in raw.get("requires", [])],
        )

    raw_policies = data.get("policies") or {}
    if not isinstance(raw_policies, Mapping):
        raise ValueError(f"[policies] must be a table in {source}")

    raw_sets = data.get("package_sets") or {}
    if not isinstance(raw_sets, Mapping):
        raise ValueError(f"[package_sets] must be a table in {source}")
    package_sets = {
        str(name): [str(pkg) for pkg in packages]
        for name, packages in raw_sets.items()
        if isinstance(packages, (list, tuple))
    }

    return TargetSpec(
        format_version=version,
        release=str(meta.get("release", "")),
        repository_generation=int(meta.get("repository_generation", 0)),
        components=components,
        policies={str(k): bool(v) for k, v in raw_policies.items()},
        package_sets=package_sets,
    )


def parse_target_toml(text: str, source: str = "<toml>") -> TargetSpec:
    """Parse a TOML document into a ``TargetSpec``, with a clear error on bad TOML."""
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ValueError(f"invalid target manifest {source}: {exc}") from exc
    return target_from_dict(data, source)


def load_target(path: str | Path | None = None) -> TargetSpec:
    """Load the desired-state target from ``path``, or the embedded default.

    With no path this returns the current published Sunshine target without
    touching the filesystem. An explicit path is read as UTF-8 TOML. Callers
    get a fresh mutable ``TargetSpec`` each time, so resolution may safely
    customise it.
    """
    if path is None:
        return parse_target_toml(DEFAULT_TARGET_TOML, "embedded default target")
    manifest_path = Path(path)
    return parse_target_toml(
        manifest_path.read_text(encoding="utf-8"), str(manifest_path)
    )
