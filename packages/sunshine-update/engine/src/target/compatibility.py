"""Source compatibility profiles for Arch → Sunshine transformation.

The five-year guarantee applies to *supported* source states, not to arbitrary
Linux installations.  This module classifies an :class:`ObservedState` into a
source profile and produces precise blockers for unsupported arrangements
instead of attempting a risky forced conversion.

Profiles (see TODO/TODO_Migration.md §14):

``arch-standard``
    Clean Arch: systemd, pacman, supported architecture, working UEFI/BIOS boot.
    Support level: ``official``.

``arch-customized``
    Arch with custom kernel, foreign/AUR packages, LVM/LUKS, or a non-default
    filesystem, provided the core foundation is still compatible.
    Support level: ``conditional`` (accepted, with warnings).

``sunshine-installed``
    An existing Sunshine OS.  The same engine reconciles it to the target.

``unsupported``
    A blocker was found (non-Arch base, no systemd, no pacman, broken package
    database, no boot entry, etc.).  Preflight must refuse to transform it.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

try:  # package import keeps a single class identity
    from ..core import ObservedState, Status
except ImportError:  # pragma: no cover - standalone scripts
    from core import ObservedState, Status


ARCH_DISTRIBUTIONS = frozenset({"arch", "archlinux", "sunshine", "sunshineos"})
SUPPORTED_ARCHITECTURES = frozenset({"x86_64", "aarch64"})
SUPPORTED_FILESYSTEMS = frozenset({"btrfs", "ext4", "xfs", "f2fs", "vfat"})


@dataclass(frozen=True)
class CompatibilityReport:
    """Result of classifying a source machine."""

    profile: str
    support_level: str  # official | conditional | unsupported
    supported: bool
    blockers: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "profile": self.profile,
            "support_level": self.support_level,
            "supported": self.supported,
            "blockers": list(self.blockers),
            "warnings": list(self.warnings),
            "evidence": list(self.evidence),
        }


def _observation(state: ObservedState, key: str) -> Optional[object]:
    return state.observations.get(key)


def _detected(state: ObservedState, key: str) -> str:
    obs = _observation(state, key)
    return str(getattr(obs, "detected", "") or "") if obs is not None else ""


def _status(state: ObservedState, key: str) -> Optional[Status]:
    obs = _observation(state, key)
    return getattr(obs, "status", None) if obs is not None else None


def classify_source(state: ObservedState) -> CompatibilityReport:
    """Classify *state* into a source compatibility profile.

    The machine is the source of truth.  A finding only becomes a blocker when
    it is observed with a usable status; an ABSENT or LOW-confidence signal is
    recorded as a warning rather than a hard refusal.
    """
    blockers: list[str] = []
    warnings: list[str] = []
    evidence: list[str] = []

    distribution = (state.distribution or "unknown").lower()
    architecture = (state.architecture or "unknown").lower()
    init = (state.init_system or "unknown").lower()
    package_manager = (state.package_manager or "unknown").lower()

    evidence.append(f"distribution={distribution}")
    evidence.append(f"architecture={architecture}")
    evidence.append(f"init_system={init}")
    evidence.append(f"package_manager={package_manager}")

    # --- hard foundation blockers ---------------------------------------- #
    if distribution not in ARCH_DISTRIBUTIONS:
        blockers.append(
            f"unsupported distribution '{state.distribution}'; Sunshine "
            "transforms Arch-based systems only"
        )
    if architecture not in SUPPORTED_ARCHITECTURES:
        blockers.append(
            f"unsupported architecture '{state.architecture}'; supported: "
            + ", ".join(sorted(SUPPORTED_ARCHITECTURES))
        )
    if init and init != "systemd":
        blockers.append(
            f"unsupported init system '{state.init_system}'; the Sunshine target "
            "requires systemd"
        )
    if package_manager and package_manager != "pacman":
        blockers.append(
            f"unsupported package manager '{state.package_manager}'; pacman "
            "remains the foundation authority"
        )

    # --- package database state ------------------------------------------ #
    if _status(state, "pacman.query") is Status.ABSENT:
        blockers.append(
            "pacman package database is not readable; repair the local database "
            "before transformation"
        )
    if "broken" in _detected(state, "pacman.query").lower():
        blockers.append("pacman reported a broken database")

    # --- boot state ------------------------------------------------------ #
    bootloader = _detected(state, "bootloader").lower()
    no_bootloader = (
        not bootloader
        or bootloader in {"none", "absent", "unknown", "not-detected"}
        or _status(state, "bootloader") is Status.ABSENT
    )
    if no_bootloader:
        blockers.append(
            "no usable bootloader entry was discovered; install and configure a "
            "supported bootloader before transformation"
        )

    # --- filesystem / encryption ----------------------------------------- #
    fs_status = _status(state, "storage.filesystems")
    fs_observed = fs_status is not None and fs_status is not Status.ABSENT
    filesystems = _detected(state, "storage.filesystems").lower()
    for fs in SUPPORTED_FILESYSTEMS:
        if fs in filesystems:
            evidence.append(f"filesystem:{fs}")
    # ``filesystem-inventory`` is a detection token, not a filesystem name.
    token_like = filesystems in {"filesystem-inventory", "filesystems", "unknown"}
    if fs_observed and not token_like and not any(fs in filesystems for fs in SUPPORTED_FILESYSTEMS):
        warnings.append(
            f"filesystem(s) '{filesystems}' are not in the verified set; "
            "transformation will be conditional"
        )
    luks_status = _status(state, "capability.luks")
    if "luks" in filesystems or (luks_status is not None and luks_status is not Status.ABSENT):
        warnings.append("LUKS detected; recovery integration will be verified after boot")
    lvm_status = _status(state, "capability.lvm")
    if lvm_status is not None and lvm_status is not Status.ABSENT:
        warnings.append("LVM detected; mount topology must be validated after boot")

    # --- conditional Arch customisations --------------------------------- #
    if state.foreign_packages:
        warnings.append(
            f"{len(state.foreign_packages)} foreign/AUR package(s) detected; "
            "they will be preserved, not removed"
        )
        evidence.append(f"foreign packages: {len(state.foreign_packages)}")
    running_kernel = _detected(state, "kernel.running")
    installed_kernels = _detected(state, "kernel.installed")
    # Detection tokens such as ``running-kernel`` are not version strings;
    # comparing them would produce a false "custom kernel" warning.
    looks_like_version = lambda s: any(ch.isdigit() for ch in s)
    if (running_kernel and installed_kernels and
            looks_like_version(running_kernel) and looks_like_version(installed_kernels) and
            running_kernel not in installed_kernels):
        warnings.append(
            f"running kernel '{running_kernel}' is not in the installed kernel "
            "set (possible custom kernel)"
        )

    # --- partial prior Sunshine installation ----------------------------- #
    partial = _status(state, "sunshine.partial-installation")
    if partial is not None and partial is not Status.ABSENT:
        warnings.append(
            "a partial Sunshine installation was detected; components will be "
            "discovered individually rather than assuming a release"
        )

    # --- choose profile -------------------------------------------------- #
    sunshine_present = distribution in {"sunshine", "sunshineos"} or (
        _status(state, "sunshine.installation") is not None
        and _status(state, "sunshine.installation") is not Status.ABSENT
    )
    if blockers:
        profile, support_level, supported = "unsupported", "unsupported", False
    elif sunshine_present:
        profile, support_level, supported = "sunshine-installed", "official", True
    elif warnings:
        profile, support_level, supported = "arch-customized", "conditional", True
    else:
        profile, support_level, supported = "arch-standard", "official", True

    return CompatibilityReport(
        profile=profile,
        support_level=support_level,
        supported=supported,
        blockers=blockers,
        warnings=warnings,
        evidence=evidence,
    )


def preflight_source(state: ObservedState, *, allow_conditional: bool = True) -> CompatibilityReport:
    """Return the compatibility report, optionally rejecting conditional sources.

    ``--apply`` uses ``allow_conditional=True``; an operator can opt into a
    stricter policy when a fully standard Arch source is required.
    """
    report = classify_source(state)
    if not allow_conditional and report.support_level == "conditional":
        return CompatibilityReport(
            profile=report.profile,
            support_level="unsupported",
            supported=False,
            blockers=list(report.blockers) + [
                "conditional source profile is not permitted by the active policy"
            ],
            warnings=list(report.warnings),
            evidence=list(report.evidence),
        )
    return report
