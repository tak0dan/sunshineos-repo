"""Derive high-level capabilities from corroborated discovery observations.

Capabilities are strings consumed by planning and validation.  They are never
invented from a single weak hint:

* an observation must be at least ``MEDIUM`` confidence (and usually in an
  active/configured status) to count as a signal;
* most capabilities require two independent signals;
* a granted capability is recorded as a ``capability.<name>`` observation with
  the list of signals that supported it, so every grant is auditable;
* LOW-confidence observations cannot grant capabilities at all, which keeps
  them from authorising destructive operations.

The capability vocabulary intentionally includes both base-system abilities
(``systemd``, ``pacman``, ``kernel-installation``, ...) and Sunshine-level ones
(``configuration-ownership``, ``component-schema-discovery``,
``state-persistence``, ...).  Missing capabilities are recorded as ABSENT
observations instead of silently omitted.
"""
from __future__ import annotations

try:  # package import keeps a single ObservedState class identity
    from ..core import Confidence, ObservedState, Status
except ImportError:  # pragma: no cover - supports standalone scripts in src/
    from core import Confidence, ObservedState, Status

from ._util import (
    Execute,
    as_execute,
    at_least,
    is_dir,
    observe,
)


_ACTIVE_STATUSES = (Status.CONFIGURED, Status.ENABLED, Status.RUNNING, Status.FUNCTIONAL)
_RUNNING_STATUSES = (Status.ENABLED, Status.RUNNING, Status.FUNCTIONAL)
_INSTALLED_STATUSES = (Status.INSTALLED, Status.CONFIGURED, Status.ENABLED, Status.RUNNING, Status.FUNCTIONAL)


def derive_capabilities(state: ObservedState, root: str = "/", execute: Execute | None = None) -> ObservedState:
    """Derive and record capabilities from *state*.

    Args:
        state: An :class:`~core.ObservedState` enriched by all `discover_*`
            passes.  Earlier passes must have run; missing observations simply
            fail the corresponding signal checks.
        root: Filesystem prefix used only for directory corroboration (for
            example the presence of both X11 and Wayland session directories).
        execute: Accepted for interface symmetry; no commands are run because
            all evidence is already in *state*.

    Returns:
        The same *state* with ``capabilities`` populated.  Each granted name
        also appears in ``state.observations["capability.<name>"]`` together
        with the corroborating signals.
    """
    del execute  # capabilities are derived from observations, not new commands
    observations = state.observations

    def signal(
        component: str,
        statuses: tuple[Status, ...] = _ACTIVE_STATUSES,
        minimum: Confidence = Confidence.MEDIUM,
        detected: str | None = None,
    ) -> bool:
        """True if *component* is a trustworthy signal for a capability."""
        item = observations.get(component)
        if item is None:
            return False
        if not at_least(item.confidence, minimum):
            return False
        if item.status not in statuses:
            return False
        if detected is not None and item.detected != detected:
            return False
        return True

    def grant(name: str, signals: list[tuple[bool, str]], minimum: int = 1) -> bool:
        """Grant *name* only when at least *minimum* signals are trustworthy."""
        supporting = [(ok, description) for ok, description in signals if ok]
        if len(supporting) < minimum:
            observe(
                state,
                f"capability.{name}",
                name,
                Confidence.LOW,
                Status.ABSENT,
                [
                    f"insufficient corroboration: {len(supporting)}/{len(signals)} signals "
                    f"(required {minimum})"
                ],
            )
            return False
        confidence = Confidence.HIGH if len(supporting) >= 2 else Confidence.MEDIUM
        evidence = [f"corroborating signals: {len(supporting)}/{len(signals)}"]
        evidence.extend(description for _ok, description in supporting)
        state.capabilities.add(name)
        observe(state, f"capability.{name}", name, confidence, Status.CONFIGURED, evidence)
        return True

    # --- base system -------------------------------------------------------
    grant(
        "systemd",
        [
            (state.init_system == "systemd", f"init_system={state.init_system}"),
            (signal("system.init", _RUNNING_STATUSES), "system.init is running"),
            (signal("services.systemd", _RUNNING_STATUSES), "systemd service manager responds"),
        ],
    )
    grant(
        "service-management",
        [
            (signal("services.enabled-units", (Status.ENABLED,)), "enabled unit list available"),
            (signal("services.running-units", (Status.RUNNING,)), "running unit list available"),
            (signal("services.systemd", _RUNNING_STATUSES), "systemd service manager responds"),
        ],
        minimum=2,
    )
    grant(
        "pacman",
        [
            (state.package_manager == "pacman", f"package_manager={state.package_manager}"),
            (signal("pacman.query", (Status.FUNCTIONAL,)), "pacman -Q succeeded"),
        ],
    )
    grant(
        "package-ownership-registry",
        [
            (signal("pacman.query", (Status.FUNCTIONAL,)), "installed package inventory readable"),
            (signal("packages.official", _INSTALLED_STATUSES), "official package classification available"),
            (signal("pacman.repositories", (Status.CONFIGURED,)), "repository configuration readable"),
        ],
        minimum=2,
    )
    grant(
        "repository-configuration",
        [
            (signal("pacman.repositories", (Status.CONFIGURED,)), "pacman repositories configured"),
            (signal("sunshine.repository", (Status.CONFIGURED,)), "Sunshine repository configured"),
        ],
    )

    # --- kernel and boot ---------------------------------------------------
    kernel_packages = sorted(
        name for name in state.packages if name == "linux" or name.startswith("linux-")
    )
    grant(
        "kernel-installation",
        [
            (signal("kernel.installed", (Status.INSTALLED,)), "installed kernel module directories"),
            (bool(kernel_packages), "kernel packages: " + ", ".join(kernel_packages)),
            (signal("boot.mkinitcpio", _INSTALLED_STATUSES), "initramfs tooling/config present"),
        ],
        minimum=2,
    )
    grant(
        "initramfs-generation",
        [
            (signal("boot.mkinitcpio", _INSTALLED_STATUSES), "mkinitcpio config/tool present"),
        ],
    )
    grant(
        "efi-boot",
        [
            (signal("boot.efi", _RUNNING_STATUSES, detected="efi-firmware"), "EFI firmware mode"),
            (signal("boot.esp", (Status.CONFIGURED,), detected="efi-system-partition"), "ESP mounted/configured"),
        ],
        minimum=2,
    )
    grant(
        "boot-entry-management",
        [
            (signal("boot.efi", _RUNNING_STATUSES), "EFI firmware mode"),
            (signal("boot.esp", (Status.CONFIGURED,)), "ESP mounted/configured"),
            (signal("boot.efibootmgr", _RUNNING_STATUSES), "efibootmgr usable"),
            (signal("bootloader", _RUNNING_STATUSES), "bootloader has an active firmware entry"),
        ],
        minimum=2,
    )

    # --- storage and recovery ---------------------------------------------
    for capability, component in (("btrfs", "storage.btrfs"), ("lvm", "storage.lvm"), ("luks", "storage.luks")):
        grant(capability, [(signal(component, _ACTIVE_STATUSES), f"{component} observed")])
    snapshot_tools = sorted(name for name in ("snapper", "timeshift", "btrfs-assistant") if name in state.packages)
    grant(
        "recovery-checkpoints",
        [
            (signal("storage.btrfs", _ACTIVE_STATUSES), "btrfs subvolumes available for snapshots"),
            (signal("storage.snapshots", _ACTIVE_STATUSES), "snapshot directories/config present"),
            (bool(snapshot_tools), "snapshot tools: " + ", ".join(snapshot_tools)),
        ],
        minimum=2,
    )

    # --- desktop -----------------------------------------------------------
    grant(
        "desktop-session-discovery",
        [
            (signal("desktop.sessions", _INSTALLED_STATUSES), "session desktop files read"),
            (is_dir(root, "/usr/share/xsessions"), "/usr/share/xsessions exists"),
            (is_dir(root, "/usr/share/wayland-sessions"), "/usr/share/wayland-sessions exists"),
        ],
        minimum=2,
    )
    grant("pipewire", [(signal("audio.pipewire", _INSTALLED_STATUSES), "PipeWire package/unit detected")])
    grant("pulseaudio", [(signal("audio.pulseaudio", _INSTALLED_STATUSES), "PulseAudio package/unit detected")])
    grant(
        "networkmanager",
        [
            (
                signal("network.backend", _ACTIVE_STATUSES, detected="networkmanager"),
                "NetworkManager is the selected backend",
            )
        ],
    )
    grant(
        "display-manager",
        [(signal("desktop.display-manager", _ACTIVE_STATUSES), "display manager enabled/running")],
    )

    # --- Sunshine-specific -------------------------------------------------
    grant(
        "configuration-ownership",
        [
            (signal("sunshine.config", (Status.CONFIGURED,)), "Sunshine configuration tree present"),
            (signal("sunshine.component-schemas", (Status.CONFIGURED,)), "component schemas present"),
            (signal("sunshine.state", (Status.CONFIGURED,)), "ownership/state records present"),
        ],
        minimum=2,
    )
    grant(
        "component-schema-discovery",
        [(signal("sunshine.component-schemas", (Status.CONFIGURED,)), "component schemas parsed")],
    )
    grant(
        "state-persistence",
        [(signal("sunshine.state", (Status.CONFIGURED,)), "persisted Sunshine state present")],
    )
    grant(
        "repository-driven-evolution",
        [
            (signal("sunshine.repository", (Status.CONFIGURED,)), "Sunshine repository configuration"),
            (signal("sunshine.component-schemas", (Status.CONFIGURED,)), "published component schemas"),
        ],
        minimum=2,
    )
    return state
