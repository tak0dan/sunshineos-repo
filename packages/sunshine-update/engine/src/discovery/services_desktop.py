"""Discover systemd services, network/audio backends and desktop sessions.

The module distinguishes four states for each backend:

* ``INSTALLED`` -- package or configuration file exists;
* ``ENABLED`` -- a systemd unit is enabled (or ``display-manager.service``
  points at it);
* ``RUNNING`` -- the unit is active or a runtime CLI answers;
* ``FUNCTIONAL`` -- reserved for the validation layer; discovery only reports
  what it observed, never that a service actually works end-to-end.

Unit lists come from ``systemctl list-unit-files --state=enabled`` and
``systemctl list-units --state=running``.  If those commands fail, individual
``systemctl is-enabled`` / ``is-active`` calls are used as a fallback for the
small set of known backends.  Desktop sessions are read from
``/usr/share/xsessions`` and ``/usr/share/wayland-sessions``; the current
session environment is taken from a root-scoped ``/proc/self/environ`` when
available, then from ``env``, and only from the host environment when the real
root is inspected (a fake root must not inherit host variables).
"""
from __future__ import annotations

import os

try:  # package import keeps a single ObservedState class identity
    from ..core import Confidence, ObservedState, Status
except ImportError:  # pragma: no cover - supports standalone scripts in src/
    from core import Confidence, ObservedState, Status

from ._util import (
    Execute,
    abbreviate,
    as_execute,
    command_ok,
    find_files,
    first_line,
    is_dir,
    lines,
    observe,
    parse_key_values,
    read_file,
    read_symlink,
    run,
)


_ENABLED_COMMAND = "systemctl list-unit-files --type=service --state=enabled --no-legend --no-pager"
_RUNNING_COMMAND = "systemctl list-units --type=service --state=running --no-legend --no-pager"
_SESSION_ENV_KEYS = (
    "XDG_SESSION_TYPE",
    "XDG_CURRENT_DESKTOP",
    "DESKTOP_SESSION",
    "DISPLAY",
    "WAYLAND_DISPLAY",
)


def _parse_unit_names(stdout: str) -> set[str]:
    """Extract unit names from ``systemctl --no-legend`` output."""
    names: set[str] = set()
    for line in lines(stdout):
        fields = line.split()
        if fields and "." in fields[0] and "=" not in fields[0]:
            names.add(fields[0])
    return names


def _unit_query(execute: Execute, unit: str, kind: str) -> bool:
    """Ask systemctl directly whether a unit is ``enabled`` or ``active``."""
    rc, stdout, _ = run(execute, f"systemctl is-{kind} {unit}")
    expected = "enabled" if kind == "enabled" else "active"
    return command_ok(rc) and stdout.strip().lower() == expected


def _collect_systemd(state: ObservedState, execute: Execute) -> tuple[set[str], set[str]]:
    """Record systemd runtime and unit-list observations."""
    evidence: list[str] = []
    signals = 0

    rc_state, out_state, _ = run(execute, "systemctl is-system-running")
    system_state = first_line(out_state).lower() if command_ok(rc_state) else ""
    if system_state:
        evidence.append(f"systemctl is-system-running: {system_state}")
        signals += 1

    rc_enabled, out_enabled, _ = run(execute, _ENABLED_COMMAND)
    enabled = _parse_unit_names(out_enabled) if command_ok(rc_enabled) else set()
    if enabled:
        evidence.append("enabled units: " + abbreviate(sorted(enabled)))
        signals += 1

    rc_running, out_running, _ = run(execute, _RUNNING_COMMAND)
    running = _parse_unit_names(out_running) if command_ok(rc_running) else set()
    if running:
        evidence.append("running units: " + abbreviate(sorted(running)))
        signals += 1

    if signals:
        status = Status.FUNCTIONAL if system_state == "running" else (Status.RUNNING if signals >= 2 else Status.INSTALLED)
        confidence = Confidence.HIGH if signals >= 2 else Confidence.MEDIUM
    else:
        status, confidence = Status.ABSENT, Confidence.LOW
        evidence.append("no systemctl response")
    observe(state, "services.systemd", "systemd", confidence, status, evidence)

    observe(
        state,
        "services.enabled-units",
        "enabled-services",
        Confidence.HIGH if command_ok(rc_enabled) else Confidence.LOW,
        Status.ENABLED if enabled else Status.ABSENT,
        ["enabled: " + abbreviate(sorted(enabled))],
    )
    observe(
        state,
        "services.running-units",
        "running-services",
        Confidence.HIGH if command_ok(rc_running) else Confidence.LOW,
        Status.RUNNING if running else Status.ABSENT,
        ["running: " + abbreviate(sorted(running))],
    )
    return enabled, running


def _detect_backends(
    state: ObservedState,
    execute: Execute,
    enabled: set[str],
    running: set[str],
    section: str,
    candidates: tuple[dict[str, object], ...],
) -> dict[str, int]:
    """Score each candidate backend and emit an observation per candidate."""
    scores: dict[str, int] = {}
    for candidate in candidates:
        token = str(candidate["token"])
        packages = tuple(str(p) for p in candidate.get("packages", ()))  # type: ignore[arg-type]
        units = tuple(str(u) for u in candidate.get("units", ()))  # type: ignore[arg-type]
        commands = tuple(str(c) for c in candidate.get("commands", ()))  # type: ignore[arg-type]

        evidence: list[str] = []
        signals = 0
        installed_packages = sorted(name for name in packages if name in state.packages)
        if installed_packages:
            evidence.append("packages: " + abbreviate(installed_packages))
            signals += 1

        # Only fall back to per-unit queries when the list commands produced no data.
        enabled_units = [unit for unit in units if unit in enabled or (not enabled and _unit_query(execute, unit, "enabled"))]
        active_units = [unit for unit in units if unit in running or (not running and _unit_query(execute, unit, "active"))]
        if enabled_units:
            evidence.append("enabled units: " + abbreviate(enabled_units))
            signals += 1
        if active_units:
            evidence.append("active units: " + abbreviate(active_units))
            signals += 1

        responding = []
        for command in commands:
            rc, stdout, _ = run(execute, command)
            if command_ok(rc):
                responding.append(f"{command}: {first_line(stdout) or 'responds'}")
        if responding:
            evidence.append("CLI: " + abbreviate(responding))
            signals += 1

        if active_units:
            status = Status.RUNNING
        elif enabled_units:
            status = Status.ENABLED
        elif signals:
            status = Status.INSTALLED
        else:
            status = Status.ABSENT
        confidence = Confidence.HIGH if signals >= 2 else (Confidence.MEDIUM if signals == 1 else Confidence.LOW)
        observe(state, f"{section}.{token}", token, confidence, status, evidence or [f"no {token} evidence"])
        scores[token] = signals

    if scores:
        best = max(scores, key=lambda token: (scores[token], token != "unknown"))
        best_observation = state.observations.get(f"{section}.{best}")
        primary_status = best_observation.status if best_observation else Status.ABSENT
        primary_confidence = best_observation.confidence if best_observation else Confidence.LOW
        primary_evidence = list(best_observation.evidence) if best_observation else []
    else:
        best, primary_status, primary_confidence = "unknown", Status.ABSENT, Confidence.LOW
        primary_evidence = ["no backend evidence"]
    primary_component = {
        "network": "network.backend",
        "audio": "audio.backend",
        "display": "desktop.display-manager",
    }.get(section, f"{section}.backend")
    observe(state, primary_component, best, primary_confidence, primary_status, primary_evidence)
    return scores


def _collect_network(state: ObservedState, execute: Execute, enabled: set[str], running: set[str]) -> None:
    """Detect NetworkManager and known alternatives."""
    _detect_backends(
        state,
        execute,
        enabled,
        running,
        "network",
        (
            {
                "token": "networkmanager",
                "packages": ("networkmanager",),
                "units": ("NetworkManager.service",),
                "commands": ("nmcli --version",),
            },
            {
                "token": "systemd-networkd",
                "packages": (),  # the systemd package is not evidence of networkd
                "units": ("systemd-networkd.service",),
                "commands": ("networkctl --version",),
            },
            {
                "token": "netctl",
                "packages": ("netctl",),
                "units": ("netctl.service",),
                "commands": (),
            },
            {
                "token": "connman",
                "packages": ("connman",),
                "units": ("connman.service",),
                "commands": ("connmanctl --version",),
            },
        ),
    )


def _collect_audio(state: ObservedState, execute: Execute, enabled: set[str], running: set[str]) -> None:
    """Detect PipeWire and PulseAudio; note that pipewire-pulse mimics Pulse."""
    scores = _detect_backends(
        state,
        execute,
        enabled,
        running,
        "audio",
        (
            {
                "token": "pipewire",
                "packages": ("pipewire", "pipewire-pulse"),
                "units": ("pipewire.service", "pipewire-pulse.service"),
                "commands": ("pw-cli info 0",),
            },
            {
                "token": "pulseaudio",
                "packages": ("pulseaudio",),
                "units": ("pulseaudio.service",),
                "commands": ("pactl info",),
            },
        ),
    )
    pulse_observation = state.observations.get("audio.pulseaudio")
    if (
        scores.get("pipewire")
        and pulse_observation is not None
        and pulse_observation.status is not Status.ABSENT
        and any("pipewire" in str(item).lower() for item in pulse_observation.evidence)
    ):
        # `pactl info` succeeds through pipewire-pulse; that is not evidence of
        # a second audio daemon and must not create a false target decision.
        pulse_observation.status = Status.ABSENT
        pulse_observation.confidence = Confidence.LOW
        pulse_observation.evidence.append(
            "pactl speaks to PipeWire compatibility layer; legacy PulseAudio daemon absent"
        )

    if scores.get("pipewire") and scores.get("pulseaudio"):
        observe(
            state,
            "audio.coexistence",
            "pipewire-pulse-compatibility",
            Confidence.MEDIUM,
            Status.CONFIGURED,
            [
                "both PipeWire and PulseAudio evidence present",
                "pipewire-pulse may provide the PulseAudio API without the legacy daemon",
            ],
        )


def _collect_desktop_sessions(state: ObservedState, root: str, env: dict[str, str]) -> None:
    """Read X11 and Wayland session desktop files."""
    sessions: list[str] = []
    evidence: list[str] = []
    dirs_seen = 0
    for directory, kind in (("/usr/share/xsessions", "x11"), ("/usr/share/wayland-sessions", "wayland")):
        if is_dir(root, directory):
            dirs_seen += 1
        for filename in find_files(root, directory, suffixes=(".desktop",), max_files=40):
            fields = parse_key_values(read_file(root, f"{directory}/{filename}"))
            name = fields.get("Name") or (filename[:-8] if filename.endswith(".desktop") else filename)
            sessions.append(f"{name} [{kind}]")
    if sessions:
        evidence.append("sessions: " + abbreviate(sorted(sessions)))
    else:
        evidence.append("no .desktop session files found")
    evidence.append(f"session directories present: {dirs_seen}/2")

    signals = int(bool(sessions)) + int(dirs_seen >= 1) + int(bool(env.get("XDG_SESSION_TYPE")))
    confidence = Confidence.HIGH if signals >= 2 else (Confidence.MEDIUM if signals == 1 else Confidence.LOW)
    status = Status.CONFIGURED if env.get("XDG_SESSION_TYPE") else (Status.INSTALLED if sessions else Status.ABSENT)
    observe(state, "desktop.sessions", "desktop-session-discovery", confidence, status, evidence)


def _collect_display_manager(state: ObservedState, root: str, execute: Execute, enabled: set[str], running: set[str]) -> None:
    """Detect the display manager from packages, symlink and unit state."""
    link_target = read_symlink(root, "/etc/systemd/system/display-manager.service") or ""
    link_name = os.path.basename(link_target).lower() if link_target else ""
    candidates: tuple[dict[str, object], ...] = (
        {"token": "sddm", "packages": ("sddm",), "units": ("sddm.service",), "commands": ()},
        {"token": "gdm", "packages": ("gdm", "gdm-beta"), "units": ("gdm.service",), "commands": ()},
        {"token": "lightdm", "packages": ("lightdm",), "units": ("lightdm.service",), "commands": ()},
        {"token": "lxdm", "packages": ("lxdm",), "units": ("lxdm.service",), "commands": ()},
        {"token": "sdm", "packages": ("sdm",), "units": ("sdm.service",), "commands": ()},
    )
    scores = _detect_backends(state, execute, enabled, running, "display", candidates)
    for token, score in scores.items():
        if not link_name:
            continue
        component = f"display.{token}"
        observation = state.observations.get(component)
        if observation is None or token not in link_name:
            continue
        observation.evidence.append(f"display-manager.service -> {link_target}")
        observation.confidence = Confidence.HIGH
        if observation.status in (Status.INSTALLED, Status.CONFIGURED):
            observation.status = Status.ENABLED
        scores[token] = score + 1
    best = max(scores, key=lambda token: scores[token]) if scores else "unknown"
    best_observation = state.observations.get(f"display.{best}")
    observe(
        state,
        "desktop.display-manager",
        best,
        best_observation.confidence if best_observation else Confidence.LOW,
        best_observation.status if best_observation else Status.ABSENT,
        list(best_observation.evidence) if best_observation else ["no display manager evidence"],
    )


def _session_environment(root: str, execute: Execute) -> tuple[dict[str, str], str, Confidence]:
    """Return session variables, their source and source confidence."""
    environ_text = read_file(root, "/proc/self/environ")
    if environ_text is not None:
        values = dict(
            item.split("=", 1)
            for item in environ_text.split("\0")
            if "=" in item
        )
        return values, "root /proc/self/environ", Confidence.HIGH

    rc, stdout, _ = run(execute, "env")
    if command_ok(rc):
        values = dict(
            (fields[0], "=".join(fields[1:]))
            for fields in (line.split("=", 1) for line in lines(stdout))
            if len(fields) == 2
        )
        return values, "env command", Confidence.MEDIUM

    if root in ("/", ""):
        return dict(os.environ), "host environment", Confidence.LOW
    return {}, "no environment source available for fake root", Confidence.LOW


def discover_services_desktop(state: ObservedState, root: str = "/", execute: Execute | None = None) -> ObservedState:
    """Populate *state* with service, backend and desktop observations.

    Args:
        state: An :class:`~core.ObservedState` to enrich.  ``state.packages``
            corroborates backend packages.
        root: Filesystem prefix for session directories, session environment
            and the display-manager symlink.
        execute: Injected command executor returning ``(rc, stdout, stderr)``.

    Returns:
        The same *state*.  ``network.*``, ``audio.*`` and ``desktop.*``
        observations record installed/enabled/running distinctions separately
        so a planner cannot treat an installed package as a running service.
    """
    ex = as_execute(execute)
    enabled, running = _collect_systemd(state, ex)
    _collect_network(state, ex, enabled, running)
    _collect_audio(state, ex, enabled, running)
    env, env_source, env_confidence = _session_environment(root, ex)
    _collect_desktop_sessions(state, root, env)
    _collect_display_manager(state, root, ex, enabled, running)

    observed_env = {key: env[key] for key in _SESSION_ENV_KEYS if key in env}
    observe(
        state,
        "desktop.session-env",
        "session-environment",
        env_confidence if observed_env else Confidence.LOW,
        Status.RUNNING if observed_env else Status.ABSENT,
        [f"source: {env_source}"] + [f"{key}={value}" for key, value in sorted(observed_env.items())],
    )
    return state
