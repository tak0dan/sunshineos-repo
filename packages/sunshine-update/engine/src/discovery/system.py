"""Discover the base operating system: distribution, architecture, init and package manager.

This is the first discovery pass.  It asks only "what is actually here?" and
never assumes Arch or Sunshine.  Every finding is recorded as an
:class:`~core.Observation`:

``system.distribution``
    Parsed ``/etc/os-release`` (``ID``, ``NAME``, ``PRETTY_NAME``), optionally
    corroborated by distribution-specific marker files.  ``state.distribution``
    is normalised to the lower-case ID (for example ``"arch"``), never to a
    guessed marketing name.

``system.architecture``
    ``uname -m`` normalised to the names used by package repositories
    (``x86_64``, ``aarch64``, ...).  The raw output stays in evidence.

``system.init``
    PID 1 (``/proc/1/comm``), ``/run/systemd/system``, the systemd binary and
    ``systemctl --version`` are independent signals.  ``RUNNING`` means PID 1
    is the init; ``INSTALLED`` means only its files/tools were found.

``system.package-manager``
    ``pacman --version``, ``/etc/pacman.conf`` and the local package database
    are independent signals.  ``FUNCTIONAL``/``RUNNING`` means the CLI answers;
    ``INSTALLED`` means only its config/database exists.

Confidence policy: two or more independent signals give ``HIGH``; one strong
signal gives ``MEDIUM``; an indirect guess (or no signal at all) gives ``LOW``.
LOW observations never authorise destructive operations.
"""
from __future__ import annotations

try:  # package import keeps a single ObservedState class identity
    from ..core import Confidence, ObservedState, Status
except ImportError:  # pragma: no cover - supports standalone scripts in src/
    from core import Confidence, ObservedState, Status

from ._util import (
    Execute,
    abbreviate,
    as_execute,
    command_ok,
    is_dir,
    lines,
    observe,
    parse_key_values,
    path_exists,
    read_file,
    run,
)


_ARCHITECTURE_ALIASES = {
    "amd64": "x86_64",
    "x86-64": "x86_64",
    "arm64": "aarch64",
    "armv8l": "aarch64",
    "i386": "i686",
    "i486": "i686",
    "i586": "i686",
}


def _detect_distribution(state: ObservedState, root: str, execute: Execute) -> None:
    """Read os-release and distribution markers; set ``state.distribution``."""
    evidence: list[str] = []
    fields = parse_key_values(read_file(root, "/etc/os-release"))
    if fields:
        evidence.append(
            "os-release: "
            + abbreviate(
                [f"{key}={fields[key]}" for key in ("ID", "NAME", "PRETTY_NAME", "ID_LIKE") if key in fields],
                limit=6,
            )
        )

    markers: list[str] = []
    for marker in ("/etc/arch-release", "/etc/debian_version", "/etc/fedora-release", "/etc/alpine-release"):
        if path_exists(root, marker):
            markers.append(marker)
    if markers:
        evidence.append("release markers: " + abbreviate(markers))

    distribution = fields.get("ID", "").strip().lower()
    if not distribution:
        if "/etc/arch-release" in markers:
            distribution = "arch"
        elif "/etc/debian_version" in markers:
            distribution = "debian"
        elif "/etc/fedora-release" in markers:
            distribution = "fedora"
        elif "/etc/alpine-release" in markers:
            distribution = "alpine"

    if distribution:
        state.distribution = distribution
        # An os-release ID is authoritative; a marker alone is a weaker signal.
        confidence = Confidence.HIGH if fields.get("ID") else Confidence.MEDIUM
        status = Status.CONFIGURED
    else:
        state.distribution = "unknown"
        confidence = Confidence.LOW
        status = Status.ABSENT
        evidence.append("no /etc/os-release or known release marker found")

    observe(state, "system.distribution", state.distribution, confidence, status, evidence)

    if fields:
        observe(
            state,
            "system.os-release",
            "os-release-parsed",
            Confidence.HIGH,
            Status.CONFIGURED,
            [f"{key}={value}" for key, value in sorted(fields.items())],
        )


def _detect_architecture(state: ObservedState, root: str, execute: Execute) -> None:
    """Normalise ``uname -m`` into a repository-style architecture name."""
    del root  # architecture comes from the executable, not from the fake root
    rc, stdout, stderr = run(execute, "uname -m")
    _out = lines(stdout)
    raw = _out[0].strip() if command_ok(rc) and _out else ""
    evidence = [f"uname -m: {raw or '(no output)'}"]
    if stderr.strip() and not raw:
        evidence.append("stderr: " + stderr.strip()[:200])

    arch = _ARCHITECTURE_ALIASES.get(raw.lower(), raw.lower()) if raw else ""
    if arch:
        state.architecture = arch
        confidence = Confidence.MEDIUM
        status = Status.RUNNING
    else:
        state.architecture = "unknown"
        confidence = Confidence.LOW
        status = Status.ABSENT

    observe(state, "system.architecture", state.architecture, confidence, status, evidence)


def _detect_init_system(state: ObservedState, root: str, execute: Execute) -> None:
    """Determine the running init system from multiple independent signals."""
    evidence: list[str] = []
    signals: dict[str, int] = {}

    rc, stdout, _ = run(execute, "cat /proc/1/comm")
    _pid1_lines = lines(stdout)
    pid1 = _pid1_lines[0].lower() if command_ok(rc) and _pid1_lines else ""
    if pid1:
        evidence.append(f"PID 1: {pid1}")
        signals[pid1] = signals.get(pid1, 0) + 2  # direct runtime evidence

    rc, stdout, _ = run(execute, "systemctl --version")
    if command_ok(rc):
        evidence.append("systemctl: " + (lines(stdout)[0] if lines(stdout) else "available"))
        signals["systemd"] = signals.get("systemd", 0) + 1

    if is_dir(root, "/run/systemd/system"):
        evidence.append("/run/systemd/system exists")
        signals["systemd"] = signals.get("systemd", 0) + 2

    if path_exists(root, "/usr/lib/systemd/systemd"):
        evidence.append("/usr/lib/systemd/systemd exists")
        signals["systemd"] = signals.get("systemd", 0) + 1

    # Alternatives are checked only to avoid falsely claiming systemd.
    for name, markers, command in (
        ("openrc", ("/etc/init.d", "/sbin/openrc"), "openrc --version"),
        ("runit", ("/etc/runit",), "runsvdir -V"),
        ("sysvinit", ("/etc/inittab",), "init --version"),
    ):
        if any(path_exists(root, marker) for marker in markers):
            evidence.append(f"{name} marker present")
            signals[name] = signals.get(name, 0) + 1
        rc, stdout, _ = run(execute, command)
        if command_ok(rc) and name in pid1:
            evidence.append(f"{name} CLI responds")
            signals[name] = signals.get(name, 0) + 1

    if not signals:
        state.init_system = "unknown"
        observe(
            state,
            "system.init",
            state.init_system,
            Confidence.LOW,
            Status.ABSENT,
            evidence + ["no init system signal found"],
        )
        return

    winner = max(signals, key=lambda name: signals[name])
    state.init_system = winner
    strength = signals[winner]
    confidence = Confidence.HIGH if strength >= 2 else Confidence.MEDIUM
    # PID 1 matching proves it is running; files alone prove installation only.
    status = Status.RUNNING if pid1 == winner else Status.INSTALLED
    if winner == "systemd" and is_dir(root, "/run/systemd/system"):
        status = Status.RUNNING
    observe(state, "system.init", winner, confidence, status, evidence)


def _detect_package_manager(state: ObservedState, root: str, execute: Execute) -> None:
    """Detect pacman and record whether it is merely installed or usable."""
    evidence: list[str] = []
    signals = 0

    rc, stdout, _ = run(execute, "pacman --version")
    if command_ok(rc):
        signals += 2
        evidence.append("pacman CLI: " + (lines(stdout)[0] if lines(stdout) else "responds"))

    if path_exists(root, "/etc/pacman.conf"):
        signals += 1
        evidence.append("/etc/pacman.conf exists")

    if is_dir(root, "/var/lib/pacman/local"):
        signals += 1
        evidence.append("/var/lib/pacman/local exists")

    if is_dir(root, "/var/lib/pacman/sync"):
        signals += 1
        evidence.append("/var/lib/pacman/sync exists (repository databases)")

    if signals:
        state.package_manager = "pacman"
        confidence = Confidence.HIGH if signals >= 2 else Confidence.MEDIUM
        status = Status.RUNNING if command_ok(rc) else Status.INSTALLED
    else:
        state.package_manager = "unknown"
        confidence = Confidence.LOW
        status = Status.ABSENT
        evidence.append("no pacman CLI, configuration or database found")

    observe(state, "system.package-manager", state.package_manager, confidence, status, evidence)


def discover_system(
    state: ObservedState | str | None = None,
    root: str | Execute | None = None,
    execute: Execute | None = None,
) -> ObservedState:
    """Populate base-system observations and return the resulting state.

    Two calling conventions are accepted:

    * pipeline form (used by :func:`discovery.discover`):
      ``discover_system(state, root, execute)`` -- *state* is enriched in place;
    * standalone form: ``discover_system(root, execute)`` -- a fresh
      :class:`~core.ObservedState` is created and returned.  Keyword calls such
      as ``discover_system(root="/fake", execute=fake)`` also work.

    Args:
        state: An :class:`~core.ObservedState` to enrich, or a root prefix in
            the standalone form (``None`` means the live filesystem).
        root: Filesystem prefix in pipeline form; the executor in standalone
            form.  ``"/"`` inspects the live machine.
        execute: ``execute(command) -> (rc, stdout, stderr)``.  ``None`` selects
            :func:`discovery._util.subprocess_execute` for real calls.

    Returns:
        The enriched state, with ``distribution``, ``architecture``,
        ``init_system``, ``package_manager`` and the ``system.*`` observations
        filled in.  Unknowns are preserved as LOW-confidence ABSENT
        observations rather than guessed.
    """
    if isinstance(state, ObservedState):
        observed = state
        actual_root = root if isinstance(root, str) else "/"
        ex = execute
    else:
        observed = ObservedState()
        actual_root = state if isinstance(state, str) else "/"
        # Keyword form: discover_system(root="/fake", execute=fake).
        if actual_root == "/" and isinstance(root, str):
            actual_root = root
        ex = root if callable(root) else execute

    ex_fn = as_execute(ex)
    _detect_distribution(observed, actual_root, ex_fn)
    _detect_architecture(observed, actual_root, ex_fn)
    _detect_init_system(observed, actual_root, ex_fn)
    _detect_package_manager(observed, actual_root, ex_fn)
    return observed
