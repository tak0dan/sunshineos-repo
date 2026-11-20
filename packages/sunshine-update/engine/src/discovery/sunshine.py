"""Discover existing Sunshine OS artefacts without assuming an installation.

Sunshine is a *target state*, so this pass is intentionally conservative: it
reports what exists and explicitly flags partial installations.  A machine may
have only a config directory, only persisted state, only schemas, or only a
repository definition; each case is recorded separately.

Observation map:

``sunshine.config``
    ``/etc/sunshine`` (and legacy ``/etc/sunshineos``) presence and contents.
    CONFIGURED means files exist; ABSENT means the paths were checked and not
    found -- that is a verified absence, recorded at HIGH confidence.

``sunshine.state``
    ``/var/lib/sunshine`` persisted component state (schema versions,
    journals, ownership records).

``sunshine.component-schemas``
    JSON component/manifest schemas under the Sunshine config/share trees.
    Parsed ``id``/``schema`` values are kept in evidence.

``sunshine.tools``
    ``sunshine --version`` and friends, plus VERSION files.  A responding CLI
    is FUNCTIONAL; a VERSION file alone is INSTALLED.

``sunshine.repository``
    Sunshine repository configuration, corroborated by ``state.repositories``
    discovered from pacman.conf.

``sunshine.services``
    Sunshine systemd units, if any.

``sunshine.installation`` / ``sunshine.partial-installation``
    Overall classification: ABSENT, PARTIAL or COMPLETE-by-markers.  A partial
    installation is never treated as a working Sunshine system.

Nothing here enables, starts or repairs anything.  Low-confidence findings do
not grant capabilities that could authorise destructive operations.
"""
from __future__ import annotations

import json

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
    list_dir,
    observe,
    path_exists,
    read_file,
    run,
    version_from,
)


_CONFIG_PATHS = ("/etc/sunshine", "/etc/sunshineos")
_STATE_PATHS = ("/var/lib/sunshine", "/var/lib/sunshineos", "/var/lib/sunshine-engine")
_SHARE_PATHS = ("/usr/share/sunshine", "/usr/lib/sunshine", "/opt/sunshine")
_VERSION_FILES = (
    "/usr/share/sunshine/VERSION",
    "/etc/sunshine/VERSION",
    "/usr/lib/sunshine/VERSION",
)
_VERSION_COMMANDS = (
    "sunshine --version",
    "sunshinectl --version",
    "sunshine-evolve --version",
    "evolution-engine --version",
)
_REPOSITORY_PATHS = (
    "/etc/sunshine/repos.conf",
    "/etc/sunshine/repositories.conf",
    "/etc/sunshine/repository.json",
    "/etc/sunshine/repos.d",
    "/etc/sunshineos/repos.conf",
)
_SCHEMA_FILE_HINTS = ("schema", "manifest", "component", "target", "target-state", "journal")


def _present(root: str, paths: tuple[str, ...]) -> list[str]:
    """Return the subset of *paths* that exists below *root*."""
    return [path for path in paths if path_exists(root, path)]


def _collect_config(state: ObservedState, root: str) -> bool:
    """Record config directory presence and its top-level files."""
    present = _present(root, _CONFIG_PATHS)
    evidence: list[str] = []
    files: list[str] = []
    for path in present:
        entries = list_dir(root, path)
        files.extend(f"{path}/{name}" for name in entries)
        evidence.append(f"{path}: " + abbreviate(entries))
    if not present:
        evidence.append("checked " + abbreviate(_CONFIG_PATHS) + ": none found")
    confidence = Confidence.HIGH if files else (Confidence.MEDIUM if present else Confidence.LOW)
    status = Status.CONFIGURED if files else (Status.INSTALLED if present else Status.ABSENT)
    observe(state, "sunshine.config", "sunshine-configuration", confidence, status, evidence)
    # An empty directory is not configuration.  Counting it as a marker made a
    # clean Arch machine look like a partial Sunshine installation.
    return bool(files)


def _collect_state_dir(state: ObservedState, root: str) -> bool:
    """Record persisted Sunshine state (schema ownership, journals, etc.)."""
    present = _present(root, _STATE_PATHS)
    evidence: list[str] = []
    files: list[str] = []
    for path in present:
        entries = list_dir(root, path)
        files.extend(f"{path}/{name}" for name in entries)
        evidence.append(f"{path}: " + abbreviate(entries))
    if not present:
        evidence.append("checked " + abbreviate(_STATE_PATHS) + ": none found")
    confidence = Confidence.HIGH if files else (Confidence.MEDIUM if present else Confidence.LOW)
    status = Status.CONFIGURED if files else (Status.INSTALLED if present else Status.ABSENT)
    observe(state, "sunshine.state", "sunshine-state", confidence, status, evidence)
    _read_committed_generation(state, root)
    # An empty directory is not persisted state.  See _collect_config above.
    return bool(files)


def _read_committed_generation(state: ObservedState, root: str) -> None:
    """Read the repository generation last committed on this machine.

    The repository index is versioned independently of releases and component
    schemas.  Knowing the committed generation lets the planner reject a
    downgrade instead of silently applying an older target.
    """
    for relative in (
        "/var/lib/sunshine/state/system.toml",
        "/var/lib/sunshine/state/migration.toml",
    ):
        text = read_file(root, relative)
        if not text:
            continue
        for line in text.splitlines():
            if "=" not in line or line.lstrip().startswith("#"):
                continue
            key, _, value = line.partition("=")
            if key.strip() != "repository_generation":
                continue
            try:
                state.repository_generation = int(value.strip())
                return
            except ValueError:
                continue


def _collect_schemas(state: ObservedState, root: str) -> bool:
    """Read JSON schemas/manifests from Sunshine configuration directories."""
    candidates: list[str] = []
    for base in _CONFIG_PATHS + _SHARE_PATHS:
        if not is_dir(root, base):
            continue
        for relative in find_files(root, base, suffixes=(".json",), max_files=100):
            candidates.append(f"{base}/{relative}")

    parsed: list[str] = []
    filenames: list[str] = []
    for path in candidates:
        filename = path.rsplit("/", 1)[-1].lower()
        content = read_file(root, path)
        if content is None:
            continue
        try:
            payload = json.loads(content)
        except (ValueError, TypeError):
            filenames.append(path)
            continue
        if not isinstance(payload, dict):
            filenames.append(path)
            continue
        schema = payload.get("schema", payload.get("schema_version", payload.get("format_version")))
        identifier = payload.get("id", payload.get("name", payload.get("component")))
        is_schemaish = any(hint in filename for hint in _SCHEMA_FILE_HINTS) or schema is not None
        if is_schemaish:
            parsed.append(f"{path}: id={identifier or 'unspecified'} schema={schema or 'unspecified'}")
        else:
            filenames.append(path)

    evidence = parsed[:12] + ([f"unparsed candidates: {abbreviate(filenames)}"] if filenames else [])
    if not evidence:
        evidence.append("no JSON schema/manifest files found under Sunshine paths")
    confidence = Confidence.HIGH if len(parsed) >= 2 else (Confidence.MEDIUM if parsed else Confidence.LOW)
    status = Status.CONFIGURED if parsed else (Status.INSTALLED if filenames else Status.ABSENT)
    observe(state, "sunshine.component-schemas", "component-schema-discovery", confidence, status, evidence)
    return bool(parsed or filenames)


def _collect_tools(state: ObservedState, root: str, execute: Execute) -> bool:
    """Probe Sunshine CLI tools and VERSION files."""
    evidence: list[str] = []
    functional = False
    for command in _VERSION_COMMANDS:
        rc, stdout, stderr = run(execute, command)
        if command_ok(rc):
            version = version_from(stdout) or first_line(stdout)
            evidence.append(f"{command}: {version or 'responds'}")
            functional = True
        elif stderr.strip():
            evidence.append(f"{command}: unavailable ({stderr.strip()[:80]})")
    installed_files = []
    for path in _VERSION_FILES:
        content = read_file(root, path)
        if content is not None:
            installed_files.append(f"{path}: {first_line(content) or 'present'}")
    evidence.extend(installed_files)
    if not evidence:
        evidence.append("no Sunshine tool responded and no VERSION file found")

    confidence = Confidence.HIGH if functional else (Confidence.MEDIUM if installed_files else Confidence.LOW)
    status = Status.FUNCTIONAL if functional else (Status.INSTALLED if installed_files else Status.ABSENT)
    observe(state, "sunshine.tools", "sunshine-tools", confidence, status, evidence)
    return functional or bool(installed_files)


def _collect_repository(state: ObservedState, root: str) -> bool:
    """Detect Sunshine repository configuration and cross-check pacman repos."""
    present = _present(root, _REPOSITORY_PATHS)
    evidence = [f"repository config: {abbreviate(present)}"] if present else []
    pacman_repos = [name for name in state.repositories if "sunshine" in name.lower()]
    if pacman_repos:
        evidence.append("pacman repositories: " + abbreviate(pacman_repos))
    if not evidence:
        evidence.append("checked " + abbreviate(_REPOSITORY_PATHS) + ": none found")
    signals = int(bool(present)) + int(bool(pacman_repos))
    confidence = Confidence.HIGH if signals >= 2 else (Confidence.MEDIUM if signals == 1 else Confidence.LOW)
    status = Status.CONFIGURED if signals else Status.ABSENT
    observe(state, "sunshine.repository", "sunshine-repository-configuration", confidence, status, evidence)
    return bool(signals)


def _collect_services(state: ObservedState, execute: Execute) -> bool:
    """Detect Sunshine-specific systemd units."""
    evidence: list[str] = []
    discovered = sorted(name for name in state.packages if "sunshine" in name.lower())
    if discovered:
        evidence.append("packages: " + abbreviate(discovered))
    unit = "sunshine.service"
    rc_enabled, out_enabled, _ = run(execute, f"systemctl is-enabled {unit}")
    rc_active, out_active, _ = run(execute, f"systemctl is-active {unit}")
    enabled = command_ok(rc_enabled) and out_enabled.strip().lower() == "enabled"
    active = command_ok(rc_active) and out_active.strip().lower() == "active"
    if enabled:
        evidence.append(f"{unit} enabled")
    if active:
        evidence.append(f"{unit} active")

    signals = int(bool(discovered)) + int(enabled) + int(active)
    confidence = Confidence.HIGH if signals >= 2 else (Confidence.MEDIUM if signals == 1 else Confidence.LOW)
    if active:
        status = Status.RUNNING
    elif enabled:
        status = Status.ENABLED
    elif signals:
        status = Status.INSTALLED
    else:
        status = Status.ABSENT
        evidence.append("no Sunshine service or package found")
    observe(state, "sunshine.services", "sunshine-service", confidence, status, evidence)
    return bool(signals)


def discover_sunshine(state: ObservedState, root: str = "/", execute: Execute | None = None) -> ObservedState:
    """Populate *state* with Sunshine-specific observations and return it.

    Args:
        state: An :class:`~core.ObservedState` to enrich (package/repository
            observations from earlier passes are used for corroboration).
        root: Filesystem prefix for ``/etc/sunshine``, ``/var/lib/sunshine``
            and share directories.
        execute: Injected command executor returning ``(rc, stdout, stderr)``.

    Returns:
        The same *state*.  ``sunshine.partial-installation`` is only emitted
        when some, but not all, marker categories are present.  A completely
        clean Arch system receives an ABSENT observation at HIGH confidence,
        not an exception or an assumed Sunshine version.
    """
    ex = as_execute(execute)
    config = _collect_config(state, root)
    state_dir = _collect_state_dir(state, root)
    schemas = _collect_schemas(state, root)
    tools = _collect_tools(state, root, ex)
    repository = _collect_repository(state, root)
    services = _collect_services(state, ex)

    markers = {
        "configuration": config,
        "persisted-state": state_dir,
        "component-schemas": schemas,
        "tools": tools,
        "repository": repository,
    }
    present = sorted(name for name, found in markers.items() if found)
    missing = sorted(name for name, found in markers.items() if not found)
    marker_evidence = [
        "present markers: " + (", ".join(present) or "(none)"),
        "missing markers: " + (", ".join(missing) or "(none)"),
        "Sunshine service observed: " + str(services),
    ]

    if not present:
        token, status = "sunshine-installation", Status.ABSENT
    elif len(present) == len(markers):
        token, status = "sunshine-installation", Status.CONFIGURED
    else:
        token, status = "sunshine-partial-installation", Status.CONFIGURED
        observe(
            state,
            "sunshine.partial-installation",
            token,
            Confidence.HIGH,
            Status.CONFIGURED,
            marker_evidence,
        )

    observe(
        state,
        "sunshine.installation",
        token,
        Confidence.HIGH,
        status,
        marker_evidence,
    )
    return state
