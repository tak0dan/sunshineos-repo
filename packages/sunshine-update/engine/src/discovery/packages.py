"""Discover installed packages, ownership and configured repositories.

The package database remains the authority (Sunshine never replaces pacman).
Three queries are combined:

``pacman -Q``
    Full ``name version`` inventory -> ``state.packages``.  A successful query
    is recorded as ``pacman.query`` with ``FUNCTIONAL`` status.

``pacman -Qqdt``
    Unrequired/orphan packages.  The engine treats this as a *foreign
    candidate* list, because such packages are not managed by the target
    state and must not be assumed to be official.

``pacman -Qqm``
    Packages absent from the sync databases (AUR or manually installed).
    These are foreign candidates too.  Ownership is only labelled ``AUR`` when
    an AUR helper is also installed; otherwise the conservative label
    ``foreign (aur-or-manual)`` is used with LOW/MEDIUM confidence.

``/etc/pacman.conf``
    Enabled repository names -> ``state.repositories``.

Classification rules (important for safe planning):

* ``official`` -- installed, not reported as foreign, and a local sync
  database exists.  Without a sync database the claim is downgraded to MEDIUM
  and explicitly marked unverified.
* ``foreign`` -- reported by either foreign query.
* ``aur`` -- reported by ``-Qqm`` *and* an AUR helper is installed.
* ``unknown`` -- reported by a foreign query but absent from ``pacman -Q``, or
  any case where the owning repository cannot be established.  Unknown
  packages are recorded with LOW confidence and are **never** claimed as
  official/AUR.  Planners must not act on them destructively.

All observations carry the command that produced them, so a human can audit
why a classification was made.
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
    observe,
    parse_names,
    parse_packages,
    parse_pacman_conf,
    read_file,
    run,
)


_AUR_HELPERS = ("yay", "paru", "trizen", "pikaur", "aurman")


def _record_query_result(state: ObservedState, component: str, command: str, rc: int, stdout: str, stderr: str) -> None:
    """Record whether a pacman query was usable and what it returned."""
    ok = command_ok(rc)
    evidence = [f"command: {command} -> rc={rc}"]
    if ok:
        evidence.append(f"result: {abbreviate([line.strip() for line in stdout.splitlines() if line.strip()])}")
    else:
        detail = stderr.strip() or stdout.strip()
        evidence.append("result: " + (detail[:200] if detail else "no data"))
    observe(
        state,
        component,
        "pacman-query",
        Confidence.HIGH if ok else Confidence.LOW,
        Status.FUNCTIONAL if ok else Status.ABSENT,
        evidence,
    )


def discover_packages(state: ObservedState, root: str = "/", execute: Execute | None = None) -> ObservedState:
    """Populate *state* with packages, foreign/AUR candidates and repositories.

    Args:
        state: An :class:`~core.ObservedState` previously enriched by
            :func:`discovery.system.discover_system` (used for corroboration).
        root: Filesystem prefix for reading ``/etc/pacman.conf`` and the sync
            database directory.
        execute: Injected command executor returning ``(rc, stdout, stderr)``.

    Returns:
        The same *state*, with ``packages``, ``foreign_packages`` and
        ``repositories`` populated plus ``pacman.*`` / ``packages.*``
        observations.  Failed queries degrade to LOW confidence instead of
        producing a misleading empty inventory.
    """
    ex = as_execute(execute)

    rc, stdout, stderr = run(ex, "pacman -Q")
    installed = parse_packages(stdout)
    state.packages.update(installed)
    _record_query_result(state, "pacman.query", "pacman -Q", rc, stdout, stderr)
    inventory_available = command_ok(rc) and bool(installed)

    rc_foreign, out_foreign, err_foreign = run(ex, "pacman -Qqdt")
    orphan_names = set(parse_names(out_foreign)) if command_ok(rc_foreign) else set()
    _record_query_result(state, "pacman.query-orphans", "pacman -Qqdt", rc_foreign, out_foreign, err_foreign)

    rc_aur, out_aur, err_aur = run(ex, "pacman -Qqm")
    foreign_names = set(parse_names(out_aur)) if command_ok(rc_aur) else set()
    _record_query_result(state, "pacman.query-foreign", "pacman -Qqm", rc_aur, out_aur, err_aur)

    all_foreign = sorted(orphan_names | foreign_names)
    state.foreign_packages = all_foreign

    # --- official packages -------------------------------------------------
    sync_db = is_dir(root, "/var/lib/pacman/sync")
    official = sorted(set(installed) - set(all_foreign))
    official_confidence = Confidence.HIGH if inventory_available and sync_db else Confidence.MEDIUM
    official_evidence = [
        "source: pacman -Q minus foreign/orphan queries",
        f"count: {len(official)}",
        "samples: " + abbreviate(official),
        "/var/lib/pacman/sync present" if sync_db else "sync databases not observed (membership unverified)",
    ]
    observe(
        state,
        "packages.official",
        "official-packages",
        official_confidence,
        Status.INSTALLED if official else Status.ABSENT,
        official_evidence,
    )

    # --- foreign / AUR packages -------------------------------------------
    foreign_evidence = [
        "source: pacman -Qqdt (unrequired/orphan candidates)",
        "source: pacman -Qqm (not present in sync databases)",
        f"count: {len(all_foreign)}",
        "samples: " + abbreviate(all_foreign),
    ]
    foreign_confidence = Confidence.MEDIUM if (command_ok(rc_foreign) or command_ok(rc_aur)) else Confidence.LOW
    observe(
        state,
        "packages.foreign",
        "foreign-packages",
        foreign_confidence,
        Status.INSTALLED if all_foreign else Status.ABSENT,
        foreign_evidence,
    )

    aur_helper_installed = any(helper in installed for helper in _AUR_HELPERS)
    aur_names = sorted(foreign_names & set(installed)) if aur_helper_installed else []
    if aur_names:
        observe(
            state,
            "packages.aur",
            "aur-packages",
            Confidence.MEDIUM,
            Status.INSTALLED,
            [
                "source: pacman -Qqm (absent from sync databases)",
                "AUR helper installed: " + abbreviate([h for h in _AUR_HELPERS if h in installed]),
                "samples: " + abbreviate(aur_names),
            ],
        )
    else:
        observe(
            state,
            "packages.aur",
            "aur-ownership-uncertain",
            Confidence.LOW,
            Status.ABSENT,
            [
                "no AUR helper corroboration; -Qqm packages may be AUR or manually installed",
                "ownership is deliberately left unknown",
            ],
        )

    # --- unknown ownership (never claimed) --------------------------------
    unknown = sorted(name for name in all_foreign if name not in installed)
    if not inventory_available:
        unknown = sorted(set(unknown) | set(installed))
    if unknown:
        observe(
            state,
            "packages.unknown",
            "unknown-package-ownership",
            Confidence.LOW,
            Status.CONFIGURED,
            [
                "reported by a pacman query but ownership could not be verified: " + abbreviate(unknown),
                "no ownership claim is made; destructive operations are not authorised",
            ],
        )
    else:
        observe(
            state,
            "packages.unknown",
            "unknown-package-ownership",
            Confidence.HIGH,
            Status.ABSENT,
            ["every reported package was cross-checked against pacman -Q"],
        )

    # --- repositories ------------------------------------------------------
    conf_text = read_file(root, "/etc/pacman.conf")
    repos = parse_pacman_conf(conf_text)
    state.repositories = repos
    if conf_text is not None and repos:
        repo_confidence, repo_status = Confidence.HIGH, Status.CONFIGURED
    elif conf_text is not None:
        repo_confidence, repo_status = Confidence.MEDIUM, Status.CONFIGURED
    else:
        repo_confidence, repo_status = Confidence.LOW, Status.ABSENT
    observe(
        state,
        "pacman.repositories",
        "repository-configuration",
        repo_confidence,
        repo_status,
        [
            "source: /etc/pacman.conf" if conf_text is not None else "/etc/pacman.conf not readable",
            "repositories: " + abbreviate(repos),
        ],
    )

    return state
