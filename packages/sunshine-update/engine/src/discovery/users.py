"""Discover local users, groups and home-directory state (read-only).

Stage B of the migration contract requires the engine to know which accounts
and privileged groups exist so target resolution can *preserve* them.  This
pass deliberately records no password hashes, no shadow data and no command
secrets: only the facts needed to avoid breaking a user's login.

Observations
------------
``users.accounts``
    Human accounts discovered from ``/etc/passwd`` (uid >= 1000 by default).
    ``FUNCTIONAL`` when at least one home directory exists, ``INSTALLED`` when
    only the account database is readable, ``ABSENT`` otherwise.

``users.groups``
    Group memberships for privilege-relevant groups (``wheel``, ``sudo``,
    ``root``, ``adm``).  Membership is derived from both the group line and the
    primary gid in ``/etc/passwd``.

``users.home-directories``
    Home directory path, mode, owner uid and group gid for each human account.
    The path is resolved under ``root`` for fixture safety; in production
    ``root="/"`` gives the real path.

No observation from this module is used to authorise a destructive operation.
Low-confidence account data is still useful for *preservation* decisions, which
are safe by definition.
"""
from __future__ import annotations

import os
from typing import Any

try:  # package import keeps a single ObservedState class identity
    from ..core import Confidence, ObservedState, Status
except ImportError:  # pragma: no cover - standalone scripts
    from core import Confidence, ObservedState, Status

from ._util import Execute, as_execute, observe, read_file, root_path

PRIVILEGED_GROUPS = ("wheel", "sudo", "root", "adm")
_MIN_HUMAN_UID = 1000
_NON_LOGIN_SHELLS = ("nologin", "false", "sync", "shutdown")


def _parse_passwd(text: str | None) -> list[dict[str, Any]]:
    users: list[dict[str, Any]] = []
    for line in (text or "").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        fields = line.split(":")
        if len(fields) < 7:
            continue
        name, _password, uid, gid, gecos, home, shell = fields[:7]
        try:
            uid_int, gid_int = int(uid), int(gid)
        except ValueError:
            continue
        users.append({
            "name": name,
            "uid": uid_int,
            "gid": gid_int,
            "gecos": gecos,
            "home": home,
            "shell": shell,
        })
    return users


def _parse_groups(text: str | None) -> dict[str, dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {}
    for line in (text or "").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        fields = line.split(":")
        if len(fields) < 4:
            continue
        name, _password, gid, members = fields[:4]
        try:
            gid_int = int(gid)
        except ValueError:
            continue
        if name in PRIVILEGED_GROUPS:
            groups[name] = {
                "gid": gid_int,
                "members": sorted({m for m in members.split(",") if m}),
            }
    return groups


def _home_info(root: str, home: str) -> dict[str, Any]:
    info: dict[str, Any] = {"path": home, "exists": False, "mode": "", "uid": -1, "gid": -1}
    if not home or not home.startswith("/"):
        return info
    full = root_path(root, home)
    try:
        stat = os.stat(full)
    except OSError:
        return info
    info.update({
        "exists": True,
        "mode": oct(stat.st_mode & 0o777),
        "uid": stat.st_uid,
        "gid": stat.st_gid,
    })
    return info


def discover_users(state: ObservedState, root: str = "/", execute: Execute | None = None) -> ObservedState:
    """Populate *state* with non-secret user, group and home-directory facts.

    ``execute`` is accepted for interface symmetry with the other passes.  The
    authoritative data is read from ``/etc/passwd`` and ``/etc/group`` below
    ``root`` so a fixture can describe users without touching the real host.
    """
    ex = as_execute(execute)  # reserved for future getent corroboration
    del ex

    passwd_text = read_file(root, "/etc/passwd")
    group_text = read_file(root, "/etc/group")
    all_users = _parse_passwd(passwd_text)
    privileged = _parse_groups(group_text)
    humans = [
        user for user in all_users
        if user["uid"] >= _MIN_HUMAN_UID
        and not any(token in user["shell"] for token in _NON_LOGIN_SHELLS)
    ]

    state.users = humans
    state.groups = {}
    for name, group in privileged.items():
        primary = [user["name"] for user in humans if user["gid"] == group["gid"]]
        state.groups[name] = sorted(set(group["members"]) | set(primary))

    homes = [_home_info(root, user["home"]) for user in humans]
    state.home_directories = homes
    existing_homes = [h for h in homes if h["exists"]]

    evidence = [
        f"passwd entries: {len(all_users)}",
        f"human accounts: {len(humans)}",
        f"home directories present: {len(existing_homes)}",
        "privileged groups: " + (", ".join(sorted(state.groups)) or "(none)"),
    ]
    if not passwd_text:
        status, confidence, detected = Status.ABSENT, Confidence.LOW, "user-database-unavailable"
    elif humans and existing_homes:
        status, confidence, detected = Status.FUNCTIONAL, Confidence.HIGH, "user-accounts"
    elif humans:
        status, confidence, detected = Status.INSTALLED, Confidence.MEDIUM, "user-accounts"
    else:
        status, confidence, detected = Status.INSTALLED, Confidence.MEDIUM, "system-accounts-only"

    observe(state, "users.accounts", detected, confidence, status, evidence)
    observe(
        state,
        "users.groups",
        "privileged-group-membership" if state.groups else "no-privileged-groups",
        Confidence.HIGH if group_text else Confidence.LOW,
        Status.CONFIGURED if state.groups else Status.ABSENT,
        [f"{name}: {','.join(members) or '(empty)'}" for name, members in sorted(state.groups.items())]
        or ["no privilege-relevant groups found"],
    )
    observe(
        state,
        "users.home-directories",
        "home-directories" if existing_homes else "no-home-directories",
        Confidence.HIGH if existing_homes else Confidence.LOW,
        Status.CONFIGURED if existing_homes else Status.ABSENT,
        [f"{h['path']}: mode={h['mode']} uid={h['uid']} gid={h['gid']}" for h in existing_homes]
        or ["no human home directories found"],
    )
    return state


__all__ = ["discover_users", "PRIVILEGED_GROUPS"]
