"""Internal helpers shared by every discovery module.

This module is deliberately private: callers use :mod:`discovery` and the
``discover_*`` functions.  It centralises the two abstractions that make the
subsystem testable without touching the host machine:

* **root prefix** -- every filesystem read is resolved below ``root`` so a test
  can present an arbitrary fake tree.  With the default ``root="/"`` the real
  filesystem is inspected.
* **execute callable** -- every command goes through ``execute(command)`` which
  returns ``(returncode, stdout, stderr)``.  ``command`` is passed as a single
  shell-like string (for example ``"pacman -Q"``) so a fake can dispatch on the
  exact command it expects.  When no callable is supplied, commands are really
  executed with :func:`subprocess.run` (``shlex.split`` is used; no shell is
  involved).

The helpers here never assume that any particular distribution or Sunshine
component exists.  Missing files and failed commands are normal observations,
not errors: discovery must be able to start from a completely blank machine.
"""
from __future__ import annotations

import os
import re
import shlex
import subprocess
from typing import Any, Callable, Iterable, Sequence

try:  # normal when ``src`` is on sys.path
    from core import Confidence, Observation, ObservedState, Status
except ImportError:  # pragma: no cover - supports ``import src.discovery``
    from ..core import Confidence, Observation, ObservedState, Status


#: Signature of an injected command executor.
Execute = Callable[[str], tuple[int, str, str]]


# ---------------------------------------------------------------------------
# command execution
# ---------------------------------------------------------------------------

def subprocess_execute(command: str, timeout: int = 20) -> tuple[int, str, str]:
    """Default executor: run *command* for real via :func:`subprocess.run`.

    The command is split with :func:`shlex.split`; a shell is never used, so
    command strings cannot accidentally perform redirection or globbing.  A
    missing binary becomes ``(127, "", message)`` rather than an exception,
    which is exactly how an injected fake would report an absent tool.
    """
    argv = shlex.split(command)
    if not argv:
        return 2, "", "empty command"
    try:
        completed = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            timeout=timeout,
            check=False,
        )
        return completed.returncode, completed.stdout or "", completed.stderr or ""
    except FileNotFoundError as exc:
        return 127, "", str(exc)
    except subprocess.TimeoutExpired as exc:
        return 124, "", str(exc)
    except OSError as exc:  # pragma: no cover - unusual exec failures
        return 1, "", str(exc)


def as_execute(execute: Execute | None) -> Execute:
    """Return *execute*, or the real subprocess-backed executor.

    Tests that supply a fake root should also supply a fake executor; otherwise
    commands would still be run against the host while files were read from the
    fake tree.  This function intentionally honours the documented contract
    ("``execute=None`` means use subprocess.run").
    """
    return execute if execute is not None else subprocess_execute


def run(execute: Execute, command: str | Sequence[str]) -> tuple[int, str, str]:
    """Invoke *execute* with a normalised command string.

    Accepting a sequence as well as a string is convenient for callers; the
    injected callable always receives one string.  Any exception raised by a
    fake (for example an unhandled command in a dict-based fake) is converted
    into a non-zero return code so discovery can continue and record an ABSENT
    or LOW-confidence observation instead of aborting.
    """
    cmd = command if isinstance(command, str) else " ".join(shlex.quote(str(p)) for p in command)
    try:
        result = execute(cmd)
    except Exception as exc:  # a fake not knowing a command is a normal "absent" signal
        return 127, "", f"execute failed for {cmd!r}: {exc}"
    if not isinstance(result, (tuple, list)) or len(result) != 3:
        return 1, "", f"execute returned an invalid result for {cmd!r}: {result!r}"
    rc, stdout, stderr = result
    try:
        rc_int = int(rc)
    except (TypeError, ValueError):
        rc_int = 1
    return rc_int, str(stdout or ""), str(stderr or "")


def command_ok(rc: int) -> bool:
    """True when a command succeeded (used as a corroborating signal)."""
    return rc == 0


# ---------------------------------------------------------------------------
# root-prefixed filesystem access
# ---------------------------------------------------------------------------

def root_path(root: str | None, path: str) -> str:
    """Resolve absolute *path* underneath *root*.

    ``root_path("/fake", "/etc/os-release")`` -> ``"/fake/etc/os-release"``;
    ``root_path("/", "/etc/os-release")`` -> ``"/etc/os-release"``.
    """
    base = root if root else "/"
    if not path.startswith("/"):
        path = "/" + path
    return os.path.normpath(os.path.join(base, path.lstrip("/")))


def read_file(root: str | None, path: str) -> str | None:
    """Read a UTF-8 text file below *root*; return ``None`` when unavailable."""
    try:
        with open(root_path(root, path), "r", encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except (OSError, UnicodeError):
        return None


def path_exists(root: str | None, path: str) -> bool:
    """True if *path* exists below *root* (files, directories and symlinks)."""
    try:
        return os.path.exists(root_path(root, path))
    except OSError:  # pragma: no cover
        return False


def is_dir(root: str | None, path: str) -> bool:
    """True if *path* is a directory below *root*."""
    try:
        return os.path.isdir(root_path(root, path))
    except OSError:  # pragma: no cover
        return False


def list_dir(root: str | None, path: str) -> list[str]:
    """Return sorted names in a directory below *root*, or ``[]`` if absent."""
    try:
        return sorted(os.listdir(root_path(root, path)))
    except OSError:
        return []


def read_symlink(root: str | None, path: str) -> str | None:
    """Return the raw target of a symlink below *root*, else ``None``.

    The target is not resolved outside the root: a fake tree may contain a
    link to ``sddm.service`` and discovery should report that literal string.
    """
    try:
        full = root_path(root, path)
        return os.readlink(full) if os.path.islink(full) else None
    except OSError:
        return None


def find_files(
    root: str | None,
    path: str,
    suffixes: Iterable[str] | None = None,
    max_files: int = 200,
) -> list[str]:
    """Return relative file paths found under *path* (bounded for safety).

    Symlinked directories are not followed, so a fake root cannot accidentally
    escape into the host filesystem.  Results are deterministic and sorted.
    """
    wanted = tuple(suffixes) if suffixes else None
    found: list[str] = []
    base = root_path(root, path)
    try:
        for dirpath, _dirnames, filenames in os.walk(base, followlinks=False):
            for name in sorted(filenames):
                if wanted and not name.endswith(wanted):
                    continue
                full = os.path.join(dirpath, name)
                if not os.path.isfile(full) or os.path.islink(full):
                    continue
                found.append(os.path.relpath(full, base).replace(os.sep, "/"))
                if len(found) >= max_files:
                    return sorted(found)
    except OSError:  # pragma: no cover
        pass
    return sorted(found)


# ---------------------------------------------------------------------------
# text parsing helpers
# ---------------------------------------------------------------------------

def lines(stdout: str | None) -> list[str]:
    """Split command output into non-empty, stripped lines."""
    if not stdout:
        return []
    return [line.strip() for line in stdout.splitlines() if line.strip()]


def parse_key_values(text: str | None, separator: str = "=") -> dict[str, str]:
    """Parse shell-style ``KEY=value`` files such as ``/etc/os-release``.

    Quotes (single or double) and trailing comments are removed.  Lines that
    are not assignments and ``#`` comments are ignored.
    """
    result: dict[str, str] = {}
    for raw in lines(text):
        if raw.startswith("#") or separator not in raw:
            continue
        key, value = raw.split(separator, 1)
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        if key:
            result[key] = value
    return result


def parse_packages(text: str | None) -> dict[str, str]:
    """Parse ``pacman -Q`` output into ``{name: version}``."""
    packages: dict[str, str] = {}
    for line in lines(text):
        parts = line.split(maxsplit=1)
        if len(parts) == 2:
            packages[parts[0]] = parts[1]
    return packages


def parse_names(text: str | None) -> list[str]:
    """Parse quiet ``pacman -Qq*`` output into a sorted, unique name list."""
    return sorted({line.split()[0] for line in lines(text) if line.split()})


def parse_pacman_conf(text: str | None) -> list[str]:
    """Extract enabled repository names from ``/etc/pacman.conf``.

    ``[options]`` is not a repository.  Commented-out sections are ignored.
    Order is preserved and duplicates removed.
    """
    repos: list[str] = []
    for line in (text or "").splitlines():
        stripped = line.strip()
        if not stripped.startswith("[") or not stripped.endswith("]"):
            continue
        name = stripped[1:-1].strip()
        if name and name.lower() != "options" and name not in repos:
            repos.append(name)
    return repos


def parse_fstab(text: str | None) -> list[dict[str, str]]:
    """Parse ``/etc/fstab`` into records with source/target/fstype/options."""
    records: list[dict[str, str]] = []
    for line in (text or "").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        fields = stripped.split()
        if len(fields) < 3:
            continue
        records.append(
            {
                "source": fields[0],
                "target": fields[1],
                "fstype": fields[2],
                "options": fields[3] if len(fields) > 3 else "",
            }
        )
    return records


def first_line(stdout: str | None) -> str:
    """First non-empty line of *stdout*, or ``""``."""
    for line in lines(stdout):
        return line
    return ""


def version_from(stdout: str | None) -> str:
    """Best-effort version extraction from a ``--version`` response."""
    for line in lines(stdout)[:5]:
        match = re.search(r"v?(\d+(?:\.\d+){1,4}[^\s,]*)", line)
        if match:
            return match.group(1)
    first = first_line(stdout)
    return first[:80] if first else ""


def abbreviate(items: Iterable[str], limit: int = 8) -> str:
    """Render a list for an evidence string without flooding observations."""
    values = list(items)
    shown = ", ".join(values[:limit])
    if len(values) > limit:
        shown += f", ... (+{len(values) - limit} more)"
    return shown or "(none)"


# ---------------------------------------------------------------------------
# observation helpers
# ---------------------------------------------------------------------------

_CONFIDENCE_RANK = {
    Confidence.LOW: 0,
    Confidence.MEDIUM: 1,
    Confidence.HIGH: 2,
}


def confidence_rank(value: Confidence | str) -> int:
    """Numeric rank used for comparisons (LOW=0, MEDIUM=1, HIGH=2)."""
    if isinstance(value, str):
        try:
            value = Confidence(value)
        except ValueError:
            return 0
    return _CONFIDENCE_RANK.get(value, 0)


def at_least(confidence: Confidence | str, minimum: Confidence) -> bool:
    """True when *confidence* is at least *minimum*."""
    return confidence_rank(confidence) >= confidence_rank(minimum)


def observe(
    state: ObservedState,
    component: str,
    detected: str,
    confidence: Confidence,
    status: Status,
    evidence: Iterable[str],
) -> Observation:
    """Create an observation, attach it to *state* and return it.

    ``detected`` is intentionally a short, stable token (``"systemd"``,
    ``"pacman"``, ``"luks"``, ...).  ``core.ObservedState.observe`` promotes
    ``detected`` into ``state.capabilities`` for active statuses, so raw
    values such as kernel versions belong in ``evidence`` instead.
    """
    observation = Observation(
        component=component,
        detected=detected,
        confidence=confidence,
        status=status,
        evidence=[str(item) for item in evidence if str(item)],
    )
    state.observe(observation)
    return observation
