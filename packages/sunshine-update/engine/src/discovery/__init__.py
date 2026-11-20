"""Capability and system discovery for the Sunshine Evolution Engine.

The public entry point is :func:`discover`: it inspects a machine (or a
simulated root) and returns a single :class:`~core.ObservedState` containing
typed observations, package inventory, capabilities and confidence levels.

Design contract
---------------

* Nothing is assumed.  A pristine Arch system and a half-migrated old
  Sunshine system go through the same passes.
* Every filesystem read is rooted at ``root``; every command goes through
  ``execute(command) -> (returncode, stdout, stderr)``.  Supplying a fake root
  *and* a fake executor lets tests simulate any system with the stdlib only.
* ``execute=None`` uses :func:`discovery._util.subprocess_execute`, i.e. real
  ``subprocess.run`` calls, with no shell.
* Discovery is read-only.  Observations distinguish ``INSTALLED``,
  ``CONFIGURED``, ``ENABLED``, ``RUNNING`` and ``FUNCTIONAL``; LOW-confidence
  findings cannot authorise destructive operations.

Typical use::

    from discovery import discover
    state = discover()                       # inspect the live machine
    fake = discover(root="/tmp/fixture", execute=fake_execute)
"""
from __future__ import annotations

try:  # package import keeps a single ObservedState class identity
    from ..core import ObservedState
except ImportError:  # pragma: no cover - supports standalone scripts in src/
    from core import ObservedState

from ._util import Execute, as_execute
from .capabilities import derive_capabilities
from .kernel_boot import discover_kernel_boot
from .packages import discover_packages
from .services_desktop import discover_services_desktop
from .storage import discover_storage
from .sunshine import discover_sunshine
from .system import discover_system
from .users import discover_users


def discover(root: str = "/", execute: Execute | None = None) -> ObservedState:
    """Run every discovery pass and return the combined observed state.

    Args:
        root: Filesystem prefix for all reads.  ``"/"`` (the default) inspects
            the live system; a temporary directory can be supplied to inspect
            a fixture.
        execute: Optional callable ``execute(command) -> (rc, stdout, stderr)``.
            It receives shell-like command strings such as ``"pacman -Q"``.
            With ``None``, commands are executed for real via
            :func:`subprocess.run`.

    Returns:
        A new :class:`~core.ObservedState`.  Passes run in dependency order:
        base system -> packages -> kernel/boot -> storage -> services/desktop
        -> users -> Sunshine -> capability derivation.  A failure in one pass is
        recorded as a LOW-confidence observation rather than raised, so a
        partially observable machine still yields a usable state.
    """
    state = ObservedState()
    ex = as_execute(execute)

    discover_system(state, root, ex)
    discover_packages(state, root, ex)
    discover_kernel_boot(state, root, ex)
    discover_storage(state, root, ex)
    discover_services_desktop(state, root, ex)
    discover_users(state, root, ex)
    discover_sunshine(state, root, ex)
    derive_capabilities(state, root, ex)
    return state


__all__ = [
    "discover",
    "discover_system",
    "discover_packages",
    "discover_kernel_boot",
    "discover_storage",
    "discover_services_desktop",
    "discover_users",
    "discover_sunshine",
    "derive_capabilities",
    "ObservedState",
    "Execute",
]
