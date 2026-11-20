"""Discover storage topology: devices, mounts, filesystems, encryption and LVM.

All findings are observations; this module never mounts, unlocks or modifies
anything.  The distinction between states matters:

* ``INSTALLED`` -- a filesystem/driver package or tool exists.
* ``CONFIGURED`` -- a persistent declaration exists (``/etc/fstab``,
  ``/etc/crypttab``, a btrfs subvolume layout, LVM metadata).
* ``RUNNING`` -- the live command output (``lsblk``/``findmnt``) shows it in
  use.
* ``FUNCTIONAL`` -- not claimed here; validation must prove a capability works.

Commands used: ``lsblk -J`` (JSON device tree), ``findmnt`` (live mounts),
``btrfs subvolume list /``, ``lvs``/``pvs``/``vgs``.  Each command may fail in a
fake root; failure degrades confidence rather than aborting discovery.  The
same ``findmnt`` command string is used by :mod:`discovery.kernel_boot` so a
single fake response can serve both.
"""
from __future__ import annotations

import json
from typing import Any

try:  # package import keeps a single ObservedState class identity
    from ..core import Confidence, ObservedState, Status
except ImportError:  # pragma: no cover - supports standalone scripts in src/
    from core import Confidence, ObservedState, Status

from ._util import (
    Execute,
    abbreviate,
    as_execute,
    command_ok,
    lines,
    observe,
    parse_fstab,
    path_exists,
    read_file,
    run,
)


_LSBLK_COMMAND = "lsblk -J -o NAME,TYPE,FSTYPE,MOUNTPOINT,LABEL,UUID,PKNAME"
_FINDMNT_COMMAND = "findmnt -rn -o TARGET,SOURCE,FSTYPE"


def _flatten_devices(node: Any) -> list[dict[str, Any]]:
    """Flatten the nested ``lsblk -J`` block-device tree into records."""
    result: list[dict[str, Any]] = []
    if isinstance(node, dict):
        if "name" in node:
            result.append(node)
        for child in node.get("children", []) or []:
            result.extend(_flatten_devices(child))
    elif isinstance(node, list):
        for item in node:
            result.extend(_flatten_devices(item))
    return result


def _collect_devices(state: ObservedState, execute: Execute) -> list[dict[str, Any]]:
    """Record device topology and return flattened device records."""
    rc, stdout, stderr = run(execute, _LSBLK_COMMAND)
    devices: list[dict[str, Any]] = []
    evidence: list[str] = []
    if command_ok(rc):
        try:
            payload = json.loads(stdout)
            devices = _flatten_devices(payload.get("blockdevices", payload))
        except (ValueError, TypeError, AttributeError):
            evidence.append("lsblk output was not parseable JSON")
    else:
        evidence.append("lsblk unavailable: " + (stderr.strip()[:200] or f"rc={rc}"))

    if devices:
        evidence.append(
            "devices: "
            + abbreviate(
                [
                    "{name}({type},{fstype},{mount})".format(
                        name=str(dev.get("name", "?")),
                        type=str(dev.get("type", "?")),
                        fstype=str(dev.get("fstype") or "no-fs"),
                        mount=str(dev.get("mountpoint") or "unmounted"),
                    )
                    for dev in devices
                ]
            )
        )
    elif not evidence:
        evidence.append("lsblk reported no block devices")

    observe(
        state,
        "storage.block-devices",
        "block-device-topology",
        Confidence.HIGH if devices else Confidence.LOW,
        Status.RUNNING if devices else Status.ABSENT,
        evidence,
    )
    return devices


def _collect_mounts(state: ObservedState, execute: Execute) -> list[str]:
    """Record live mounts and return their filesystem types."""
    rc, stdout, stderr = run(execute, _FINDMNT_COMMAND)
    mount_lines = lines(stdout) if command_ok(rc) else []
    fstypes = [fields[2] for fields in (line.split() for line in mount_lines) if len(fields) >= 3]
    evidence = mount_lines[:10] or ["findmnt unavailable: " + (stderr.strip()[:200] or f"rc={rc}")]
    observe(
        state,
        "storage.mounts",
        "mount-topology",
        Confidence.HIGH if mount_lines else Confidence.LOW,
        Status.RUNNING if mount_lines else Status.ABSENT,
        evidence,
    )
    return fstypes


def _collect_filesystems(state: ObservedState, devices: list[dict[str, Any]], mount_fstypes: list[str]) -> list[str]:
    """Summarise filesystem types seen from both lsblk and findmnt."""
    device_fstypes = [str(dev.get("fstype")) for dev in devices if dev.get("fstype")]
    fstypes = sorted({fs.lower() for fs in device_fstypes + mount_fstypes if fs})
    observe(
        state,
        "storage.filesystems",
        "filesystem-inventory",
        Confidence.HIGH if fstypes else Confidence.LOW,
        Status.CONFIGURED if fstypes else Status.ABSENT,
        ["filesystems: " + abbreviate(fstypes), "sources: lsblk FSTYPE, findmnt FSTYPE"],
    )
    return fstypes


def _collect_fstab(state: ObservedState, root: str) -> list[dict[str, str]]:
    """Record persistent mount declarations from ``/etc/fstab``."""
    text = read_file(root, "/etc/fstab")
    records = parse_fstab(text)
    evidence = [
        f"{record['source']} -> {record['target']} [{record['fstype']}] {record['options']}".strip()
        for record in records
    ] or ["no /etc/fstab entries found"]
    observe(
        state,
        "storage.fstab",
        "fstab",
        Confidence.MEDIUM if records else Confidence.LOW,
        Status.CONFIGURED if records else Status.ABSENT,
        evidence[:12],
    )
    return records


def _collect_btrfs(state: ObservedState, root: str, execute: Execute, fstab: list[dict[str, str]], fstypes: list[str]) -> None:
    """Detect btrfs subvolumes from ``btrfs``, fstab options and lsblk/findmnt."""
    rc, stdout, _ = run(execute, "btrfs subvolume list /")
    subvol_lines = lines(stdout) if command_ok(rc) else []
    fstab_subvols = [
        f"{record['target']} ({record['fstype']}, {record['options']})"
        for record in fstab
        if "subvol" in record["options"] or record["fstype"] == "btrfs"
    ]
    evidence: list[str] = []
    if subvol_lines:
        evidence.append("btrfs subvolume list: " + abbreviate(subvol_lines))
    if fstab_subvols:
        evidence.append("f btrfs entries: " + abbreviate(fstab_subvols))
    if "btrfs" in fstypes:
        evidence.append("btrfs seen in live filesystem inventory")
    signals = sum(bool(group) for group in (subvol_lines, fstab_subvols, "btrfs" in fstypes))
    confidence = Confidence.HIGH if signals >= 2 else (Confidence.MEDIUM if signals == 1 else Confidence.LOW)
    status = Status.RUNNING if subvol_lines else (Status.CONFIGURED if signals else Status.ABSENT)
    observe(state, "storage.btrfs", "btrfs", confidence, status, evidence or ["no btrfs evidence"])


def _collect_luks(state: ObservedState, root: str, devices: list[dict[str, Any]]) -> None:
    """Detect LUKS from live device types and ``/etc/crypttab``."""
    crypttab = read_file(root, "/etc/crypttab")
    crypttab_records = [
        line.strip()
        for line in (crypttab or "").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    luks_devices = [
        str(dev.get("name", "?"))
        for dev in devices
        if str(dev.get("fstype", "")).lower() in ("crypto_luks", "luks") or dev.get("type") == "crypt"
    ]
    evidence: list[str] = []
    if luks_devices:
        evidence.append("lsblk crypto devices/mappers: " + abbreviate(luks_devices))
    if crypttab_records:
        evidence.append("crypttab: " + abbreviate(crypttab_records))
    signals = sum(bool(group) for group in (luks_devices, crypttab_records))
    confidence = Confidence.HIGH if signals == 2 else (Confidence.MEDIUM if signals == 1 else Confidence.LOW)
    status = Status.RUNNING if luks_devices else (Status.CONFIGURED if signals else Status.ABSENT)
    observe(state, "storage.luks", "luks", confidence, status, evidence or ["no LUKS evidence"])


def _collect_lvm(state: ObservedState, execute: Execute, devices: list[dict[str, Any]]) -> None:
    """Detect LVM from ``lvs``/``pvs`` output and lsblk types."""
    evidence: list[str] = []
    for command, label in (
        ("lvs --noheadings -o lv_name", "lvs"),
        ("pvs --noheadings -o pv_name", "pvs"),
    ):
        rc, stdout, _ = run(execute, command)
        values = lines(stdout) if command_ok(rc) else []
        if values:
            evidence.append(f"{label}: " + abbreviate(values))
    lvm_devices = [str(dev.get("name", "?")) for dev in devices if dev.get("type") == "lvm"]
    if lvm_devices:
        evidence.append("lsblk lvm devices: " + abbreviate(lvm_devices))
    signals = sum(bool(group) for group in (evidence, lvm_devices))
    confidence = Confidence.HIGH if signals >= 2 else (Confidence.MEDIUM if signals == 1 else Confidence.LOW)
    status = Status.RUNNING if lvm_devices or evidence else Status.ABSENT
    observe(state, "storage.lvm", "lvm", confidence, status, evidence or ["no LVM evidence"])


def _collect_snapshots(state: ObservedState, root: str, packages: dict[str, str]) -> None:
    """Look for snapshot/checkpoint infrastructure used for recovery points."""
    evidence: list[str] = []
    snapshot_paths = (
        "/.snapshots",
        "/btrfs/snapshots",
        "/var/lib/snapper",
        "/etc/snapper",
        "/var/lib/timeshift",
        "/.sunshine/checkpoints",
        "/var/lib/sunshine/checkpoints",
    )
    present = [path for path in snapshot_paths if path_exists(root, path)]
    if present:
        evidence.append("snapshot paths: " + abbreviate(present))
    tools = sorted(name for name in ("snapper", "timeshift", "btrfs-assistant") if name in packages)
    if tools:
        evidence.append("snapshot tools installed: " + abbreviate(tools))
    signals = sum(bool(group) for group in (present, tools))
    confidence = Confidence.HIGH if signals >= 2 else (Confidence.MEDIUM if signals == 1 else Confidence.LOW)
    status = Status.CONFIGURED if signals else Status.ABSENT
    observe(
        state,
        "storage.snapshots",
        "snapshot-infrastructure",
        confidence,
        status,
        evidence or ["no snapshot tooling or directories found"],
    )


def discover_storage(state: ObservedState, root: str = "/", execute: Execute | None = None) -> ObservedState:
    """Populate *state* with storage observations and return it.

    Args:
        state: An :class:`~core.ObservedState` to enrich.  ``state.packages``
            is used only to corroborate snapshot tooling.
        root: Filesystem prefix for ``/etc/fstab`` and ``/etc/crypttab``.
        execute: Injected command executor returning ``(rc, stdout, stderr)``.

    Returns:
        The same *state*.  Every command result, including failures, is
        represented as evidence so later layers can tell "not present" from
        "not observable".
    """
    ex = as_execute(execute)
    devices = _collect_devices(state, ex)
    mount_fstypes = _collect_mounts(state, ex)
    fstypes = _collect_filesystems(state, devices, mount_fstypes)
    fstab = _collect_fstab(state, root)
    _collect_btrfs(state, root, ex, fstab, fstypes)
    _collect_luks(state, root, devices)
    _collect_lvm(state, ex, devices)
    _collect_snapshots(state, root, state.packages)
    return state
