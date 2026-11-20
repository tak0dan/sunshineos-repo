"""Typed operation factories for the Sunshine Evolution Engine.

Every operation the planner can emit is created through one of the factories in
this module.  The factories are the single place where operation parameters are
validated and where deterministic operation ids are assigned, which keeps plans
reproducible and makes a malformed operation impossible to construct silently.

The factories are pure: they neither inspect nor modify the machine.  They only
build :class:`src.core.Operation` values.
"""
from __future__ import annotations

import hashlib
import json
import re
from enum import Enum
from typing import Any, Iterable, Optional

from ..core import Lifecycle, OpType, Operation

__all__ = [
    "install_packages",
    "remove_packages",
    "transfer_ownership",
    "create_configuration",
    "migrate_configuration",
    "register_component",
    "enable_service",
    "disable_service",
    "install_kernel",
    "generate_initramfs",
    "install_boot_entry",
    "create_checkpoint",
    "validate_capability",
]


# --------------------------------------------------------------------------- #
# Parameter helpers
# --------------------------------------------------------------------------- #

def _string(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value.strip()


def _string_list(value: Any, name: str) -> list[str]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Iterable):
        raise ValueError(f"{name} must be a list of non-empty strings")
    items = list(value)
    if not items:
        raise ValueError(f"{name} must be a non-empty list")
    result: list[str] = []
    for item in items:
        cleaned = _string(item, f"{name} entry")
        if cleaned not in result:
            result.append(cleaned)
    return result


def _integer(value: Any, name: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")
    if value < minimum:
        raise ValueError(f"{name} must be >= {minimum}")
    return value


def _lifecycle(value: Any) -> str:
    if isinstance(value, Lifecycle):
        return value.value
    text = _string(value, "lifecycle")
    try:
        return Lifecycle(text).value
    except ValueError as exc:
        raise ValueError(
            "lifecycle must be one of " + ", ".join(x.value for x in Lifecycle)
        ) from exc


def _requires(requires: Any) -> list[str]:
    if requires is None:
        return []
    if isinstance(requires, str):
        candidates: Iterable[Any] = [requires]
    elif isinstance(requires, Iterable):
        candidates = list(requires)
    else:
        raise ValueError("requires must be an operation id or an iterable of ids")
    result: list[str] = []
    for candidate in candidates:
        op_id = _string(candidate, "requires entry")
        if op_id not in result:
            result.append(op_id)
    return result


def _operation_id(op_type: OpType, component: str, params: dict[str, Any]) -> str:
    """Stable, collision-resistant id derived only from the operation content."""
    payload = json.dumps(params, sort_keys=True, default=str, ensure_ascii=True)
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:10]
    scope = re.sub(r"[^A-Za-z0-9_.-]+", "_", component or "global")
    return f"{scope}.{op_type.value}.{digest}"


def _build(
    op_type: OpType,
    params: dict[str, Any],
    *,
    component: str,
    requires: Any,
    lifecycle: Any,
    reversible: bool,
    destructive: bool,
    needs_reboot: bool,
) -> Operation:
    scope = _string(component, "component") if component else ""
    params = dict(params)
    params["lifecycle"] = _lifecycle(lifecycle)
    return Operation(
        id=_operation_id(op_type, scope, params),
        type=op_type,
        component=scope,
        params=params,
        requires=_requires(requires),
        reversible=reversible,
        destructive=destructive,
        needs_reboot=needs_reboot,
    )


# --------------------------------------------------------------------------- #
# Factories (one per OpType)
# --------------------------------------------------------------------------- #

def install_packages(
    packages: list[str],
    *,
    component: str = "",
    requires: Any = None,
    lifecycle: Any = Lifecycle.EVOLVE,
    reason: str = "",
) -> Operation:
    """Install (or upgrade to) the requested Arch packages."""
    return _build(
        OpType.INSTALL_PACKAGES,
        {"packages": _string_list(packages, "packages"), "reason": reason},
        component=component,
        requires=requires,
        lifecycle=lifecycle,
        reversible=True,
        destructive=False,
        needs_reboot=False,
    )


def remove_packages(
    packages: list[str],
    *,
    component: str = "",
    requires: Any = None,
    lifecycle: Any = Lifecycle.RETIRE,
    reason: str = "",
) -> Operation:
    """Remove packages.  Destructive by definition; a checkpoint is mandatory."""
    return _build(
        OpType.REMOVE_PACKAGES,
        {"packages": _string_list(packages, "packages"), "reason": reason},
        component=component,
        requires=requires,
        lifecycle=lifecycle,
        reversible=False,
        destructive=True,
        needs_reboot=False,
    )


def transfer_ownership(
    paths: list[str] | str,
    from_owner: str,
    to_owner: str,
    *,
    component: str = "",
    requires: Any = None,
    lifecycle: Any = Lifecycle.INTRODUCE,
    recursive: bool = True,
    destructive: bool = True,
) -> Operation:
    """Set filesystem ownership for Sunshine-managed trees.

    ``destructive`` should be False when no tree exists yet: assigning the
    correct owner to directories created during a fresh install cannot destroy
    user data, and the executor's confidence gate must not block it.
    """
    if isinstance(paths, str):
        paths = [paths]
    cleaned_paths = _string_list(paths, "paths")
    return _build(
        OpType.TRANSFER_OWNERSHIP,
        {
            "paths": cleaned_paths,
            "path": cleaned_paths[0],
            "from_owner": _string(from_owner, "from_owner"),
            "to_owner": _string(to_owner, "to_owner"),
            # Aliases understood by the executor primitive.
            "from": from_owner,
            "to": to_owner,
            "recursive": bool(recursive),
        },
        component=component,
        requires=requires,
        lifecycle=lifecycle,
        reversible=True,
        destructive=destructive,
        needs_reboot=False,
    )


def create_configuration(
    path: str,
    *,
    content: Optional[str] = None,
    capabilities: Optional[list[str]] = None,
    component: str = "",
    requires: Any = None,
    lifecycle: Any = Lifecycle.INTRODUCE,
) -> Operation:
    """Create a configuration file/directory that does not yet exist."""
    params: dict[str, Any] = {"path": _string(path, "path")}
    if content is not None:
        if not isinstance(content, str):
            raise ValueError("content must be a string when provided")
        params["content"] = content
    if capabilities is not None:
        params["capabilities"] = _string_list(capabilities, "capabilities")
    return _build(
        OpType.CREATE_CONFIGURATION,
        params,
        component=component,
        requires=requires,
        lifecycle=lifecycle,
        reversible=True,
        destructive=False,
        needs_reboot=False,
    )


def migrate_configuration(
    path: str,
    from_schema: int,
    to_schema: int,
    *,
    source_path: Optional[str] = None,
    component: str = "",
    requires: Any = None,
    lifecycle: Any = Lifecycle.EVOLVE,
    backup: bool = True,
) -> Operation:
    """Migrate configuration from one schema to a newer one (destructive).

    ``path`` is the resulting managed configuration; ``source_path`` is the old
    location that the executor reads from and removes after a successful write.
    Both are relative to the state root, as required by the executor.
    """
    start = _integer(from_schema, "from_schema")
    end = _integer(to_schema, "to_schema")
    if end <= start:
        raise ValueError("to_schema must be greater than from_schema")
    destination = _string(path, "path")
    source = _string(source_path, "source_path") if source_path else f"{destination}.legacy"
    return _build(
        OpType.MIGRATE_CONFIGURATION,
        {
            "path": destination,
            "source_path": source,
            "from_schema": start,
            "to_schema": end,
            "backup": bool(backup),
        },
        component=component,
        requires=requires,
        lifecycle=lifecycle,
        reversible=True,
        destructive=True,
        needs_reboot=False,
    )


def register_component(
    component_id: str,
    *,
    schema: int = 0,
    provides: Optional[list[str]] = None,
    component: str = "",
    requires: Any = None,
    lifecycle: Any = Lifecycle.INTRODUCE,
) -> Operation:
    """Register a Sunshine component in the component registry.

    ``component_id`` is mandatory (it is the identity being registered), even
    when the generic ``component`` field of the operation is left empty.
    """
    cid = _string(component_id, "component_id")
    params: dict[str, Any] = {
        "component_id": cid,
        "id": cid,
        "schema": _integer(schema, "schema"),
    }
    if provides is not None:
        params["provides"] = _string_list(provides, "provides")
    return _build(
        OpType.REGISTER_COMPONENT,
        params,
        component=component or cid,
        requires=requires,
        lifecycle=lifecycle,
        reversible=True,
        destructive=False,
        needs_reboot=False,
    )


def enable_service(
    service: str,
    *,
    component: str = "",
    requires: Any = None,
    lifecycle: Any = Lifecycle.EVOLVE,
) -> Operation:
    return _build(
        OpType.ENABLE_SERVICE,
        {"service": _string(service, "service")},
        component=component,
        requires=requires,
        lifecycle=lifecycle,
        reversible=True,
        destructive=False,
        needs_reboot=False,
    )


def disable_service(
    service: str,
    *,
    component: str = "",
    requires: Any = None,
    lifecycle: Any = Lifecycle.RETIRE,
) -> Operation:
    return _build(
        OpType.DISABLE_SERVICE,
        {"service": _string(service, "service")},
        component=component,
        requires=requires,
        lifecycle=lifecycle,
        reversible=True,
        destructive=True,
        needs_reboot=False,
    )


def install_kernel(
    kernel_version: str,
    *,
    package: Optional[str] = None,
    component: str = "",
    requires: Any = None,
    lifecycle: Any = Lifecycle.EVOLVE,
) -> Operation:
    version = _string(kernel_version, "kernel_version")
    params: dict[str, Any] = {
        "kernel_version": version,
        "version": version,
    }
    if package is not None:
        params["package"] = _string(package, "package")
    return _build(
        OpType.INSTALL_KERNEL,
        params,
        component=component,
        requires=requires,
        lifecycle=lifecycle,
        reversible=True,
        destructive=False,
        needs_reboot=True,
    )


def generate_initramfs(
    kernel_version: str,
    *,
    preset: Optional[str] = None,
    fallback: bool = True,
    component: str = "",
    requires: Any = None,
    lifecycle: Any = Lifecycle.EVOLVE,
) -> Operation:
    version = _string(kernel_version, "kernel_version")
    params: dict[str, Any] = {
        "kernel_version": version,
        "kernel": version,
        "fallback": bool(fallback),
    }
    if preset is not None:
        params["preset"] = _string(preset, "preset")
    return _build(
        OpType.GENERATE_INITRAMFS,
        params,
        component=component,
        requires=requires,
        lifecycle=lifecycle,
        reversible=True,
        destructive=False,
        needs_reboot=False,
    )


def install_boot_entry(
    loader: str,
    *,
    label: Optional[str] = None,
    kernel_version: Optional[str] = None,
    component: str = "",
    requires: Any = None,
    lifecycle: Any = Lifecycle.EVOLVE,
) -> Operation:
    params: dict[str, Any] = {"loader": _string(loader, "loader")}
    if label is not None:
        params["label"] = _string(label, "label")
    if kernel_version is not None:
        params["kernel_version"] = _string(kernel_version, "kernel_version")
    return _build(
        OpType.INSTALL_BOOT_ENTRY,
        params,
        component=component,
        requires=requires,
        lifecycle=lifecycle,
        reversible=True,
        destructive=False,
        needs_reboot=True,
    )


def create_checkpoint(
    name: str,
    *,
    component: str = "",
    requires: Any = None,
    lifecycle: Any = Lifecycle.EVOLVE,
    reason: str = "",
) -> Operation:
    label = _string(name, "name")
    params: dict[str, Any] = {"name": label, "label": label}
    if reason:
        params["reason"] = _string(reason, "reason")
    return _build(
        OpType.CREATE_CHECKPOINT,
        params,
        component=component,
        requires=requires,
        lifecycle=lifecycle,
        reversible=True,
        destructive=False,
        needs_reboot=False,
    )


def validate_capability(
    capabilities: list[str] | str,
    *,
    component: str = "",
    requires: Any = None,
    lifecycle: Any = Lifecycle.EVOLVE,
) -> Operation:
    if isinstance(capabilities, str):
        capabilities = [capabilities]
    checked = _string_list(capabilities, "capabilities")
    return _build(
        OpType.VALIDATE_CAPABILITY,
        {"capabilities": checked, "capability": checked[0]},
        component=component,
        requires=requires,
        lifecycle=lifecycle,
        reversible=True,
        destructive=False,
        needs_reboot=False,
    )
