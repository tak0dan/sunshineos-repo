"""Runtime bridge from typed operations to verified, sandboxed Rust adapters.

This module is imported lazily by :mod:`primitives` only when an operation carries
an ``adapter_id``. An adapter can never replace a built-in primitive by accident:
without a validated registry in the execution context, the operation is refused.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

try:
    from ..adapters import (
        AdapterInvocation,
        AdapterLauncher,
        AdapterRegistry,
        default_adapter_launcher,
        validate_adapter_params,
    )
    from ..core import OpType, Operation
    from ..trust.model import canonical_bytes
    from .primitives import ExecutionContext, Result, _refuse, _verify
except ImportError:  # pragma: no cover
    from src.adapters import (  # type: ignore
        AdapterInvocation, AdapterLauncher, AdapterRegistry, default_adapter_launcher,
        validate_adapter_params,
    )
    from src.core import OpType, Operation  # type: ignore
    from src.trust.model import canonical_bytes  # type: ignore
    from executor.primitives import ExecutionContext, Result, _refuse, _verify  # type: ignore


def _verify_for(operation: Operation) -> dict[str, Any] | None:
    params = operation.params
    if params.get("target_path"):
        return _verify("file", path=str(params["target_path"]))
    if params.get("capability"):
        return _verify("capability", capability=str(params["capability"]))
    if params.get("unit") or params.get("service") or operation.type in (
        OpType.ENABLE_SERVICE, OpType.DISABLE_SERVICE
    ):
        unit = str(params.get("unit") or params.get("service") or operation.component)
        return _verify("service", unit=unit) if unit else None
    return None


def execute_adapter(operation: Operation, context: ExecutionContext) -> Result:
    """Validate, verify, launch and journal one signed adapter invocation."""
    adapter_id = str(operation.params.get("adapter_id", ""))
    if not adapter_id:
        return _refuse("adapter operation has no adapter_id")

    registry = context.metadata.get("adapters")
    if not isinstance(registry, AdapterRegistry):
        return _refuse(f"adapter {adapter_id}: no validated adapter registry is active")
    try:
        adapter = registry.verify_invocation(adapter_id)
    except ValueError as exc:
        return _refuse(str(exc))

    manifest = adapter.manifest
    if manifest.component != operation.component:
        return _refuse(
            f"adapter {adapter_id}: component mismatch ({manifest.component} != {operation.component})"
        )
    if manifest.operation != operation.type:
        return _refuse(
            f"adapter {adapter_id}: operation mismatch "
            f"({manifest.operation.value} != {operation.type.value})"
        )
    try:
        params = validate_adapter_params(manifest, operation.params)
    except ValueError as exc:
        return _refuse(str(exc))

    digest_input = canonical_bytes({
        "operation": operation.id,
        "adapter": adapter_id,
        "params": params,
        "plan": context.plan_id,
    })
    invocation = AdapterInvocation(
        adapter=adapter,
        params=params,
        state_root=Path(context.state_root),
        dry_run=context.dry_run,
        invocation_id=hashlib.sha256(digest_input).hexdigest()[:20],
    )
    invocation_data = invocation.to_dict()
    # Stored before launch so a crash or a failed launch is still attributable.
    context.metadata["adapter_invocation"] = invocation_data

    launcher: AdapterLauncher = context.metadata.get("adapter_launcher") or default_adapter_launcher
    try:
        launch = launcher(invocation)
    except Exception as exc:  # a broken launcher must fail closed
        return Result(
            False, output=f"adapter launch error: {exc}", changed=False,
            reversible=operation.reversible,
            metadata={"adapter": invocation_data, "verify": _verify_for(operation)},
        )

    metadata: dict[str, Any] = dict(launch.metadata)
    metadata["adapter"] = invocation_data
    verify = _verify_for(operation)
    if verify is not None:
        metadata["verify"] = verify
    return Result(
        ok=launch.ok,
        output=launch.output,
        changed=bool(launch.changed) and not context.dry_run,
        reversible=launch.reversible and operation.reversible,
        detail=f"adapter {adapter_id} v{manifest.version}",
        metadata=metadata,
    )
