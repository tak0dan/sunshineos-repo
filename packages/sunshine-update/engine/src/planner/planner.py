"""Planner orchestration.

The planner is a pure function of (observed state, target spec).  It never
touches the filesystem, the package manager, or the caller's objects.  Both a
pure Arch machine and an older Sunshine OS go through exactly this same code
path: the only inputs are what was observed and what is desired.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import fields, is_dataclass, replace
from enum import Enum
from typing import Any, Iterable, Optional

from ..core import (Lifecycle, ObservedState, OpType, Operation, Plan, TargetSpec,
                    state_fingerprint)
from . import operations as ops
from .graph import DependencyGraph
from .strategies import _detect_presence, build_context, plan_component

__all__ = ["plan", "build_plan", "capability_deltas"]


# --------------------------------------------------------------------------- #
# Pure helpers
# --------------------------------------------------------------------------- #

def _freeze(value: Any) -> Any:
    """Convert dataclasses/enums/sets into plain JSON-compatible data."""
    if isinstance(value, Enum):
        return value.value
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, set):
        return sorted(_freeze(item) for item in value)
    if isinstance(value, dict):
        return {
            str(_freeze(key)): _freeze(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, (list, tuple)):
        return [_freeze(item) for item in value]
    if is_dataclass(value):
        return {
            field.name: _freeze(getattr(value, field.name))
            for field in fields(value)
        }
    return str(value)


def capability_deltas(observed: ObservedState, target: TargetSpec) -> dict[str, list[str]]:
    """Return the capabilities that are missing and components that are stale."""
    missing: set[str] = set()
    outdated: list[str] = []
    for component_id, spec in target.components.items():
        missing.update(cap for cap in spec.provides if cap not in observed.capabilities)
        if build_context(observed, spec, target).outdated:
            outdated.append(component_id)
    return {"missing": sorted(missing), "outdated": sorted(outdated)}


def _capability_providers(target: TargetSpec) -> dict[str, list[str]]:
    """Map each declared capability to the component ids that provide it."""
    providers: dict[str, list[str]] = {}
    for cid, spec in target.components.items():
        for capability in spec.provides:
            providers.setdefault(capability, []).append(cid)
    return providers


def _dependency_components(observed: ObservedState, target: TargetSpec) -> dict[str, set[str]]:
    """Translate component ``requires`` entries into concrete component edges.

    Target manifests declare dependencies as *capabilities* (for example
    ``unified-configuration`` or ``package-ownership-registry``), following the
    architecture's capability model.  The planner, however, needs component
    edges for its DAG.  Each requirement is resolved as follows:

    1. If it names a component id directly, use it.
    2. Otherwise, find components declaring it in ``provides`` and depend on
       every provider (this keeps the graph conservative if several components
       could satisfy the capability).
    3. If nothing in the target provides the capability but the observed
       machine already has it (e.g. ``systemd``, ``pacman`` on Arch), it is a
       satisfied foundation prerequisite and adds no edge.
    4. Truly unknown requirements are ignored here and surfaced by validation,
       so a future target cannot silently produce destructive operations from
       an unresolvable dependency.
    """
    providers = _capability_providers(target)
    result: dict[str, set[str]] = {}
    for cid, spec in target.components.items():
        deps: set[str] = set()
        for requirement in spec.requires:
            if requirement in target.components:
                deps.add(requirement)
                continue
            matched = providers.get(requirement, [])
            if matched:
                deps.update(matched)
            elif requirement in observed.capabilities:
                continue  # foundation capability already present
            # else: unresolved -- validation will report the missing capability
        result[cid] = deps
    return result


def _active_components(observed: ObservedState, target: TargetSpec) -> set[str]:
    """Required components, plus present optional ones, plus their closure."""
    active: set[str] = {
        cid for cid, spec in target.components.items()
        if spec.required or _detect_presence(observed, spec)
    }
    dependencies = _dependency_components(observed, target)
    queue = list(active)
    while queue:
        cid = queue.pop()
        for dependency in dependencies.get(cid, set()):
            if dependency not in target.components:
                raise ValueError(
                    f"component '{cid}' requires unknown component '{dependency}'"
                )
            if dependency not in active:
                active.add(dependency)
                queue.append(dependency)
    return active


def _component_order(observed: ObservedState, target: TargetSpec, active: set[str]) -> list[str]:
    """Topologically order active components by their resolved dependencies."""
    dependencies = _dependency_components(observed, target)
    indegree: dict[str, int] = {}
    children: dict[str, list[str]] = {cid: [] for cid in active}
    for cid in active:
        deps = [dep for dep in dependencies.get(cid, set()) if dep in active]
        indegree[cid] = len(deps)
        for dependency in deps:
            children[dependency].append(cid)

    ready = sorted(cid for cid, degree in indegree.items() if degree == 0)
    order: list[str] = []
    while ready:
        cid = ready.pop(0)
        order.append(cid)
        newly_ready: list[str] = []
        for child in children[cid]:
            indegree[child] -= 1
            if indegree[child] == 0:
                newly_ready.append(child)
        ready = sorted(ready + newly_ready)

    if len(order) != len(active):
        blocked = sorted(active - set(order))
        raise ValueError("component dependency cycle detected among: " + ", ".join(blocked))
    return order


def _annotate(operation: Operation, reason: str) -> Operation:
    params = dict(operation.params)
    params.setdefault("planning_reason", reason)
    return replace(operation, params=params)


def _plan_id(source: dict[str, Any], target: dict[str, Any], operations: list[Operation]) -> str:
    payload = json.dumps(
        {
            "source": source,
            "target": target,
            "operations": [op.id for op in operations],
        },
        sort_keys=True,
        default=str,
        ensure_ascii=True,
    )
    return "plan-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #

def plan(
    observed: ObservedState,
    target: TargetSpec,
    decisions: Optional[Iterable[dict[str, Any]]] = None,
    *,
    dry_run: bool = False,
) -> Plan:
    """Compute a deterministic, side-effect-free transformation plan.

    ``decisions`` (unresolved choices from target resolution) are passed through
    into ``Plan.decisions``.  Per-component rationale is additionally exposed
    as ``plan.planning_decisions`` and in each operation's ``planning_reason``.

    ``dry_run=True`` marks the produced operations as simulated.  Planning is
    pure in either mode: inputs are never mutated and no external command is
    ever executed.
    """
    if not isinstance(observed, ObservedState):
        raise ValueError("plan() expects an ObservedState")
    if not isinstance(target, TargetSpec):
        raise ValueError("plan() expects a TargetSpec")

    # Reject rollback to an older repository generation unless an explicitly
    # authorised recovery procedure clears the committed marker.  A target is
    # never allowed to move the machine backwards silently.
    committed = getattr(observed, "repository_generation", 0) or 0
    if committed and target.repository_generation and target.repository_generation < committed:
        raise ValueError(
            f"repository rollback refused: machine has committed generation "
            f"{committed}, target offers {target.repository_generation}; "
            "use an authorised recovery procedure to roll back"
        )

    source = _freeze(observed)
    source["observed_fingerprint"] = state_fingerprint(observed)
    target_snapshot = _freeze(target)
    deltas = capability_deltas(observed, target)
    active = _active_components(observed, target)
    order = _component_order(observed, target, active)

    planning_decisions: list[dict[str, Any]] = [{
        "kind": "capability-deltas",
        "missing_capabilities": deltas["missing"],
        "outdated_components": deltas["outdated"],
    }]

    # 1. Ask each component strategy what it needs, honouring component deps.
    strategy_ops: dict[str, list[Operation]] = {}
    last_by_component: dict[str, str] = {}
    for cid in order:
        spec = target.components[cid]
        ctx = build_context(observed, spec, target)
        dependencies: list[str] = []
        for required in spec.requires:
            if required in last_by_component:
                dependencies.append(last_by_component[required])
        component_ops = plan_component(observed, spec, target, deps=dependencies)
        strategy_ops[cid] = component_ops
        if component_ops:
            last_by_component[cid] = component_ops[-1].id
        planning_decisions.append({
            "kind": "component",
            "component": cid,
            "lifecycle": (
                "introduce" if ctx.introduce
                else "converged" if not ctx.needs_work
                else "evolve"
            ),
            "source_schema": ctx.schema,
            "target_schema": spec.schema,
            "reason": ctx.reason,
            "operations": [operation.id for operation in component_ops],
        })

    by_id: dict[str, Operation] = {
        operation.id: operation
        for cid in order
        for operation in strategy_ops[cid]
    }

    # 1b. When the repository generation changes, Arch forbids partial
    #     upgrades: every package install must follow one coherent full-upgrade
    #     transaction.  Emit that foundation operation and make every other
    #     package installation depend on it.
    source_generation = source.get("repository_generation")
    needs_packages = any(
        op.type == OpType.INSTALL_PACKAGES for op in by_id.values()
    )
    if (needs_packages and target.repository_generation and
            target.repository_generation != source_generation):
        foundation = Operation(
            id="foundation.full-upgrade",
            type=OpType.INSTALL_PACKAGES,
            component="core",
            params={
                "packages": [],
                "foundation": True,
                "full_upgrade": True,
                "repository_generation": target.repository_generation,
                "reason": "coherent full-upgrade before installing Sunshine packages "
                          "(partial upgrades are refused by Arch)",
            },
            requires=[],
            reversible=True,
            destructive=False,
        )
        by_id[foundation.id] = foundation
        strategy_ops.setdefault("core", []).insert(0, foundation)
        for operation in list(by_id.values()):
            if (operation.id != foundation.id and
                    operation.type == OpType.INSTALL_PACKAGES and
                    foundation.id not in operation.requires):
                by_id[operation.id] = replace(
                    operation, requires=list(operation.requires) + [foundation.id]
                )
        for cid in order:
            strategy_ops[cid] = [by_id[op.id] for op in strategy_ops[cid]]
        planning_decisions.append({
            "kind": "foundation-full-upgrade",
            "operation": foundation.id,
            "reason": foundation.params["reason"],
        })

    # 2. A single checkpoint protects every destructive operation in the plan.
    destructive = [operation for operation in by_id.values() if operation.destructive]
    graph = DependencyGraph()
    checkpoint_id: Optional[str] = None
    if destructive:
        checkpoint = ops.create_checkpoint(
            "pre-transformation",
            component="",
            reason=f"protecting {len(destructive)} destructive operation(s)",
        )
        checkpoint_id = checkpoint.id
        graph.add(checkpoint)
        for operation in destructive:
            if checkpoint_id not in operation.requires:
                by_id[operation.id] = replace(
                    operation, requires=list(operation.requires) + [checkpoint_id]
                )
        for cid in order:
            strategy_ops[cid] = [by_id[op.id] for op in strategy_ops[cid]]
        planning_decisions.append({
            "kind": "checkpoint",
            "checkpoint": checkpoint_id,
            "protects": sorted(operation.id for operation in destructive),
        })

    # 3. Add the strategy operations in dependency order, then recalculate in
    #    case observed state already satisfies some prerequisite.  The
    #    foundation full-upgrade must enter the graph before any package
    #    installation that depends on it, regardless of component order.
    if "foundation.full-upgrade" in by_id:
        graph.add(by_id["foundation.full-upgrade"])
        strategy_ops["core"] = [op for op in strategy_ops.get("core", [])
                                if op.id != "foundation.full-upgrade"]
    for cid in order:
        for operation in strategy_ops[cid]:
            graph.add(operation)
    removed = graph.recalculate(observed)
    if removed:
        planning_decisions.append({
            "kind": "recalculated",
            "removed": removed,
        })

    # 4. Final validation per component: it depends on all of that component's
    #    remaining mutations, so it always runs last for that component.
    survivors = graph.topological_sort()
    final_by_component: dict[str, str] = {}
    for operation in survivors:
        if operation.component:
            final_by_component[operation.component] = operation.id

    for cid in order:
        spec = target.components[cid]
        capabilities = list(spec.provides) or [f"sunshine-component:{cid}"]
        prerequisite = final_by_component.get(cid)
        validation = ops.validate_capability(
            capabilities,
            component=cid,
            requires=[prerequisite] if prerequisite else [],
        )
        validation = _annotate(
            validation,
            f"verify target capabilities for component '{cid}'",
        )
        graph.add(validation)
        if dry_run:
            planning_decisions.append({
                "kind": "dry-run",
                "component": cid,
                "validation": validation.id,
            })

    graph.validate()
    ordered = graph.topological_sort()

    if dry_run:
        ordered = [
            replace(
                operation,
                params={**operation.params, "dry_run": True},
            )
            for operation in ordered
        ]

    plan_decisions = list(decisions) if decisions is not None else []
    result = Plan(
        id=_plan_id(source, target_snapshot, ordered),
        source=source,
        target=target_snapshot,
        operations=ordered,
        decisions=plan_decisions,
    )
    # Extra, non-serialized metadata for callers that want the rationale.
    result.planning_decisions = planning_decisions  # type: ignore[attr-defined]
    result.dry_run = dry_run  # type: ignore[attr-defined]
    result.deltas = deltas  # type: ignore[attr-defined]
    return result


# Backwards/forwards-friendly alias used by some callers.
build_plan = plan
