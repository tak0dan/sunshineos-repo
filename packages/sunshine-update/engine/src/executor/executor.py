"""Transactional, journaled executor for declarative evolution plans."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Callable, Optional

try:
    from ..core import (Confidence, JournalEntry, Observation, ObservedState, OpType,
                        Operation, Plan, Status, state_fingerprint)
except ImportError:  # pragma: no cover
    from core import (Confidence, JournalEntry, Observation, ObservedState, OpType,  # type: ignore
                      Operation, Plan, Status, state_fingerprint)

from ..adapters import AdapterRegistry
from .journal import Journal, JournalState, default_execute
from .primitives import (BOOT_OPS, ExecutionContext, Result, _packages, _unit,
                         dispatch)
from .recovery import RecoveryPlan, build_recovery

Execute = Callable[[str], tuple[int, str, str]]
Checkpoint = Callable[..., Any]

GROUP_ORDER = ("bootstrap", "foundation", "core architecture", "kernel/boot", "desktop", "finalization")
_GROUP_ALIASES = {
    "core": "core architecture", "core_architecture": "core architecture",
    "core-architecture": "core architecture", "kernel_boot": "kernel/boot",
    "kernel-boot": "kernel/boot", "kernel": "kernel/boot", "boot": "kernel/boot",
    "bootstrap": "bootstrap", "foundation": "foundation", "desktop": "desktop",
    "finalization": "finalization", "finalize": "finalization",
}


@dataclass
class ExecutionResult:
    plan_id: str
    status: str  # success | failed | dry_run
    completed_ops: list[str] = field(default_factory=list)
    skipped_ops: list[str] = field(default_factory=list)
    failed_op: str = ""
    errors: list[str] = field(default_factory=list)
    changed: bool = False
    checkpoints: list[str] = field(default_factory=list)
    validations: list[dict[str, Any]] = field(default_factory=list)
    recovery_actions: list[str] = field(default_factory=list)
    recovery_report: str = "No recovery required."
    recovery_plan: Optional[dict[str, Any]] = None
    journal_status: str = "absent"

    @property
    def failed_op_id(self) -> str:
        return self.failed_op

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def normalize_group(name: str) -> str:
    key = str(name).strip().lower().replace(" ", "_")
    return _GROUP_ALIASES.get(key, _GROUP_ALIASES.get(str(name).strip().lower(), str(name)))


def group_for(op: Operation, plan: Plan) -> str:
    """Assign an operation to a transaction group (explicit params win)."""
    if op.params.get("group"):
        return normalize_group(str(op.params["group"]))
    for decision in plan.decisions or []:
        if decision.get("op_id") == op.id and decision.get("group"):
            return normalize_group(str(decision["group"]))

    component = str(op.component or "").lower()
    desktopish = any(k in component for k in ("desktop", "session", "pipewire", "shell", "profile", "greeter"))
    if op.type == OpType.CREATE_CHECKPOINT:
        # A checkpoint that depends on another operation must live in the same
        # or a later group than that dependency; forcing all checkpoints into
        # "bootstrap" broke plans where a checkpoint guarded a destructive op
        # whose prerequisites were installed in a later transaction group.
        if op.requires:
            by_id = {candidate.id: candidate for candidate in plan.operations}
            dep_groups = [
                group_for(by_id[dep], plan) for dep in op.requires if dep in by_id
            ]
            if dep_groups:
                latest = max(dep_groups, key=lambda g: GROUP_ORDER.index(g))
                return latest
        return "bootstrap"
    if op.type == OpType.VALIDATE_CAPABILITY:
        return "finalization"
    if op.type in (OpType.INSTALL_KERNEL, OpType.GENERATE_INITRAMFS, OpType.INSTALL_BOOT_ENTRY):
        return "kernel/boot"
    if op.type == OpType.INSTALL_PACKAGES:
        if op.params.get("foundation") or op.params.get("full_upgrade"):
            return "foundation"
        return "desktop" if desktopish else "core architecture"
    if op.type in (OpType.ENABLE_SERVICE, OpType.DISABLE_SERVICE):
        return "desktop" if desktopish else "core architecture"
    if op.type == OpType.REMOVE_PACKAGES:
        return "foundation" if op.params.get("foundation") else "core architecture"
    return "core architecture"


def topological_order(operations: list[Operation]) -> list[Operation]:
    """Stable Kahn sort: dependencies first, original declaration order otherwise."""
    by_id = {o.id: o for o in operations}
    if len(by_id) != len(operations):
        raise ValueError("duplicate operation ids in plan")
    deps: dict[str, list[str]] = {}
    for op in operations:
        deps[op.id] = []
        for dep in op.requires:
            if dep not in by_id:
                raise ValueError(f"operation {op.id} requires unknown operation {dep}")
            deps[op.id].append(dep)
    done: set[str] = set()
    remaining = list(operations)
    ordered: list[Operation] = []
    while remaining:
        ready = [o for o in remaining if all(d in done for d in deps[o.id])]
        if not ready:
            raise ValueError("cycle in plan dependencies: " + ", ".join(o.id for o in remaining))
        for op in ready:
            ordered.append(op)
            done.add(op.id)
            remaining.remove(op)
    return ordered


def _observations_from_plan(plan: Plan) -> tuple[dict[str, Observation], Optional[ObservedState]]:
    source = plan.source or {}
    raw = source.get("observations") or {}
    observations: dict[str, Observation] = {}
    if isinstance(raw, dict):
        items = [(str(k), v) for k, v in raw.items()]
    else:
        items = [(str(v.get("component") or v.get("name") or i), v) for i, v in enumerate(raw)]
    for key, value in items:
        if isinstance(value, Observation):
            observations[key] = value
            continue
        if not isinstance(value, dict):
            continue
        confidence = value.get("confidence", "low")
        status = value.get("status", "installed")
        observations[key] = Observation(
            component=str(value.get("component") or key),
            detected=str(value.get("detected") or value.get("package") or key),
            confidence=Confidence(str(getattr(confidence, "value", confidence)).lower()),
            status=Status(str(getattr(status, "value", status)).lower()),
            evidence=[str(e) for e in (value.get("evidence") or [])],
        )
    observed: Optional[ObservedState] = None
    state = source.get("observed_state") or source.get("observed")
    if isinstance(state, ObservedState):
        observed = state
    elif isinstance(state, dict):
        observed = ObservedState(
            distribution=str(state.get("distribution", "unknown")),
            architecture=str(state.get("architecture", "unknown")),
            init_system=str(state.get("init_system", "unknown")),
            package_manager=str(state.get("package_manager", "unknown")),
            packages={str(k): str(v) for k, v in (state.get("packages") or {}).items()},
            foreign_packages=list(state.get("foreign_packages") or []),
            repositories=list(state.get("repositories") or []),
            capabilities={str(c) for c in (state.get("capabilities") or [])},
        )
        for obs in observations.values():
            observed.observe(obs)
    return observations, observed


def preflight_group(group: str, operations: list[Operation], context: ExecutionContext) -> list[str]:
    """Static, non-mutating checks run once before each transaction group."""
    issues: list[str] = []
    has_foundation = any(o.type == OpType.INSTALL_PACKAGES and
                         (o.params.get("foundation") or o.params.get("full_upgrade"))
                         for o in operations)
    for op in operations:
        try:
            if op.type == OpType.INSTALL_PACKAGES or op.type == OpType.REMOVE_PACKAGES:
                pkgs = _packages(op)
                if op.type == OpType.REMOVE_PACKAGES and not pkgs:
                    issues.append(f"{op.id}: removal target not explicitly identified")
            if op.type in (OpType.ENABLE_SERVICE, OpType.DISABLE_SERVICE):
                if not _unit(op):
                    issues.append(f"{op.id}: missing systemd unit")
        except ValueError as exc:
            issues.append(f"{op.id}: {exc}")
        if op.destructive and not context.observations and context.observed is None:
            issues.append(f"{op.id}: destructive operation without any discovery observations")
        if group == "kernel/boot" and op.type in BOOT_OPS and not context.checkpoint_ref:
            issues.append(f"{op.id}: boot operation requires a checkpoint")
    if context.repository_generation_changed and not has_foundation and not context.upgraded:
        if any(o.type == OpType.INSTALL_PACKAGES and _safe_packages(o) for o in operations):
            issues.append("repository databases changed but no foundation full-upgrade operation "
                          "(partial upgrades are refused)")
    return list(dict.fromkeys(issues))


def _safe_packages(op: Operation) -> list[str]:
    try:
        return _packages(op)
    except ValueError:
        return []


def _abort(plan: Plan, op: Optional[Operation], group: str, error: str,
           result: ExecutionResult, context: ExecutionContext, *,
           journal: Optional[Journal] = None, write_journal: bool = False) -> ExecutionResult:
    if journal is not None and write_journal and op is not None:
        failure_detail: dict[str, Any] = {
            "operation": op.type.value, "component": op.component, "group": group,
        }
        if context.metadata.get("adapter_invocation"):
            failure_detail["adapter"] = context.metadata["adapter_invocation"]
        journal.fail(op.id, error, failure_detail)
    recovery = build_recovery(plan, op, group, error, checkpoint_ref=context.checkpoint_ref,
                              completed_ops=list(result.completed_ops))
    result.status = "failed"
    result.failed_op = op.id if op is not None else ""
    result.errors.append(error)
    result.recovery_actions = [a.to_dict()["action"] + (f" [{a.command}]" if a.command else "")
                               for a in recovery.actions]
    result.recovery_plan = recovery.to_dict()
    result.recovery_report = recovery.report()
    if journal is not None:
        result.journal_status = journal.load().status
    return result


def execute_plan(plan: Plan, state_root: str | Path, execute: Optional[Execute] = None,
                 checkpoint: Optional[Checkpoint] = None, *, resume: bool = False,
                 dry_run: bool = False, validator: Optional[Callable[..., Any]] = None,
                 observed: Optional[ObservedState] = None, verify: bool = True,
                 adapters: Optional[AdapterRegistry] = None,
                 adapter_launcher: Optional[Callable[..., Any]] = None,
                 system_root: Optional[str | Path] = None) -> ExecutionResult:
    """Execute a plan transactionally.

    ``resume=True`` re-discovers actual state (journal + probes) and skips only
    operations whose effects are demonstrably still present.
    """
    result = ExecutionResult(plan_id=plan.id, status="dry_run" if dry_run else "failed")
    ex = execute or default_execute
    journal = Journal(state_root, plan.id, in_memory=dry_run)
    observations, discovered = _observations_from_plan(plan)
    if observed is not None:
        discovered = observed
    context = ExecutionContext(
        state_root=Path(state_root), system_root=Path(system_root) if system_root is not None else None,
        execute=ex, checkpoint=checkpoint, validator=validator,
        dry_run=dry_run, resume=resume, plan_id=plan.id, observed=discovered,
        observations=observations,
        repository_generation_changed=bool(
            (plan.source or {}).get("repository_generation") !=
            (plan.target or {}).get("repository_generation")
        ),
        repository_generation=str((plan.target or {}).get(
            "repository_generation", (plan.source or {}).get("repository_generation", ""))),
        metadata={
            "adapters": adapters,
            "adapter_launcher": adapter_launcher,
        },
    )

    # A plan is only valid for the machine it was built from.  When a caller
    # supplies current discovery data, a mismatch means state changed after
    # planning and nothing may be executed against that stale intent.
    planned_fingerprint = str((plan.source or {}).get("observed_fingerprint", ""))
    if observed is not None and planned_fingerprint:
        current_fingerprint = state_fingerprint(observed)
        if current_fingerprint != planned_fingerprint:
            return _abort(
                plan, None, "bootstrap",
                f"stale plan: observed state changed since planning "
                f"({planned_fingerprint} -> {current_fingerprint}); re-discover and replan",
                result, context, journal=journal, write_journal=not dry_run,
            )

    try:
        ordered = topological_order(plan.operations)
    except ValueError as exc:
        return _abort(plan, None, "bootstrap", f"preflight failed: {exc}", result, context, journal=journal)

    previous = journal.load() if resume else JournalState()
    if not previous.transaction or previous.status == "absent":
        journal.start(plan)

    # Assign each operation to a transaction group, then promote dependents to
    # the group of their dependencies.  Grouping must never invert a DAG edge:
    # a RegisterComponent that depends on an InstallBootEntry belongs in the
    # kernel/boot group even though its component is otherwise architectural.
    op_group: dict[str, str] = {op.id: group_for(op, plan) for op in ordered}
    promoted = True
    while promoted:
        promoted = False
        for op in ordered:
            group_index = GROUP_ORDER.index(op_group[op.id])
            for dep in op.requires:
                if dep not in op_group:
                    continue
                dep_index = GROUP_ORDER.index(op_group[dep])
                if dep_index > group_index:
                    op_group[op.id] = op_group[dep]
                    promoted = True
                    break

    # Rebuild the sequence from the final assignment.  `ordered` is already
    # topological, so filtering it by group preserves intra-group ordering.
    sequence: list[tuple[str, Operation]] = []
    for group in GROUP_ORDER:
        sequence.extend((group, op) for op in ordered if op_group[op.id] == group)

    positions = {op.id: i for i, (_g, op) in enumerate(sequence)}
    for _g, op in sequence:
        for dep in op.requires:
            if positions.get(dep, -1) >= positions[op.id]:
                error = f"operation {op.id} depends on {dep} in a later transaction group"
                return _abort(plan, op, group_for(op, plan), error, result, context,
                              journal=journal, write_journal=not dry_run)

    # Resume: a completed journal line is only a hint. Probe the machine.
    skip_ids: set[str] = set()
    if resume and previous.entries:
        completed_ids = [e.id for e in previous.entries
                         if e.status == "completed" and ":" not in e.id and
                         not e.operation.startswith("Transaction")]
        if completed_ids:
            actual = journal.read_actual_state(context.fs_root, ex, completed_ids, previous,
                                               state_root=context.root)
            for op_id in completed_ids:
                check = actual.checks.get(op_id)
                if check is not None and not check.matches:
                    journal.append(JournalEntry(
                        id=f"{op_id}:reconcile", operation="Reconcile", status="running",
                        output=f"journal claimed completion but actual state differs: "
                               f"{check.kind}, expected_present={check.expected_present}, "
                               f"present={check.present}; evidence={'; '.join(check.evidence)}",
                    ), {"discrepancy": check.to_dict()})
                else:
                    skip_ids.add(op_id)
        for e in previous.entries:
            if e.id in skip_ids and e.operation == "CreateCheckpoint":
                ref = str((previous.details.get(e.id) or {}).get("checkpoint") or "")
                if ref:
                    context.note_checkpoint(ref)
        for op in ordered:
            if op.id in skip_ids and op.type == OpType.INSTALL_PACKAGES and \
                    (op.params.get("foundation") or op.params.get("full_upgrade")):
                context.upgraded = True

    current_group = ""
    for group, op in sequence:
        if group != current_group:
            current_group = group
            issues = preflight_group(group, [o for g, o in sequence if g == group], context)
            if issues:
                error = f"preflight failed for group '{group}': " + "; ".join(issues)
                return _abort(plan, op, group, error, result, context,
                              journal=journal, write_journal=not dry_run)

        if op.id in skip_ids:
            result.skipped_ops.append(op.id)
            result.completed_ops.append(op.id)
            if op.type == OpType.CREATE_CHECKPOINT:
                ref = str((previous.details.get(op.id) or {}).get("checkpoint") or "")
                if ref:
                    context.note_checkpoint(ref)
            continue

        # A checkpoint must exist before anything destructive or boot-related.
        if (op.destructive or op.type in BOOT_OPS) and not context.checkpoint_ref:
            auto = Operation(id=f"auto-checkpoint-{op.id}", type=OpType.CREATE_CHECKPOINT,
                             component=op.component, params={"label": f"pre-{op.id}"})
            cp_result = dispatch(auto, context)
            journal.complete(auto.id, cp_result, {
                "operation": auto.type.value, "component": auto.component,
                "params": auto.params, "group": group,
            })
            if not cp_result.ok:
                return _abort(plan, auto, group, cp_result.output, result, context,
                              journal=journal, write_journal=not dry_run)
            context.note_checkpoint(str(cp_result.metadata.get("checkpoint") or auto.id))
            result.checkpoints.append(context.checkpoint_ref)

        outcome: Result = dispatch(op, context)
        if not outcome.ok:
            return _abort(plan, op, group, outcome.output or outcome.detail, result, context,
                          journal=journal, write_journal=not dry_run)

        journal.complete(op.id, outcome, {
            "operation": op.type.value, "component": op.component,
            "params": op.params, "group": group,
        })
        if op.type == OpType.CREATE_CHECKPOINT and outcome.metadata.get("checkpoint"):
            result.checkpoints.append(str(outcome.metadata["checkpoint"]))
        if outcome.changed and not dry_run:
            result.changed = True

        # Per-step validation: journal success is not proof of system state.
        if verify and not dry_run and outcome.metadata.get("verify"):
            actual = journal.read_actual_state(context.fs_root, ex, [op.id], state_root=context.root)
            check = actual.checks.get(op.id)
            if check is not None and not check.matches:
                error = (f"post-execution validation failed for {op.id}: expected_present="
                         f"{check.expected_present}, present={check.present}, "
                         f"evidence={'; '.join(check.evidence)}")
                validation_detail: dict[str, Any] = {
                    "operation": op.type.value, "group": group, "recovery": "required",
                }
                if context.metadata.get("adapter_invocation"):
                    validation_detail["adapter"] = context.metadata["adapter_invocation"]
                journal.fail(op.id, error, validation_detail)
                return _abort(plan, op, group, error, result, context, journal=journal)
            if check is not None:
                result.validations.append(check.to_dict())
        result.completed_ops.append(op.id)

    if not dry_run and verify:
        journal_state = journal.load()
        actual = journal.read_actual_state(context.fs_root, ex, journal_state=journal_state,
                                           state_root=context.root)
        discrepancies = actual.discrepancies(journal_state)
        result.validations = [c.to_dict() for c in actual.checks.values()]
        if discrepancies:
            error = "final reconciliation failed: " + "; ".join(
                f"{d['op_id']} ({d['kind']})" for d in discrepancies)
            return _abort(plan, sequence[-1][1] if sequence else None,
                          current_group, error, result, context, journal=journal)

    if not dry_run:
        journal.commit(f"{len(result.completed_ops)} operation(s) completed; validation passed")
    result.journal_status = journal.load().status
    result.status = "dry_run" if dry_run else "success"
    result.recovery_report = "No recovery required: all transaction groups validated and committed."
    return result
