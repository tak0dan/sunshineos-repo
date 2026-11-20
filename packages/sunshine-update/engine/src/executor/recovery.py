"""Recovery strategies and human-readable recovery reports.

Strategies are selected per transaction group.  They produce *recommended*
actions (and, where safe, commands) but never execute anything themselves: an
operator or a subsequent resume decides whether to apply them.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

try:
    from ..core import Operation, Plan
except ImportError:  # pragma: no cover
    from core import Operation, Plan  # type: ignore


@dataclass
class RecoveryAction:
    group: str
    strategy: str
    action: str
    command: str = ""
    reversible: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {"group": self.group, "strategy": self.strategy, "action": self.action,
                "command": self.command, "reversible": self.reversible}


@dataclass
class RecoveryPlan:
    plan_id: str
    failed_op: str
    group: str
    error: str
    actions: list[RecoveryAction] = field(default_factory=list)
    completed_ops: list[str] = field(default_factory=list)
    checkpoint_ref: str = ""

    @property
    def strategies(self) -> list[str]:
        return list(dict.fromkeys(a.strategy for a in self.actions))

    def descriptions(self) -> list[str]:
        out = []
        for i, a in enumerate(self.actions, 1):
            line = f"{i}. [{a.strategy}] {a.action}"
            if a.command:
                line += f"  (command: {a.command})"
            out.append(line)
        return out

    def report(self) -> str:
        lines = [
            f"Recovery report for plan '{self.plan_id}'",
            "=" * (33 + len(self.plan_id)),
            f"Failed operation : {self.failed_op or '(none)'}",
            f"Transaction group: {self.group or '(unknown)'}",
            f"Error            : {self.error or '(none)'}",
            f"Checkpoint       : {self.checkpoint_ref or 'none recorded'}",
            "",
            "Strategies: " + (", ".join(self.strategies) if self.strategies else "none"),
            "Recommended actions:",
        ]
        lines += self.descriptions() or ["  1. Inspect the system; no automatic action is safe."]
        if self.completed_ops:
            lines += ["", "Operations journalled as completed before the failure:",
                      "  " + ", ".join(self.completed_ops)]
        lines += ["", "Note: re-run with resume=True after remediation; the executor re-probes",
                  "actual system state and never resumes solely from journal entries."]
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {"plan_id": self.plan_id, "failed_op": self.failed_op, "group": self.group,
                "error": self.error, "checkpoint_ref": self.checkpoint_ref,
                "completed_ops": list(self.completed_ops), "strategies": self.strategies,
                "actions": [a.to_dict() for a in self.actions], "report": self.report()}


def _snapshot(group: str, checkpoint_ref: str) -> list[RecoveryAction]:
    if not checkpoint_ref:
        return [RecoveryAction(group, "snapshot-rollback",
                               "No checkpoint exists; inspect managed configuration manually before retrying",
                               reversible=True)]
    return [
        RecoveryAction(group, "snapshot-rollback", f"Restore snapshot {checkpoint_ref}",
                       f"sunshine-recovery restore {checkpoint_ref}"),
        RecoveryAction(group, "snapshot-rollback", "Re-apply validated operations with resume=True",
                       "recovery: resume"),
    ]


def _service_revert(op: Optional[Operation]) -> list[RecoveryAction]:
    if op is None:
        return []
    unit = str(op.params.get("unit") or op.params.get("service") or op.component)
    if not unit:
        return []
    action = "disable" if op.type.value == "EnableService" else "enable"
    return [RecoveryAction("desktop", "service-revert", f"Revert service state for {unit}",
                           f"systemctl {action} {unit}")]


def _boot_fallback(op: Optional[Operation]) -> list[RecoveryAction]:
    if op is None:
        return []
    label = str(op.params.get("label") or op.component or "Sunshine")
    previous = str(op.params.get("previous_boot_order") or "")
    actions = [
        RecoveryAction("kernel/boot", "boot-entry-fallback",
                       f"Remove the failed boot entry '{label}' if it was partially registered",
                       "efibootmgr -b <Boot####> -B"),
        RecoveryAction("kernel/boot", "boot-entry-fallback",
                       "Confirm the fallback initramfs is still bootable",
                       "ls /boot/initramfs-linux*-fallback.img"),
    ]
    if previous:
        actions.append(RecoveryAction("kernel/boot", "boot-entry-fallback",
                                      "Restore the previous boot order",
                                      f"efibootmgr -o {previous}"))
    return actions


def build_recovery(plan: Plan, op: Optional[Operation], group: str, error: str,
                   *, checkpoint_ref: str = "", completed_ops: Optional[list[str]] = None) -> RecoveryPlan:
    """Choose strategies for a failed group and build the report."""
    group = group or "(unknown)"
    actions: list[RecoveryAction] = []
    if group in ("bootstrap", "foundation", "core architecture", "finalization"):
        actions += _snapshot(group, checkpoint_ref)
    elif group == "desktop":
        actions += _snapshot(group, checkpoint_ref)
        if op is not None and op.type.value in ("EnableService", "DisableService"):
            actions += _service_revert(op)
    elif group == "kernel/boot":
        actions += _boot_fallback(op)
        actions += _snapshot(group, checkpoint_ref)
    else:
        actions += _snapshot(group, checkpoint_ref)
    if op is not None and op.type.value in ("EnableService", "DisableService") and \
            not any(a.strategy == "service-revert" for a in actions):
        actions += _service_revert(op)

    return RecoveryPlan(
        plan_id=plan.id,
        failed_op=op.id if op is not None else "",
        group=group,
        error=str(error),
        actions=actions,
        completed_ops=list(completed_ops or []),
        checkpoint_ref=checkpoint_ref,
    )
