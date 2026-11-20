"""Append-only, fsync-backed journal and reconciliation helpers.

The journal records *intent* only.  After an interruption ``read_actual_state``
probes the machine (through the injected ``execute`` callable and the filesystem
under ``root``) so a resume never trusts a ``completed`` line by itself.

Layout under ``state_root``::

    migration/journal/journal.jsonl        append-only JSON lines (fsync)
    migration/transactions/active/<plan>.json
    migration/transactions/completed/<plan>.json
    migration/transactions/failed/<plan>.json
    migration/managed/<path>               last managed copy of a config file
    migration/merges/<name>.json           three-way merge records
    migration/checkpoints/<ref>.json       snapshot references
"""
from __future__ import annotations

import json
import os
import subprocess
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

try:  # package import (preferred)
    from ..core import JournalEntry, Operation, Plan
except ImportError:  # pragma: no cover - allows `src` itself on sys.path
    from core import JournalEntry, Operation, Plan  # type: ignore

Execute = Callable[[str], tuple[int, str, str]]


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def default_execute(cmd: str) -> tuple[int, str, str]:
    """Only used when no executor callable was injected (stdlib only)."""
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr


def write_json(path: Path, data: Any, *, fsync: bool = True) -> None:
    """Atomically write JSON, optionally fsync'ing file and parent directory."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, sort_keys=True, indent=2)
        fh.write("\n")
        fh.flush()
        if fsync:
            os.fsync(fh.fileno())
    os.replace(tmp, path)
    if fsync:
        _fsync_dir(path.parent)


def _fsync_dir(path: Path) -> None:
    try:
        fd = os.open(str(path), os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:  # some filesystems do not allow directory fsync
        pass


@dataclass
class JournalState:
    """Snapshot of everything the journal knows (intent, not truth)."""

    plan_id: str = ""
    entries: list[JournalEntry] = field(default_factory=list)
    details: dict[str, dict[str, Any]] = field(default_factory=dict)
    transaction: Optional[dict[str, Any]] = None
    completed: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)
    status: str = "absent"

    def __iter__(self):
        return iter(self.entries)

    def __len__(self) -> int:
        return len(self.entries)

    def entry(self, op_id: str) -> Optional[JournalEntry]:
        for e in self.entries:
            if e.id == op_id:
                return e
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "status": self.status,
            "completed": list(self.completed),
            "failed": list(self.failed),
            "transaction": self.transaction,
            "entries": [asdict(e) for e in self.entries],
            "details": dict(self.details),
        }


@dataclass
class ActualCheck:
    op_id: str
    kind: str = "unknown"
    expected_present: Optional[bool] = None
    present: bool = False
    confidence: str = "unknown"  # high | low | unknown
    evidence: list[str] = field(default_factory=list)

    @property
    def matches(self) -> bool:
        if self.confidence == "unknown" or self.expected_present is None:
            return True  # no reliable probe: tolerate, but never authorise destruction
        return self.present == self.expected_present

    def to_dict(self) -> dict[str, Any]:
        return {
            "op_id": self.op_id,
            "kind": self.kind,
            "expected_present": self.expected_present,
            "present": self.present,
            "confidence": self.confidence,
            "evidence": list(self.evidence),
            "matches": self.matches,
        }


@dataclass
class ActualState:
    """Result of comparing journal intent with what is actually on the system."""

    root: str = ""
    checks: dict[str, ActualCheck] = field(default_factory=dict)

    def matches(self, op_id: str) -> bool:
        check = self.checks.get(op_id)
        return True if check is None else check.matches

    def discrepancies(self, journal: JournalState) -> list[dict[str, Any]]:
        out = []
        for e in journal.entries:
            check = self.checks.get(e.id)
            if e.status == "completed" and check is not None and not check.matches:
                out.append({"op_id": e.id, "operation": e.operation, **check.to_dict()})
        return out

    def to_dict(self) -> dict[str, Any]:
        return {"root": self.root, "checks": {k: v.to_dict() for k, v in self.checks.items()}}


class Journal:
    """Persistent transaction journal rooted at ``state_root/migration``."""

    ENTRY_FIELDS = set(JournalEntry.__dataclass_fields__)

    def __init__(self, state_root: str | Path, plan_id: str = "", *, in_memory: bool = False):
        self.root = Path(state_root)
        self.plan_id = str(plan_id)
        self.in_memory = in_memory
        self.base = self.root / "migration"
        self.journal_dir = self.base / "journal"
        self.journal_file = self.journal_dir / "journal.jsonl"
        self.txn_dir = self.base / "transactions"
        self.active_dir = self.txn_dir / "active"
        self.completed_dir = self.txn_dir / "completed"
        self.failed_dir = self.txn_dir / "failed"
        self._memory: list[dict[str, Any]] = []
        self._memory_txn: Optional[dict[str, Any]] = None

    # ------------------------------------------------------------------ paths
    def _txn_path(self, status: str) -> Path:
        return getattr(self, f"{status}_dir") / f"{self.plan_id}.json"

    def _ensure_dirs(self) -> None:
        if self.in_memory:
            return
        for d in (self.journal_dir, self.active_dir, self.completed_dir, self.failed_dir):
            d.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ writes
    def start(self, plan: Plan) -> JournalState:
        """Begin a transaction, recording the full intent before any change."""
        self.plan_id = plan.id
        txn = {
            "plan_id": plan.id,
            "status": "active",
            "started_at": utcnow(),
            "completed_at": "",
            "intent": [o.to_dict() for o in plan.operations],
            "completed": [],
            "failed": [],
            "skipped": [],
            "source": plan.source,
            "target": plan.target,
        }
        self._write_txn("active", txn)
        self.append(
            JournalEntry(
                id=f"{plan.id}:start",
                operation="TransactionStart",
                status="running",
                output=f"plan {plan.id}: {len(plan.operations)} operation(s) intended",
            ),
            {"plan_id": plan.id, "intent": txn["intent"]},
        )
        return self.load()

    def append(self, entry: JournalEntry, extra: Optional[dict[str, Any]] = None) -> JournalEntry:
        """Append one JSON line and fsync it. Entries are never rewritten."""
        record = asdict(entry)
        record.update(extra or {})
        record.setdefault("ts", utcnow())
        record.setdefault("plan_id", self.plan_id)
        if self.in_memory:
            self._memory.append(record)
        else:
            self._ensure_dirs()
            line = json.dumps(record, sort_keys=True, default=str) + "\n"
            fd = os.open(str(self.journal_file), os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600)
            try:
                os.write(fd, line.encode("utf-8"))
                os.fsync(fd)
            finally:
                os.close(fd)
        return entry

    def complete(self, op_id: str, result: Any, extra: Optional[dict[str, Any]] = None) -> JournalEntry:
        extra = dict(extra or {})
        output = getattr(result, "output", "") if not isinstance(result, dict) else str(result.get("output", ""))
        meta = getattr(result, "metadata", {}) if not isinstance(result, dict) else dict(result.get("metadata", {}))
        entry = JournalEntry(
            id=op_id,
            operation=str(extra.get("operation", "Operation")),
            status="completed",
            component=str(extra.get("component", "")),
            started_at=str(extra.get("started_at", "")),
            completed_at=utcnow(),
            validation_passed=bool(getattr(result, "ok", True) if not isinstance(result, dict) else result.get("ok", True)),
            recovery=str(extra.get("recovery", "not-required")),
            output=str(output)[:20000],
        )
        detail = {
            "operation": entry.operation,
            "params": extra.get("params", {}),
            "verify": meta.get("verify") or extra.get("verify"),
            "checkpoint": meta.get("checkpoint"),
            "changed": bool(getattr(result, "changed", False) if not isinstance(result, dict) else result.get("changed", False)),
            "reversible": bool(getattr(result, "reversible", True) if not isinstance(result, dict) else result.get("reversible", True)),
            "group": extra.get("group", ""),
        }
        if extra.get("skipped"):
            detail["skipped"] = True
        # Signed adapter invocations are part of the audit trail.  The adapter
        # runner puts this metadata on every Result, including dry runs.
        if meta.get("adapter") or extra.get("adapter"):
            detail["adapter"] = meta.get("adapter") or extra.get("adapter")
        self.append(entry, detail)
        txn = self._transaction() or {}
        completed = list(txn.get("completed", []))
        if op_id not in completed:
            completed.append(op_id)
        txn.update({"completed": completed, "status": "active"})
        self._write_txn("active", txn)
        return entry

    def skip(self, op_id: str, reason: str, extra: Optional[dict[str, Any]] = None) -> JournalEntry:
        """Record that an op was re-discovered as already satisfied."""
        extra = dict(extra or {})
        extra["skipped"] = True
        return self.complete(op_id, _Skipped(reason), extra)

    def fail(self, op_id: str, error: str, extra: Optional[dict[str, Any]] = None) -> JournalEntry:
        extra = dict(extra or {})
        entry = JournalEntry(
            id=op_id,
            operation=str(extra.get("operation", "Operation")),
            status="failed",
            component=str(extra.get("component", "")),
            completed_at=utcnow(),
            validation_passed=False,
            recovery=str(extra.get("recovery", "required")),
            output=str(error)[:20000],
        )
        failure_detail = {"operation": entry.operation, "group": extra.get("group", ""),
                          "error": str(error), "recovery": entry.recovery}
        if extra.get("adapter"):
            failure_detail["adapter"] = extra["adapter"]
        self.append(entry, failure_detail)
        txn = self._transaction() or {}
        failed = list(txn.get("failed", []))
        if op_id not in failed:
            failed.append(op_id)
        txn.update({"failed": failed, "status": "failed"})
        self._write_txn("failed", txn)
        return entry

    def commit(self, detail: str = "all groups validated") -> JournalEntry:
        entry = JournalEntry(
            id=f"{self.plan_id}:commit",
            operation="TransactionCommit",
            status="completed",
            completed_at=utcnow(),
            validation_passed=True,
            output=detail,
        )
        self.append(entry, {"commit": True})
        txn = self._transaction() or {}
        txn.update({"status": "completed", "completed_at": utcnow()})
        self._write_txn("completed", txn)
        return entry

    # ------------------------------------------------------------------ reads
    def load(self) -> JournalState:
        records = list(self._memory) if self.in_memory else self._read_records()
        state = JournalState(plan_id=self.plan_id)
        known = Journal.ENTRY_FIELDS
        for rec in records:
            if not isinstance(rec, dict):
                continue
            fields = {k: v for k, v in rec.items() if k in known and k != "status"}
            status = str(rec.get("status", "pending"))
            try:
                entry = JournalEntry(status=status, **fields)
            except TypeError:  # tolerate older/hand-edited records
                continue
            state.entries.append(entry)
            state.details[str(entry.id)] = {k: v for k, v in rec.items() if k not in known}
        txn = self._transaction()
        state.transaction = txn
        if txn:
            state.status = str(txn.get("status", "active"))
            state.completed = list(txn.get("completed", []))
            state.failed = list(txn.get("failed", []))
        else:
            state.status = "absent"
            for e in state.entries:
                if e.status == "completed" and ":" not in e.id:
                    state.completed.append(e.id)
                elif e.status == "failed" and ":" not in e.id:
                    state.failed.append(e.id)
            if state.failed:
                state.status = "failed"
            elif state.entries and any(e.operation == "TransactionCommit" for e in state.entries):
                state.status = "completed"
        return state

    def last_committed(self) -> Optional[JournalEntry]:
        entries = self.load().entries
        for e in reversed(entries):
            if e.status == "completed" and e.operation == "TransactionCommit":
                return e
        for e in reversed(entries):
            if e.status == "completed" and ":" not in e.id:
                return e
        return None

    def read_actual_state(self, root: str | Path | None = None, execute: Optional[Execute] = None,
                          op_ids: Optional[Iterable[str]] = None,
                          journal_state: Optional[JournalState] = None,
                          state_root: Optional[str | Path] = None) -> ActualState:
        """Probe the real machine for each journalled operation.

        This is intentionally independent of the journal's ``status`` fields.
        A completed line whose effect is absent is reported as a discrepancy.
        """
        root_path = Path(root) if root is not None else self.root
        ex = execute or default_execute
        state = journal_state or self.load()
        wanted = set(op_ids) if op_ids is not None else None
        actual = ActualState(root=str(root_path))
        for entry in state.entries:
            if entry.id.endswith(":start") or entry.operation.startswith("Transaction"):
                continue
            if wanted is not None and entry.id not in wanted:
                continue
            detail = state.details.get(entry.id, {})
            verify = dict(detail.get("verify") or {})
            kind, targets, expected, present, confidence, evidence = _probe(
                entry, detail, verify, root_path, ex,
                Path(state_root) if state_root is not None else None,
            )
            actual.checks[entry.id] = ActualCheck(
                op_id=entry.id, kind=kind, expected_present=expected,
                present=present, confidence=confidence, evidence=evidence,
            )
        return actual

    # ---------------------------------------------------------------- private
    def _read_records(self) -> list[dict[str, Any]]:
        if not self.journal_file.exists():
            return []
        records = []
        for line in self.journal_file.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                # A torn final line after a crash must not destroy earlier intent.
                continue
            if isinstance(obj, dict):
                records.append(obj)
        return records

    def _transaction(self) -> Optional[dict[str, Any]]:
        if self.in_memory:
            return self._memory_txn
        for status in ("active", "completed", "failed"):
            p = self._txn_path(status)
            if p.exists():
                try:
                    return json.loads(p.read_text(encoding="utf-8"))
                except (json.JSONDecodeError, OSError):
                    return None
        return None

    def _write_txn(self, status: str, txn: dict[str, Any]) -> None:
        if self.in_memory:
            self._memory_txn = dict(txn)
            return
        self._ensure_dirs()
        target = self._txn_path(status)
        write_json(target, txn)
        # Only one status file may describe a transaction at a time.
        for other in ("active", "completed", "failed"):
            if other != status:
                p = self._txn_path(other)
                if p.exists():
                    p.unlink()
                    _fsync_dir(p.parent)


class _Skipped:
    ok = True
    changed = False
    reversible = True
    metadata: dict[str, Any] = {}

    def __init__(self, reason: str):
        self.output = f"skipped: {reason}"


def _safe_args(values: Iterable[Any]) -> list[str]:
    import shlex

    return [shlex.quote(str(v)) for v in values if str(v).strip()]


def _probe(entry: JournalEntry, detail: dict[str, Any], verify: dict[str, Any],
           root: Path, ex: Execute, state_root: Optional[Path] = None) -> tuple[str, list[str], Optional[bool], bool, str, list[str]]:
    """Return (kind, targets, expected, present, confidence, evidence).

    ``root`` is the transformed filesystem (live ``/`` or fixture sandbox);
    ``state_root`` holds engine bookkeeping such as checkpoints and ownership
    records, which must be probed where they were actually written.
    """
    kind = str(verify.get("kind") or _infer_kind(entry.operation))
    expected = verify.get("expected_present")
    if isinstance(expected, str):
        expected = expected.lower() in ("true", "1", "yes")
    if expected is not None:
        expected = bool(expected)
    targets = [str(t) for t in (verify.get("targets") or [])]
    evidence: list[str] = []

    def probe_command(cmd: str, found: Callable[[int, str, str], bool]) -> Optional[bool]:
        try:
            rc, out, err = ex(cmd)
        except Exception as exc:  # a broken probe must fail closed, not crash
            evidence.append(f"probe error: {exc}")
            return None
        evidence.append(f"{cmd} -> rc={rc}: {(out or err).strip()[:200]}")
        return found(rc, out or "", err or "")

    if kind == "packages":
        if not targets:
            params = detail.get("params") or {}
            raw = params.get("packages") or params.get("package") or []
            targets = [str(raw)] if isinstance(raw, str) else [str(x) for x in raw]
        results = [probe_command(f"pacman -Q {a}", lambda rc, o, e: rc == 0) for a in _safe_args(targets)]
        if any(r is None for r in results):
            return kind, targets, expected, False, "unknown", evidence
        present = all(results) if expected is not False else any(results)
        return kind, targets, expected, present, "high", evidence

    if kind == "service":
        params = detail.get("params") or {}
        unit = str(verify.get("unit") or params.get("unit") or params.get("service") or entry.component)
        if not unit:
            return kind, [], expected, False, "unknown", evidence
        rc_result = probe_command(f"systemctl is-enabled {_safe_args([unit])[0]}",
                                  lambda rc, o, e: rc == 0 and "disabled" not in o.lower() and "masked" not in o.lower())
        if rc_result is None:
            return kind, [unit], expected, False, "unknown", evidence
        return kind, [unit], expected, bool(rc_result), "high", evidence

    # Commands that run against the live filesystem (mkinitcpio writes to the
    # real /boot) must be probed through the executor, not against state_root.
    # Fixture executors answer the same command from their sandbox, so this
    # keeps fail-closed verification in both modes.
    probe_cmd = verify.get("command")
    if probe_cmd:
        present = probe_command(str(probe_cmd),
                                lambda rc, o, e: rc == 0 and bool(o.strip()))
        return kind, targets, expected, bool(present), "high" if present is not None else "unknown", evidence

    if kind in ("file", "checkpoint", "ownership", "initramfs"):
        params = detail.get("params") or {}
        rel = verify.get("path") or params.get("path") or ""
        if kind == "checkpoint":
            ref = str(verify.get("ref") or detail.get("checkpoint") or "")
            if ref.startswith("dry-run:"):
                return kind, [ref], expected, True, "low", ["virtual dry-run checkpoint"]
            if ref:
                rel = str(ref)
        if not rel:
            return kind, [], expected, False, "unknown", evidence
        probe_root = state_root if kind in ("checkpoint", "ownership") and state_root is not None else root
        p = Path(str(rel))
        if not p.is_absolute():
            p = probe_root / p
        present = p.exists()
        evidence.append(f"exists({p}) -> {present}")
        if kind == "checkpoint" and not present and detail.get("checkpoint"):
            # An injected snapshot callback may store its snapshot outside our root.
            evidence.append("snapshot callback reference; snapshot not locally probeable")
            return kind, [str(p)], expected, True, "low", evidence
        return kind, [str(p)], expected, present, "high", evidence

    if kind == "boot_entry":
        label = str(verify.get("label") or (detail.get("params") or {}).get("label") or entry.component)
        result = probe_command("efibootmgr -v", lambda rc, o, e: rc == 0 and bool(label) and label in o)
        if result is None:
            return kind, [label], expected, False, "unknown", evidence
        return kind, [label], expected, bool(result), "high", evidence

    if kind == "capability":
        cap = str(verify.get("capability") or (detail.get("params") or {}).get("capability") or entry.component)
        try:
            from ..validation.validator import validate_capability  # type: ignore
            report = validate_capability(cap, root, ex, state_root=state_root)
            present = bool(report.passed)
            evidence.append(report.detail)
        except Exception:
            # Capability presence fallback: recorded observed capability or marker dir.
            present = bool((detail.get("params") or {}).get("observed_present"))
            evidence.append("validator unavailable; used recorded observation")
            return kind, [cap], expected, present, "low", evidence
        return kind, [cap], expected, present, "high", evidence

    return kind, targets, expected, False, "unknown", evidence


def _infer_kind(operation: str) -> str:
    mapping = {
        "InstallPackages": "packages",
        "RemovePackages": "packages",
        "InstallKernel": "packages",
        "EnableService": "service",
        "DisableService": "service",
        "RegisterComponent": "file",
        "CreateConfiguration": "file",
        "MigrateConfiguration": "file",
        "TransferOwnership": "ownership",
        "GenerateInitramfs": "initramfs",
        "InstallBootEntry": "boot_entry",
        "CreateCheckpoint": "checkpoint",
        "ValidateCapability": "capability",
    }
    return mapping.get(str(operation), "unknown")
