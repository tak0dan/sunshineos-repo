"""Dependency graph for transformation plans.

The graph is deliberately small and deterministic.  It owns three things:

* the operations, keyed by their (content-derived) id;
* explicit conflict rules for mutually exclusive operations;
* algorithms that turn the graph into an executable order or a set of
  parallel layers.

All structural problems (missing prerequisites, cycles, declared conflicts)
raise :class:`ValueError` so a bad plan can never reach the executor.
"""
from __future__ import annotations

from dataclasses import replace
from typing import Iterable, Optional

from ..core import ObservedState, OpType, Operation

__all__ = ["DependencyGraph"]


# Operations that must not be planned for the same component at the same time.
_DEFAULT_TYPE_CONFLICTS: frozenset[tuple[OpType, OpType]] = frozenset({
    (OpType.INSTALL_PACKAGES, OpType.REMOVE_PACKAGES),
    (OpType.ENABLE_SERVICE, OpType.DISABLE_SERVICE),
    (OpType.CREATE_CONFIGURATION, OpType.MIGRATE_CONFIGURATION),
})


def _pair(a: str, b: str) -> tuple[str, str]:
    return (a, b) if a <= b else (b, a)


class DependencyGraph:
    """A directed acyclic graph of :class:`~src.core.Operation` values."""

    def __init__(self) -> None:
        self._ops: dict[str, Operation] = {}
        self._type_conflicts: set[tuple[OpType, OpType]] = {
            _pair(a, b) for a, b in _DEFAULT_TYPE_CONFLICTS
        }
        self._id_conflicts: set[tuple[str, str]] = set()

    # ------------------------------------------------------------------ #
    # Mutation
    # ------------------------------------------------------------------ #
    def add(
        self,
        op: Operation,
        requires: Optional[Iterable[str] | str] = None,
        *,
        allow_pending: bool = False,
    ) -> Operation:
        """Add an operation, optionally adding prerequisite ids.

        By default every prerequisite must already be present in the graph,
        which makes it impossible to accidentally emit a plan whose operations
        refer to something that does not exist.  Set ``allow_pending=True``
        when constructing a graph in several passes (useful for cycle tests).
        """
        if not isinstance(op, Operation):
            raise ValueError("add() expects an Operation")
        if op.id in self._ops:
            raise ValueError(f"duplicate operation id: {op.id}")

        extra: list[str] = []
        if requires is not None:
            if isinstance(requires, str):
                extra = [requires]
            else:
                extra = [str(item) for item in requires]
            for rid in extra:
                if not rid:
                    raise ValueError("requires entries must be non-empty operation ids")

        merged = list(op.requires)
        for rid in extra:
            if rid not in merged:
                merged.append(rid)
        stored = replace(op, requires=merged)
        self._ops[stored.id] = stored

        if not allow_pending:
            self._check_dependencies()
        return stored

    def add_all(self, operations: Iterable[Operation]) -> list[Operation]:
        """Add operations in the supplied (dependency-safe) order."""
        return [self.add(op) for op in operations]

    def remove(self, op_id: str) -> Optional[Operation]:
        """Remove an operation; prerequisites pointing at it are rewired."""
        removed = self._ops.pop(op_id, None)
        if removed is None:
            return None
        for oid, op in list(self._ops.items()):
            if op_id in op.requires:
                self._ops[oid] = replace(
                    op, requires=[r for r in op.requires if r != op_id]
                )
        return removed

    def add_conflict(self, a: str | OpType, b: str | OpType) -> None:
        """Declare two operation types (or operation ids) mutually exclusive."""
        left = a.value if isinstance(a, OpType) else str(a)
        right = b.value if isinstance(b, OpType) else str(b)
        valid = {t.value for t in OpType}
        if left in valid and right in valid:
            self._type_conflicts.add(_pair(OpType(left), OpType(right)))
        else:
            self._id_conflicts.add(_pair(left, right))

    # ------------------------------------------------------------------ #
    # Introspection
    # ------------------------------------------------------------------ #
    @property
    def operations(self) -> list[Operation]:
        return list(self._ops.values())

    @property
    def operation_ids(self) -> list[str]:
        return list(self._ops)

    def get(self, op_id: str) -> Operation:
        try:
            return self._ops[op_id]
        except KeyError as exc:
            raise ValueError(f"unknown operation id: {op_id}") from exc

    def __contains__(self, op_id: object) -> bool:
        return op_id in self._ops

    def __len__(self) -> int:
        return len(self._ops)

    # ------------------------------------------------------------------ #
    # Validation
    # ------------------------------------------------------------------ #
    def _check_dependencies(self) -> None:
        known = set(self._ops)
        for op in self._ops.values():
            for rid in op.requires:
                if rid not in known:
                    raise ValueError(
                        f"missing dependency '{rid}' required by operation '{op.id}'"
                    )

    @staticmethod
    def _scope(op: Operation) -> str:
        return op.component or ""

    def _check_conflicts(self) -> list[tuple[str, str]]:
        found: list[tuple[str, str]] = []
        ops = list(self._ops.values())
        for i, left in enumerate(ops):
            for right in ops[i + 1:]:
                if self._scope(left) != self._scope(right):
                    continue
                pair_ids = _pair(left.id, right.id)
                pair_types = _pair(left.type, right.type)
                if pair_ids in self._id_conflicts or pair_types in self._type_conflicts:
                    found.append(pair_ids)
        return found

    def detect_conflicts(self) -> list[tuple[str, str]]:
        """Return id pairs of mutually exclusive operations in this graph."""
        return sorted(self._check_conflicts())

    def _kahn(self) -> tuple[list[Operation], list[list[Operation]]]:
        indegree = {oid: len(op.requires) for oid, op in self._ops.items()}
        dependents: dict[str, list[str]] = {oid: [] for oid in self._ops}
        for oid, op in self._ops.items():
            for rid in op.requires:
                dependents[rid].append(oid)

        ready = sorted(oid for oid, degree in indegree.items() if degree == 0)
        order: list[Operation] = []
        layers: list[list[Operation]] = []
        while ready:
            layer_ids = ready
            layers.append([self._ops[oid] for oid in layer_ids])
            order.extend(self._ops[oid] for oid in layer_ids)
            next_ready: list[str] = []
            for oid in layer_ids:
                for child in dependents[oid]:
                    indegree[child] -= 1
                    if indegree[child] == 0:
                        next_ready.append(child)
            ready = sorted(next_ready)

        if len(order) != len(self._ops):
            blocked = sorted(set(self._ops) - {op.id for op in order})
            raise ValueError("dependency cycle detected among: " + ", ".join(blocked))
        return order, layers

    def validate(self) -> None:
        """Raise :class:`ValueError` for any structural problem in the graph."""
        self._check_dependencies()
        conflicts = self._check_conflicts()
        if conflicts:
            raise ValueError(
                "mutually exclusive operations planned: "
                + ", ".join(f"{a} vs {b}" for a, b in conflicts)
            )
        self._kahn()  # raises on cycles

    # ------------------------------------------------------------------ #
    # Ordering
    # ------------------------------------------------------------------ #
    def topological_sort(self) -> list[Operation]:
        self._check_dependencies()
        conflicts = self._check_conflicts()
        if conflicts:
            raise ValueError(
                "mutually exclusive operations planned: "
                + ", ".join(f"{a} vs {b}" for a, b in conflicts)
            )
        order, _ = self._kahn()
        return order

    def parallel_layers(self) -> list[list[Operation]]:
        self._check_dependencies()
        conflicts = self._check_conflicts()
        if conflicts:
            raise ValueError(
                "mutually exclusive operations planned: "
                + ", ".join(f"{a} vs {b}" for a, b in conflicts)
            )
        _, layers = self._kahn()
        return layers

    # ------------------------------------------------------------------ #
    # Recalculation
    # ------------------------------------------------------------------ #
    @staticmethod
    def _satisfied_now(op: Operation, observed: ObservedState) -> bool:
        """True when observed state already fulfils this operation's purpose."""
        params = op.params

        # Validation is evidence, not a mutation: never discard it here.
        if op.type is OpType.VALIDATE_CAPABILITY:
            return False

        extra_caps = params.get("requires_capabilities")
        if isinstance(extra_caps, (list, tuple)) and extra_caps:
            if not all(c in observed.capabilities for c in extra_caps):
                return False

        if op.type is OpType.INSTALL_PACKAGES:
            packages = params.get("packages", [])
            return bool(packages) and all(p in observed.packages for p in packages)

        if op.type is OpType.REMOVE_PACKAGES:
            packages = params.get("packages", [])
            return bool(packages) and all(p not in observed.packages for p in packages)

        if op.type is OpType.REGISTER_COMPONENT:
            cid = params.get("component_id") or op.component
            marker = f"sunshine-component:{cid}"
            return marker in observed.capabilities

        return bool(extra_caps)  # satisfied solely via requires_capabilities

    def recalculate(self, observed: ObservedState) -> list[str]:
        """Drop operations whose prerequisites are already met by ``observed``.

        When an operation is dropped its successors inherit that operation's own
        prerequisites, so the graph stays equivalent.  The ids of the dropped
        operations are returned.
        """
        if not isinstance(observed, ObservedState):
            raise ValueError("recalculate() expects an ObservedState")

        current = dict(self._ops)
        removed = {
            oid for oid, op in current.items() if self._satisfied_now(op, observed)
        }
        if not removed:
            return []

        # Inline the prerequisites of removed operations, repeatedly in case a
        # removed operation was itself a prerequisite of another removed one.
        for _ in range(len(current) + 1):
            changed = False
            for oid, op in list(current.items()):
                if oid in removed:
                    continue
                new_requires: list[str] = []
                for rid in op.requires:
                    if rid in removed:
                        inherited = current[rid].requires if rid in current else []
                        for inherited_id in inherited:
                            if inherited_id not in new_requires:
                                new_requires.append(inherited_id)
                        changed = True
                    elif rid not in new_requires:
                        new_requires.append(rid)
                if changed:
                    current[oid] = replace(op, requires=new_requires)
            if not changed:
                break

        self._ops = {oid: op for oid, op in current.items() if oid not in removed}
        # Re-check structure: rewiring must not have introduced a broken edge.
        self._check_dependencies()
        return sorted(removed)
