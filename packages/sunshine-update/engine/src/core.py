"""Shared typed models for the Sunshine Evolution Engine.

These models are the contracts between discovery, target resolution, planning,
execution and validation. Keep them dependency-free (stdlib only) so the engine
can run before Python-heavy Sunshine components are installed.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Status(str, Enum):
    ABSENT = "absent"
    INSTALLED = "installed"
    CONFIGURED = "configured"
    ENABLED = "enabled"
    RUNNING = "running"
    FUNCTIONAL = "functional"


class Lifecycle(str, Enum):
    INTRODUCE = "introduce"
    EVOLVE = "evolve"
    REPLACE = "replace"
    RECONFIGURE = "reconfigure"
    RETIRE = "retire"


class OpType(str, Enum):
    INSTALL_PACKAGES = "InstallPackages"
    REMOVE_PACKAGES = "RemovePackages"
    TRANSFER_OWNERSHIP = "TransferOwnership"
    CREATE_CONFIGURATION = "CreateConfiguration"
    MIGRATE_CONFIGURATION = "MigrateConfiguration"
    REGISTER_COMPONENT = "RegisterComponent"
    ENABLE_SERVICE = "EnableService"
    DISABLE_SERVICE = "DisableService"
    INSTALL_KERNEL = "InstallKernel"
    GENERATE_INITRAMFS = "GenerateInitramfs"
    INSTALL_BOOT_ENTRY = "InstallBootEntry"
    CREATE_CHECKPOINT = "CreateCheckpoint"
    VALIDATE_CAPABILITY = "ValidateCapability"


@dataclass
class Observation:
    component: str
    detected: str
    confidence: Confidence = Confidence.LOW
    status: Status = Status.INSTALLED
    evidence: list[str] = field(default_factory=list)

    def allow_destructive(self) -> bool:
        """Low-confidence observations must never authorize destructive operations."""
        return self.confidence in (Confidence.HIGH, Confidence.MEDIUM)


@dataclass
class ObservedState:
    distribution: str = "unknown"
    architecture: str = "unknown"
    init_system: str = "unknown"
    package_manager: str = "unknown"
    observations: dict[str, Observation] = field(default_factory=dict)
    packages: dict[str, str] = field(default_factory=dict)  # name -> version
    foreign_packages: list[str] = field(default_factory=list)
    repositories: list[str] = field(default_factory=list)
    capabilities: set[str] = field(default_factory=set)
    # Non-secret user inventory from Stage B discovery.  Password hashes and
    # shadow data are intentionally never copied into plans or logs.
    users: list[dict[str, Any]] = field(default_factory=list)
    groups: dict[str, list[str]] = field(default_factory=dict)
    home_directories: list[dict[str, Any]] = field(default_factory=list)
    # Repository generation already committed on this machine (0 = unknown).
    # Used to reject rollback to an older published repository state.
    repository_generation: int = 0

    def observe(self, o: Observation) -> None:
        self.observations[o.component] = o
        if o.status in (Status.RUNNING, Status.FUNCTIONAL, Status.ENABLED):
            self.capabilities.add(o.detected)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["capabilities"] = sorted(self.capabilities)
        return d


@dataclass
class ComponentSpec:
    id: str
    schema: int = 0
    required: bool = True
    software_version: str = ""
    lifecycle: Lifecycle = Lifecycle.EVOLVE
    provides: list[str] = field(default_factory=list)
    requires: list[str] = field(default_factory=list)


@dataclass
class TargetSpec:
    format_version: int = 1
    release: str = ""
    repository_generation: int = 0
    components: dict[str, ComponentSpec] = field(default_factory=dict)
    policies: dict[str, bool] = field(default_factory=dict)
    package_sets: dict[str, list[str]] = field(default_factory=dict)

    def required_components(self) -> list[ComponentSpec]:
        return [c for c in self.components.values() if c.required]


@dataclass
class Operation:
    id: str
    type: OpType
    component: str = ""
    params: dict[str, Any] = field(default_factory=dict)
    requires: list[str] = field(default_factory=list)
    reversible: bool = True
    destructive: bool = False
    needs_reboot: bool = False

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["type"] = self.type.value
        return d


@dataclass
class Plan:
    id: str
    source: dict[str, Any]
    target: dict[str, Any]
    operations: list[Operation] = field(default_factory=list)
    decisions: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "format_version": 1,
            "plan_id": self.id,
            "source": self.source,
            "target": self.target,
            "operations": [o.to_dict() for o in self.operations],
            "decisions": self.decisions,
        }


@dataclass
class JournalEntry:
    id: str
    operation: str
    status: str  # pending | running | completed | failed
    component: str = ""
    source_schema: int = 0
    target_schema: int = 0
    started_at: str = ""
    completed_at: str = ""
    validation_passed: bool = False
    recovery: str = "not-required"
    output: str = ""


def observation(component: str, detected: str, confidence: str, status: str, evidence: list[str]) -> Observation:
    return Observation(component, detected, Confidence(confidence), Status(status), evidence)


def state_fingerprint(state: ObservedState) -> str:
    """Stable digest of an observed machine, used for stale-plan detection."""
    payload = json.dumps(
        state.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
