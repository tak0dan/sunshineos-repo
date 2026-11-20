"""Transformation planner for the Sunshine Evolution Engine.

Public entry point::

    from src.planner import plan
    plan = plan(observed, target, decisions=decisions)

The same entry point plans a pure Arch installation and an older Sunshine OS;
the decision is derived solely from observed state versus the target spec.
"""
from __future__ import annotations

from .graph import DependencyGraph
from .operations import (
    create_checkpoint,
    create_configuration,
    disable_service,
    enable_service,
    generate_initramfs,
    install_boot_entry,
    install_kernel,
    install_packages,
    migrate_configuration,
    register_component,
    remove_packages,
    transfer_ownership,
    validate_capability,
)
from .planner import build_plan, capability_deltas, plan
from .strategies import (
    ComponentContext,
    STRATEGIES,
    build_context,
    plan_component,
)

__all__ = [
    "plan",
    "build_plan",
    "capability_deltas",
    "DependencyGraph",
    "ComponentContext",
    "build_context",
    "plan_component",
    "STRATEGIES",
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
