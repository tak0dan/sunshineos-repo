"""Per-component transformation strategies.

A strategy answers one question: given what is actually observed and the
desired :class:`~src.core.ComponentSpec`, which operations bring the component
to the target state?

There is no "source version" switch here.  Every strategy first asks whether
the component is registered/present and whether its observed schema is behind
the target.  An absent component is *introduced* (registration + bootstrap
operations); a present but older component is only *evolved* (migrations,
upgrades, reconfiguration).  The same code therefore handles a pure Arch
machine and an older Sunshine OS installation.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, replace
from typing import Callable, Iterable, Optional

from ..core import (
    ComponentSpec,
    Lifecycle,
    ObservedState,
    OpType,
    Operation,
    Status,
    TargetSpec,
)
from . import operations as ops

__all__ = [
    "ComponentContext",
    "build_context",
    "plan_component",
    "STRATEGIES",
    "plan_core",
    "plan_configuration",
    "plan_ownership",
    "plan_kernel_management",
    "plan_boot_integration",
    "plan_recovery",
    "plan_desktop_integration",
    "plan_nix_integration",
]


# Capabilities that a plain Arch installation already provides.  Their presence
# must not be mistaken for "Sunshine component is registered".
GENERIC_ARCH_CAPABILITIES = frozenset({
    "systemd",
    "pacman",
    "linux",
    "base",
    "coreutils",
    "bash",
    "network",
    "network-connection",
    "audio-pipewire",
    "desktop-session-discovery",
    "kernel-installation",
})

# Used only when the target does not declare a package set for a component.
DEFAULT_PACKAGES: dict[str, list[str]] = {
    "core": ["base", "systemd", "pacman"],
    "configuration": ["sunshine-base"],
    "ownership": ["sunshine-base"],
    "kernel_management": ["linux", "mkinitcpio"],
    "boot_integration": ["efibootmgr", "grub"],
    "recovery": ["sunshine-recovery"],
    "desktop_integration": ["sunshine-desktop"],
    "nix_integration": ["nix"],
}

_SCHEMA_RE = re.compile(r"schema\s*[=:]?\s*(\d+)", re.IGNORECASE)


# --------------------------------------------------------------------------- #
# Context
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class ComponentContext:
    """Everything a strategy needs to decide, already reduced from raw facts."""

    observed: ObservedState
    spec: ComponentSpec
    target: TargetSpec
    deps: tuple[str, ...]
    present: bool
    schema: int
    packages: tuple[str, ...]
    missing_packages: tuple[str, ...]
    missing_capabilities: tuple[str, ...]
    introduce: bool
    outdated: bool
    reason: str

    @property
    def lifecycle(self) -> Lifecycle:
        return Lifecycle.INTRODUCE if self.introduce else Lifecycle.EVOLVE

    @property
    def needs_work(self) -> bool:
        return (
            self.introduce
            or self.outdated
            or bool(self.missing_packages)
            or bool(self.missing_capabilities)
        )


def _registration_markers(component_id: str) -> set[str]:
    return {
        f"sunshine-component:{component_id}",
        f"sunshine-{component_id}",
    }


def _sunshine_capabilities(spec: ComponentSpec) -> set[str]:
    return {
        cap for cap in spec.provides
        if cap and cap not in GENERIC_ARCH_CAPABILITIES
    }


def _matching_observations(observed: ObservedState, spec: ComponentSpec) -> list:
    markers = _registration_markers(spec.id)
    sunshine_caps = _sunshine_capabilities(spec)
    matches = []
    for observation in observed.observations.values():
        if observation.component == spec.id:
            matches.append(observation)
        elif observation.detected in markers or observation.detected in sunshine_caps:
            matches.append(observation)
    return matches


def _detect_presence(observed: ObservedState, spec: ComponentSpec) -> bool:
    """Whether a *Sunshine* component is registered on the machine.

    A capability being observable is NOT proof that the Sunshine component
    providing it is installed.  A clean Arch machine already has
    ``boot-entry-management`` (via GRUB) and ``kernel-installation`` (via
    mkinitcpio), and PipeWire provides ``audio-pipewire``.  Treating those
    generic capabilities as registration markers made the planner skip the
    introduction of boot, desktop and recovery components on pure Arch.

    Presence therefore requires an explicit Sunshine marker from discovery
    (written when a component registry entry is found), a matching observation
    detected as such a marker, or evidence that names a Sunshine registration.
    """
    markers = _registration_markers(spec.id)
    if markers & observed.capabilities:
        return True
    for observation in _matching_observations(observed, spec):
        if observation.status is Status.ABSENT:
            continue
        if observation.detected in markers:
            return True
        evidence = " ".join(observation.evidence).lower()
        if any(
            token in evidence
            for token in ("sunshine-component", "registered", "schema=", "component registry")
        ):
            return True
    return False


def _detect_schema(observed: ObservedState, spec: ComponentSpec, present: bool) -> int:
    values: list[int] = []
    for observation in _matching_observations(observed, spec):
        for text in [observation.detected, *observation.evidence]:
            match = _SCHEMA_RE.search(str(text))
            if match:
                values.append(int(match.group(1)))
    if values:
        return max(values)
    # A registered component with no explicit version is assumed current; this
    # makes planning idempotent for discoveries that do not report a schema.
    return spec.schema if present else 0


def build_context(
    observed: ObservedState,
    spec: ComponentSpec,
    target: TargetSpec,
    deps: Iterable[str] = (),
) -> ComponentContext:
    """Reduce observed state + target spec into a strategy decision."""
    if not isinstance(observed, ObservedState) or not isinstance(spec, ComponentSpec):
        raise ValueError("build_context expects ObservedState and ComponentSpec")

    packages = list(target.package_sets.get(spec.id, DEFAULT_PACKAGES.get(spec.id, [])))
    missing_packages = tuple(p for p in packages if p not in observed.packages)
    missing_capabilities = tuple(c for c in spec.provides if c not in observed.capabilities)

    present = _detect_presence(observed, spec)
    schema = _detect_schema(observed, spec, present)
    introduce = not present
    outdated = present and schema < spec.schema

    if introduce:
        reason = f"component '{spec.id}' is not registered on the observed machine"
    elif outdated:
        reason = f"component '{spec.id}' schema {schema} is behind target {spec.schema}"
    elif missing_packages:
        reason = f"component '{spec.id}' is missing packages: {', '.join(missing_packages)}"
    elif missing_capabilities:
        reason = (
            f"component '{spec.id}' is missing capabilities: "
            + ", ".join(missing_capabilities)
        )
    else:
        reason = f"component '{spec.id}' already satisfies the target"

    return ComponentContext(
        observed=observed,
        spec=spec,
        target=target,
        deps=tuple(dict.fromkeys(deps)),
        present=present,
        schema=schema,
        packages=tuple(packages),
        missing_packages=missing_packages,
        missing_capabilities=missing_capabilities,
        introduce=introduce,
        outdated=outdated,
        reason=reason,
    )


# --------------------------------------------------------------------------- #
# Chain / annotation helpers
# --------------------------------------------------------------------------- #

def _finish(operations: list[Operation], ctx: ComponentContext) -> list[Operation]:
    """Attach prerequisites and planning metadata to a strategy's operations."""
    if not operations:
        return []
    chain: list[Operation] = []
    previous: list[str] = list(ctx.deps)
    for operation in operations:
        if previous:
            operation = replace(operation, requires=list(previous))
        annotated = dict(operation.params)
        annotated["planning_reason"] = ctx.reason
        annotated["source_schema"] = ctx.schema
        annotated["target_schema"] = ctx.spec.schema
        chain.append(replace(operation, params=annotated))
        previous = [chain[-1].id]
    return chain


def _install(ctx: ComponentContext, lifecycle: Optional[Lifecycle] = None) -> Optional[Operation]:
    if not ctx.missing_packages:
        return None
    return ops.install_packages(
        list(ctx.missing_packages),
        component=ctx.spec.id,
        lifecycle=lifecycle or ctx.lifecycle,
    )


def _migrate(ctx: ComponentContext) -> Optional[Operation]:
    if not ctx.outdated:
        return None
    return ops.migrate_configuration(
        f"etc/sunshine/components/{ctx.spec.id}.toml",
        ctx.schema,
        ctx.spec.schema,
        source_path=f"etc/sunshine/legacy/{ctx.spec.id}.toml",
        component=ctx.spec.id,
        lifecycle=Lifecycle.EVOLVE,
    )


def _register(ctx: ComponentContext) -> Optional[Operation]:
    if not ctx.introduce:
        return None
    return ops.register_component(
        ctx.spec.id,
        schema=ctx.spec.schema,
        provides=list(ctx.spec.provides),
        component=ctx.spec.id,
        lifecycle=Lifecycle.INTRODUCE,
    )


def _kernel_version(ctx: ComponentContext) -> str:
    return ctx.spec.software_version or "current"


# --------------------------------------------------------------------------- #
# Strategies
# --------------------------------------------------------------------------- #

def plan_core(ctx: ComponentContext) -> list[Operation]:
    emitted = [op for op in (
        _install(ctx),
        _migrate(ctx),
        _register(ctx),
    ) if op is not None]
    return _finish(emitted, ctx)


def plan_configuration(ctx: ComponentContext) -> list[Operation]:
    emitted: list[Operation] = []
    install = _install(ctx)
    if install is not None:
        emitted.append(install)

    needs_config = ctx.introduce or "configuration-ownership" in ctx.missing_capabilities
    if needs_config and not ctx.outdated:
        emitted.append(ops.create_configuration(
            f"etc/sunshine/components/{ctx.spec.id}.toml",
            capabilities=list(ctx.spec.provides) or ["configuration-ownership"],
            component=ctx.spec.id,
            lifecycle=ctx.lifecycle,
        ))

    migrate = _migrate(ctx)
    if migrate is not None:
        emitted.append(migrate)

    register = _register(ctx)
    if register is not None:
        emitted.append(register)
    return _finish(emitted, ctx)


def _has_sunshine_tree(observed: ObservedState) -> bool:
    """Whether a Sunshine-owned tree already exists whose owner can be changed.

    A pure Arch machine has no ``/etc/sunshine`` or ``/var/lib/sunshine`` to
    hand over; ownership transfer there is meaningless and, being destructive,
    is correctly refused by the executor's confidence gate.  Emitting the
    operation only when a tree actually exists keeps plans executable on both
    source paths with one implementation.
    """
    occupied = {Status.CONFIGURED, Status.ENABLED, Status.RUNNING, Status.FUNCTIONAL}
    for key in ("sunshine.config", "sunshine.state", "sunshine.component-schemas"):
        obs = observed.observations.get(key)
        if obs is not None and obs.status in occupied:
            return True
    return False


def plan_ownership(ctx: ComponentContext) -> list[Operation]:
    emitted: list[Operation] = []
    install = _install(ctx)
    if install is not None:
        emitted.append(install)

    needs_transfer = (
        ctx.introduce
        or "package-ownership-registry" in ctx.missing_capabilities
        or "configuration-ownership" in ctx.missing_capabilities
    )
    if needs_transfer and not ctx.outdated:
        # Setting the owner of directories we are about to create is safe on a
        # fresh install.  Only an actual existing tree makes chown destructive
        # and subject to the confidence gate.
        emitted.append(ops.transfer_ownership(
            ["etc/sunshine", "var/lib/sunshine", "var/lib/sunshine/ownership"],
            "root",
            "sunshine",
            component=ctx.spec.id,
            lifecycle=ctx.lifecycle,
            destructive=_has_sunshine_tree(ctx.observed),
        ))

    migrate = _migrate(ctx)
    if migrate is not None:
        emitted.append(migrate)

    register = _register(ctx)
    if register is not None:
        emitted.append(register)
    return _finish(emitted, ctx)


def plan_kernel_management(ctx: ComponentContext) -> list[Operation]:
    emitted: list[Operation] = []
    install = _install(ctx)
    if install is not None:
        emitted.append(install)

    version = _kernel_version(ctx)
    needs_kernel = (
        ctx.introduce
        or ctx.outdated
        or "kernel-installation" in ctx.missing_capabilities
        or "kernel-fallback" in ctx.missing_capabilities
    )
    if needs_kernel:
        # The mkinitcpio preset is the kernel package name (e.g. ``linux``),
        # not the Sunshine release version. On a real Arch system only
        # /etc/mkinitcpio.d/linux.preset exists, so using the release version
        # here fails with "Failed to load preset: /etc/mkinitcpio.d/2026.1.preset".
        preset = ctx.packages[0] if ctx.packages else "linux"
        emitted.append(ops.install_kernel(
            version,
            package=preset,
            component=ctx.spec.id,
            lifecycle=ctx.lifecycle,
        ))
        emitted.append(ops.generate_initramfs(
            version,
            preset=preset,
            fallback=True,
            component=ctx.spec.id,
            lifecycle=ctx.lifecycle,
        ))

    migrate = _migrate(ctx)
    if migrate is not None:
        emitted.append(migrate)

    register = _register(ctx)
    if register is not None:
        emitted.append(register)
    return _finish(emitted, ctx)


def plan_boot_integration(ctx: ComponentContext) -> list[Operation]:
    emitted: list[Operation] = []
    install = _install(ctx)
    if install is not None:
        emitted.append(install)

    needs_entry = (
        ctx.introduce
        or ctx.outdated
        or "boot-entry-management" in ctx.missing_capabilities
    )
    if needs_entry:
        # The loader is an EFI path, not the component's software version.
        # Using ``software_version`` here produced e.g. ``loader="2026.1"``,
        # which the executor correctly refused as an invalid absolute path.
        emitted.append(ops.install_boot_entry(
            "/boot/EFI/Linux/sunshine.efi",
            label="Sunshine OS",
            component=ctx.spec.id,
            lifecycle=ctx.lifecycle,
        ))

    migrate = _migrate(ctx)
    if migrate is not None:
        emitted.append(migrate)

    register = _register(ctx)
    if register is not None:
        emitted.append(register)
    return _finish(emitted, ctx)


def plan_recovery(ctx: ComponentContext) -> list[Operation]:
    emitted: list[Operation] = []
    install = _install(ctx)
    if install is not None:
        emitted.append(install)

    needs_baseline = (
        ctx.introduce
        or "recovery-checkpoints" in ctx.missing_capabilities
        or "migration-recovery" in ctx.missing_capabilities
    )
    if needs_baseline and not ctx.outdated:
        reason = ctx.reason
        if "luks" in ctx.observed.capabilities:
            # A boot-kernel change on an encrypted root must be recoverable even
            # if the header or crypttab is damaged. State the requirement in the
            # checkpoint intent; the recovery provider implements the backup.
            extra = "back up LUKS headers and /etc/crypttab before boot changes"
            reason = f"{reason}; {extra}" if reason else extra
        emitted.append(ops.create_checkpoint(
            f"baseline-{ctx.spec.id}",
            component=ctx.spec.id,
            lifecycle=ctx.lifecycle,
            reason=reason,
        ))

    migrate = _migrate(ctx)
    if migrate is not None:
        emitted.append(migrate)

    register = _register(ctx)
    if register is not None:
        emitted.append(register)
    return _finish(emitted, ctx)


def plan_desktop_integration(ctx: ComponentContext) -> list[Operation]:
    emitted: list[Operation] = []
    install = _install(ctx)
    if install is not None:
        emitted.append(install)

    needs_profiles = (
        ctx.introduce
        or "sunshine-profile-management" in ctx.missing_capabilities
        or "desktop-session-discovery" in ctx.missing_capabilities
    )
    if needs_profiles and not ctx.outdated:
        # Profile management is delivered by the declarative profile tree.
        # The published sunshine-base package provides sunshine-apps.service
        # to finish the chosen app/profile setup; there is no
        # sunshine-profiles.service, and enabling a unit no package provides
        # fails on a real system.
        selected = [p.split(":", 1)[1] for p in ctx.spec.provides
                    if p.startswith("desktop-profile:")]
        profile_content = json.dumps(
            {"component": ctx.spec.id, "managed": True, "profiles": selected},
            sort_keys=True, indent=2,
        ) + "\n"
        emitted.append(ops.create_configuration(
            "etc/sunshine/profiles/default.toml",
            content=profile_content,
            capabilities=["sunshine-profile-management"],
            component=ctx.spec.id,
            lifecycle=ctx.lifecycle,
        ))
        emitted.append(ops.enable_service(
            "sunshine-apps",
            component=ctx.spec.id,
            lifecycle=ctx.lifecycle,
        ))

    migrate = _migrate(ctx)
    if migrate is not None:
        emitted.append(migrate)

    register = _register(ctx)
    if register is not None:
        emitted.append(register)
    return _finish(emitted, ctx)


def plan_nix_integration(ctx: ComponentContext) -> list[Operation]:
    emitted: list[Operation] = []
    install = _install(ctx)
    if install is not None:
        emitted.append(install)

    needs_nix = ctx.introduce or "nix-daemon" in ctx.missing_capabilities
    if needs_nix and not ctx.outdated:
        emitted.append(ops.create_configuration(
            "etc/nix/nix.conf",
            capabilities=["nix-integration"],
            component=ctx.spec.id,
            lifecycle=ctx.lifecycle,
        ))
        emitted.append(ops.enable_service(
            "nix-daemon",
            component=ctx.spec.id,
            lifecycle=ctx.lifecycle,
        ))

    migrate = _migrate(ctx)
    if migrate is not None:
        emitted.append(migrate)

    register = _register(ctx)
    if register is not None:
        emitted.append(register)
    return _finish(emitted, ctx)


def _plan_generic(ctx: ComponentContext) -> list[Operation]:
    emitted = [op for op in (
        _install(ctx),
        _migrate(ctx),
        _register(ctx),
    ) if op is not None]
    return _finish(emitted, ctx)


STRATEGIES: dict[str, Callable[[ComponentContext], list[Operation]]] = {
    "core": plan_core,
    "configuration": plan_configuration,
    "ownership": plan_ownership,
    "kernel_management": plan_kernel_management,
    "boot_integration": plan_boot_integration,
    "recovery": plan_recovery,
    "desktop_integration": plan_desktop_integration,
    "nix_integration": plan_nix_integration,
}


def plan_component(
    observed: ObservedState,
    spec: ComponentSpec,
    target: TargetSpec,
    deps: Iterable[str] = (),
) -> list[Operation]:
    """Dispatch to the strategy for ``spec.id`` (generic fallback for extras)."""
    ctx = build_context(observed, spec, target, deps)
    if not ctx.needs_work:
        return []
    strategy = STRATEGIES.get(spec.id, _plan_generic)
    return strategy(ctx)
