"""Target-state subsystem of the Sunshine Evolution Engine.

Sunshine is a *desired state*, not an installation history. This package owns
the description of that state and the first reconciliation step:

    published manifest --load_target()--> TargetSpec (generic desired state)
    TargetSpec + ObservedState --resolve_target()--> specialised TargetSpec
                                                     + decisions

The resolver only settles questions that the observations can answer safely:
one detected desktop with high/medium confidence is selected, a configured
default wins when several desktops are present, and existing compatible
bootloader/network/audio/Nix choices are preserved. Anything genuinely
ambiguous becomes one explicit decision requiring user input, never a batch of
questions. All returned data is declarative; the planner decides operations.
"""
from .manifest import load_target
from .resolver import resolve_target
from .compatibility import classify_source, preflight_source, CompatibilityReport

__all__ = [
    "load_target",
    "resolve_target",
    "classify_source",
    "preflight_source",
    "CompatibilityReport",
]
