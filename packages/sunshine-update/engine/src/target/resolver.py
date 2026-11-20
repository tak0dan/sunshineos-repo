"""Desired-state resolution: turn observations into a concrete target.

``resolve_target()`` takes the published target (which describes *what* a
Sunshine system must be) and the observed machine (which describes *what is
there*) and returns a customised target plus a list of decisions. It never
mutates its inputs.

The guiding rule is to decide automatically whenever the observation is strong
enough, and to ask at most one focused question when it is not:

* exactly one supported desktop seen with high/medium confidence -> select it;
* several desktops seen, one marked as the configured default -> keep it;
* several desktops with no clear default -> one user decision with the candidates;
* existing bootloader / network / audio choices that the target supports are
  preserved verbatim by activating their corresponding package set;
* Nix integration is activated only when Nix is actually present.

The resulting ``TargetSpec`` is still declarative: profile packages and
preserved choices are expressed as package sets and capability contracts, so
the planner remains the only component that decides *how* to converge.
"""
from __future__ import annotations

import re
from copy import deepcopy
from pathlib import Path
from typing import Any, Iterable, Mapping

from ..core import Confidence, ObservedState, Status, TargetSpec
from .profiles import (
    DesktopDetection,
    DesktopProfile,
    choose_profile,
    detect_desktop_sessions,
    load_profiles,
)

_PRESERVED_CATEGORIES = ("bootloader", "network", "audio")
_GENERIC_VALUES = {
    "configured",
    "installed",
    "enabled",
    "running",
    "functional",
    "present",
    "detected",
    "yes",
    "true",
    "unknown",
    # Observation key suffixes that describe the *kind* of finding, not a
    # user choice (e.g. audio.backend=pipewire, audio.coexistence=...).
    "backend",
    "coexistence",
    "implementation",
    "mode",
    "profile",
    "selection",
    "service",
    # Compatibility layers are not competing backends.
    "pipewire-pulse-compatibility",
    "compatibility",
}
_NEGATIVE_VALUES = {"absent", "none", "false", "disabled", "no", "not-installed", "not installed"}


def _decision(
    decision_id: str,
    kind: str,
    *,
    selected: str | None = None,
    options: Iterable[str] = (),
    auto: bool = True,
    action: str = "select",
    reason: str = "",
    evidence: Iterable[str] = (),
    question: str = "",
    confidence: str = "",
    conflicts: Iterable[str] = (),
) -> dict[str, Any]:
    """Build a uniform decision record consumable by planners and the CLI.

    ``auto`` decisions are informational facts the resolver settled itself;
    ``requires_user_input`` is the single flag callers should check before
    prompting. All records carry the same keys so consumers never need to guess
    which fields exist.
    """
    return {
        "id": decision_id,
        "kind": kind,
        "action": action,
        "auto": bool(auto),
        "requires_user_input": not auto,
        "selected": selected,
        "options": list(options),
        "question": question,
        "reason": reason,
        "evidence": list(evidence),
        "confidence": confidence,
        "conflicts": list(conflicts),
    }


def _dedupe(items: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(items))


def resolve_target(
    observed: ObservedState,
    target: TargetSpec,
    profiles_dir: str | Path | None = None,
    answers: Mapping[str, str] | None = None,
) -> tuple[TargetSpec, list[dict[str, Any]]]:
    """Resolve the published target against a simulated or real observed state.

    Returns a deep copy of ``target`` specialised for this machine and the
    decisions that led there. A copy guarantees that repeated resolution with
    different observations cannot leak one machine's profile into another's.

    ``answers`` maps decision ids (e.g. ``desktop-profile``) to operator
    selections. They are consumed *during* resolution so a manually selected
    profile contributes its packages and capabilities to the same declarative
    target that automatic detection produces. Annotating decisions afterwards
    would leave the plan unable to converge on the chosen state.
    """
    resolved = deepcopy(target)
    decisions: list[dict[str, Any]] = []
    profiles = load_profiles(profiles_dir)
    detections = detect_desktop_sessions(observed, profiles)
    operator = answers or {}

    _resolve_desktop(observed, resolved, profiles, detections, decisions, operator)
    for category in _PRESERVED_CATEGORIES:
        _preserve_choice(observed, resolved, category, decisions, operator)
    _resolve_nix(observed, resolved, decisions)
    _resolve_storage_providers(observed, resolved, decisions)
    return resolved, decisions


def _operator_answer(answers: Mapping[str, str], decision_id: str) -> str | None:
    value = str(answers.get(decision_id, "")).strip()
    return value or None


def _resolve_storage_providers(
    observed: ObservedState,
    target: TargetSpec,
    decisions: list[dict[str, Any]],
) -> None:
    """Select recovery/boot tooling from *observed* capabilities.

    The published target lists conservative defaults (``rsync``, ``btrfs-progs``,
    ``os-prober``). Installing btrfs snapshot tools on an ext4/LUKS root, or GRUB
    probing tools on a systemd-boot system, is harmless but wrong: it changes an
    upstream Arch installation without a capability that needs it. Conversely,
    a LUKS root needs ``cryptsetup`` present before any boot work so headers and
    ``crypttab`` can be backed up. This is capability-based provider selection,
    not a second package manager and not a source-specific branch.
    """
    evidence: list[str] = []
    recovery = list(target.package_sets.get("recovery", []))
    recovery_changed = False
    if "btrfs" not in observed.capabilities and "btrfs-progs" in recovery:
        recovery.remove("btrfs-progs")
        recovery_changed = True
        evidence.append("btrfs capability absent: btrfs-progs not required for checkpoints")
    if "luks" in observed.capabilities and "cryptsetup" not in recovery:
        recovery.append("cryptsetup")
        recovery_changed = True
        evidence.append("luks capability present: cryptsetup required for header backup")
    if recovery_changed:
        target.package_sets["recovery"] = _dedupe(recovery)

    bootloader = next(
        (d["selected"] for d in decisions if d["id"] == "bootloader-choice"), None
    )
    boot = list(target.package_sets.get("boot_integration", []))
    boot_changed = False
    if bootloader == "systemd-boot" and "os-prober" in boot:
        boot.remove("os-prober")
        boot_changed = True
        evidence.append("systemd-boot selected: os-prober is a GRUB-only tool")
    if boot_changed:
        target.package_sets["boot_integration"] = _dedupe(boot)

    if evidence:
        decisions.append(_decision(
            "storage-providers",
            "storage",
            selected="capability-based",
            options=["capability-based"],
            reason="Recovery and boot tooling follows observed storage/boot capabilities.",
            evidence=evidence,
        ))


def _resolve_desktop(
    observed: ObservedState,
    target: TargetSpec,
    profiles: Mapping[str, DesktopProfile],
    detections: Mapping[str, DesktopDetection],
    decisions: list[dict[str, Any]],
    answers: Mapping[str, str] | None = None,
) -> None:
    """Select a desktop profile, automatically where the evidence allows it."""
    operator = _operator_answer(answers or {}, "desktop-profile")
    chosen, options, needs_input = choose_profile(detections, profiles.keys())

    if operator is not None:
        # An explicit operator choice always wins over ambiguous evidence and
        # is validated against the declared profiles before it reaches the
        # target. Invalid values fail closed rather than silently changing the
        # desktop, and the same validation is repeated by the CLI layer.
        if operator not in profiles:
            choices = ", ".join(sorted(profiles))
            raise ValueError(
                f"invalid value '{operator}' for desktop-profile; expected one of {choices}"
            )
        chosen, needs_input = operator, False
    elif needs_input:
        details = ", ".join(options) if options else "none of the supported profiles"
        decisions.append(
            _decision(
                "desktop-profile",
                "desktop_profile",
                options=options,
                auto=False,
                question="Which desktop profile should Sunshine manage?",
                reason=f"Desktop intent is ambiguous or undetected ({details}).",
                evidence=[
                    f"{pid}: {det.confidence.value}" for pid, det in sorted(detections.items())
                ],
            )
        )
        return

    assert chosen is not None  # choose_profile guarantees this when needs_input is False
    profile = profiles[chosen]
    component = target.components.get("desktop_integration")

    target.package_sets["desktop_integration"] = _dedupe(
        list(target.package_sets.get("desktop_integration", [])) + list(profile.packages)
    )
    if component is not None:
        # A profile's required_capabilities describe what the *component*
        # provides once the profile is active.  Treating them as prerequisites
        # made desktop_integration depend on itself whenever a desktop was
        # unambiguously detected (a break found in fixture CLI mode).
        own_capabilities = set(component.provides) | {component.id}
        extra_requirements = [
            capability for capability in profile.required_capabilities
            if capability not in own_capabilities
        ]
        component.requires = _dedupe(
            list(component.requires) + extra_requirements
        )
        component.provides = _dedupe(
            list(component.provides) + [f"desktop-profile:{profile.id}"]
        )

    detection = detections.get(chosen)
    evidence = list(detection.evidence) if detection else []
    if operator is not None:
        reason = f"Operator selected desktop profile '{chosen}'."
    elif detection is not None and detection.is_default:
        reason = f"'{chosen}' is the configured default desktop; preserving it."
    elif detection is not None:
        reason = f"Exactly one supported desktop ('{chosen}') was detected with sufficient confidence."
    else:
        reason = f"Selected desktop profile '{chosen}'."

    decisions.append(
        _decision(
            "desktop-profile",
            "desktop_profile",
            selected=chosen,
            options=[chosen],
            action="preserve",
            reason=reason,
            evidence=evidence,
            confidence=detection.confidence.value if detection else "",
            conflicts=profile.conflicts,
        )
    )


def _supported_choices(target: TargetSpec, category: str) -> dict[str, list[str]]:
    """Derive the supported choices from ``<category>.<choice>`` package sets."""
    prefix = category + "."
    return {
        name[len(prefix) :]: list(packages)
        for name, packages in target.package_sets.items()
        if name.startswith(prefix) and isinstance(packages, list)
    }


def _choice_from_text(value: str, choices: Iterable[str]) -> str | None:
    """Match a free-form observed value against known choice identifiers."""
    text = re.sub(r"[^a-z0-9]+", "-", str(value).lower()).strip("-")
    known = set(choices)
    if text in known:
        return text
    for token in text.split("-"):
        if token in known:
            return token
    compact = text.replace("-", "")
    for choice in known:
        if choice.replace("-", "") in compact:
            return choice
    return None


def _signal_strength(observation) -> int:
    """Rank how actively an observation describes an installed choice.

    An installed-but-unused package is not a competing backend. Active units,
    firmware entries and written configuration are much stronger evidence than
    mere package presence; the resolver must not ask the user to arbitrate
    between a running service and an unused alternative.
    """
    strength = {
        Status.RUNNING: 3,
        Status.CONFIGURED: 3,
        Status.INSTALLED: 1,
        Status.ABSENT: 0,
    }.get(observation.status, 0)
    evidence = " ".join(str(e).lower() for e in observation.evidence)
    if any(marker in evidence for marker in (
        "enabled units", "active units", "efi boot entry", "config:",
        "configured default", "display-manager.service",
    )):
        strength += 1
    return strength


def _observed_choices(
    observed: ObservedState, category: str
) -> list[tuple[str, list[str], Confidence, int]]:
    """Find every distinct raw choice for ``category`` from observations.

    A machine can legitimately report contradictory signals (for example GRUB
    and systemd-boot entries). Returning only the first one silently guessed
    intent; collecting all of them lets :func:`_preserve_choice` ask one focused
    question when the signals are equally strong. Installed-only alternatives
    are deliberately weaker than running/configured backends.
    """
    needle = category.lower()
    pattern = re.compile(rf"(?:^|[-_:./ ]){re.escape(needle)}[-_:./ ]?")
    collected: dict[str, tuple[str, list[str], Confidence, int]] = {}
    rank = {Confidence.LOW: 0, Confidence.MEDIUM: 1, Confidence.HIGH: 2}

    def add(token: str, evidence: list[str], confidence: Confidence, strength: int) -> None:
        token = token.strip()
        if not token or token.lower() in _GENERIC_VALUES:
            return
        key = token.lower()
        previous = collected.get(key)
        if previous is None:
            collected[key] = (token, list(dict.fromkeys(evidence)), confidence, strength)
            return
        merged_confidence = (
            previous[2] if rank[previous[2]] >= rank[confidence] else confidence
        )
        collected[key] = (
            previous[0],
            list(dict.fromkeys(previous[1] + evidence)),
            merged_confidence,
            max(previous[3], strength),
        )

    for key, observation in observed.observations.items():
        if observation.status == Status.ABSENT:
            continue
        # The category must be part of the observation's identity (key or
        # component), not merely mentioned in free-form evidence.  Otherwise a
        # generic observation such as ``services.systemd`` whose evidence
        # mentions "network" would be misread as the network backend choice.
        identity = f"{key} {observation.component}".lower()
        if not re.search(rf"(?:^|[-_:./ ]){re.escape(needle)}(?:[-_:./ ]|$)", identity):
            continue
        candidates: list[str] = []
        # Prefer the value encoded in the key suffix, e.g.
        # ``network.networkmanager`` -> ``networkmanager``.
        for source in (key, observation.component):
            split = pattern.split(str(source).lower(), maxsplit=1)
            if len(split) == 2 and split[1].strip():
                candidates.append(split[1].strip())
        candidates.append(str(observation.detected))
        candidates.extend(str(e) for e in observation.evidence)
        for candidate in candidates:
            token = candidate.strip()
            if token and token.lower() not in _GENERIC_VALUES:
                add(token, [f"{key}: {observation.detected}"],
                    observation.confidence, _signal_strength(observation))
                break  # one signal per observation is enough

    for capability in sorted(observed.capabilities):
        split = re.split(rf"^{re.escape(needle)}[-_:]", str(capability).lower(), maxsplit=1)
        if len(split) == 2 and split[1].strip():
            add(split[1].strip(), [f"capability: {capability}"], Confidence.MEDIUM, 1)
    # Preserve observation order: the first discovered backend is the most
    # direct signal and remains the backward-compatible `_observed_choice`.
    return list(collected.values())


def _observed_choice(
    observed: ObservedState, category: str
) -> tuple[str, list[str], Confidence] | None:
    """Backward-compatible wrapper returning the first observed choice."""
    choices = _observed_choices(observed, category)
    if not choices:
        return None
    token, evidence, confidence, _strength = choices[0]
    return token, evidence, confidence


def _preserve_choice(
    observed: ObservedState,
    target: TargetSpec,
    category: str,
    decisions: list[dict[str, Any]],
    answers: Mapping[str, str] | None = None,
) -> None:
    """Keep an existing compatible choice, or ask one question if incompatible."""
    supported = _supported_choices(target, category)
    if not supported:
        return

    operator = _operator_answer(answers or {}, f"{category}-choice")
    if operator is not None:
        # Operator answers must produce the same declarative package-set change
        # as an automatically preserved choice, otherwise the planner cannot
        # converge on the selected backend. Validate against the published
        # choices so a typo cannot install an unknown package set.
        if operator not in supported:
            choices = ", ".join(sorted(supported))
            raise ValueError(
                f"invalid value '{operator}' for {category}-choice; expected one of {choices}"
            )
        target.package_sets[category] = _dedupe(list(supported[operator]))
        decisions.append(
            _decision(
                f"{category}-choice",
                category,
                selected=operator,
                options=[operator],
                action="select",
                reason=f"Operator selected the {category} choice '{operator}'.",
            )
        )
        return

    found = _observed_choices(observed, category)
    if not found:
        return

    # Only equally strong signals compete. A running GRUB entry and an unused
    # refind package are not a contradiction; they are different evidence tiers.
    strongest = max(item[3] for item in found)
    actionable = [item for item in found if item[3] == strongest]

    resolved_choices: list[str] = []
    all_evidence: list[str] = []
    best_confidence = Confidence.LOW
    unsupported: list[str] = []
    for raw, evidence, confidence, _strength in actionable:
        all_evidence.extend(evidence)
        if rank_confidence(confidence) > rank_confidence(best_confidence):
            best_confidence = confidence
        choice = _choice_from_text(raw, supported)
        if choice is None:
            unsupported.append(raw)
        else:
            resolved_choices.append(choice)
    distinct = sorted(set(resolved_choices))

    if unsupported or len(distinct) != 1:
        options = distinct or sorted(supported)
        reason = (
            f"Observed {category} '{', '.join(unsupported)}' is not supported by this target."
            if unsupported else
            f"Conflicting {category} choices were observed: {', '.join(distinct)}."
        )
        decisions.append(
            _decision(
                f"{category}-choice",
                category,
                options=options,
                auto=False,
                question=f"Which {category} should Sunshine use?",
                reason=reason,
                evidence=all_evidence,
                confidence=best_confidence.value,
            )
        )
        return

    choice = distinct[0]
    target.package_sets[category] = _dedupe(list(supported[choice]))
    decisions.append(
        _decision(
            f"{category}-choice",
            category,
            selected=choice,
            options=[choice],
            action="preserve",
            reason=f"Preserving the existing compatible {category} choice '{choice}'.",
            evidence=all_evidence,
            confidence=best_confidence.value,
        )
    )


def rank_confidence(confidence: Confidence) -> int:
    return {Confidence.LOW: 0, Confidence.MEDIUM: 1, Confidence.HIGH: 2}[confidence]


def _is_negative(value: str) -> bool:
    return str(value).strip().lower() in _NEGATIVE_VALUES


def _resolve_nix(
    observed: ObservedState,
    target: TargetSpec,
    decisions: list[dict[str, Any]],
) -> None:
    """Activate the optional Nix component only when Nix is really present."""
    evidence: list[str] = []
    for key, observation in observed.observations.items():
        blob = f"{key} {observation.component} {observation.detected}".lower()
        if (
            "nix" in blob
            and observation.status != Status.ABSENT
            and not _is_negative(observation.detected)
        ):
            evidence.append(f"{key}: {observation.detected}")
    for package in observed.packages:
        name = str(package).lower()
        if name == "nix" or name.startswith("nix-") or name.startswith("nixpkgs"):
            evidence.append(f"package: {package}")
    for capability in observed.capabilities:
        if "nix" in str(capability).lower():
            evidence.append(f"capability: {capability}")

    if not evidence:
        return

    component = target.components.get("nix_integration")
    if component is not None:
        component.required = True
    optional = target.package_sets.get("nix.optional") or ["nix"]
    target.package_sets["nix_integration"] = _dedupe(
        list(target.package_sets.get("nix_integration", [])) + list(optional)
    )
    decisions.append(
        _decision(
            "nix-integration",
            "nix",
            selected="enabled",
            options=["enabled"],
            action="preserve",
            reason="Nix is present; integrating it keeps foreign packages visible to ownership policy.",
            evidence=evidence,
        )
    )
