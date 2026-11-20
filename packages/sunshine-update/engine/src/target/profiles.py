"""Desktop profiles and profile selection from observed sessions.

A desktop profile describes one *compatible* way of satisfying the target's
``desktop_integration`` component: the capabilities it needs, the packages it
contributes, and the other profiles it conflicts with. Profiles are data
(``profiles/*.toml``), not code, so new desktops can be supported without
touching the resolver.

Detection is deliberately evidence-driven. A session observation with
high/medium confidence is enough to select a profile automatically; low
confidence observations, ambiguous multi-session machines with no configured
default, and unknown desktops all produce a *single* decision for the user
instead of a questionnaire. Package names and capability strings are accepted
as secondary evidence because simulated discovery states often expose only
those.
"""
from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping

from ..core import Confidence, ObservedState, Observation, Status

DEFAULT_PROFILES_DIR = Path(__file__).resolve().parent / "profiles"

# Alternative session names that map onto a supported profile id.
_ALIASES = {
    "kde": "plasma",
    "kde-plasma": "plasma",
    "plasmawayland": "plasma",
    "plasma-x11": "plasma",
    "gnome-shell": "gnome",
    "gnome-wayland": "gnome",
    "gnome-xorg": "gnome",
    "xfce4": "xfce",
    "xfce-session": "xfce",
    "hyprland-desktop": "hyprland",
    "swaywm": "sway",
}

_CONFIDENCE_RANK = {
    Confidence.LOW: 0,
    Confidence.MEDIUM: 1,
    Confidence.HIGH: 2,
}


@dataclass(frozen=True)
class DesktopProfile:
    """A declarative desktop choice; immutable so resolution cannot corrupt it."""

    id: str
    name: str = ""
    description: str = ""
    required_capabilities: tuple[str, ...] = ()
    packages: tuple[str, ...] = ()
    conflicts: tuple[str, ...] = ()

    @property
    def marker_package(self) -> str:
        """The first package is the definitive 'this desktop is present' marker."""
        return self.packages[0] if self.packages else self.id


@dataclass(frozen=True)
class DesktopDetection:
    """One supported desktop seen in an ``ObservedState``."""

    profile_id: str
    confidence: Confidence
    evidence: tuple[str, ...] = ()
    is_default: bool = False

    @property
    def actionable(self) -> bool:
        """Only high/medium confidence may drive an automatic decision."""
        return self.confidence in (Confidence.HIGH, Confidence.MEDIUM)


def load_profiles(profiles_dir: str | Path | None = None) -> dict[str, DesktopProfile]:
    """Load all ``*.toml`` desktop profiles from ``profiles_dir``.

    When no directory is given, the bundled ``src/target/profiles`` directory
    is used. File names are only a fallback for a missing ``id`` key: the id in
    the manifest is authoritative because the resolver records it in decisions.
    """
    directory = Path(profiles_dir) if profiles_dir is not None else DEFAULT_PROFILES_DIR
    if not directory.is_dir():
        raise FileNotFoundError(f"desktop profiles directory not found: {directory}")

    profiles: dict[str, DesktopProfile] = {}
    for path in sorted(directory.glob("*.toml")):
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except tomllib.TOMLDecodeError as exc:
            raise ValueError(f"invalid desktop profile {path}: {exc}") from exc
        profile_id = str(data.get("id") or path.stem)
        if profile_id in profiles:
            raise ValueError(f"duplicate desktop profile id '{profile_id}' in {path}")
        profiles[profile_id] = DesktopProfile(
            id=profile_id,
            name=str(data.get("name", "")),
            description=str(data.get("description", "")),
            required_capabilities=tuple(
                str(c) for c in data.get("required_capabilities", [])
            ),
            packages=tuple(str(p) for p in data.get("packages", [])),
            conflicts=tuple(str(c) for c in data.get("conflicts", [])),
        )
    if not profiles:
        raise ValueError(f"no desktop profiles found in {directory}")
    return profiles


def _normalize_profile(value: str, profiles: Mapping[str, DesktopProfile]) -> str | None:
    """Map a session name/path/evidence string onto a supported profile id."""
    text = value.strip().lower()
    if not text:
        return None
    text = text.replace("\\", "/").rsplit("/", 1)[-1]
    for suffix in (".desktop", ".service", ".conf"):
        if text.endswith(suffix):
            text = text[: -len(suffix)]
    text = text.strip("-_.")

    if text in profiles:
        return text
    if text in _ALIASES and _ALIASES[text] in profiles:
        return _ALIASES[text]
    for token in re.split(r"[^a-z0-9]+", text):
        if token in profiles:
            return token
        if token in _ALIASES and _ALIASES[token] in profiles:
            return _ALIASES[token]
    return None


def _first_profile(values: Iterable[str], profiles: Mapping[str, DesktopProfile]) -> str | None:
    for value in values:
        found = _normalize_profile(str(value), profiles)
        if found is not None:
            return found
    return None


def _is_default(key: str, observation: Observation, profile_id: str) -> bool:
    """Recognise an explicit 'this session is the default' observation."""
    blob = " ".join(
        [key, observation.component, observation.detected, *observation.evidence]
    ).lower()
    return "default" in blob and profile_id in blob


def detect_desktop_sessions(
    observed: ObservedState,
    profiles: Mapping[str, DesktopProfile] | None = None,
) -> dict[str, DesktopDetection]:
    """Collect supported desktop sessions from every available observation.

    Explicit session observations carry their own confidence. Evidence strings
    that mention another desktop contribute only weak (LOW) evidence, and
    installed marker packages / capability strings contribute MEDIUM evidence.
    Results are merged per profile id keeping the strongest confidence.
    """
    available = profiles if profiles is not None else load_profiles()
    found: dict[str, DesktopDetection] = {}

    def add(profile_id: str, confidence: Confidence, evidence: Iterable[str], is_default: bool = False) -> None:
        if profile_id not in available:
            return
        new_evidence = tuple(dict.fromkeys(evidence))
        previous = found.get(profile_id)
        if previous is None:
            found[profile_id] = DesktopDetection(profile_id, confidence, new_evidence, is_default)
            return
        merged = tuple(dict.fromkeys(previous.evidence + new_evidence))
        strongest = (
            previous.confidence
            if _CONFIDENCE_RANK[previous.confidence] >= _CONFIDENCE_RANK[confidence]
            else confidence
        )
        found[profile_id] = DesktopDetection(
            profile_id, strongest, merged, previous.is_default or is_default
        )

    for key, observation in observed.observations.items():
        if observation.status == Status.ABSENT:
            continue
        label = f"{key}: {observation.detected}"
        primary = _first_profile(
            (observation.detected, key, observation.component), available
        )
        if primary is not None:
            add(primary, observation.confidence, [label], _is_default(key, observation, primary))
        for item in observation.evidence:
            from_evidence = _normalize_profile(str(item), available)
            if from_evidence is not None and from_evidence != primary:
                add(from_evidence, Confidence.LOW, [f"{key}.evidence: {item}"])

    for capability in observed.capabilities:
        profile_id = _normalize_profile(str(capability), available)
        if profile_id is not None:
            add(
                profile_id,
                Confidence.MEDIUM,
                [f"capability: {capability}"],
                is_default="default" in str(capability).lower(),
            )

    for package in observed.packages:
        package_name = str(package).lower()
        for profile_id, profile in available.items():
            marker = profile.marker_package.lower()
            if package_name == marker or package_name.startswith(marker + "-"):
                add(profile_id, Confidence.MEDIUM, [f"package: {package}"])
    return found


def choose_profile(
    detections: Mapping[str, DesktopDetection],
    available: Iterable[str] = (),
) -> tuple[str | None, list[str], bool]:
    """Decide which profile to apply without guessing.

    Returns ``(profile_id, options, needs_user_input)``. Automatic choices are
    made only when a single supported desktop is actionable, or when several
    are detected and exactly one is marked as the configured default. Every
    other case asks exactly one question with the candidate ids as options.
    """
    actionable = sorted(pid for pid, det in detections.items() if det.actionable)
    if len(actionable) == 1:
        return actionable[0], [actionable[0]], False
    if len(actionable) > 1:
        defaults = [pid for pid in actionable if detections[pid].is_default]
        if len(defaults) == 1:
            return defaults[0], actionable, False
        return None, actionable, True
    return None, sorted(set(available)), True
