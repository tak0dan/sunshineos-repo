"""Typed operation handlers (primitives).

Every handler has the signature ``(operation, context) -> Result`` and performs
all system interaction through ``context.execute``.  Handlers never import or
call ``subprocess`` when an executor callable was injected.  With
``context.dry_run = True`` they compute the intended effect, return a descriptive
``Result`` and make no changes at all.
"""
from __future__ import annotations

import difflib
import json
import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

try:
    from ..core import Confidence, OpType, Operation, ObservedState
except ImportError:  # pragma: no cover
    from core import Confidence, OpType, Operation, ObservedState  # type: ignore

from .journal import default_execute, utcnow, write_json

Execute = Callable[[str], tuple[int, str, str]]

_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+@-]*$")
_UNIT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9@._-]*(\.[A-Za-z]+)?$")
_BOOT_OPS = (OpType.INSTALL_KERNEL, OpType.GENERATE_INITRAMFS, OpType.INSTALL_BOOT_ENTRY)


@dataclass
class Result:
    """Outcome of one primitive."""

    ok: bool
    output: str = ""
    changed: bool = False
    reversible: bool = True
    detail: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok, "output": self.output, "changed": self.changed,
            "reversible": self.reversible, "detail": self.detail,
            "metadata": dict(self.metadata),
        }


@dataclass
class ExecutionContext:
    """Everything a primitive is allowed to consult."""

    state_root: Path
    execute: Execute
    system_root: Optional[Path] = None
    checkpoint: Optional[Callable[..., Any]] = None
    validator: Optional[Callable[..., Any]] = None
    dry_run: bool = False
    resume: bool = False
    plan_id: str = ""
    group: str = ""
    observed: Optional[ObservedState] = None
    observations: dict[str, Any] = field(default_factory=dict)
    checkpoints: list[str] = field(default_factory=list)
    checkpoint_ref: str = ""
    repository_generation_changed: bool = False
    repository_generation: str = ""
    upgraded: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def root(self) -> Path:
        """Engine state root: journal, checkpoints, merge records."""
        return Path(self.state_root)

    @property
    def fs_root(self) -> Path:
        """Filesystem being transformed: live ``/`` or a fixture sandbox.

        File mutations and capability probes must use this root; only engine
        bookkeeping belongs under ``state_root``. A real apply writes actual
        config into the system root, so verification sees the same tree.
        """
        return Path(self.system_root) if self.system_root is not None else self.root

    def note_checkpoint(self, ref: str) -> None:
        self.checkpoint_ref = str(ref)
        if ref not in self.checkpoints:
            self.checkpoints.append(str(ref))


def _confidence_of(obs: Any) -> str:
    if isinstance(obs, dict):
        return str(obs.get("confidence", "low")).lower()
    if obs is None:
        return "absent"
    conf = getattr(obs, "confidence", "low")
    return str(getattr(conf, "value", conf)).lower()


def _confidence_for(context: ExecutionContext, *names: str) -> str:
    """Return the strongest observation confidence for the given names."""
    found = []
    for name in names:
        if not name:
            continue
        obs = context.observations.get(name)
        if obs is None and context.observed is not None:
            obs = context.observed.observations.get(name)
        if obs is not None:
            found.append(_confidence_of(obs))
    if not found:
        return "absent"
    return "high" if "high" in found else ("medium" if "medium" in found else "low")


def _destruction_allowed(context: ExecutionContext, op: Operation, targets: list[str]) -> bool:
    """Destructive operations require explicit, at least medium-confidence facts."""
    if not op.destructive:
        return True
    explicit = str(op.params.get("ownership_confidence", "")).lower()
    if explicit in ("low", "guess", "unknown", "heuristic"):
        return False
    names = list(targets) + ([op.component] if op.component else [])
    conf = _confidence_for(context, *names)
    if conf in ("high", "medium"):
        return True
    # An observation for the exact target may be keyed with a prefix.
    for name in names:
        for key, obs in context.observations.items():
            if name and name in str(key) and _confidence_of(obs) in ("high", "medium"):
                return True
        if context.observed is not None:
            for key, obs in context.observed.observations.items():
                if name and name in str(key) and _confidence_of(obs) in ("high", "medium"):
                    return True
    return False


def _refuse(why: str, *, reversible: bool = True) -> Result:
    return Result(False, output=f"refused: {why}", detail=why, reversible=reversible)


def _dry(cmd: str, note: str = "") -> Result:
    return Result(True, output=f"[dry-run] would run: {cmd}" + (f" ({note})" if note else ""),
                  changed=False, reversible=True)


def _exec(context: ExecutionContext, cmd: str) -> tuple[bool, str, str]:
    """Run a read-only or mutating command through the injected callable."""
    if context.dry_run:
        return True, f"[dry-run] would run: {cmd}", ""
    try:
        rc, out, err = context.execute(cmd)
    except Exception as exc:  # broken executor must fail closed
        return False, "", f"execute error: {exc}"
    return rc == 0, out or "", err or ""


def _q(value: Any) -> str:
    return shlex.quote(str(value))


def _valid_name(value: str, pattern: re.Pattern[str] = _NAME_RE) -> bool:
    return bool(pattern.match(str(value)))


def _packages(op: Operation) -> list[str]:
    raw = op.params.get("packages")
    if raw is None:
        raw = op.params.get("package") or op.params.get("name") or []
    items = [str(raw)] if isinstance(raw, str) else [str(x) for x in (raw or [])]
    items = [x.strip() for x in items if str(x).strip()]
    bad = [x for x in items if not _valid_name(x)]
    if bad:
        raise ValueError(f"invalid package name(s): {bad}")
    return items


def _unit(op: Operation) -> str:
    value = str(op.params.get("unit") or op.params.get("service") or op.component or "")
    if value and not _valid_name(value, _UNIT_RE):
        raise ValueError(f"invalid systemd unit: {value}")
    return value


def _verify(kind: str, *, targets: Optional[list[str]] = None, path: str = "",
            expected: bool = True, **extra: Any) -> dict[str, Any]:
    v = {"kind": kind, "expected_present": expected}
    if targets:
        v["targets"] = list(targets)
    if path:
        v["path"] = str(path)
    v.update(extra)
    return v


def _managed_path(root: Path, rel: str) -> Path:
    p = Path(str(rel))
    if p.is_absolute() or ".." in p.parts:
        raise ValueError(f"path must be relative to state_root: {rel}")
    return root / p


# ------------------------------------------------------------------ packages
def install_packages(op: Operation, context: ExecutionContext) -> Result:
    try:
        packages = _packages(op)
    except ValueError as exc:
        return _refuse(str(exc))
    foundation = bool(op.params.get("foundation") or op.params.get("full_upgrade"))
    repo_changed = bool(context.repository_generation_changed or op.params.get("repository_generation_changed"))
    reversible = op.reversible

    if repo_changed and not context.upgraded:
        if packages:
            return _refuse(
                "partial upgrade refused: repository databases changed; run the "
                "single foundation transaction `pacman -Syu --noconfirm` before "
                "installing selected packages", reversible=reversible,
            )
        marker = context.root / "migration" / "state" / (
            f"full-upgrade-{re.sub(r'[^A-Za-z0-9_.-]+', '_', str(context.repository_generation))}.json")
        if not context.dry_run and marker.exists():
            context.upgraded = True
            return Result(True, output=f"full-upgrade already recorded for generation "
                                       f"{context.repository_generation}", changed=False,
                          reversible=reversible,
                          metadata={"verify": _verify("packages", targets=[], expected=True)})
        cmd = "pacman -Syu --noconfirm"
        ok, out, err = _exec(context, cmd)
        if not ok:
            return Result(False, output=err or out, detail="full-upgrade failed", reversible=reversible)
        context.upgraded = True
        if not context.dry_run:
            write_json(marker, {"generation": context.repository_generation, "at": utcnow()})
        return Result(True, output=out.strip() or cmd, changed=not context.dry_run, reversible=reversible,
                      detail="single full-upgrade transaction completed",
                      metadata={"verify": _verify("packages", targets=[], expected=True),
                                "command": cmd, "foundation": True})

    if not packages:
        return Result(True, output="no packages requested", changed=False, reversible=reversible)

    missing = list(packages)
    if not context.dry_run:
        missing = []
        for pkg in packages:
            ok, _, _ = _exec(context, f"pacman -Q {_q(pkg)}")
            if not ok:
                missing.append(pkg)
        if not missing:
            return Result(True, output="packages already installed: " + ", ".join(packages),
                          changed=False, reversible=reversible,
                          metadata={"verify": _verify("packages", targets=packages, expected=True)})

    cmd = "pacman -S --needed --noconfirm " + " ".join(_q(p) for p in missing)
    ok, out, err = _exec(context, cmd)
    if not ok:
        return Result(False, output=err or out, detail="pacman install failed", reversible=reversible)
    return Result(True, output=out.strip() or cmd, changed=not context.dry_run, reversible=reversible,
                  detail="selected packages installed after full-upgrade" if context.upgraded else "packages installed",
                  metadata={"verify": _verify("packages", targets=packages, expected=True), "command": cmd})


def remove_packages(op: Operation, context: ExecutionContext) -> Result:
    try:
        packages = _packages(op)
    except ValueError as exc:
        return _refuse(str(exc))
    if not packages:
        return _refuse("RemovePackages requires explicitly identified packages")
    if not _destruction_allowed(context, op, packages):
        return _refuse("low-confidence package ownership; refusing destructive removal")
    present = list(packages)
    if not context.dry_run:
        present = []
        for pkg in packages:
            ok, _, _ = _exec(context, f"pacman -Q {_q(pkg)}")
            if ok:
                present.append(pkg)
        if not present:
            return Result(True, output="packages already absent: " + ", ".join(packages),
                          changed=False, reversible=False,
                          metadata={"verify": _verify("packages", targets=packages, expected=False)})
    cmd = "pacman -Rs --noconfirm " + " ".join(_q(p) for p in present)
    ok, out, err = _exec(context, cmd)
    if not ok:
        return Result(False, output=err or out, detail="pacman removal failed", reversible=False)
    return Result(True, output=out.strip() or cmd, changed=not context.dry_run, reversible=False,
                  detail="explicitly identified packages removed",
                  metadata={"verify": _verify("packages", targets=packages, expected=False), "command": cmd})


# ------------------------------------------------------------------ configs
def _content(op: Operation) -> str:
    for key in ("content", "configuration", "config", "settings", "data"):
        if key in op.params:
            value = op.params[key]
            if isinstance(value, (dict, list)):
                return json.dumps(value, sort_keys=True, indent=2) + "\n"
            return str(value)
    return json.dumps({"component": op.component or op.id, "managed": True}, sort_keys=True, indent=2) + "\n"


def _changed_ranges(base: list[str], modified: list[str]) -> list[tuple[int, int, list[str]]]:
    matcher = difflib.SequenceMatcher(None, base, modified, autojunk=False)
    return [(i1, i2, modified[j1:j2]) for tag, i1, i2, j1, j2 in matcher.get_opcodes() if tag != "equal"]


def three_way_merge(base: str, ours: str, theirs: str) -> tuple[bool, str, str]:
    """Line-based three-way merge. On conflict, fail closed without writing."""
    if ours == theirs:
        return True, ours, "identical"
    base_lines, our_lines, their_lines = (s.splitlines(keepends=True) for s in (base, ours, theirs))
    if our_lines == base_lines:
        return True, theirs, "fast-forward-theirs"
    if their_lines == base_lines:
        return True, ours, "preserve-ours"
    changes = [("ours", *c) for c in _changed_ranges(base_lines, our_lines)]
    changes += [("theirs", *c) for c in _changed_ranges(base_lines, their_lines)]
    changes.sort(key=lambda c: (c[1], c[2]))
    out: list[str] = []
    cursor = 0
    for _origin, start, end, replacement in changes:
        if start < cursor:
            return False, f"overlapping edits at line {start + 1}; manual merge required", "conflict"
        out.extend(base_lines[cursor:start])
        out.extend(replacement)
        cursor = end
    out.extend(base_lines[cursor:])
    return True, "".join(out), "three-way"


def _write_config(op: Operation, context: ExecutionContext, rel: str, content: str) -> Result:
    reversible = op.reversible
    try:
        target = _managed_path(context.fs_root, rel)
    except ValueError as exc:
        return _refuse(str(exc))
    if not _destruction_allowed(context, op, [rel, op.component]):
        return _refuse("low-confidence observations; refusing configuration replacement")

    base_file = context.root / "migration" / "managed" / rel
    merge_file = context.root / "migration" / "merges" / (re.sub(r"[^A-Za-z0-9_.-]+", "_", rel) + ".json")
    base = base_file.read_text(encoding="utf-8") if base_file.exists() else ""
    ours = target.read_text(encoding="utf-8") if target.exists() else ""
    merged, strategy = content, "new-file"
    if target.exists():
        ok, merged, strategy = three_way_merge(base, ours, content)
        if not ok:
            record = {"path": rel, "strategy": "conflict", "error": merged,
                      "base": base, "ours": ours, "theirs": content, "at": utcnow()}
            if not context.dry_run:
                write_json(merge_file, record)
            return Result(False, output=merged, detail="configuration merge conflict; user config untouched",
                          reversible=reversible, metadata={"verify": _verify("file", path=rel, expected=True),
                                                           "merge": record})

    if ours == merged and target.exists():
        converged_meta: dict[str, Any] = {
            "verify": _verify("file", path=rel, expected=True), "strategy": strategy,
        }
        if strategy in ("preserve-ours", "three-way") and not context.dry_run:
            converged_meta["merge"] = {"path": rel, "strategy": strategy, "base": base,
                                       "ours": ours, "theirs": content, "merged": merged,
                                       "at": utcnow(), "wrote": False}
            write_json(merge_file, converged_meta["merge"])
        return Result(True, output=f"configuration already converged: {rel}", changed=False,
                      reversible=reversible, metadata=converged_meta)

    record = {"path": rel, "strategy": strategy, "base": base, "ours": ours,
              "theirs": content, "merged": merged, "at": utcnow()}
    if context.dry_run:
        return Result(True, output=f"[dry-run] would write {rel} via {strategy} merge", changed=False,
                      reversible=reversible,
                      metadata={"verify": _verify("file", path=rel, expected=True), "merge": record})
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_name(target.name + ".tmp")
    tmp.write_text(merged, encoding="utf-8")
    tmp.replace(target)
    base_file.parent.mkdir(parents=True, exist_ok=True)
    base_file.write_text(merged, encoding="utf-8")
    write_json(merge_file, record)
    return Result(True, output=f"wrote managed configuration: {rel} ({strategy})", changed=True,
                  reversible=reversible,
                  metadata={"verify": _verify("file", path=rel, expected=True), "merge": record})


def register_component(op: Operation, context: ExecutionContext) -> Result:
    component = op.component or str(op.params.get("id", ""))
    if not component or not _valid_name(component):
        return _refuse("RegisterComponent requires a valid component id")
    schema = int(op.params.get("schema", 0))
    rel = str(op.params.get("path") or f"etc/sunshine/components/{component}.json")
    main = _write_config(op, context, rel, _content(op))
    if not main.ok:
        return main
    registry_rel = "var/lib/sunshine/state/components.toml"
    registry = context.root / registry_rel
    entry = f'[[component]]\nid = "{component}"\nschema = {schema}\n'
    existing = registry.read_text(encoding="utf-8") if registry.exists() else ""
    if f'id = "{component}"' not in existing:
        if not context.dry_run:
            registry.parent.mkdir(parents=True, exist_ok=True)
            with open(registry, "a", encoding="utf-8") as fh:
                fh.write(entry)
                fh.flush()
                import os
                os.fsync(fh.fileno())
        main.changed = True
        main.output += "; registered component in " + registry_rel
    main.metadata.setdefault("verify", _verify("file", path=rel, expected=True))
    main.metadata["component"] = component
    return main


def create_configuration(op: Operation, context: ExecutionContext) -> Result:
    name = str(op.params.get("name") or op.component or op.id)
    rel = str(op.params.get("path") or f"etc/sunshine/config/{name}.conf")
    return _write_config(op, context, rel, _content(op))


def migrate_configuration(op: Operation, context: ExecutionContext) -> Result:
    source = str(op.params.get("source_path") or op.params.get("source") or "")
    if not source:
        return _refuse("MigrateConfiguration requires source_path")
    try:
        source_path = _managed_path(context.fs_root, source)
    except ValueError as exc:
        return _refuse(str(exc))
    name = str(op.params.get("name") or op.component or op.id)
    rel = str(op.params.get("path") or f"etc/sunshine/config/{name}.conf")
    incoming = op.params.get("content")
    if incoming is None:
        incoming = source_path.read_text(encoding="utf-8") if source_path.exists() else ""
    result = _write_config(op, context, rel, str(incoming))
    if result.ok and source_path.exists() and not context.dry_run:
        source_path.unlink()
        result.changed = True
        result.output += f"; removed migrated source {source}"
    return result


def transfer_ownership(op: Operation, context: ExecutionContext) -> Result:
    new_owner = str(op.params.get("to") or op.params.get("owner") or "sunshine")
    old_owner = str(op.params.get("from") or op.params.get("previous_owner") or "unknown")
    resource = str(op.params.get("path") or op.params.get("resource") or op.component or op.id)
    if not _destruction_allowed(context, op, [resource, op.component]):
        return _refuse("low-confidence observations; refusing ownership transfer")
    rel = f"var/lib/sunshine/ownership/{re.sub(r'[^A-Za-z0-9_.-]+', '_', resource)}.json"
    record = {"resource": resource, "from": old_owner, "to": new_owner, "at": utcnow()}
    if context.dry_run:
        return Result(True, output=f"[dry-run] would transfer {resource} to {new_owner}", changed=False,
                      metadata={"verify": _verify("ownership", path=rel, expected=True)})
    target = context.root / rel
    previous = {}
    if target.exists():
        try:
            previous = json.loads(target.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            previous = {}
    unchanged = (
        previous.get("resource") == resource and
        previous.get("from") == old_owner and
        previous.get("to") == new_owner
    )
    if unchanged:
        return Result(True, output=f"ownership of {resource} already assigned to {new_owner}",
                      changed=False, metadata={"verify": _verify("ownership", path=rel, expected=True)})
    write_json(target, record)
    return Result(True, output=f"transferred ownership of {resource} to {new_owner}", changed=True,
                  metadata={"verify": _verify("ownership", path=rel, expected=True)})


# ------------------------------------------------------------------ services
def _service(op: Operation, context: ExecutionContext, enable: bool) -> Result:
    try:
        unit = _unit(op)
    except ValueError as exc:
        return _refuse(str(exc))
    if not unit:
        return _refuse("service operation requires a unit name")
    if not enable and not _destruction_allowed(context, op, [unit, op.component]):
        return _refuse("low-confidence observations; refusing service disable")
    label = "enabled" if enable else "disabled"
    action = "enable" if enable else "disable"
    if context.dry_run:
        return _dry(f"systemctl {action} {_q(unit)}", label)
    ok, out, _ = _exec(context, f"systemctl is-enabled {_q(unit)}")
    current = (out or "").strip().lower()
    if ok and (current == "enabled" if enable else current == "disabled"):
        return Result(True, output=f"{unit} already {label}", changed=False, reversible=True,
                      metadata={"verify": _verify("service", unit=unit, expected=enable)})
    ok, out, err = _exec(context, f"systemctl {action} {_q(unit)}")
    if not ok:
        return Result(False, output=err or out, detail=f"failed to {action} {unit}")
    return Result(True, output=out.strip() or f"{unit} {label}", changed=True, reversible=True,
                  metadata={"verify": _verify("service", unit=unit, expected=enable)})


def enable_service(op: Operation, context: ExecutionContext) -> Result:
    return _service(op, context, True)


def disable_service(op: Operation, context: ExecutionContext) -> Result:
    return _service(op, context, False)


# ------------------------------------------------------------------ boot
def _checkpoint_required(op: Operation, context: ExecutionContext) -> Optional[Result]:
    if context.checkpoint_ref:
        return None
    if context.dry_run:
        context.note_checkpoint("dry-run:implicit-before-" + op.id)
        return None
    return _refuse(
        f"checkpoint required before {op.type.value}; create a checkpoint first",
        reversible=op.reversible,
    )


def install_kernel(op: Operation, context: ExecutionContext) -> Result:
    blocked = _checkpoint_required(op, context)
    if blocked:
        return blocked
    try:
        packages = _packages(op)
    except ValueError as exc:
        return _refuse(str(exc))
    if not packages:
        packages = [str(op.params.get("version") or op.component or "linux")]
    if not all(_valid_name(p) for p in packages):
        return _refuse("invalid kernel package name")
    missing = list(packages)
    if not context.dry_run:
        missing = []
        for pkg in packages:
            ok, _, _ = _exec(context, f"pacman -Q {_q(pkg)}")
            if not ok:
                missing.append(pkg)
        if not missing:
            return Result(True, output="kernel already installed", changed=False,
                          metadata={"verify": _verify("packages", targets=packages, expected=True),
                                    "checkpoint": context.checkpoint_ref})
    cmd = "pacman -S --needed --noconfirm " + " ".join(_q(p) for p in missing)
    ok, out, err = _exec(context, cmd)
    if not ok:
        return Result(False, output=err or out, detail="kernel installation failed")
    return Result(True, output=out.strip() or cmd, changed=not context.dry_run,
                  detail="kernel installed after checkpoint",
                  metadata={"verify": _verify("packages", targets=packages, expected=True),
                            "checkpoint": context.checkpoint_ref, "command": cmd})


def generate_initramfs(op: Operation, context: ExecutionContext) -> Result:
    blocked = _checkpoint_required(op, context)
    if blocked:
        return blocked
    preset = str(op.params.get("preset") or op.params.get("kernel") or "linux")
    if not _valid_name(preset):
        return _refuse("invalid initramfs preset")
    rel = f"boot/initramfs-{preset}.img"
    target = context.fs_root / rel
    # mkinitcpio writes to the live /boot, not to state_root. Probe through the
    # executor so a real apply verifies the image it actually generated while
    # fixture executors answer the same command from their sandbox.
    probe = f"ls /boot/initramfs-{preset}*.img"
    verify = _verify("initramfs", command=probe, path=rel, expected=True)
    want_fallback = bool(op.params.get("fallback", True))
    fallback_rel = f"/boot/initramfs-{preset}-fallback.img"

    def ensure_fallback() -> tuple[bool, str, bool]:
        """Return (ok, output, changed); upstream presets often omit fallback."""
        if not want_fallback:
            return True, "", False
        ok_rc, _, _ = _exec(context, f"ls /boot/initramfs-{preset}*-fallback.img 2>/dev/null")
        if ok_rc:
            return True, "", False
        # Upstream Sunshine/Arch presets declare only the default image. Build
        # the fallback explicitly without the autodetect hook so it boots on
        # different hardware, which is the point of the fallback capability.
        command = (f"mkinitcpio -k {_q('/boot/vmlinuz-' + preset)} "
                   f"-g {_q(fallback_rel)} -S autodetect")
        ok, out, err = _exec(context, command)
        return ok, (err or out or command).strip(), (ok and not context.dry_run)

    if target.exists() and not context.dry_run:
        ok, output, changed = ensure_fallback()
        if not ok:
            return Result(False, output=output, detail="fallback initramfs generation failed")
        return Result(True, output=f"initramfs already present: {rel}" + (f"; {output}" if output else ""),
                      changed=changed,
                      metadata={"verify": verify, "checkpoint": context.checkpoint_ref})
    full = bool(op.params.get("all") or op.params.get("presets"))
    cmd = "mkinitcpio -P" if full else f"mkinitcpio -p {_q(preset)}"
    ok, out, err = _exec(context, cmd)
    if not ok:
        return Result(False, output=err or out, detail="initramfs generation failed")
    ok, fb_out, fb_changed = ensure_fallback()
    if not ok:
        return Result(False, output=fb_out, detail="fallback initramfs generation failed")
    return Result(True, output="\n".join(x for x in (out.strip() or cmd, fb_out) if x),
                  changed=not context.dry_run or fb_changed,
                  detail="initramfs generated after checkpoint",
                  metadata={"verify": verify, "checkpoint": context.checkpoint_ref, "command": cmd})


def install_boot_entry(op: Operation, context: ExecutionContext) -> Result:
    blocked = _checkpoint_required(op, context)
    if blocked:
        return blocked
    label = str(op.params.get("label") or op.component or "Sunshine")
    loader = str(op.params.get("loader") or "/boot/EFI/Linux/sunshine.efi")
    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}$", label) or not loader.startswith("/"):
        return _refuse("invalid boot entry label or loader")
    if not context.dry_run:
        ok, out, _ = _exec(context, "efibootmgr -v")
        if ok and label in out:
            return Result(True, output=f"boot entry already present: {label}", changed=False,
                          metadata={"verify": _verify("boot_entry", label=label, expected=True),
                                    "checkpoint": context.checkpoint_ref})
    cmd = f"efibootmgr -c -L {_q(label)} -l {_q(loader)}"
    if op.params.get("disk"):
        cmd += f" -d {_q(op.params['disk'])}"
    if op.params.get("partition"):
        cmd += f" -p {_q(op.params['partition'])}"
    ok, out, err = _exec(context, cmd)
    if not ok:
        return Result(False, output=err or out, detail="boot entry creation failed")
    return Result(True, output=out.strip() or cmd, changed=not context.dry_run,
                  detail="boot entry created after checkpoint",
                  metadata={"verify": _verify("boot_entry", label=label, expected=True),
                            "checkpoint": context.checkpoint_ref, "command": cmd})


# ------------------------------------------------------------- checkpoint/val
def create_checkpoint(op: Operation, context: ExecutionContext) -> Result:
    label = str(op.params.get("label") or op.component or f"{context.plan_id}:{op.id}")
    if context.dry_run:
        ref = f"dry-run:{label}"
        context.note_checkpoint(ref)
        return Result(True, output=f"[dry-run] would create checkpoint {label}", changed=False,
                      detail="virtual checkpoint only; nothing was recorded",
                      metadata={"checkpoint": ref, "verify": _verify("checkpoint", path=ref, expected=True)})
    if context.checkpoint is not None:
        try:
            result = context.checkpoint(label)
        except TypeError:
            result = context.checkpoint()
        if isinstance(result, dict):
            ref = str(result.get("ref") or result.get("id") or label)
        else:
            ref = str(result) if result is not None else label
    else:
        cp_dir = context.root / "migration" / "checkpoints"
        existing = ""
        if cp_dir.is_dir():
            for candidate in sorted(cp_dir.glob("*.json")):
                try:
                    if (json.loads(candidate.read_text(encoding="utf-8")).get("label") == label):
                        existing = str(candidate.relative_to(context.root))
                        break
                except (OSError, json.JSONDecodeError):
                    continue
        if existing:
            ref = existing
            context.note_checkpoint(ref)
            return Result(True, output=f"checkpoint already recorded: {ref}", changed=False,
                          detail="existing snapshot reference reused",
                          metadata={"checkpoint": ref, "verify": _verify("checkpoint", path=ref, expected=True)})
        stamp = utcnow().replace(":", "-")
        safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", label)
        rel = f"migration/checkpoints/{safe}-{stamp}.json"
        write_json(context.root / rel, {"label": label, "plan_id": context.plan_id,
                                        "created_at": utcnow(), "root": str(context.root)})
        ref = rel
    context.note_checkpoint(ref)
    return Result(True, output=f"checkpoint created: {ref}", changed=True,
                  detail="snapshot reference recorded before destructive/boot work",
                  metadata={"checkpoint": ref, "verify": _verify("checkpoint", path=ref, expected=True)})


def validate_capability(op: Operation, context: ExecutionContext) -> Result:
    cap = str(op.params.get("capability") or op.params.get("name") or op.component)
    if not cap:
        return _refuse("ValidateCapability requires a capability name")
    if context.dry_run:
        return Result(True, output=f"[dry-run] would validate capability {cap}", changed=False,
                      metadata={"verify": _verify("capability", capability=cap, expected=True,
                                                  observed_present=cap in (context.observed.capabilities
                                                                           if context.observed else set()))})
    passed: Optional[bool] = None
    evidence: list[str] = []
    if context.validator is not None:
        try:
            report = context.validator(cap, str(context.fs_root), context.execute, context.observed)
            passed = bool(getattr(report, "passed", report))
            evidence.append(str(getattr(report, "detail", "injected validator")))
        except TypeError:
            passed = bool(context.validator(cap))
            evidence.append("injected validator(capability)")
    if passed is None:
        try:
            from ..validation.validator import validate_capability as probe  # type: ignore
            report = probe(cap, context.fs_root, context.execute, context.observed,
                           state_root=context.root)
            passed = bool(report.passed)
            evidence.append(report.detail)
        except Exception as exc:
            passed = bool(context.observed and cap in context.observed.capabilities)
            evidence.append(f"active validator unavailable ({exc}); used observed capability set")
    return Result(bool(passed), output=f"capability {cap}: {'passed' if passed else 'failed'}; " + "; ".join(evidence),
                  changed=False, detail="capability validation",
                  metadata={"verify": _verify("capability", capability=cap, expected=True,
                                              observed_present=passed)})


HANDLERS: dict[OpType, Callable[[Operation, ExecutionContext], Result]] = {
    OpType.INSTALL_PACKAGES: install_packages,
    OpType.REMOVE_PACKAGES: remove_packages,
    OpType.TRANSFER_OWNERSHIP: transfer_ownership,
    OpType.CREATE_CONFIGURATION: create_configuration,
    OpType.MIGRATE_CONFIGURATION: migrate_configuration,
    OpType.REGISTER_COMPONENT: register_component,
    OpType.ENABLE_SERVICE: enable_service,
    OpType.DISABLE_SERVICE: disable_service,
    OpType.INSTALL_KERNEL: install_kernel,
    OpType.GENERATE_INITRAMFS: generate_initramfs,
    OpType.INSTALL_BOOT_ENTRY: install_boot_entry,
    OpType.CREATE_CHECKPOINT: create_checkpoint,
    OpType.VALIDATE_CAPABILITY: validate_capability,
}

BOOT_OPS = _BOOT_OPS


def dispatch(operation: Operation, context: ExecutionContext) -> Result:
    # Adapter-typed operations are routed only through the verified sandbox.
    # Import lazily to avoid a cycle with primitives itself.
    if operation.params.get("adapter_id"):
        from .adapter_ops import execute_adapter  # local import by design

        return execute_adapter(operation, context)
    handler = HANDLERS.get(operation.type)
    if handler is None:  # fail closed for unknown operation types
        return _refuse(f"no primitive registered for {operation.type}")
    try:
        return handler(operation, context)
    except Exception as exc:
        return Result(False, output=f"primitive error: {exc}", detail=type(exc).__name__,
                      reversible=operation.reversible)
