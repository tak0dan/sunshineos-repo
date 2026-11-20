"""Component contracts: how a component declares its capabilities and state.

Spec §5.1 requires every evolutionary component to publish a machine-readable
contract.  The planner must not need to know a component's internals; it only
needs the contract's capabilities, dependencies, owned paths and lifecycle.
"""
from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping


@dataclass(frozen=True)
class ComponentContract:
    format_version: int
    id: str
    name: str
    software_version: str
    schema: int
    provides: tuple[str, ...]
    requires: tuple[str, ...]
    managed_paths: tuple[str, ...]
    installable: bool
    upgradeable: bool
    replaceable: bool
    removable: bool
    adapters: tuple[str, ...] = ()
    description: str = ""

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ComponentContract":
        version = dict(data.get("version") or {})
        provides = dict(data.get("provides") or {})
        requires = dict(data.get("requires") or {})
        ownership = dict(data.get("ownership") or {})
        lifecycle = dict(data.get("lifecycle") or {})
        return cls(
            format_version=int(data.get("format_version", 0)),
            id=str(data.get("id", "")),
            name=str(data.get("name", "")),
            description=str(data.get("description", "")),
            software_version=str(version.get("software", "")),
            schema=int(version.get("schema", 0)),
            provides=tuple(str(c) for c in provides.get("capabilities", [])),
            requires=tuple(str(c) for c in requires.get("capabilities", [])),
            managed_paths=tuple(str(p) for p in ownership.get("managed_paths", [])),
            installable=bool(lifecycle.get("installable", False)),
            upgradeable=bool(lifecycle.get("upgradeable", False)),
            replaceable=bool(lifecycle.get("replaceable", False)),
            removable=bool(lifecycle.get("removable", False)),
            adapters=tuple(str(a) for a in (data.get("adapters") or [])),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "format_version": self.format_version,
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "version": {"software": self.software_version, "schema": self.schema},
            "provides": {"capabilities": list(self.provides)},
            "requires": {"capabilities": list(self.requires)},
            "ownership": {"managed_paths": list(self.managed_paths)},
            "lifecycle": {
                "installable": self.installable,
                "upgradeable": self.upgradeable,
                "replaceable": self.replaceable,
                "removable": self.removable,
            },
            "adapters": list(self.adapters),
        }


def validate_contract(contract: ComponentContract) -> list[str]:
    """Return a list of contract problems; empty means valid."""
    errors: list[str] = []
    if contract.format_version != 1:
        errors.append(f"{contract.id}: unsupported contract format {contract.format_version}")
    if not contract.id or not contract.id.replace("_", "").replace("-", "").isalnum():
        errors.append(f"{contract.id or '(empty)'}: invalid component id")
    if not contract.software_version:
        errors.append(f"{contract.id}: missing software version")
    if contract.schema < 0:
        errors.append(f"{contract.id}: negative schema")
    if not contract.provides:
        errors.append(f"{contract.id}: no provided capabilities")
    if len(set(contract.provides)) != len(contract.provides):
        errors.append(f"{contract.id}: duplicate provided capabilities")
    if any(not path.startswith("/") for path in contract.managed_paths):
        errors.append(f"{contract.id}: managed paths must be absolute")
    if not any((contract.installable, contract.upgradeable, contract.replaceable, contract.removable)):
        errors.append(f"{contract.id}: lifecycle declares no permitted action")
    return errors


def load_contract(path: str | Path) -> ComponentContract:
    path = Path(path)
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ValueError(f"cannot load component contract {path}: {exc}") from exc
    return ComponentContract.from_dict(data)


def load_contracts(directory: str | Path) -> dict[str, ComponentContract]:
    base = Path(directory)
    contracts: dict[str, ComponentContract] = {}
    if not base.is_dir():
        return contracts
    for path in sorted(base.glob("*.toml")):
        contract = load_contract(path)
        if contract.id in contracts:
            raise ValueError(f"duplicate component contract id {contract.id}")
        contracts[contract.id] = contract
    return contracts


def validate_contract_set(
    contracts: Mapping[str, ComponentContract],
    target_components: Mapping[str, Any],
) -> list[str]:
    """Check that contracts cover the target and do not contradict it."""
    errors: list[str] = []
    for cid, spec in target_components.items():
        contract = contracts.get(cid)
        if contract is None:
            errors.append(f"missing component contract for target component '{cid}'")
            continue
        errors.extend(validate_contract(contract))
        if getattr(spec, "schema", None) is not None and contract.schema < int(spec.schema):
            errors.append(
                f"{cid}: contract schema {contract.schema} is older than target {spec.schema}"
            )
        target_provides = set(getattr(spec, "provides", []) or [])
        if target_provides and not target_provides.issubset(set(contract.provides)):
            errors.append(
                f"{cid}: contract does not declare target capabilities "
                + ", ".join(sorted(target_provides - set(contract.provides)))
            )
    return errors
