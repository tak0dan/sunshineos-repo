#!/usr/bin/env python3
"""Sunshine Evolution Engine orchestrator and CLI.

Pipeline: Discover → Resolve → Plan → Preflight → Execute → Validate → Commit.

The CLI mirrors the intended production interface:

    sunshine-evolve --check          # discover + report only
    sunshine-evolve --plan           # produce a reviewable plan (JSON)
    sunshine-evolve --apply          # execute the plan (with journaling)
    sunshine-evolve --verify         # validate current capabilities
    sunshine-evolve --repair         # replan + resume from journal
    sunshine-evolve --history        # show journal
    sunshine-evolve --fixture clean-arch --plan
                                     # offline, host-independent demo mode

The same executable enters transformation mode on a pure Arch machine and
normal reconciliation mode on an existing Sunshine OS — there is one engine.
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.adapters import AdapterRegistry  # noqa: E402
from src.core import ObservedState, Plan  # noqa: E402
from src.components import load_contracts, validate_contract_set  # noqa: E402
from src.discovery import discover  # noqa: E402
from src.fixtures import (  # noqa: E402
    applied_fixture,
    fixture_executor,
    fixture_root,
    write_apply_marker,
)
from src.target import (  # noqa: E402
    load_target,
    resolve_target,
    preflight_source,
)
from src.planner import plan as build_plan  # noqa: E402
from src.executor import execute_plan, ExecutionResult  # noqa: E402
from src.trust import (  # noqa: E402
    StageAReport,
    TrustPolicy,
    gpg_verifier,
    verify_receipt,
    verify_stage_a,
)
from src.validation import validate_system, ValidationReport  # noqa: E402

DEFAULT_ROOT = "/"
STATE_ROOT = Path("/var/lib/sunshine")


def _json(obj) -> str:
    if hasattr(obj, "to_dict"):
        obj = obj.to_dict()
    elif hasattr(obj, "__dataclass_fields__"):
        obj = asdict(obj)
    return json.dumps(obj, indent=2, ensure_ascii=False, default=str)


def _discover(root: str, execute=None) -> ObservedState:
    """Discover *root*, using an injected executor when supplied.

    Passing ``execute`` is essential for fixture mode: without it, a fake
    filesystem would still be combined with real host commands, producing a
    plan that reflects the developer's machine rather than the fixture.
    """
    return discover(root=root, execute=execute)


def _resolve(root: str, observed: ObservedState, answers: Optional[dict[str, str]] = None):
    target = load_target()
    return resolve_target(
        observed, target,
        profiles_dir=Path(__file__).resolve().parent / "target" / "profiles",
        answers=answers,
    )


def _contract_validation(published_target) -> list[str]:
    """Validate bundled component contracts against the published target."""
    directory = Path(__file__).resolve().parent / "target" / "contracts"
    return validate_contract_set(load_contracts(directory), published_target.components)


def _load_policy(path: str | None) -> TrustPolicy | None:
    if not path:
        return None
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return TrustPolicy.from_dict(data)


def _stage_a(args, execute=None):
    """Verify Stage A from signed index or a receipt written by Rust bootstrap."""
    index = getattr(args, "trust_index", None)
    report_path = getattr(args, "trust_report", None)
    receipt_path = getattr(args, "trust_receipt", None)
    if index and report_path:
        raise ValueError("--trust-index and --trust-report are mutually exclusive")
    if not index and not report_path:
        return None
    if report_path and not receipt_path:
        raise ValueError("--trust-report requires --trust-receipt")
    if not getattr(args, "trust_policy", None) or not getattr(args, "trust_keyring", None):
        raise ValueError("Stage A requires --trust-policy and --trust-keyring")
    policy = _load_policy(args.trust_policy)
    verifier = gpg_verifier(args.trust_keyring)
    if index:
        return verify_stage_a(
            index, policy, verifier,
            artifact_root=Path(index).resolve().parent,
        )
    report = StageAReport.from_dict(json.loads(Path(report_path).read_text(encoding="utf-8")))
    ok, _payload, errors = verify_receipt(receipt_path, policy, verifier, report)
    if not ok:
        return StageAReport(False, errors)
    return report


def _adapter_registry(args, trust):
    """Build the only registry from which a plan may name a Rust adapter."""
    if not getattr(args, "adapter_dir", None):
        return None
    if trust is None or not trust.passed:
        raise ValueError("--adapter-dir requires successful Stage A verification")
    if not getattr(args, "trust_keyring", None):
        raise ValueError("--adapter-dir requires --trust-keyring")
    index = getattr(args, "trust_index", None) or getattr(args, "trust_report", None)
    if not index:
        raise ValueError("--adapter-dir requires --trust-index or --trust-report")
    artifact_root = getattr(args, "adapter_artifact_root", None) or str(Path(index).resolve().parent)
    return AdapterRegistry.load(
        args.adapter_dir,
        verifier=gpg_verifier(args.trust_keyring),
        trusted_keys=trust.trusted_keys,
        artifact_root=artifact_root,
        stage_artifacts=trust.artifacts_verified,
        contract_component_ids=set(load_target().components),
    )


def cmd_check(root: str, execute=None, trust=None) -> int:
    observed = _discover(root, execute)
    published = load_target()
    contract_errors = _contract_validation(published)
    target, decisions = _resolve(root, observed)
    compatibility = preflight_source(observed)
    print("Sunshine Evolution Engine — discovery report")
    print(_json({
        "observed": observed.to_dict(),
        "source_compatibility": compatibility.to_dict(),
        "stage_a": trust.to_dict() if trust is not None else None,
        "component_contract_errors": contract_errors,
        "target_release": target.release,
        "repository_generation": target.repository_generation,
        "required_components": {k: c.schema for k, c in target.components.items() if c.required},
        "decisions_required": decisions,
    }))
    return 0


def _parse_decision_answers(answers: Optional[list[str]]) -> dict[str, str]:
    """Parse ``--decide id=value`` strings into a decision-id map.

    The same map is handed to the resolver (which applies the answer to the
    declarative target) and to the decision annotator, so ``--plan`` and
    ``--apply`` cannot disagree about what an operator selected.
    """
    parsed: dict[str, str] = {}
    for answer in answers or []:
        if "=" not in answer:
            raise ValueError(f"invalid decision '{answer}'; expected id=value")
        key, value = answer.split("=", 1)
        key, value = key.strip(), value.strip()
        if not key or not value:
            raise ValueError(f"invalid decision '{answer}'; expected id=value")
        parsed[key] = value
    return parsed


def cmd_plan(root: str, execute=None, trust=None, decide: Optional[list[str]] = None) -> int:
    observed = _discover(root, execute)
    target, decisions = _resolve(root, observed, _parse_decision_answers(decide))
    decisions = _apply_decisions(decisions, decide or [])
    plan = build_plan(observed, target, decisions=decisions)
    print(_json(plan))
    return 0


def _apply_decisions(decisions: list[dict], answers: list[str]) -> list[dict]:
    """Annotate decisions that the resolver settled from operator answers.

    Resolution itself consumes the answers (see ``resolve_target``); this only
    normalises the record for callers that inspect ``plan.decisions``.
    """
    parsed = _parse_decision_answers(answers)
    for decision in decisions:
        answer = parsed.get(str(decision.get("id", "")))
        if answer is None:
            continue
        options = [str(o) for o in decision.get("options", [])]
        if options and answer not in options:
            raise ValueError(f"invalid value '{answer}' for {decision['id']}; "
                             f"expected one of {options}")
        decision["auto"] = True
        decision["requires_user_input"] = False
        decision["selected"] = answer
        decision["reason"] = f"operator selected '{answer}'"
    return decisions


def cmd_apply(root: str, state_root: str, resume: bool, dry_run: bool,
              decide: Optional[list[str]] = None, execute=None, trust=None,
              adapters=None, fixture_name: str | None = None) -> int:
    if trust is not None and not trust.passed:
        print("Stage A trust verification failed:\n" + _json(trust.to_dict()), file=sys.stderr)
        return 3
    observed = _discover(root, execute)
    contract_errors = _contract_validation(load_target())
    if contract_errors:
        print("Invalid component contracts:\n" + _json(contract_errors), file=sys.stderr)
        return 3
    # Preflight refuses unsupported source profiles before any transformation.
    # The machine, not a stored migration version, decides compatibility.
    compatibility = preflight_source(observed)
    if not compatibility.supported:
        print("Unsupported source state:\n" + _json(compatibility.to_dict()),
              file=sys.stderr)
        return 3
    target, decisions = _resolve(root, observed, _parse_decision_answers(decide))
    decisions = _apply_decisions(decisions, decide or [])
    plan = build_plan(observed, target, decisions=decisions)
    unresolved = [d for d in plan.decisions if d.get("requires_user_input")]
    if unresolved and not resume:
        print("Unresolved decisions:\n" + _json(unresolved), file=sys.stderr)
        return 2
    if fixture_name is not None and not dry_run:
        # Materialize the source tree so a later --verify probes the migrated
        # sandbox, not the pristine fixture. Dry runs remain side-effect free.
        write_apply_marker(fixture_name, state_root)
    # An injected executor (fixture) stages effects inside state_root; a live
    # apply mutates and verifies the real filesystem. Keeping these roots
    # separate lets one implementation serve both without path mismatches.
    system_root = Path(state_root) if execute is not None else Path(root)
    result = execute_plan(plan, state_root=state_root, execute=execute,
                          resume=resume, dry_run=dry_run, observed=observed,
                          adapters=adapters, system_root=system_root)
    print(_json(result))
    return 0 if result.status in ("success", "no-op", "dry_run") else 1


def cmd_verify(root: str, execute=None, trust=None, state_root=None) -> int:
    if trust is not None and not trust.passed:
        print("Stage A trust verification failed:\n" + _json(trust.to_dict()), file=sys.stderr)
        return 3
    observed = _discover(root, execute)
    target, _ = _resolve(root, observed)
    reports = validate_system(observed, target, root=root, execute=execute, state_root=state_root)
    serialized = [r.to_dict() for r in reports]
    print(_json({"passed": all(r.passed for r in reports), "reports": serialized}))
    return 0 if all(r.passed for r in reports) else 1


def cmd_repair(root: str, state_root: str, decide: Optional[list[str]] = None,
               execute=None, trust=None, adapters=None,
               fixture_name: str | None = None) -> int:
    # Re-discover first: the machine, not the journal, is the source of truth.
    return cmd_apply(root, state_root, resume=True, dry_run=False,
                     decide=decide, execute=execute, trust=trust, adapters=adapters,
                     fixture_name=fixture_name)


def cmd_history(state_root: str) -> int:
    from src.executor.journal import Journal
    j = Journal(state_root)
    print(_json(j.load()))
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="sunshine-evolve", description="Sunshine Evolution Engine")
    ap.add_argument("--root", default=None, help="filesystem root for discovery (testing)")
    ap.add_argument("--fixture", metavar="NAME",
                    help="use an offline fixture root and injected command executor")
    ap.add_argument("--state-root", default=str(STATE_ROOT), help="Sunshine state directory")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--check", action="store_true")
    g.add_argument("--plan", action="store_true")
    g.add_argument("--apply", action="store_true")
    g.add_argument("--verify", action="store_true")
    g.add_argument("--repair", action="store_true")
    g.add_argument("--history", action="store_true")
    ap.add_argument("--resume", action="store_true", help="with --apply: resume from journal after re-discovery")
    ap.add_argument("--dry-run", action="store_true", help="with --apply: simulate without changes")
    ap.add_argument("--decide", action="append", default=[], metavar="ID=VALUE",
                    help="answer a decision, e.g. --decide desktop-profile=hyprland")
    ap.add_argument("--trust-index", metavar="PATH",
                    help="signed Stage A repository index (production bootstrap input)")
    ap.add_argument("--trust-policy", metavar="PATH",
                    help="JSON trust policy containing pinned_roots and protocol limits")
    ap.add_argument("--trust-keyring", metavar="PATH",
                    help="dedicated GPG keyring used to verify Stage A signatures")
    ap.add_argument("--trust-report", metavar="PATH",
                    help="Stage A report written by the Rust bootstrap (with --trust-receipt)")
    ap.add_argument("--trust-receipt", metavar="PATH",
                    help="signed handoff receipt verified by Core before transformation")
    ap.add_argument("--adapter-dir", metavar="PATH",
                    help="directory of signed Rust adapter manifests to allow for this run")
    ap.add_argument("--adapter-artifact-root", metavar="PATH",
                    help="directory containing adapter binaries (default: Stage A index/report directory)")
    a = ap.parse_args(argv)
    root = a.root or DEFAULT_ROOT
    execute = None
    if a.fixture:
        if a.root is not None:
            print("--fixture and --root are mutually exclusive", file=sys.stderr)
            return 2
        if a.state_root == str(STATE_ROOT) and a.apply:
            print("refusing to run a fixture apply against the live state root; "
                  "pass an explicit --state-root sandbox", file=sys.stderr)
            return 2
        try:
            root = str(fixture_root(a.fixture))
            sandbox = None
            if a.apply and not a.dry_run:
                sandbox = a.state_root
            elif a.verify and applied_fixture(a.state_root, a.fixture):
                # After a fixture apply, verification must probe the migrated
                # state root. The pristine source tree would hide regressions.
                root = a.state_root
                sandbox = a.state_root
            elif a.repair and applied_fixture(a.state_root, a.fixture):
                sandbox = a.state_root
            # Dry-run and read-only commands must not create sandbox side effects.
            execute = fixture_executor(a.fixture, sandbox)
        except (ValueError, FileNotFoundError) as exc:
            print(str(exc), file=sys.stderr)
            return 2

    try:
        trust = _stage_a(a, execute)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Stage A configuration error: {exc}", file=sys.stderr)
        return 3
    if trust is not None and not trust.passed:
        print("Stage A trust verification failed:\n" + _json(trust.to_dict()), file=sys.stderr)
        return 3

    try:
        adapters = _adapter_registry(a, trust)
    except (OSError, ValueError) as exc:
        print(f"Adapter configuration error: {exc}", file=sys.stderr)
        return 3

    if a.history:
        return cmd_history(a.state_root)
    if a.check:
        return cmd_check(root, execute, trust)
    if a.plan:
        return cmd_plan(root, execute, trust, a.decide)
    if a.verify:
        return cmd_verify(root, execute, trust, a.state_root)
    if a.apply:
        return cmd_apply(root, a.state_root, a.resume, a.dry_run, a.decide, execute,
                         trust, adapters, a.fixture)
    if a.repair:
        return cmd_repair(root, a.state_root, a.decide, execute, trust, adapters, a.fixture)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
