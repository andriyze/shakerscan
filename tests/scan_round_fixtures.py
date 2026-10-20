"""Unit-test fixtures that compile an admitted Scan and its continuation rounds.

These are planner fixtures, not live Scans: discovery is replaced by operator-supplied
endpoints (``custom_endpoints``), and every settled action is a synthetic result whose
consumption a test chooses. They drive the real admission compiler, the real round compiler
and the real allocator, so a test can read exactly what each round would append.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from typing import Any, Callable, Mapping

from api.scan.admission_actions import _compile_scan_admission_action_authority
from api.scan.capability_result import CapabilityResultReason, CapabilityResultStatus
from api.scan.continuation_rounds import compile_next_continuation
from api.scan.contracts import resolve_scan_contract
from api.scan.work_manifests import build_canonical_scan_nuclei_template_manifest
from tests.test_scan_continuation import SCAN_ID, _target
from tests.test_scan_orchestrator import _result

ACTIVE_FAMILIES = ("recon", "nuclei_passive", "nuclei_active", "xss", "sqli")
BODY_ENDPOINT = 'POST /api/login json:{"username":"a","password":"b"}'


def custom_endpoints(*, endpoints: int, queries: int, body: bool) -> list[str]:
    """Operator endpoints giving ``endpoints`` manifest entries (the origin is one of them)."""
    plain = max(0, int(endpoints) - int(queries) - int(bool(body)) - 1)
    rows = [f"GET /q{index:03d}?q=1" for index in range(int(queries))]
    rows += [f"GET /p{index:03d}" for index in range(plain)]
    if body:
        rows.append(BODY_ENDPOINT)
    return rows


def admitted_round_fixture(
    profile: str,
    *,
    endpoints: int,
    queries: int,
    body: bool = False,
    state_changing: bool = True,
    families: tuple[str, ...] = ACTIVE_FAMILIES,
    advanced: Mapping[str, Any] | None = None,
    extra_options: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """The keyword arguments ``compile_next_continuation`` takes for a freshly admitted Scan."""
    target = _target()
    contract = resolve_scan_contract(
        budget_profile=profile,
        policy={
            "active_testing": True,
            "allow_state_changing_http": bool(state_changing),
            "include_families": list(families),
        },
        advanced=dict(advanced) if advanced else None,
        approval_receipt_id="approval-1",
    )
    template = build_canonical_scan_nuclei_template_manifest(
        scan_id=SCAN_ID, target_binding_digest=target.digest,
        include_active="nuclei_active" in families,
    )
    parent, allocation = _compile_scan_admission_action_authority(
        scan_id=SCAN_ID, scan_contract=contract, target_binding=target,
        template_manifest_ref=template.reference().canonical_dict(),
    )
    return dict(
        parent_plan=parent, allocation=allocation, parent_results={},
        execution_plan=contract.execution_plan, target=target,
        target_url="https://app.example.test", observations={}, request_manifests=(),
        options={
            # The flattened plan snapshots every Scan carries (its policy decides whether the
            # round's candidate manifest holds request-body candidates).
            **contract.execution_plan.option_metadata(),
            "template_manifest_ref": template.reference().canonical_dict(),
            "custom_endpoints": custom_endpoints(endpoints=endpoints, queries=queries, body=body),
            **dict(extra_options or {}),
        },
    )


Settlement = tuple[CapabilityResultStatus, "CapabilityResultReason | None", Mapping[str, int]]


def settle_lightly(action: Any) -> Settlement:
    """Success, spending one unit of every held dimension."""
    return (
        CapabilityResultStatus.SUCCESS, None,
        {name: min(1, int(value)) for name, value in action.requested_budget.items()},
    )


def settle_round(
    fixture: dict[str, Any],
    outcome: Callable[[Any], Settlement] = settle_lightly,
    *,
    observations: Callable[[Any], tuple[Mapping[str, Any], ...]] | None = None,
) -> None:
    """Settle every action of the parent plan that has no result yet."""
    for action in fixture["parent_plan"].actions:
        if action.action_id in fixture["parent_results"]:
            continue
        status, reason, consumed = outcome(action)
        fixture["parent_results"][action.action_id] = replace(
            _result(action, status=status, reason=reason),
            budget_consumed={
                name: min(int(action.requested_budget.get(name, 0)), int(amount))
                for name, amount in consumed.items() if name in action.requested_budget
            },
            result_digest=None,
        )
        if observations is not None:
            rows = observations(action)
            if rows:
                fixture["observations"][action.action_id] = tuple(rows)


def compile_round(fixture: dict[str, Any], revision_number: int) -> Any:
    """Compile one round and make its plan the parent of the next."""
    prepared = compile_next_continuation(**fixture, revision_number=revision_number)
    fixture["parent_plan"] = prepared.plan
    fixture["options"] = {**fixture["options"], **prepared.options}
    return prepared


def appended_actions(prepared: Any, parent_count: int) -> tuple[Any, ...]:
    return tuple(prepared.plan.actions[parent_count:])


def _sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), default=dict).encode()
    ).hexdigest()


def action_rows(actions: Any) -> list[dict[str, Any]]:
    """Every planned fact a round freezes into its actions, in plan order.

    The readable facts (id, capability, slice, frozen budget) are kept as they are; the bulky
    ones (the capability arguments and the dependency list) as digest prefixes.
    """
    return [
        {
            "action_id": action.action_id,
            "capability_name": action.capability_name,
            "stage": action.stage,
            "slice": json.loads(json.dumps(action.capability_args.get("slice"), default=dict)),
            "manifest_entries": action.capability_args.get("manifest_entries"),
            "extends": action.capability_args.get("extends"),
            "requested_budget": dict(sorted(action.requested_budget.items())),
            "required": bool(action.required),
            # The input binding digest covers every capability argument and the plan's
            # manifest and authority refs; a prefix pins them.
            "input_binding": str(action.input_binding_digest)[:16],
            "dependencies": _sha256(list(action.dependencies))[:16],
        }
        for action in actions
    ]
