from __future__ import annotations

import uuid

import pytest

from api.scan.action_plan import (
    ScanAction,
    ScanActionPlan,
    ScanActionPlanError,
    digest_input_bindings,
)


SCAN_ID = str(uuid.UUID("00000000-0000-0000-0000-000000000101"))
TARGET_DIGEST = "a" * 64
EXECUTION_DIGEST = "b" * 64
INPUT_DIGEST = "c" * 64


def _action(
    action_id: str,
    ordinal: int,
    *,
    dependencies: tuple[str, ...] = (),
    args=None,
) -> ScanAction:
    return ScanAction(
        action_id=action_id,
        stage="discover_surface",
        ordinal=ordinal,
        capability_name="web.crawl",
        capability_args=args or {"manifest_ref": "endpoint-manifest-1", "limit": 10},
        target_binding_digest=TARGET_DIGEST,
        input_binding_digest=INPUT_DIGEST,
        requested_budget={"tool_wall_seconds": 10, "http_requests": 10},
        placement={"backend": "any", "required_capabilities": ["katana"]},
        dependencies=dependencies,
        required=True,
        supporting=True,
        output_schema="katana-lines/v1",
    )


def test_scan_action_and_plan_are_immutable_canonical_and_digest_bound():
    args = {"limit": 10, "refs": ["b", "a"]}
    first = _action("discover.probe", 0, args=args)
    second = _action("discover.crawl", 1, dependencies=("discover.probe",))
    plan = ScanActionPlan(
        scan_id=SCAN_ID,
        execution_plan_digest=EXECUTION_DIGEST,
        target_binding_digest=TARGET_DIGEST,
        actions=(first, second),
    )

    args["limit"] = 999
    assert first.capability_args["limit"] == 10
    assert len(first.action_digest) == 64
    assert len(plan.plan_digest) == 64
    assert ScanActionPlan.from_dict(plan.canonical_dict()) == plan
    assert ScanAction.from_dict(first.canonical_dict()) == first

    tampered = plan.canonical_dict()
    tampered["actions"][0]["requested_budget"]["http_requests"] = 11
    with pytest.raises(ScanActionPlanError, match="action_digest"):
        ScanActionPlan.from_dict(tampered)


def test_action_plan_rejects_forward_missing_and_cross_target_dependencies():
    with pytest.raises(ScanActionPlanError, match="precede"):
        ScanActionPlan(
            scan_id=SCAN_ID,
            execution_plan_digest=EXECUTION_DIGEST,
            target_binding_digest=TARGET_DIGEST,
            actions=(
                _action("discover.probe", 0, dependencies=("discover.crawl",)),
                _action("discover.crawl", 1),
            ),
        )

    wrong_target = _action("discover.crawl", 0).canonical_dict()
    wrong_target["target_binding_digest"] = "d" * 64
    wrong_target["action_digest"] = None
    reconstructed = ScanAction(**{
        key: value for key, value in wrong_target.items() if key != "action_digest"
    })
    with pytest.raises(ScanActionPlanError, match="target binding differs"):
        ScanActionPlan(
            scan_id=SCAN_ID,
            execution_plan_digest=EXECUTION_DIGEST,
            target_binding_digest=TARGET_DIGEST,
            actions=(reconstructed,),
        )


def test_input_binding_digest_is_order_independent_and_rejects_ambiguous_values():
    left = digest_input_bindings({
        "credential_profile": {"id": "profile-1", "version": 4},
        "manifest_digests": ["a" * 64, "b" * 64],
    })
    right = digest_input_bindings({
        "manifest_digests": ["a" * 64, "b" * 64],
        "credential_profile": {"version": 4, "id": "profile-1"},
    })
    assert left == right
    with pytest.raises(ScanActionPlanError, match="unsupported value type"):
        digest_input_bindings({"unstable": 1.25})


@pytest.mark.parametrize(
    "secret_input",
    (
        {"authorization": "Bearer canary"},
        {"nested": {"cookie": "session=canary"}},
        {"request": {"body": "canary"}},
        {"argv": ["curl", "https://outside.test"]},
    ),
)
def test_action_contract_rejects_secret_and_untrusted_execution_material(secret_input):
    with pytest.raises(ScanActionPlanError, match="action input key is forbidden"):
        _action("verify.canary", 0, args=secret_input)


def test_static_credentials_allocate_no_auth_input_action():
    """Only an interactive credential gets an ``inputs.auth_*`` action.

    A bearer token is resolved worker-side at execution and needs no session
    established first. Callers allocated a zero-cost budget entry per
    credential regardless, naming actions the compiler never creates, so the
    plan was rejected with "action budget allocation contains unknown actions"
    -- and every scan carrying a static credential failed that way, which is
    most authenticated scans.
    """
    from api.scan.action_plan import interactive_auth_input_action_ids

    static = [
        {"lane": "primary", "auth_kind": "bearer_token"},
        {"lane": "secondary", "auth_kind": "api_key_header"},
        {"lane": "primary", "auth_kind": "cookie"},
    ]
    assert interactive_auth_input_action_ids(static) == ()

    interactive = [
        {"lane": "primary", "auth_kind": "form_login"},
        {"lane": "secondary", "auth_kind": "oauth_password"},
    ]
    assert interactive_auth_input_action_ids(interactive) == (
        "inputs.auth_primary", "inputs.auth_secondary",
    )
    # Lanes the compiler never gives an action to are excluded either way.
    assert interactive_auth_input_action_ids(
        [{"lane": "service", "auth_kind": "form_login"},
         {"lane": "ssh", "auth_kind": "ssh_password"}]
    ) == ()


def test_allocation_and_compilation_share_one_rule():
    """Both transports delegate credential allocation to the one round compiler."""
    import pathlib
    root = pathlib.Path(__file__).resolve().parent.parent
    shared = (root / "api/scan/continuation_rounds.py").read_text(encoding="utf-8")
    broker = (root / "api/fleet_routes/router.py").read_text(encoding="utf-8")
    assert "interactive_auth_input_action_ids(credential_refs)" in shared
    assert "prepared = compile_next_continuation(" in broker
    assert 'f"inputs.auth_{str(item.get(' not in shared + broker
