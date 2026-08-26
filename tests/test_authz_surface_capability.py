from __future__ import annotations

from api.capabilities.authz_surface import (
    PrincipalProbe,
    RouteComparison,
    bfla_finding,
    boundary_established,
)
from api.check_registry import get_check_family
from api.runtime.capability_registry import CAPABILITY_REGISTRY
from api.scan.action_plan import ScanActionPlan, ScanActionPlanCompiler
from api.scan.contracts import SCAN_V2_FAMILY_NAMES, public_scan_contract
from api.scan.finalizer import finalize_scan_report
from tests.test_scan_action_compiler import _execution, _target
from tests.test_scan_finalizer import _result_with_observation_count
from tests.test_scan_orchestrator import SCAN_ID, _action


def _probe(status, sha, length=200, is_json=True, error=False):
    return PrincipalProbe(
        status=status, body_sha256=sha, body_len=length, is_json=is_json, error=error,
    )


def _route(route_id, anon, authed):
    return RouteComparison(
        route_id=route_id, url=f"https://app.example.test/{route_id}",
        anonymous=anon, authenticated=authed,
    )


_BOUNDARY = _route(
    "admin",
    (_probe(401, "z", 5, False), _probe(401, "z", 5, False)),
    (_probe(200, "y"), _probe(200, "y")),
)
_BFLA = _route(
    "users",
    (_probe(200, "h"), _probe(200, "h")),
    (_probe(200, "h"), _probe(200, "h")),
)


def test_boundary_requires_a_denied_anonymous_and_authenticated_success():
    assert boundary_established([_BOUNDARY, _BFLA]) is True
    # A fully public app never denies the anonymous principal: no boundary.
    assert boundary_established([_BFLA]) is False
    # A route both principals are denied is not a boundary either.
    denied_both = _route(
        "x", (_probe(403, "d"), _probe(403, "d")), (_probe(403, "d"), _probe(403, "d")),
    )
    assert boundary_established([denied_both]) is False


def test_identical_anonymous_access_to_authenticated_json_is_bfla():
    finding = bfla_finding(_BFLA)
    assert finding is not None
    assert finding["proof_contract"] == "authz_surface_anonymous_access/v1"
    assert finding["boundary_established"] is True
    assert finding["repetitions"] == 2


def test_bfla_contract_excludes_public_and_trivial_and_denied_routes():
    # Anonymous is denied while authenticated succeeds: correct auth, not BFLA.
    assert bfla_finding(_route(
        "ok", (_probe(403, "d"), _probe(403, "d")), (_probe(200, "y"), _probe(200, "y")),
    )) is None
    # Different bodies: not identical access.
    assert bfla_finding(_route(
        "diff", (_probe(200, "a"), _probe(200, "a")), (_probe(200, "b"), _probe(200, "b")),
    )) is None
    # A short static page reachable by both is not promoted.
    assert bfla_finding(_route(
        "home", (_probe(200, "s", 10, False), _probe(200, "s", 10, False)),
        (_probe(200, "s", 10, False), _probe(200, "s", 10, False)),
    )) is None
    # Unstable (flapping) responses do not promote.
    assert bfla_finding(_route(
        "flap", (_probe(200, "a"), _probe(200, "b")), (_probe(200, "a"), _probe(200, "b")),
    )) is None


def test_authz_surface_is_a_credential_gated_canonical_family():
    assert "authz_surface" in SCAN_V2_FAMILY_NAMES
    spec = get_check_family("authz_surface")
    assert spec.is_active is True and spec.requires_credentials is True
    assert get_check_family("bfla").name == "authz_surface"  # alias
    capability = CAPABILITY_REGISTRY.require("authz_surface.verify_batch")
    assert capability.required_approval == "active_testing"
    assert "authz_surface_proof" in capability.evidence_contract
    families = {item["name"] for item in public_scan_contract()["families"]}
    assert "authz_surface" in families


def test_compiler_emits_authz_surface_only_with_primary_auth():
    credentials = (
        {"profile_id": "primary-id", "version": 4, "digest": "e" * 64,
         "lane": "primary", "auth_kind": "form_login"},
    )
    with_auth = ScanActionPlanCompiler().compile(
        scan_id=SCAN_ID,
        execution_plan=_execution(include=("authz_surface",), active=True),
        target_binding=_target(), credential_profile_refs=credentials,
        action_scope="full",
    )
    assert "authz_surface.verify_batch" in {
        action.capability_name for action in with_auth.actions
    }

    # No primary principal: the family cannot run, so no batch is planned.
    without_auth = ScanActionPlanCompiler().compile(
        scan_id=SCAN_ID,
        execution_plan=_execution(include=("authz_surface",), active=True),
        target_binding=_target(), action_scope="full",
    )
    assert "authz_surface.verify_batch" not in {
        action.capability_name for action in without_auth.actions
    }


def test_finalizer_promotes_only_boundary_gated_authz_surface_proof():
    verify = _action("verify.authz_surface", 0, capability_name="authz_surface.verify_batch")
    final = _action("finalize.report", 1, dependencies=(verify.action_id,))
    plan = ScanActionPlan(
        scan_id=SCAN_ID, execution_plan_digest="b" * 64,
        target_binding_digest="a" * 64, actions=(verify, final),
    )
    results = {verify.action_id: _result_with_observation_count(verify, 2)}
    observations = {verify.action_id: (
        {
            "kind": "authz_surface_proof",
            "proof_state": "verified", "finding_verdict": "verified",
            "proof_contract": "authz_surface_anonymous_access/v1",
            "technique": "anonymous_equals_authenticated_repeated",
            "route_id": "users", "request_url": "https://app.example.test/api/Users",
            "anonymous_status": 200, "authenticated_status": 200,
            "response_body_sha256": "h" * 64, "boundary_established": True,
            "repetitions": 2,
        },
        {
            # Same signature but no established boundary must not promote.
            "kind": "authz_surface_proof",
            "proof_state": "verified", "finding_verdict": "verified",
            "proof_contract": "authz_surface_anonymous_access/v1",
            "route_id": "public", "request_url": "https://app.example.test/api/Public",
            "boundary_established": False, "repetitions": 2,
        },
    )}

    report = finalize_scan_report(
        plan=plan, target_url="https://app.example.test",
        action_results=results, observations=observations,
    )

    assert len(report["findings"]) == 1
    finding = report["findings"][0]
    assert finding["tool"] == "shakerscan_authz_surface"
    assert finding["severity"] == "high"
    assert finding["cwe"] == "CWE-862"
    assert finding["verified"] is True
    assert finding["evidence"]["canonical_capability"] == "authz_surface.verify_batch"
