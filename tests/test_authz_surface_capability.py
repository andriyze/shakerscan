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
    assert finding["cwe"] == "CWE-862"
    assert finding["evidence"]["canonical_capability"] == "authz_surface.verify_batch"
    # The differential shows the endpoint is public; only knowing the function
    # is privileged would make that a broken control, and nothing here does.
    # It is reported for verification rather than asserted as proven.
    assert finding["severity"] == "medium"
    assert finding["verified"] is False
    assert finding["suspected"] is True
    assert finding["needs_verification"] is True


# --- Stored password hashes in a signed-in API response ------------------------------------

from api.capabilities.authz_surface import (  # noqa: E402
    account_password_hashes,
    password_hash_disclosure_finding,
)

_BCRYPT_ADMIN = "$2b$10$" + "Qm9yZWRBZG1pbkhhc2hWYWx1ZUZvclRlc3RzT25seS4uLi4uLi4uLi4u"[:53]
_BCRYPT_USER = "$2b$10$" + "VXNlclR3b0hhc2hWYWx1ZUZvclRlc3RzT25seS4uLi4uLi4uLi4uLi4u"[:53]


def test_password_hash_fields_are_found_in_json_bodies():
    body = (
        '{"id":1,"username":"admin","role":"admin","salary":182000,"password_hash":"%s"}'
        % _BCRYPT_ADMIN
    ).encode()
    assert account_password_hashes(body, is_json=True) == [("password_hash", _BCRYPT_ADMIN)]
    # An MD5 digest under the account's password key (Juice Shop's user records).
    md5 = '{"data":[{"id":1,"email":"a@b.test","password":"0192023a7bbd73250516f069df18b500"}]}'
    assert account_password_hashes(md5.encode(), is_json=True) == [
        ("data[0].password", "0192023a7bbd73250516f069df18b500"),
    ]


def test_ordinary_values_are_not_password_hashes():
    for body in (
        # A hex id under an unrelated key, a hex-looking placeholder, a plaintext password.
        '{"request_id":"0192023a7bbd73250516f069df18b500"}',
        '{"password":"00000000000000000000000000000000"}',
        '{"password":"hunter2-but-long-enough"}',
        '{"password_hash":"[REDACTED]"}',
        '"not an object"',
    ):
        assert account_password_hashes(body.encode(), is_json=True) == [], body
    # Not JSON: never parsed.
    assert account_password_hashes(_BCRYPT_ADMIN.encode(), is_json=False) == []


def _hash_probe(status, sha, digests=(), fields=()):
    return PrincipalProbe(
        status=status, body_sha256=sha, body_len=200, is_json=True,
        hash_digests=tuple(digests), hash_fields=tuple(fields),
    )


def test_another_accounts_hash_read_by_one_principal_is_high():
    denied = (_probe(401, "z", 5, False), _probe(401, "z", 5, False))
    me = _route("me", denied, (_hash_probe(200, "m", ["d-user"], ["password_hash"]),) * 2)
    other = _route("users/1", denied, (_hash_probe(200, "u", ["d-admin"], ["password_hash"]),) * 2)
    seen = {"d-user", "d-admin"}
    finding = password_hash_disclosure_finding(other, seen)
    assert finding["proof_contract"] == "authz_surface_password_hash_disclosure/v1"
    assert finding["other_accounts_hashes"] is True
    assert finding["anonymous_reads_hashes"] is False
    assert finding["hash_fields"] == [{"field": "password_hash"}]
    # The principal's own record alone shows one hash: excessive exposure, not cross-account.
    alone = password_hash_disclosure_finding(me, {"d-user"})
    assert alone["other_accounts_hashes"] is False


def test_hash_disclosure_needs_the_same_hashes_on_every_read():
    flapping = _route("x", (), (
        _hash_probe(200, "a", ["d1"]), _hash_probe(200, "a", ["d2"]),
    ))
    assert password_hash_disclosure_finding(flapping, {"d1", "d2"}) is None
    none = _route("y", (), (_hash_probe(200, "b"), _hash_probe(200, "b")))
    assert password_hash_disclosure_finding(none, set()) is None
    denied = _route("z", (), (_hash_probe(403, "c", ["d1"]), _hash_probe(403, "c", ["d1"])))
    assert password_hash_disclosure_finding(denied, {"d1"}) is None


def test_finalizer_reports_another_accounts_password_hash_as_verified_high():
    verify = _action("verify.authz_surface", 0, capability_name="authz_surface.verify_batch")
    final = _action("finalize.report", 1, dependencies=(verify.action_id,))
    plan = ScanActionPlan(
        scan_id=SCAN_ID, execution_plan_digest="b" * 64,
        target_binding_digest="a" * 64, actions=(verify, final),
    )
    results = {verify.action_id: _result_with_observation_count(verify, 1)}
    observations = {verify.action_id: ({
        "kind": "authz_surface_proof",
        "proof_state": "verified", "finding_verdict": "verified",
        "proof_contract": "authz_surface_password_hash_disclosure/v1",
        "technique": "authenticated_response_password_hash_fields_repeated",
        "route_id": "users", "request_url": "https://app.example.test/hub/api/users/1",
        "anonymous_status": 401, "authenticated_status": 200,
        "response_body_sha256": "h" * 64, "hash_count": 1,
        "hash_fields": [{"field": "password_hash"}],
        "other_accounts_hashes": True, "anonymous_reads_hashes": False,
        "repetitions": 2,
    },)}
    report = finalize_scan_report(
        plan=plan, target_url="https://app.example.test",
        action_results=results, observations=observations,
    )
    assert len(report["findings"]) == 1
    finding = report["findings"][0]
    assert finding["title"] == "API returns other accounts' password hashes"
    assert finding["severity"] == "high"
    assert finding["cwe"] == "CWE-639"
    assert finding["verified"] is True
    assert finding["evidence"]["hash_fields"] == [{"field": "password_hash"}]


def test_two_batches_each_with_one_hash_still_prove_another_accounts_hash():
    """/me and /users/1 fell into different slices on a live Scan: each batch saw one hash."""
    first = _action("verify.authz_surface", 0, capability_name="authz_surface.verify_batch")
    second = _action("verify.authz_surface.001", 1, capability_name="authz_surface.verify_batch")
    final = _action("finalize.report", 2, dependencies=(first.action_id, second.action_id))
    plan = ScanActionPlan(
        scan_id=SCAN_ID, execution_plan_digest="b" * 64,
        target_binding_digest="a" * 64, actions=(first, second, final),
    )

    def proof(path, digest):
        return {
            "kind": "authz_surface_proof", "proof_state": "verified", "finding_verdict": "verified",
            "proof_contract": "authz_surface_password_hash_disclosure/v1",
            "route_id": path, "request_url": f"https://app.example.test{path}",
            "authenticated_status": 200, "anonymous_status": 401, "hash_count": 1,
            "hash_digests": [digest], "hash_fields": [{"field": "password_hash"}],
            "other_accounts_hashes": False, "anonymous_reads_hashes": False, "repetitions": 2,
        }

    report = finalize_scan_report(
        plan=plan, target_url="https://app.example.test",
        action_results={
            first.action_id: _result_with_observation_count(first, 1),
            second.action_id: _result_with_observation_count(second, 1),
        },
        observations={
            first.action_id: (proof("/hub/api/me", "hmac-sha256-x:own"),),
            second.action_id: (proof("/hub/api/users/1", "hmac-sha256-x:admin"),),
        },
    )
    assert {f["severity"] for f in report["findings"]} == {"high"}
    assert all(f["evidence"]["distinct_hashes_read_in_scan"] == 2 for f in report["findings"])
