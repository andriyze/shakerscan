"""A body candidate must be able to reach deterministic proof.

`execution_url_for_manifest_candidate` requires the candidate's field to appear in the
endpoint's `query_parameter_names`. A body candidate's field appears in
`body_field_names`, so every proof escalation raised "candidate identity conflicts with
its endpoint manifest" before it executed -- and the proof site then built a
`ReplayRequest` with `body=b""`, `body_mode="none"` anyway. The engine could obtain a body
signal and never turn it into the verified finding that signal exists to produce, which is
why login SQLi stays a miss.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))

SOURCE = (ROOT / "api" / "scan" / "action_adapter.py").read_text(encoding="utf-8")


def test_the_proof_sites_no_longer_use_the_query_only_resolver():
    """Only the single-candidate action lookup may still resolve to a bare URL."""
    assert SOURCE.count("execution_url_for_manifest_candidate(") <= 2, (
        "a proof site still resolves candidates to a URL, which body candidates cannot be"
    )
    for label in ("canonical SQLi candidate", "canonical NoSQLi candidate"):
        block = SOURCE[SOURCE.index(label) - 700:SOURCE.index(label) + 200]
        assert "proof_request_for_candidate(" in block, label
        assert 'body_mode="none"' not in block, label


def test_a_body_proof_requires_mutation_authority():
    """A body candidate mutates; it needs the authority the private request path demands."""
    for label in ("canonical SQLi candidate", "canonical NoSQLi candidate"):
        block = SOURCE[SOURCE.index(label) - 900:SOURCE.index(label)]
        assert "allow_state_changing_http" in block, label
        assert "approval_receipt_id" in block, label


def test_the_helper_builds_a_well_formed_body_for_each_content_type():
    import json as _json
    from scan.action_adapter import proof_request_for_candidate

    class _Manifest:
        pass

    def _resolved(**overrides):
        base = {
            "method": "POST", "url": "https://target.test/rest/user/login",
            "content_type": "application/json", "field_name": "email",
            "body_field_names": ["email", "password"],
        }
        base.update(overrides)
        return base

    import scan.action_adapter as adapter
    original = adapter.execution_request_for_manifest_candidate
    try:
        adapter.execution_request_for_manifest_candidate = lambda *a, **k: _resolved()
        request = proof_request_for_candidate(
            _Manifest(), _Manifest(), 0, request_id="c", ordinal=0, name="n",
            headers=(("X-Test", "1"),), authenticated=False,
        )
        assert request.method == "POST"
        assert request.body_mode == "raw"
        assert _json.loads(request.body.decode()) == {
            "email": "shakerscan", "password": "shakerscan",
        }
        assert ("Content-Type", "application/json") in request.headers

        adapter.execution_request_for_manifest_candidate = lambda *a, **k: _resolved(
            content_type="application/x-www-form-urlencoded",
        )
        form = proof_request_for_candidate(
            _Manifest(), _Manifest(), 0, request_id="c", ordinal=0, name="n",
            headers=(), authenticated=True,
        )
        assert form.body == b"email=shakerscan&password=shakerscan"
        assert ("Content-Type", "application/x-www-form-urlencoded") in form.headers
        assert form.auth_type == "broker_session"

        # A query candidate is unchanged: a bare URL with no body.
        adapter.execution_request_for_manifest_candidate = lambda *a, **k: _resolved(
            method="GET", body_field_names=[], content_type=None,
            url="https://target.test/search?q=shakerscan",
        )
        query = proof_request_for_candidate(
            _Manifest(), _Manifest(), 0, request_id="c", ordinal=0, name="n",
            headers=(), authenticated=False,
        )
        assert query.body == b""
        assert query.body_mode == "none"
        assert query.method == "GET"
    finally:
        adapter.execution_request_for_manifest_candidate = original


def test_a_body_attempt_is_charged_to_the_state_changing_ledger():
    """`max_state_changing_requests` exists to bound mutation traffic and never decremented.

    Every request a body attempt sends is a mutation, so its state-changing cost equals its
    request cost. The body floors omitted the dimension, so a body attempt consumed nothing
    from the ceiling that exists to bound it. (The permission was always enforced --
    `work_manifests` only creates a body candidate when `allow_state_changing_http` is set
    -- so this was missing accounting, not missing authority.)
    """
    from scan.external_process import BATCH_ATTEMPT_BODY_FLOORS, batch_attempt_floor

    for capability, floor in BATCH_ATTEMPT_BODY_FLOORS.items():
        assert floor["state_changing_requests"] == floor["http_requests"], capability
        resolved = batch_attempt_floor(capability, body_candidate=True)
        assert resolved["state_changing_requests"] == floor["state_changing_requests"]
        # A query attempt sends no mutations and must not be charged for any.
        assert "state_changing_requests" not in batch_attempt_floor(capability)


def test_only_a_profile_that_can_fund_a_body_attempt_reserves_for_one():
    from scan.action_plan import _BATCH_PROFILES
    from scan.contracts import BUDGET_PROFILES
    from scan.external_process import BATCH_ATTEMPT_BODY_FLOORS

    for profile, batches in _BATCH_PROFILES.items():
        ceiling = BUDGET_PROFILES[profile].ledger_limits()["state_changing_requests"]
        for capability, floor in BATCH_ATTEMPT_BODY_FLOORS.items():
            entry = batches.get(capability)
            if entry is None:
                continue
            reserved = int(entry[1].get("state_changing_requests", 0))
            assert reserved <= ceiling, (
                f"{profile}/{capability} reserves {reserved} mutations against a "
                f"{ceiling} ceiling"
            )
            if reserved:
                assert reserved >= floor["state_changing_requests"], (
                    f"{profile}/{capability} reserves {reserved}, below the "
                    f"{floor['state_changing_requests']} one attempt costs -- it could "
                    "never fund the attempt it reserved for"
                )
