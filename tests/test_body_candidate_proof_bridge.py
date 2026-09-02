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

        # A dotted field path rebuilds nested JSON, not a literal flat key, so the
        # verifier's dotted-path mutator lands on a real node instead of raising.
        adapter.execution_request_for_manifest_candidate = lambda *a, **k: _resolved(
            body_field_names=["profile.email", "password"],
        )
        nested = proof_request_for_candidate(
            _Manifest(), _Manifest(), 0, request_id="c", ordinal=0, name="n",
            headers=(), authenticated=False,
        )
        assert _json.loads(nested.body.decode()) == {
            "profile": {"email": "shakerscan"}, "password": "shakerscan",
        }

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


def test_nosqli_reservation_funds_more_than_two_body_fields():
    """The verifier spends four requests per declared field.

    An 8-request-per-candidate reservation funded only two fields and marked
    ordinary larger bodies partial; fund at least four fields per candidate.
    """
    from scan.action_plan import _BATCH_PROFILES

    for profile in ("fast", "balanced", "thorough"):
        count, budget = _BATCH_PROFILES[profile]["nosqli.verify_batch"]
        per_candidate = budget["http_requests"] // count
        assert per_candidate >= 16, (profile, per_candidate)


def test_body_attempts_are_mutation_metered_with_affordable_profile_holds():
    from scan.external_process import BATCH_ATTEMPT_BODY_FLOORS
    from scan.action_plan import _BATCH_PROFILES
    from scan.contracts import BUDGET_PROFILES

    for capability, floor in BATCH_ATTEMPT_BODY_FLOORS.items():
        assert floor["state_changing_requests"] == floor["http_requests"]
    thorough = _BATCH_PROFILES["thorough"]["sqli.verify_batch"][1]
    ceiling = BUDGET_PROFILES["thorough"].max_state_changing_requests
    assert thorough["state_changing_requests"] == 480
    assert 2 * thorough["state_changing_requests"] <= ceiling
