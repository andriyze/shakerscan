"""A retest replayed against a refused baseline never reads as fixed.

A retest compares payload answers with the target's answer to the original request. When that
answer is a refusal (a session-less replay answered 401, a redirect to sign-in, a WAF's 403),
reproducing nothing proves nothing fixed: the verdict is inconclusive and the finding stays
open. Fixtures only.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from scanner_tools import proof_of_exploit
from worker_handlers.retest_outcome import classify_retest_outcome


def test_a_retest_replayed_against_a_refusal_never_reads_as_fixed(monkeypatch):
    async def not_proven(*_args, **_kwargs):
        return proof_of_exploit.ExploitProof()

    async def refused_fetch(url, **_kwargs):
        return {"status_code": 401, "headers": {}, "body": "", "final_url": url}

    monkeypatch.setattr(proof_of_exploit, "_prove_sqli", not_proven)
    monkeypatch.setattr(proof_of_exploit, "fetch_with_capture", refused_fetch)
    proof = asyncio.run(proof_of_exploit.prove_sqli("https://app.example.test/api/orders?id=1", "id"))
    assert proof.evidence_type == "authentication_required"
    status, verdict, reason = classify_retest_outcome(
        proof=proof.to_dict(), proven=False, confidence=proof.confidence,
        inputs={"original_url": "https://app.example.test/api/orders?id=1"},
        internal_target_authorized=True,
    )
    assert (status, verdict) == ("inconclusive", "inconclusive"), reason
    assert "stays open" in reason
    # The same replay answered normally is still "likely fixed", as before.
    status, verdict, _ = classify_retest_outcome(
        proof={"evidence_type": ""}, proven=False, confidence=0.6,
        inputs={"original_url": "https://app.example.test/api/orders?id=1"},
        internal_target_authorized=True,
    )
    assert verdict == "likely_fixed"


def test_a_sign_in_redirect_on_a_retest_baseline_is_refused_but_a_login_endpoint_is_not():
    assert proof_of_exploit.baseline_refusal(
        "https://app.example.test/hub/orders?id=1",
        {"status_code": 200, "headers": {}, "final_url": "https://app.example.test/hub/login"},
    ) == "authentication_required"
    assert proof_of_exploit.baseline_refusal(
        "https://app.example.test/hub/login", {"status_code": 401, "headers": {}}, body=True,
    ) is None
    # Only a body sent to a sign-in path is exempt, by whole segments.
    for path in ("/api/authors?id=1", "/api/sessions/123/notes", "/api/loginhistory",
                 "/api/users/authorization"):
        assert proof_of_exploit.baseline_refusal(
            f"https://app.example.test{path}", {"status_code": 401, "headers": {}}, body=True,
        ) == "authentication_required", path
    assert proof_of_exploit.baseline_refusal(
        "https://app.example.test/hub/login?next=1", {"status_code": 401, "headers": {}},
    ) == "authentication_required", "a GET is not a login attempt"
    assert proof_of_exploit.baseline_refusal(
        "https://app.example.test/api/orders", {"status_code": 403, "headers": {}},
    ) == "target_refused"


def test_a_refused_retest_does_not_resolve_its_finding():
    # The retest worker only records a verdict; the finding row is resolved by an analyst, by
    # an opt-in high-confidence false_positive retest, or by release retirement of header and
    # exposure duplicates after a complete-coverage scan. An inconclusive verdict is none.
    _status, verdict, _ = classify_retest_outcome(
        proof={"evidence_type": "target_refused"}, proven=False, confidence=0.8,
        inputs={"original_url": "https://app.example.test/x?id=1"}, internal_target_authorized=True,
    )
    assert verdict not in {"false_positive", "likely_fixed"}
    assert SimpleNamespace(verdict=verdict).verdict == "inconclusive"


def test_a_focused_ai_gate_replay_the_target_refused_is_not_likely_fixed():
    from worker_handlers.retest_outcome import replay_refusal

    refused = {
        "findings": [{"evidence": {"note": "authentication_required"}}],
        "coverage": {"family_coverage": [{"family": "ai", "reason": "action_incomplete"}]},
        "action_results": [{"status": "partial", "reason_code": "authentication_required",
                            "errors": ["authentication_required:401"]}],
    }
    assert replay_refusal(refused) == "authentication_required"
    assert replay_refusal({"ai_gate": {"errors": ["target_refused:403"]}}) == "target_refused:403"
    # A finding's own text is never read, and prose is not a token.
    assert replay_refusal({
        "findings": [{"reason": "authentication_required"}],
        "ai_gate": {"transcripts": ["the model said authentication_required is missing"]},
    }) is None
