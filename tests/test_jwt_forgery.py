"""How an application handles its own JSON Web Token: the pure checks and the batch that runs them."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import urllib.parse
import uuid

import pytest

import scan.action_adapter as action_adapter_module
from capabilities import jwt_forgery
from runtime.models import ScanPolicy
from runtime.request_replay_executor import ReplayTransportResult
from scan.action_plan import ScanActionPlan
from scan.finalizer import finalize_scan_report
from scan.work_manifests import build_endpoint_manifest

from tests.test_scan_action_adapter import TARGET, Backend, _action, _dispatcher, _lease, _noop
from tests.test_scan_finalizer import _result_with_observation_count


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _token(secret: str = "a-long-random-secret-nobody-would-guess", alg: str = "HS256") -> str:
    head = _b64(json.dumps({"alg": alg, "typ": "JWT"}, separators=(",", ":")).encode())
    claims = _b64(json.dumps({"sub": "user-2", "role": "user"}, separators=(",", ":")).encode())
    signature = hmac.new(secret.encode(), f"{head}.{claims}".encode(), hashlib.sha256).digest()
    return f"{head}.{claims}.{_b64(signature)}"


def _parts(token):
    head, claims, signature = token.split(".")
    pad = lambda value: value + "=" * (-len(value) % 4)  # noqa: E731
    return (json.loads(base64.urlsafe_b64decode(pad(head))),
            json.loads(base64.urlsafe_b64decode(pad(claims))), signature)


def _valid(token: str, secret: str) -> bool:
    head, claims, signature = token.split(".")
    expected = hmac.new(secret.encode(), f"{head}.{claims}".encode(), hashlib.sha256).digest()
    return _b64(expected) == signature


def test_only_a_signed_compact_token_is_a_bearer_jwt():
    token = _token()
    assert jwt_forgery.bearer_jwt({"Authorization": f"Bearer {token}"}) == token
    assert jwt_forgery.bearer_jwt((("authorization", f"bearer {token}"),)) == token
    for value in ("Bearer opaque-session-token", "Basic dXNlcjpwYXNz", f"Bearer {token}.x.y",
                  "Bearer a.b.c", f"Token {token}"):
        assert jwt_forgery.bearer_jwt({"Authorization": value}) is None
    assert jwt_forgery.bearer_jwt({"Cookie": "a=b"}) is None


def test_forged_tokens_never_change_a_claim():
    token = _token()
    _header, claims, signature = _parts(token)
    altered = jwt_forgery.altered_signature(token)
    assert altered.split(".")[:2] == token.split(".")[:2] and altered.split(".")[2] != signature
    for spelling in ("none", "None", "NONE", "nOnE"):
        unsigned = jwt_forgery.unsigned(token, spelling)
        header, same_claims, empty = _parts(unsigned)
        assert header["alg"] == spelling and same_claims == claims and empty == ""
    resigned = jwt_forgery.signed_with(token, "secret")
    _header, same, _signature = _parts(resigned)
    # The same claims, none added: only the token differs from the principal's own.
    assert same == claims and resigned != token
    assert _valid(resigned, "secret")


def test_a_listed_secret_is_found_offline_and_a_random_one_is_not():
    assert jwt_forgery.guessed_secret(_token("secret")) == "secret"
    assert jwt_forgery.guessed_secret(_token()) is None
    # An asymmetric token has no shared secret to guess.
    assert jwt_forgery.guessed_secret(_token(alg="RS256")) is None


def _check(token, accepts, *, requests=20, without_bearer=(401, "refused"), accepted_body="page"):
    """``sent`` holds the forged tokens only; the first request is the one without a bearer."""
    sent: list[str] = []
    calls: list[str | None] = []

    async def send(forged):
        calls.append(forged)
        if forged is None:
            return without_bearer
        sent.append(forged)
        return (200, accepted_body if accepts(forged) else "error") if accepts(forged) else (401, "refused")

    proof = asyncio.run(jwt_forgery.check_token_handling(
        token, send=send, accepted_status=200, accepted_digest="page",
        left=lambda: requests - len(calls),
    ))
    assert calls[:1] in ([None], [])
    return proof, sent


def test_a_route_that_accepts_an_altered_signature_does_not_verify_it():
    proof, sent = _check(_token(), lambda forged: True)
    assert proof["technique"] == "jwt_signature_not_verified_repeated"
    assert proof["proof_contract"] == "authz_surface_jwt_forgery/v1" and proof["repetitions"] == 2
    # The altered token twice; nothing else is needed.
    assert len(sent) == 2 and sent[0] == sent[1]


def test_alg_none_is_reported_only_when_the_altered_signature_was_refused():
    proof, sent = _check(_token(), lambda forged: forged.endswith(".") and _parts(forged)[0]["alg"] == "None")
    assert proof["technique"] == "jwt_alg_none_accepted_repeated"
    assert proof["none_spelling"] == "None"
    # Altered signature (refused), "none" (refused), "None" twice.
    assert len(sent) == 4


def test_a_guessable_secret_is_proven_by_the_signature_and_shown_by_acceptance():
    token = _token("secret")
    proof, sent = _check(token, lambda forged: _valid(forged, "secret"))
    assert proof["technique"] == "jwt_weak_hmac_secret_reproduced"
    assert proof["secret_in_common_list"] is True and proof["forged_token_accepted"] is True
    assert proof["secret_length"] == 6
    # The secret and the token are never part of an observation.
    assert "secret\"" not in json.dumps(proof) and token not in json.dumps(proof)
    assert proof["secret_values_visible"] is False
    assert _parts(sent[-1])[1] == _parts(token)[1] and sent[-1] != token


def test_a_route_that_checks_its_tokens_yields_nothing():
    token = _token()
    proof, sent = _check(token, lambda forged: forged == token)
    assert proof is None
    assert len(sent) == 5  # the altered signature and the four spellings, once each


def test_no_token_is_sent_past_what_is_left():
    proof, sent = _check(_token("secret"), lambda forged: False, requests=4)
    # The match is offline, so it is still reported; acceptance was not shown.
    assert proof["technique"] == "jwt_weak_hmac_secret_reproduced"
    assert proof["forged_token_accepted"] is None and len(sent) <= 3


def _run_batch(monkeypatch, accepts, token, *, principal=None, cookie_authenticates=False):
    scan_id = str(uuid.uuid4())
    manifest = build_endpoint_manifest(
        scan_id=scan_id, target_binding_digest=TARGET.digest,
        surface_manifest={
            "schema_version": "endpoint-manifest/v2", "status": "complete", "reason": None,
            "endpoints": [{
                "method": "GET", "scheme": "https", "host": "app.example.test", "port": 443,
                "normalized_path": path, "concrete_path": path, "query_keys": [], "source": "web.crawl",
            } for path in ("/api/profile", "/public")],
        },
        source_action_ids=("discover.web_crawl",),
    )
    sent: list[tuple[str, str]] = []

    class Transport:
        async def send(self, request, **_kwargs):
            bearer = next((value.split(" ", 1)[1] for name, value in request.headers
                           if name.lower() == "authorization"), "")
            cookie = any(name.lower() == "cookie" for name, _value in request.headers)
            path = urllib.parse.urlsplit(request.url).path
            sent.append((path, bearer))
            ok = (
                path == "/public" or (cookie_authenticates and cookie)
                or (bool(bearer) and (bearer == token or accepts(bearer)))
            )
            return ReplayTransportResult(
                status_code=200 if ok else 401, connected_address="192.0.2.10",
                final_url=request.url, response_headers={"Content-Type": "application/json"},
                response_body=b'{"id":2,"name":"user"}' if ok else b'{"error":"unauthorized"}',
                elapsed_ms=4,
            )

    monkeypatch.setattr(action_adapter_module, "PinnedAiohttpReplayTransport", Transport)
    monkeypatch.setattr(
        action_adapter_module, "resolve_scan_http_principal",
        principal or (lambda _options, *, lane, capability_name=None: type("Principal", (), {
            "authenticated": True, "binding_digest": "1" * 64,
            "headers": lambda self: {"Authorization": f"Bearer {token}"},
        })()),
    )
    action = _action("verify.authz_surface", "authz_surface.verify_batch", 0, capability_args={
        "endpoint_manifest_ref": manifest.reference().canonical_dict(),
        "slice": {"start": 0, "count": 100}, "profile": "balanced",
        "proof_policy": "deterministic_proof_contract_required",
    })
    plan = ScanActionPlan(scan_id=scan_id, execution_plan_digest="a" * 64,
                          target_binding_digest=TARGET.digest, actions=(action,))
    backend = Backend(manifests={manifest.manifest_id: manifest})
    dispatcher = _dispatcher(
        plan, backend, policy=ScanPolicy(active_testing=True, approval_receipt_id="approval-1"),
    )
    receipt = asyncio.run(dispatcher(action, _lease(plan, action), _noop))
    return receipt, sent, (dispatcher, plan, action)


def _token_proofs(receipt):
    return [item for item in receipt.observations
            if item.get("proof_contract") == "authz_surface_jwt_forgery/v1"]


def test_the_batch_checks_the_principals_token_on_a_gated_route_once(monkeypatch):
    token = _token()
    receipt, sent, (dispatcher, plan, action) = _run_batch(
        monkeypatch, lambda bearer: bearer.endswith("."), token,
    )
    proofs = _token_proofs(receipt)
    assert len(proofs) == 1
    assert proofs[0]["technique"] == "jwt_alg_none_accepted_repeated"
    assert proofs[0]["request_url"].endswith("/api/profile")
    assert proofs[0]["anonymous_status"] == 401 and proofs[0]["authenticated_status"] == 200
    # Forged tokens go to the gated route only, after both routes were compared.
    forged = [(path, bearer) for path, bearer in sent if bearer and bearer != token]
    assert forged and {path for path, _bearer in forged} == {"/api/profile"}
    # After both routes were compared (8 requests) and the request without a bearer (1).
    assert sent.index(forged[0]) == 9
    assert sent[8] == ("/api/profile", "")
    assert receipt.budget_consumed["http_requests"] == len(sent)
    # A resumed batch sends nothing and reports the same proof.
    before = len(sent)
    resumed = asyncio.run(dispatcher(action, _lease(plan, action), _noop))
    assert len(sent) == before and len(_token_proofs(resumed)) == 1


def test_the_batch_sends_no_forged_token_for_an_opaque_bearer(monkeypatch):
    receipt, sent, _ = _run_batch(monkeypatch, lambda bearer: False, "opaque-session-token")
    assert _token_proofs(receipt) == []
    assert all(bearer in {"", "opaque-session-token"} for _path, bearer in sent)
    assert len(sent) == 8


@pytest.mark.parametrize(("technique", "cwe"), [
    ("jwt_signature_not_verified_repeated", "CWE-347"),
    ("jwt_alg_none_accepted_repeated", "CWE-347"),
    ("jwt_weak_hmac_secret_reproduced", "CWE-1391"),
])
def test_the_finalizer_reports_accepted_forgery_as_a_verified_critical_finding(technique, cwe):
    from tests.test_scan_orchestrator import SCAN_ID, _action as _plan_action

    verify = _plan_action("verify.authz_surface", 0, capability_name="authz_surface.verify_batch")
    final = _plan_action("finalize.report", 1, dependencies=(verify.action_id,))
    plan = ScanActionPlan(scan_id=SCAN_ID, execution_plan_digest="b" * 64,
                          target_binding_digest="a" * 64, actions=(verify, final))
    proof = {
        "kind": "authz_surface_proof", "proof_state": "verified", "finding_verdict": "verified",
        "proof_contract": "authz_surface_jwt_forgery/v1", "technique": technique,
        "algorithm": "HS256", "route_id": "r1",
        "request_url": "https://app.example.test/api/profile", "anonymous_status": 401,
        "authenticated_status": 200, "forged_status": 200, "repetitions": 2,
    }
    unknown = {**proof, "technique": "made_up"}
    report = finalize_scan_report(
        plan=plan, target_url="https://app.example.test",
        action_results={verify.action_id: _result_with_observation_count(verify, 2)},
        observations={verify.action_id: (proof, unknown)},
    )
    assert len(report["findings"]) == 1
    finding = report["findings"][0]
    assert finding["tool"] == "shakerscan_authz_surface" and finding["cwe"] == cwe
    assert finding["severity"] == "critical" and finding["verified"] is True
    assert finding["evidence"]["algorithm"] == "HS256"


def test_a_route_that_answers_the_principal_without_the_bearer_is_not_checked():
    """A session cookie or an API key authenticates there: the token is not what the route reads,
    so an altered token being "accepted" says nothing about its signature."""
    proof, sent = _check(_token("secret"), lambda forged: True, without_bearer=(200, "page"))
    assert proof is None and sent == []


def test_a_forged_token_answered_200_with_another_body_was_not_accepted():
    """An API that answers a bad token 200 with an error document did not accept it."""
    proof, sent = _check(_token(), lambda forged: True, accepted_body="error document")
    assert proof is None
    assert len(sent) == 5


def test_the_batch_reports_nothing_for_a_cookie_session_that_ignores_the_bearer(monkeypatch):
    token = _token()

    def patched_principal(_options, *, lane, capability_name=None):
        return type("Principal", (), {
            "authenticated": True, "binding_digest": "1" * 64,
            "headers": lambda self: {"Authorization": f"Bearer {token}", "Cookie": "session=abc"},
        })()

    receipt, sent, _ = _run_batch(monkeypatch, lambda bearer: True, token, principal=patched_principal,
                                  cookie_authenticates=True)
    assert _token_proofs(receipt) == []
    # The two comparisons of each route and the one request without a bearer; no forged token.
    assert all(bearer in {"", token} for _path, bearer in sent)
