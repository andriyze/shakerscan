"""candidate.verify for an injection candidate runs the server's own differential proofs."""
from __future__ import annotations

import asyncio
import re
import urllib.parse

import pytest

from api.hunt import injection_proof
from api.runtime.request_replay_executor import ReplayTransportResult

RUN = {"id": "20000000-0000-4000-8000-000000000001", "target_kind": "web",
       "target_id": "10000000-0000-4000-8000-000000000001", "device_target_id": None}
CONTEXT = {"target": {"url": "https://app.example.test", "origins": ["https://app.example.test"]}}
PASSWD = b"root:x:0:0:root:/root:/bin/bash\n"


def _candidate(family, **locus):
    return {"id": "30000000-0000-4000-8000-000000000001", "family": family,
            "canonical_locus": {"route": "/render", "parameter": "q", **locus},
            "verification_context": {}, "status": "open",
            "target_id": RUN["target_id"]}


class Transport:
    def __init__(self, respond):
        self.respond, self.values = respond, []

    async def send(self, request, **_kwargs):
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(request.url).query, keep_blank_values=True)
        value = (query.get("q") or [""])[0]
        self.values.append(value)
        status, body, elapsed = self.respond(urllib.parse.urlsplit(request.url).path, value)
        return ReplayTransportResult(
            status_code=status, connected_address="192.0.2.10", final_url=request.url,
            response_headers={"Content-Type": "text/html"}, response_body=body, elapsed_ms=elapsed)


def _prove(family, respond, **locus):
    transport = Transport(respond)
    proof = asyncio.run(injection_proof.run_proof(
        run=RUN, context=CONTEXT, policy={}, candidate=_candidate(family, **locus),
        action_id="40000000-0000-4000-8000-000000000001", transport=transport))
    return proof, transport


def _jinja(_path, value):
    rendered = re.sub(r"\{\{(\d+)\*(\d+)\}\}", lambda m: str(int(m.group(1)) * int(m.group(2))), value)
    return 200, f"<p>{rendered}</p>".encode(), 8


def test_a_template_injection_candidate_is_proven_by_the_servers_own_differential():
    proof, transport = _prove("ssti", _jinja)
    assert proof["promotable"] and proof["verdict"] == "verified"
    assert proof["verified"]["kind"] == "template_injection"
    assert proof["url"] == "https://app.example.test/render"
    assert proof["traffic"]["http_requests"] == len(transport.values) <= injection_proof.PROOF_REQUESTS
    record = injection_proof.finding_record(
        proof["verified"], kind="template_injection", hunt_id=RUN["id"],
        action_id="40000000-0000-4000-8000-000000000001", url=proof["url"])
    assert record["severity"] == "critical" and record["cwe"] == "CWE-1336"
    assert record["evidence"]["proof_state"] == "verified"
    assert record["evidence"]["canonical_capability"] == "candidate.verify"


def test_the_family_picks_the_proof_and_plain_injection_runs_them_all():
    def reader(_path, value):
        hit = value.startswith("../") and value.endswith("etc/passwd")
        return (200, PASSWD, 8) if hit else (404, b"no such file", 8)

    specific, transport = _prove("path_traversal", reader)
    assert specific["verified"]["kind"] == "path_traversal"
    assert not any("{{" in value or "sleep" in value for value in transport.values)
    everything, _transport = _prove("injection", reader)
    assert everything["verified"]["kind"] == "path_traversal"
    assert everything["proofs"] == ["template_injection", "path_traversal", "command_injection",
                                    "ssrf", "sqli", "nosqli"]


def test_a_sql_injection_candidate_runs_every_stage_of_the_sql_proof():
    def blind(_path, value):
        return 200, b'{"item":1}', 1100 if "PG_SLEEP" in value else 10

    proof, _transport = _prove("sqli", blind, route="/render?q=7")
    assert proof["verified"]["kind"] == "sqli"
    assert proof["verified"]["proof_contract"] == "sqli_time_differential/v1"


def test_an_endpoint_that_only_echoes_is_not_reproduced_and_nothing_is_promoted():
    proof, _transport = _prove("injection", lambda _path, value: (200, f"<p>{value}</p>".encode(), 8))
    assert not proof["promotable"] and proof["verified"] is None
    assert proof["verdict"] in {"not_reproduced", "inconclusive"}


@pytest.mark.parametrize(("family", "locus", "reason"), [
    ("xss", {}, "injection_proof_browser_family"),
    ("ssti", {"parameter": ""}, "injection_proof_parameter_missing"),
    ("ssti", {"method": "POST"}, "injection_proof_get_only"),
    ("ssti", {"route": "render"}, "injection_proof_route_missing"),
    ("ssti", {"route": "/a/../b"}, "injection_proof_route_missing"),
])
def test_a_candidate_the_proof_cannot_run_is_refused_before_anything_is_sent(family, locus, reason):
    with pytest.raises(injection_proof.InjectionProofRefused) as refused:
        injection_proof.proofs_for(family)
        injection_proof.proof_request(_candidate(family, **locus), origin="https://app.example.test")
    assert refused.value.reason == reason


def test_the_request_keeps_the_other_parameters_and_the_tested_ones_value():
    url, route, parameter = injection_proof.proof_request(
        _candidate("sqli", route="https://app.example.test/items?page=2&q=lamp"),
        origin="https://app.example.test")
    assert (route, parameter) == ("/items", "q")
    assert urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query) == [("page", "2"), ("q", "lamp")]


def test_planners_are_told_which_injection_families_verify():
    from api.hunt.candidate_verification_preflight import public_verification_families

    told = public_verification_families()
    assert "ssrf" in told["injection_families"]["families"]
    assert all(injection_proof.is_injection_family(name) for name in told["injection_families"]["families"])
    assert "isolation, injection" not in told["other_families"]


def test_only_a_hunt_admits_an_injection_candidate_and_holds_the_proofs_requests():
    from api.hunt.candidate_verification_preflight import (
        CandidateVerificationRefused, web_candidate_preflight,
    )
    from api.hunt.verification_budget import web_candidate_budget

    candidate = _candidate("ssrf")
    assert web_candidate_preflight(candidate, injection_proofs=True) == ("injection", "/render", "GET")
    with pytest.raises(CandidateVerificationRefused, match="verification bridge supports"):
        web_candidate_preflight(candidate)
    with pytest.raises(CandidateVerificationRefused, match="injection_proof_parameter_missing"):
        web_candidate_preflight(_candidate("ssrf", parameter=""), injection_proofs=True)
    assert web_candidate_budget("ssrf")["http_requests"] == injection_proof.PROOF_REQUESTS
    assert web_candidate_budget("sqli")["http_requests"] == injection_proof.PROOF_REQUESTS
    assert web_candidate_budget("bola")["http_requests"] == 24
    assert web_candidate_budget("business_logic")["state_changing_requests"] == 12


def test_a_candidate_on_a_network_target_is_proved_on_the_service_it_names():
    from api.hunt.candidate_verification_preflight import verification_service_origin

    run = {**RUN, "target_kind": "network"}
    context = {"target": {"url": "host://app.example.test", "origins": ["http://app.example.test:8080"]}}
    transport = Transport(_jinja)
    proof = asyncio.run(injection_proof.run_proof(
        run=run, context=context, policy={},
        candidate=_candidate("ssti", origin="http://app.example.test:8080"),
        action_id="40000000-0000-4000-8000-000000000001", transport=transport,
        service_origin=verification_service_origin))
    assert proof["url"] == "http://app.example.test:8080/render"
    assert proof["promotable"]


def test_a_candidate_the_proof_cannot_run_is_answered_with_the_verifier_call_that_proves_it():
    from api.hunt.candidate_verification_preflight import (
        CandidateVerificationRefused, web_candidate_preflight,
    )

    # XSS: xss.verify on the same parameter, the other query parameters kept.
    with pytest.raises(CandidateVerificationRefused) as refused:
        web_candidate_preflight(_candidate("xss", route="/search?page=2&q=abc"), injection_proofs=True)
    assert refused.value.reason_code == "verification_family_unsupported"
    assert refused.value.next_call == {"capability": "xss.verify", "input": {"path": "/search?page=2&q=abc"}}
    assert "next_call" in refused.value.detail
    # A body parameter: sqli.verify with the body fields, signed in as the principal the locus names.
    with pytest.raises(CandidateVerificationRefused) as refused:
        web_candidate_preflight(_candidate("sqli", route="/login", method="POST", parameter="username",
                                           body_field_names=["username", "password"],
                                           content_type="application/json", as_principal="user2"),
                                injection_proofs=True)
    assert refused.value.reason_code == "verification_method_unsupported"
    call = refused.value.next_call
    assert call["capability"] == "sqli.verify" and "state-changing" in call["note"]
    assert call["input"] == {"path": "/login", "method": "POST", "body_field_names": ["username", "password"],
                             "injection_field": "username", "content_type": "application/json",
                             "as_principal": "user2"}
    # Another injection class in a body: sqli.verify, and it says it proves SQL injection only.
    call = injection_proof.verifier_call(_candidate("ssti", method="PUT"))
    assert call["capability"] == "sqli.verify" and "SQL injection only" in call["note"]
    assert call["input"]["body_field_names"] == ["q"]
    # A locus without a parameter or a usable route names no call; the refusal says what is missing.
    with pytest.raises(CandidateVerificationRefused) as refused:
        web_candidate_preflight(_candidate("xss", parameter=""), injection_proofs=True)
    assert refused.value.next_call is None and refused.value.reason_code == "verification_family_unsupported"
    assert injection_proof.verifier_call(_candidate("xss", route="//evil.test/x")) is None
    assert injection_proof.verifier_call(_candidate("bola")) is None
    # A GET query parameter of an injection family still runs the server's own proof.
    assert web_candidate_preflight(_candidate("sqli"), injection_proofs=True) == ("injection", "/render", "GET")


def test_the_families_told_to_planners_say_injection_has_verifiers():
    from api.hunt.candidate_verification_preflight import public_verification_families

    told = public_verification_families()
    assert set(told["injection_verifiers"]) == {"sqli.verify", "xss.verify"}
    assert "do have verifiers" in told["other_families"]
    assert "no deterministic verifier proves it" not in told["other_families"]
