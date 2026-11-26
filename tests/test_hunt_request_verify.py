"""request.verify in a Hunt: its contract, admission rules, request building, settlement and the
findings it materializes (hunt/request_verification.py)."""
from __future__ import annotations

import asyncio
import json

import pytest

from api.capabilities.injection_verify import INJECTION_CLASSES
from api.capabilities.request_verify import REQUEST_CHECKS
from api.hunt.capability_executor import CapabilityAdapterResult
from api.hunt.request_verification import (
    CAPABILITY, CHECKS, NOSQL_CHECK, SQL_CHECK, REQUEST_FINDINGS, RequestVerificationExecutionAdapter,
    admission_refusal, build_request, finding_records, verifier_adapter, writes,
)
from api.runtime.capability_registry import CAPABILITY_REGISTRY
from api.runtime.models import TargetBinding

ACTIVE = {"active_testing": True}
WRITES = {"active_testing": True, "allow_state_changing_http": True}
ORIGIN = "https://app.example.test"


def test_the_published_checks_are_exactly_the_ones_the_verifiers_implement():
    assert set(CHECKS) == {*INJECTION_CLASSES, NOSQL_CHECK, SQL_CHECK, *REQUEST_CHECKS}
    spec = CAPABILITY_REGISTRY.require(CAPABILITY)
    assert spec.planner_visible and spec.hunt_executor == "worker_http"
    assert spec.required_approval == "active_testing" and spec.risk_tier == "active"
    assert spec.input_schema["properties"]["check"]["enum"] == list(CHECKS)
    assert set(spec.input_schema["required"]) == {"check", "path"}
    # A short action: it never waits for one of the Hunt's two long-action slots.
    from api.hunt.agent_job_concurrency import long_action
    assert not long_action(CAPABILITY)
    # Every proof class a request check can produce has a finding.
    from api.capabilities.request_verify import PROOF_CONTRACTS
    assert set(PROOF_CONTRACTS) - {"jwt"} <= set(REQUEST_FINDINGS) | {"jwt"}


@pytest.mark.parametrize("values,policy,expected", [
    ({"check": "command_injection", "path": "/ping"}, ACTIVE, "parameter"),
    ({"check": "command_injection", "path": "/ping", "parameter": "host"}, {}, "active_testing"),
    ({"check": "command_injection", "method": "POST", "path": "/ping", "parameter": "host",
      "form_body": {"host": "x"}}, ACTIVE, "allow_state_changing_http"),
    # Traversal only through a request that reads (#540).
    ({"check": "path_traversal", "method": "POST", "path": "/save", "parameter": "name",
      "form_body": {"name": "a"}}, WRITES, "reads"),
    # SSRF in-band, GET only.
    ({"check": "ssrf", "method": "POST", "path": "/fetch", "parameter": "url", "form_body": {"url": "x"}},
     WRITES, "GET"),
    # Injection probes are not sent to a sign-in endpoint.
    ({"check": "command_injection", "method": "POST", "path": "/api/login", "parameter": "user",
      "form_body": {"user": "a"}}, WRITES, "sign-in"),
    ({"check": "xxe", "method": "POST", "path": "/import", "json_body": {"a": 1}}, WRITES, "xml_body"),
    ({"check": "csrf", "path": "/account"}, WRITES, "state-changing"),
    ({"check": "file_upload", "method": "POST", "path": "/upload", "parameter": "file"}, WRITES, "retrieve_path"),
    ({"check": "jwt", "path": "/api/me"}, ACTIVE, "principal"),
    ({"check": "rate_limit", "path": "/login", "parameter": "password"}, ACTIVE, "POST"),
    ({"check": "cors", "path": "/", "headers": {"Authorization": "Bearer x"}}, ACTIVE, "headers refused"),
    ({"check": "cors", "path": "/", "headers": {"X-Forwarded-For": "1.2.3.4"}}, ACTIVE, "headers refused"),
    ({"check": "cors", "path": "/", "form_body": {"a": "b"}}, ACTIVE, "body needs"),
    ({"check": "nope", "path": "/"}, ACTIVE, "check must be one of"),
])
def test_admission_refuses_what_a_check_may_not_send(values, policy, expected):
    refusal = admission_refusal(values, policy)
    assert refusal and expected in refusal


@pytest.mark.parametrize("values,policy", [
    ({"check": "command_injection", "path": "/ping", "parameter": "host"}, ACTIVE),
    ({"check": "path_traversal", "path": "/view", "parameter": "page"}, ACTIVE),
    ({"check": "rate_limit", "method": "POST", "path": "/api/login", "parameter": "password",
      "form_body": {"username": "a", "password": "b"}}, WRITES),
    ({"check": "xxe", "method": "POST", "path": "/import", "xml_body": "<a>b</a>"}, WRITES),
    ({"check": "file_upload", "method": "POST", "path": "/upload", "parameter": "file",
      "retrieve_path": "/uploads/{filename}"}, WRITES),
    ({"check": "cors", "path": "/", "headers": {"X-Forwarded-For": "1.2.3.4"}},
     {**ACTIVE, "allow_identity_headers": True}),
])
def test_admission_accepts_a_call_that_fits_its_check(values, policy):
    assert admission_refusal(values, policy) is None


def test_an_upload_always_writes_and_a_get_check_does_not():
    assert writes({"check": "file_upload", "method": "POST"})
    assert writes({"check": "csrf", "method": "PATCH"})
    assert not writes({"check": "cors", "method": "GET"})


def test_build_request_encodes_the_body_and_carries_the_resolved_identity():
    request = build_request(
        {"check": "nosql_injection", "method": "POST", "path": "/api/login?x=1", "query": {"y": "2"},
         "json_body": {"username": "a", "password": "b"}, "headers": {"X-Trace": "1"}},
        base_url=ORIGIN + "/", headers={"Cookie": "session=abcdefgh"}, action_id="a1",
    )
    assert request.url == ORIGIN + "/api/login?x=1&y=2"
    assert json.loads(request.body) == {"username": "a", "password": "b"}
    assert ("Content-Type", "application/json") in request.headers
    assert ("Cookie", "session=abcdefgh") in request.headers and ("X-Trace", "1") in request.headers
    assert request.has_sensitive_material
    form = build_request({"check": "csrf", "method": "POST", "path": "/a", "form_body": {"a": ["1", "2"], "b": True}},
                         base_url=ORIGIN, headers={}, action_id="a2")
    assert form.body == b"a=1&a=2&b=true"


def _target():
    return TargetBinding(
        target_id="10000000-0000-4000-8000-000000000001", target_kind="web",
        canonical_host="app.example.test", allowed_origins=(ORIGIN,), allowed_addresses=("192.0.2.10",),
        allowed_root_domains=("example.test",), scope_receipt_id="10000000-0000-4000-8000-000000000002",
    )


def test_injection_checks_run_the_scan_verifier_on_exactly_one_class():
    values = {"check": "template_injection", "method": "GET", "path": "/render", "query": {"q": "a"},
              "parameter": "q"}
    request = build_request(values, base_url=ORIGIN, headers={}, action_id="a")
    adapter = verifier_adapter(values, target=_target(), request=request, recorder=lambda row: None,
                               principal_slot="anonymous", requested_budget={"http_requests": 48,
                                                                             "tool_wall_seconds": 120},
                               seed="s", transport=object())
    assert type(adapter).__name__ == "InjectionVerifyAdapter" and adapter.classes == ("template_injection",)
    nosql = verifier_adapter({**values, "check": NOSQL_CHECK}, target=_target(), request=request,
                             recorder=lambda row: None, principal_slot="anonymous",
                             requested_budget={"http_requests": 48, "tool_wall_seconds": 120}, seed="s",
                             transport=object())
    assert type(nosql).__name__ == "NoSQLiVerifyAdapter"


def test_a_writing_check_settles_its_requests_as_verifier_writes_within_the_hold():
    class Inner:
        async def execute(self, *, heartbeat, cancelled):
            return CapabilityAdapterResult(status="success", actual_budget={
                "http_requests": 7, "state_changing_requests": 7, "tool_wall_seconds": 3})

    class Spec:
        output_schema = "request-proof/v1"

    async def operation():
        return Inner()

    adapter = RequestVerificationExecutionAdapter(
        specification=Spec(), operation=operation, redacted_execution={"check": "csrf"},
        requested_budget={"http_requests": 48, "tool_wall_seconds": 120, "verifier_write_requests": 48},
    )
    result = asyncio.run(adapter.execute(heartbeat=None, cancelled=lambda: False))
    assert result.actual_budget == {"http_requests": 7, "tool_wall_seconds": 3, "verifier_write_requests": 7}
    assert result.redacted_execution["check"] == "csrf"


def _proof(**extra):
    return {"kind": "request_proof", "check": "open_redirect", "proof_class": "open_redirect",
            "origin": ORIGIN, "canonical_path": "/go", "method": "GET", "field_path": "next",
            "proof_state": "verified", "finding_verdict": "verified",
            "proof_contract": "request_open_redirect_differential/v1", "technique": "t", "repetitions": 2,
            "response_pairs": [{"control_status": 200}], **extra}


def test_findings_come_only_from_verified_repeated_proofs_on_the_hunts_own_services():
    records = finding_records("h", "a", ORIGIN + "/", "r", {"check": "open_redirect"}, [
        _proof(),
        _proof(proof_state="not_proven", finding_verdict="not_proven"),
        _proof(repetitions=1),
        _proof(origin="https://other.example.test"),
        _proof(proof_contract=None),
    ])
    assert len(records) == 1
    record = records[0]
    assert record["url"] == ORIGIN + "/go" and record["cwe"] == "CWE-601"
    assert record["evidence"]["canonical_capability"] == CAPABILITY
    assert record["evidence"]["secret_values_visible"] is False
    assert record["fingerprint"].startswith("t:")


def test_finding_severity_and_titles_follow_the_proof():
    cors = finding_records("h", "a", ORIGIN, "r", {"check": "cors"}, [
        _proof(check="cors", proof_class="cors_reflected_origin", credentials=True, field_path=None,
               proof_contract="request_cors_origin_differential/v1")])[0]
    assert cors["severity"] == "high"
    injection = finding_records("h", "a", ORIGIN, "r", {"check": "command_injection"}, [{
        "kind": "injection_proof", "injection_class": "command_injection", "origin": ORIGIN,
        "canonical_path": "/ping", "method": "GET", "field_path": "host", "proof_state": "verified",
        "finding_verdict": "verified", "proof_contract": "injection_command_differential/v1", "repetitions": 2,
    }])[0]
    assert injection["title"] == "Verified command injection" and injection["cwe"] == "CWE-78"
    assert injection["severity"] == "critical"


def test_a_server_side_sweep_runs_a_check_from_endpoint_parameter_and_class_alone():
    """No planner input: an endpoint, its parameter and the class, under the run's policy."""
    from api.hunt.request_verification import RequestVerificationRefused, run_check
    from api.runtime.request_replay_executor import ReplayTransportResult
    import urllib.parse as parse

    class Redirector:
        sent = 0

        async def send(self, request, **_kwargs):
            Redirector.sent += 1
            value = parse.parse_qs(parse.urlsplit(request.url).query).get("next", ["/"])[0]
            return ReplayTransportResult(status_code=302, connected_address="192.0.2.10", final_url=request.url,
                                         response_headers={"Location": value}, response_body=b"")

    result = asyncio.run(run_check("open_redirect", url=ORIGIN + "/go?next=/home", parameter="next",
                                   target=_target(), transport=Redirector(), policy=ACTIVE, seed="sweep-1"))
    assert [item["proof_class"] for item in result.observations if item["proof_state"] == "verified"] == [
        "open_redirect"]
    records = finding_records("h", "a", ORIGIN, "r", {"check": "open_redirect"}, list(result.observations))
    assert records and records[0]["cwe"] == "CWE-601"
    # The same limits as a planner's call: refused before anything is sent.
    before = Redirector.sent
    with pytest.raises(RequestVerificationRefused):
        asyncio.run(run_check("path_traversal", url=ORIGIN + "/save", method="POST", parameter="name",
                              form_body={"name": "a"}, target=_target(), transport=Redirector(),
                              policy=WRITES, seed="sweep-2"))
    assert Redirector.sent == before


def test_sql_injection_is_proved_in_a_few_requests_by_the_scan_proof_and_never_at_a_sign_in():
    from api.hunt.request_verification import run_check
    from api.runtime.request_replay_executor import ReplayTransportResult
    import urllib.parse as parse

    class Database:
        """id=1 finds a row; a quote breaks the statement; AND 1=1 keeps the row, AND 1=2 drops it."""
        sent = 0

        async def send(self, request, **_kwargs):
            Database.sent += 1
            value = parse.parse_qs(parse.urlsplit(request.url).query).get("id", [""])[0]
            if value.count("'") % 2:
                body = b"You have an error in your SQL syntax; check the manual that corresponds to your MySQL"
                return ReplayTransportResult(status_code=500, connected_address="192.0.2.10",
                                             final_url=request.url, response_body=body)
            row = value == "1" or value.endswith("'1'='1") or value.endswith("1=1")
            body = b'{"id": 1, "name": "widget"}' if row else b"[]"
            return ReplayTransportResult(status_code=200, connected_address="192.0.2.10",
                                         final_url=request.url, response_body=body)

    result = asyncio.run(run_check(SQL_CHECK, url=ORIGIN + "/item?id=1", parameter="id", target=_target(),
                                   transport=Database(), policy=ACTIVE, seed="sweep-sql"))
    verified = [item for item in result.observations if item.get("proof_state") == "verified"]
    assert verified and verified[0]["kind"] == "sqli_proof" and Database.sent <= 48
    records = finding_records("h", "a", ORIGIN, "r", {"check": SQL_CHECK}, list(result.observations))
    assert records and records[0]["cwe"] == "CWE-89" and records[0]["severity"] == "critical"
    assert records[0]["finding_type"] == "sql_injection"
    # An input check: the parameter is required, and a sign-in is never sent SQL probes.
    assert "parameter" in admission_refusal({"check": SQL_CHECK, "method": "GET", "path": "/item"}, ACTIVE)
    assert "sign-in" in admission_refusal({"check": SQL_CHECK, "method": "POST", "path": "/login",
                                           "parameter": "username", "form_body": {"username": "a"}}, WRITES)


def test_an_anonymous_product_management_api_is_proved_against_a_sibling_control():
    from api.capabilities.product_api import product_api_for
    from api.hunt.request_verification import run_check
    from api.runtime.request_replay_executor import ReplayTransportResult
    import urllib.parse as parse

    class Jupyter:
        async def send(self, request, **_kwargs):
            path = parse.urlsplit(request.url).path
            if path == "/api/kernels":
                body = b'[{"id": "k1", "name": "python3", "execution_state": "idle", "connections": 0}]'
                return ReplayTransportResult(status_code=200, connected_address="192.0.2.10", final_url=request.url,
                                             response_body=body)
            return ReplayTransportResult(status_code=404, connected_address="192.0.2.10", final_url=request.url,
                                         response_body=b'{"message": "Not found"}')

    class CatchAll(Jupyter):
        async def send(self, request, **_kwargs):  # every path answers like the route: proves nothing
            return await super().send(replace_path(request, "/api/kernels"))

    def replace_path(request, path):
        from dataclasses import replace
        parts = parse.urlsplit(request.url)
        return replace(request, url=parse.urlunsplit((parts.scheme, parts.netloc, path, "", "")))

    assert product_api_for("/api/kernels").product == "Jupyter Server" and product_api_for("/about") is None
    result = asyncio.run(run_check("unauthenticated_api", url=ORIGIN + "/api/kernels", target=_target(),
                                   transport=Jupyter(), policy=ACTIVE, seed="sweep-api"))
    records = finding_records("h", "a", ORIGIN, "r", {"check": "unauthenticated_api"}, list(result.observations))
    assert records and records[0]["cwe"] == "CWE-306" and records[0]["evidence"]["product"] == "Jupyter Server"
    loose = asyncio.run(run_check("unauthenticated_api", url=ORIGIN + "/api/kernels", target=_target(),
                                  transport=CatchAll(), policy=ACTIVE, seed="sweep-api-2"))
    assert not finding_records("h", "a", ORIGIN, "r", {"check": "unauthenticated_api"}, list(loose.observations))
    unknown = asyncio.run(run_check("unauthenticated_api", url=ORIGIN + "/about", target=_target(),
                                    transport=Jupyter(), policy=ACTIVE, seed="sweep-api-3"))
    assert not finding_records("h", "a", ORIGIN, "r", {"check": "unauthenticated_api"}, list(unknown.observations))
    assert "anonymous" in admission_refusal({"check": "unauthenticated_api", "method": "GET", "path": "/api/kernels",
                                             "as_principal": "primary"}, ACTIVE)


def test_an_exposure_class_is_proved_twice_against_a_sibling_control():
    from api.hunt.request_verification import run_check
    from api.runtime.request_replay_executor import ReplayTransportResult
    import urllib.parse as parse

    metrics = b"# HELP http_requests_total Total requests.\n# TYPE http_requests_total counter\nhttp_requests_total 3\n"

    class Server:
        def __init__(self, everywhere=False):
            self.everywhere = everywhere

        async def send(self, request, **_kwargs):
            path = parse.urlsplit(request.url).path
            if path == "/metrics" or self.everywhere:
                return ReplayTransportResult(status_code=200, connected_address="192.0.2.10", final_url=request.url,
                                             response_headers={"Content-Type": "text/plain"}, response_body=metrics)
            return ReplayTransportResult(status_code=404, connected_address="192.0.2.10", final_url=request.url,
                                         response_body=b"not found")

    result = asyncio.run(run_check("exposure", url=ORIGIN + "/metrics", target=_target(), transport=Server(),
                                   policy=ACTIVE, seed="sweep-exposure"))
    records = finding_records("h", "a", ORIGIN, "r", {"check": "exposure"}, list(result.observations))
    assert records and records[0]["finding_type"] == "metrics_endpoint" and records[0]["cwe"] == "CWE-200"
    assert "Exposed metrics endpoint" == records[0]["title"]
    loose = asyncio.run(run_check("exposure", url=ORIGIN + "/metrics", target=_target(), transport=Server(True),
                                  policy=ACTIVE, seed="sweep-exposure-2"))
    assert not finding_records("h", "a", ORIGIN, "r", {"check": "exposure"}, list(loose.observations))
