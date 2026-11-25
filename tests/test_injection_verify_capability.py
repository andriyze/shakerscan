from __future__ import annotations

import asyncio
import json
import re
import urllib.parse

import pytest

from api.capabilities.injection_verify import (
    INJECTION_CLASSES, InjectionVerifyAdapter, InjectionVerifyError, PROOF_CONTRACTS,
)
from api.runtime.capability_registry import CAPABILITY_REGISTRY
from api.runtime.models import TargetBinding
from api.runtime.request_replay_executor import ReplayTransportResult
from scanner.scanner_tools.request_replay import ReplayAuthorization, build_replay_plan

PASSWD = b"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"


def _target() -> TargetBinding:
    return TargetBinding(
        target_id="10000000-0000-4000-8000-000000000001",
        target_kind="web",
        canonical_host="app.example.test",
        allowed_origins=("https://app.example.test",),
        allowed_addresses=("192.0.2.10",),
        allowed_root_domains=("example.test",),
        scope_receipt_id="10000000-0000-4000-8000-000000000002",
    )


def _request(*, method: str = "GET", url: str, body: str = "", content_type: str = ""):
    headers = {"Content-Type": content_type} if content_type else {}
    return build_replay_plan(
        ({
            "id": "exact-request", "method": method, "url": url, "headers": headers,
            "body": body, "body_mode": content_type or "none",
            "has_sensitive_material": bool(body),
        },),
        allowed_origins=_target().allowed_origins,
        authorization=ReplayAuthorization(
            active_testing=True, allow_state_changing_http=True,
            approval_receipt_id="approval-1",
        ),
    ).requests[0]


def _candidate(**extra):
    return {"candidate_id": "a" * 64, "method": "GET", "parameter_name": "q",
            "request_class": "safe_read", "canonical_path": "/render", **extra}


def _run(request, candidate, transport, *, classes=INJECTION_CLASSES, http_requests=60):
    adapter = InjectionVerifyAdapter(
        specification=CAPABILITY_REGISTRY.require("injection.verify_batch"),
        target=_target(), request=request, candidate=candidate, transport=transport,
        requested_budget={
            "http_requests": http_requests,
            "state_changing_requests": http_requests if request.method == "POST" else 0,
            "tool_wall_seconds": 120,
        },
        classes=classes,
    )
    return asyncio.run(adapter.execute(
        heartbeat=lambda: asyncio.sleep(0), cancelled=lambda: False,
    ))


def _value(request, name="q"):
    return urllib.parse.parse_qs(
        urllib.parse.urlsplit(request.url).query, keep_blank_values=True,
    ).get(name, [""])[0]


def _answer(request, body: bytes, *, status: int = 200, elapsed_ms: int = 10):
    return ReplayTransportResult(
        status_code=status, connected_address="192.0.2.10", final_url=request.url,
        response_headers={"Content-Type": "text/html"}, response_body=body,
        elapsed_ms=elapsed_ms,
    )


def _by_class(result):
    return {item["injection_class"]: item for item in result.observations}


class Recorder:
    def __init__(self, respond):
        self.respond = respond
        self.values: list[str] = []

    async def send(self, request, **_kwargs):
        value = _value(request)
        self.values.append(value)
        return self.respond(request, value)


def _jinja(request, value):
    """Evaluates ``{{a*b}}`` and echoes everything else, as a template rendered from input does."""
    rendered = re.sub(
        r"\{\{(\d+)\*(\d+)\}\}", lambda m: str(int(m.group(1)) * int(m.group(2))), value,
    )
    return _answer(request, f"<p>Hello {rendered}</p>".encode())


def test_template_injection_needs_the_product_twice_and_a_silent_control():
    transport = Recorder(_jinja)
    result = _run(
        _request(url="https://app.example.test/render?q=world"), _candidate(), transport,
        classes=("template_injection",),
    )
    proof = result.observations[0]
    assert result.status == "success"
    assert proof["proof_state"] == "verified"
    assert proof["proof_contract"] == PROOF_CONTRACTS["template_injection"]
    assert proof["technique"] == "arithmetic_double_brace_repeated"
    assert proof["payload_shape"] == "{{<n>*<n>}}"
    assert proof["repetitions"] == 2 and len(proof["response_pairs"]) == 2
    assert proof["origin"] == "https://app.example.test"
    # The baseline, two probes with different factors, and the control without template syntax.
    probes = [value for value in transport.values if value.startswith("{{")]
    assert len(probes) == 2 and probes[0] != probes[1]
    assert any(re.fullmatch(r"\d+\*\d+", value) for value in transport.values)


def test_an_endpoint_that_echoes_its_input_is_not_template_injection():
    transport = Recorder(lambda request, value: _answer(request, f"<p>{value}</p>".encode()))
    result = _run(
        _request(url="https://app.example.test/render?q=world"), _candidate(), transport,
        classes=("template_injection",),
    )
    assert result.observations[0]["proof_state"] == "not_proven"


def test_an_arithmetic_evaluator_is_not_template_injection():
    def calculator(request, value):
        inner = re.sub(r"^\{\{|\}\}$", "", value)
        match = re.fullmatch(r"(\d+)\*(\d+)", inner)
        return _answer(
            request, str(int(match.group(1)) * int(match.group(2))).encode() if match else b"?",
        )

    transport = Recorder(calculator)
    result = _run(
        _request(url="https://app.example.test/render?q=1"), _candidate(), transport,
        classes=("template_injection",),
    )
    # The product came back for the template form, and for the bare factors too: the control.
    assert result.observations[0]["proof_state"] == "not_proven"
    assert any(re.fullmatch(r"\d+\*\d+", value) for value in transport.values)


def test_path_traversal_is_proven_by_a_file_signature_a_missing_file_does_not_return():
    def reader(request, value):
        if value.endswith("etc/passwd") and value.startswith("../"):
            return _answer(request, PASSWD)
        return _answer(request, b"<p>not found</p>", status=404)

    transport = Recorder(reader)
    result = _run(
        _request(url="https://app.example.test/render?q=report.txt"), _candidate(), transport,
        classes=("path_traversal",),
    )
    proof = result.observations[0]
    assert proof["proof_state"] == "verified"
    assert proof["proof_contract"] == PROOF_CONTRACTS["path_traversal"]
    assert proof["file_signature"] == "unix_passwd"
    assert proof["technique"] == "file_signature_dot_dot_slash_repeated"
    # The file's content is never kept: digests and statuses only.
    assert b"root:x" not in json.dumps(proof).encode()


def test_a_page_that_always_shows_a_passwd_file_is_not_path_traversal():
    transport = Recorder(lambda request, value: _answer(request, b"<pre>" + PASSWD + b"</pre>"))
    result = _run(
        _request(url="https://app.example.test/render?q=report.txt"), _candidate(), transport,
        classes=("path_traversal",),
    )
    proof = result.observations[0]
    assert proof["proof_state"] == "not_proven"
    assert proof["inconclusive_reason"] == "marker_in_baseline"
    # Only the baseline was sent: nothing can be compared with it.
    assert transport.values == ["report.txt"]


def test_a_traversal_answered_the_same_for_a_missing_file_is_not_proof():
    def decoy(request, value):
        return _answer(request, PASSWD if ".." in value else b"<p>ok</p>")

    transport = Recorder(decoy)
    result = _run(
        _request(url="https://app.example.test/render?q=report.txt"), _candidate(), transport,
        classes=("path_traversal",),
    )
    assert result.observations[0]["proof_state"] == "not_proven"


def _shell(request, value):
    """``ping <value>`` through a shell: a ``;echo`` runs and its arithmetic is expanded."""
    match = re.search(r";echo (\w+)\$\(\((\d+)\+(\d+)\)\)(\w+);", value)
    if match:
        total = int(match.group(2)) + int(match.group(3))
        return _answer(request, f"PING\n{match.group(1)}{total}{match.group(4)}\n".encode())
    return _answer(request, b"PING 1 packets transmitted\n")


def test_command_injection_is_proven_by_evaluated_arithmetic_between_markers():
    transport = Recorder(_shell)
    result = _run(
        _request(url="https://app.example.test/render?q=127.0.0.1"), _candidate(), transport,
        classes=("command_injection",),
    )
    proof = result.observations[0]
    assert proof["proof_state"] == "verified"
    assert proof["proof_contract"] == PROOF_CONTRACTS["command_injection"]
    assert proof["technique"] == "arithmetic_echo_semicolon_repeated"
    assert all(value.startswith("127.0.0.1") for value in transport.values)


def test_blind_command_injection_is_proven_by_a_repeated_delay():
    transport = Recorder(lambda request, value: _answer(
        request, b"ok", elapsed_ms=1100 if "|sleep 1" in value else 15,
    ))
    result = _run(
        _request(url="https://app.example.test/render?q=127.0.0.1"), _candidate(), transport,
        classes=("command_injection",),
    )
    proof = result.observations[0]
    assert proof["proof_state"] == "verified"
    assert proof["proof_contract"] == PROOF_CONTRACTS["command_injection_time"]
    assert proof["repetitions"] == 3 and len(proof["response_pairs"]) == 3
    assert proof["timing_ms"]["payload_median"] - proof["timing_ms"]["control_median"] >= 750


def test_one_slow_answer_is_not_command_injection():
    slow = iter([True])

    def flaky(request, value):
        return _answer(
            request, b"ok", elapsed_ms=1500 if "sleep 1" in value and next(slow, False) else 15,
        )

    result = _run(
        _request(url="https://app.example.test/render?q=127.0.0.1"), _candidate(),
        Recorder(flaky), classes=("command_injection",),
    )
    assert result.observations[0]["proof_state"] == "not_proven"


XML = '<?xml version="1.0"?><order><item>lamp</item></order>'


class XmlTransport:
    def __init__(self, *, external: bool):
        self.external = external
        self.bodies: list[str] = []

    async def send(self, request, **_kwargs):
        body = request.body.decode()
        self.bodies.append(body)
        entities = dict(re.findall(r'<!ENTITY (\w+) "([^"]*)">', body))
        system = dict(re.findall(r'<!ENTITY (\w+) SYSTEM "([^"]*)">', body))
        item = re.search(r"<item>(.*?)</item>", body).group(1)
        if item == "&skx;" and "skx" in system:
            found = self.external and system["skx"] == "file:///etc/passwd"
            return _answer(request, PASSWD if found else b"<error/>")
        if item == "&skx;" and "skx" in entities:
            expanded = re.sub(r"&(\w+);", lambda m: entities.get(m.group(1), ""), entities["skx"])
            return _answer(request, f"<ok>{expanded}</ok>".encode())
        return _answer(request, f"<ok>{item}</ok>".encode())


def _xml_run(transport):
    return _run(
        _request(method="POST", url="https://app.example.test/order", body=XML,
                 content_type="application/xml"),
        _candidate(method="POST", parameter_name="item", request_class="confirmed_mutation",
                   canonical_path="/order"),
        transport, classes=("xxe",),
    )


def test_xxe_is_proven_by_an_external_entity_that_returns_a_file_signature():
    transport = XmlTransport(external=True)
    result = _xml_run(transport)
    proof = _by_class(result)["xxe"]
    assert proof["proof_state"] == "verified"
    assert proof["proof_contract"] == PROOF_CONTRACTS["xxe"]
    assert proof["file_signature"] == "unix_passwd"
    assert all(body.count("<!DOCTYPE order [") == 1 for body in transport.bodies[1:])
    assert result.actual_budget["state_changing_requests"] == len(transport.bodies)


def test_expanded_internal_entities_alone_are_not_xxe():
    result = _xml_run(XmlTransport(external=False))
    proof = _by_class(result)["xxe"]
    assert proof["proof_state"] == "not_proven"
    assert proof["internal_entities_expanded"] is True


def test_xxe_is_not_tried_on_a_request_that_is_not_xml():
    transport = Recorder(lambda request, value: _answer(request, b"ok"))
    result = _run(
        _request(url="https://app.example.test/render?q=world"), _candidate(), transport,
        classes=("xxe",),
    )
    assert result.observations == ()
    assert transport.values == ["world"]


def test_every_class_runs_on_one_candidate_and_only_the_real_one_is_proven():
    transport = Recorder(_jinja)
    result = _run(
        _request(url="https://app.example.test/render?q=world"), _candidate(), transport,
    )
    states = {name: item["proof_state"] for name, item in _by_class(result).items()}
    assert states == {
        "template_injection": "verified", "path_traversal": "not_proven",
        "command_injection": "not_proven",
    }
    assert result.status == "success"


def test_a_refused_baseline_is_inconclusive_and_sends_no_probe():
    transport = Recorder(lambda request, value: _answer(request, b"", status=401))
    result = _run(
        _request(url="https://app.example.test/render?q=world"), _candidate(), transport,
    )
    assert transport.values == ["world"]
    assert result.status == "partial"
    assert result.observations[0]["finding_verdict"] == "inconclusive"
    assert result.observations[0]["proof_state"] == "not_proven"


def test_the_request_reservation_is_never_exceeded_and_a_short_one_is_partial():
    transport = Recorder(lambda request, value: _answer(request, b"ok"))
    result = _run(
        _request(url="https://app.example.test/render?q=world"), _candidate(), transport,
        http_requests=6,
    )
    assert len(transport.values) <= 6
    assert result.actual_budget["http_requests"] == len(transport.values)
    # Not every class could be tried: partial, never a clean "nothing found".
    assert result.status == "partial" and result.partial is True


def test_a_request_that_writes_settles_every_request_as_state_changing():
    class Body:
        def __init__(self):
            self.sent = 0

        async def send(self, request, **_kwargs):
            self.sent += 1
            return _answer(request, b"ok")

    transport = Body()
    result = _run(
        _request(method="POST", url="https://app.example.test/render",
                 body=json.dumps({"q": "world"}), content_type="application/json"),
        _candidate(method="POST", field_path="q", request_class="confirmed_mutation"),
        transport, classes=("template_injection",),
    )
    assert result.actual_budget["state_changing_requests"] == transport.sent
    assert result.actual_budget["http_requests"] == transport.sent


def test_a_candidate_without_a_field_or_with_another_method_is_refused():
    spec = CAPABILITY_REGISTRY.require("injection.verify_batch")
    request = _request(url="https://app.example.test/render?q=world")
    budget = {"http_requests": 10}
    with pytest.raises(InjectionVerifyError):
        InjectionVerifyAdapter(
            specification=spec, target=_target(), request=request,
            candidate={"candidate_id": "a" * 64, "method": "GET"},
            transport=None, requested_budget=budget,
        )
    with pytest.raises(InjectionVerifyError):
        InjectionVerifyAdapter(
            specification=spec, target=_target(), request=request,
            candidate=_candidate(method="POST"), transport=None, requested_budget=budget,
        )
    with pytest.raises(InjectionVerifyError):
        InjectionVerifyAdapter(
            specification=spec, target=_target(), request=request, candidate=_candidate(),
            transport=None, requested_budget={"http_requests": 3},
        )
