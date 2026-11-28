"""Applications that are not vulnerable but answered the injection proofs as if they were.

Each test pairs a "fooling application" (a load balancer, a firewall, a search page) that must
not be verified with the genuinely vulnerable one that still is. The fakes model a behaviour,
never a product.
"""
from __future__ import annotations

import asyncio
import itertools
import json
import re

import pytest

from api.capabilities.injection_verify import InjectionVerifyAdapter, InjectionVerifyError, PROOF_CONTRACTS
from api.capabilities.sqli_proof import SQLiProofAdapter, _mixed_order
from api.runtime.capability_registry import CAPABILITY_REGISTRY
from tests.test_injection_verify_capability import (
    PASSWD, Recorder, XML, XmlTransport, _answer, _blind_shell, _by_class, _candidate, _request,
    _run, _target,
)

BLIND = "https://app.example.test/render?q=127.0.0.1"


def _command(respond):
    transport = Recorder(respond)
    result = _run(_request(url=BLIND), _candidate(), transport, classes=("command_injection",))
    return result.observations[0], transport


# -- blind command injection: time alone is not the proof ----------------------------------------


@pytest.mark.parametrize("period, latencies", [
    (2, (0, 1200)), (2, (1200, 0)),
    (3, (0, 1000, 2000)), (3, (1000, 2000, 0)), (3, (2000, 0, 1000)),
    (4, (0, 1200, 0, 1200)), (4, (0, 0, 1200, 1200)), (5, (0, 1000, 2000, 0, 1000)),
])
def test_replicas_of_different_speed_behind_a_round_robin_are_not_command_injection(period, latencies):
    """Requests go to each replica in turn and one is slower. Control and payload sent in turn
    line up with the replicas: every control fast, every payload slow, and no shell anywhere."""
    confirmed = 0
    for phase in range(period):
        turn = itertools.count(phase)

        def balanced(request, value):
            return _answer(request, b"ok", elapsed_ms=15 + latencies[next(turn) % period])

        proof, transport = _command(balanced)
        assert proof["proof_state"] == "not_proven", (period, latencies, phase)
        confirmed += any("sleep 0" in value for value in transport.values)
    # In some phase a screen did land on a slower replica: the confirmation was sent, and failed.
    assert confirmed


@pytest.mark.parametrize("scaled", [False, True])
def test_a_firewall_that_holds_and_refuses_a_sleep_payload_is_not_command_injection(scaled):
    """``sleep 0`` passes; ``sleep 1`` is held and answered 403. The delay is the firewall's."""
    def firewall(request, value):
        blocked = re.search(r"sleep ([1-9])", value)
        if blocked:
            held = 1200 * (int(blocked.group(1)) if scaled else 1)
            return _answer(request, b"<h1>Forbidden</h1>", status=403, elapsed_ms=15 + held)
        return _answer(request, b"ok", elapsed_ms=15)

    proof, transport = _command(firewall)
    assert proof["proof_state"] == "not_proven"
    assert any("sleep 2" in value for value in transport.values)


def test_a_fixed_penalty_for_a_sleep_payload_is_not_command_injection():
    """Same status and body, 1.2 s slower for any ``sleep <n>`` with n above zero: the delay does
    not follow the number of seconds, so nothing slept."""
    def tarpit(request, value):
        return _answer(request, b"ok", elapsed_ms=1215 if re.search(r"sleep [1-9]", value) else 15)

    proof, _transport = _command(tarpit)
    assert proof["proof_state"] == "not_proven"


def test_a_delayed_answer_with_another_body_is_not_command_injection():
    """A challenge page with the control's status, served after a delay that even follows the
    seconds asked for: the body is not the application's."""
    def challenge(request, value):
        blocked = re.search(r"sleep ([1-9])", value)
        if blocked:
            return _answer(request, b"<p>checking your browser</p>", elapsed_ms=15 + 1000 * int(blocked.group(1)))
        return _answer(request, b"ok", elapsed_ms=15)

    proof, _transport = _command(challenge)
    assert proof["proof_state"] == "not_proven"


def test_a_blind_shell_behind_a_page_that_changes_every_time_and_echoes_its_input_is_still_proven():
    """The body cannot be compared (a clock in it) and the payload is echoed: status and the
    delay following the seconds still prove it."""
    tick = itertools.count()

    def shell(request, value):
        base = _blind_shell(request, value)
        return _answer(request, f"<p>{value}</p><i>{next(tick)}</i>".encode(), elapsed_ms=base.elapsed_ms)

    proof, _transport = _command(shell)
    assert proof["proof_state"] == "verified"
    assert proof["proof_contract"] == PROOF_CONTRACTS["command_injection_time"]


def test_a_blind_shell_that_runs_the_command_twice_is_still_proven():
    def twice(request, value):
        slept = re.search(r"\|sleep (\d+)$", value)
        return _answer(request, b"ok", elapsed_ms=40 + (2000 * int(slept.group(1)) if slept else 0))

    proof, _transport = _command(twice)
    assert proof["proof_state"] == "verified"


def test_the_blind_confirmation_stays_inside_its_request_reservation():
    transport = Recorder(_blind_shell)
    result = _run(_request(url=BLIND), _candidate(), transport, classes=("command_injection",),
                  http_requests=24)
    assert result.observations[0]["proof_state"] == "verified"
    # The baseline, eleven echo probes, two screens (semicolon, pipe) and the seven confirmations.
    assert len(transport.values) == 21 == result.actual_budget["http_requests"]


def test_a_mixed_order_never_repeats_with_any_period():
    for seed in ("a", "b", "c", "d" * 64):
        for labels in (("control", "payload") * 3, ("control",) * 3 + ("one",) * 2 + ("two",) * 2):
            order = _mixed_order(seed, labels)
            assert sorted(order) == sorted(labels) and order == _mixed_order(seed, labels)
            for period in range(2, len(order)):
                assert any(
                    order[first] != order[second]
                    for first in range(len(order))
                    for second in range(first + period, len(order), period)
                ), (seed, period, order)


# -- SQL injection time proof: the same order and answer rules -------------------------------------


def _sqli(respond, *, extended=False):
    transport = Recorder(respond)
    adapter = SQLiProofAdapter(
        specification=CAPABILITY_REGISTRY.require("sqli.prove_batch"), target=_target(),
        request=_request(url="https://app.example.test/search?q=apple"),
        candidate={"candidate_id": "f" * 64, "method": "GET", "parameter_name": "q",
                   "request_class": "safe_read"},
        transport=transport,
        requested_budget={"http_requests": 30, "state_changing_requests": 0, "tool_wall_seconds": 60},
        extended=extended,
    )
    result = asyncio.run(adapter.execute(heartbeat=lambda: asyncio.sleep(0), cancelled=lambda: False))
    return result.observations[0], transport


@pytest.mark.parametrize("extended", [False, True])
def test_replicas_of_different_speed_are_not_time_based_sql_injection(extended):
    for phase in (0, 1):
        turn = itertools.count(phase)

        def balanced(request, value):
            return _answer(request, b'{"products":[]}', elapsed_ms=20 + 1200 * (next(turn) % 2))

        proof, _transport = _sqli(balanced, extended=extended)
        assert proof["proof_state"] == "not_proven", (extended, phase)


@pytest.mark.parametrize("status", [403, 401, 429, 503, 406])
def test_a_firewall_that_holds_and_refuses_a_delay_function_is_not_sql_injection(status):
    def firewall(request, value):
        if "SLEEP" in value.upper() or "WAITFOR" in value.upper():
            return _answer(request, b"blocked", status=status, elapsed_ms=1300)
        return _answer(request, b'{"products":[]}', elapsed_ms=20)

    proof, transport = _sqli(firewall)
    assert proof["proof_state"] == "not_proven"
    assert sum("SLEEP(1)" in value for value in transport.values) == 3


@pytest.mark.parametrize("delayed_status", [200, 404])
def test_a_delay_the_database_made_is_still_time_based_sql_injection(delayed_status):
    """The delayed statement matched nothing: the same page, or the application's own 404."""
    def database(request, value):
        if "SLEEP(1)" in value:
            return _answer(request, b'{"products":[]}', status=delayed_status, elapsed_ms=1100)
        return _answer(request, b'{"products":[{"id":1}]}', elapsed_ms=20)

    proof, transport = _sqli(database)
    assert proof["proof_state"] == "verified"
    assert proof["proof_contract"] == "sqli_time_differential/v1"
    # The request ceiling is what it was: error pairs, boolean pairs, three controls and payloads.
    assert len(transport.values) == 14


# -- path traversal: a page that quotes the file is not a read of it ---------------------------------

TUTORIAL = b"<h1>Linux users</h1><pre>" + PASSWD + b"</pre>"


def _traversal(respond):
    transport = Recorder(respond)
    result = _run(_request(url="https://app.example.test/docs?q=intro"), _candidate(),
                  transport, classes=("path_traversal",))
    return result.observations[0], transport


def test_a_search_that_finds_a_page_quoting_the_file_is_not_path_traversal():
    """A documentation search splits the query into words and returns pages holding all of them:
    ``../../etc/passwd`` finds the tutorial that quotes the file, a missing file name finds
    nothing, and no file was ever read."""
    def search(request, value):
        words = {word.lower() for word in re.findall(r"[A-Za-z0-9]+", value)}
        return _answer(request, TUTORIAL if words and words <= {"etc", "passwd", "file"} else b"<p>No results</p>")

    proof, transport = _traversal(search)
    assert proof["proof_state"] == "not_proven"
    assert "etc passwd" in transport.values


def test_a_file_read_from_the_traversal_is_still_path_traversal():
    def reader(request, value):
        path = value.replace("....//", "../")
        if path.startswith("file://"):
            path = path[len("file://"):]
        resolved = "/" + "/".join(part for part in path.split("/") if part not in {"", ".."})
        return _answer(request, PASSWD if resolved == "/etc/passwd" and ("/" in value) else b"not found")

    proof, transport = _traversal(reader)
    assert proof["proof_state"] == "verified"
    assert proof["file_signature"] == "unix_passwd"
    # The probe, its repeat, the missing file and the words: four requests after the baseline.
    assert len(transport.values) == 5 and transport.values[-1] == "etc passwd"


def test_a_file_included_in_a_page_layout_is_still_path_traversal():
    def include(request, value):
        found = value.count("../") >= 3 and value.endswith("/etc/passwd")
        return _answer(request, b"<html><nav>Home</nav><main>" + (PASSWD if found else b"") + b"</main></html>")

    proof, _transport = _traversal(include)
    assert proof["proof_state"] == "verified"


# -- one class that cannot be written into the request does not end the candidate -------------------


def test_xxe_is_reached_on_an_xml_request_when_every_class_is_asked_for():
    """Template syntax cannot be written into an XML body. That is the template class's answer,
    not the candidate's: the XML external entity class still runs, and proves."""
    transport = XmlTransport(external=True)
    result = _run(
        _request(method="POST", url="https://app.example.test/order", body=XML, content_type="application/xml"),
        _candidate(method="POST", parameter_name="item", request_class="confirmed_mutation", canonical_path="/order"),
        transport,
    )
    proofs = _by_class(result)
    assert proofs["xxe"]["proof_state"] == "verified"
    assert proofs["template_injection"]["inapplicable_reason"] == "field_not_mutable"
    assert proofs["template_injection"]["proof_state"] == "not_proven"
    assert proofs["command_injection"]["inapplicable_reason"] == "field_not_mutable"
    assert result.status == "success" and result.errors == ()
    assert result.redacted_execution["inapplicable_classes"] == ["command_injection", "template_injection"]
    assert "xxe" in result.redacted_execution["classes"]


def test_a_request_no_class_can_be_written_into_is_still_blocked():
    class Count:
        sent = 0

        async def send(self, request, **_kwargs):
            self.sent += 1
            return _answer(request, b"ok")

    transport = Count()
    result = _run(
        _request(method="POST", url="https://app.example.test/order", body="plain text", content_type="text/plain"),
        _candidate(method="POST", parameter_name="item", request_class="confirmed_mutation"),
        transport, classes=("template_injection", "command_injection"),
    )
    assert result.status == "blocked" and transport.sent == 1
    assert all(item["proof_state"] == "not_proven" for item in result.observations)


# -- a write is sent only against a state-changing hold, and never past it ---------------------------


def _write_adapter(transport, budget):
    return InjectionVerifyAdapter(
        specification=CAPABILITY_REGISTRY.require("injection.verify_batch"), target=_target(),
        request=_request(method="POST", url="https://app.example.test/render",
                         body=json.dumps({"q": "world"}), content_type="application/json"),
        candidate=_candidate(method="POST", field_path="q", request_class="confirmed_mutation"),
        transport=transport, requested_budget=budget,
        classes=("template_injection", "command_injection"),
    )


class _Counting:
    def __init__(self):
        self.sent = 0

    async def send(self, request, **_kwargs):
        self.sent += 1
        return _answer(request, b"ok")


@pytest.mark.parametrize("budget", [
    {"http_requests": 40, "tool_wall_seconds": 60},
    {"http_requests": 40, "state_changing_requests": 0, "tool_wall_seconds": 60},
    {"http_requests": 40, "state_changing_requests": 3, "tool_wall_seconds": 60},
])
def test_a_write_candidate_without_a_state_changing_hold_is_refused_before_any_request(budget):
    transport = _Counting()
    with pytest.raises(InjectionVerifyError, match="state-changing"):
        _write_adapter(transport, budget)
    assert transport.sent == 0


def test_a_write_candidate_sends_no_request_past_its_state_changing_hold():
    transport = _Counting()
    adapter = _write_adapter(
        transport, {"http_requests": 40, "state_changing_requests": 6, "tool_wall_seconds": 60},
    )
    result = asyncio.run(adapter.execute(heartbeat=lambda: asyncio.sleep(0), cancelled=lambda: False))
    assert 4 <= transport.sent <= 6
    assert result.actual_budget["state_changing_requests"] == transport.sent
    assert result.actual_budget["http_requests"] == transport.sent
    assert result.partial is True
    # The same candidate with the hold its requests need sends them all.
    funded = _Counting()
    asyncio.run(_write_adapter(
        funded, {"http_requests": 40, "state_changing_requests": 40, "tool_wall_seconds": 60},
    ).execute(heartbeat=lambda: asyncio.sleep(0), cancelled=lambda: False))
    assert funded.sent > 6


def test_a_graphql_query_sent_by_post_needs_no_state_changing_hold():
    transport = _Counting()
    adapter = InjectionVerifyAdapter(
        specification=CAPABILITY_REGISTRY.require("injection.verify_batch"), target=_target(),
        request=_request(method="POST", url="https://app.example.test/graphql",
                         body=json.dumps({"query": 'query{search(keyword:"a"){id}}'}),
                         content_type="application/json"),
        candidate=_candidate(method="POST", field_path="graphql:keyword", request_class="safe_read"),
        transport=transport, requested_budget={"http_requests": 12, "tool_wall_seconds": 60},
        classes=("template_injection",),
    )
    result = asyncio.run(adapter.execute(heartbeat=lambda: asyncio.sleep(0), cancelled=lambda: False))
    assert transport.sent > 1 and "state_changing_requests" not in result.actual_budget
