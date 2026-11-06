"""A fixed intranet app on a production-labelled target can be retested as likely fixed.

Unit fixtures: the finding's host resolves (through an injected lookup) to the private address
10.20.30.40, and connections to it are served by a local asyncio server the test starts, so the
destination policy sees the private address while the bytes stay on this machine.
"""
from __future__ import annotations

import asyncio

import pytest

from api.targets import liveness as lv
from api.worker_handlers import retest_outcome as ro

PRIVATE_URL = "http://10.20.30.40:8080/search?q=1"
INPUTS = {"original_url": PRIVATE_URL}


def _not_reproduced(**kwargs):
    return ro.classify_retest_outcome(proof={"evidence_type": ""}, proven=False, confidence=0.8,
                                      inputs=INPUTS, **kwargs)


def test_a_private_target_with_no_shown_reach_stays_inconclusive():
    assert _not_reproduced() == (
        "inconclusive", "out_of_scope_internal",
        "Target appears internal/private and could require internal network access.")
    status, verdict, reason = _not_reproduced(origin_reached=False,
                                              reach_reason="http://10.20.30.40:8080 was not reached: port 8080: connection refused")
    assert (status, verdict) == ("inconclusive", "out_of_scope_internal")
    assert "connection refused" in reason


def test_a_private_target_the_retest_reached_is_likely_fixed():
    assert _not_reproduced(origin_reached=True)[:2] == ("likely_fixed", "likely_fixed")
    # Reach never turns other inconclusive readings into fixed.
    refused = ro.classify_retest_outcome(proof={"evidence_type": "target_refused"}, proven=False,
                                         confidence=None, inputs=INPUTS, origin_reached=True)
    assert refused[1] == "inconclusive"
    weak = ro.classify_retest_outcome(proof={"evidence_type": ""}, proven=False, confidence=0.1,
                                      inputs=INPUTS, origin_reached=True)
    assert weak[1] == "inconclusive"


@pytest.fixture
def private_origin(monkeypatch):
    """10.20.30.40:8080 served by a local server answering ``answer`` (None: refuse)."""
    state = {"answer": b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", "connections": 0}
    real_open = asyncio.open_connection

    async def fake_open(address, port, **kwargs):
        assert address == "10.20.30.40" and port == 8080
        state["connections"] += 1
        if state["answer"] is None:
            raise ConnectionRefusedError()

        async def serve(reader, writer):
            await reader.readuntil(b"\r\n\r\n")
            writer.write(state["answer"])
            await writer.drain()
            writer.close()
        server = await asyncio.start_server(serve, "127.0.0.1", 0)
        state.setdefault("servers", []).append(server)
        return await real_open("127.0.0.1", server.sockets[0].getsockname()[1], **kwargs)

    async def lookup(host):
        return ["10.20.30.40"]
    monkeypatch.setattr(lv.asyncio, "open_connection", fake_open)
    monkeypatch.setattr(lv.target_resolution, "system_lookup", lookup)
    monkeypatch.delenv("SHAKERSCAN_PRIVATE_NETWORK_TARGETS", raising=False)
    return state


def test_reach_check_on_a_private_production_origin(private_origin):
    reached, reason = asyncio.run(ro.internal_origin_reach(PRIVATE_URL, authorized=False))
    assert reached is True and reason == "http://10.20.30.40:8080 answered HTTP 200"
    assert _not_reproduced(origin_reached=reached, reach_reason=reason)[1] == "likely_fixed"

    private_origin["answer"] = None
    reached, reason = asyncio.run(ro.internal_origin_reach(PRIVATE_URL, authorized=False))
    assert reached is False and "connection refused" in reason
    assert _not_reproduced(origin_reached=reached, reach_reason=reason)[1] == "out_of_scope_internal"


def test_reach_check_respects_a_deployment_that_refuses_private_targets(private_origin, monkeypatch):
    monkeypatch.setenv("SHAKERSCAN_PRIVATE_NETWORK_TARGETS", "refuse")
    reached, reason = asyncio.run(ro.internal_origin_reach(PRIVATE_URL, authorized=False))
    assert reached is False and "destination policy" in reason
    assert private_origin["connections"] == 0


def test_no_reach_check_when_not_needed(private_origin):
    assert asyncio.run(ro.internal_origin_reach(PRIVATE_URL, authorized=True)) == (None, None)
    assert asyncio.run(ro.internal_origin_reach("https://app.example.com/", authorized=False)) == (None, None)
    assert private_origin["connections"] == 0


def test_a_non_http_answer_is_not_reach(private_origin):
    private_origin["answer"] = b"SSH-2.0-OpenSSH\r\n"
    reached, reason = asyncio.run(ro.internal_origin_reach(PRIVATE_URL, authorized=False))
    assert reached is False and "not HTTP" in reason
