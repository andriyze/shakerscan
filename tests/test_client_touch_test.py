"""``shakerscan approve --test``, and what ``agent --allow`` shows before its touch (client
touchtest.py, scripts/hunt_approve.py).

Unit fixtures throughout: the gateway is a SCRIPTED GATEWAY written from the protocol text
(``send(method, path, payload)`` answers), and the security key is a scripted signer. The real
gateway and python-fido2 over a software CTAP2 key are exercised by the Enterprise gateway's own
end-to-end tests.

Covered: the touch test is one touch over a document that decides nothing (purpose ``key_check``),
asked only at an interactive terminal (exit 3 elsewhere, no request sent), not begun against a
gateway that predates it, and refused without an Enterprise connection; ``agent --allow`` shows the
session's safety budget, as the gateway names it, before the touch.
"""

from __future__ import annotations

import io
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "client" / "src"))

import hunt_approve as approval  # noqa: E402
import v2_cli  # noqa: E402

ORIGIN = "https://gateway.example.com"


def at_a_terminal(monkeypatch, *, stdin=True, stdout=True):
    monkeypatch.setattr(sys, "stdin", types.SimpleNamespace(isatty=lambda: stdin, readline=lambda: ""))
    out = io.StringIO()
    out.isatty = lambda: stdout  # type: ignore[method-assign]
    monkeypatch.setattr(sys, "stdout", out)
    return out


# ---- agent --allow: the session's one safety budget ------------------------------------------


def test_the_sessions_safety_budget_is_shown_before_the_touch(monkeypatch):
    shown = []
    terminal = types.SimpleNamespace(require=lambda *a, **k: None, say=shown.append)
    challenge = {"approval_id": "apv_1", "set_digest": "0" * 64, "account": "alice",
                 "safety_budget": [{"limit": "max_state_changing_requests", "label": "state-changing requests",
                                    "total": 40}, {"limit": "max_tcp_ports", "label": "TCP\x1b[2J ports",
                                                   "total": 2400}]}
    order = []
    monkeypatch.setattr(approval.StepUp, "begin", lambda self, purpose, body: (challenge, {}))
    monkeypatch.setattr(approval.StepUp, "prove", lambda self, c: order.append(list(shown)) or {"method": "x"})
    monkeypatch.setattr(approval.StepUp, "finish", lambda self, c, p: {"preauthorization": {"id": "prt_1"}})
    approval.preauthorize(lambda *a, **k: (200, {}), ORIGIN, terminal, ["budget.raise:2x"], use="agent_launch")
    said = [line for line in order[0] if "safety budget" in line]
    assert said == ["Every Hunt this agent session starts shares one safety budget: state-changing requests "
                    f"40, {approval._inert('TCP' + chr(27) + '[2J ports')[:40]} 2,400."]
    assert chr(27) not in said[0]
    assert approval.safety_budget_words(None) == "" and approval.safety_budget_words([{"total": "40"}]) == ""


# ---- shakerscan approve --test --------------------------------------------------------------


class TouchTestGateway:
    """SCRIPTED GATEWAY (unit fixture): describes itself, and begins and finishes a touch test as
    the protocol text says (the set document names the touch test and that it decides nothing)."""

    def __init__(self, *, newer=True, touch_required=False):
        self.newer, self.touch_required = newer, touch_required
        self.calls: list[tuple[str, str, dict | None]] = []

    def __call__(self, method, path, payload=None, headers=None, **_):
        self.calls.append((method, path, payload))
        if method == "GET" and path == approval.ME_PATH:
            return 200, ({"person_decision_proof": self.touch_required} if self.newer else {"user": {}})
        if path == approval.BEGIN_PATH:
            document = approval.set_document("key_check", "alice", ORIGIN, {"key_check": payload["key_check"]})
            digest = approval.set_digest(document)
            nonce = "bm9uY2U"
            return 200, {"schema_version": "shakerscan-approval-challenge/v1", "approval_id": "apv_1",
                         "set_digest": digest, "methods": ["security_key"], "account": "alice", "nonce": nonce,
                         "webauthn": {"challenge": approval.expected_challenge(nonce, digest),
                                      "rpId": "gateway.example.com", "userVerification": "discouraged"}}
        if path == approval.FINISH_PATH:
            return 200, {"schema_version": "shakerscan-approval-result/v1", "decided_by": "alice",
                         "key_check": {"answered": True, "decides": "nothing",
                                       "touch_required": self.touch_required}}
        raise AssertionError(path)


def _touch_test(monkeypatch, gateway, *, token="token-1"):
    from shakerscan import touchtest

    monkeypatch.setattr(v2_cli, "_approval_send", lambda client: gateway)
    monkeypatch.setattr(touchtest, "load", lambda name: v2_cli)
    monkeypatch.setattr(approval, "security_key_readiness", lambda **_: "")
    signed = []

    def signer(webauthn, origin, terminal, *, prompt="", **_):
        signed.append((dict(webauthn), prompt))
        terminal.say(prompt)
        return {"id": "Y3JlZA", "rawId": "Y3JlZA", "type": "public-key", "response": {}}

    monkeypatch.setattr(approval, "security_key_assertion", signer)
    environ = {"SHAKERSCAN_API_TOKEN": token} if token else {}
    return touchtest.approve_test(["--test"], ORIGIN, None, environ=environ), signed


@pytest.mark.parametrize("required", [False, True])
def test_a_touch_test_is_one_touch_and_decides_nothing(monkeypatch, required):
    monkeypatch.delenv("SHAKERSCAN_AGENT_NAME", raising=False)
    out = at_a_terminal(monkeypatch)
    gateway = TouchTestGateway(touch_required=required)
    status, signed = _touch_test(monkeypatch, gateway)
    assert status == 0
    begin = next(payload for method, path, payload in gateway.calls if path == approval.BEGIN_PATH)
    assert begin["purpose"] == "key_check" and begin["key_check"] == {"test": "touch", "decides": "nothing"}
    assert len(signed) == 1 and signed[0][1] == ("Touch your security key to test it; this decides nothing, "
                                                 "as alice (Ctrl-C to cancel)...")
    said = out.getvalue()
    assert "Your security key answered for alice: a touch from this terminal works. Nothing was decided." in said
    assert ("Your administrator requires this touch" in said) is required
    assert ("The touch switch is off on this installation" in said) is not required


@pytest.mark.parametrize(("stdin", "stdout", "agent"), [(False, True, ""), (True, False, ""), (True, True, "codex")])
def test_a_touch_test_asks_only_a_person_at_their_terminal(monkeypatch, capsys, stdin, stdout, agent):
    at_a_terminal(monkeypatch, stdin=stdin, stdout=stdout)
    if agent:
        monkeypatch.setenv("SHAKERSCAN_AGENT_NAME", agent)
    else:
        monkeypatch.delenv("SHAKERSCAN_AGENT_NAME", raising=False)
    gateway = TouchTestGateway()
    status, signed = _touch_test(monkeypatch, gateway)
    assert status == 3 and signed == [] and gateway.calls == []


def test_a_touch_test_is_not_begun_against_a_gateway_that_predates_it(monkeypatch, capsys):
    monkeypatch.delenv("SHAKERSCAN_AGENT_NAME", raising=False)
    at_a_terminal(monkeypatch)
    gateway = TouchTestGateway(newer=False)
    status, signed = _touch_test(monkeypatch, gateway)
    assert status == 1 and signed == []
    assert [path for _, path, _ in gateway.calls] == [approval.ME_PATH]
    assert "no touch test" in capsys.readouterr().err


def test_a_touch_test_needs_an_enterprise_connection(monkeypatch, capsys):
    monkeypatch.delenv("SHAKERSCAN_AGENT_NAME", raising=False)
    at_a_terminal(monkeypatch)
    gateway = TouchTestGateway()
    status, _ = _touch_test(monkeypatch, gateway, token="")
    assert status == 2 and gateway.calls == []
    assert "Enterprise gateway" in capsys.readouterr().err


def test_the_touch_test_document_is_the_one_the_gateway_signs():
    """The set document of a touch test, as the gateway computes it (approvals.set_document)."""
    document = approval.set_document("key_check", "alice", ORIGIN + "/", {"key_check": {"ignored": True}})
    assert document == {"schema_version": "shakerscan-approval-set/v1", "purpose": "key_check",
                        "account": "alice", "origin": ORIGIN, "key_check": {"test": "touch", "decides": "nothing"}}
