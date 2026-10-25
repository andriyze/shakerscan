"""A Hunt start past its agent session's safety budget, and decisions a terminal cannot confirm
(scripts/person_decision.py, scripts/shakerscan_mcp.py).

Unit fixtures throughout: the gateway's refusals are written from the protocol text. The real
gateway is exercised by the Enterprise gateway's own end-to-end tests.

Covered: a Hunt start the gateway names ``hunt.start`` (past its agent session's one safety budget):
the person's command is that start itself through ``shakerscan api``, and the agent's line and the
MCP answer say not to send it again; a decision the gateway says only the browser confirms
(``proof: browser``) is never begun, in a terminal or not, and the line and the MCP answer say to
make it in the browser.
"""

from __future__ import annotations

import hashlib
import io
import json
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "client" / "src"))

import person_decision as decision  # noqa: E402
import shakerscan_mcp as mcp  # noqa: E402

ORIGIN = "https://gateway.example.com"
TARGET = "1a2b3c4d-1111-4222-8333-444455556666"
START = {"target_id": TARGET, "target_kind": "web", "policy": {}, "allow": ["budget.raise:2x"]}
START_SUMMARY = (
    "Start a Hunt of honey.example.com on the balanced profile, start bounds budget.raise:2x, past "
    "the safety budget of agent session prt_1234… (launched 10:41 UTC) (1 Hunt counted): it starts "
    "with state-changing requests 20 (safety ceiling; 0 of 40 left)"
)
START_REFUSAL = {"error": "person_decision_required", "decision": "hunt.start", "summary": START_SUMMARY,
                 "proof": "security_key", "message": "an administrator requires a security-key touch"}
PLAN = f"/hunts/{TARGET}/shell-plans/{TARGET}/confirm"
BROWSER_REFUSAL = {"error": "person_decision_required", "decision": "shell_plan.confirm",
                   "summary": "Confirm SSH plan 1a2b3c4d… of Hunt 1a2b3c4d… on honey.example.com",
                   "proof": "browser", "message": "made in the browser only"}


def at_a_terminal(monkeypatch, *, stdin=True, stdout=True):
    monkeypatch.setattr(sys, "stdin", types.SimpleNamespace(isatty=lambda: stdin, readline=lambda: ""))
    out = io.StringIO()
    out.isatty = lambda: stdout  # type: ignore[method-assign]
    monkeypatch.setattr(sys, "stdout", out)
    return out


# ---- a Hunt start past its session's safety budget -------------------------------------------


def test_the_persons_command_for_a_start_past_the_budget_is_that_start_itself():
    raw = json.dumps(START, separators=(",", ":")).encode()
    command = decision.person_command("POST", "/hunts", raw, START_REFUSAL)
    assert command == "shakerscan api POST /hunts '" + raw.decode() + "'"
    # Never the target's authorization (which the person would run, and the agent then start).
    assert "targets authorize" not in command
    line = decision.refusal_line(START_REFUSAL, command)
    assert line.startswith(f"person decision required: {START_SUMMARY}. Nothing was started.")
    assert "Do not send this start again" in line
    # The agent finds the Hunt the person's command started; the person passes no id back.
    assert "find that Hunt with `shakerscan hunt list`" in line
    assert line.endswith(command) and "\n" not in line


def test_a_long_start_body_is_named_by_a_file_in_the_decisions_directory(tmp_path, monkeypatch):
    monkeypatch.setenv("SHAKERSCAN_CONFIG_DIR", str(tmp_path))
    body = {**START, "goal": "x" * 2000}
    raw = json.dumps(body).encode()
    command = decision.person_command("POST", "/hunts", raw, START_REFUSAL)
    saved = tmp_path / "decisions" / (hashlib.sha256(raw).hexdigest()[:24] + ".json")
    assert command == f"shakerscan api POST /hunts @{saved}"
    assert saved.read_bytes() == raw


def test_an_agents_start_past_the_budget_exits_3_and_never_begins(monkeypatch):
    at_a_terminal(monkeypatch, stdout=False)
    begun = []
    with pytest.raises(decision.PersonDecisionRefused) as refused:
        decision.handle(lambda path, payload: begun.append(path) or (500, {}), origin=ORIGIN, method="POST",
                        path="/hunts", body=json.dumps(START).encode(), detail=START_REFUSAL,
                        resend=lambda grant: None)
    assert begun == []
    assert refused.value.command.startswith("shakerscan api POST /hunts ")


def test_the_mcp_adapter_says_the_users_command_starts_the_hunt():
    error = types.SimpleNamespace(code=403, headers={"x-shakerscan-step-up": "required"})
    answer = mcp._person_decision_error(error, json.dumps({"detail": START_REFUSAL}), "POST", "/hunts",
                                        json.dumps(START).encode())
    assert "do not start it again yourself: the user's command starts it" in answer.message
    detail = mcp._error_detail(answer)
    assert detail["decision"] == "hunt.start" and detail["command"].startswith("shakerscan api POST /hunts ")
    assert detail["recovery"] == mcp.PERSON_DECISION_START_RECOVERY


# ---- decisions only the browser confirms ------------------------------------------------------


@pytest.mark.parametrize("stdout", [True, False])
def test_a_decision_only_the_browser_confirms_is_never_begun(monkeypatch, stdout):
    at_a_terminal(monkeypatch, stdout=stdout)
    begun = []
    with pytest.raises(decision.PersonDecisionRefused) as refused:
        decision.handle(lambda path, payload: begun.append(path) or (500, {}), origin=ORIGIN, method="POST",
                        path=PLAN, body=b"{}", detail=BROWSER_REFUSAL, resend=lambda grant: None)
    assert begun == []
    assert refused.value.command == ""
    assert refused.value.line == (f"person decision required: {BROWSER_REFUSAL['summary']}. Nothing was "
                                  f"changed. {decision.BROWSER_ONLY}")


def test_the_mcp_adapter_sends_a_browser_only_decision_to_the_browser():
    error = types.SimpleNamespace(code=403, headers={"x-shakerscan-step-up": "required"})
    answer = mcp._person_decision_error(error, json.dumps({"detail": BROWSER_REFUSAL}), "POST", PLAN, b"{}")
    assert "makes it in the browser" in answer.message and "shakerscan api" not in answer.message
    detail = mcp._error_detail(answer)
    assert detail["proof"] == "browser" and "command" not in detail
    assert detail["recovery"] == mcp.PERSON_DECISION_BROWSER_RECOVERY


