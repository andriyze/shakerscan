"""A person's decision an Enterprise gateway asks a security-key touch for (scripts/person_decision.py).

Unit fixtures throughout: the gateway is a SCRIPTED GATEWAY written from the protocol text (the
refusal, the begin and finish routes of purpose ``person_decision``, the grant header), reached
through the product CLI's own urllib client with a fake opener; the security key is a scripted
signer. The real gateway and python-fido2 over a software CTAP2 key are exercised by the
Enterprise gateway's own end-to-end tests.

Covered: when a refusal is a person's decision, interactive (stdin and stdout a terminal, not an
agent) versus anything else, the command named for each decision kind, the binding the client
checks before asking for a touch, one touch and one resend of the exact bytes with the grant (the
three HTTP stacks: the product CLI, ``shakerscan api`` and ``shakerscan scan``), exit 3 without a
terminal and the key never asked, the MCP adapter's mapping, ``approve`` preferring a plugged-in
key, the user verification the gateway asks for, the key chooser, the watch with no session, and
``targets authorize`` and ``hunt budget raise``.
"""

from __future__ import annotations

import base64
import email.message
import hashlib
import io
import json
import shlex
import sys
import types
import urllib.error
import urllib.parse
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import api_cli  # noqa: E402
import hunt_approve as approval  # noqa: E402
import person_decision as decision  # noqa: E402
import scan_cli  # noqa: E402
import shakerscan_mcp as mcp  # noqa: E402
import v2_cli  # noqa: E402

ORIGIN = "https://gateway.example.com"
HUNT = "3f2a91c0-1111-4222-8333-444455556666"
TARGET = "1a2b3c4d-1111-4222-8333-444455556666"
AMENDMENT = f"/hunts/{HUNT}/budget-amendments"
RAISE = {"schema_version": "hunt-budget-amendment/v1", "limits": {"max_state_changing_requests": 40},
         "expected_revision": 0, "idempotency_key": "k-1", "operator_confirmed": True}
SUMMARY = "Raise state-changing requests 20 -> 40 (safety ceiling) for Hunt 3f2a91c0… (honey.example.com)"
REFUSAL = {"detail": {"error": "person_decision_required", "decision": "budget.raise", "summary": SUMMARY,
                      "proof": "security_key", "message": "an administrator requires a security-key touch"}}


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


class ScriptedGateway:
    """SCRIPTED GATEWAY (unit fixture): refuses a person decision without a grant, answers begin
    and finish as the protocol text says, and accepts the grant once for the same bytes."""

    def __init__(self, *, refuse=True, tamper=None):
        self.refuse, self.tamper = refuse, tamper
        self.sent: list[dict] = []
        self.begun: list[dict] = []
        self.grants: dict[str, str] = {}

    # the proxied request -------------------------------------------------------------------
    def open(self, request, timeout=None):
        headers = {key.lower(): value for key, value in request.header_items()}
        sent = {"method": request.get_method(), "url": request.full_url, "data": request.data,
                "headers": headers}
        self.sent.append(sent)
        grant = headers.get("x-shakerscan-person-proof")
        path = urllib.parse.urlsplit(request.full_url).path
        if self.refuse and path.endswith(("/budget-amendments", "/authorization", "/scans")):
            digest = hashlib.sha256(request.data or b"").hexdigest()
            if not grant or self.grants.pop(grant, None) != digest:
                message = email.message.Message()
                message["x-shakerscan-step-up"] = "required"
                raise urllib.error.HTTPError(request.full_url, 403, "Forbidden", message,
                                             io.BytesIO(json.dumps(REFUSAL).encode()))
        answer = {"ok": True, "status": "active", "scan_id": "s-1"}
        if path.endswith("/authorization"):
            answer = {"target_id": TARGET, "authorization": {"approved_by": "Alice via terminal security-key touch"}}
        if path == "/targets" and request.get_method() == "POST":
            answer = {"id": TARGET, "url": "https://app.example.com/", "name": "app"}
        if path == f"/hunts/{HUNT}" and request.get_method() == "GET":
            answer = {"hunt_id": HUNT, "budget": {"max_state_changing_requests": 20, "max_http_requests": 500},
                      "budget_revision": 2}
        if path == "/scan/contracts":
            answer = {"schema_version": "scan-public-contract/v1", "families": [], "advanced_limits": []}
        if path == "/_enterprise/me":
            # As a gateway describes itself to a connection's token (the service account, the
            # person it acts for, whether a touch is required).
            answer = {"user": {"auth": "token", "display": "Laptop", "token_label": "laptop"},
                      "acts_for_name": "alice", "person_decision_proof": True}
        return _Response(answer)

    # the approval routes -------------------------------------------------------------------
    def post(self, path, payload):
        if path == decision.BEGIN_PATH:
            self.begun.append(payload)
            part = payload["person_decision"]
            target, _, query = part["path"].partition("?")
            body = base64.urlsafe_b64decode(part["body"] + "=" * (-len(part["body"]) % 4))
            binding = {"schema_version": "shakerscan-person-decision/v1", "method": part["method"],
                       "path": urllib.parse.unquote(target), "query": query,
                       "body_sha256": hashlib.sha256(body).hexdigest(), "token_id": "tok-1", "person_id": "p-1"}
            document = {"schema_version": "shakerscan-approval-set/v1", "purpose": "person_decision",
                        "account": "alice", "origin": payload["origin"],
                        "person_decision": {**binding, "decision": "budget.raise", "summary": SUMMARY}}
            if self.tamper:
                self.tamper(document)
            canonical = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            digest = hashlib.sha256(canonical.encode()).hexdigest()
            nonce = b64url(b"n" * 32)
            challenge = b64url(hashlib.sha256(b"n" * 32 + bytes.fromhex(digest)).digest())
            self.digest_of_body = binding["body_sha256"]
            return 200, {"schema_version": "shakerscan-approval-challenge/v1", "approval_id": "apv_1",
                         "set_digest": digest, "methods": ["security_key"], "document": document,
                         "nonce": nonce, "webauthn": {"challenge": challenge, "rpId": "gateway.example.com",
                                                      "userVerification": "discouraged"}}
        if path == decision.FINISH_PATH:
            assert payload["proof"]["method"] == "security_key"
            self.grants["apv_grant_1"] = self.digest_of_body
            return 200, {"schema_version": "shakerscan-approval-result/v1", "decided_by": "alice",
                         "person_decision": {"grant": "apv_grant_1", "header": "x-shakerscan-person-proof"}}
        raise AssertionError(path)


class _Response:
    def __init__(self, value):
        self.raw, self.status = json.dumps(value).encode(), 200

    def read(self, limit=None):
        return self.raw

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class Signer:
    """A scripted security key (unit fixture): records each challenge it was asked to sign."""

    def __init__(self):
        self.asked: list[dict] = []

    def __call__(self, webauthn, origin, terminal, *, prompt="", insert_seconds=None):
        self.asked.append({"webauthn": dict(webauthn), "origin": origin, "insert_seconds": insert_seconds})
        if prompt:  # as the real assertion does, once the key is chosen
            terminal.say(prompt)
        return {"id": "Y3JlZA", "rawId": "Y3JlZA", "type": "public-key", "response": {}}


@pytest.fixture
def gateway(monkeypatch):
    found = ScriptedGateway()
    monkeypatch.setattr(v2_cli, "_opener", lambda: found)
    monkeypatch.setattr(api_cli, "_opener", lambda: found)
    monkeypatch.setattr(scan_cli, "_opener", lambda: found)
    monkeypatch.setattr(decision, "json_poster", lambda *a, **k: found.post)
    monkeypatch.delenv("SHAKERSCAN_AGENT_NAME", raising=False)
    # A key is plugged in and python-fido2 is there (the scripted signer stands for both).
    monkeypatch.setattr(approval, "security_key_readiness", lambda **_: "")
    return found


def newer_gateway(method, path):
    """What a gateway with the touch switch on answers to its own description and the feed."""
    if method == "GET" and path == approval.ME_PATH:
        return 200, {"person_decision_proof": True}
    if method == "GET" and path.startswith(approval.PERSON_FEED_PATH):
        return 200, {"schema_version": approval.PERSON_FEED_SCHEMA, "touch_required": True, "decisions": [],
                     "after": 0}
    return None


def at_a_terminal(monkeypatch, *, stdin=True, stdout=True):
    monkeypatch.setattr(sys, "stdin", types.SimpleNamespace(isatty=lambda: stdin, readline=lambda: ""))
    out = io.StringIO()
    out.isatty = lambda: stdout  # type: ignore[method-assign]
    monkeypatch.setattr(sys, "stdout", out)
    return out


# ---- what counts as a person's decision, and who is asked -------------------------------------


def test_only_the_gateways_refusal_with_its_header_is_a_persons_decision():
    detail = REFUSAL["detail"]
    assert decision.required(403, {"x-shakerscan-step-up": "required"}, detail)
    assert not decision.required(403, {}, detail), "the header is part of the refusal"
    assert not decision.required(409, {"x-shakerscan-step-up": "required"}, detail)
    assert not decision.required(403, {"x-shakerscan-step-up": "required"}, {"error": "step_up_required"})
    assert not decision.required(403, {"x-shakerscan-step-up": "required"}, "person_decision_required")


@pytest.mark.parametrize(("stdin", "stdout", "agent", "expected"), [
    (True, True, "", True),
    (False, True, "", False),  # `yes | shakerscan ...`: a pipe is never the person
    (True, False, "", False),  # output captured: an agent's tool call, `| jq`, `| tee`, `> file`
    (False, False, "", False),
    (True, True, "claude", False),  # inside `shakerscan agent`, even in its own terminal
])
def test_only_a_person_at_a_terminal_is_asked(stdin, stdout, agent, expected):
    """stdin and stdout terminals, and not an agent's shell: a harness that gives a command a
    terminal for its input and errors and captures its output never gets a prompt (and a key
    never blinks for it)."""
    streams = [types.SimpleNamespace(isatty=lambda value=value: value) for value in (stdin, stdout)]
    assert decision.interactive(streams[0], streams[1], {"SHAKERSCAN_AGENT_NAME": agent}) is expected


@pytest.mark.parametrize(("stdin", "stdout", "stderr", "agent", "whole", "asked_on"), [
    (True, True, True, "", True, "stdout"),
    (False, True, True, "", False, None),  # a pipe for input is never the person
    (True, True, False, "", True, "stdout"),
    (True, True, True, "opencode", False, None),  # inside `shakerscan agent`, even in its own terminal
    # stdin a terminal, the output captured (`| tee log`, `> file`): asked as client 0.11.1 asked
    # (the prompts on stderr where it is a terminal), never as the whole terminal.
    (True, False, True, "", False, "stderr"),
    (True, False, False, "", False, "stdout"),
])
def test_approve_asks_as_0_11_1_did_and_a_persons_decision_needs_the_whole_terminal(
        monkeypatch, stdin, stdout, stderr, agent, whole, asked_on):
    """approve, --watch, agent --allow and the knowledge decisions (Terminal.require) ask wherever
    client 0.11.1 asked (stdin a terminal, outside an agent's shell), so nothing that worked with
    0.11.0 or 0.11.1 is refused; a person's decision under the touch switch (interactive) and the
    commands new in 0.11.2 (``whole``) need stdin and stdout terminals. Without a terminal for
    input, NotAtTerminal (exit 3) before anything is shown or asked of a key."""
    streams = [types.SimpleNamespace(isatty=lambda value=value: value, write=lambda text: None, flush=lambda: None)
               for value in (stdin, stdout, stderr)]
    if agent:
        monkeypatch.setenv("SHAKERSCAN_AGENT_NAME", agent)
    else:
        monkeypatch.delenv("SHAKERSCAN_AGENT_NAME", raising=False)
    monkeypatch.setattr(approval.sys, "stderr", streams[2])
    assert decision.interactive(streams[0], streams[1], {"SHAKERSCAN_AGENT_NAME": agent}) is whole
    terminal = approval.Terminal(streams[0], streams[1])
    if asked_on is None:
        with pytest.raises(approval.NotAtTerminal) as refused:
            terminal.require("shakerscan approve")
        assert "nothing was asked or decided" in str(refused.value)
        assert isinstance(refused.value, approval.ApprovalError)
    else:
        terminal.require("shakerscan approve")
        assert terminal.stdout is streams[["stdin", "stdout", "stderr"].index(asked_on)]
        assert terminal.full is whole
    strict = approval.Terminal(streams[0], streams[1])
    if whole:
        strict.require("a touch test", whole=True)
    else:
        with pytest.raises(approval.NotAtTerminal):
            strict.require("a touch test", whole=True)


@pytest.mark.parametrize("switch", [False, True])
def test_with_the_output_captured_a_touch_the_switch_requires_is_never_asked(monkeypatch, switch):
    """stdin a terminal and stdout captured: with the touch switch off the person is asked, with
    0.11.1's choice of proof (the code where the gateway offers one, never a key first); with it
    on, refused (exit 3) before anything is begun, so a key never blinks for a harness that gives
    an agent's command a terminal for its input and errors."""
    monkeypatch.delenv("SHAKERSCAN_AGENT_NAME", raising=False)
    streams = [types.SimpleNamespace(isatty=lambda value=value: value, write=lambda text: None, flush=lambda: None)
               for value in (True, False, True)]
    monkeypatch.setattr(approval.sys, "stderr", streams[2])
    read = []

    def send(method, path, payload=None, **_):
        read.append((method, path))
        if (method, path) == ("GET", approval.ME_PATH):
            return 200, {"user": {"auth": "token"}, "person_decision_proof": switch}
        raise AssertionError((method, path))

    terminal = approval.Terminal(streams[0], streams[1])
    if switch:
        with pytest.raises(approval.NotAtTerminal) as refused:
            terminal.require("shakerscan approve", touch_required=approval.touch_switch(send))
        assert refused.value.why == "output"
        assert "only when the command's output is your terminal too" in str(refused.value)
        assert read == [("GET", approval.ME_PATH)], "only the gateway's description was read"
        return
    terminal.require("shakerscan approve", touch_required=approval.touch_switch(send))
    assert terminal.full is False and terminal.stdout is streams[2]
    stepup = approval.StepUp(send, ORIGIN, terminal)
    monkeypatch.setattr(approval, "security_keys_present", lambda: True)
    # A key plugged in, the gateway offering the code too: the code, as 0.11.1 chose.
    assert stepup.method_for({"methods": ["totp", "security_key"], "webauthn": {}}) == "totp"
    assert stepup.method_for({"methods": ["sso", "security_key"], "webauthn": {}}) == "security_key"
    assert approval.StepUp(send, ORIGIN, terminal, method="security_key").method_for(
        {"methods": ["totp", "security_key"]}) == "security_key", "--method still chooses"


def test_a_step_up_begun_for_captured_output_under_the_switch_is_refused_before_the_gateway_is_asked():
    """The backstop under every command's own check (Terminal.require): a step-up whose terminal is
    not the whole terminal never begins an approval where the gateway requires a touch."""
    read = []

    def send(method, path, payload=None, **_):
        read.append((method, path))
        if (method, path) == ("GET", approval.ME_PATH):
            return 200, {"user": {"auth": "token"}, "person_decision_proof": True}
        raise AssertionError((method, path))

    terminal = approval.Terminal(io.StringIO(), io.StringIO())
    terminal.full = False
    stepup = approval.StepUp(send, ORIGIN, terminal, account="alice")
    with pytest.raises(approval.NotAtTerminal) as refused:
        stepup.begin("key_check", {"key_check": dict(approval.KEY_CHECK)})
    assert refused.value.why == "output"
    assert read == [("GET", approval.ME_PATH)], "nothing begun"


@pytest.mark.parametrize(("stdout", "stderr", "asked_on", "full"), [
    (True, True, "stderr", True),  # stdout carries the JSON answer: the prompt goes to stderr
    (True, False, "stdout", True),  # `2> log`: the prompt stays where the person sees it
    # `HUNT=$(shakerscan hunt start ... --allow ... | jq -r .hunt_id)`: asked on stderr, as 0.11.1 did
    (False, True, "stderr", False),
    # `... > out.json 2> err.log`: still on stderr, never into the JSON answer (0.11.1 wrote it there)
    (False, False, "stderr", False),
])
def test_hunt_start_allow_asks_on_stderr(monkeypatch, stdout, stderr, asked_on, full):
    """Terminal(stdin, stdout, stderr), as `hunt start --allow` constructs it: the prompt prefers
    stderr; a captured stdout (its data channel) is asked as client 0.11.1 asked."""
    monkeypatch.delenv("SHAKERSCAN_AGENT_NAME", raising=False)
    streams = {name: types.SimpleNamespace(isatty=lambda value=value: value)
               for name, value in (("stdin", True), ("stdout", stdout), ("stderr", stderr))}
    monkeypatch.setattr(approval.sys, "stderr", streams["stderr"])
    terminal = approval.Terminal(streams["stdin"], streams["stdout"], streams["stderr"])
    terminal.require("pre-authorizing --allow bounds")
    assert terminal.stdout is streams[asked_on] and terminal.full is full


REQUEST_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"


def test_approve_without_a_terminal_exits_3_and_reads_nothing(monkeypatch, capsys):
    """The product CLI's approve in an agent's tool call (no terminal for its input): refused with
    exit 3 (nothing ran), before the instance is read."""
    monkeypatch.delenv("SHAKERSCAN_AGENT_NAME", raising=False)
    at_a_terminal(monkeypatch, stdin=False, stdout=False)
    monkeypatch.setattr(sys, "stderr", io.StringIO())
    sent = []
    monkeypatch.setattr(v2_cli, "_approval_send", lambda client: lambda *a, **k: sent.append(a) or (200, {}))
    monkeypatch.setenv("SHAKERSCAN_API_TOKEN", "sst_fixture_token")
    for argv in (["approve", REQUEST_ID.upper()], ["approve", "--all-pending"], ["approve", "--watch"],
                 ["deny", REQUEST_ID]):
        assert v2_cli.main(["--api-url", ORIGIN, *argv]) == approval.EXIT_NOT_AT_TERMINAL == 3, argv
    assert sent == [], "nothing was read from or sent to the gateway"
    lines = sys.stderr.getvalue().splitlines()
    assert len(lines) == 4 and all("interactive terminal" in line for line in lines)
    # The command is named once (it read "shakerscan approve: shakerscan approve asks ..."),
    # and the line ends with the command the person runs, naming the request.
    assert lines[0].startswith("shakerscan approve: it asks the person at an interactive terminal")
    assert all(line.count("shakerscan approve") + line.count("shakerscan deny") == 2 for line in lines), lines
    assert [line.rsplit(": ", 1)[1] for line in lines] == [
        f"shakerscan approve {REQUEST_ID}", "shakerscan approve --all-pending", "shakerscan approve --watch",
        f"shakerscan deny {REQUEST_ID}"]


@pytest.mark.parametrize("named", ["--url=https://evil.example", "-x", "r-1", "a b", "'; rm -rf ~"])
def test_the_persons_approve_command_names_a_request_only_by_its_uuid(monkeypatch, named):
    """An agent's request id that is no UUID (``shakerscan approve -- -- --url=https://evil.example``)
    never becomes a word of the person's command: the person's client would read it as an option
    and speak the approval protocol to an origin the agent chose."""
    monkeypatch.delenv("SHAKERSCAN_AGENT_NAME", raising=False)
    at_a_terminal(monkeypatch, stdin=False, stdout=False)
    monkeypatch.setattr(sys, "stderr", io.StringIO())
    monkeypatch.setattr(v2_cli, "_approval_send", lambda client: lambda *a, **k: (200, {}))
    monkeypatch.setenv("SHAKERSCAN_API_TOKEN", "sst_fixture_token")
    assert v2_cli.main(["--api-url", ORIGIN, "approve", "--", named]) == 3
    assert v2_cli.main(["--api-url", ORIGIN, "approve", REQUEST_ID, f"--hunt={named}"]) == 3
    first, second = sys.stderr.getvalue().strip().splitlines()
    assert first.endswith("the person runs this in their own terminal: shakerscan approve <request-id>"), first
    assert second.endswith(f"the person runs this in their own terminal: shakerscan approve {REQUEST_ID}"), second
    assert "evil.example" not in first + second


@pytest.mark.parametrize(("method", "path", "body", "command"), [
    ("POST", AMENDMENT, RAISE, f"shakerscan hunt budget raise {HUNT} --limit max_state_changing_requests=40"),
    ("POST", AMENDMENT, {**RAISE, "resume": True},
     f"shakerscan hunt budget raise {HUNT} --limit max_state_changing_requests=40 --resume"),
    ("POST", f"/targets/{TARGET}/authorization", {"approved_by": "x"}, f"shakerscan targets authorize {TARGET}"),
    ("POST", "/scans", {"target": "https://new.example.com", "policy": {"active_testing": True}},
     "shakerscan targets authorize https://new.example.com"),
    ("POST", "/hunts", {"target_id": TARGET}, f"shakerscan targets authorize {TARGET}"),
    ("POST", f"/targets/{TARGET}/scan", {"policy": {}}, f"shakerscan targets authorize {TARGET}"),
    ("POST", "/credential-profiles/p/grants", {"target_id": "t"},
     """shakerscan api POST /credential-profiles/p/grants '{"target_id":"t"}'"""),
])
def test_the_refusal_names_the_command_the_person_runs(method, path, body, command):
    raw = json.dumps(body, separators=(",", ":")).encode()
    assert decision.person_command(method, path, raw) == command
    line = decision.refusal_line(REFUSAL["detail"], command)
    assert line.startswith("person decision required: Raise state-changing requests 20 -> 40")
    assert "Nothing was changed." in line and line.endswith(command) and "\n" not in line


def test_hostile_summary_text_is_shown_inert():
    line = decision.refusal_line({"summary": "Authorize \x1b[2Jevil‮.com"}, "shakerscan x")
    assert "\x1b" not in line and "‮" not in line


# ---- the binding the client checks before any key is asked -------------------------------------


@pytest.mark.parametrize("tamper", [
    lambda d: d["person_decision"].update(body_sha256="0" * 64),
    lambda d: d["person_decision"].update(path="/hunts/other/budget-amendments"),
    lambda d: d["person_decision"].update(method="PUT"),
    lambda d: d["person_decision"].update(query="x=1"),
    lambda d: d.update(origin="https://elsewhere.example.com"),
    lambda d: d.update(purpose="permission_decision"),
], ids=["body", "path", "method", "query", "origin", "purpose"])
def test_a_challenge_for_any_other_request_is_never_signed(monkeypatch, tamper):
    gateway = ScriptedGateway(tamper=tamper)
    signer = Signer()
    with pytest.raises(decision.PersonDecisionError, match="not for this request"):
        decision.complete(gateway.post, origin=ORIGIN, method="POST", path=AMENDMENT,
                          body=json.dumps(RAISE).encode(), detail=REFUSAL["detail"],
                          terminal=approval.Terminal(io.StringIO(), io.StringIO()), assertion=signer)
    assert signer.asked == [], "the key is never asked for a challenge that is not this request's"


def test_a_challenge_not_bound_to_its_document_is_never_signed():
    gateway = ScriptedGateway()
    original = gateway.post

    def unbound(path, payload):
        status, body = original(path, payload)
        if path == decision.BEGIN_PATH:
            body["webauthn"]["challenge"] = b64url(b"x" * 32)
        return status, body

    signer = Signer()
    with pytest.raises(decision.PersonDecisionError, match="not bound"):
        decision.complete(unbound, origin=ORIGIN, method="POST", path=AMENDMENT, body=b"{}",
                          detail=REFUSAL["detail"], terminal=approval.Terminal(io.StringIO(), io.StringIO()),
                          assertion=signer)
    assert signer.asked == []


def test_windows_is_told_plainly_before_any_request(monkeypatch):
    monkeypatch.setattr(decision.sys, "platform", "win32")
    gateway = ScriptedGateway()
    with pytest.raises(decision.PersonDecisionError, match="not supported on Windows"):
        decision.complete(gateway.post, origin=ORIGIN, method="POST", path=AMENDMENT, body=b"{}",
                          detail=REFUSAL["detail"], terminal=approval.Terminal(io.StringIO(), io.StringIO()))
    assert gateway.begun == []


# ---- the three HTTP stacks ---------------------------------------------------------------------


def test_the_product_cli_touches_once_and_resends_the_exact_request(gateway, monkeypatch):
    out = at_a_terminal(monkeypatch)
    signer = Signer()
    monkeypatch.setattr(approval, "security_key_assertion", signer)
    client = v2_cli.ApiClient(ORIGIN, api_token="token-1")
    answer = client.request("POST", AMENDMENT, payload=RAISE, idempotency_key="key-1")
    assert answer["ok"] is True
    first, second = gateway.sent
    assert first["data"] == second["data"], "the resend carries exactly the bytes the touch was for"
    assert second["headers"]["x-shakerscan-person-proof"] == "apv_grant_1"
    assert first["headers"]["idempotency-key"] == second["headers"]["idempotency-key"] == "key-1"
    assert "x-shakerscan-person-proof" not in first["headers"]
    (begun,) = gateway.begun
    assert begun["origin"] == ORIGIN and begun["purpose"] == "person_decision"
    assert base64.urlsafe_b64decode(begun["person_decision"]["body"] + "==") == first["data"]
    (asked,) = signer.asked
    assert asked["webauthn"]["userVerification"] == "discouraged" and asked["origin"] == ORIGIN
    text = out.getvalue()
    assert "This needs your decision (your administrator requires a security-key touch):" in text
    assert SUMMARY in text and "Touch your security key to approve (Ctrl-C to cancel)" in text


def test_without_a_terminal_nothing_is_asked_and_the_command_exits_3(gateway, monkeypatch, capsys):
    at_a_terminal(monkeypatch, stdin=False)
    signer = Signer()
    monkeypatch.setattr(approval, "security_key_assertion", signer)
    client = v2_cli.ApiClient(ORIGIN, api_token="token-1")
    with pytest.raises(v2_cli.CliError) as refused:
        client.request("POST", AMENDMENT, payload=RAISE)
    assert refused.value.error_type == "person_decision_required"
    assert refused.value.api_detail["command"].startswith("shakerscan hunt budget raise")
    assert signer.asked == [] and gateway.begun == [], "the key never lit up for an agent"
    assert len(gateway.sent) == 1


def test_shakerscan_api_touches_in_a_terminal_and_exits_3_in_an_agents_shell(gateway, monkeypatch, capsys):
    monkeypatch.setenv("SHAKERSCAN_API_TOKEN", "token-1")
    signer = Signer()
    monkeypatch.setattr(approval, "security_key_assertion", signer)
    at_a_terminal(monkeypatch)
    assert api_cli.main(["--api-url", ORIGIN, "POST", AMENDMENT, json.dumps(RAISE)]) == 0
    assert gateway.sent[0]["data"] == gateway.sent[1]["data"] and len(signer.asked) == 1
    gateway.sent.clear()
    monkeypatch.setenv("SHAKERSCAN_AGENT_NAME", "claude")
    assert api_cli.main(["--api-url", ORIGIN, "POST", AMENDMENT, json.dumps(RAISE)]) == 3
    err = capsys.readouterr().err
    assert "person decision required:" in err and "shakerscan hunt budget raise" in err
    assert len(gateway.sent) == 1 and len(signer.asked) == 1


def test_shakerscan_scan_asks_for_the_targets_authorization_then_queues(gateway, monkeypatch, capsys):
    monkeypatch.setenv("SHAKERSCAN_API_TOKEN", "token-1")
    signer = Signer()
    monkeypatch.setattr(approval, "security_key_assertion", signer)
    at_a_terminal(monkeypatch, stdin=False)
    # No terminal: exit 3, naming `targets authorize`; the key is never asked.
    code = scan_cli.main(["--api-url", ORIGIN, "--ui-url", ORIGIN, "https://new.example.com",
                          "--active-testing", "--confirm-active"])
    assert code == 3 and signer.asked == []
    assert "shakerscan targets authorize https://new.example.com" in capsys.readouterr().err
    # At the person's terminal --confirm-active answers only the local question, never the touch:
    # one touch, then the same submission (bytes and Idempotency-Key) once more with the grant.
    gateway.sent.clear()
    at_a_terminal(monkeypatch)
    code = scan_cli.main(["--api-url", ORIGIN, "--ui-url", ORIGIN, "https://new.example.com",
                          "--active-testing", "--confirm-active", "--idempotency-key", "scan-key-0001"])
    scans = [sent for sent in gateway.sent if sent["url"].endswith("/scans")]
    assert code == 0 and len(signer.asked) == 1 and len(scans) == 2
    assert scans[0]["data"] == scans[1]["data"]
    assert scans[0]["headers"]["idempotency-key"] == scans[1]["headers"]["idempotency-key"] == "scan-key-0001"
    assert "x-shakerscan-person-proof" not in scans[0]["headers"]
    assert scans[1]["headers"]["x-shakerscan-person-proof"] == "apv_grant_1"


# ---- the MCP adapter ---------------------------------------------------------------------------


def test_the_mcp_adapter_names_the_persons_command_and_never_retries(gateway, monkeypatch):
    client = mcp.ArsenalClient(ORIGIN, api_token="token-1")
    client.opener = gateway
    with pytest.raises(mcp.MCPError) as refused:
        client.request_json("POST", AMENDMENT, RAISE)
    message = refused.value.message
    assert "A person's decision is required" in message and SUMMARY in message
    assert f"`shakerscan hunt budget raise {HUNT} --limit max_state_changing_requests=40`" in message
    assert "do not retry" in message
    detail = mcp._error_detail(refused.value)
    assert detail["outcome"] == "person_decision_required" and detail["decision"] == "budget.raise"
    assert len(gateway.sent) == 1 and gateway.begun == []


# ---- approve and --watch -----------------------------------------------------------------------


def test_approve_prefers_a_plugged_in_key_and_falls_back_as_before(monkeypatch):
    monkeypatch.setattr(approval, "security_keys_present", lambda: True)
    # A gateway that does not say it asks only for a touch: the code first, as before.
    assert approval.preferred_method(["totp", "security_key"]) == "totp"
    assert approval.preferred_method(["security_key"]) == "security_key"
    assert approval.preferred_method(["totp"]) == "totp"
    monkeypatch.setattr(approval, "security_keys_present", lambda: False)
    assert approval.preferred_method(["totp", "security_key"]) == "totp"
    # No key plugged in: the browser sign-in a single sign-on person has beside a registered key,
    # as the code is a local person's fallback; a key that is the only proof is still asked.
    assert approval.preferred_method(["sso", "security_key"]) == "sso"
    assert approval.preferred_method(["security_key"]) == "security_key"
    assert approval.preferred_method(["sso"]) == "sso"


def test_the_key_is_asked_for_what_the_gateway_asks_and_several_keys_are_chosen(monkeypatch):
    seen = {}

    class Client:
        def __init__(self, device, user_interaction=None, **kwargs):
            seen["device"] = device

        def get_assertion(self, options):
            seen["options"] = options
            inner = types.SimpleNamespace(client_data=b"{}", authenticator_data=b"a", signature=b"s", user_handle=None)
            return types.SimpleNamespace(get_response=lambda index: types.SimpleNamespace(raw_id=b"id", response=inner))

    keys = [types.SimpleNamespace(descriptor=types.SimpleNamespace(product_name=name)) for name in ("Work", "Spare")]
    modules = {
        "fido2": types.ModuleType("fido2"),
        "fido2.client": types.SimpleNamespace(Fido2Client=Client, UserInteraction=object,
                                              DefaultClientDataCollector=lambda origin: origin),
        "fido2.hid": types.SimpleNamespace(CtapHidDevice=types.SimpleNamespace(list_devices=lambda: iter(keys))),
        "fido2.webauthn": types.SimpleNamespace(
            PublicKeyCredentialDescriptor=lambda **k: k, PublicKeyCredentialRequestOptions=lambda **k: k,
            PublicKeyCredentialType=types.SimpleNamespace(PUBLIC_KEY="public-key"),
            UserVerificationRequirement=lambda value: f"uv:{value}"),
    }
    for name, module in modules.items():
        monkeypatch.setitem(sys.modules, name, module)

    class Picks(approval.Terminal):
        def line(self, prompt):
            self.stdout.write(prompt)
            return "2"

    terminal = Picks(io.StringIO(), io.StringIO())
    approval.security_key_assertion({"challenge": "AA", "userVerification": "discouraged"}, ORIGIN, terminal)
    assert seen["device"] is keys[1] and seen["options"]["user_verification"] == "uv:discouraged"
    assert "1) Work" in terminal.stdout.getvalue() and "2) Spare" in terminal.stdout.getvalue()
    approval.security_key_assertion({"challenge": "AA"}, ORIGIN, terminal)
    assert seen["options"]["user_verification"] == "uv:required", "an older gateway asks for the PIN"


def test_the_feed_lines_say_how_each_decision_was_made():
    when = 1792772519
    made = approval.person_decision_line({"at": when, "made": "with_token", "outcome": "unproven",
                                          "decision": "budget.raise", "method": "POST", "path": AMENDMENT,
                                          "connection": "work-laptop"})
    assert "made with a token, no touch: raise a Hunt's budget (POST " in made and "via connection work-laptop" in made
    refused = approval.person_decision_line({"at": when, "made": "with_token", "outcome": "unproven_409",
                                             "decision": "budget.raise", "connection": "x"})
    assert "(the engine answered HTTP 409)" in refused
    proved = approval.person_decision_line({"at": when, "made": "proved", "decision": "target.authorize",
                                            "connection": "laptop\x1b[2J"})
    assert proved.split("] ", 1)[1].startswith("decided by key touch: authorize a target")
    assert "\x1b" not in proved
    failed = approval.person_decision_line({"at": when, "made": "proved", "outcome": "security_key_409",
                                            "decision": "budget.raise", "connection": "x"})
    assert "proved by key touch, not applied (the engine answered HTTP 409)" in failed


def test_the_watch_asks_a_touch_per_decision_when_no_session_opens(monkeypatch):
    from tests.test_hunt_approve import ORIGIN as SCRIPTED_ORIGIN
    from tests.test_hunt_approve import Gateway, Terminal, _request

    gateway = Gateway(_request(), _request(id="cccccccc-cccc-4ccc-8ccc-cccccccccccc", title="Second"),
                      methods=("security_key",))
    original = gateway.__call__
    proofs = []

    def touch_only(method, path, payload=None, headers=None, *, timeout=None):
        if (answer := newer_gateway(method, path)) is not None:
            return answer
        if path == approval.BEGIN_PATH and payload["purpose"] == "approver_session":
            return 403, {"schema_version": "shakerscan-approval-error/v1", "error": "touch_required",
                         "message": "each decision is one touch"}
        if path == approval.FINISH_PATH:
            proofs.append(payload["proof"])
        return original(method, path, payload, headers, timeout=timeout)

    monkeypatch.setattr(approval.StepUp, "prove", lambda self, challenge: {"method": "security_key", "credential": {}})
    monkeypatch.setattr(approval, "security_key_readiness", lambda **_: "")
    terminal = Terminal(keys=["l"])

    def stop(seconds):  # the person presses Ctrl-C once the requests are decided
        raise KeyboardInterrupt

    assert approval.watch(touch_only, terminal, enterprise=True, origin=SCRIPTED_ORIGIN, account="alice",
                          poll_seconds=0.01, sleep=stop) == 0
    text = terminal.text
    assert "Each decision is one touch of your security key" in text
    assert "allow a[l]l 2 shown" in text and "approver session open" not in text
    assert gateway.sessions == {}
    assert proofs == [{"method": "security_key", "credential": {}}], "one touch decided both"
    assert all(item["status"] == "granted" for item in gateway.requests.values())


# ---- targets authorize and hunt budget raise ---------------------------------------------------


def _client_module(monkeypatch, gateway):
    """The client's own module, with its vendored product CLI reaching the scripted gateway."""
    sys.path.insert(0, str(ROOT / "client" / "src"))
    from shakerscan import decisions

    monkeypatch.setattr(decisions.load("_v2_cli"), "_opener", lambda: gateway)
    return decisions


def test_targets_authorize_registers_then_authorizes_with_one_touch(gateway, monkeypatch, capsys):
    decisions = _client_module(monkeypatch, gateway)
    monkeypatch.setenv("SHAKERSCAN_API_TOKEN", "token-1")
    signer = Signer()
    monkeypatch.setattr(approval, "security_key_assertion", signer)
    at_a_terminal(monkeypatch)
    import shakerscan.cli as cli

    monkeypatch.setattr(cli, "apply_connection", lambda args: ORIGIN)
    args = types.SimpleNamespace(action="authorize", target="app.example.com", reason=None, json=False,
                                 timeout=None, url=None, token_file=None)
    assert decisions.cmd_targets(args) == 0
    me, created, refused, resent = gateway.sent
    assert json.loads(created["data"]) == {"url": "https://app.example.com"}
    assert urllib.parse.urlsplit(me["url"]).path == "/_enterprise/me" and me["method"] == "GET"
    sent = json.loads(refused["data"])
    # The person the connection acts for, never this computer's user (the gateway writes the
    # person who touched over it when it requires a touch).
    assert sent == {"approved_by": "alice via shakerscan targets authorize, service token laptop",
                    "risk_tier": "active"}
    assert resent["headers"]["x-shakerscan-person-proof"] == "apv_grant_1" and len(signer.asked) == 1
    assert "for active testing, recorded as Alice via terminal security-key touch" in sys.stdout.getvalue()


def test_hunt_budget_raise_reads_the_budget_and_sends_totals(gateway, monkeypatch, capsys):
    decisions = _client_module(monkeypatch, gateway)
    monkeypatch.setenv("SHAKERSCAN_API_TOKEN", "token-1")
    at_a_terminal(monkeypatch, stdin=False)
    code = decisions.hunt_budget_raise([HUNT, "--limit", "max_state_changing_requests=+20",
                                        "--limit", "max_http_requests=600"], ORIGIN)
    assert code == 3, "an agent's shell gets the person's command, never a prompt"
    assert gateway.sent == [], "nothing was read from or sent to the instance"
    err = capsys.readouterr().err
    # One line, not the CLI's error JSON, ending with the person's command.
    assert err.startswith("shakerscan: person decision required: ") and err.count("\n") == 1, err
    assert err.rstrip().endswith(f"shakerscan hunt budget raise {HUNT} --limit max_state_changing_requests=+20 "
                                 "--limit max_http_requests=600"), err
    assert "{" not in err
    # In the person's own terminal: the budget read, totals sent, one touch, the same bytes again.
    at_a_terminal(monkeypatch)
    signer = Signer()
    monkeypatch.setattr(approval, "security_key_assertion", signer)
    assert decisions.hunt_budget_raise([HUNT, "--limit", "max_state_changing_requests=+20",
                                        "--limit", "max_http_requests=600"], ORIGIN) == 0
    read, me, refused, resent = gateway.sent
    assert urllib.parse.urlsplit(me["url"]).path == "/_enterprise/me"
    body = json.loads(refused["data"])
    assert body["limits"] == {"max_state_changing_requests": 40, "max_http_requests": 600}
    assert body["expected_revision"] == 2 and body["operator_confirmed"] is True
    assert resent["data"] == refused["data"] and len(signer.asked) == 1
    capsys.readouterr()
    with pytest.raises(SystemExit):
        decisions.hunt_budget_raise([HUNT], ORIGIN)  # --limit is required
    assert decisions.hunt_budget_raise([HUNT, "--limit", "max_hosts=5"], ORIGIN) == 2
    assert "no budget limit max_hosts" in capsys.readouterr().err
    # A limit that is not NAME=N|+N is refused before anything, wherever it runs.
    gateway.sent.clear()
    assert decisions.hunt_budget_raise([HUNT, "--limit=--url=https://evil.example=1"], ORIGIN) == 2
    assert gateway.sent == []


# ---- the whole decision, the binding, Ctrl-C, readiness -----------------------------------------

EVERY_LIMIT = ("Raise state-changing requests 20 -> 100000 (safety ceiling); out-of-band interactions "
               "0 -> 100000 (safety ceiling); TCP ports 10 -> 100000 (safety ceiling); UDP ports 0 -> 100000 "
               "(safety ceiling); hosts 1 -> 100000 (safety ceiling); device fragility points 0 -> 100000 "
               "(safety ceiling); approval-gated actions 5 -> 100000; HTTP requests 500 -> 100000; browser "
               "actions 50 -> 100000; capability calls 200 -> 100000; candidate and finding records 50 -> "
               "100000; verifications 20 -> 100000; duration in seconds 3600 -> 100000 for Hunt 3f2a91c0… on "
               "honey.example.com")


def _complete(gateway, detail, signer=None, terminal=None, **kwargs):
    terminal = terminal or approval.Terminal(io.StringIO(), io.StringIO())
    return terminal, decision.complete(gateway.post, origin=ORIGIN, method="POST", path=AMENDMENT,
                                       body=json.dumps(RAISE).encode(), detail=detail, terminal=terminal,
                                       assertion=signer or Signer(), **kwargs)


def test_every_limit_of_a_raise_is_shown_whole_and_never_cut(monkeypatch):
    """The display was cut at 240 characters with no ellipsis, so a raise
    of every limit hid the state-changing ceiling the engine then received."""
    gateway = ScriptedGateway(tamper=lambda d: d["person_decision"].update(summary=EVERY_LIMIT))
    detail = {**REFUSAL["detail"], "summary": EVERY_LIMIT}
    terminal, grant = _complete(gateway, detail)
    shown = " ".join(line.strip() for line in terminal.stdout.getvalue().splitlines())
    assert grant == "apv_grant_1"
    assert "state-changing requests 20 -> 100000 (safety ceiling)" in shown
    assert "duration in seconds 3600 -> 100000" in shown and "honey.example.com" in shown
    assert max(len(line) for line in terminal.stdout.getvalue().splitlines()) <= decision.WRAP + 4
    line = decision.refusal_line(detail, "shakerscan x")
    assert EVERY_LIMIT in line


def test_a_decision_too_long_to_show_is_never_touched_for():
    # What counts is what the challenge signs (the refusal's words are never shown): a signed
    # summary longer than a terminal shows is never touched for.
    signer = Signer()
    signed_long = ScriptedGateway(tamper=lambda d: d["person_decision"].update(summary="y" * 1001))
    with pytest.raises(decision.PersonDecisionError, match="in full"):
        _complete(signed_long, REFUSAL["detail"], signer)
    assert signer.asked == []


def test_a_set_digest_that_is_not_its_documents_is_never_signed():
    """Without this check the method, path and body checks on the document
    do not bind what the key signs."""
    gateway = ScriptedGateway()
    original = gateway.post

    def other_digest(path, payload):
        status, body = original(path, payload)
        if path == decision.BEGIN_PATH:
            digest = "ab" * 32
            nonce = base64.urlsafe_b64decode(body["nonce"] + "=")
            body["set_digest"] = digest
            body["webauthn"]["challenge"] = b64url(hashlib.sha256(nonce + bytes.fromhex(digest)).digest())
        return status, body

    signer = Signer()
    with pytest.raises(decision.PersonDecisionError, match="digest is not its document"):
        decision.complete(other_digest, origin=ORIGIN, method="POST", path=AMENDMENT,
                          body=json.dumps(RAISE).encode(), detail=REFUSAL["detail"],
                          terminal=approval.Terminal(io.StringIO(), io.StringIO()), assertion=signer)
    assert signer.asked == []


def test_the_agents_line_carries_no_terminal_control_bytes():
    command = decision.person_command("POST", "/credential-profiles/p/grants", b'{"a":"\x1b[2J\x07"}')
    line = decision.refusal_line(REFUSAL["detail"], command)
    assert "\x1b" not in line and "\x07" not in line and "shakerscan api POST" in line


def test_the_gateway_is_asked_first_then_the_key_and_the_decision_is_shown_either_way(monkeypatch):
    """A person with no key registered and none plugged in was told to insert one
    first, and learned only after inserting it that none was registered. The gateway is asked
    first (it refuses an account with no key, or a decision it cannot name); the key after."""
    monkeypatch.setattr(approval, "security_key_readiness", lambda **_: "")
    monkeypatch.delenv("SSH_CONNECTION", raising=False)
    monkeypatch.delenv("SSH_TTY", raising=False)

    def none_inserted(webauthn, origin, terminal, **kwargs):
        raise approval.ApprovalError("no USB security key was inserted within 60 seconds; nothing was decided")

    monkeypatch.setattr(approval, "security_key_assertion", none_inserted)
    gateway = ScriptedGateway()
    out = io.StringIO()
    with pytest.raises(decision.PersonDecisionError, match="no USB security key was inserted") as raised:
        decision.complete(gateway.post, origin=ORIGIN, method="POST", path=AMENDMENT, body=b"{}",
                          detail=REFUSAL["detail"], terminal=approval.Terminal(io.StringIO(), out))
    assert len(gateway.begun) == 1
    assert SUMMARY[:40] in out.getvalue(), "what the person would have touched for"
    assert "shakerscan hunt budget raise" not in str(raised.value), "named only over SSH"


def test_ctrl_c_at_the_touch_cancels_it_and_exits_130(gateway, monkeypatch, capsys):
    def cancelled(*args, **kwargs):
        raise KeyboardInterrupt

    with pytest.raises(decision.PersonDecisionCancelled, match="cancelled; nothing was changed"):
        _complete(ScriptedGateway(), REFUSAL["detail"], cancelled)
    monkeypatch.setenv("SHAKERSCAN_API_TOKEN", "token-1")
    monkeypatch.setattr(approval, "security_key_assertion", cancelled)
    at_a_terminal(monkeypatch)
    assert api_cli.main(["--api-url", ORIGIN, "POST", AMENDMENT, json.dumps(RAISE)]) == 130
    assert "cancelled; nothing was changed" in capsys.readouterr().err
    client = v2_cli.ApiClient(ORIGIN, api_token="token-1")
    with pytest.raises(v2_cli.CliError) as stopped:
        client.request("POST", AMENDMENT, payload=RAISE)
    assert stopped.value.error_type == "person_decision_cancelled"


def test_the_yes_flag_never_bypasses_the_touch(gateway, monkeypatch, capsys):
    """--confirm-active (the scan's --yes) answers the local question; the touch is still asked
    in a terminal and never happens without one."""
    monkeypatch.setenv("SHAKERSCAN_API_TOKEN", "token-1")
    signer = Signer()
    monkeypatch.setattr(approval, "security_key_assertion", signer)
    at_a_terminal(monkeypatch)
    code = scan_cli.main(["--api-url", ORIGIN, "--ui-url", ORIGIN, "https://new.example.com",
                          "--active-testing", "--confirm-active"])
    assert code == 0 and len(signer.asked) == 1


def test_the_local_question_is_not_asked_twice_when_a_touch_confirms(monkeypatch, capsys):
    monkeypatch.setattr(scan_cli, "_touch_follows", lambda url, target: True)
    monkeypatch.setattr(sys, "stdin", types.SimpleNamespace(isatty=lambda: True))
    monkeypatch.setattr("builtins.input", lambda prompt="": pytest.fail("asked twice"))
    args = types.SimpleNamespace(active_testing=True, confirm_active=False, target="https://a.example.com",
                                 api_url=ORIGIN)
    scan_cli._confirm_active(args)
    assert "touch of your security key" in capsys.readouterr().err
    monkeypatch.setattr(scan_cli, "_touch_follows", lambda url, target: False)
    monkeypatch.setattr("builtins.input", lambda prompt="": "no")
    with pytest.raises(scan_cli.ScanCliError, match="cancelled"):
        scan_cli._confirm_active(args)


# ---- approve picks a key that can answer, says why not, and asks only the person ----------------


class FakeCtapError(Exception):
    class ERR:
        NO_CREDENTIALS = types.SimpleNamespace(name="NO_CREDENTIALS")

    def __init__(self, code):
        self.code = code


def fake_fido2(monkeypatch, keys):
    """FAKE python-fido2 (unit fixture): each key holds some credential ids, has a PIN or not."""

    class Ctap2:
        def __init__(self, device):
            self.device = device
            self.info = types.SimpleNamespace(options={"clientPin": device.pin}, max_cred_id_length=None,
                                              max_creds_in_list=8)

        def get_assertion(self, rp_id, client_data_hash, allow_list, options=None):
            assert options == {"up": False}, "the probe never asks for a touch"
            self.device.probed += 1
            if any(item["id"] in self.device.holds for item in allow_list):
                return object()
            raise FakeCtapError(FakeCtapError.ERR.NO_CREDENTIALS)

    def verify_rp_id(rp_id, origin):  # python-fido2's rule for an https origin
        host = urllib.parse.urlsplit(origin).hostname or ""
        return origin.startswith("https://") and bool(rp_id) and (host == rp_id or host.endswith("." + rp_id))

    modules = {
        "fido2": types.ModuleType("fido2"),
        "fido2.ctap": types.SimpleNamespace(CtapError=FakeCtapError),
        "fido2.ctap2": types.SimpleNamespace(Ctap2=Ctap2),
        "fido2.hid": types.SimpleNamespace(CtapHidDevice=types.SimpleNamespace(list_devices=lambda: iter(keys))),
        "fido2.rpid": types.SimpleNamespace(verify_rp_id=verify_rp_id),
    }
    for name, module in modules.items():
        monkeypatch.setitem(sys.modules, name, module)


def key(name, holds=(), pin=True):
    return types.SimpleNamespace(descriptor=types.SimpleNamespace(product_name=name, serial_number=None, path=None),
                                 holds=set(holds), pin=pin, probed=0)


WEBAUTHN = {"rpId": "gateway.example.com", "challenge": "AA", "userVerification": "required",
            "allowCredentials": [{"type": "public-key", "id": b64url(b"mine")}]}


def test_approve_prefers_the_key_only_when_a_plugged_in_key_can_answer(monkeypatch):
    """A Touch ID passkey on the account and an unrelated YubiKey plugged in
    made 0.11.2 ask for a touch that could only fail, where 0.11.1 asked for the TOTP code."""
    touch = {**WEBAUTHN, "userVerification": "discouraged"}
    unrelated = key("YubiKey 5", holds=[b"other"])
    fake_fido2(monkeypatch, [unrelated])
    assert approval.preferred_method(["totp", "security_key"], touch, ORIGIN) == "totp"
    assert unrelated.probed == 1
    fake_fido2(monkeypatch, [unrelated, key("YubiKey 5C", holds=[b"mine"])])
    assert approval.preferred_method(["totp", "security_key"], touch, ORIGIN) == "security_key"
    fake_fido2(monkeypatch, [key("no PIN", holds=[b"mine"], pin=False)])
    assert approval.preferred_method(["totp", "security_key"], WEBAUTHN, ORIGIN) == "totp"
    assert approval.preferred_method(["totp", "security_key"], touch, ORIGIN) == "security_key"
    # Under the switch the key is the only method: it is asked, and says plainly why not.
    assert approval.preferred_method(["security_key"], WEBAUTHN, ORIGIN) == "security_key"
    # A key with a PIN that answers nothing to the touch is offered with its PIN (it may hold a
    # passkey that needs it), never chosen over the code (above); without a PIN it is refused.
    assert approval.answering_keys([unrelated], touch, ORIGIN) == ([unrelated], "", True)
    devices, why = approval.eligible_devices([key("spare", holds=[b"other"], pin=False)], touch, ORIGIN)
    assert devices == [] and "not registered to your account" in why
    devices, why = approval.eligible_devices([key("no PIN", holds=[b"mine"], pin=False)], WEBAUTHN, ORIGIN)
    assert devices == [] and "has no PIN" in why


def test_only_the_keys_that_can_answer_are_offered_before_the_touch(monkeypatch):
    mine, spare = key("YubiKey", holds=[b"mine"]), key("YubiKey", holds=[b"other"])
    fake_fido2(monkeypatch, [spare, mine])
    devices, _ = approval.eligible_devices([spare, mine], WEBAUTHN, ORIGIN)
    assert devices == [mine], "the chooser never lists a key that cannot answer"


def test_a_key_that_holds_a_credential_is_used_without_asking_which(monkeypatch):
    """With two keys plugged in that both answered yes to the silent check, the client used to
    ask 'Which one is registered to your account?'. Any of them answers: the
    first is used, and the chooser is left for keys that could not be asked."""
    first, second = key("YubiKey 5C", holds=[b"mine"]), key("YubiKey 5 NFC", holds=[b"mine"])
    fake_fido2(monkeypatch, [first, second])
    devices, _ = approval.eligible_devices([first, second], WEBAUTHN, ORIGIN)
    assert devices == [first]
    terminal = approval.Terminal(io.StringIO(), io.StringIO())
    assert approval.choose_device(devices, terminal) is first
    assert terminal.stdout.getvalue() == ""


def test_the_silent_probe_asks_a_key_only_for_this_gateways_relying_party(monkeypatch):
    """The silent getAssertion used to go to whatever rpId the gateway named, so a gateway
    could learn whether the key holds a credential of another site. The probe now asks
    only for an rpId valid for the connection's origin (python-fido2's own rule), and without
    one, or without the origin, the key is not asked at all."""
    mine = key("YubiKey", holds=[b"mine"])
    fake_fido2(monkeypatch, [mine])
    for rp_id, origin in (("bank.example", ORIGIN), ("example.com", "http://gateway.example.com"),
                          ("gateway.example.com", "")):
        assert approval.probe_device(mine, {**WEBAUTHN, "rpId": rp_id}, origin) == "unknown", (rp_id, origin)
    assert mine.probed == 0
    assert approval.probe_device(mine, WEBAUTHN, ORIGIN) == "yes" and mine.probed == 1
    # A parent domain the origin belongs to is valid, as for the assertion itself.
    assert approval.probe_device(mine, {**WEBAUTHN, "rpId": "example.com"}, ORIGIN) == "yes"


@pytest.mark.parametrize(("code", "cause", "words"), [
    ("DEVICE_INELIGIBLE", None, "not registered to your account"),
    ("TIMEOUT", "USER_ACTION_TIMEOUT", "no touch in time"),
    ("CONFIGURATION_UNSUPPORTED", None, "set a PIN on the key"),
    ("OTHER_ERROR", "PIN_BLOCKED", "PIN is blocked"),
    ("OTHER_ERROR", "PIN_INVALID", "PIN was not accepted"),
    ("OTHER_ERROR", None, "did not answer as expected"),
])
def test_a_key_error_is_said_in_plain_words(code, cause, words):
    error = Exception()
    error.code = types.SimpleNamespace(name=code)
    error.cause = types.SimpleNamespace(code=types.SimpleNamespace(name=cause)) if cause else None
    text = approval.key_failure(error)
    assert words in text and "ERR" not in text and "<" not in text


def test_a_missing_library_or_an_unreadable_key_is_explained(monkeypatch):
    # A local terminal: over SSH the remote session is named first (tested on its own below).
    monkeypatch.delenv("SSH_CONNECTION", raising=False)
    monkeypatch.delenv("SSH_TTY", raising=False)
    monkeypatch.setitem(sys.modules, "fido2.hid", None)
    monkeypatch.setattr(approval, "_homebrew_install", lambda: True)
    assert "Homebrew install" in approval.security_key_readiness()
    assert "pipx install shakerscan" in approval.security_key_readiness()
    monkeypatch.setattr(approval.sys, "platform", "linux")
    import glob as globbing
    monkeypatch.setattr(globbing, "glob", lambda pattern: ["/dev/hidraw0"])
    monkeypatch.setattr(approval.os, "access", lambda path, mode: False)
    assert "udev rules" in approval._no_device()


def test_approve_never_runs_for_an_agent_even_in_its_own_terminal(monkeypatch):
    tty = types.SimpleNamespace(isatty=lambda: True, write=lambda text: None, flush=lambda: None)
    terminal = approval.Terminal(tty, tty)
    monkeypatch.delenv("SHAKERSCAN_AGENT_NAME", raising=False)
    terminal.require("shakerscan approve")
    monkeypatch.setenv("SHAKERSCAN_AGENT_NAME", "opencode")
    with pytest.raises(approval.ApprovalError, match="agent that `shakerscan agent`"):
        terminal.require("shakerscan approve")
    monkeypatch.delenv("SHAKERSCAN_AGENT_NAME")
    piped = approval.Terminal(types.SimpleNamespace(isatty=lambda: False), tty)
    with pytest.raises(approval.ApprovalError, match="interactive terminal"):
        piped.require("shakerscan approve")


def test_an_approval_names_no_account_and_takes_the_one_the_gateway_answers():
    body = {"decisions": [{"hunt_id": HUNT, "request_id": "r-1", "subject_digest": "d", "decision": "allow",
                           "scope": "hunt", "choice": {}}]}
    sent = []

    def send(method, path, payload=None, headers=None, *, timeout=None):
        if method == "GET" and path == approval.ME_PATH:
            # As an older Enterprise gateway answers a token, and as a newer gateway does.
            return 200, ({"user": {"auth": "token"}} if old[0] else {"person_decision_proof": False})
        if method == "GET":
            # Such a gateway answers its unknown feed route 403 (and audits it): never read here.
            raise AssertionError(f"unexpected GET {path}")
        sent.append(payload)
        if not payload["account"] and (old[0] or invalid[0]):
            return 422, {"schema_version": "shakerscan-approval-error/v1", "error": "request_invalid",
                         "message": "invalid approval request fields"}
        account = payload["account"] or "sso:00u1example"
        document = approval.set_document("permission_decision", account, ORIGIN, body)
        return 200, {"schema_version": "shakerscan-approval-challenge/v1", "approval_id": "apv_1",
                     "set_digest": approval.set_digest(document), "methods": ["security_key"], "account": account}

    old, invalid = [False], [False]
    stepup = approval.StepUp(send, ORIGIN, approval.Terminal(io.StringIO(), io.StringIO()))
    challenge, _ = stepup.begin("permission_decision", body)
    assert sent[0]["account"] == "" and stepup.account == "sso:00u1example" and len(sent) == 1
    # An older gateway needs the name: asked once, before anything is posted (an empty name would
    # be refused and written to its audit log as a denied approval on every command).
    old[0], sent[:] = True, []

    class Asks(approval.Terminal):
        def line(self, prompt):
            return "alice"

    stepup = approval.StepUp(send, ORIGIN, Asks(io.StringIO(), io.StringIO()))
    stepup.begin("permission_decision", body)
    assert [item["account"] for item in sent] == ["alice"] and stepup.account == "alice"
    # A gateway that names the approver itself refuses an invalid request for another reason:
    # said as it is, and no name is asked for.
    old[0], invalid[0], sent[:] = False, True, []
    stepup = approval.StepUp(send, ORIGIN, Asks(io.StringIO(), io.StringIO()))
    with pytest.raises(approval.GatewayRefused) as refused:
        stepup.begin("permission_decision", body)
    assert refused.value.code == "request_invalid" and [item["account"] for item in sent] == [""]


def test_doctor_says_whether_a_touch_is_required_and_could_happen_here(monkeypatch):
    sys.path.insert(0, str(ROOT / "client" / "src"))
    from shakerscan import decisions

    monkeypatch.setattr(approval, "security_key_readiness", lambda: "no USB security key found; insert it")
    monkeypatch.setattr(approval, "key_out_of_reach", lambda: "")
    monkeypatch.setattr(decisions, "helper", lambda name: approval)
    asked = []

    def me(answer):
        return types.SimpleNamespace(request_json=lambda method, path: asked.append(path) or answer)

    # Where a touch is required, no key plugged in is said as what to do; elsewhere it is no
    # failure (the line said "needed only when ..." under the line that said it is required).
    assert decisions.touch_lines(me({"person_decision_proof": True})) == [
        "touch:    required for person decisions from terminals",
        "key:      none plugged in: plug in the security key registered to you before you decide from this "
        "terminal"]
    off = me({"person_decision_proof": False})
    assert decisions.touch_lines(off) == [
        "touch:    not required (the administrator's switch is off)",
        "key:      none plugged in (not needed here: approvals then use your other step-up)"]
    # A key plugged in is not said to be unregistered (doctor cannot tell which is registered).
    monkeypatch.setattr(approval, "security_key_readiness", lambda: "")
    ready = decisions.touch_lines(me({"person_decision_proof": True}))[1]
    assert "a security key is plugged in (test it: shakerscan approve --test, one touch, nothing decided)" in ready
    assert "register it once" not in ready
    monkeypatch.setattr(approval, "security_key_readiness", lambda: "no USB security key found; insert it")
    older = me({"user": {"auth": "token"}})
    assert decisions.touch_lines(older)[0] == "touch:    not offered by this gateway (an older Enterprise gateway)"
    # Only the gateway's description of itself is read: an older gateway's feed route would be
    # refused and audited on every doctor run.
    assert set(asked) == {approval.ME_PATH}
    # An instance that does not describe itself is no Enterprise gateway: nothing is said.
    gone = types.SimpleNamespace(request_json=lambda method, path: (_ for _ in ()).throw(OSError("404")))
    assert decisions.touch_lines(gone) == []


# ---- a touch-mode watch survives a failed or cancelled touch ------------------------------------


def _touch_watch(monkeypatch, gateway, proofs, keys, *, incremental=False, sleeps=3):
    """A touch-mode --watch against test_hunt_approve's SCRIPTED GATEWAY (unit fixture): the
    approver session is refused with touch_required; ``proofs`` are what each touch does."""
    from tests.test_hunt_approve import ORIGIN as SCRIPTED_ORIGIN
    from tests.test_hunt_approve import Terminal

    original = gateway.__call__

    def touch_only(method, path, payload=None, headers=None, *, timeout=None):
        if (answer := newer_gateway(method, path)) is not None:
            return answer
        if path == approval.BEGIN_PATH and payload["purpose"] == "approver_session":
            return 403, {"schema_version": "shakerscan-approval-error/v1", "error": "touch_required",
                         "message": "each decision is one touch"}
        return original(method, path, payload, headers, timeout=timeout)

    def prove(self, challenge):
        outcome = proofs.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return {"method": "security_key", "credential": {}}

    monkeypatch.setattr(approval.StepUp, "prove", prove)
    monkeypatch.setattr(approval, "security_key_readiness", lambda **_: "")
    if incremental:
        # The engine's cross-Hunt feed brings each request once, then only changes.
        polls = [list(gateway.requests.values())]
        monkeypatch.setattr(approval.PendingFeed, "poll", lambda self: polls.pop(0) if polls else [])
    terminal = Terminal(keys=list(keys))
    slept = []

    def sleep(seconds):
        slept.append(seconds)
        if len(slept) >= sleeps:
            raise KeyboardInterrupt

    code = approval.watch(touch_only, terminal, enterprise=True, origin=SCRIPTED_ORIGIN, account="alice",
                          poll_seconds=0.01, sleep=sleep)
    return code, terminal.text


@pytest.mark.parametrize("failure", [approval.ApprovalError("the security key did not sign: no touch in time"),
                                     KeyboardInterrupt()], ids=["no-touch", "ctrl-c"])
def test_a_failed_or_cancelled_touch_leaves_the_request_pending_and_the_watch_open(monkeypatch, failure):
    from tests.test_hunt_approve import REQUEST, Gateway, _request

    gateway = Gateway(_request(), methods=("security_key",))
    code, text = _touch_watch(monkeypatch, gateway, [failure, None], ["a", "a"], incremental=True)
    assert code == 0
    reason = "touch cancelled" if isinstance(failure, KeyboardInterrupt) else "not decided: the security key"
    assert f"{reason}" in text and "the request stays pending and is shown again" in text
    assert text.count("[a]llow") == 2, "the same request was shown again and decided by the second touch"
    assert gateway.requests[REQUEST]["status"] == "granted"


def test_allow_all_decides_every_request_shown_one_touch_per_fifty(monkeypatch):
    from tests.test_hunt_approve import Gateway, _request

    requests = [_request(id=f"{index:08x}-cccc-4ccc-8ccc-cccccccccccc", title=f"Request {index}") for index in range(51)]
    gateway = Gateway(*requests, methods=("security_key",))
    finishes = []
    original = gateway.__call__

    def counting(method, path, payload=None, headers=None, *, timeout=None):
        if path == approval.FINISH_PATH:
            finishes.append(payload)
        return original(method, path, payload, headers, timeout=timeout)

    code, text = _touch_watch(monkeypatch, counting, [None, None], ["l"], sleeps=1)
    assert code == 0 and len(finishes) == 2, "50, then the 51st: every request shown was decided"
    assert {item["status"] for item in gateway.requests.values()} == {"granted"}
    assert "allow a[l]l 51 shown" in text


def test_a_key_that_fails_at_the_touch_is_explained_not_dumped(monkeypatch):
    """Python-fido2's errors have no readable text of their own; what reached
    the person was an enum tuple. The assertion path says it in plain words."""

    class Timeout(Exception):
        code = types.SimpleNamespace(name="TIMEOUT")
        cause = types.SimpleNamespace(code=types.SimpleNamespace(name="USER_ACTION_TIMEOUT"))

        def __str__(self):
            return "(<ERR.TIMEOUT: 5>, CtapError(USER_ACTION_TIMEOUT))"

    class Client:
        def __init__(self, device, user_interaction=None, **kwargs):
            pass

        def get_assertion(self, options):
            raise Timeout()

    keys = [types.SimpleNamespace(descriptor=types.SimpleNamespace(product_name="YubiKey"))]
    for name, module in {
        "fido2": types.ModuleType("fido2"),
        "fido2.client": types.SimpleNamespace(Fido2Client=Client, UserInteraction=object,
                                              DefaultClientDataCollector=lambda origin: origin),
        "fido2.hid": types.SimpleNamespace(CtapHidDevice=types.SimpleNamespace(list_devices=lambda: iter(keys))),
        "fido2.webauthn": types.SimpleNamespace(
            PublicKeyCredentialDescriptor=lambda **k: k, PublicKeyCredentialRequestOptions=lambda **k: k,
            PublicKeyCredentialType=types.SimpleNamespace(PUBLIC_KEY="public-key"),
            UserVerificationRequirement=lambda value: value),
    }.items():
        monkeypatch.setitem(sys.modules, name, module)
    terminal = approval.Terminal(io.StringIO(), io.StringIO())
    with pytest.raises(approval.ApprovalError) as failed:
        approval.security_key_assertion({"challenge": "AA", "userVerification": "discouraged"}, ORIGIN, terminal)
    assert str(failed.value) == "the security key did not sign: no touch in time"


# ---- what the person is shown, where the key is, what happens after a refusal -------------------


def test_the_person_is_shown_only_what_the_key_signs(monkeypatch):
    """When the refusal's words and the signed document's differed, both were
    printed and the touch went on. Only the signed words are shown now."""
    gateway = ScriptedGateway()
    signed = "Raise HTTP requests 500 -> 900 for Hunt 3f2a91c0… on honey.example.com"

    def signs(document):
        document["person_decision"]["summary"] = signed

    gateway.tamper = signs
    out = io.StringIO()
    signer = Signer()
    grant = decision.complete(gateway.post, origin=ORIGIN, method="POST", path=AMENDMENT, body=b"{}",
                              detail=REFUSAL["detail"], terminal=approval.Terminal(io.StringIO(), out),
                              assertion=signer)
    assert grant == "apv_grant_1" and len(signer.asked) == 1
    text = out.getvalue()
    assert signed in text and SUMMARY not in text and "signed as" not in text


def test_over_ssh_the_key_is_said_to_be_elsewhere_with_the_command_to_run_there(monkeypatch):
    monkeypatch.setenv("SSH_CONNECTION", "203.0.113.5 50000 198.51.100.7 22")
    monkeypatch.setattr(approval, "security_key_readiness", lambda **_: approval._no_device())
    gateway = ScriptedGateway()
    with pytest.raises(decision.PersonDecisionError) as raised:
        decision.complete(gateway.post, origin=ORIGIN, method="POST", path=AMENDMENT,
                          body=json.dumps(RAISE).encode(), detail=REFUSAL["detail"],
                          terminal=approval.Terminal(io.StringIO(), io.StringIO()))
    text = str(raised.value)
    assert "remote (SSH) session" in text and "the computer you connect from" in text
    assert f"shakerscan hunt budget raise {HUNT} --limit max_state_changing_requests=40" in text
    assert approval.remote_session({"SSH_TTY": "/dev/pts/3"}) and not approval.remote_session({})


def test_a_refused_start_is_sent_again_only_after_the_person_authorized_the_target():
    """An agent told 'do not retry' after a refused scan or Hunt start stalled
    after the person authorized the target; and it must not send it again before the person
    decided either."""
    refused = {**REFUSAL["detail"], "decision": "target.authorize", "submission": "hunt", "target_id": TARGET,
               "summary": "Authorize app.example.com for active testing (to run this Hunt)"}
    command = decision.person_command("POST", "/hunts", json.dumps({"target_id": TARGET}).encode(), refused)
    line = decision.refusal_line(refused, command)
    assert f"shakerscan targets authorize {TARGET}" in line
    assert "Do not send this request again until the person says the target is authorized" in line
    assert "then send it once (with the same Idempotency-Key, if it had one)." in line
    # The command ends the line, so a copy that takes the line's end takes no period with it.
    assert line.endswith(f"touches their security key: shakerscan targets authorize {TARGET}")
    plain = decision.refusal_line(REFUSAL["detail"], "shakerscan hunt budget raise x")
    assert "same request again" not in plain
    message = email.message.Message()
    message["x-shakerscan-step-up"] = "required"
    error = urllib.error.HTTPError(ORIGIN + "/hunts", 403, "Forbidden", message, io.BytesIO(b""))
    mapped = mcp._person_decision_error(error, json.dumps({"detail": refused}), "POST", "/hunts",
                                        json.dumps({"target_id": TARGET}).encode())
    data = json.loads(mapped.data)["detail"]
    assert data["recovery"] == mcp.PERSON_DECISION_SUBMISSION_RECOVERY and data["submission"] == "hunt"
    assert data["command"] == f"shakerscan targets authorize {TARGET}"
    assert "until the user says the target is authorized" in str(mapped)
    assert "Do not send this request again until the user tells you" in data["recovery"]
    assert "same idempotency key" in str(mapped) and "do not retry" not in str(mapped)
    other = mcp._person_decision_error(error, json.dumps(REFUSAL), "POST", AMENDMENT, b"{}")
    assert json.loads(other.data)["detail"]["recovery"] == mcp.PERSON_DECISION_RECOVERY
    assert "submission" not in json.loads(other.data)["detail"]


@pytest.mark.parametrize("code", sorted(approval.FINAL_REFUSALS))
def test_a_touch_mode_watch_ends_when_asking_again_cannot_help(code):
    """After security_key_not_registered (and the like) the watch put the
    request back and began again on every poll."""
    seen, retry = {"r-1"}, []

    def run():
        raise approval.GatewayRefused("no key", code=code, status=403)

    terminal = approval.Terminal(io.StringIO(), io.StringIO())
    with pytest.raises(approval.GatewayRefused):
        approval._touch_decision(terminal, seen, retry, [{"id": "r-1"}], run)
    assert retry == []


def test_a_feed_line_says_what_was_decided_in_the_gateways_words():
    line = approval.person_decision_line({
        "at": 1792772519, "made": "with_token", "outcome": "unproven", "decision": "budget.raise",
        "method": "POST", "path": AMENDMENT, "connection": "work-laptop",
        "summary": "Raise state-changing requests to 41 (safety ceiling) for Hunt 3f2a91c0…\x1b[2J",
    })
    assert "made with a token, no touch: Raise state-changing requests to 41 (safety ceiling)" in line
    assert "via connection work-laptop" in line and "\x1b" not in line and "POST " not in line


def test_a_target_registered_before_a_refused_touch_is_said_to_stay_registered(gateway, monkeypatch, capsys):
    """`targets authorize <url>` registers the target before the touch, so a
    refusal or Ctrl-C there left a registered, unauthorized target while it said nothing changed."""
    decisions = _client_module(monkeypatch, gateway)
    monkeypatch.setenv("SHAKERSCAN_API_TOKEN", "token-1")
    at_a_terminal(monkeypatch, stdin=False, stdout=False)
    import shakerscan.cli as cli

    monkeypatch.setattr(cli, "apply_connection", lambda args: ORIGIN)
    original = gateway.open

    def created(request, timeout=None):
        if request.get_method() == "POST" and urllib.parse.urlsplit(request.full_url).path == "/targets":
            gateway.sent.append({"method": "POST", "url": request.full_url, "data": request.data, "headers": {}})
            return _Response({"id": TARGET, "url": "https://app.example.com/", "status": "created"})
        return original(request, timeout)

    gateway.open = created
    args = types.SimpleNamespace(action="authorize", target="app.example.com", reason=None, json=False,
                                 timeout=None, url=None, token_file=None)
    # In an agent's shell: refused before anything is read or registered (switch on or off), so
    # there is no note to give.
    assert decisions.cmd_targets(args) == 3
    err = capsys.readouterr().err
    assert "shakerscan targets authorize app.example.com" in err and "registered" not in err
    assert gateway.sent == []
    # In the person's terminal the target is registered first; a touch that fails leaves it
    # registered, and that is said.
    at_a_terminal(monkeypatch)

    def no_key(webauthn, origin, terminal, **kwargs):
        raise approval.ApprovalError("no USB security key was inserted within 60 seconds; nothing was decided")

    monkeypatch.setattr(approval, "security_key_assertion", no_key)
    assert decisions.cmd_targets(args) == 1
    err = capsys.readouterr().err
    assert "was registered as a target just now and stays registered, not authorized" in err


# ---- a refused start names the target, an unplugged key is waited for, older gateways ----------

DEVICE = "7c7c7c7c-1111-4222-8333-444455556666"


@pytest.mark.parametrize(("method", "path", "body", "target"), [
    ("POST", f"/findings/{HUNT}/retest", {}, TARGET),
    ("POST", f"/devices/{DEVICE}/scan", {"ports": "top-100"}, DEVICE),
    ("POST", f"/targets/{TARGET}/network-scans", {"confirm_authorized": True}, TARGET),
    ("POST", "/scans", {"target": "https://new.example.com", "policy": {"active_testing": True}}, TARGET),
], ids=["retest", "device-scan", "network-scan", "scan"])
def test_a_refused_retest_or_network_scan_names_the_targets_authorization_never_the_work(
        method, path, body, target):
    """The person's command for a refused submission was the agent's own request through
    `shakerscan api`: the person ran the agent's retest or network scan, and the agent was told to
    send it again, so it ran twice. It is the target's authorization now, by the id the refusal
    names."""
    refused = {**REFUSAL["detail"], "decision": "target.authorize", "submission": "retest", "target_id": target,
               "summary": "Authorize app.example.com for active testing in the production environment"}
    raw = json.dumps(body).encode()
    command = decision.person_command(method, path, raw, refused)
    assert command == f"shakerscan targets authorize {target}"
    line = decision.refusal_line(refused, command)
    assert "shakerscan api" not in line and "Do not send this request again until the person says" in line
    # Without the target's id (the gateway could not read it), still never the work itself.
    unnamed = {key: value for key, value in refused.items() if key != "target_id"}
    if path.startswith("/findings/"):
        assert decision.person_command(method, path, raw, unnamed) == "shakerscan targets authorize TARGET-ID"
    elif path.startswith("/devices/"):
        assert decision.person_command(method, path, raw, unnamed) == f"shakerscan targets authorize {DEVICE}"


@pytest.mark.parametrize(("path", "body", "command"), [
    ("/targets", {"url": "https://10.0.0.5/", "authorized_by": "agent", "cohort": "lab"},
     "shakerscan targets authorize https://10.0.0.5/"),
    ("/targets/hosts", {"locator": "10.0.0.6", "approved_by": "agent"}, "shakerscan targets authorize host://10.0.0.6"),
])
def test_a_target_registered_and_authorized_in_one_request_is_authorized_in_two_steps(path, body, command):
    """An Enterprise gateway offers no touch for a one-step registration and authorization (the
    environment it is authorized in is known only once the target is registered)."""
    assert decision.person_command("POST", path, json.dumps(body).encode()) == command


def test_targets_authorize_takes_a_device_id_and_a_host_target(gateway, monkeypatch, capsys):
    decisions = _client_module(monkeypatch, gateway)
    monkeypatch.setenv("SHAKERSCAN_API_TOKEN", "token-1")
    original = gateway.open
    seen = []

    def devices_and_hosts(request, timeout=None):
        path = urllib.parse.urlsplit(request.full_url).path
        seen.append((request.get_method(), path, request.data))
        if request.get_method() == "GET" and path == f"/targets/{DEVICE}":
            raise urllib.error.HTTPError(request.full_url, 404, "Not Found", email.message.Message(),
                                         io.BytesIO(b'{"detail":"Target not found"}'))
        if request.get_method() == "GET" and path == f"/devices/{DEVICE}":
            return _Response({"id": DEVICE, "name": "camera", "primary_locator": "198.51.100.5"})
        if request.get_method() == "POST" and path == "/targets/hosts":
            return _Response({"id": TARGET, "url": "host://10.0.0.6", "status": "created"})
        return original(request, timeout)

    gateway.open = devices_and_hosts
    client = decisions._client(ORIGIN, None)[1]
    device = decisions.find_target(client, DEVICE, create=True)
    assert device["id"] == DEVICE and device["device"] is True and device["url"] == "198.51.100.5"
    host = decisions.find_target(client, "host://10.0.0.6", create=True)
    assert host["id"] == TARGET
    assert ("POST", "/targets/hosts", b'{"locator":"10.0.0.6"}') in seen
    with pytest.raises(decisions.DecisionError):
        decisions.find_target(client, "host://", create=True)


def test_an_unplugged_key_is_waited_for_then_the_touch_goes_on(monkeypatch):
    """With the key on a keyring every one-shot command exited ('insert it and
    run the command again') and the person began again."""
    # A local terminal: over SSH no key can arrive, so nothing is waited for (tested on its own).
    monkeypatch.delenv("SSH_CONNECTION", raising=False)
    monkeypatch.delenv("SSH_TTY", raising=False)
    plugged = [[], [], ["key"]]
    terminal_out = io.StringIO()
    terminal = approval.Terminal(io.StringIO(), terminal_out)
    slept = []
    found = approval.wait_for_key(lambda: plugged.pop(0) if plugged else ["key"], terminal, 30,
                                  sleep=slept.append, clock=lambda: len(slept) * 0.5)
    assert found == ["key"] and len(slept) == 2
    assert terminal_out.getvalue().count("Insert your security key (Ctrl-C to cancel") == 1
    # Never past the bound: the challenge would expire before the touch.
    slept.clear()
    with pytest.raises(approval.ApprovalError, match="no USB security key was inserted within 3 seconds"):
        approval.wait_for_key(lambda: [], terminal, 3, sleep=slept.append, clock=lambda: len(slept) * 0.5)
    assert len(slept) == 6
    # Ctrl-C while waiting cancels (the caller turns it into "nothing was changed", exit 130).
    def interrupted(seconds):
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        approval.wait_for_key(lambda: [], terminal, 30, sleep=interrupted, clock=lambda: 0.0)


def test_over_ssh_an_unplugged_key_is_not_waited_for(monkeypatch):
    monkeypatch.setenv("SSH_CONNECTION", "203.0.113.5 50000 198.51.100.7 22")
    terminal = approval.Terminal(io.StringIO(), io.StringIO())
    with pytest.raises(approval.ApprovalError, match="remote \\(SSH\\) session"):
        approval.wait_for_key(lambda: [], terminal, 30, sleep=lambda s: pytest.fail("waited"))


def test_the_wait_for_a_key_stays_within_the_challenges_life():
    now = 1_000_000.0
    import datetime

    def at(seconds):
        return {"expires_at": datetime.datetime.fromtimestamp(now + seconds, datetime.timezone.utc).isoformat()}

    assert decision.insert_seconds(at(120), now=now) == 60.0
    assert decision.insert_seconds(at(50), now=now) == 20.0
    assert decision.insert_seconds(at(10), now=now) == 5.0
    assert decision.insert_seconds({}, now=now) == decision.INSERT_SECONDS


def test_the_touch_waits_locally_and_only_python_fido2_missing_or_ssh_stops_it(monkeypatch):
    monkeypatch.delenv("SSH_CONNECTION", raising=False)
    monkeypatch.delenv("SSH_TTY", raising=False)
    hid = types.SimpleNamespace(CtapHidDevice=types.SimpleNamespace(list_devices=lambda: iter([])))
    monkeypatch.setitem(sys.modules, "fido2", types.ModuleType("fido2"))
    monkeypatch.setitem(sys.modules, "fido2.hid", hid)
    assert approval.security_key_readiness(waiting=True) == ""
    assert "no USB security key found" in approval.security_key_readiness()
    monkeypatch.setenv("SSH_TTY", "/dev/pts/3")
    assert "remote (SSH) session" in approval.security_key_readiness(waiting=True)
    monkeypatch.setitem(sys.modules, "fido2.hid", None)
    assert "python-fido2" in approval.security_key_readiness(waiting=True)


def test_the_linux_hint_says_an_unreadable_device_may_be_the_key_not_that_it_is(monkeypatch):
    """A laptop's keyboard or touchpad is a HID device too: an unreadable node is a possibility."""
    monkeypatch.delenv("SSH_CONNECTION", raising=False)
    monkeypatch.delenv("SSH_TTY", raising=False)
    monkeypatch.setattr(approval.sys, "platform", "linux")
    import glob as globbing
    monkeypatch.setattr(globbing, "glob", lambda pattern: ["/dev/hidraw0"])
    monkeypatch.setattr(approval.os, "access", lambda path, mode: False)
    text = approval._no_device()
    assert "if your key is plugged in, this user may not be allowed to open it" in text
    assert "USB devices are plugged in" not in text


def test_the_terminal_shows_exactly_the_signed_decision_and_nothing_more():
    """Every line the person sees before the touch, exactly: the header, the signed words and the
    prompt; nothing added to the words the key signs."""
    gateway = ScriptedGateway()
    out = io.StringIO()
    decision.complete(gateway.post, origin=ORIGIN, method="POST", path=AMENDMENT, body=json.dumps(RAISE).encode(),
                      detail={**REFUSAL["detail"], "summary": "the refusal's words, never shown"},
                      terminal=approval.Terminal(io.StringIO(), out), assertion=Signer())
    assert out.getvalue().splitlines() == [
        "This needs your decision (your administrator requires a security-key touch):",
        *decision.summary_lines(SUMMARY),
        "Touch your security key to approve (Ctrl-C to cancel)...",
        # Not "done": the request is sent again now, and its answer is the command's own output.
        "touch accepted for alice (security-key touch); sending the request again...",
    ]
    assert decision.summary_lines(SUMMARY) == ["  " + SUMMARY]


def test_the_product_cli_resends_once_and_never_asks_a_second_touch(gateway, monkeypatch):
    """A resend the gateway refuses again (the grant not accepted) is reported, never touched for
    again: one begin, one touch, two sends."""
    at_a_terminal(monkeypatch)
    signer = Signer()
    monkeypatch.setattr(approval, "security_key_assertion", signer)
    class Forgetful(dict):
        def pop(self, key, default=None):
            return None  # the gateway does not take the grant

    gateway.grants = Forgetful()
    client = v2_cli.ApiClient(ORIGIN, api_token="token-1")
    with pytest.raises(v2_cli.CliError) as refused:
        client.request("POST", AMENDMENT, payload=RAISE)
    assert refused.value.http_status == 403 and refused.value.error_type == "api_error"
    assert len(gateway.begun) == 1 and len(signer.asked) == 1 and len(gateway.sent) == 2


def test_a_failed_touch_exits_1_with_one_line_in_every_command(gateway, monkeypatch, capsys):
    decisions = _client_module(monkeypatch, gateway)
    monkeypatch.setenv("SHAKERSCAN_API_TOKEN", "token-1")
    at_a_terminal(monkeypatch)

    def no_key(webauthn, origin, terminal, **kwargs):
        raise approval.ApprovalError("no USB security key was inserted within 60 seconds; nothing was decided")

    monkeypatch.setattr(approval, "security_key_assertion", no_key)
    raise_args = [HUNT, "--limit", "max_state_changing_requests=40"]
    assert decisions.hunt_budget_raise(raise_args, ORIGIN) == 1
    err = capsys.readouterr().err
    assert err.startswith("shakerscan: no USB security key was inserted") and err.count("\n") == 1
    assert api_cli.main(["--api-url", ORIGIN, "POST", AMENDMENT, json.dumps(RAISE)]) == 1
    capsys.readouterr()


def test_an_older_gateway_is_told_from_a_newer_by_what_it_says_of_itself():
    """Against Enterprise gateways that need the sign-in name, the
    client checked a route those gateways answer 403, and re-raised the empty-name refusal. Their
    own description of themselves says it, and nothing they audit as refused is read."""
    asked = []

    def gateway_answering(answer):
        def send(method, path, payload=None, headers=None, *, timeout=None):
            asked.append((method, path))
            return answer

        return send

    older = approval.gateway_features(gateway_answering((200, {"user": {"auth": "token"}})))
    assert older == {"known": True, "names_approver": False, "touch_required": False}
    newer = approval.gateway_features(gateway_answering((200, {"person_decision_proof": True})))
    assert newer == {"known": True, "names_approver": True, "touch_required": True}
    for answer in ((404, {"detail": "Not Found"}), (403, {"detail": "not available"}), (200, "text")):
        assert approval.gateway_features(gateway_answering(answer))["names_approver"] is False
    assert {path for _, path in asked} == {approval.ME_PATH}


def test_the_local_question_reads_the_gateways_own_description(monkeypatch):
    asked = []

    def request_json(url, **kwargs):
        asked.append(url)
        return {"person_decision_proof": True}

    monkeypatch.setattr(scan_cli, "_bearer_token", lambda: "token-1")
    monkeypatch.setattr(scan_cli, "_request_json", request_json)
    assert scan_cli._touch_confirms(ORIGIN) is True
    assert asked == [ORIGIN + "/_enterprise/me"]
    monkeypatch.setattr(scan_cli, "_request_json", lambda url, **kwargs: {"version": "older"})
    assert scan_cli._touch_confirms(ORIGIN) is False


# ---- where a key can reach, where python-fido2 installs, who is recorded ----------------------


@pytest.mark.parametrize(("environ", "files", "words"), [
    ({"WSL_DISTRO_NAME": "Ubuntu"}, (), "runs in WSL"),
    ({}, (("proc/sys/kernel/osrelease", "5.15.153.1-microsoft-standard-WSL2"),), "runs in WSL"),
    ({}, ((".dockerenv", ""),), "runs in a container"),
    ({}, (("run/.containerenv", ""),), "runs in a container"),
    ({"SSH_TTY": "/dev/pts/3"}, (), "remote (SSH) session"),
])
def test_a_terminal_a_plugged_in_key_cannot_reach_says_so_at_once(tmp_path, environ, files, words):
    """Only SSH used to be recognized; under WSL2 without USB passthrough or in a container the
    client waited the full minute for a key that could never arrive."""
    for name, text in files:
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text(text)
    reason = approval.key_out_of_reach(environ, root=str(tmp_path))
    assert words in reason and "acts for you" in reason
    assert approval.key_out_of_reach({}, root=str(tmp_path / "plain")) == ""


def test_in_wsl_an_unplugged_key_is_not_waited_for(monkeypatch):
    monkeypatch.setattr(approval, "key_out_of_reach", lambda: approval.WSL_NO_KEY)
    terminal = approval.Terminal(io.StringIO(), io.StringIO())
    with pytest.raises(approval.ApprovalError, match="usbipd attach"):
        approval.wait_for_key(lambda: [], terminal, 30, sleep=lambda s: pytest.fail("waited"))
    # A key passed through is found and used as anywhere else.
    assert approval.wait_for_key(lambda: ["key"], terminal, 30) == ["key"]


def test_the_wait_names_the_remote_shells_it_cannot_recognize(monkeypatch):
    """Named when the wait ends without a key, not at every local prompt."""
    monkeypatch.setattr(approval, "key_out_of_reach", lambda: "")
    out = io.StringIO()
    with pytest.raises(approval.ApprovalError) as ended:
        approval.wait_for_key(lambda: [], approval.Terminal(io.StringIO(), out), 1, sleep=lambda s: None,
                              clock=iter([0.0, 0.5, 2.0]).__next__)
    assert "mosh" not in out.getvalue()
    assert out.getvalue().startswith("Insert your security key (Ctrl-C to cancel; waiting up to 1 seconds)")
    assert "cannot reach this terminal over mosh or another remote shell" in str(ended.value)


@pytest.mark.parametrize(("platform", "machine", "declared"), [
    ("darwin", "arm64", True), ("darwin", "x86_64", True), ("linux", "x86_64", True), ("linux", "aarch64", True),
    ("linux", "armv7l", False), ("linux", "i686", False), ("win32", "AMD64", False), ("freebsd14", "amd64", False),
])
def test_python_fido2_is_declared_only_where_cryptography_ships_wheels(platform, machine, declared):
    """cryptography 49 and later publish no Intel macOS wheel, so the client would need a Rust toolchain on an Intel Mac. The package's markers and the client's own
    reading of them agree: python-fido2 on macOS and 64-bit Linux, cryptography below 49 on an
    Intel Mac, nothing elsewhere."""
    import tomllib

    from packaging.requirements import Requirement

    project = tomllib.loads((ROOT / "client/pyproject.toml").read_text())["project"]
    environment = {"sys_platform": platform, "platform_machine": machine}
    applying = [Requirement(text) for text in project["dependencies"]
                if Requirement(text).marker.evaluate(environment)]
    assert any(item.name == "fido2" for item in applying) is declared
    # cryptography where python-fido2 installs: 48.0.x on an Intel Mac (no wheel of 49 or later
    # there), elsewhere from the locked 50.0.2 up to python-fido2's own bound (<52), so its fixes
    # keep arriving; never declared otherwise.
    from packaging.specifiers import SpecifierSet

    crypto = [item.specifier for item in applying if item.name == "cryptography"]
    intel_mac = platform == "darwin" and machine == "x86_64"
    expected = [SpecifierSet(">=48.0.1,<49" if intel_mac else ">=50.0.2,<52")] if declared else []
    assert crypto == expected, crypto
    assert all(str(Requirement(text).specifier) for text in project["dependencies"])
    assert approval.fido2_declared(platform, machine) is declared


def test_python_fido2_is_pinned_to_the_reviewed_release_and_the_lock_records_what_installs():
    """The touch path's library is exactly the reviewed python-fido2 (no later upload installs
    unreviewed), and the hash-locked resolution records, per platform, the cryptography a plain
    install of these ranges resolves (50.0.2; 48.0.1 on an Intel Mac)."""
    import tomllib

    from packaging.requirements import Requirement

    project = tomllib.loads((ROOT / "client/pyproject.toml").read_text())["project"]
    [fido2] = [Requirement(text) for text in project["dependencies"] if Requirement(text).name == "fido2"]
    assert str(fido2.specifier) == "==2.2.1"
    declared = [line for line in (ROOT / "client/requirements/runtime.txt").read_text().splitlines()
                if line and not line.startswith("#")]
    assert declared == project["dependencies"], "runtime.txt lists exactly what the package declares"
    lock = (ROOT / "client/requirements/runtime.lock").read_text()
    pinned = {line.split(" ;")[0] for line in lock.splitlines() if line[:1].isalpha()}
    assert {"fido2==2.2.1", "cryptography==48.0.1", "cryptography==50.0.2"} <= pinned, pinned
    assert "cryptography==48.0.1 ; platform_machine == 'x86_64' and sys_platform == 'darwin'" in lock


def test_a_platform_without_python_fido2_is_told_why(monkeypatch):
    monkeypatch.setattr(approval, "_homebrew_install", lambda: False)
    monkeypatch.setattr(approval, "fido2_declared", lambda: False)
    assert "installs without python-fido2 on this platform" in approval._no_fido2()
    monkeypatch.setattr(approval, "fido2_declared", lambda: True)
    assert "reinstall the client" in approval._no_fido2()


def test_targets_authorize_records_the_person_the_connection_acts_for(monkeypatch):
    """With the switch off the engine used to record '<local OS user> via shakerscan targets
    authorize' (root, on a VPS). On an Enterprise connection it is the person the token
    acts for, as the gateway names them; on an open-source engine, this computer's user."""
    sys.path.insert(0, str(ROOT / "client" / "src"))
    from shakerscan import decisions

    monkeypatch.setattr(decisions, "helper", lambda name: approval)
    monkeypatch.setattr(decisions, "_os_user", lambda: "root")

    def client(answer):
        def get(path):
            assert path == approval.ME_PATH
            if isinstance(answer, Exception):
                raise answer
            return answer
        return types.SimpleNamespace(get=get)

    # Where the gateway requires a touch it writes the person who touched over this: the person.
    person = {"user": {"display": "Laptop", "token_label": "laptop"}, "acts_for_name": "alice",
              "person_decision_proof": True}
    assert decisions._decider(client(person), "authorize") == (
        "alice via shakerscan targets authorize, service token laptop")
    # Elsewhere the engine keeps what is sent, which no person proved: the token first, and that
    # (the scanner UI showed it as the person's own decision).
    off = {**person, "person_decision_proof": False}
    assert decisions._decider(client(off), "authorize") == (
        "alice's token laptop, no security-key touch (shakerscan targets authorize)")
    service = {"user": {"display": "CI", "token_label": "ci"}, "acts_for_name": None, "person_decision_proof": False}
    assert decisions._decider(client(service), "unauthorize") == (
        "service token ci (CI), no security-key touch (shakerscan targets unauthorize)")
    older = {"user": {"display": "Laptop", "subject": "laptop"}}
    assert decisions._decider(client(older), "authorize") == (
        "a service token (Laptop), no security-key touch (shakerscan targets authorize)")
    assert decisions._decider(client(OSError("404")), "authorize") == "root via shakerscan targets authorize"
    for proof in (True, False):
        long = {"user": {"display": "x" * 300, "token_label": "y" * 300}, "acts_for_name": "z" * 300,
                "person_decision_proof": proof}
        assert len(decisions._decider(client(long), "authorize")) <= 200


def test_a_refused_decision_in_the_watch_says_the_persons_command():
    """Refused decisions in `approve --watch` used to say 'refused, a key touch is required'
    with no command."""
    when = 1792772519
    submission = approval.person_decision_line({"at": when, "made": "refused", "decision": "target.authorize",
                                                "method": "POST", "path": "/scans", "target_id": TARGET.upper(),
                                                "connection": "agent"})
    assert f"(run in your terminal: shakerscan targets authorize {TARGET})" in submission
    raise_ = approval.person_decision_line({"at": when, "made": "refused", "decision": "budget.raise",
                                            "method": "POST", "path": AMENDMENT, "connection": "agent"})
    assert f"shakerscan hunt budget raise {HUNT} --limit NAME=N" in raise_
    other = approval.person_decision_line({"at": when, "made": "refused", "decision": "credential.share",
                                           "method": "POST", "path": "/credential-profiles/x/grants",
                                           "connection": "agent"})
    assert "run in your terminal" not in other and "refused, a key touch is required" in other
    environment = approval.person_decision_line({"at": when, "made": "with_token", "outcome": "unproven",
                                                 "decision": "target.environment", "connection": "agent"})
    assert "change the environment a target or device is judged in" in environment


def test_a_refused_start_in_the_watch_says_to_ask_the_agent_for_its_command():
    """A Hunt start past its session's safety budget: the feed keeps no request body, so the
    watch cannot name the start's own `shakerscan api POST /hunts` command; it says whom to ask
    for it, and what the decision is."""
    when = 1792772519
    line = approval.person_decision_line({"at": when, "made": "refused", "decision": "hunt.start",
                                          "method": "POST", "path": "/hunts", "connection": "agent"})
    assert "refused, a key touch is required (ask the agent for its command: the start's own" in line
    assert "`shakerscan api POST /hunts ...` line, which only its output has)" in line
    assert "start a Hunt past its agent session's safety budget (POST /hunts)" in line
    assert "run in your terminal" not in line
    said = approval.person_decision_line({"at": when, "made": "refused", "decision": "hunt.start",
                                          "summary": "Start a Hunt of honey.example.com", "connection": "agent"})
    assert said.endswith(": Start a Hunt of honey.example.com via connection agent")


def test_a_token_is_only_ever_sent_over_https_by_the_touch():
    """The approval routes take the connection's bearer token; over http:// it is refused before
    any request is built (defense in depth: the commands refuse such a connection first)."""
    for url in ("http://gateway.example.com", "HTTP://gateway.example.com", "gateway.example.com"):
        with pytest.raises(decision.PersonDecisionError, match="only ever sent over https://"):
            decision.json_poster(url, "secret-token")
    assert callable(decision.json_poster("https://gateway.example.com/", "secret-token"))
    # No token, no bearer header: nothing to protect (an engine without one).
    assert callable(decision.json_poster("http://127.0.0.1:8080", None))


def test_an_approval_names_whom_it_is_for_at_the_proof_not_in_a_line_of_its_own(monkeypatch):
    """The client asks for no sign-in name; someone using a token that acts for another person
    used to be asked for that person's proof without being told. The touch prompt names them
    ("..., as alice"; a code's prompt already does: "TOTP code for alice"), instead of a line
    'Approving as alice, ...' printed on every run."""
    def send(method, path, payload=None, headers=None, *, timeout=None):
        if method == "GET" and path == approval.ME_PATH:
            return 200, {"person_decision_proof": False}  # a gateway that names the approver
        document = approval.set_document("permission_decision", "alice", ORIGIN, {"decisions": []})
        nonce = "bm9uY2U"
        digest = approval.set_digest(document)
        return 200, {"schema_version": "shakerscan-approval-challenge/v1", "approval_id": "apv_1",
                     "account": "alice", "set_digest": digest, "methods": ["security_key"], "nonce": nonce,
                     "webauthn": {"challenge": approval.expected_challenge(nonce, digest), "rpId": "x"}}

    told = []
    monkeypatch.setattr(approval, "security_key_assertion",
                        lambda webauthn, origin, terminal, **kw: told.append(kw.get("prompt")) or {})
    out = io.StringIO()
    stepup = approval.StepUp(send, ORIGIN, approval.Terminal(io.StringIO(), out))
    stepup.prompt = "Touch your security key to allow (Ctrl-C to cancel)..."
    challenge, _ = stepup.begin("permission_decision", {"decisions": []})
    stepup.prove(challenge)
    assert "Approving as" not in out.getvalue()
    assert told == ["Touch your security key to allow, as alice (Ctrl-C to cancel)..."]
    # Named with --account: the person typed the name, nothing more is said.
    named = approval.StepUp(send, ORIGIN, approval.Terminal(io.StringIO(), out), account="alice")
    named.prompt = "Touch your security key to allow (Ctrl-C to cancel)..."
    named.prove(named.begin("permission_decision", {"decisions": []})[0])
    assert told[-1] == "Touch your security key to allow (Ctrl-C to cancel)..."
    assert approval.as_approver("Touch your security key.", "bob") == "Touch your security key, as bob."



# ---- the least work for the person, the words they are shown, where a key cannot be opened ------


def test_the_key_is_preferred_whenever_it_holds_the_persons_key_switch_on_or_off(monkeypatch):
    """Without --method a plugged-in key that holds one of the person's keys is asked, whether the
    gateway asks only for a touch (its administrator requires one) or also for the key's PIN (the
    switch off): never a 6-digit code while a key can answer. The code only when no key can: none
    holds the person's key, the key has no PIN where one is asked, or there is no challenge to
    ask a key about."""
    mine = key("YubiKey 5C", holds=[b"mine"])
    fake_fido2(monkeypatch, [mine])
    touch = {**WEBAUTHN, "userVerification": "discouraged"}
    assert approval.preferred_method(["totp", "security_key"], WEBAUTHN, ORIGIN) == "security_key"
    assert approval.preferred_method(["totp", "security_key"], touch, ORIGIN) == "security_key"
    assert approval.preferred_method(["totp", "security_key"], None, ORIGIN) == "totp"
    fake_fido2(monkeypatch, [key("YubiKey 5C", holds=[b"other"])])
    assert approval.preferred_method(["totp", "security_key"], WEBAUTHN, ORIGIN) == "totp"
    fake_fido2(monkeypatch, [key("no PIN", holds=[b"mine"], pin=False)])
    assert approval.preferred_method(["totp", "security_key"], WEBAUTHN, ORIGIN) == "totp"
    fake_fido2(monkeypatch, [])
    assert approval.preferred_method(["totp", "security_key"], WEBAUTHN, ORIGIN) == "totp"
    fake_fido2(monkeypatch, [mine])
    # A key is all the person has: it is asked (with its PIN when the gateway asks for one).
    assert approval.preferred_method(["security_key"], WEBAUTHN, ORIGIN) == "security_key"
    assert approval.preferred_method(["security_key", "sso"], WEBAUTHN, ORIGIN) == "security_key"
    # --method still chooses.
    stepup = approval.StepUp(lambda *a, **k: (200, {}), ORIGIN, approval.Terminal(io.StringIO(), io.StringIO()),
                             method="security-key")
    assert stepup.method_for({"methods": ["totp", "security_key"], "webauthn": WEBAUTHN}) == "security_key"


def test_a_key_with_a_pin_that_finds_nothing_without_it_is_left_to_the_real_assertion(monkeypatch):
    """A credential a browser made to need the key's PIN for every use (credProtect) is not found
    by the silent check, which asks no PIN. When the gateway asks for the PIN anyway, the key is
    not called 'not registered' on that answer: the assertion, with the PIN, decides."""
    holder = key("YubiKey 5", holds=[], pin=True)
    fake_fido2(monkeypatch, [holder])
    assert approval.probe_device(holder, WEBAUTHN, ORIGIN) == "unknown"
    devices, why = approval.eligible_devices([holder], WEBAUTHN, ORIGIN)
    assert devices == [holder] and why == ""
    # A touch asks no PIN. Such a credential cannot answer one, so the key is asked once more
    # with its PIN (one PIN, then the touch) instead of being called unregistered: a passkey-only
    # account could approve with 0.11.1 and its PIN, and must not lose that with 0.11.2.
    touch = {**WEBAUTHN, "userVerification": "discouraged"}
    assert approval.probe_device(holder, touch, ORIGIN) == "pin_only"
    devices, why = approval.eligible_devices([holder], touch, ORIGIN)
    assert devices == [holder] and why == ""
    assert approval.answering_keys([holder], touch, ORIGIN) == ([holder], "", True)
    # A key that holds one answers the touch alone, and is chosen before it.
    mine = key("YubiKey 5C", holds=[b"mine"])
    fake_fido2(monkeypatch, [holder, mine])
    assert approval.answering_keys([holder, mine], touch, ORIGIN) == ([mine], "", False)
    # A key with no PIN that holds nothing is not registered to the person: said plainly.
    bare = key("Security Key", holds=[], pin=False)
    fake_fido2(monkeypatch, [bare])
    assert approval.probe_device(bare, touch, ORIGIN) == "no"
    devices, why = approval.eligible_devices([bare], touch, ORIGIN)
    assert devices == [] and "not registered to your account" in why
    assert '"Use it: for terminal approvals (touch)"' in why


def test_a_passkey_that_answers_only_after_its_pin_is_asked_with_its_pin_once(monkeypatch):
    """With the gateway asking for a touch only, a sign-in passkey a browser
    made to need its PIN for every use (credProtect) found nothing silently, and 0.11.2 refused
    with "add the key again", although the gateway accepts a PIN-verified assertion. The key is
    now asked with its PIN, said first in plain words."""
    holder = key("YubiKey 5", holds=[], pin=True)
    fake_fido2(monkeypatch, [holder])
    seen = {}

    class Client:
        def __init__(self, device, user_interaction=None, **kwargs):
            seen["device"], self.interaction = device, user_interaction

        def get_assertion(self, options):
            seen["options"] = options
            seen["pin"] = self.interaction.request_pin(None, "gateway.example.com")
            inner = types.SimpleNamespace(client_data=b"{}", authenticator_data=b"a", signature=b"s", user_handle=None)
            return types.SimpleNamespace(get_response=lambda index: types.SimpleNamespace(raw_id=b"id", response=inner))

    monkeypatch.setitem(sys.modules, "fido2.client", types.SimpleNamespace(
        Fido2Client=Client, UserInteraction=object, DefaultClientDataCollector=lambda origin: origin))
    monkeypatch.setitem(sys.modules, "fido2.webauthn", types.SimpleNamespace(
        PublicKeyCredentialDescriptor=lambda **k: k, PublicKeyCredentialRequestOptions=lambda **k: k,
        PublicKeyCredentialType=types.SimpleNamespace(PUBLIC_KEY="public-key"),
        UserVerificationRequirement=lambda value: f"uv:{value}"))
    monkeypatch.setattr(approval, "pin_retries", lambda device: 8)

    class Typed(approval.Terminal):
        def secret(self, prompt):
            self.stdout.write(prompt)
            return "4321"

    terminal = Typed(io.StringIO(), io.StringIO())
    approval.security_key_assertion({**WEBAUTHN, "userVerification": "discouraged"}, ORIGIN, terminal,
                                    prompt="Touch your security key to approve (Ctrl-C to cancel)...")
    assert seen["device"] is holder and seen["options"]["user_verification"] == "uv:required"
    assert seen["pin"] == "4321"
    text = terminal.stdout.getvalue()
    said = text.index("it holds a passkey that answers only after the key's PIN. To try it, enter the key's PIN")
    assert said < text.index("Security key PIN (not your authenticator code): ")
    # The touch prompt follows the PIN, not before it (the key waits for the PIN first).
    assert "Touch your security key to approve" not in text[:said]


def _decide_by_touch(monkeypatch, decision_word, *, touch=True):
    from tests.test_hunt_approve import ORIGIN as SCRIPTED_ORIGIN
    from tests.test_hunt_approve import Gateway, Terminal, _request

    gateway = Gateway(_request(), methods=("security_key",))
    original = gateway.__call__

    def with_webauthn(method, path, payload=None, headers=None, *, timeout=None):
        status, answer = original(method, path, payload, headers, timeout=timeout)
        if path == approval.BEGIN_PATH and status == 200:
            nonce = b64url(b"n" * 32)
            answer = {**answer, "nonce": nonce, "webauthn": {
                "challenge": approval.expected_challenge(nonce, answer["set_digest"]), "rpId": "scanner.example.com",
                "userVerification": "discouraged" if touch else "required"}}
        return status, answer

    prompts = []

    def assertion(webauthn, origin, terminal, *, prompt="", insert_seconds=60.0):
        prompts.append(prompt)
        terminal.say(prompt)
        return {"id": "Y3JlZA", "rawId": "Y3JlZA", "type": "public-key", "response": {}}

    monkeypatch.setattr(approval, "security_key_assertion", assertion)
    terminal = Terminal()
    code = approval.decide(with_webauthn, terminal, [_request()], decision_word, enterprise=True,
                           origin=SCRIPTED_ORIGIN, account="alice")
    return code, prompts, terminal.text


@pytest.mark.parametrize(("word", "verb", "state"), [("allow", "allow", "granted"), ("deny", "deny", "denied")])
def test_a_touch_says_what_it_decides_and_the_result_says_it_was_a_touch(monkeypatch, word, verb, state):
    code, prompts, text = _decide_by_touch(monkeypatch, word)
    assert code == 0
    assert prompts == [f"Touch your security key to {verb} (Ctrl-C to cancel)..."]
    assert f"{state}: " in text and "(by alice, security-key touch)" in text
    # With the switch off a key with its PIN is said as before.
    code, prompts, text = _decide_by_touch(monkeypatch, word, touch=False)
    assert "(by alice, terminal stepup)" in text


def test_several_requests_say_how_many_one_touch_decides(monkeypatch):
    from tests.test_hunt_approve import ORIGIN as SCRIPTED_ORIGIN
    from tests.test_hunt_approve import Gateway, Terminal, _request

    second = _request(id="eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", title="Second")
    gateway = Gateway(_request(), second, methods=("security_key",))
    original = gateway.__call__

    def with_webauthn(method, path, payload=None, headers=None, *, timeout=None):
        status, answer = original(method, path, payload, headers, timeout=timeout)
        if path == approval.BEGIN_PATH and status == 200:
            nonce = b64url(b"n" * 32)
            answer = {**answer, "nonce": nonce, "webauthn": {
                "challenge": approval.expected_challenge(nonce, answer["set_digest"]), "rpId": "scanner.example.com",
                "userVerification": "discouraged"}}
        return status, answer

    prompts = []
    monkeypatch.setattr(approval, "security_key_assertion",
                        lambda webauthn, origin, terminal, *, prompt="", insert_seconds=60.0:
                        prompts.append(prompt) or {"id": "Y3JlZA", "rawId": "Y3JlZA", "type": "public-key",
                                                   "response": {}})
    approval.decide(with_webauthn, Terminal(), [_request(), second], "allow", enterprise=True,
                    origin=SCRIPTED_ORIGIN, account="alice")
    assert prompts == ["Touch your security key to allow these 2 requests (Ctrl-C to cancel)..."]


def test_no_key_registered_names_the_decision_and_asks_no_touch():
    """Before any touch was asked, the person used to read 'the gateway refused the touch
    (security_key_not_registered, HTTP 403)' with no word of the decision."""
    def post(path, payload):
        assert path == decision.BEGIN_PATH, "nothing is finished without a touch"
        return 403, {"schema_version": "shakerscan-approval-error/v1", "error": "security_key_not_registered",
                     "message": "register a USB or NFC security key once, in the browser, under My account"}

    asked = []
    out = io.StringIO()
    with pytest.raises(decision.PersonDecisionError) as raised:
        decision.complete(post, origin=ORIGIN, method="POST", path=AMENDMENT, body=json.dumps(RAISE).encode(),
                          detail=REFUSAL["detail"], terminal=approval.Terminal(io.StringIO(), out),
                          assertion=lambda *a, **k: asked.append(a))
    text = str(raised.value)
    assert asked == [] and "refused the touch" not in text
    assert text.startswith(f"{SUMMARY}: no touch was asked (security_key_not_registered): register a USB or NFC")
    assert text.endswith("nothing was changed")


NO_KEY = ("register a USB or NFC security key once, in the browser, at https://gateway.example.com/_enterprise/"
          "#account, under My account > Passkeys with \"Use it: for terminal approvals (touch)\" (it never signs "
          "you in), then run the command again: alice has no security key registered for terminal approvals. "
          "An administrator requires a security-key touch for terminal approvals on this installation; a code, "
          "a phone or Touch ID cannot answer a terminal, and a passkey saved in a browser cannot either, so "
          "use a USB or NFC key such as a YubiKey and touch it when the command asks.")


def test_approve_says_no_key_registered_whole_before_any_request_and_exits_1(monkeypatch):
    """`shakerscan approve <id>` for a person with no key under the switch: the gateway's remedy
    was cut at 400 characters ("...a phone or Touch ID cann"), printed after the request list,
    and approve exited 2 where `targets authorize` exits 1."""
    assert len(NO_KEY) > 400
    monkeypatch.delenv("SHAKERSCAN_AGENT_NAME", raising=False)
    out = at_a_terminal(monkeypatch)
    monkeypatch.setattr(sys, "stderr", io.StringIO())
    monkeypatch.setenv("SHAKERSCAN_API_TOKEN", "sst_fixture_token")
    request = {"id": REQUEST_ID, "hunt_id": HUNT, "status": "pending", "title": "Raise max_http_requests",
               "kind": "budget.raise", "subject_digest": "d" * 64, "choices": ["allow", "deny"],
               "scopes": ["hunt"], "remember_supported": False}
    posted = []

    def send(method, path, payload=None, **_):
        if (method, path) == ("GET", approval.ME_PATH):
            return 200, {"user": {"auth": "token"}, "person_decision_proof": True}
        if method == "GET" and path.startswith(f"/hunts/{HUNT}/permission-requests/{REQUEST_ID}"):
            return 200, request
        if (method, path) == ("POST", approval.BEGIN_PATH):
            posted.append(path)
            return 403, {"schema_version": "shakerscan-approval-error/v1", "error": "security_key_not_registered",
                         "message": NO_KEY}
        raise AssertionError((method, path))

    monkeypatch.setattr(v2_cli, "_approval_send", lambda client: send)
    code = v2_cli.main(["--api-url", ORIGIN, "approve", REQUEST_ID, "--hunt", HUNT])
    assert code == 1, sys.stderr.getvalue()
    assert posted == [approval.BEGIN_PATH], "begun once, nothing finished"
    err = sys.stderr.getvalue()
    assert NO_KEY in err, err
    assert "permission request(s)" not in out.getvalue() and "Raise max_http_requests" not in out.getvalue()


def test_a_touch_the_gateway_did_not_accept_is_said_as_such():
    challenge = {}

    def post(path, payload):
        if path == decision.BEGIN_PATH:
            gateway = ScriptedGateway()
            status, answer = gateway.post(path, payload)
            challenge.update(answer)
            return status, answer
        return 403, {"schema_version": "shakerscan-approval-error/v1", "error": "stepup_failed",
                     "message": "the security key's signature was not accepted"}

    with pytest.raises(decision.PersonDecisionError, match="the gateway did not accept the touch \\(stepup_failed"):
        decision.complete(post, origin=ORIGIN, method="POST", path=AMENDMENT, body=json.dumps(RAISE).encode(),
                          detail=REFUSAL["detail"], terminal=approval.Terminal(io.StringIO(), io.StringIO()),
                          assertion=Signer())


SECRET_REF = "5a5a5a5a-1111-4222-8333-444455556666"


@pytest.mark.parametrize(("path", "body", "command"), [
    (f"/targets/{TARGET}/discovered-secrets/{SECRET_REF}/state", {"state": "active"},
     f"shakerscan secrets reactivate {TARGET} {SECRET_REF}"),
    (f"/targets/{TARGET}/discovered-secrets/{SECRET_REF}/expiry", {"days": 30},
     f"shakerscan secrets expiry {TARGET} {SECRET_REF} --days 30"),
])
def test_a_secrets_decision_names_the_secrets_command(path, body, command):
    assert decision.person_command("POST", path, json.dumps(body).encode()) == command


def test_a_large_request_is_named_by_a_saved_body_not_one_long_line(tmp_path, monkeypatch):
    """A generic decision's whole body went into one `shakerscan api` line (up to about 190 KB
    in the agent's output and the person's shell history). A body longer than INLINE_BODY is
    saved, owner-only, and the command names the file; `shakerscan api` reads it with @."""
    monkeypatch.setenv("SHAKERSCAN_CONFIG_DIR", str(tmp_path / "cfg"))
    path = f"/targets/{TARGET}/hunt-authority"
    body = json.dumps({"expected_revision": 3, "collection_ids": [TARGET] * 200}).encode()
    command = decision.person_command("PUT", path, body)
    assert len(command) < 300, command
    assert command.startswith(f"shakerscan api PUT {path} @")
    saved = Path(command.split(" @", 1)[1])
    assert saved.read_bytes() == body
    assert saved.parent == tmp_path / "cfg" / "decisions"
    assert saved.stat().st_mode & 0o077 == 0
    # The same body is one file; a short body stays inline.
    assert decision.person_command("PUT", path, body) == command
    small = json.dumps({"expected_revision": 3}).encode()
    assert decision.person_command("PUT", path, small) == f"shakerscan api PUT {path} '{small.decode()}'"
    request = api_cli.build_request("PUT", path, "@" + str(saved), api_url=ORIGIN, token=None)
    assert json.loads(request.data) == json.loads(body)
    with pytest.raises(api_cli.ApiCliError, match="cannot read the request body"):
        api_cli.build_request("PUT", path, "@" + str(saved.parent / "missing.json"), api_url=ORIGIN, token=None)
    with pytest.raises(api_cli.ApiCliError, match="reads a request body only from"):
        api_cli.build_request("PUT", path, "@" + str(tmp_path / "missing.json"), api_url=ORIGIN, token=None)


@pytest.mark.parametrize("name", [
    "--url=https://evil.example/a", "Max_hosts", "max-hosts", "max hosts", "max_hosts;id", "x" * 65, "",
    "max_hosts2",
])
def test_a_raise_names_its_own_command_only_when_every_limit_name_is_a_plain_word(name):
    """A limit name from the agent's body went into the dedicated command quoted, not checked: a
    name such as --url=https://evil.example/a became `--limit --url=...=40`, one argument that
    reads as the client's own --url. Only names of lower-case letters and underscores (at most
    64) get the dedicated command; any other body is named as itself through `shakerscan api`."""
    body = json.dumps({**RAISE, "limits": {"max_hosts": 3, name: 40}}).encode()
    command = decision.person_command("POST", AMENDMENT, body)
    assert command.startswith(f"shakerscan api POST {AMENDMENT} "), command
    assert "budget raise" not in command and "--limit" not in command
    assert shlex.split(command)[4] == body.decode()
    plain = json.dumps({**RAISE, "limits": {"m" * 64: 40, "max_hosts": 3}}).encode()
    assert decision.person_command("POST", AMENDMENT, plain) == (
        f"shakerscan hunt budget raise {HUNT} --limit max_hosts=3 --limit {'m' * 64}=40"
    )


def test_api_reads_a_body_file_only_from_the_clients_decisions_directory(tmp_path, monkeypatch):
    """`shakerscan api ... @FILE` read any path, and any JSON file there became the request's body:
    an agent running as another user could talk the person into sending `@~/.docker/config.json`.
    A body is read only from the directory the client saves a person's long bodies in."""
    monkeypatch.setenv("SHAKERSCAN_CONFIG_DIR", str(tmp_path / "cfg"))
    monkeypatch.setenv("HOME", str(tmp_path))
    secret = tmp_path / "config.json"
    secret.write_text('{"auths": {"registry.example": {"auth": "c2VjcmV0"}}}')
    decisions = tmp_path / "cfg" / "decisions"
    decisions.mkdir(parents=True)
    (decisions / "link.json").symlink_to(secret)
    (decisions / "up").symlink_to(tmp_path)
    for where in (str(secret), "~/config.json", str(decisions / "link.json"), str(decisions / "up" / "config.json"),
                  str(decisions / ".." / ".." / "config.json")):
        with pytest.raises(api_cli.ApiCliError, match="reads a request body only from") as refused:
            api_cli.build_request("POST", "/targets", "@" + where, api_url=ORIGIN, token=None)
        assert str(decisions) in str(refused.value) and "c2VjcmV0" not in str(refused.value)
    saved = Path(decision.saved_body(b'{"expected_revision": 3}'))
    assert saved.parent == decisions
    request = api_cli.build_request("PUT", "/targets", "@" + str(saved), api_url=ORIGIN, token=None)
    assert json.loads(request.data) == {"expected_revision": 3}
    # A JSON body is still given inline, from any file the person reads themselves.
    inline = api_cli.build_request("POST", "/targets", secret.read_text(), api_url=ORIGIN, token=None)
    assert json.loads(inline.data)["auths"]


def test_a_saved_body_is_removed_after_a_week(tmp_path, monkeypatch):
    """Saved bodies were never cleaned up. One older than a week is removed the next time a body
    is saved; a newer one, and any file the client did not save there, stays."""
    import os
    import time

    monkeypatch.setenv("SHAKERSCAN_CONFIG_DIR", str(tmp_path / "cfg"))
    path = f"/targets/{TARGET}/hunt-authority"
    old = Path(decision.person_command("PUT", path, json.dumps({"ids": [TARGET] * 100}).encode()).split(" @", 1)[1])
    recent = Path(decision.person_command("PUT", path, json.dumps({"ids": [TARGET] * 101}).encode()).split(" @", 1)[1])
    other = old.parent / "notes.json"
    other.write_text("{}")
    week = decision.SAVED_SECONDS
    os.utime(old, (time.time() - week - 60,) * 2)
    os.utime(other, (time.time() - week - 60,) * 2)
    os.utime(recent, (time.time() - week + 3600,) * 2)
    decision.person_command("PUT", path, json.dumps({"ids": [TARGET] * 102}).encode())
    assert not old.exists() and recent.exists() and other.exists()


def test_a_body_that_cannot_be_saved_is_named_without_it(tmp_path, monkeypatch):
    blocked = tmp_path / "file"
    blocked.write_text("")
    monkeypatch.setenv("SHAKERSCAN_CONFIG_DIR", str(blocked))  # a file: no directory can be made in it
    body = json.dumps({"expected_revision": 3, "collection_ids": [TARGET] * 200}).encode()
    command = decision.person_command("PUT", f"/targets/{TARGET}/hunt-authority", body)
    assert len(command) < 400 and "@" in command and str(len(body)) in command


def _linux_nodes(tmp_path, monkeypatch, descriptor):
    (tmp_path / "dev").mkdir()
    (tmp_path / "dev" / "hidraw0").write_text("")
    if descriptor is not None:
        where = tmp_path / "sys" / "class" / "hidraw" / "hidraw0" / "device"
        where.mkdir(parents=True)
        (where / "report_descriptor").write_bytes(descriptor)
    monkeypatch.setattr(approval.sys, "platform", "linux")
    monkeypatch.setattr(approval, "key_out_of_reach", lambda: "")
    real_access = approval.os.access
    monkeypatch.setattr(approval.os, "access",
                        lambda path, mode: False if "/dev/hidraw" in str(path) else real_access(path, mode))
    return str(tmp_path)


FIDO_DESCRIPTOR = bytes.fromhex("06d0f10901a1010920150026ff007508954081020921150026ff00750895409102c0")
KEYBOARD_DESCRIPTOR = bytes.fromhex("05010906a101050719e029e715002501750195088102c0")


def test_on_linux_a_key_this_user_cannot_open_is_said_at_once(tmp_path, monkeypatch):
    """python-fido2 skips a /dev/hidraw node it cannot open, so a plugged-in key with no udev
    access looked unplugged: the client waited a minute for an insertion and then said none was
    inserted. A FIDO node (its report descriptor names the FIDO usage page) that cannot be opened
    is now said at once, with the udev remedy."""
    root = _linux_nodes(tmp_path, monkeypatch, FIDO_DESCRIPTOR)
    assert approval.unopenable_keys(root=root) == "fido"
    terminal = approval.Terminal(io.StringIO(), io.StringIO())
    with pytest.raises(approval.ApprovalError, match="a security key is plugged in that this user may not open"):
        approval.wait_for_key(lambda: [], terminal, 30, sleep=lambda s: pytest.fail("waited"), root=root)
    assert "udev" in approval._no_device(root=root)


def test_on_linux_an_unreadable_device_of_unknown_kind_is_named_while_waiting(tmp_path, monkeypatch):
    root = _linux_nodes(tmp_path, monkeypatch, None)
    assert approval.unopenable_keys(root=root) == "maybe"
    out = io.StringIO()
    with pytest.raises(approval.ApprovalError) as raised:
        approval.wait_for_key(lambda: [], approval.Terminal(io.StringIO(), out), 1, sleep=lambda s: None,
                              clock=iter([0.0, 0.5, 2.0]).__next__, root=root)
    assert "this user may not be allowed to open it" in out.getvalue()
    assert "this user may not be allowed to open it" in str(raised.value)
    # A keyboard's node is no key: not named.
    keyboard = tmp_path / "k"
    keyboard.mkdir()
    assert approval.unopenable_keys(root=_linux_nodes(keyboard, monkeypatch, KEYBOARD_DESCRIPTOR)) == ""


def test_doctor_against_an_open_source_engine_prints_no_enterprise_lines(monkeypatch):
    sys.path.insert(0, str(ROOT / "client" / "src"))
    from shakerscan import decisions

    monkeypatch.setattr(decisions, "helper", lambda name: approval)
    gone = types.SimpleNamespace(request_json=lambda method, path: (_ for _ in ()).throw(OSError("404")))
    assert decisions.touch_lines(gone) == []


def test_the_homebrew_formula_says_at_install_that_it_cannot_touch():
    formula = (ROOT / "client" / "homebrew" / "shakerscan.rb.in").read_text()
    assert "def caveats" in formula
    caveats = formula.split("def caveats", 1)[1]
    assert "security key" in caveats and "pipx install shakerscan" in caveats
    # `brew info` shows them too, with both installers that carry python-fido2 and the check.
    assert "uv tool install shakerscan" in caveats and "shakerscan doctor" in caveats


# ---- one resend in every stack, quoted commands, the record, no side effect --------------------


def test_shakerscan_scan_resends_once_and_never_asks_a_second_touch(gateway, monkeypatch, capsys):
    """scan_cli's resend carries the grant and is never completed again: a resend the gateway
    refuses once more is reported (one begin, one touch, two sends), as the product CLI does."""
    monkeypatch.setenv("SHAKERSCAN_API_TOKEN", "token-1")
    at_a_terminal(monkeypatch)
    signer = Signer()
    monkeypatch.setattr(approval, "security_key_assertion", signer)

    class Forgetful(dict):
        def pop(self, key, default=None):
            return None  # the gateway does not take the grant

    gateway.grants = Forgetful()
    code = scan_cli.main(["--api-url", ORIGIN, "--ui-url", ORIGIN, "https://new.example.com",
                          "--active-testing", "--confirm-active"])
    scans = [sent for sent in gateway.sent if sent["url"].endswith("/scans")]
    assert code != 0
    assert len(gateway.begun) == 1 and len(signer.asked) == 1 and len(scans) == 2
    assert scans[1]["headers"]["x-shakerscan-person-proof"] == "apv_grant_1"
    capsys.readouterr()


@pytest.mark.parametrize("hostile", ["$(id)", "x;touch pwned", "`id`", "a'b", "a b"])
def test_every_value_a_persons_command_names_is_one_quoted_word(hostile):
    """The Hunt id, a target id or URL, a secret's ids and a budget limit come from the request
    an agent sent: each is one shell word of the command the person is given, never code."""
    body = json.dumps({**RAISE, "limits": {"max_state_changing_requests": 40}}).encode()
    words = shlex.split(decision.person_command("POST", f"/hunts/{hostile}/budget-amendments", body))
    assert words[:5] == ["shakerscan", "hunt", "budget", "raise", hostile]
    words = shlex.split(decision.person_command("POST", f"/targets/{hostile}/authorization", b"{}"))
    assert words == ["shakerscan", "targets", "authorize", hostile]
    scan = json.dumps({"target": hostile, "policy": {"active_testing": True}}).encode()
    assert shlex.split(decision.person_command("POST", "/scans", scan)) == ["shakerscan", "targets", "authorize",
                                                                          hostile]
    secret = f"/targets/{hostile}/discovered-secrets/{hostile}/state"
    assert shlex.split(decision.person_command("POST", secret, b'{"state": "active"}')) == [
        "shakerscan", "secrets", "reactivate", hostile, hostile]
    other = shlex.split(decision.person_command("PATCH", f"/targets/{hostile}", b'{"cohort": "lab"}'))
    assert other == ["shakerscan", "api", "PATCH", f"/targets/{hostile}", '{"cohort": "lab"}']


@pytest.mark.parametrize("hostile", ["-x", "--url=https://evil.example", "--token-file=/tmp/t"])
def test_a_value_that_reads_as_an_option_is_never_one(hostile):
    """A value an agent's request carried that starts with "-" would be an option of the person's
    command (`--url=...` sends the person's connection elsewhere): the request is named whole
    through `shakerscan api` instead (its path starts with "/"), and a refused start names the
    target's authorization by a placeholder, never the start."""
    body = json.dumps(RAISE).encode()
    cases = [
        ("POST", f"/hunts/{hostile}/budget-amendments", body, None),
        ("POST", f"/targets/{hostile}/authorization", b"{}", None),
        ("POST", f"/targets/{hostile}/discovered-secrets/{hostile}/state", b'{"state": "active"}', None),
        ("POST", "/scans", json.dumps({"target": hostile, "policy": {"active_testing": True}}).encode(), None),
        ("POST", "/hunts", json.dumps({"target_id": hostile}).encode(), {"submission": "hunt"}),
    ]
    for method, path, sent, detail in cases:
        words = shlex.split(decision.person_command(method, path, sent, detail))
        assert not any(word.startswith(hostile) for word in words), words
        options = [word for word in words if word.startswith("-")]
        assert set(options) <= {"--limit", "--resume", "--days"}, words
        if path.startswith(("/scans", "/hunts")) and path in {"/scans", "/hunts"}:
            assert words == ["shakerscan", "targets", "authorize", "TARGET-ID"], words


def test_a_refused_retest_without_a_target_names_a_placeholder_a_shell_does_not_wait_on():
    """The command used to read `<the target's URL or id>`: pasted whole, the apostrophe left the
    shell waiting for a closing quote; then `<target>`, which a shell reads as input redirected
    from a file named target. TARGET-ID is one plain word, which `targets authorize` refuses."""
    command = decision.person_command("POST", f"/findings/{HUNT}/retest", b"{}", {"submission": "retest"})
    assert command == "shakerscan targets authorize TARGET-ID"
    assert not set(command) & set("'\"<>|;&$`")


def test_targets_authorize_with_the_switch_off_is_sent_and_recorded_as_the_tokens(gateway, monkeypatch, capsys):
    """Where no touch is required the person's own `targets authorize` is sent with no touch, and
    the engine records the token first and that no person proved it; the command says nothing
    more (`shakerscan doctor` says the switch is off). From an agent's shell it is refused with
    the switch off too: a decision only a person makes is never an agent's one-line command
    (an agent holding the token can still send the request itself: the accepted risk)."""
    decisions = _client_module(monkeypatch, gateway)
    monkeypatch.setenv("SHAKERSCAN_API_TOKEN", "token-1")
    at_a_terminal(monkeypatch, stdin=False)
    import shakerscan.cli as cli

    monkeypatch.setattr(cli, "apply_connection", lambda args: ORIGIN)
    args = types.SimpleNamespace(action="authorize", target="app.example.com", reason=None, json=False,
                                 timeout=None, url=None, token_file=None)
    gateway.refuse = False
    assert decisions.cmd_targets(args) == 3
    assert gateway.sent == []
    assert capsys.readouterr().err.rstrip().endswith("shakerscan targets authorize app.example.com")
    out = at_a_terminal(monkeypatch)

    monkeypatch.setattr(cli, "apply_connection", lambda args: ORIGIN)
    gateway.refuse = False
    original = gateway.open

    def switch_off(request, timeout=None):
        if urllib.parse.urlsplit(request.full_url).path == "/_enterprise/me":
            gateway.sent.append({"method": "GET", "url": request.full_url, "data": None, "headers": {}})
            return _Response({"user": {"auth": "token", "display": "Laptop", "token_label": "laptop"},
                              "acts_for_name": "alice", "person_decision_proof": False})
        return original(request, timeout)

    gateway.open = switch_off
    args = types.SimpleNamespace(action="authorize", target="app.example.com", reason=None, json=False,
                                 timeout=None, url=None, token_file=None)
    assert decisions.cmd_targets(args) == 0
    authorized = [sent for sent in gateway.sent if sent["url"].endswith("/authorization")]
    assert json.loads(authorized[0]["data"])["approved_by"] == (
        "alice's token laptop, no security-key touch (shakerscan targets authorize)")
    shown = out.getvalue().splitlines()
    assert len(shown) == 1 and shown[0].startswith("authorized https://app.example.com/ for active testing"), (
        "one line, no note on the switch")
    capsys.readouterr()


def test_a_raise_records_why_and_that_no_person_proved_it_where_no_touch_is_required():
    sys.path.insert(0, str(ROOT / "client" / "src"))
    from shakerscan import decisions

    off = {"user": {"display": "Laptop", "token_label": "laptop"}, "acts_for_name": "alice",
           "person_decision_proof": False}
    assert decisions._raise_reason(None, off) == (
        "Raised with alice's token laptop, no security-key touch (shakerscan hunt budget raise)")
    assert decisions._raise_reason("the login form needs more", off) == (
        "the login form needs more (with alice's token laptop, no security-key touch)")
    # Where a touch is required the gateway writes its own reason; on an open-source engine there
    # are no tokens.
    assert decisions._raise_reason(None, {**off, "person_decision_proof": True}) == (
        "Raised from the terminal (shakerscan hunt budget raise)")
    assert decisions._raise_reason("why", None) == "why"
    assert len(decisions._raise_reason("x" * 900, off)) <= 500


# ---- the key's PIN, one approver per watch, a copied command, the local question --------------


def _pin_asking_fido2(monkeypatch, seen):
    """FAKE python-fido2 (unit fixture) whose key asks for its PIN during the assertion."""

    class Client:
        def __init__(self, device, user_interaction=None, **kwargs):
            self.interaction = user_interaction

        def get_assertion(self, options):
            seen["pin"] = self.interaction.request_pin(None, "gateway.example.com")
            inner = types.SimpleNamespace(client_data=b"{}", authenticator_data=b"a", signature=b"s", user_handle=None)
            return types.SimpleNamespace(get_response=lambda index: types.SimpleNamespace(raw_id=b"id", response=inner))

    keys = [types.SimpleNamespace(descriptor=types.SimpleNamespace(product_name="YubiKey"))]
    modules = {
        "fido2": types.ModuleType("fido2"),
        "fido2.client": types.SimpleNamespace(Fido2Client=Client, UserInteraction=object,
                                              DefaultClientDataCollector=lambda origin: origin),
        "fido2.hid": types.SimpleNamespace(CtapHidDevice=types.SimpleNamespace(list_devices=lambda: iter(keys))),
        "fido2.webauthn": types.SimpleNamespace(
            PublicKeyCredentialDescriptor=lambda **k: k, PublicKeyCredentialRequestOptions=lambda **k: k,
            PublicKeyCredentialType=types.SimpleNamespace(PUBLIC_KEY="public-key"),
            UserVerificationRequirement=lambda value: f"uv:{value}"),
    }
    for name, module in modules.items():
        monkeypatch.setitem(sys.modules, name, module)


@pytest.mark.parametrize(("retries", "words"), [
    (8, " 8 PIN tries are left."),
    (2, " Only 2 PIN tries are left before the key blocks its PIN; unblocking it resets the key"),
    (1, " Only 1 PIN try is left"),
    (None, "where you enrolled one."),
])
def test_the_pin_prompt_says_it_is_the_keys_pin_not_an_authenticator_code(monkeypatch, retries, words):
    """With the switch off a plugged-in key is preferred over the authenticator code, and the
    gateway asks for its PIN: someone used to typing the 6-digit code at that prompt spent the
    key's PIN tries on it (three in a row need the key removed and inserted again; eight block its
    PIN, and a reset removes every credential on the key)."""
    seen = {}
    _pin_asking_fido2(monkeypatch, seen)
    monkeypatch.setattr(approval, "pin_retries", lambda device: retries)

    class Typed(approval.Terminal):
        def secret(self, prompt):
            self.stdout.write(prompt)
            return "4321"

    terminal = Typed(io.StringIO(), io.StringIO())
    approval.security_key_assertion({"challenge": "AA", "userVerification": "required"}, ORIGIN, terminal)
    text = terminal.stdout.getvalue()
    notice = text.index("asks for your security key's own PIN (the one set on the key), not your authenticator")
    assert notice < text.index("Security key PIN (not your authenticator code): ")
    assert words in text and "--method totp approves with the code instead" in text
    assert seen["pin"] == "4321"


def test_the_pin_tries_are_read_silently_or_not_at_all(monkeypatch):
    calls = []

    class ClientPin:
        def __init__(self, ctap):
            calls.append(ctap)

        def get_pin_retries(self):
            return 5, None

    monkeypatch.setitem(sys.modules, "fido2.ctap2", types.SimpleNamespace(Ctap2=lambda device: ("ctap", device)))
    monkeypatch.setitem(sys.modules, "fido2.ctap2.pin", types.SimpleNamespace(ClientPin=ClientPin))
    assert approval.pin_retries("key") == 5 and calls == [("ctap", "key")]

    def refused(ctap):
        raise FakeCtapError("INVALID_COMMAND")

    monkeypatch.setitem(sys.modules, "fido2.ctap2.pin", types.SimpleNamespace(ClientPin=refused))
    assert approval.pin_retries("key") is None
    assert "not an authenticator code" in approval.key_failure(
        types.SimpleNamespace(code=None, cause=types.SimpleNamespace(code=types.SimpleNamespace(name="PIN_INVALID"))))


def test_a_touch_mode_watch_names_the_approver_once_for_every_decision(monkeypatch):
    """A watch started without --account printed 'Approving as alice, ...' before every decision
    (and read the gateway's description again each time): the approver session it was refused
    named nobody, and each decision began without a name. The name the first decision's challenge
    gives is passed to every later one, and the touch prompt names it (no line of its own)."""
    from tests.test_hunt_approve import ORIGIN as SCRIPTED_ORIGIN
    from tests.test_hunt_approve import Gateway, Terminal, _request

    gateway = Gateway(_request(), _request(id="cccccccc-cccc-4ccc-8ccc-cccccccccccc", title="Second"),
                      methods=("security_key",))
    original = gateway.__call__
    begun = []

    def touch_only(method, path, payload=None, headers=None, *, timeout=None):
        if (answer := newer_gateway(method, path)) is not None:
            return answer
        if path == approval.BEGIN_PATH and payload["purpose"] == "approver_session":
            return 403, {"schema_version": "shakerscan-approval-error/v1", "error": "touch_required",
                         "message": "each decision is one touch"}
        if path == approval.BEGIN_PATH:
            begun.append(payload["account"])
            status, answer = original(method, path, {**payload, "account": "alice"}, headers, timeout=timeout)
            return status, {**answer, "account": "alice"}
        return original(method, path, payload, headers, timeout=timeout)

    named = []
    monkeypatch.setattr(approval.StepUp, "prove", lambda self, challenge: named.append(self.named)
                        or {"method": "security_key", "credential": {}})
    monkeypatch.setattr(approval, "security_key_readiness", lambda **_: "")
    terminal = Terminal(keys=["a", "a"])

    def stop(seconds):
        raise KeyboardInterrupt

    assert approval.watch(touch_only, terminal, enterprise=True, origin=SCRIPTED_ORIGIN,
                          poll_seconds=0.01, sleep=stop) == 0
    assert "Approving as" not in terminal.text, terminal.text
    assert begun == ["", "alice"], "the second decision names the approver the first one was given"
    assert named == [True, True], "every decision's touch prompt names the approver the gateway gave"
    assert all(item["status"] == "granted" for item in gateway.requests.values())


def _decisions_module():
    sys.path.insert(0, str(ROOT / "client" / "src"))
    from shakerscan import decisions

    return decisions


@pytest.mark.parametrize("value", [f"{TARGET}.", f"{TARGET},", f"{TARGET})", "https://app.example.com.",
                                   "https://app.example.com/;", "TARGET-ID", "target-id", "<target>", "TARGET-URL"])
def test_targets_authorize_refuses_a_placeholder_or_a_copied_punctuation_mark(gateway, monkeypatch, capsys, value):
    """`targets authorize <id>.`, copied with the sentence's period, registered and authorized a
    target `https://<id>.`; a placeholder pasted as it was printed registered a host of that
    name. Both are refused before anything is sent."""
    decisions = _client_module(monkeypatch, gateway)
    monkeypatch.setenv("SHAKERSCAN_API_TOKEN", "token-1")
    at_a_terminal(monkeypatch)
    import shakerscan.cli as cli

    monkeypatch.setattr(cli, "apply_connection", lambda args: ORIGIN)
    args = types.SimpleNamespace(action="authorize", target=value, reason=None, json=False,
                                 timeout=None, url=None, token_file=None)
    assert decisions.cmd_targets(args) == 2
    assert gateway.sent == [] and gateway.begun == []
    err = capsys.readouterr().err
    if value.startswith(TARGET):
        assert f"did you mean {TARGET}?" in err
    elif "app.example.com" in value:
        assert "ends in punctuation" in err
    else:
        assert "stands for the target" in err


def test_a_named_target_is_kept_as_it_was_typed():
    decisions = _decisions_module()
    for value in (TARGET, TARGET.upper(), "https://app.example.com", "app.example.com:8443",
                  "host://198.51.100.7", "https://app.example.com/path-(v2"):
        assert decisions.checked_target(f"  {value} ") == value


def test_the_agents_line_ends_with_the_persons_command_for_every_decision():
    for detail in (REFUSAL["detail"], {**REFUSAL["detail"], "submission": "scan", "target_id": TARGET}):
        line = decision.refusal_line(detail, "shakerscan targets authorize " + TARGET)
        assert line.endswith(": shakerscan targets authorize " + TARGET), line
        assert line.count("shakerscan targets authorize") == 1


class _Answers:
    """The scan command's JSON reads, scripted (unit fixture): what the gateway says of itself,
    the target it registers for the URL and that target's standing authorization."""

    def __init__(self, *, proof=True, authorization=None, fail=None):
        self.proof, self.authorization, self.fail = proof, authorization, fail
        self.asked = []

    def __call__(self, url, **kwargs):
        path = urllib.parse.urlsplit(url).path
        self.asked.append((path, kwargs.get("payload")))
        if self.fail == path:
            raise scan_cli.ScanCliError("unreachable")
        if path == "/_enterprise/me":
            return {"person_decision_proof": self.proof}
        if path == "/targets":
            return {"id": TARGET.upper(), "url": "https://app.example.com/"}
        if path == f"/targets/{TARGET}/authorization":
            return {"target_id": TARGET, "authorization": self.authorization}
        raise AssertionError(path)


@pytest.mark.parametrize(("answers", "asked"), [
    (_Answers(), False),
    (_Answers(authorization={"standing": True, "approved_by": "alice"}), True),
    (_Answers(proof=False), True),
    (_Answers(fail="/targets"), True),
    (_Answers(fail=f"/targets/{TARGET}/authorization"), True),
])
def test_the_local_question_stays_for_a_target_no_touch_will_confirm(monkeypatch, capsys, answers, asked):
    """With the switch on the local "Type 'yes'" was dropped for every active scan, also of a
    target already authorized, which then runs with no touch: the person's own accidental
    `scan --active-testing` ran with no confirmation at all. The question is dropped only when the
    target the engine registers for the URL holds no standing authorization, so the gateway asks
    for the touch."""
    monkeypatch.setattr(scan_cli, "_bearer_token", lambda: "token-1")
    monkeypatch.setattr(scan_cli, "_request_json", answers)
    monkeypatch.setattr(sys, "stdin", types.SimpleNamespace(isatty=lambda: True))
    questions = []
    monkeypatch.setattr("builtins.input", lambda prompt="": questions.append(prompt) or "yes")
    args = types.SimpleNamespace(active_testing=True, confirm_active=False, target="https://app.example.com",
                                 api_url=ORIGIN, credential_profile=[], approval_receipt=None)
    scan_cli._confirm_active(args)
    assert bool(questions) is asked, (questions, answers.asked)
    if not asked:
        assert "is not authorized yet: you confirm it with a touch of your security key" in capsys.readouterr().err
        assert ("/targets", {"url": "https://app.example.com"}) in answers.asked


def test_a_scan_with_its_own_credential_or_receipt_keeps_the_local_question(monkeypatch):
    """The gateway asks a touch only for active work without a credential or receipt of its own."""
    answers = _Answers()
    monkeypatch.setattr(scan_cli, "_bearer_token", lambda: "token-1")
    monkeypatch.setattr(scan_cli, "_request_json", answers)
    monkeypatch.setattr(sys, "stdin", types.SimpleNamespace(isatty=lambda: True))
    questions = []
    monkeypatch.setattr("builtins.input", lambda prompt="": questions.append(prompt) or "yes")
    for changes in ({"credential_profile": ["p-1"]}, {"approval_receipt": "r-1"}):
        args = types.SimpleNamespace(active_testing=True, confirm_active=False, target="https://app.example.com",
                                     api_url=ORIGIN, credential_profile=[], approval_receipt=None)
        vars(args).update(changes)
        scan_cli._confirm_active(args)
    assert len(questions) == 2 and answers.asked == []


def test_the_budget_reason_help_says_what_a_touch_records_instead():
    import contextlib

    decisions = _decisions_module()
    out = io.StringIO()
    with contextlib.redirect_stdout(out), pytest.raises(SystemExit):
        decisions.hunt_budget_raise(["--help"], ORIGIN)
    assert "the gateway records 'Raised by <you> (terminal security-key touch)'" in " ".join(out.getvalue().split())
