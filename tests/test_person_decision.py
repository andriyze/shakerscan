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


@pytest.mark.parametrize(("stdin", "stdout", "stderr", "agent", "expected"), [
    (True, True, True, "", True),
    (False, True, True, "", False),  # `yes | shakerscan ...`: a pipe is never the person
    (True, False, False, "", False),  # output and errors captured by a tool
    (True, False, True, "", True),  # `shakerscan scan ... --json | jq` in the person's terminal
    (True, True, True, "claude", False),  # inside `shakerscan agent`, even in its own terminal
])
def test_only_a_person_at_a_terminal_is_asked(stdin, stdout, stderr, agent, expected):
    streams = [types.SimpleNamespace(isatty=lambda value=value: value) for value in (stdin, stdout, stderr)]
    assert decision.interactive(streams[0], streams[1], {"SHAKERSCAN_AGENT_NAME": agent}, streams[2]) is expected


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
    assert approval.preferred_method(["totp", "security_key"]) == "security_key"
    assert approval.preferred_method(["totp"]) == "totp"
    monkeypatch.setattr(approval, "security_keys_present", lambda: False)
    assert approval.preferred_method(["totp", "security_key"]) == "totp"
    assert approval.preferred_method(["security_key", "sso"]) == "security_key"
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
    created, refused, resent = gateway.sent
    assert json.loads(created["data"]) == {"url": "https://app.example.com"}
    sent = json.loads(refused["data"])
    assert sent["risk_tier"] == "active" and sent["approved_by"].endswith(" via shakerscan targets authorize")
    assert resent["headers"]["x-shakerscan-person-proof"] == "apv_grant_1" and len(signer.asked) == 1
    assert "for active testing, recorded as Alice via terminal security-key touch" in sys.stdout.getvalue()


def test_hunt_budget_raise_reads_the_budget_and_sends_totals(gateway, monkeypatch, capsys):
    decisions = _client_module(monkeypatch, gateway)
    monkeypatch.setenv("SHAKERSCAN_API_TOKEN", "token-1")
    at_a_terminal(monkeypatch, stdin=False)
    code = decisions.hunt_budget_raise([HUNT, "--limit", "max_state_changing_requests=+20",
                                        "--limit", "max_http_requests=600"], ORIGIN)
    assert code == 3, "an agent's shell gets the person's command, never a prompt"
    read, refused = gateway.sent
    body = json.loads(refused["data"])
    assert body["limits"] == {"max_state_changing_requests": 40, "max_http_requests": 600}
    assert body["expected_revision"] == 2 and body["operator_confirmed"] is True
    err = capsys.readouterr().err
    # One line, not the CLI's error JSON.
    assert err.startswith("shakerscan: person decision required: ") and err.count("\n") == 1, err
    assert "shakerscan hunt budget raise" in err and "{" not in err
    with pytest.raises(SystemExit):
        decisions.hunt_budget_raise([HUNT], ORIGIN)  # --limit is required
    assert decisions.hunt_budget_raise([HUNT, "--limit", "max_hosts=5"], ORIGIN) == 2
    assert "no budget limit max_hosts" in capsys.readouterr().err


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
    monkeypatch.setattr(scan_cli, "_touch_confirms", lambda url: True)
    monkeypatch.setattr(sys, "stdin", types.SimpleNamespace(isatty=lambda: True))
    monkeypatch.setattr("builtins.input", lambda prompt="": pytest.fail("asked twice"))
    args = types.SimpleNamespace(active_testing=True, confirm_active=False, target="https://a.example.com",
                                 api_url=ORIGIN)
    scan_cli._confirm_active(args)
    assert "touch of your security key" in capsys.readouterr().err
    monkeypatch.setattr(scan_cli, "_touch_confirms", lambda url: False)
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

    modules = {
        "fido2": types.ModuleType("fido2"),
        "fido2.ctap": types.SimpleNamespace(CtapError=FakeCtapError),
        "fido2.ctap2": types.SimpleNamespace(Ctap2=Ctap2),
        "fido2.hid": types.SimpleNamespace(CtapHidDevice=types.SimpleNamespace(list_devices=lambda: iter(keys))),
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
    unrelated = key("YubiKey 5", holds=[b"other"])
    fake_fido2(monkeypatch, [unrelated])
    assert approval.preferred_method(["totp", "security_key"], WEBAUTHN) == "totp"
    assert unrelated.probed == 1
    fake_fido2(monkeypatch, [unrelated, key("YubiKey 5C", holds=[b"mine"])])
    assert approval.preferred_method(["totp", "security_key"], WEBAUTHN) == "security_key"
    fake_fido2(monkeypatch, [key("no PIN", holds=[b"mine"], pin=False)])
    assert approval.preferred_method(["totp", "security_key"], WEBAUTHN) == "totp"
    assert approval.preferred_method(["totp", "security_key"], {**WEBAUTHN, "userVerification": "discouraged"}) == (
        "security_key")
    # Under the switch the key is the only method: it is asked, and says plainly why not.
    assert approval.preferred_method(["security_key"], WEBAUTHN) == "security_key"
    devices, why = approval.eligible_devices([unrelated], WEBAUTHN)
    assert devices == [] and "not registered to your account" in why
    devices, why = approval.eligible_devices([key("no PIN", holds=[b"mine"], pin=False)], WEBAUTHN)
    assert devices == [] and "has no PIN" in why


def test_only_the_keys_that_can_answer_are_offered_before_the_touch(monkeypatch):
    mine, spare = key("YubiKey", holds=[b"mine"]), key("YubiKey", holds=[b"other"])
    fake_fido2(monkeypatch, [spare, mine])
    devices, _ = approval.eligible_devices([spare, mine], WEBAUTHN)
    assert devices == [mine], "the chooser never lists a key that cannot answer"


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
    # An older gateway needs the name: asked once, as before.
    old[0], sent[:] = True, []

    class Asks(approval.Terminal):
        def line(self, prompt):
            return "alice"

    stepup = approval.StepUp(send, ORIGIN, Asks(io.StringIO(), io.StringIO()))
    stepup.begin("permission_decision", body)
    assert [item["account"] for item in sent] == ["", "alice"] and stepup.account == "alice"
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
    monkeypatch.setattr(decisions, "helper", lambda name: approval)
    asked = []

    def me(answer):
        return types.SimpleNamespace(request_json=lambda method, path: asked.append(path) or answer)

    assert decisions.touch_lines(me({"person_decision_proof": True})) == [
        "touch:    required for person decisions from terminals", "key:      no USB security key found; insert it"]
    off = me({"person_decision_proof": False})
    assert decisions.touch_lines(off)[0] == "touch:    not required (the administrator's switch is off)"
    older = me({"user": {"auth": "token"}})
    assert decisions.touch_lines(older)[0] == "touch:    not offered by this gateway (an older Enterprise gateway)"
    # Only the gateway's description of itself is read: an older gateway's feed route would be
    # refused and audited on every doctor run.
    assert set(asked) == {approval.ME_PATH}
    gone = types.SimpleNamespace(request_json=lambda method, path: (_ for _ in ()).throw(OSError("404")))
    assert decisions.touch_lines(gone)[0] == "touch:    unknown (this instance does not say)"


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
    assert line.endswith("then send it once, with the same Idempotency-Key")
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
    assert decisions.cmd_targets(args) == 3
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
        assert decision.person_command(method, path, raw, unnamed).startswith("shakerscan targets authorize <")
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


def test_an_unplugged_key_is_waited_for_then_the_touch_goes_on():
    """With the key on a keyring every one-shot command exited ('insert it and
    run the command again') and the person began again."""
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
        "done; decided by alice (security-key touch)",
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
