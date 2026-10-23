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

    def __call__(self, webauthn, origin, terminal, *, prompt=""):
        self.asked.append({"webauthn": dict(webauthn), "origin": origin})
        return {"id": "Y3JlZA", "rawId": "Y3JlZA", "type": "public-key", "response": {}}


@pytest.fixture
def gateway(monkeypatch):
    found = ScriptedGateway()
    monkeypatch.setattr(v2_cli, "_opener", lambda: found)
    monkeypatch.setattr(api_cli, "_opener", lambda: found)
    monkeypatch.setattr(scan_cli, "_opener", lambda: found)
    monkeypatch.setattr(decision, "json_poster", lambda *a, **k: found.post)
    monkeypatch.delenv("SHAKERSCAN_AGENT_NAME", raising=False)
    return found


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
    (True, False, "", False),  # output captured by a tool
    (True, True, "claude", False),  # inside `shakerscan agent`
])
def test_only_a_person_at_a_terminal_is_asked(stdin, stdout, agent, expected):
    streams = [types.SimpleNamespace(isatty=lambda value=value: value) for value in (stdin, stdout)]
    assert decision.interactive(*streams, {"SHAKERSCAN_AGENT_NAME": agent}) is expected


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


def test_the_watch_asks_a_touch_per_decision_when_no_session_opens(monkeypatch):
    from tests.test_hunt_approve import ORIGIN as SCRIPTED_ORIGIN
    from tests.test_hunt_approve import Gateway, Terminal, _request

    gateway = Gateway(_request(), _request(id="cccccccc-cccc-4ccc-8ccc-cccccccccccc", title="Second"),
                      methods=("security_key",))
    original = gateway.__call__
    proofs = []

    def touch_only(method, path, payload=None, headers=None, *, timeout=None):
        if path == approval.BEGIN_PATH and payload["purpose"] == "approver_session":
            return 403, {"schema_version": "shakerscan-approval-error/v1", "error": "touch_required",
                         "message": "each decision is one touch"}
        if path == approval.FINISH_PATH:
            proofs.append(payload["proof"])
        return original(method, path, payload, headers, timeout=timeout)

    monkeypatch.setattr(approval.StepUp, "prove", lambda self, challenge: {"method": "security_key", "credential": {}})
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
    assert json.loads(refused["data"]) == {"approved_by": "shakerscan targets authorize", "risk_tier": "active"}
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
    assert "person_decision_required" in err and "shakerscan hunt budget raise" in err
    with pytest.raises(SystemExit):
        decisions.hunt_budget_raise([HUNT], ORIGIN)  # --limit is required
    assert decisions.hunt_budget_raise([HUNT, "--limit", "max_hosts=5"], ORIGIN) == 2
    assert "no budget limit max_hosts" in capsys.readouterr().err
