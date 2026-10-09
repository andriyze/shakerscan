"""The terminal approval protocol (scripts/hunt_approve.py) and the product CLI that carries it.

Unit fixtures throughout: ``send`` is a scripted instance and the terminal is a labelled double
(the pseudo-terminal process tests are in test_hunt_terminal_approval.py). Covered here: the set
digest and the security-key challenge binding, the opt-in approver session (in memory only,
revoked at the end), the security-key path through a CTAP2 test double, ``--all-pending`` with one
step-up, ``hunt permissions list|show|wait`` (L1: the wait's pacing, also counted against the HTTP
stub of tests/hunt_permission_stub.py, a unit fixture), ``hunt start --allow``, the ``hunt call``
text for a parked action, and the redirect explanation (D17).
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import sys
import threading
import time
import types
import urllib.error
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import hunt_approve as approval  # noqa: E402
import v2_cli  # noqa: E402

from tests.hunt_permission_stub import DIGEST, HUNT, REQUEST, TITLE, TOTP, approval_set_digest  # noqa: E402

ORIGIN = "https://scanner.example.com"


def _request(**extra):
    return {"id": REQUEST, "hunt_id": HUNT, "kind": "budget.raise", "reason_code": "budget_exhausted",
            "status": "pending", "subject_digest": DIGEST, "title": TITLE, "explanation": "why",
            "effect": "what", "scopes": ["hunt"], "remember_supported": False, **extra}


class Terminal(approval.Terminal):
    """A labelled double for the person's terminal: scripted answers and keys."""

    def __init__(self, *answers, keys=()):
        super().__init__(io.StringIO(), io.StringIO())
        self.answers = list(answers)
        self.keys = list(keys)

    def require(self, what):
        return None

    def line(self, prompt):
        self.stdout.write(prompt)
        return self.answers.pop(0)

    def secret(self, prompt):
        self.stdout.write(prompt)
        return self.answers.pop(0)

    def key(self, prompt, choices, **_waiting):
        self.stdout.write(prompt)
        if not self.keys:
            raise KeyboardInterrupt
        return self.keys.pop(0)

    @property
    def text(self):
        return self.stdout.getvalue()


class Gateway:
    """A scripted G1 gateway plus the engine reads (unit fixture)."""

    def __init__(self, *requests, methods=("totp",)):
        self.requests = {item["id"]: dict(item) for item in requests}
        self.methods = list(methods)
        self.sent = []
        self.begun = {}
        self.sessions = {}
        self.timeouts = {}

    def __call__(self, method, path, payload=None, headers=None, *, timeout=None):
        self.sent.append((method, path, payload))
        self.timeouts[path] = timeout
        if path.startswith(f"/hunts/{HUNT}/permission-requests?status=pending"):
            return 200, {"requests": [item for item in self.requests.values() if item["status"] == "pending"]}
        if path.startswith("/hunts?status="):
            return 200, {"hunts": [{"hunt_id": HUNT}] if "active" in path else []}
        if path == approval.BEGIN_PATH:
            approval_id = f"apv_{len(self.begun)}"
            self.begun[approval_id] = payload
            return 200, {"schema_version": "shakerscan-approval-challenge/v1", "approval_id": approval_id,
                         "set_digest": approval_set_digest(payload, ORIGIN), "methods": self.methods}
        if path == approval.FINISH_PATH:
            begun = self.begun.pop(payload["approval_id"])
            proof = payload["proof"]
            via = "approver_session" if proof["method"] == "approver_session" else "terminal_stepup"
            if proof["method"] == "approver_session" and self.sessions.get(proof["session_id"]) != proof["session_secret"]:
                return 403, {"schema_version": "shakerscan-approval-error/v1", "error": "session_invalid"}
            if begun["purpose"] == "approver_session":
                self.sessions["ses_1"] = "the-session-secret"
                return 200, {"schema_version": "shakerscan-approval-result/v1", "decided_by": "alice",
                             "session": {"session_id": "ses_1", "session_secret": "the-session-secret",
                                         "expires_at": "soon"}}
            results = []
            for item in begun["decisions"]:
                self.requests[item["request_id"]]["status"] = "granted" if item["decision"] == "allow" else "denied"
                results.append({"hunt_id": HUNT, "request_id": item["request_id"], "http_status": 200,
                                "request": self.requests[item["request_id"]]})
            return 200, {"schema_version": "shakerscan-approval-result/v1", "decided_by": "alice",
                         "decision_via": via, "results": results}
        if path == approval.SESSION_REVOKE_PATH:
            return 200, {"schema_version": "shakerscan-approval-session/v1", "revoked": True}
        raise AssertionError(f"unexpected {method} {path}")


def test_the_set_digest_is_canonical_and_binds_the_instance_and_the_person():
    entry = approval.decision_entry(_request(), "allow")
    other = approval.decision_entry(_request(id="eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"), "deny")
    one = approval.set_document("permission_decision", "alice", ORIGIN, {"decisions": [entry, other]})
    two = approval.set_document("permission_decision", "alice", ORIGIN + "/", {"decisions": [other, entry]})
    assert approval.set_digest(one) == approval.set_digest(two), "order and a trailing slash do not matter"
    assert approval.set_digest(one) == approval_set_digest(
        {"purpose": "permission_decision", "account": "alice", "decisions": [entry, other]}, ORIGIN,
    ), "the client and the gateway compute the same digest from the protocol text"
    for changed in (
        approval.set_document("permission_decision", "mallory", ORIGIN, {"decisions": [entry, other]}),
        approval.set_document("permission_decision", "alice", "https://other.example.com", {"decisions": [entry, other]}),
        approval.set_document("permission_decision", "alice", ORIGIN, {"decisions": [entry]}),
    ):
        assert approval.set_digest(changed) != approval.set_digest(one)
    nonce = base64.urlsafe_b64encode(b"n" * 32).rstrip(b"=").decode()
    expected = hashlib.sha256(b"n" * 32 + bytes.fromhex(approval.set_digest(one))).digest()
    assert approval.expected_challenge(nonce, approval.set_digest(one)) == base64.urlsafe_b64encode(expected).rstrip(b"=").decode()


def test_all_pending_is_one_step_up_for_every_request():
    second = _request(id="eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", title="Authorize api.example.com:8443 for this Hunt")
    gateway = Gateway(_request(), second)
    terminal = Terminal(TOTP)
    args = types.SimpleNamespace(watch=False, all_pending=True, request_id=None, hunt=None, account="alice",
                                 method=None, remember=False, total=None, minutes=30)
    assert approval.run("approve", args, gateway, enterprise=True, origin=ORIGIN, terminal=terminal) == 0
    assert [path for _, path, _ in gateway.sent].count(approval.FINISH_PATH) == 1
    assert {item["status"] for item in gateway.requests.values()} == {"granted"}
    assert TITLE in terminal.text and "Authorize api.example.com:8443" in terminal.text


def test_a_challenge_that_does_not_match_the_set_approves_nothing():
    gateway = Gateway(_request())
    original = gateway.__call__

    def tampered(method, path, payload=None, headers=None):
        status, body = original(method, path, payload, headers)
        if path == approval.BEGIN_PATH:
            body = {**body, "set_digest": "0" * 64}
        return status, body

    with pytest.raises(approval.ApprovalError, match="does not match what you are approving"):
        approval.decide(tampered, Terminal(TOTP), [_request()], "allow", enterprise=True, origin=ORIGIN, account="alice")
    assert approval.FINISH_PATH not in [path for _, path, _ in gateway.sent]


def _ctrl_c(seconds):
    """The person ends --watch with Ctrl-C after the first poll."""
    raise KeyboardInterrupt


def test_the_approver_session_lives_in_memory_only_and_is_revoked(tmp_path, monkeypatch):
    monkeypatch.setenv("SHAKERSCAN_CONFIG_DIR", str(tmp_path / "cfg"))
    gateway = Gateway(_request())
    terminal = Terminal(TOTP, keys=["a"])
    before = dict(os.environ)
    assert approval.watch(gateway, terminal, enterprise=True, origin=ORIGIN, hunt_id=HUNT, account="alice",
                          sleep=_ctrl_c) == 0
    finishes = [payload for _, path, payload in gateway.sent if path == approval.FINISH_PATH]
    assert finishes[0]["proof"] == {"method": "totp", "code": TOTP}
    assert finishes[1]["proof"]["method"] == "approver_session", "the keypress decided through the session"
    assert gateway.requests[REQUEST]["status"] == "granted"
    assert gateway.sent[-1][1] == approval.SESSION_REVOKE_PATH, "the session ends at the gateway too"
    assert gateway.timeouts[approval.SESSION_REVOKE_PATH] == approval.REVOKE_TIMEOUT_SECONDS
    assert "could not revoke" not in terminal.text
    assert dict(os.environ) == before, "nothing went into the environment"
    assert not any("the-session-secret" in path.read_text(errors="ignore")
                   for path in tmp_path.rglob("*") if path.is_file()), "nothing went to disk"
    assert "the-session-secret" not in terminal.text
    held = approval._HeldSecret("value")
    assert "value" not in repr(held)
    held.wipe()
    assert held() == ""


@pytest.mark.parametrize("failure", [approval.ApprovalError("the ShakerScan API did not answer in time"),
                                     KeyboardInterrupt(), (503, {"detail": "unavailable"})])
def test_a_revoke_that_fails_or_is_interrupted_still_ends_watch_and_wipes_the_secret(failure, monkeypatch):
    gateway = Gateway(_request())
    original = gateway.__call__
    wiped = []
    monkeypatch.setattr(approval._HeldSecret, "wipe", lambda self: wiped.append(True))

    def revoke_fails(method, path, payload=None, headers=None, *, timeout=None):
        if path == approval.SESSION_REVOKE_PATH:
            gateway.sent.append((method, path, payload))
            if isinstance(failure, tuple):
                return failure
            raise failure  # no answer in time, or a second Ctrl-C while waiting for one
        return original(method, path, payload, headers, timeout=timeout)

    terminal = Terminal(TOTP, keys=[])
    assert approval.watch(revoke_fails, terminal, enterprise=True, origin=ORIGIN, hunt_id=HUNT, account="alice",
                          sleep=_ctrl_c) == 0
    assert gateway.sent[-1][1] == approval.SESSION_REVOKE_PATH
    assert "could not revoke the approver session at the gateway; it expires on its own" in terminal.text
    assert wiped == [True]


def test_a_local_watch_decides_on_the_keypress():
    sent = []
    pending = [_request()]

    def engine(method, path, payload=None, headers=None):
        sent.append((method, path, payload))
        if path.endswith("/decision"):
            pending.clear()
            return 200, {"request": {**_request(), "status": "denied"}}
        return 200, {"requests": list(pending)}

    terminal = Terminal(keys=["d"])
    assert approval.watch(engine, terminal, enterprise=False, origin="http://127.0.0.1:8080", hunt_id=HUNT,
                          sleep=_ctrl_c) == 0
    decision = next(payload for _, path, payload in sent if path.endswith("/decision"))
    assert decision["decision"] == "deny" and decision["decision_via"] == "local_confirm"
    assert "[y/N]" not in terminal.text, "the keypress was the confirmation"


def _fake_fido2(monkeypatch, *, device=True):
    """A CTAP2 test authenticator standing in for python-fido2 and a USB key (labelled double)."""
    seen = {}

    class Descriptor:
        def __init__(self, type, id):
            self.id = id

    class Options:
        def __init__(self, **kwargs):
            seen["options"] = kwargs

    class Response:
        raw_id = b"credential-id-1"
        response = types.SimpleNamespace(client_data=b'{"type":"webauthn.get"}', authenticator_data=b"auth-data",
                                         signature=b"signature", user_handle=b"user-1")

    class Client:
        def __init__(self, device, origin=None, user_interaction=None, **kwargs):
            seen["origin"] = origin or kwargs["client_data_collector"].origin
            user_interaction.prompt_up()

        def get_assertion(self, options):
            return types.SimpleNamespace(get_response=lambda index: Response())

    client = types.ModuleType("fido2.client")
    client.Fido2Client = Client
    client.UserInteraction = object
    hid = types.ModuleType("fido2.hid")
    hid.CtapHidDevice = types.SimpleNamespace(list_devices=lambda: iter([object()] if device else []))
    webauthn = types.ModuleType("fido2.webauthn")
    webauthn.PublicKeyCredentialDescriptor = Descriptor
    webauthn.PublicKeyCredentialRequestOptions = Options
    webauthn.PublicKeyCredentialType = types.SimpleNamespace(PUBLIC_KEY="public-key")
    webauthn.UserVerificationRequirement = types.SimpleNamespace(REQUIRED="required")
    for name, module in {"fido2": types.ModuleType("fido2"), "fido2.client": client, "fido2.hid": hid,
                         "fido2.webauthn": webauthn}.items():
        monkeypatch.setitem(sys.modules, name, module)
    return seen


def test_a_security_key_signs_a_challenge_bound_to_the_set(monkeypatch):
    seen = _fake_fido2(monkeypatch)
    gateway = Gateway(_request(), methods=("security_key",))
    nonce = base64.urlsafe_b64encode(b"x" * 32).rstrip(b"=").decode()
    original = gateway.__call__

    def with_key(method, path, payload=None, headers=None):
        status, body = original(method, path, payload, headers)
        if path == approval.BEGIN_PATH:
            body = {**body, "nonce": nonce, "webauthn": {
                "challenge": approval.expected_challenge(nonce, body["set_digest"]), "rpId": "scanner.example.com",
                "allowCredentials": [{"type": "public-key", "id": "Y3JlZA"}], "userVerification": "required",
            }}
        return status, body

    terminal = Terminal()
    assert approval.decide(with_key, terminal, [_request()], "allow", enterprise=True, origin=ORIGIN,
                           account="alice", method="security_key") == 0
    proof = next(payload for _, path, payload in gateway.sent if path == approval.FINISH_PATH)["proof"]
    assert proof["method"] == "security_key"
    credential = proof["credential"]
    assert credential["type"] == "public-key" and credential["rawId"] == credential["id"]
    assert set(credential["response"]) == {"clientDataJSON", "authenticatorData", "signature", "userHandle"}
    assert seen["origin"] == ORIGIN and seen["options"]["rp_id"] == "scanner.example.com"
    assert "Touch your security key." in terminal.text


def test_a_security_key_needs_the_library_and_a_bound_challenge(monkeypatch):
    monkeypatch.setitem(sys.modules, "fido2", None)
    with pytest.raises(approval.ApprovalError, match="pipx inject shakerscan fido2"):
        approval.security_key_assertion({"challenge": "AA"}, ORIGIN, Terminal())
    stepup = approval.StepUp(lambda *a, **k: None, ORIGIN, Terminal(), account="alice", method="security_key")
    with pytest.raises(approval.ApprovalError, match="not bound to this approval"):
        stepup.prove({"methods": ["security_key"], "set_digest": DIGEST, "nonce": "AA",
                      "webauthn": {"challenge": "not-the-binding"}})


# --- the product CLI ---------------------------------------------------------------------------


class Client(v2_cli.ApiClient):
    """A scripted engine behind the product CLI's own client (unit fixture)."""

    def __init__(self, answers, token=None):
        super().__init__("https://scanner.example.com" if token else "http://127.0.0.1:8080", api_token=token)
        self.answers = answers
        self.sent = []

    def request(self, method, path, *, payload=None, idempotency_key=None, headers=None):
        self.sent.append((method, path, payload, dict(headers or {})))
        answer = self.answers[(method, path.split("?")[0])]
        if isinstance(answer, v2_cli.CliError):
            raise answer
        return answer(payload) if callable(answer) else answer


def _parse(*argv):
    return v2_cli.build_parser().parse_args(["--api-url", "http://127.0.0.1:8080", *argv])


def test_hunt_permissions_list_show_and_wait_print_the_servers_text():
    base = f"/hunts/{HUNT}/permission-requests"
    client = Client({
        ("GET", "/hunts"): {"hunts": [{"hunt_id": HUNT}]},
        ("GET", base): {"requests": [_request()]},
        ("GET", f"{base}/{REQUEST}"): _request(status="granted"),
    })
    listed = v2_cli._run_hunt(_parse("hunt", "permissions", "list"), client)
    assert listed["requests"][0]["title"] == TITLE and listed["requests"][0]["hunt_id"] == HUNT
    shown = v2_cli._run_hunt(_parse("hunt", "permissions", "show", REQUEST, "--hunt", HUNT), client)
    assert shown["explanation"] == "why"
    waited = v2_cli._run_hunt(_parse("hunt", "permissions", "wait", REQUEST, "--hunt", HUNT, "--seconds", "1"), client)
    assert waited["outcome"] == "granted" and "same idempotency key" in waited["next"]


def test_hunt_start_allow_on_an_open_source_engine_is_sent_as_the_operators(monkeypatch):
    monkeypatch.delenv("SHAKERSCAN_HUNT_ALLOW", raising=False)
    contract = {"schema_version": "hunt-start/v2", "target_kinds": ["web"], "budget_profiles": {"balanced": {}},
                "budget_dimensions": []}
    client = Client({("GET", "/hunts/contract"): contract, ("POST", "/hunts"): lambda payload: {"hunt_id": HUNT}})
    args = _parse("hunt", "start", "--target-id", "t-1", "--target-kind", "web", "--allow", "budget.raise:2x",
                  "--allow", "capability:state-changing", "--propose-allow", "target.authorize:api.example.com")
    v2_cli._run_hunt(args, client)
    _method, _path, payload, headers = client.sent[-1]
    assert payload["allow"] == ["budget.raise:2x", "capability:state-changing"]
    assert payload["proposed_allow"] == ["target.authorize:api.example.com"]
    assert headers == {}


def test_hunt_start_allow_on_enterprise_needs_the_persons_step_up_first(monkeypatch):
    monkeypatch.delenv("SHAKERSCAN_HUNT_ALLOW", raising=False)
    monkeypatch.delenv("SHAKERSCAN_PREAUTHORIZATION_ID", raising=False)
    contract = {"schema_version": "hunt-start/v2", "target_kinds": ["web"], "budget_profiles": {"balanced": {}},
                "budget_dimensions": []}
    closed = v2_cli.CliError("Operators cannot use POST /_enterprise/approvals/begin", error_type="api_error",
                             http_status=403, api_detail="Operators cannot use POST /_enterprise/approvals/begin")
    client = Client({("GET", "/hunts/contract"): contract, ("POST", "/_enterprise/approvals/begin"): closed,
                     ("POST", "/hunts"): lambda payload: {"hunt_id": HUNT}}, token="token-1")
    monkeypatch.setattr(v2_cli.sys, "stdin", types.SimpleNamespace(isatty=lambda: True, readline=lambda: "alice\n"))
    args = _parse("hunt", "start", "--target-id", "t-1", "--target-kind", "web", "--allow", "budget.raise:2x")
    with pytest.raises(v2_cli.CliError) as refused:
        v2_cli._run_hunt(args, client)
    assert refused.value.error_type == "preauthorization_required"
    assert "has no terminal approval yet" in str(refused.value) and "No Hunt was started" in str(refused.value)
    assert ("POST", "/hunts") not in [(m, p) for m, p, *_ in client.sent]
    # Naming a pre-authorization from an earlier step-up sends it with the bounds.
    args = _parse("hunt", "start", "--target-id", "t-1", "--target-kind", "web", "--allow", "budget.raise:2x",
                  "--preauthorization", "pre_0042")
    v2_cli._run_hunt(args, client)
    assert client.sent[-1][3] == {"X-ShakerScan-Preauthorization": "pre_0042"}


def test_hunt_start_inherits_the_launch_bounds_of_shakerscan_agent(monkeypatch):
    monkeypatch.setenv("SHAKERSCAN_HUNT_ALLOW", json.dumps(["budget.raise:2x"]))
    monkeypatch.setenv("SHAKERSCAN_PREAUTHORIZATION_ID", "pre_0042")
    contract = {"schema_version": "hunt-start/v2", "target_kinds": ["web"], "budget_profiles": {"balanced": {}},
                "budget_dimensions": []}
    client = Client({("GET", "/hunts/contract"): contract, ("POST", "/hunts"): lambda payload: {"hunt_id": HUNT}},
                    token="token-1")
    v2_cli._run_hunt(_parse("hunt", "start", "--target-id", "t-1", "--target-kind", "web"), client)
    _method, _path, payload, headers = client.sent[-1]
    assert payload["allow"] == ["budget.raise:2x"] and headers == {"X-ShakerScan-Preauthorization": "pre_0042"}


def test_hunt_call_names_the_request_and_the_command_for_a_parked_action():
    parked = v2_cli.CliError("permission required", error_type="api_error", http_status=409, api_detail={
        "code": "permission_required", "action_id": "a-1",
        "permission_request": {"id": REQUEST, "kind": "budget.raise", "title": TITLE},
    })
    client = Client({("GET", f"/hunts/{HUNT}"): {"capabilities": [{"name": "web.crawl"}]},
                     ("POST", f"/hunts/{HUNT}/capabilities/web.crawl"): parked})
    with pytest.raises(v2_cli.CliError) as waiting:
        v2_cli._run_hunt(_parse("hunt", "call", HUNT, "web.crawl", "--idempotency-key", "key-crawl-1"), client)
    assert waiting.value.error_type == "awaiting_permission"
    message = str(waiting.value)
    assert f"`shakerscan approve {REQUEST}`" in message and "--idempotency-key key-crawl-1" in message
    assert f"shakerscan hunt permissions wait {REQUEST}" in message


def test_cli_redirect_errors_name_the_https_origin_and_the_url_option():
    """D17: the CLI named --api-url (an internal flag) and gave no hint."""
    import api_cli

    class Redirecting:
        def open(self, request, timeout=None):
            raise urllib.error.HTTPError(request.full_url, 308, "redirect",
                                         {"Location": "https://scanner.example.com/hunts"}, io.BytesIO(b""))

    request = api_cli.build_request("GET", "/hunts", None, api_url="http://scanner.example.com", token=None)
    with pytest.raises(api_cli.ApiCliError) as refused:
        api_cli.call(request, opener=Redirecting())
    text = str(refused.value)
    assert "--api-url" not in text
    assert "served over HTTPS at https://scanner.example.com" in text and "--url https://scanner.example.com" in text
    error = urllib.error.HTTPError("http://scanner.example.com/hunts", 308, "redirect",
                                   {"Location": "https://scanner.example.com/hunts"}, io.BytesIO(b""))
    assert "--url https://scanner.example.com" in v2_cli._redirect_text(error, "http://scanner.example.com/hunts")


class _Clock:
    """A labelled fake monotonic clock: sleeping and a server's hold advance it."""

    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        assert seconds > 0, "never a zero or negative pause"
        self.now += seconds


def _waiting_engine(clock, *, holds):
    """A pending request behind a scripted engine (unit fixture). ``holds``: the engine keeps the
    long-poll open for the wait it was asked for; otherwise it answers at once (the worst case)."""
    asked = []

    def engine(method, path, payload=None, headers=None):
        assert method == "GET" and path.startswith(f"/hunts/{HUNT}/permission-requests/{REQUEST}?wait_seconds=")
        seconds = int(path.rsplit("=", 1)[1])
        asked.append(seconds)
        if holds:
            clock.now += seconds
        else:
            clock.now += 0.01
        return 200, _request()

    return engine, asked


@pytest.mark.parametrize("seconds", [8, 5, 7.63, 1, 0.4])
def test_wait_never_floods_the_engine_with_zero_second_polls(seconds):
    """L1: the time left was rounded down, so the last second sent ~80 wait_seconds=0 reads."""
    clock = _Clock()
    engine, asked = _waiting_engine(clock, holds=False)
    started = clock()
    current = approval.wait_for(engine, _request(), seconds, clock=clock, sleep=clock.sleep)
    assert current["status"] == "pending"
    assert 0 not in asked, f"a zero-second long-poll was sent: {asked}"
    assert len(asked) <= int(seconds) + 1, f"{len(asked)} reads in {seconds}s: {asked}"
    assert asked[0] == min(25, max(1, -(-seconds // 1))), "the first poll holds for the time left, rounded up"
    assert started + seconds <= clock() <= started + seconds + 0.05, "it ends at the deadline"


@pytest.mark.parametrize("seconds", [8, 7.63, 60])
def test_wait_against_an_engine_that_holds_asks_once_per_hold(seconds):
    clock = _Clock()
    engine, asked = _waiting_engine(clock, holds=True)
    approval.wait_for(engine, _request(), seconds, clock=clock, sleep=clock.sleep)
    assert asked == ([8] if seconds < 25 else [25, 25, 10])
    assert sum(asked) - seconds < 1, "at most the last second's rounding past the deadline"


def test_wait_for_no_time_reads_once():
    clock = _Clock()
    engine, asked = _waiting_engine(clock, holds=False)
    approval.wait_for(engine, _request(), 0, clock=clock, sleep=clock.sleep)
    assert asked == [0]


def test_hunt_permissions_wait_counts_its_requests_against_a_stub_engine():
    """L1 over real HTTP: the stub engine holds each long-poll for the wait it is asked for."""
    from tests.hunt_permission_stub import StubInstance

    with StubInstance() as stub:
        started = time.monotonic()
        code = v2_cli.main(["--api-url", stub.url, "hunt", "permissions", "wait", REQUEST,
                            "--hunt", HUNT, "--seconds", "2.5"])
        elapsed = time.monotonic() - started
    polls = [path for method, path, _ in stub.seen
             if method == "GET" and path.startswith(f"/hunts/{HUNT}/permission-requests/{REQUEST}?")]
    assert code == 0
    assert polls == [f"/hunts/{HUNT}/permission-requests/{REQUEST}?wait_seconds=3"], polls
    assert 2.5 <= elapsed < 6, elapsed


def test_permissions_show_with_arguments_in_the_wrong_order_prints_its_own_usage(capsys):
    """O3: the leftover argument was reported with the whole CLI's usage."""
    with pytest.raises(SystemExit) as exited:
        v2_cli.main(["--api-url", "http://127.0.0.1:8080", "hunt", "permissions", "show", HUNT, REQUEST])
    assert exited.value.code == 2
    err = capsys.readouterr().err
    assert "permissions show [-h] [--hunt HUNT] request_id" in err, err
    assert f"unrecognized arguments: {REQUEST}" in err
    assert "{hunt,approve,deny" not in err, "not the top-level usage"


def _second_request():
    return _request(id="eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", subject_digest="e" * 64,
                    title="Allow state-changing HTTP for this Hunt", created_at="2026-10-09T10:01:00Z")


class _PtyTerminal(approval.Terminal):
    """The real Terminal on a pseudo-terminal, with its output recorded (labelled double)."""

    def __init__(self):
        import pty
        self.master, slave = pty.openpty()
        self.text_out = io.StringIO()
        self.lock = threading.Lock()
        super().__init__(os.fdopen(slave, "r", closefd=True), self)

    def write(self, text):
        with self.lock:
            self.text_out.write(text)

    def flush(self):
        return None

    def require(self, what):
        return None

    @property
    def text(self):
        with self.lock:
            return self.text_out.getvalue()

    def wait_for(self, text, count=1, timeout=10.0):
        deadline = time.monotonic() + timeout
        while self.text.count(text) < count:
            assert time.monotonic() < deadline, f"never saw {text!r} x{count}: {self.text}"
            time.sleep(0.01)


def test_a_key_meant_for_a_request_that_ended_never_decides_the_next_one():
    """The switch race: request A ends elsewhere while its prompt waits and request B is shown at
    once. A key pressed for A (here: the moment B is announced) must not decide B; the switch is
    announced and B takes only a fresh key."""

    first, second = _request(), _second_request()
    state = {"first": "pending", "second": "pending", "lists": 0, "sleeps": 0}
    decisions = []

    def engine(method, path, payload=None, headers=None):
        if path.startswith(f"/hunts/{HUNT}/permission-requests?status=pending"):
            state["lists"] += 1
            return 200, {"requests": [first] if state["lists"] == 1 else
                         ([second] if state["second"] == "pending" else [])}
        if path == f"/hunts/{HUNT}/permission-requests/{first['id']}":
            state["first"] = "expired"  # it expires while its prompt waits
            return 200, {**first, "status": "expired"}
        if path.endswith("/decision"):
            decisions.append((path, payload["decision"]))
            state["second"] = "granted" if payload["decision"] == "allow" else "denied"
            return 200, {"request": {**second, "status": state["second"]}}
        raise AssertionError(path)

    def sleep(seconds):
        state["sleeps"] += 1
        if state["sleeps"] > 1:
            raise KeyboardInterrupt

    terminal = _PtyTerminal()

    def person():
        terminal.wait_for(f"now showing request {second['id']}")
        os.write(terminal.master, b"a")  # meant for the request that just ended
        terminal.wait_for("[q]uit: ", count=2)  # B's own prompt
        os.write(terminal.master, b"d")

    thread = threading.Thread(target=person, daemon=True)
    thread.start()
    assert approval.watch(engine, terminal, enterprise=False, origin="http://127.0.0.1:8080", hunt_id=HUNT,
                          poll_seconds=0.2, sleep=sleep) == 0
    thread.join(5)
    assert f"request {first['id']} ended (expired); now showing request {second['id']} (press a new key for it)" in terminal.text
    assert "(ignored keys pressed before this prompt was ready)" in terminal.text
    assert decisions == [(f"/hunts/{HUNT}/permission-requests/{second['id']}/decision", "deny")], decisions
    os.close(terminal.master)


def test_a_request_gone_with_its_hunt_ends_its_prompt():
    """A 404 while the prompt waits means the request ended with its Hunt; the prompt used to stay
    until the watch's deadline because every read error counted as still pending."""
    def engine(method, path, payload=None, headers=None):
        if "?status=pending" in path:
            return 200, {"requests": [_request()]}
        if path == f"/hunts/{HUNT}/permission-requests/{REQUEST}":
            return 404, {"detail": "Not Found"}
        raise AssertionError(path)

    class Waiting(Terminal):
        def key(self, prompt, choices, *, keep_waiting=None, **_):
            self.stdout.write(prompt)
            self.abandoned = keep_waiting is not None and not keep_waiting()
            return None if self.abandoned else "s"

    terminal = Waiting()
    assert approval.watch(engine, terminal, enterprise=False, origin="http://127.0.0.1:8080", hunt_id=HUNT,
                          sleep=_ctrl_c) == 0
    assert terminal.abandoned, "a 404 ends the prompt"
    assert f"{TITLE}: no longer there (it ended with its Hunt)" in terminal.text


def test_a_failed_read_that_is_not_a_404_keeps_the_prompt():
    def engine(method, path, payload=None, headers=None):
        if "?status=pending" in path:
            return 200, {"requests": [_request()]}
        return 503, {"detail": "unavailable"}

    class Waiting(Terminal):
        def key(self, prompt, choices, *, keep_waiting=None, **_):
            self.kept = keep_waiting()
            return "s"

    terminal = Waiting()
    approval.watch(engine, terminal, enterprise=False, origin="http://127.0.0.1:8080", hunt_id=HUNT, sleep=_ctrl_c)
    assert terminal.kept is True


def test_the_prompt_says_why_a_request_the_start_bounds_covered_is_asked_again():
    """R1: after a person revokes a grant, the start bounds stop granting what it covered; the
    prompt prints the server's reason so the person knows why they are asked again."""
    note = ("Asked again because grant g-1 (state-changing) was revoked at 2026-10-09T10:00:00+00:00 by "
            "alice@example.test. The Hunt's start bounds no longer allow this automatically (it would turn "
            "on allow_state_changing_http again); allowing it now is a new decision.")
    rendered = approval.render_request({**_request(), "auto_grant_withheld_note": note})
    assert f"    note:     {note}" in rendered.splitlines()
    assert "note:" not in approval.render_request(_request())
