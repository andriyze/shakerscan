"""Terminal approval of Hunt permission requests: ``shakerscan approve|deny`` and ``--allow``.

A Hunt action refused for a reason a person can allow waits as a permission request
(docs/hunt-permission-requests.md). This module is the person's side of it, in their own
terminal; no Hunt step needs the browser and no agent can decide.

Two instances, two proofs:

* **Enterprise** (the connection has a service token). The token alone never approves: the
  person names their account and proves it with a TOTP code typed here or a USB/NFC security
  key (CTAP2, through python-fido2 when it is installed). Every decision, pre-authorization and
  approver session goes through the gateway's step-up routes (``/_enterprise/approvals/...``,
  ``GATEWAY CONTRACT`` below); the gateway forwards decisions to the engine with ``decided_by``
  set to the person. The engine's decision route is never called from an Enterprise connection,
  and a gateway without the step-up routes gets an exact error, never a fallback.
* **Local open-source engine** (no token, no accounts). The trust boundary is the host: the
  approval is a plain ``y/N`` on this terminal, sent to the engine's decision route. Any local
  process that can reach the API could do the same; this is stated, not hidden.

Both refuse to prompt without an interactive terminal, so a command an agent runs in its own
tool shell cannot decide anything.

GATEWAY CONTRACT (G1 implements it; every response, success or refusal, carries a
``schema_version`` starting ``shakerscan-approval-``, which is how a missing route is told apart)::

    POST /_enterprise/approvals/begin     {schema_version: "shakerscan-approval-begin/v1",
        purpose, account, origin, decisions | preauthorization | session}
      -> {schema_version: "shakerscan-approval-challenge/v1", approval_id, set_digest, methods,
          expires_at, decisions?, nonce?, webauthn?}
    POST /_enterprise/approvals/finish    {schema_version: "shakerscan-approval-finish/v1",
        approval_id, set_digest, proof}
      -> {schema_version: "shakerscan-approval-result/v1", approval_id, decided_by, decision_via,
          results? | preauthorization? | session?}
    POST /_enterprise/approvals/session/revoke {schema_version:
        "shakerscan-approval-session-revoke/v1", session_id, session_secret}
      -> {schema_version: "shakerscan-approval-session/v1", session_id, revoked: true}

The digest, proof and result shapes are defined by the functions below and documented in
docs/hunt-permission-requests.md ("E3: the terminal approval protocol and the G1 contract").
"""

from __future__ import annotations

import base64
import getpass
import hashlib
import json
import os
import re
import sys
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from typing import Any

APPROVAL_SCHEMA_PREFIX = "shakerscan-approval-"
BEGIN_PATH = "/_enterprise/approvals/begin"
FINISH_PATH = "/_enterprise/approvals/finish"
SESSION_REVOKE_PATH = "/_enterprise/approvals/session/revoke"
PREAUTHORIZATION_HEADER = "X-ShakerScan-Preauthorization"
SET_SCHEMA = "shakerscan-approval-set/v1"
PURPOSES = ("permission_decision", "preauthorization", "approver_session")
PREAUTHORIZATION_USES = ("agent_launch", "hunt_start")
# Hunts that can hold a pending request. The engine withdraws requests when a Hunt ends.
OPEN_HUNT_STATUSES = ("active", "awaiting_planner", "budget_exhausted")
SESSION_SECONDS = 30 * 60
WATCH_POLL_SECONDS = 3.0
_TOTP = re.compile(r"^[0-9]{6,8}$")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


class ApprovalError(Exception):
    """A problem the person can act on; printed without a traceback."""


class StepUpUnavailable(ApprovalError):
    """The Enterprise gateway does not serve the step-up routes (it predates G1)."""


# --- transport ---------------------------------------------------------------------------------
#
# ``send(method, path, payload=None, headers=None) -> (status, body)``: ``body`` is the parsed JSON
# of a success, or the error ``detail`` of a refusal. It raises ApprovalError only when no answer
# arrived. The product CLI supplies it over its own authenticated, redirect-refusing client.

Send = Callable[..., tuple[int, Any]]


def _quote(value: str) -> str:
    import urllib.parse
    return urllib.parse.quote(str(value), safe="")


def _ok(status: int) -> bool:
    return 200 <= status < 300


def _detail_text(body: Any) -> str:
    if isinstance(body, Mapping):
        for key in ("message", "detail", "error"):
            if isinstance(body.get(key), str) and body[key].strip():
                return body[key].strip()[:400]
        return json.dumps(dict(body), sort_keys=True)[:400]
    return str(body or "no detail")[:400]


# --- reading requests --------------------------------------------------------------------------


def list_pending(send: Send, hunt_id: str | None = None) -> list[dict[str, Any]]:
    """Pending requests of one Hunt, or of every Hunt that can hold one, oldest first."""
    hunts = [hunt_id] if hunt_id else _open_hunts(send)
    pending: list[dict[str, Any]] = []
    for hunt in hunts:
        status, body = send("GET", f"/hunts/{_quote(hunt)}/permission-requests?status=pending")
        if not _ok(status):
            if hunt_id:
                raise ApprovalError(f"cannot read the permission requests of Hunt {hunt}: HTTP {status}: {_detail_text(body)}")
            continue
        for item in (body or {}).get("requests") or ():
            if isinstance(item, Mapping) and item.get("status") == "pending":
                pending.append({**item, "hunt_id": str(item.get("hunt_id") or hunt)})
    return sorted(pending, key=lambda item: (str(item.get("created_at") or ""), str(item.get("id"))))


def _open_hunts(send: Send) -> list[str]:
    found: list[str] = []
    for state in OPEN_HUNT_STATUSES:
        status, body = send("GET", f"/hunts?status={state}&limit=200")
        if not _ok(status):
            raise ApprovalError(f"cannot list Hunts: HTTP {status}: {_detail_text(body)}")
        found += [str(item.get("hunt_id")) for item in (body or {}).get("hunts") or ()
                  if isinstance(item, Mapping) and item.get("hunt_id")]
    return list(dict.fromkeys(found))


def find_request(send: Send, request_id: str, hunt_id: str | None = None) -> dict[str, Any]:
    """One request by id; without ``hunt_id`` it is looked for in every open Hunt."""
    request_id = str(request_id).strip().lower()
    if not _UUID.fullmatch(request_id):
        raise ApprovalError(f"{request_id!r} is not a permission request id (a UUID from `shakerscan approve <id>`)")
    hunts = [hunt_id] if hunt_id else _open_hunts(send)
    for hunt in hunts:
        status, body = send("GET", f"/hunts/{_quote(hunt)}/permission-requests/{_quote(request_id)}")
        if _ok(status) and isinstance(body, Mapping):
            return {**body, "hunt_id": str(body.get("hunt_id") or hunt)}
        if status != 404 and hunt_id:
            raise ApprovalError(f"cannot read permission request {request_id}: HTTP {status}: {_detail_text(body)}")
    where = f"Hunt {hunt_id}" if hunt_id else "any active Hunt"
    raise ApprovalError(f"no permission request {request_id} in {where}; it may have ended with its Hunt")


def wait_for(send: Send, request: Mapping[str, Any], seconds: float, *, step: int = 25) -> dict[str, Any]:
    """Long-poll one request until it is decided or ``seconds`` pass; return its last state."""
    deadline = time.monotonic() + max(0.0, seconds)
    path = f"/hunts/{_quote(request['hunt_id'])}/permission-requests/{_quote(request['id'])}"
    current = dict(request)
    while True:
        remaining = int(max(0, deadline - time.monotonic()))
        status, body = send("GET", f"{path}?wait_seconds={min(step, remaining)}")
        if not _ok(status):
            raise ApprovalError(f"cannot read permission request {request['id']}: HTTP {status}: {_detail_text(body)}")
        current = {**body, "hunt_id": str(body.get("hunt_id") or request["hunt_id"])}
        if current.get("status") != "pending" or time.monotonic() >= deadline - 0.5:
            return current


def render_request(request: Mapping[str, Any]) -> str:
    """The server's own words for one request; nothing here is composed by the client."""
    lines = [
        f"  {request.get('title')}",
        f"    why:      {request.get('explanation')}",
        f"    effect:   {request.get('effect')}",
        f"    request:  {request.get('id')} ({request.get('kind')}, {request.get('reason_code')}) "
        f"in Hunt {request.get('hunt_id')}",
    ]
    if request.get("expires_at"):
        lines.append(f"    expires:  {request.get('expires_at')}")
    if request.get("remember_supported"):
        lines.append("    scope:    this Hunt only, or remembered for the target (--remember)")
    return "\n".join(lines)


# --- the decision set and its digest -----------------------------------------------------------


def decision_entry(request: Mapping[str, Any], decision: str, *, remember: bool = False,
                   total: int | None = None) -> dict[str, Any]:
    if decision not in {"allow", "deny"}:
        raise ApprovalError("decision must be allow or deny")
    scopes = list(request.get("scopes") or ["hunt"])
    scope = "target" if remember and "target" in scopes and decision == "allow" else "hunt"
    choice = {"total": int(total)} if total is not None and decision == "allow" else {}
    return {
        "hunt_id": str(request["hunt_id"]), "request_id": str(request["id"]),
        "subject_digest": str(request["subject_digest"]), "decision": decision,
        "scope": scope, "choice": choice,
    }


def set_document(purpose: str, account: str, origin: str, body: Mapping[str, Any]) -> dict[str, Any]:
    """The canonical document a step-up approves. The gateway computes the same digest."""
    if purpose not in PURPOSES:
        raise ApprovalError(f"unknown approval purpose {purpose!r}")
    document: dict[str, Any] = {"schema_version": SET_SCHEMA, "purpose": purpose,
                                "account": account, "origin": origin.rstrip("/")}
    if purpose == "permission_decision":
        document["decisions"] = sorted(
            ({key: entry[key] for key in ("hunt_id", "request_id", "subject_digest", "decision", "scope", "choice")}
             for entry in body["decisions"]),
            key=lambda entry: (entry["hunt_id"], entry["request_id"]),
        )
    elif purpose == "preauthorization":
        document["preauthorization"] = {
            "allow": sorted(dict.fromkeys(str(item) for item in body["preauthorization"]["allow"])),
            "use": str(body["preauthorization"]["use"]),
        }
    else:
        document["session"] = {"ttl_seconds": int(body["session"]["ttl_seconds"])}
    return document


def set_digest(document: Mapping[str, Any]) -> str:
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


def _b64url_decode(value: str) -> bytes:
    text = str(value)
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(bytes(value)).rstrip(b"=").decode("ascii")


def expected_challenge(nonce: str, digest: str) -> str:
    """The WebAuthn challenge a security key signs: SHA-256(nonce || set digest), base64url."""
    return _b64url(hashlib.sha256(_b64url_decode(nonce) + bytes.fromhex(digest)).digest())


# --- the terminal ------------------------------------------------------------------------------


class Terminal:
    """The person's own terminal. Every prompt refuses to run without one."""

    def __init__(self, stdin: Any = None, stdout: Any = None) -> None:
        self.stdin = stdin or sys.stdin
        self.stdout = stdout or sys.stdout

    def require(self, what: str) -> None:
        try:
            interactive = self.stdin.isatty()
        except (AttributeError, ValueError):
            interactive = False
        if not interactive:
            raise ApprovalError(
                f"{what} asks the person at an interactive terminal and refuses to read a pipe: run it "
                "yourself in your own terminal, never through an agent's shell"
            )

    def say(self, text: str = "") -> None:
        self.stdout.write(text + "\n")
        self.stdout.flush()

    def line(self, prompt: str) -> str:
        self.stdout.write(prompt)
        self.stdout.flush()
        answer = self.stdin.readline()
        if not answer:
            raise ApprovalError("no answer (end of input); nothing was decided")
        return answer.strip()

    def secret(self, prompt: str) -> str:
        try:
            return getpass.getpass(prompt, stream=self.stdout).strip()
        except EOFError as exc:
            raise ApprovalError("no answer (end of input); nothing was decided") from exc

    def confirm(self, prompt: str) -> bool:
        return self.line(prompt + " [y/N] ").lower() in {"y", "yes"}

    def key(self, prompt: str, choices: str) -> str:
        """One keypress from ``choices`` (a line on terminals that cannot read a single key)."""
        self.stdout.write(prompt)
        self.stdout.flush()
        answer = ""
        try:
            import termios
            import tty
            fd = self.stdin.fileno()
            saved = termios.tcgetattr(fd)
            try:
                tty.setcbreak(fd)
                answer = os.read(fd, 1).decode("utf-8", "replace")
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, saved)
            self.stdout.write(answer + "\n")
        except (ImportError, OSError, ValueError, AttributeError):
            answer = self.stdin.readline()[:1]
        answer = answer.lower()
        return answer if answer and answer in choices else ""


# --- Enterprise step-up ------------------------------------------------------------------------


class StepUp:
    """The gateway's step-up routes (G1). Nothing here falls back to the engine."""

    def __init__(self, send: Send, origin: str, terminal: Terminal, *, account: str | None = None,
                 method: str | None = None) -> None:
        self.send = send
        self.origin = origin.rstrip("/")
        self.terminal = terminal
        self.account = (account or "").strip() or None
        self.method = method

    def _account(self) -> str:
        if not self.account:
            self.account = self.terminal.line("Your ShakerScan Enterprise sign-in name: ").strip()
        if not self.account or len(self.account) > 200:
            raise ApprovalError("an account name is needed: the person who approves proves who they are")
        return self.account

    def _post(self, path: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        status, body = self.send("POST", path, dict(payload))
        schema = str((body or {}).get("schema_version") or "") if isinstance(body, Mapping) else ""
        if not schema.startswith(APPROVAL_SCHEMA_PREFIX):
            if status == 401:
                raise ApprovalError("the instance refused this connection's token (HTTP 401): run shakerscan connect again")
            raise StepUpUnavailable(
                f"this ShakerScan Enterprise gateway has no terminal approval yet: POST {path} answered "
                f"HTTP {status} ({_detail_text(body)}). Approving from the terminal needs the gateway's "
                "step-up routes (G1). Nothing was approved, denied or pre-authorized, and the engine's "
                "decision route is never called from an Enterprise connection."
            )
        if not _ok(status):
            code = str(body.get("error") or "refused")
            raise ApprovalError(f"the gateway refused ({code}, HTTP {status}): {_detail_text(body)}")
        return dict(body)

    def begin(self, purpose: str, body: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
        account = self._account()
        document = set_document(purpose, account, self.origin, body)
        challenge = self._post(BEGIN_PATH, {
            "schema_version": "shakerscan-approval-begin/v1", "purpose": purpose,
            "account": account, "origin": self.origin,
            **{key: value for key, value in document.items() if key in {"decisions", "preauthorization", "session"}},
        })
        if challenge.get("set_digest") != set_digest(document):
            raise ApprovalError(
                "the gateway's challenge does not match what you are approving (set digest differs); "
                "nothing was approved"
            )
        if not str(challenge.get("approval_id") or ""):
            raise ApprovalError("the gateway's challenge has no approval_id; nothing was approved")
        return challenge, document

    def finish(self, challenge: Mapping[str, Any], proof: Mapping[str, Any]) -> dict[str, Any]:
        return self._post(FINISH_PATH, {
            "schema_version": "shakerscan-approval-finish/v1",
            "approval_id": challenge["approval_id"], "set_digest": challenge["set_digest"],
            "proof": dict(proof),
        })

    def prove(self, challenge: Mapping[str, Any]) -> dict[str, Any]:
        """The person's proof: a TOTP code typed here, or a security-key assertion."""
        methods = [str(item) for item in challenge.get("methods") or ()]
        method = self.method or ("totp" if "totp" in methods else "security_key" if "security_key" in methods else "")
        if method not in methods:
            raise ApprovalError(
                f"your account offers {', '.join(methods) or 'no step-up method'} for this approval, not "
                f"{method or 'any this client supports'}; enrol TOTP or a security key in the console"
            )
        if method == "totp":
            code = self.terminal.secret(f"TOTP code for {self.account} (never type it into an agent's chat): ")
            if not _TOTP.fullmatch(code):
                raise ApprovalError("a TOTP code is 6 to 8 digits; nothing was approved")
            return {"method": "totp", "code": code}
        webauthn = challenge.get("webauthn") if isinstance(challenge.get("webauthn"), Mapping) else {}
        nonce = str(challenge.get("nonce") or "")
        if not webauthn or not nonce or webauthn.get("challenge") != expected_challenge(nonce, challenge["set_digest"]):
            raise ApprovalError("the gateway's security-key challenge is not bound to this approval; nothing was approved")
        return {"method": "security_key", "credential": security_key_assertion(webauthn, self.origin, self.terminal)}


def security_key_assertion(webauthn: Mapping[str, Any], origin: str, terminal: Terminal) -> dict[str, Any]:
    """A WebAuthn assertion from a USB/NFC security key over CTAP2 (python-fido2).

    Platform authenticators (Touch ID, Windows Hello, synced passkeys) are not reachable from a
    pip-installed command, so only a roaming key is used. The key's PIN (user verification) is
    asked for here, as at sign-in."""
    try:
        from fido2.client import Fido2Client, UserInteraction
        from fido2.hid import CtapHidDevice
        from fido2.webauthn import (
            PublicKeyCredentialDescriptor, PublicKeyCredentialRequestOptions,
            PublicKeyCredentialType, UserVerificationRequirement,
        )
    except ImportError as exc:
        raise ApprovalError(
            "a security key needs python-fido2 beside the client: pipx inject shakerscan fido2 "
            "(or pip install fido2); or approve with a TOTP code (--method totp)"
        ) from exc
    device = next(iter(CtapHidDevice.list_devices()), None)
    if device is None:
        raise ApprovalError("no USB security key found; insert it (or approve with --method totp)")

    class Interaction(UserInteraction):  # type: ignore[misc,valid-type]
        def prompt_up(self) -> None:
            terminal.say("Touch your security key.")

        def request_pin(self, permissions: Any, rp_id: Any) -> str:  # noqa: ARG002
            return terminal.secret("Security key PIN: ")

        def request_uv(self, permissions: Any, rp_id: Any) -> bool:  # noqa: ARG002
            return True

    options = PublicKeyCredentialRequestOptions(
        challenge=_b64url_decode(str(webauthn["challenge"])),
        rp_id=str(webauthn.get("rpId") or ""),
        allow_credentials=[
            PublicKeyCredentialDescriptor(type=PublicKeyCredentialType.PUBLIC_KEY, id=_b64url_decode(str(item["id"])))
            for item in webauthn.get("allowCredentials") or () if isinstance(item, Mapping) and item.get("id")
        ] or None,
        user_verification=UserVerificationRequirement.REQUIRED,
        timeout=webauthn.get("timeout"),
    )
    try:  # python-fido2 2.x takes a client-data collector; 1.x takes the origin.
        from fido2.client import DefaultClientDataCollector
        client = Fido2Client(device, client_data_collector=DefaultClientDataCollector(origin),
                             user_interaction=Interaction())
    except ImportError:
        client = Fido2Client(device, origin, user_interaction=Interaction())
    try:
        response = client.get_assertion(options).get_response(0)
    except Exception as exc:  # the library raises several client/CTAP errors for the same failure
        raise ApprovalError(f"the security key did not sign the approval: {exc}") from exc
    return assertion_json(response)


def assertion_json(response: Any) -> dict[str, Any]:
    """The browser-shaped ``PublicKeyCredential`` JSON the gateway verifies, as at sign-in."""
    inner = getattr(response, "response", response)
    raw_id = getattr(response, "raw_id", None) or getattr(response, "credential_id", None)
    if raw_id is None:
        raw_id = (getattr(response, "credential", None) or {}).get("id")
    user_handle = getattr(inner, "user_handle", None)
    item = {
        "id": _b64url(raw_id), "rawId": _b64url(raw_id), "type": "public-key",
        "response": {
            "clientDataJSON": _b64url(bytes(getattr(inner, "client_data"))),
            "authenticatorData": _b64url(bytes(getattr(inner, "authenticator_data"))),
            "signature": _b64url(bytes(getattr(inner, "signature"))),
        },
    }
    if user_handle:
        item["response"]["userHandle"] = _b64url(user_handle)
    return item


def preauthorize(send: Send, origin: str, terminal: Terminal, allow: Sequence[str], *, use: str,
                 account: str | None = None, method: str | None = None) -> dict[str, Any]:
    """Step up once for start bounds; return the gateway's pre-authorization (id, allow, expiry)."""
    if use not in PREAUTHORIZATION_USES:
        raise ApprovalError(f"unknown pre-authorization use {use!r}")
    terminal.require("pre-authorizing --allow bounds")
    bounds = sorted(dict.fromkeys(str(item).strip() for item in allow if str(item).strip()))
    terminal.say("Pre-authorize these bounds (requests inside them are granted as they arise):")
    for bound in bounds:
        terminal.say(f"  --allow {bound}")
    stepup = StepUp(send, origin, terminal, account=account, method=method)
    challenge, _ = stepup.begin("preauthorization", {"preauthorization": {"allow": bounds, "use": use}})
    result = stepup.finish(challenge, stepup.prove(challenge))
    grant = result.get("preauthorization") if isinstance(result.get("preauthorization"), Mapping) else {}
    if not grant.get("id"):
        raise ApprovalError("the gateway answered without a pre-authorization id; nothing was pre-authorized")
    return dict(grant)


# --- deciding ----------------------------------------------------------------------------------


def _local_decide(send: Send, entries: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Local OSS: the engine's own decision route, as the operator at this host."""
    results = []
    for entry in entries:
        path = f"/hunts/{_quote(entry['hunt_id'])}/permission-requests/{_quote(entry['request_id'])}/decision"
        body = {
            "decision": entry["decision"], "scope": entry["scope"], "subject_digest": entry["subject_digest"],
            "choice": dict(entry["choice"]), "idempotency_key": f"local-approve-{uuid.uuid4().hex}",
            "decided_by": "local-operator", "decision_via": "local_confirm",
        }
        status, answer = send("POST", path, body)
        results.append({"hunt_id": entry["hunt_id"], "request_id": entry["request_id"], "http_status": status,
                        **({"request": answer.get("request"), "grant": answer.get("grant")} if _ok(status)
                           and isinstance(answer, Mapping) else {"error": answer})})
    return results


def _report(terminal: Terminal, requests: Mapping[str, Mapping[str, Any]], results: Sequence[Mapping[str, Any]],
            *, decided_by: str, via: str) -> int:
    failures = 0
    for result in results:
        title = (requests.get(str(result.get("request_id"))) or {}).get("title") or result.get("request_id")
        status = int(result.get("http_status") or 0)
        if _ok(status) and isinstance(result.get("request"), Mapping):
            state = result["request"].get("status")
            terminal.say(f"{state}: {title} (by {decided_by}, {via})")
        else:
            failures += 1
            terminal.say(f"not applied: {title}: HTTP {status}: {_detail_text(result.get('error'))}")
    return 1 if failures else 0


def decide(send: Send, terminal: Terminal, requests: Sequence[Mapping[str, Any]], decision: str, *,
           enterprise: bool, origin: str, remember: bool = False, total: int | None = None,
           account: str | None = None, method: str | None = None,
           session: Mapping[str, Any] | None = None, confirmed: bool = False) -> int:
    """Decide ``requests`` with one proof: one step-up (or the open approver ``session``) on
    Enterprise, one local confirmation on OSS (``confirmed``: the --watch keypress was it)."""
    if not requests:
        terminal.say("no pending permission requests")
        return 0
    entries = [decision_entry(item, decision, remember=remember, total=total) for item in requests]
    by_id = {str(item["id"]): item for item in requests}
    if remember and decision == "allow":
        for entry in entries:
            if entry["scope"] != "target":
                terminal.say(f"note: {by_id[entry['request_id']].get('title')} cannot be remembered; "
                             "it is allowed for this Hunt only")
    if not enterprise:
        verb = "Allow" if decision == "allow" else "Deny"
        what = "this request" if len(entries) == 1 else f"these {len(entries)} requests"
        if not confirmed and not terminal.confirm(f"{verb} {what} on this engine?"):
            terminal.say("nothing was decided")
            return 1
        return _report(terminal, by_id, _local_decide(send, entries), decided_by="local-operator",
                       via="local confirmation")
    stepup = StepUp(send, origin, terminal, account=account, method=method)
    challenge, _ = stepup.begin("permission_decision", {"decisions": entries})
    if session is not None:
        proof = {"method": "approver_session", "session_id": session["session_id"],
                 "session_secret": session["secret"]()}
    else:
        proof = stepup.prove(challenge)
    result = stepup.finish(challenge, proof)
    via = str(result.get("decision_via") or "terminal_stepup").replace("_", " ")
    return _report(terminal, by_id, list(result.get("results") or ()),
                   decided_by=str(result.get("decided_by") or stepup.account), via=via)


# --- the opt-in approver session ---------------------------------------------------------------


class _HeldSecret:
    """The approver session secret, held only in this process's memory.

    Never written to disk, the environment or any config, never printed, and wiped (best
    effort: Python may hold copies) when the session ends."""

    def __init__(self, value: str) -> None:
        self._value = bytearray(value.encode("utf-8"))

    def __call__(self) -> str:
        return self._value.decode("utf-8")

    def __repr__(self) -> str:
        return "<approver session secret>"

    def wipe(self) -> None:
        for index in range(len(self._value)):
            self._value[index] = 0
        self._value = bytearray()


def watch(send: Send, terminal: Terminal, *, enterprise: bool, origin: str, hunt_id: str | None = None,
          minutes: int = 30, account: str | None = None, method: str | None = None,
          poll_seconds: float = WATCH_POLL_SECONDS, sleep: Callable[[float], None] = time.sleep) -> int:
    """Show each new request and decide it on a keypress, for at most ``minutes``.

    Enterprise: one step-up opens an approver session at the gateway (30 minutes at most); its
    secret lives only in this foreground process. Local OSS: every keypress is the confirmation.
    """
    terminal.require("shakerscan approve --watch")
    seconds = max(60, min(int(minutes) * 60, SESSION_SECONDS))
    held: _HeldSecret | None = None
    session: dict[str, Any] | None = None
    if enterprise:
        stepup = StepUp(send, origin, terminal, account=account, method=method)
        challenge, _ = stepup.begin("approver_session", {"session": {"ttl_seconds": seconds}})
        opened = stepup.finish(challenge, stepup.prove(challenge)).get("session") or {}
        if not opened.get("session_id") or not opened.get("session_secret"):
            raise ApprovalError("the gateway answered without an approver session; nothing was opened")
        held = _HeldSecret(str(opened["session_secret"]))
        session = {"session_id": str(opened["session_id"]), "secret": held}
        account = stepup.account
        terminal.say(f"approver session open until {opened.get('expires_at') or f'{seconds // 60} minutes from now'} "
                     "(held in this process only; Ctrl-C ends it)")
    deadline = time.monotonic() + seconds
    seen: set[str] = set()
    try:
        while time.monotonic() < deadline:
            for request in list_pending(send, hunt_id):
                if str(request["id"]) in seen:
                    continue
                seen.add(str(request["id"]))
                terminal.say(render_request(request))
                remember = "r" if request.get("remember_supported") else ""
                choice = terminal.key(
                    "  [a]llow" + ("  [r]emember for the target" if remember else "") + "  [d]eny  [s]kip  [q]uit: ",
                    "ads" + remember + "q",
                )
                if choice == "q":
                    return 0
                if choice in {"a", "r", "d"}:
                    decide(send, terminal, [request], "deny" if choice == "d" else "allow",
                           enterprise=enterprise, origin=origin, remember=choice == "r",
                           account=account, method=method, session=session, confirmed=not enterprise)
            sleep(poll_seconds)
        terminal.say("approver session ended (time limit)")
        return 0
    except KeyboardInterrupt:
        terminal.say("\napprover session ended")
        return 0
    finally:
        if session is not None and held is not None:
            try:
                send("POST", SESSION_REVOKE_PATH, {
                    "schema_version": "shakerscan-approval-session-revoke/v1",
                    "session_id": session["session_id"], "session_secret": held(),
                })
            except ApprovalError:
                terminal.say("could not revoke the approver session at the gateway; it expires on its own")
            held.wipe()


# --- the commands ------------------------------------------------------------------------------


def run(command: str, args: Any, send: Send, *, enterprise: bool, origin: str,
        terminal: Terminal | None = None) -> int:
    """``shakerscan approve|deny`` as parsed by the product CLI; returns the exit code."""
    terminal = terminal or Terminal()
    decision = "deny" if command == "deny" else "allow"
    if getattr(args, "watch", False):
        if decision == "deny":
            raise ApprovalError("--watch belongs to shakerscan approve")
        return watch(send, terminal, enterprise=enterprise, origin=origin, hunt_id=args.hunt,
                     minutes=args.minutes, account=args.account, method=args.method)
    terminal.require(f"shakerscan {command}")
    if args.all_pending:
        requests = list_pending(send, args.hunt)
    elif args.request_id:
        request = find_request(send, args.request_id, args.hunt)
        if request.get("status") != "pending":
            terminal.say(f"{request.get('title')}: already {request.get('status')}"
                         + (f" by {request.get('decided_by')}" if request.get("decided_by") else ""))
            return 0 if request.get("status") == ("granted" if decision == "allow" else "denied") else 1
        requests = [request]
    else:
        raise ApprovalError(f"name a request (shakerscan {command} <request-id>) or use --all-pending")
    if not requests:
        terminal.say("no pending permission requests")
        return 0
    terminal.say(f"{'Allow' if decision == 'allow' else 'Deny'} {len(requests)} permission request(s):")
    for request in requests:
        terminal.say(render_request(request))
    if args.total is not None and len(requests) != 1:
        raise ApprovalError("--total applies to one budget request at a time")
    if not enterprise:
        terminal.say("This engine has no accounts: anyone who can reach its API could decide. "
                     "The confirmation below is the only check.")
    return decide(send, terminal, requests, decision, enterprise=enterprise, origin=origin,
                  remember=args.remember, total=args.total, account=args.account, method=args.method)


def add_arguments(parser: Any, command: str) -> None:
    parser.add_argument("request_id", nargs="?", help="the permission request id the agent named")
    parser.add_argument("--all-pending", action="store_true", help="every pending request (of --hunt, else of every open Hunt)")
    parser.add_argument("--hunt", help="the Hunt the request belongs to (found automatically otherwise)")
    parser.add_argument("--account", help="Enterprise: your sign-in name (asked for otherwise)")
    parser.add_argument("--method", choices=("totp", "security_key"),
                        help="Enterprise step-up: a TOTP code, or a USB/NFC security key (needs python-fido2)")
    if command == "approve":
        parser.add_argument("--remember", action="store_true",
                            help="where the request supports it, remember the grant for the target")
        parser.add_argument("--total", type=int, help="a budget request: the total to allow instead of the proposed one")
        parser.add_argument("--watch", action="store_true",
                            help="stay open and decide each new request on a keypress (Enterprise: one "
                                 "step-up opens a 30-minute approver session held only in this process)")
        parser.add_argument("--minutes", type=int, default=30, help="--watch: how long (at most 30)")
    else:
        parser.set_defaults(remember=False, total=None, watch=False, minutes=30)


__all__ = [
    "APPROVAL_SCHEMA_PREFIX", "ApprovalError", "BEGIN_PATH", "FINISH_PATH", "PREAUTHORIZATION_HEADER",
    "SESSION_REVOKE_PATH", "StepUp", "StepUpUnavailable", "Terminal", "add_arguments", "assertion_json",
    "decide", "decision_entry", "expected_challenge", "find_request", "list_pending", "preauthorize",
    "render_request", "run", "set_digest", "set_document", "wait_for", "watch",
]
