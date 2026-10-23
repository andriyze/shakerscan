"""A person's decision an Enterprise gateway asks a security-key touch for, in the person's terminal.

An administrator of an Enterprise gateway can require a security-key touch for the decisions only
a person should make (raising a Hunt's budget, authorizing a target for active testing, sharing a
saved credential, widening a target's Hunt permissions, ...) when a terminal sends them with the
connection's token. The gateway then refuses such a request::

    HTTP 403, header x-shakerscan-step-up: required
    {"detail": {"error": "person_decision_required", "decision": "<kind>",
                "summary": "<the decision in plain words>", "proof": "security_key", "message"}}

and every command of this client completes it the same way, in the person's own terminal only:

1. it shows the decision in the gateway's words;
2. ``POST /_enterprise/approvals/begin`` with purpose ``person_decision`` and the exact request
   (method, path with its query, the body bytes) answers a WebAuthn challenge over a document that
   binds that request. The client checks the document names this request (method, path, query,
   SHA-256 of the body), that the set digest is the document's, and that the challenge is
   SHA-256(nonce || set digest);
3. the person touches a security key registered to their account (user presence; python-fido2
   over USB; no PIN unless the gateway asks for one);
4. ``finish`` answers a one-time grant valid for that request through this connection;
5. the request is sent again, once, unchanged, with the ``X-ShakerScan-Person-Proof`` header.

Without an interactive terminal (stdin and stdout both a terminal), or inside an agent that
``shakerscan agent`` launched (SHAKERSCAN_AGENT_NAME), it never prompts and never opens a key: it
raises PersonDecisionRefused, one line that names the decision and the command the person runs in
their own terminal, and the command exits 3 (refused, nothing ran). No option skips the touch.

What a touch proves: a person was at the key. A program running as the same computer user can
change this client or start a request of its own the moment the person expects to touch; touch
only for a prompt you started, and read the decision it names.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shlex
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from typing import Any

ERROR = "person_decision_required"
STEP_UP_HEADER = "x-shakerscan-step-up"
PROOF_HEADER = "X-ShakerScan-Person-Proof"
BEGIN_PATH = "/_enterprise/approvals/begin"
FINISH_PATH = "/_enterprise/approvals/finish"
BINDING_SCHEMA = "shakerscan-person-decision/v1"
SET_SCHEMA = "shakerscan-approval-set/v1"
# Exit status of a command whose request needs a person's decision it could not ask for here:
# refused, nothing ran (the same meaning as the CI mode's 3).
EXIT_REFUSED = 3
MAX_BODY = 48 * 1024
TIMEOUT_SECONDS = 30.0


class PersonDecisionError(Exception):
    """The touch could not be completed; nothing was changed. Printed without a traceback."""


class PersonDecisionRefused(PersonDecisionError):
    """Not an interactive terminal: the person makes this decision in their own terminal."""

    def __init__(self, line: str, *, detail: Mapping[str, Any], command: str) -> None:
        super().__init__(line)
        self.line, self.detail, self.command = line, dict(detail), command


def _approve():
    try:
        import hunt_approve
    except ModuleNotFoundError:
        from scripts import hunt_approve
    return hunt_approve


def _inert(text: Any, limit: int = 300) -> str:
    return _approve()._inert(str(text if text is not None else ""))[:limit]


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(bytes(value)).rstrip(b"=").decode("ascii")


def required(status: int | None, headers: Any, detail: Any) -> bool:
    """Whether this answer is the gateway asking for a person's decision with a security-key
    touch: HTTP 403, ``x-shakerscan-step-up: required`` and the error code in the detail."""
    if status != 403 or not isinstance(detail, Mapping) or detail.get("error") != ERROR:
        return False
    value = ""
    if headers is not None:
        try:
            value = str(headers.get(STEP_UP_HEADER) or headers.get("X-ShakerScan-Step-Up") or "")
        except AttributeError:
            value = ""
    return value.strip().lower() == "required"


def detail_of(raw: bytes | str | None) -> Any:
    """The ``detail`` of an error body, or None."""
    try:
        value = json.loads(raw) if raw else None
    except (ValueError, UnicodeDecodeError):
        return None
    return value.get("detail") if isinstance(value, Mapping) else None


def interactive(stdin: Any = None, stdout: Any = None, environ: Mapping[str, str] | None = None) -> bool:
    """A person at a terminal: stdin and stdout are both a terminal, and this is not an agent
    that `shakerscan agent` launched. An agent's tool call has no terminal."""
    environ = os.environ if environ is None else environ
    if (environ.get("SHAKERSCAN_AGENT_NAME") or "").strip():
        return False
    for stream in (stdin or sys.stdin, stdout or sys.stdout):
        try:
            if not stream.isatty():
                return False
        except (AttributeError, ValueError):
            return False
    return True


# ---- the person's command --------------------------------------------------------------------


def person_command(method: str, path: str, body: bytes | None) -> str:
    """The command the person runs in their own terminal to make this decision: the dedicated
    command where there is one (a budget raise, a target's authorization), else exactly this
    request through ``shakerscan api``."""
    route = urllib.parse.urlsplit(path).path
    parts = [part for part in route.split("/") if part]
    try:
        payload = json.loads(body) if body else None
    except (ValueError, UnicodeDecodeError):
        payload = None
    payload = payload if isinstance(payload, dict) else None
    if method == "POST" and len(parts) == 3 and parts[0] == "hunts" and parts[2] == "budget-amendments" and payload:
        limits = payload.get("limits") if isinstance(payload.get("limits"), dict) else {}
        pairs = [f"--limit {shlex.quote(f'{key}={value}')}" for key, value in sorted(limits.items())
                 if isinstance(key, str) and type(value) is int]
        if pairs and len(pairs) == len(limits):
            resume = " --resume" if payload.get("resume") is True else ""
            return f"shakerscan hunt budget raise {shlex.quote(parts[1])} " + " ".join(pairs) + resume
    if method == "POST" and len(parts) == 3 and parts[0] == "targets" and parts[2] == "authorization":
        tier = (payload or {}).get("risk_tier")
        if tier in (None, "active"):
            return f"shakerscan targets authorize {shlex.quote(parts[1])}"
    if method == "POST" and route == "/scans" and payload and isinstance(payload.get("target"), str):
        return f"shakerscan targets authorize {shlex.quote(payload['target'])}"
    if method == "POST" and route == "/hunts" and payload and isinstance(payload.get("target_id"), str):
        return f"shakerscan targets authorize {shlex.quote(payload['target_id'])}"
    if method == "POST" and len(parts) == 3 and parts[0] == "targets" and parts[2] in {"scan", "network-scans"}:
        return f"shakerscan targets authorize {shlex.quote(parts[1])}"
    text = body.decode("utf-8", "replace") if body else ""
    return "shakerscan api " + " ".join(shlex.quote(part) for part in (method, path, *([text] if text else [])))


def refusal_line(detail: Mapping[str, Any], command: str) -> str:
    """One line for an agent's tool call: the decision, that nothing changed, the person's command."""
    summary = _inert(detail.get("summary") or detail.get("decision") or "a person's decision", 240)
    return (
        f"person decision required: {summary}. Nothing was changed. The person runs this in their "
        f"own terminal and touches their security key: {command}"
    )


# ---- the touch -------------------------------------------------------------------------------


Post = Callable[[str, Mapping[str, Any]], tuple[int, Any]]


def json_poster(api_url: str, token: str | None, *, opener: Any = None, timeout: float = TIMEOUT_SECONDS) -> Post:
    """``post(path, payload) -> (status, body)`` for the approval routes: the connection's bearer
    token, only over https, never a followed redirect."""
    base = api_url.rstrip("/")
    if token and not base.startswith("https://"):
        raise PersonDecisionError("a token is only ever sent over https://")

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
            return None

    chosen = opener or urllib.request.build_opener(_NoRedirect())

    def post(path: str, payload: Mapping[str, Any]) -> tuple[int, Any]:
        request = urllib.request.Request(
            base + path, data=json.dumps(dict(payload), separators=(",", ":")).encode(), method="POST",
            headers={"Accept": "application/json", "Content-Type": "application/json",
                     **({"Authorization": "Bearer " + token} if token else {})},
        )
        try:
            with chosen.open(request, timeout=timeout) as response:
                raw = response.read(1024 * 1024)
                status = response.status
        except urllib.error.HTTPError as exc:
            raw, status = exc.read(64 * 1024), exc.code
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise PersonDecisionError(f"the gateway did not answer: {getattr(exc, 'reason', exc)}") from exc
        try:
            value = json.loads(raw) if raw else {}
        except (ValueError, UnicodeDecodeError):
            value = {}
        if not 200 <= status < 300 and isinstance(value, Mapping) and isinstance(value.get("detail"), Mapping):
            value = value["detail"]
        return status, value

    return post


def _refused(status: int, body: Any) -> PersonDecisionError:
    text = _approve()._detail_text(body)
    code = str(body.get("error") or "refused") if isinstance(body, Mapping) else "refused"
    return PersonDecisionError(f"the gateway refused the touch ({code}, HTTP {status}): {text}; nothing was changed")


def check_challenge(challenge: Mapping[str, Any], *, origin: str, method: str, path: str, body: bytes) -> dict:
    """The document the challenge is for, when it names exactly this request; else an error."""
    approve = _approve()
    document = challenge.get("document")
    if not isinstance(document, Mapping):
        raise PersonDecisionError("the gateway's challenge carries no document; nothing was changed")
    part = document.get("person_decision")
    target, _, query = path.partition("?")
    expected = {
        "schema_version": BINDING_SCHEMA,
        "method": method,
        "path": urllib.parse.unquote(target),
        "query": query,
        "body_sha256": hashlib.sha256(body or b"").hexdigest(),
    }
    if (
        not isinstance(part, Mapping)
        or document.get("schema_version") != SET_SCHEMA
        or document.get("purpose") != "person_decision"
        or str(document.get("origin") or "").rstrip("/") != origin.rstrip("/")
        or any(part.get(key) != value for key, value in expected.items())
    ):
        raise PersonDecisionError(
            "the gateway's challenge is not for this request (method, path, query or body differ); "
            "nothing was changed"
        )
    if challenge.get("set_digest") != approve.set_digest(document):
        raise PersonDecisionError("the gateway's challenge digest is not its document's; nothing was changed")
    webauthn = challenge.get("webauthn")
    nonce = str(challenge.get("nonce") or "")
    if (
        "security_key" not in (challenge.get("methods") or ())
        or not isinstance(webauthn, Mapping)
        or not nonce
        or webauthn.get("challenge") != approve.expected_challenge(nonce, str(challenge["set_digest"]))
    ):
        raise PersonDecisionError("the gateway's security-key challenge is not bound to this request; nothing was changed")
    return dict(document)


def complete(post: Post, *, origin: str, method: str, path: str, body: bytes, detail: Mapping[str, Any],
             terminal: Any = None, assertion: Callable[..., dict] | None = None) -> str:
    """Ask the person, at this terminal, for one touch for exactly this request; the grant."""
    approve = _approve()
    terminal = terminal or approve.Terminal()
    if sys.platform == "win32" and assertion is None:
        # Raw USB access to a FIDO key needs administrator rights on Windows; this release does
        # not use Windows' own WebAuthn API. Said plainly rather than failing at the key.
        raise PersonDecisionError(
            "a security-key touch from a terminal is not supported on Windows in this release; "
            "make this decision in the browser; nothing was changed"
        )
    if len(body or b"") > MAX_BODY:
        raise PersonDecisionError("this request is too large for a security-key proof; make it in the browser")
    terminal.say("This needs your decision (your administrator requires a security-key touch):")
    terminal.say("  " + _inert(detail.get("summary") or detail.get("decision") or "a person's decision", 240))
    status, challenge = post(BEGIN_PATH, {
        "schema_version": "shakerscan-approval-begin/v1", "purpose": "person_decision", "origin": origin.rstrip("/"),
        "person_decision": {"method": method, "path": path, "body": _b64url(body or b"")},
    })
    if not 200 <= status < 300 or not isinstance(challenge, Mapping):
        raise _refused(status, challenge)
    document = check_challenge(challenge, origin=origin, method=method, path=path, body=body or b"")
    shown = document["person_decision"].get("summary")
    if isinstance(shown, str) and shown and shown != detail.get("summary"):
        # What the key signs is the document's summary; show it if it says something else.
        terminal.say("  signed as: " + _inert(shown, 240))
    terminal.say("Touch your security key to approve (Ctrl-C to cancel)...")
    sign = assertion or approve.security_key_assertion
    try:
        credential = sign(challenge["webauthn"], origin.rstrip("/"), terminal, prompt="")
    except approve.ApprovalError as exc:
        raise PersonDecisionError(f"{exc}; nothing was changed") from exc
    status, result = post(FINISH_PATH, {
        "schema_version": "shakerscan-approval-finish/v1", "approval_id": challenge.get("approval_id"),
        "set_digest": challenge.get("set_digest"), "proof": {"method": "security_key", "credential": credential},
    })
    granted = result.get("person_decision") if isinstance(result, Mapping) else None
    if not 200 <= status < 300 or not isinstance(granted, Mapping) or not isinstance(granted.get("grant"), str):
        raise _refused(status, result)
    terminal.say("done; decided by " + _inert(result.get("decided_by") or "you", 120) + " (security-key touch)")
    return granted["grant"]


def handle(post: Post, *, origin: str, method: str, path: str, body: bytes | None, detail: Mapping[str, Any],
           resend: Callable[[str], Any], terminal: Any = None, environ: Mapping[str, str] | None = None,
           assertion: Callable[..., dict] | None = None) -> Any:
    """The refused request, completed: in an interactive terminal one touch and one resend (its
    answer is returned, whatever it is); anywhere else PersonDecisionRefused."""
    command = person_command(method, path, body)
    stdin = getattr(terminal, "stdin", None)
    stdout = getattr(terminal, "stdout", None)
    if not interactive(stdin, stdout, environ):
        raise PersonDecisionRefused(refusal_line(detail, command), detail=detail, command=command)
    grant = complete(post, origin=origin, method=method, path=path, body=body or b"", detail=detail,
                     terminal=terminal, assertion=assertion)
    return resend(grant)


__all__ = [
    "ERROR", "EXIT_REFUSED", "PROOF_HEADER", "PersonDecisionError", "PersonDecisionRefused", "check_challenge",
    "complete", "detail_of", "handle", "interactive", "json_poster", "person_command", "refusal_line", "required",
]
