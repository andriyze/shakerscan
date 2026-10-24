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
        purpose, account, origin, decisions | preauthorization | session | knowledge}
      -> {schema_version: "shakerscan-approval-challenge/v1", approval_id, set_digest, methods,
          expires_at, decisions?, nonce?, webauthn?}
    POST /_enterprise/approvals/finish    {schema_version: "shakerscan-approval-finish/v1",
        approval_id, set_digest, proof}
      -> {schema_version: "shakerscan-approval-result/v1", approval_id, decided_by, decision_via,
          results? | preauthorization? | session? | knowledge?}
    POST /_enterprise/approvals/session/revoke {schema_version:
        "shakerscan-approval-session-revoke/v1", session_id, session_secret}
      -> {schema_version: "shakerscan-approval-session/v1", session_id, revoked: true}

The digest, proof and result shapes are defined by the functions below and documented in
docs/hunt-permission-requests.md ("E3: the terminal approval protocol and the G1 contract").

The ``knowledge_decision`` purpose carries one knowledge-review decision (``shakerscan knowledge
review`` and ``knowledge allow-changes``): accepting one instruction or saved-action proposal,
confirming one target's agent-written instructions, or letting Hunts edit one target's
instructions. The step-up is bound to that single decision (the target, the proposal, the digest
of the text that was shown, the revision) and the gateway applies it itself after the proof.
"""

from __future__ import annotations

import base64
import contextlib
import getpass
import hashlib
import json
import math
import os
import re
import select
import shlex
import sys
import time
import urllib.parse
import uuid
from collections.abc import Callable, Iterator, Mapping, Sequence
from typing import Any

APPROVAL_SCHEMA_PREFIX = "shakerscan-approval-"
BEGIN_PATH = "/_enterprise/approvals/begin"
FINISH_PATH = "/_enterprise/approvals/finish"
SESSION_REVOKE_PATH = "/_enterprise/approvals/session/revoke"
PREAUTHORIZATION_HEADER = "X-ShakerScan-Preauthorization"
SET_SCHEMA = "shakerscan-approval-set/v1"
PURPOSES = ("permission_decision", "preauthorization", "approver_session", "knowledge_decision", "key_check")
# A touch test (``shakerscan approve --test``): one touch of the person's key over a document that
# decides nothing, on an Enterprise gateway that offers it.
KEY_CHECK = {"test": "touch", "decides": "nothing"}
# One knowledge-review decision, always with exactly these keys (null where they do not apply).
KNOWLEDGE_DECISIONS = ("accept", "confirm", "allow_changes", "dismiss", "reopen", "retract", "retract_hunt", "release_marker")
KNOWLEDGE_KEYS = ("decision", "target_id", "subject_id", "text_sha256", "expected_revision", "reason", "note")
# Which keys each decision names; every other key is null. The subject is the proposal (accept),
# the finding (dismiss, reopen), the interpretation entry (retract) or the Hunt (retract_hunt).
KNOWLEDGE_SUBJECT = frozenset({"accept", "dismiss", "reopen", "retract", "retract_hunt"})
KNOWLEDGE_TEXT = frozenset({"accept", "confirm", "release_marker"})
KNOWLEDGE_REVISION = frozenset({"confirm", "allow_changes"})
KNOWLEDGE_NOTE_REQUIRED = frozenset({"dismiss", "reopen", "retract", "retract_hunt"})
DISMISSAL_REASONS = ("false_positive", "accepted_risk", "duplicate")
MAX_NOTE_CHARACTERS = 2000
PREAUTHORIZATION_USES = ("agent_launch", "hunt_start")
# Hunts that can hold a pending request. The engine withdraws requests when a Hunt ends.
OPEN_HUNT_STATUSES = ("active", "awaiting_planner", "budget_exhausted")
SESSION_SECONDS = 30 * 60
WATCH_POLL_SECONDS = 3.0
# --watch backs off while nothing new arrives (3, 6, 12, 15 s) and returns to WATCH_POLL_SECONDS
# when a request is shown. A shown request is still re-read every poll interval while it waits.
WATCH_MAX_POLL_SECONDS = 15.0
# The engine's cross-Hunt feed (2.11): one list/v1 read, then since= deltas. An engine or gateway
# without it answers one of FEED_ABSENT (a 2.10 engine takes the path for /hunts/{hunt_id}; a
# gateway refuses a route it does not know with 403) and the per-Hunt reads are used instead.
FEED_PATH = "/hunts/permission-requests"
FEED_PAGE = 200
FEED_ABSENT = frozenset({400, 403, 404, 405, 422})
# Pages read per poll, at most (FEED_PAGE requests each; a Hunt holds at most 20 pending).
MAX_PAGES = 50
HUNT_PAGE = 200
# --watch keys: after a request is shown, keys are discarded for this long before its prompt is
# written (a key meant for the previous screen never decides the next one); bytes arriving within
# KEY_BURST_SECONDS of each other are one burst (an escape sequence or a paste), never a key; and
# escape sequences are also followed byte by byte, whatever their timing (Terminal._feed).
KEY_SETTLE_SECONDS = 0.75
# ESC ] (OSC), ESC P (DCS), ESC _ (APC), ESC ^ (PM), ESC X (SOS): strings ended only by BEL or ST,
# or, at a prompt, by this long without input (a terminal sends its replies in one write).
KEY_STRING_QUIET_SECONDS = 1.5
_STRING_INTRODUCERS = frozenset(b"]P_^X")
KEY_BURST_SECONDS = 0.03
# `hunt permissions wait`: never more than one read of a request per this many seconds (L1).
WAIT_MIN_POLL_SECONDS = 1.0
# Ending --watch revokes the approver session as a courtesy (it expires on its own anyway), so the
# revoke waits this long at most: Ctrl-C must end the command promptly even when the gateway or
# the network has stalled, not after the CLI's general per-request timeout.
REVOKE_TIMEOUT_SECONDS = 5.0
_TOTP = re.compile(r"^[0-9]{6,8}$")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


class ApprovalError(Exception):
    """A problem the person can act on; printed without a traceback."""


class RequestGone(ApprovalError):
    """The request is not there (HTTP 404): it ended with its Hunt, or never existed."""


class StepUpUnavailable(ApprovalError):
    """The Enterprise gateway does not serve the step-up routes (it predates G1)."""


class OutcomeUnknown(ApprovalError):
    """The decision was sent but its outcome is not known (no answer in time): check, never resend."""


class NotAtTerminal(ApprovalError):
    """The command asks the person, and this is no person's terminal (its input or every output is
    not a terminal, or the shell belongs to an agent that ``shakerscan agent`` started). Nothing
    was asked of the person or a security key; the command exits 3 (refused, nothing ran)."""


# Exit status of a command that asks the person and has no terminal to ask on: refused, nothing
# ran (person_decision.EXIT_REFUSED has the same meaning).
EXIT_NOT_AT_TERMINAL = 3


class GatewayRefused(ApprovalError):
    """The gateway's step-up routes answered with a refusal in the contract's shape."""

    def __init__(self, message: str, *, code: str, status: int) -> None:
        super().__init__(message)
        self.code, self.status = code, status


# --- transport ---------------------------------------------------------------------------------
#
# ``send(method, path, payload=None, headers=None, *, timeout=None) -> (status, body)``: ``body`` is
# the parsed JSON of a success, or the error ``detail`` of a refusal. It raises ApprovalError only
# when no answer arrived (``timeout`` seconds, else the CLI's own per-request timeout). The product
# CLI supplies it over its own authenticated, redirect-refusing client.

Send = Callable[..., tuple[int, Any]]


def _quote(value: str) -> str:
    import urllib.parse
    return urllib.parse.quote(str(value), safe="")


def _ok(status: int) -> bool:
    return 200 <= status < 300


def _inert(text: str) -> str:
    """Server text as it may reach the terminal: no control, bidirectional or invisible
    formatting character can move the cursor or reorder what the person reads."""
    import unicodedata
    return "".join("?" if (ord(ch) < 0x20 and ch != "\t") or 0x7F <= ord(ch) < 0xA0
                   or unicodedata.category(ch) in {"Cf", "Zl", "Zp"} else ch for ch in text)


def _detail_text(body: Any, limit: int = 400) -> str:
    if isinstance(body, Mapping):
        for key in ("message", "detail", "error"):
            if isinstance(body.get(key), str) and body[key].strip():
                return _inert(body[key].strip()[:limit])
        return _inert(json.dumps(dict(body), sort_keys=True)[:limit])
    return _inert(str(body or "no detail")[:limit])


# What an Enterprise gateway says of itself to a connection's token: every gateway serves it.
ME_PATH = "/_enterprise/me"


def gateway_features(send: Send) -> dict[str, bool]:
    """What an Enterprise gateway says of itself (GET /_enterprise/me): ``known`` (it answered),
    ``names_approver`` (it reports ``person_decision_proof``: it takes an approval with no sign-in
    name, the approver being the person the token acts for, and serves the person-decision feed)
    and ``touch_required`` (its administrator requires a security-key touch for person decisions
    from terminals). Read instead of probing a route an older gateway refuses, which would write
    a refusal into its audit log on every command."""
    try:
        status, body = send("GET", ME_PATH)
    except ApprovalError:
        status, body = None, None
    if not isinstance(status, int) or not _ok(status) or not isinstance(body, Mapping):
        return {"known": False, "names_approver": False, "touch_required": False}
    return {"known": True, "names_approver": "person_decision_proof" in body,
            "touch_required": body.get("person_decision_proof") is True}


# --- reading requests --------------------------------------------------------------------------


def list_pending(send: Send, hunt_id: str | None = None) -> list[dict[str, Any]]:
    """Pending requests of one Hunt, or of every Hunt that can hold one, oldest first."""
    return PendingFeed(send, hunt_id).poll()


class PendingFeed:
    """The pending requests ``--watch`` and ``--all-pending`` read.

    With the engine's cross-Hunt feed: one paged read, then on each later ``poll`` only what was
    raised or decided since the previous one (``since=``, so the caller keeps what it has seen).
    Without it (an engine before 2.11, or a gateway that does not pass the route): the per-Hunt
    reads, every open Hunt's pending requests on each poll. Which one is settled by the first
    answer and kept."""

    def __init__(self, send: Send, hunt_id: str | None = None) -> None:
        self.send, self.hunt_id = send, hunt_id
        self.supported: bool | None = None
        self.since: str | None = None

    def poll(self) -> list[dict[str, Any]]:
        if self.supported is not False:
            found = self._feed()
            if found is not None:
                return found
        return _list_pending_per_hunt(self.send, self.hunt_id)

    def _feed(self) -> list[dict[str, Any]] | None:
        query: dict[str, Any] = {"status": "pending", "limit": FEED_PAGE}
        if self.hunt_id:
            query["hunt_id"] = self.hunt_id
        if self.since:
            query["since"] = self.since
        pending: list[dict[str, Any]] = []
        generated_at: str | None = None
        cursor: str | None = None
        for _ in range(MAX_PAGES):
            status, body = self.send("GET", f"{FEED_PATH}?{urllib.parse.urlencode({**query, **({'cursor': cursor} if cursor else {})})}")
            page = body if isinstance(body, Mapping) and isinstance(body.get("items"), list) else None
            if self.supported is None and (status in FEED_ABSENT or (_ok(status) and page is None)):
                self.supported = False
                return None
            if not _ok(status):
                raise ApprovalError(f"cannot read permission requests: HTTP {status}: {_detail_text(body)}")
            if page is None:
                raise ApprovalError("cannot read permission requests: the answer has no items")
            self.supported = True
            # The first page's time: a later page's is newer, and since= is inclusive, so the
            # next poll may repeat a request but never skips one written while these were read.
            generated_at = generated_at or str(page.get("generated_at") or "") or None
            pending += [{**item, "hunt_id": str(item.get("hunt_id") or self.hunt_id or "")}
                        for item in page["items"] if isinstance(item, Mapping) and item.get("status") == "pending"]
            cursor = str(page.get("next_cursor") or "") or None
            if not page.get("has_more") or not cursor:
                break
        else:
            raise ApprovalError(f"cannot read permission requests: more than {MAX_PAGES} pages pending")
        if generated_at:
            self.since = generated_at
        return sorted(pending, key=lambda item: (str(item.get("created_at") or ""), str(item.get("id"))))


def _list_pending_per_hunt(send: Send, hunt_id: str | None = None) -> list[dict[str, Any]]:
    """``list_pending`` on an instance without the cross-Hunt feed: one read per open Hunt."""
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
    """Every open Hunt, page by page: a status with more than one page (200) of Hunts was cut."""
    found: list[str] = []
    for state in OPEN_HUNT_STATUSES:
        for page in range(MAX_PAGES):
            status, body = send("GET", f"/hunts?status={state}&limit={HUNT_PAGE}&offset={page * HUNT_PAGE}")
            if not _ok(status):
                raise ApprovalError(f"cannot list Hunts: HTTP {status}: {_detail_text(body)}")
            rows = [item for item in (body or {}).get("hunts") or () if isinstance(item, Mapping)]
            before = len(set(found))
            found += [str(item.get("hunt_id")) for item in rows if item.get("hunt_id")]
            total = (body or {}).get("total") if isinstance(body, Mapping) else None
            more = (page + 1) * HUNT_PAGE < total if isinstance(total, int) else len(rows) >= HUNT_PAGE
            # A page with nothing new (an instance that ignored offset) ends the status too.
            if not rows or not more or len(set(found)) == before:
                break
    return list(dict.fromkeys(found))


def find_request(send: Send, request_id: str, hunt_id: str | None = None) -> dict[str, Any]:
    """One request by id; without ``hunt_id`` it is looked for in every open Hunt."""
    request_id = str(request_id).strip().lower()
    if not _UUID.fullmatch(request_id):
        raise ApprovalError(f"{request_id!r} is not a permission request id (a UUID from `shakerscan approve <id>`)")
    if not hunt_id:
        # A pending request (the usual case) names its Hunt in the feed: one read for that Hunt
        # instead of one per open Hunt. A decided one, or no feed, is looked for Hunt by Hunt.
        try:
            listed = PendingFeed(send)._feed() or []
        except ApprovalError:
            listed = []  # the Hunt-by-Hunt search below reports what is wrong, if anything
        named = next((item for item in listed if str(item.get("id")) == request_id), None)
        if named and named.get("hunt_id"):
            hunt_id = str(named["hunt_id"])
    hunts = [hunt_id] if hunt_id else _open_hunts(send)
    for hunt in hunts:
        status, body = send("GET", f"/hunts/{_quote(hunt)}/permission-requests/{_quote(request_id)}")
        if _ok(status) and isinstance(body, Mapping):
            return {**body, "hunt_id": str(body.get("hunt_id") or hunt)}
        if status != 404 and hunt_id:
            raise ApprovalError(f"cannot read permission request {request_id}: HTTP {status}: {_detail_text(body)}")
    where = f"Hunt {hunt_id}" if hunt_id else "any active Hunt"
    raise RequestGone(f"no permission request {request_id} in {where}; it may have ended with its Hunt")


def wait_for(send: Send, request: Mapping[str, Any], seconds: float, *, step: int = 25,
             clock: Callable[[], float] = time.monotonic,
             sleep: Callable[[float], None] = time.sleep) -> dict[str, Any]:
    """Long-poll one request until it is decided or ``seconds`` pass; return its last state.

    L1: the time left was rounded down to whole seconds, so in the last second every poll asked
    for ``wait_seconds=0`` and the loop hammered the engine (79-86 requests in that second). Each
    poll now asks the server to hold for the time left rounded up (at most ``step``), so
    ``wait_seconds=0`` is sent only when the caller asked for no wait at all, and only once. A
    server that answers before holding (or a pending answer that comes back early) is polled at
    most once per WAIT_MIN_POLL_SECONDS. The wait ends at the deadline, at most the last whole
    second's rounding past it."""
    deadline = clock() + max(0.0, seconds)
    path = f"/hunts/{_quote(request['hunt_id'])}/permission-requests/{_quote(request['id'])}"
    current = dict(request)
    while True:
        started = clock()
        left = deadline - started
        hold = min(step, max(1, math.ceil(left))) if left > 0 else 0
        status, body = send("GET", f"{path}?wait_seconds={hold}")
        if not _ok(status):
            raise ApprovalError(f"cannot read permission request {request['id']}: HTTP {status}: {_detail_text(body)}")
        current = {**body, "hunt_id": str(body.get("hunt_id") or request["hunt_id"])}
        now = clock()
        if current.get("status") != "pending" or now >= deadline:
            return current
        pause = min(WAIT_MIN_POLL_SECONDS - (now - started), deadline - now)
        if pause > 0:
            sleep(pause)
        if clock() >= deadline:
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
    if request.get("auto_grant_withheld_note"):
        lines.append(f"    note:     {request.get('auto_grant_withheld_note')}")
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
    elif purpose == "knowledge_decision":
        keys = KNOWLEDGE_KEYS + (("release_label", "released_at")
                                if body["knowledge"].get("decision") == "release_marker" else ())
        document["knowledge"] = {key: body["knowledge"].get(key) for key in keys}
    elif purpose == "key_check":
        document["key_check"] = dict(KEY_CHECK)
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


def _is_tty(stream: Any) -> bool:
    try:
        return bool(stream is not None and stream.isatty())
    except (AttributeError, ValueError):
        return False


def person_at_terminal(*streams: Any, environ: Mapping[str, str] | None = None) -> bool:
    """A person at a terminal: every stream given is a terminal, and this is not an agent that
    ``shakerscan agent`` launched (SHAKERSCAN_AGENT_NAME). An agent's tool call has no terminal;
    an agent's own pseudo-terminal still carries the variable."""
    environ = os.environ if environ is None else environ
    if (environ.get("SHAKERSCAN_AGENT_NAME") or "").strip():
        return False
    return all(_is_tty(stream) for stream in streams)


def terminal_output(stdin: Any, stdout: Any, *prefer: Any, environ: Mapping[str, str] | None = None) -> Any:
    """The stream a person is asked on, or None. A person is at a terminal when stdin and stdout
    are both terminals and this is not an agent that ``shakerscan agent`` launched: one rule for
    every command that asks the person (an approval, a watch, start bounds, a person's decision,
    a knowledge decision). A command whose output is captured (an agent's tool call, a harness
    that gives it a terminal for its input and errors only, ``| jq``, ``| tee``, ``> file``)
    never asks and never makes a key blink: it exits 3 with the command to run without the pipe.
    The prompt goes to the first of ``prefer`` that is a terminal too (``hunt start --allow``
    asks on stderr, its stdout carrying the JSON answer), else to stdout."""
    if not person_at_terminal(stdin, stdout, environ=environ):
        return None
    return next((stream for stream in prefer if _is_tty(stream)), stdout)


class Terminal:
    """The person's own terminal. Every prompt refuses to run without one (``require``: stdin and
    stdout terminals), and every prompt is written to ``prompts`` when it is a terminal too, else
    to stdout."""

    def __init__(self, stdin: Any = None, stdout: Any = None, prompts: Any = None) -> None:
        self.stdin = stdin or sys.stdin
        self.stdout = stdout or sys.stdout
        # Where a command whose stdout carries its answer asks instead (hunt start --allow: stderr).
        self.prompts = prompts
        self._key_fd: int | None = None
        self._key_saved: Any = None
        self._escape = "idle"  # the escape-sequence state machine of key()
        self._utf8_left = 0  # continuation bytes still due for a UTF-8 character
        self._last_input = 0.0  # when _feed last saw a byte (a control string's quiet reset)

    def require(self, what: str = "it", *, person_runs: str | None = None) -> None:
        """Refuse (NotAtTerminal, exit 3) unless a person is at this terminal: before anything is
        read from the gateway, shown or asked of a security key. From here on every prompt goes
        to the output that is the terminal. ``what`` names the command where the line printed
        does not already (it is printed after the command's own name otherwise: "it");
        ``person_runs`` is the command the person runs in their own terminal (the request id
        named, for an agent to pass on)."""
        run = (f"the person runs this in their own terminal: {_inert(person_runs)}" if person_runs
               else "run it yourself in your own terminal")
        if (os.environ.get("SHAKERSCAN_AGENT_NAME") or "").strip():
            # Inside an agent that `shakerscan agent` started (its shell may well be a terminal):
            # a plugged-in key would answer the agent's own request.
            raise NotAtTerminal(
                f"{what} asks the person, and this shell belongs to an agent that `shakerscan agent` "
                f"started; nothing was asked or decided: {run}"
            )
        stream = terminal_output(self.stdin, self.stdout, *([self.prompts] if self.prompts is not None else []))
        if stream is None:
            raise NotAtTerminal(
                f"{what} asks the person at an interactive terminal (its input and its output a "
                "terminal) and refuses a pipe or captured output, never through an agent's shell; "
                f"nothing was asked or decided: {run}"
            )
        self.stdout = stream

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

    @contextlib.contextmanager
    def keypresses(self) -> Iterator[None]:
        """Read single keys (no echo, no Enter) for as long as the block runs.

        L2: the keypress mode used to be switched on after the prompt was written, with
        ``tty.setcbreak``'s default TCSAFLUSH, so a key typed in between was echoed and then
        thrown away, and the watch sat in a blocking read with nothing decided and no polling.
        The mode is now switched on once, before any request is shown, without flushing; a key
        typed before a prompt is ready is discarded deliberately (``key``'s settle) and said
        so, and every key typed after that is read. The terminal is restored on the way
        out, whatever ends the block (Ctrl-C included)."""
        try:
            import termios
            import tty
            fd = self.stdin.fileno()
            saved = termios.tcgetattr(fd)
            tty.setcbreak(fd, termios.TCSANOW)
        except (ImportError, OSError, ValueError, AttributeError):
            yield  # no terminal control here: key() falls back to reading a line
            return
        self._key_fd = fd
        self._key_saved = saved
        try:
            yield
        finally:
            self._key_fd = None
            self._key_saved = None
            # TCSANOW: TCSADRAIN waits until the terminal's output queue is read, and an echoed
            # key nobody reads (a pseudo-terminal) would hold Ctrl-C there for ever.
            try:
                termios.tcsetattr(fd, termios.TCSANOW, saved)
            except (OSError, termios.error):  # the terminal is gone (SIGHUP): nothing to restore
                pass

    @contextlib.contextmanager
    def lines(self) -> Iterator[None]:
        """Inside ``keypresses``: the terminal's ordinary line mode (echo, Enter, editing) for as
        long as the block runs, for a typed answer (a sign-in name, a TOTP code); keypress mode
        is back afterwards, with any key typed meanwhile discarded by the next prompt's settle."""
        fd, saved = getattr(self, "_key_fd", None), getattr(self, "_key_saved", None)
        if fd is None or saved is None:
            yield
            return
        import termios
        import tty
        # Typed-ahead input (a key or a line sent before this prompt existed) is discarded, so it
        # can never answer the sign-in name or code prompt that follows.
        termios.tcsetattr(fd, termios.TCSAFLUSH, saved)
        self._key_fd = None
        try:
            yield
        finally:
            with contextlib.suppress(OSError, termios.error):
                tty.setcbreak(fd, termios.TCSANOW)
            self._escape, self._utf8_left = "idle", 0
            self._key_fd = fd

    def _burst(self, fd: int, first: bytes) -> bytes:
        """``first`` and every byte that follows it at once: an escape sequence or a paste."""
        data = first
        while select.select([fd], [], [], KEY_BURST_SECONDS)[0]:
            more = os.read(fd, 1024)
            if not more:
                break
            data += more
        return data

    def _feed(self, data: bytes) -> bool:
        """Run ``data`` through the escape-sequence state machine; True when it began with the
        machine idle and it is one byte that is not part of a sequence (a lone key).

        B1: timing alone cannot tell a sequence from keys (ESC, then ``[A`` 0.3 s later over a
        slow link), so the state is kept across reads and prompts: after ESC the next byte
        belongs to the sequence; after ``ESC [`` (or the 8-bit CSI 0x9B) every byte up to a final
        byte (0x40-0x7E) does; after ``ESC O`` one more byte does. ``ESC ]`` (OSC), ``ESC P``
        (DCS), ``ESC _`` (APC), ``ESC ^`` (PM) and ``ESC X`` (SOS) open a string that only BEL or
        ST (``ESC \\``) ends, so a terminal's reply or a pasted control string never decides. A
        byte of 0x80 or above decides nothing: it is part of a UTF-8 character (followed through
        its continuation bytes) or is ignored, except a 0x9B outside UTF-8, which is CSI."""
        self._last_input = time.monotonic()
        lone = len(data) == 1 and self._escape == "idle" and not self._utf8_left
        for byte in data:
            state = self._escape
            if state == "idle":
                if self._utf8_left and 0x80 <= byte <= 0xBF:
                    self._utf8_left -= 1
                    continue
                self._utf8_left = 0
                if byte == 0x1B:
                    self._escape = "escape"
                elif byte == 0x9B:
                    self._escape = "csi"
                elif 0xC2 <= byte <= 0xF4:
                    self._utf8_left = 1 if byte < 0xE0 else 2 if byte < 0xF0 else 3
                if byte >= 0x80 or byte == 0x1B:
                    lone = False
            elif state == "escape":
                self._escape = ("csi" if byte == 0x5B else "ss3" if byte == 0x4F
                                else "string" if byte in _STRING_INTRODUCERS
                                else "escape" if byte == 0x1B  # ESC ESC: a new sequence starts
                                else "idle")
            elif state == "csi":
                if 0x40 <= byte <= 0x7E:
                    self._escape = "idle"
            elif state == "string":
                if byte == 0x07:
                    self._escape = "idle"
                elif byte == 0x1B:
                    self._escape = "string-escape"
            elif state == "string-escape":
                self._escape = "idle" if byte == 0x5C else "string-escape" if byte == 0x1B else "string"
            else:  # ss3: one byte names the key
                self._escape = "idle"
        return lone

    def _string_open(self) -> bool:
        return self._escape in {"string", "string-escape"}

    def drain_keys(self, seconds: float) -> int:
        """Discard every key typed before now and during the next ``seconds`` (keypress mode
        only), still following escape sequences; return how many bytes were discarded."""
        fd = getattr(self, "_key_fd", None)
        if fd is None:
            return 0
        dropped = 0
        deadline = time.monotonic() + max(0.0, seconds)
        while True:
            left = deadline - time.monotonic()
            if not select.select([fd], [], [], max(0.0, left))[0]:
                if left <= 0:
                    return dropped
                continue
            chunk = os.read(fd, 1024)
            if not chunk:
                return dropped
            self._feed(chunk)
            dropped += len(chunk)

    def key(self, prompt: str, choices: str, *, keep_waiting: Callable[[], bool] | None = None,
            interval: float = WATCH_POLL_SECONDS, settle: float = KEY_SETTLE_SECONDS) -> str | None:
        """One lone keypress from ``choices``; anything else is ignored and the wait goes on.

        Before the prompt is written, keys typed until then and for ``settle`` seconds more are
        discarded (and said so): a key meant for an earlier screen never decides this one. B1:
        only one byte arriving on its own, outside any escape sequence, and exactly one of the
        lowercase ``choices`` decides. An arrow key (``ESC [ A``), Alt-a (``ESC a``) or a paste
        arrives as a burst and is discarded whole; a sequence split across reads is followed by
        the state machine (``_feed``); an uppercase letter never decides. While no key arrives,
        ``keep_waiting()`` is asked every ``interval`` seconds; when it answers False the prompt
        is abandoned and None is returned, so a watch never stops polling while it waits.
        Outside keypress mode (no terminal control) a line is read instead."""
        fd = getattr(self, "_key_fd", None)
        if fd is not None and self.drain_keys(settle):
            self.say("(ignored keys pressed before this prompt was ready)")
        self.stdout.write(prompt)
        self.stdout.flush()
        if fd is None:
            answer = self.stdin.readline()[:1]
            return answer if answer and answer in choices else ""
        next_poll = time.monotonic() + max(0.05, interval)
        told = False
        while True:
            now = time.monotonic()
            wait = max(0.0, next_poll - now)
            if self._string_open():
                # A control string only BEL or ST ends would otherwise hold every later key. A
                # terminal sends its replies in one write, so after a quiet pause the string is
                # over (or was never going to end) and keys count again.
                quiet_left = self._last_input + KEY_STRING_QUIET_SECONDS - now
                if quiet_left <= 0:
                    self._escape = "idle"
                    told = False
                    self.say("\n(the terminal control string ended after a pause; keys count again)")
                    self.stdout.write(prompt)
                    self.stdout.flush()
                    continue
                wait = min(wait, quiet_left)
            if not select.select([fd], [], [], max(0.01, wait))[0]:
                if time.monotonic() >= next_poll:
                    next_poll = time.monotonic() + max(0.05, interval)
                    if keep_waiting is not None and not keep_waiting():
                        self.stdout.write("\n")
                        self.stdout.flush()
                        return None
                continue
            first = os.read(fd, 1)
            if not first:
                raise ApprovalError("the terminal closed; nothing was decided")
            data = self._burst(fd, first)
            was_open = self._string_open()
            lone = self._feed(data)
            if (was_open or self._string_open()) and not told:
                told = True
                self.say("\n(input ignored: a terminal control string is open)")
                self.stdout.write(prompt)
                self.stdout.flush()
            if not lone:
                continue  # an escape sequence (arrow, function or Alt key), a part of one, or a paste
            answer = chr(data[0])
            if answer in choices:  # exact: no case folding, so an uppercase letter never decides
                self.stdout.write(answer + "\n")
                self.stdout.flush()
                return answer


# --- Enterprise step-up ------------------------------------------------------------------------


class StepUp:
    """The gateway's step-up routes (G1). Nothing here falls back to the engine."""

    def __init__(self, send: Send, origin: str, terminal: Terminal, *, account: str | None = None,
                 method: str | None = None) -> None:
        self.send = send
        self.origin = origin.rstrip("/")
        self.terminal = terminal
        self.account = (account or "").strip() or None
        self.method = method.replace("-", "_") if method else None
        # What the person is told at the touch (decide() names what it decides); None: the
        # assertion's own words.
        self.prompt: str | None = None
        # The gateway named the approver (no --account): the person this connection acts for,
        # whom the touch prompt then names ("..., as alice").
        self.named = False

    def _names_no_approver(self) -> bool:
        """Whether this gateway predates an approval that names its own approver: it refuses an
        empty sign-in name as request_invalid (422), and its own description of itself (GET
        /_enterprise/me, which every Enterprise gateway serves to a token) does not report
        ``person_decision_proof``. Anything but a gateway that says it is newer counts as older,
        so the person is asked for the name rather than left with a refusal."""
        return not gateway_features(self.send)["names_approver"]

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
            raise GatewayRefused(f"the gateway refused ({code}, HTTP {status}): {_detail_text(body)}",
                                 code=code, status=status)
        return dict(body)

    def begin(self, purpose: str, body: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
        """Begin an approval. Without ``--account`` the approver is the person this connection's
        token acts for: the gateway names them in its answer, and the set document is checked with
        that name. A gateway that needs a name (a token that acts for nobody, or one that predates
        this) is answered by asking for it."""
        parts = {key: value for key, value in set_document(purpose, "", self.origin, body).items()
                 if key in {"decisions", "preauthorization", "session", "knowledge", "key_check"}}

        def post(account: str) -> dict[str, Any]:
            return self._post(BEGIN_PATH, {
                "schema_version": "shakerscan-approval-begin/v1", "purpose": purpose,
                "account": account, "origin": self.origin, **parts,
            })

        if not self.account and self._names_no_approver():
            # A gateway from before the approver was named (it does not report
            # person_decision_proof) refuses an empty sign-in name and audits the refusal: ask
            # for the name first, as client 0.11.1 always did, instead of posting it empty.
            self._account()
        if self.account:
            challenge = post(self.account)
        else:
            try:
                challenge = post("")
            except GatewayRefused as exc:
                # A token that acts for nobody (account_required), or a gateway from before the
                # approver was named (it refuses the empty name as request_invalid): ask for it.
                # A gateway that names the approver refuses request_invalid for another reason,
                # which is said as it is.
                if exc.status != 422 or exc.code not in {"account_required", "request_invalid"}:
                    raise
                if exc.code == "request_invalid" and not self._names_no_approver():
                    raise
                challenge = post(self._account())
            named = challenge.get("account")
            if not self.account:
                if not isinstance(named, str) or not named.strip() or len(named) > 200:
                    raise ApprovalError("the gateway's challenge names no approver; nothing was approved")
                self.account = named
                # The proof asked for is this person's (a token that acts for another person than
                # the one at the keyboard approves as that person, unless --account): the prompt
                # names them at the moment of the proof ("TOTP code for alice", "Touch your
                # security key ..., as alice"), not in a line of its own on every run.
                self.named = True
        account = self.account
        document = set_document(purpose, account, self.origin, body)
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
        """A TOTP code, security-key assertion, or browser confirmation of this exact set."""
        methods = [str(item) for item in challenge.get("methods") or ()]
        method = self.method_for(challenge)
        if method not in methods:
            raise ApprovalError(
                f"your account offers {', '.join(methods) or 'no step-up method'} for this approval, not "
                f"{method or 'any this client supports'}; enrol TOTP or a security key in the console"
            )
        if method == "sso":
            sso = challenge.get("sso")
            url = str(sso.get("authorize_url") or "") if isinstance(sso, Mapping) else ""
            parsed, origin = urllib.parse.urlsplit(url), urllib.parse.urlsplit(self.origin)
            if (
                (parsed.scheme, parsed.netloc) != (origin.scheme, origin.netloc)
                or parsed.username or parsed.password or parsed.query or parsed.fragment
                or not re.fullmatch(r"/_enterprise/approvals/browser/[A-Za-z0-9_-]{40,100}", parsed.path)
            ):
                raise ApprovalError("the browser approval URL is not on this gateway; nothing was approved")
            self.terminal.say("Open this link in your browser, review the exact decision, and sign in again:")
            self.terminal.say(url)
            self.terminal.say(f"Approval digest: {challenge['set_digest']}")
            self.terminal.line("Press Enter after the browser confirms your sign-in: ")
            status = self._post("/_enterprise/approvals/sso/status", {
                "schema_version": "shakerscan-approval-finish/v1",
                "approval_id": challenge["approval_id"], "set_digest": challenge["set_digest"],
                "proof": {},
            })
            if status.get("state") != "granted":
                raise ApprovalError(
                    "the browser sign-in is not confirmed or has expired; nothing was approved; "
                    "finish sign-in and retry the command"
                )
            return {"method": "sso"}
        if method == "totp":
            code = self.terminal.secret(f"TOTP code for {self.account} (never type it into an agent's chat): ")
            if not _TOTP.fullmatch(code):
                raise ApprovalError("a TOTP code is 6 to 8 digits; nothing was approved")
            return {"method": "totp", "code": code}
        webauthn = challenge.get("webauthn") if isinstance(challenge.get("webauthn"), Mapping) else {}
        nonce = str(challenge.get("nonce") or "")
        if not webauthn or not nonce or webauthn.get("challenge") != expected_challenge(nonce, challenge["set_digest"]):
            raise ApprovalError("the gateway's security-key challenge is not bound to this approval; nothing was approved")
        prompt = self.prompt
        if self.named and self.account:
            prompt = as_approver(prompt or "Touch your security key.", self.account)
        told = {"prompt": prompt} if prompt else {}
        return {"method": "security_key",
                "credential": security_key_assertion(webauthn, self.origin, self.terminal, **told)}

    def method_for(self, challenge: Mapping[str, Any]) -> str:
        methods = [str(item) for item in challenge.get("methods") or ()]
        webauthn = challenge.get("webauthn") if isinstance(challenge.get("webauthn"), Mapping) else None
        return self.method or preferred_method(methods, webauthn, self.origin)


def as_approver(prompt: str, account: str) -> str:
    """The touch prompt naming whom the touch approves as: "Touch your security key to allow, as
    alice (Ctrl-C to cancel)..."."""
    who = f", as {_inert(account)[:120]}"
    for tail in (" (Ctrl-C to cancel)...", "."):
        if prompt.endswith(tail):
            return prompt[: -len(tail)] + who + tail
    return prompt + who


def _homebrew_install() -> bool:
    return "/Cellar/shakerscan/" in os.path.realpath(__file__)


def fido2_declared(platform: str | None = None, machine: str | None = None) -> bool:
    """Whether the client package installs python-fido2 here (client/pyproject.toml): macOS, and
    64-bit Linux, where its cryptography dependency publishes wheels."""
    import platform as _platform

    platform = sys.platform if platform is None else platform
    machine = _platform.machine() if machine is None else machine
    return platform == "darwin" or (platform.startswith("linux") and machine in {"x86_64", "aarch64"})


def _no_fido2() -> str:
    if _homebrew_install():
        return ("this Homebrew install of the client has no security-key support (python-fido2 is not "
                "in the formula): install the client with pipx (pipx install shakerscan) or uv (uv tool "
                "install shakerscan), which carry it")
    if not fido2_declared():
        return ("the client installs without python-fido2 on this platform (its cryptography dependency "
                "publishes no wheel for it, and on Windows the terminal touch is not supported yet): "
                "pipx inject shakerscan fido2 adds it where a cryptography wheel or a Rust toolchain exists")
    return ("a security key needs python-fido2 beside the client: reinstall the client (0.11.2 and later "
            "carry it), or pipx inject shakerscan fido2 (or pip install fido2)")


def remote_session(environ: Mapping[str, str] | None = None) -> bool:
    """Whether this terminal is a remote (SSH) session, where a key plugged into the computer the
    person connects from is out of reach."""
    environ = os.environ if environ is None else environ
    return bool((environ.get("SSH_CONNECTION") or environ.get("SSH_TTY") or "").strip())


REMOTE_NO_KEY = (
    "no USB security key found: this terminal is a remote (SSH) session, and a key plugged into the "
    "computer you connect from is out of reach here; run the command on that computer, with a "
    "connection of its own that acts for you"
)
WSL_NO_KEY = (
    "no USB security key found: this terminal runs in WSL, which sees a USB key only when it is "
    "passed through (usbipd attach); pass the key through, or run the command where the key is "
    "plugged in, with a connection of its own that acts for you"
)
CONTAINER_NO_KEY = (
    "no USB security key found: this terminal runs in a container, which sees a USB key only when "
    "the container is given the device; run the command on the computer the key is plugged into, "
    "with a connection of its own that acts for you"
)


def key_out_of_reach(environ: Mapping[str, str] | None = None, *, root: str = "/") -> str:
    """Why a key plugged in by the person cannot arrive in this terminal, or "": a remote (SSH)
    session, WSL (whose Linux sees a USB key only when it is passed through) or a container. Then
    no key listed means none will be (the client says why at once instead of waiting for an
    insertion). mosh and other remote shells are not recognized: the wait names them."""
    environ = os.environ if environ is None else environ
    if remote_session(environ):
        return REMOTE_NO_KEY
    if not sys.platform.startswith("linux") and root == "/":
        return ""
    if environ.get("WSL_DISTRO_NAME") or environ.get("WSL_INTEROP"):
        return WSL_NO_KEY
    try:
        with open(os.path.join(root, "proc/sys/kernel/osrelease"), encoding="utf-8") as release:
            if "microsoft" in release.read(200).lower():
                return WSL_NO_KEY
    except OSError:
        pass
    if any(os.path.exists(os.path.join(root, marker)) for marker in (".dockerenv", "run/.containerenv")):
        return CONTAINER_NO_KEY
    return ""


# The report-descriptor item that names the FIDO Alliance usage page (0xF1D0): every FIDO
# security key's HID interface declares it.
FIDO_USAGE_PAGE = b"\x06\xd0\xf1"
UNOPENABLE_KEY = (
    "a security key is plugged in that this user may not open: log in at the desktop (systemd 244 "
    "and later let a desktop session open it), or install your distribution's FIDO udev rules "
    "(libu2f-udev on Debian and Ubuntu, u2f-hidraw-policy on Fedora; with no desktop session, a "
    "rule for your group: see the client guide), then run the command again (over SSH a key on "
    "your laptop is out of reach)"
)
MAYBE_UNOPENABLE = (
    " (if your key is plugged in, this user may not be allowed to open it: log in at the desktop, "
    "or install your distribution's FIDO udev rules, libu2f-udev on Debian and Ubuntu or "
    "u2f-hidraw-policy on Fedora; over SSH a key on your laptop is out of reach)"
)


def unopenable_keys(*, root: str = "/") -> str:
    """On Linux, a plugged-in key this user cannot open, which python-fido2 leaves out of its list
    (it lists only the devices it can open, so such a key looks unplugged): "fido" when a
    /dev/hidraw node this user may not read and write is a FIDO key (its report descriptor, which
    sysfs lets anyone read, names the FIDO usage page), "maybe" when such a node's kind cannot be
    read, else "" (a keyboard's or touchpad's node is not a key)."""
    if not sys.platform.startswith("linux"):
        return ""
    import glob

    found = ""
    for node in sorted(glob.glob(os.path.join(root, "dev/hidraw*"))):
        if os.access(node, os.R_OK | os.W_OK):
            continue
        described = os.path.join(root, "sys/class/hidraw", os.path.basename(node), "device/report_descriptor")
        try:
            with open(described, "rb") as handle:
                descriptor = handle.read(4096)
        except OSError:
            found = found or "maybe"
            continue
        if FIDO_USAGE_PAGE in descriptor:
            return "fido"
    return found


def _no_device(*, root: str = "/") -> str:
    """No key found: over SSH, where the key is; on Linux, a plugged-in key this user cannot open
    (said plainly when its node is a FIDO key, as a possibility when its kind cannot be read)."""
    if reason := key_out_of_reach():
        return reason
    kind = unopenable_keys(root=root)
    if kind == "fido":
        return UNOPENABLE_KEY
    text = "no USB security key found; insert it and run the command again"
    return text + (MAYBE_UNOPENABLE if kind == "maybe" else "")


def security_key_readiness(*, waiting: bool = False) -> str:
    """Why no key could answer here (python-fido2 missing, no key plugged in), or "". With
    ``waiting``, a key that is only not plugged in yet is no reason in a local terminal (the
    assertion waits for it to be inserted); over SSH it still is (it cannot arrive)."""
    try:
        from fido2.hid import CtapHidDevice
    except ImportError:
        return _no_fido2()
    if waiting and not key_out_of_reach():
        return ""
    try:
        found = next(iter(CtapHidDevice.list_devices()), None)
    except Exception:  # no HID access, or a platform the library does not serve
        found = None
    return "" if found is not None else _no_device()


# While waiting for a key to be inserted: how often the USB devices are listed again.
INSERT_POLL_SECONDS = 0.5


def wait_for_key(list_devices: Callable[[], Any], terminal: "Terminal", seconds: float,
                 *, sleep: Callable[[float], None] | None = None,
                 clock: Callable[[], float] | None = None, root: str = "/") -> list[Any]:
    """The plugged-in keys, after waiting up to ``seconds`` for one to be inserted (a key kept on
    a keyring costs no second run of the command); the person is told once, and Ctrl-C cancels.
    None in time: ApprovalError. On Linux a key this user cannot open is said at once (waiting
    cannot help), and a device of unknown kind it cannot open is named while waiting and after."""
    sleep = sleep or time.sleep
    clock = clock or time.monotonic
    try:
        devices = list(list_devices())
    except Exception:
        devices = []
    if devices:
        return devices
    if reason := key_out_of_reach():
        raise ApprovalError(reason)
    kind = unopenable_keys(root=root)
    if kind == "fido":
        raise ApprovalError(UNOPENABLE_KEY)
    hint = MAYBE_UNOPENABLE if kind == "maybe" else ""
    terminal.say(f"Insert your security key (Ctrl-C to cancel; waiting up to {int(seconds)} seconds){hint}...")
    deadline = clock() + max(0.0, seconds)
    while clock() < deadline:
        sleep(INSERT_POLL_SECONDS)
        try:
            devices = list(list_devices())
        except Exception:
            devices = []
        if devices:
            return devices
    # Said only now, not at every local prompt: a key plugged into another computer never arrives
    # over mosh or another remote shell the client cannot recognize (SSH, WSL and containers are
    # said at once, key_out_of_reach).
    raise ApprovalError(f"no USB security key was inserted within {int(seconds)} seconds{hint}; nothing "
                        "was decided (insert it and run the command again; a key plugged into another "
                        "computer cannot reach this terminal over mosh or another remote shell)")


def security_keys_present() -> bool:
    """Whether python-fido2 is importable and at least one USB security key is plugged in."""
    return not security_key_readiness()


def _credential_ids(webauthn: Mapping[str, Any] | None) -> list[bytes]:
    return [
        _b64url_decode(str(item["id"]))
        for item in (webauthn or {}).get("allowCredentials") or ()
        if isinstance(item, Mapping) and item.get("id")
    ]


def rp_id_valid(rp_id: str, origin: str) -> bool:
    """Whether a WebAuthn relying party id may be used from this origin (python-fido2's own check,
    the one its client applies to the assertion itself)."""
    try:
        from fido2.rpid import verify_rp_id
    except ImportError:
        return False
    try:
        return bool(rp_id) and bool(origin) and bool(verify_rp_id(rp_id, origin))
    except Exception:
        return False


def probe_device(device: Any, webauthn: Mapping[str, Any] | None, origin: str = "") -> str:
    """Whether this key can answer the challenge, asked silently (user presence off, so the key
    does not wait for a touch): "yes" (it holds one of the person's keys), "no" (it holds none),
    "no_pin" (the gateway asks for the key's PIN and this key has none), "pin_only" (the gateway
    asks for a touch alone, and the key has a PIN but answers nothing without it: it may hold a
    passkey a browser made to need the PIN for every use, which the assertion then asks with its
    PIN), or "unknown" (a key that cannot be asked this way, such as a U2F-only key; the touch
    itself then tells).

    Only for a relying party id valid for the connection's ``origin`` (rp_id_valid): a gateway
    could otherwise learn, from what the client does next, whether the key holds a credential of
    another site. Without a valid one the key is not asked, and the assertion (which checks the
    same) refuses."""
    if not rp_id_valid(str((webauthn or {}).get("rpId") or ""), origin):
        return "unknown"
    try:
        from fido2.ctap import CtapError
        from fido2.ctap2 import Ctap2
        ctap2 = Ctap2(device)
        info = ctap2.info
    except Exception:
        return "unknown"
    options = getattr(info, "options", None) or {}
    requirement = str((webauthn or {}).get("userVerification") or "required")
    verifies = bool(options.get("clientPin") or options.get("uv"))
    if requirement == "required" and not verifies:
        return "no_pin"
    ids = _credential_ids(webauthn)
    rp_id = str((webauthn or {}).get("rpId") or "")
    if not ids or not rp_id:
        return "unknown"
    longest = getattr(info, "max_cred_id_length", None)
    listed = [{"type": "public-key", "id": item} for item in ids if not longest or len(item) <= longest]
    size = max(1, int(getattr(info, "max_creds_in_list", None) or 1))
    for start in range(0, len(listed), size):
        try:
            ctap2.get_assertion(rp_id, b"\0" * 32, listed[start:start + size], options={"up": False})
            return "yes"
        except CtapError as exc:
            if exc.code != CtapError.ERR.NO_CREDENTIALS:
                return "unknown"
        except Exception:
            return "unknown"
    if requirement in {"required", "preferred"} and verifies:
        # A credential a browser made to need the key's PIN for every use (credProtect) is not
        # found without it; the gateway asks for the PIN here, so the assertion, with it, decides.
        return "unknown"
    if verifies:
        # The same credential, where the gateway asks for a touch only: it is asked with its PIN
        # (a PIN-verified assertion is user presence too), not called unregistered.
        return "pin_only"
    return "no"


def eligible_devices(devices: Sequence[Any], webauthn: Mapping[str, Any] | None,
                     origin: str = "") -> tuple[list[Any], str]:
    """The plugged-in keys that can answer, and why none can when the list is empty
    (answering_keys, without whether the PIN is asked)."""
    found, why, _ = answering_keys(devices, webauthn, origin)
    return found, why


def answering_keys(devices: Sequence[Any], webauthn: Mapping[str, Any] | None,
                   origin: str = "") -> tuple[list[Any], str, bool]:
    """The plugged-in keys that can answer, why none can when the list is empty, and whether they
    are asked with their PIN where the gateway asks for a touch only: the first key that holds one
    of the person's credentials (any of them answers, so nobody is asked to pick among keys that
    all can), else every key that could not be asked (the person picks), else every key with a
    PIN that answered nothing without it (asked with the PIN: a passkey made to need it for every
    use answers then)."""
    found = [(device, probe_device(device, webauthn, origin)) for device in devices]
    holding = [device for device, status in found if status == "yes"]
    unknown = [device for device, status in found if status == "unknown"]
    with_pin = [device for device, status in found if status == "pin_only"]
    if holding:
        return holding[:1], "", False
    if unknown:
        return unknown, "", False
    if with_pin:
        return with_pin, "", True
    if any(status == "no_pin" for _, status in found):
        return [], ("this security key has no PIN, and this approval asks for the key's PIN: set one "
                    "(for a YubiKey: ykman fido access change-pin), or approve with --method totp where "
                    "the gateway offers it"), False
    return [], ("the security key plugged in holds none of your keys: it is not registered to your "
                "account; use the key you registered, or add this one under My account in the "
                "Enterprise console (a local account: Passkeys, \"Use it: for terminal approvals "
                "(touch)\"; single sign-on: \"Security key for terminal decisions\")"), False


def preferred_method(methods: Sequence[str], webauthn: Mapping[str, Any] | None = None, origin: str = "") -> str:
    """The proof to give when ``--method`` is not named: the security key whenever the gateway
    offers one, python-fido2 is installed and a plugged-in key holds one of the person's keys for
    this challenge (asked silently: nothing blinks), with the administrator's touch switch on or
    off (a touch, with no PIN, wherever the gateway asks only for user presence; an earlier
    gateway asks the key's PIN, as at sign-in), never a 6-digit code while a key can answer;
    also when a key is the only proof offered. A TOTP code only when no key can answer here (none
    plugged in, none registered, or the gateway asks for a PIN the key has none for); for a
    single sign-on person the browser sign-in then. ``--method totp`` still chooses the code."""
    if "security_key" in methods and security_keys_present():
        if "totp" in methods:
            # Only a key that says it holds one of the person's credentials: a code is there to
            # fall back on (and with no challenge to ask about, the code).
            if webauthn is not None and _key_answers_here(webauthn, origin, unknown_counts=False):
                return "security_key"
        elif len(methods) == 1 or webauthn is None or _key_answers_here(webauthn, origin):
            # No code to fall back on: a key that could not be asked silently (a U2F-only key,
            # or a credential that answers only after its PIN) is tried too.
            return "security_key"
    # No key can answer here: the code, else the browser sign-in, are the fallbacks; a key the
    # gateway offers alone is still asked (insert it when told).
    for method in ("totp", "sso", "security_key"):
        if method in methods:
            return method
    return ""


def _key_answers_here(webauthn: Mapping[str, Any], origin: str = "", *, unknown_counts: bool = True) -> bool:
    """Whether a plugged-in key holds one of the person's credentials for this challenge (probe
    "yes"), or, with ``unknown_counts``, could not be asked silently (probe "unknown")."""
    try:
        from fido2.hid import CtapHidDevice
        found = [probe_device(device, webauthn, origin) for device in CtapHidDevice.list_devices()]
    except Exception:
        return False
    return "yes" in found or (unknown_counts and "unknown" in found)


def _device_name(device: Any) -> str:
    descriptor = getattr(device, "descriptor", None)
    name = getattr(descriptor, "product_name", None) or getattr(device, "product_name", None)
    serial = getattr(descriptor, "serial_number", None)
    where = getattr(descriptor, "path", None)
    text = str(name or "security key") + (f", serial {serial}" if serial else f" at {where}" if where else "")
    return _inert(text)[:100]


def choose_device(devices: Sequence[Any], terminal: Terminal) -> Any:
    """The key to ask: the only one that can answer, or, among keys that could not be asked
    silently (eligible_devices), the one the person picks by number."""
    if len(devices) == 1:
        return devices[0]
    terminal.say("Several security keys are plugged in, and none could be asked which one is yours:")
    for number, device in enumerate(devices, 1):
        terminal.say(f"  {number}) {_device_name(device)}")
    answer = terminal.line(f"Which one is registered to your account? [1-{len(devices)}]: ")
    if not answer.isdigit() or not 1 <= int(answer) <= len(devices):
        raise ApprovalError("no security key chosen; nothing was approved")
    return devices[int(answer) - 1]


def key_failure(exc: BaseException) -> str:
    """What a python-fido2 error means, in plain words (its own text names an enum)."""
    code = getattr(getattr(exc, "code", None), "name", "")
    cause = getattr(exc, "cause", None)
    cause_code = getattr(getattr(cause, "code", None), "name", "") or code
    if code == "DEVICE_INELIGIBLE" or cause_code == "NO_CREDENTIALS":
        return ("this security key is not registered to your account: use the key you registered, or "
                "add this one under My account in the Enterprise console")
    if code == "TIMEOUT" or cause_code in {"USER_ACTION_TIMEOUT", "ACTION_TIMEOUT", "KEEPALIVE_CANCEL"}:
        return "no touch in time"
    if cause_code in {"PIN_BLOCKED", "PIN_AUTH_BLOCKED"}:
        return "the key's PIN is blocked after wrong PINs: remove and insert the key, or reset its PIN"
    if cause_code == "PIN_INVALID":
        return "the PIN was not accepted (the key's own PIN, not an authenticator code; each wrong PIN costs a try)"
    if code == "CONFIGURATION_UNSUPPORTED" or cause_code in {"PIN_NOT_SET", "UNSUPPORTED_OPTION"}:
        return ("this key cannot do what the approval asks (its PIN): set a PIN on the key (for a "
                "YubiKey: ykman fido access change-pin), or approve with --method totp where offered")
    if cause_code == "OPERATION_DENIED":
        return "the key declined"
    return "the security key did not answer as expected"


def pin_retries(device: Any) -> int | None:
    """How many wrong PINs the key still takes before it blocks its PIN, as the key says
    (CTAP2 getPinRetries: a silent command, nothing blinks); None when it does not say."""
    try:
        from fido2.ctap2 import Ctap2
        from fido2.ctap2.pin import ClientPin

        retries = ClientPin(Ctap2(device)).get_pin_retries()[0]
    except Exception:  # an older key, a U2F-only key, or a library without the command
        return None
    return retries if type(retries) is int and 0 <= retries <= 255 else None


def pin_notice(retries: int | None) -> str:
    """What the person is told before a security key's PIN is asked for: it is the key's own PIN
    (the one set on the key, as at sign-in), not the 6-digit code of an authenticator app, and
    how many tries are left; each wrong PIN costs one, and a blocked PIN is reset only by
    resetting the key, which removes every credential on it, other sites' passkeys included."""
    text = ("This approval asks for your security key's own PIN (the one set on the key), not your "
            "authenticator app's code; --method totp approves with the code instead, where you enrolled one.")
    if retries is None:
        return text
    if retries <= 3:
        return (text + f" Only {retries} PIN {'try is' if retries == 1 else 'tries are'} left before the key "
                "blocks its PIN; unblocking it resets the key and removes every credential on it.")
    return text + f" {retries} PIN tries are left."


def security_key_assertion(webauthn: Mapping[str, Any], origin: str, terminal: Terminal, *,
                           prompt: str = "Touch your security key.",
                           insert_seconds: float = 60.0) -> dict[str, Any]:
    """A WebAuthn assertion from a USB/NFC security key over CTAP2 (python-fido2).

    Platform authenticators (Touch ID, Windows Hello, synced passkeys) are not reachable from a
    pip-installed command, so only a roaming key is used. User verification is what the gateway
    asks for (``userVerification``): ``required`` (the key's PIN is asked for here, as at sign-in)
    or, when an administrator requires a touch for each decision, ``discouraged`` (a touch, no
    PIN). A gateway that names none asks for ``required``."""
    try:
        from fido2.client import Fido2Client, UserInteraction
        from fido2.hid import CtapHidDevice
        from fido2.webauthn import (
            PublicKeyCredentialDescriptor, PublicKeyCredentialRequestOptions,
            PublicKeyCredentialType, UserVerificationRequirement,
        )
    except ImportError as exc:
        raise ApprovalError(_no_fido2() + "; or approve with a TOTP code where the gateway offers one "
                            "(--method totp)") from exc
    # A key not plugged in yet is waited for (bounded, within the challenge's life).
    devices = wait_for_key(CtapHidDevice.list_devices, terminal, insert_seconds)
    # Asked silently first, so the key that blinks is one that can answer, and the person picks
    # among those before being told to touch.
    candidates, why, with_pin = answering_keys(devices, webauthn, origin)
    if not candidates:
        raise ApprovalError(why)
    device = choose_device(candidates, terminal)
    requirement = str(webauthn.get("userVerification") or "required")
    if requirement not in {"required", "preferred", "discouraged"}:
        requirement = "required"
    if with_pin and requirement == "discouraged":
        # Nothing on the key answers a touch alone: a passkey a browser made to need its PIN for
        # every use answers with it (the gateway accepts a PIN-verified touch), so the PIN is asked
        # once instead of the key being called unregistered.
        terminal.say("This security key answers nothing to a touch alone: it is not registered to your account, "
                     "or it holds a passkey that answers only after the key's PIN. To try it, enter the key's "
                     "PIN, then touch it (Ctrl-C to cancel).")
        requirement = "required"

    # A touch alone (no PIN): told now, once the key is chosen. With a PIN: after it is typed.
    told = [requirement == "discouraged"]
    if prompt and told[0]:
        terminal.say(prompt)

    class Interaction(UserInteraction):  # type: ignore[misc,valid-type]
        def prompt_up(self) -> None:
            if prompt and not told[0]:
                told[0] = True
                terminal.say(prompt)

        def request_pin(self, permissions: Any, rp_id: Any) -> str:  # noqa: ARG002
            # Said before the prompt: someone used to typing an authenticator code here (client
            # 0.11.1 asked for one) would spend one of the key's PIN tries on it.
            terminal.say(pin_notice(pin_retries(device)))
            return terminal.secret("Security key PIN (not your authenticator code): ")

        def request_uv(self, permissions: Any, rp_id: Any) -> bool:  # noqa: ARG002
            return True

    options = PublicKeyCredentialRequestOptions(
        challenge=_b64url_decode(str(webauthn["challenge"])),
        rp_id=str(webauthn.get("rpId") or ""),
        allow_credentials=[
            PublicKeyCredentialDescriptor(type=PublicKeyCredentialType.PUBLIC_KEY, id=_b64url_decode(str(item["id"])))
            for item in webauthn.get("allowCredentials") or () if isinstance(item, Mapping) and item.get("id")
        ] or None,
        user_verification=UserVerificationRequirement(requirement),
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
        raise ApprovalError(f"the security key did not sign: {key_failure(exc)}") from exc
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
    if budget := safety_budget_words(challenge.get("safety_budget")):
        # Under the administrator's touch switch, what this one touch approves besides the bounds:
        # the one safety budget every Hunt of the agent session shares (the gateway's words).
        terminal.say(f"Every Hunt this agent session starts shares one safety budget: {budget}.")
        terminal.say("A Hunt start past what is left, or a raise past it, asks you again.")
    result = stepup.finish(challenge, stepup.prove(challenge))
    grant = result.get("preauthorization") if isinstance(result.get("preauthorization"), Mapping) else {}
    if not grant.get("id"):
        raise ApprovalError("the gateway answered without a pre-authorization id; nothing was pre-authorized")
    return dict(grant)


def safety_budget_words(lines: Any) -> str:
    """An agent session's safety budget as the gateway named it (each ceiling's label and total),
    in one line; "" when the gateway named none (the switch is off, or an earlier gateway)."""
    if not isinstance(lines, list):
        return ""
    words = []
    for item in lines[:6]:
        if not isinstance(item, Mapping) or type(item.get("total")) is not int:
            continue
        words.append(f"{_inert(str(item.get('label') or item.get('limit') or ''))[:40]} {item['total']:,}")
    return ", ".join(words)


# --- knowledge-review decisions ----------------------------------------------------------------

HEALTH_PATH = "/_enterprise/healthz"


def instance_kind(send: Send) -> str:
    """"enterprise" or "local", as the server says, never inferred from whether this connection
    holds a token: an Enterprise gateway answers GET /_enterprise/healthz with mode "enterprise";
    an open-source engine has no such route (404). Anything else is refused: the client cannot
    tell, so it decides nothing."""
    status, body = send("GET", HEALTH_PATH)
    if _ok(status) and isinstance(body, Mapping) and body.get("mode") == "enterprise":
        return "enterprise"
    if status == 404 or (_ok(status) and not (isinstance(body, Mapping) and "mode" in body)):
        return "local"
    raise ApprovalError(f"cannot tell what kind of instance this is (GET {HEALTH_PATH} answered HTTP {status}); "
                        "nothing was decided")



def knowledge_entry(decision: str, target_id: str, *, subject_id: str | None = None,
                    text_sha256: str | None = None, expected_revision: int | None = None,
                    reason: str | None = None, note: str | None = None,
                    release_label: str | None = None, released_at: str | None = None) -> dict[str, Any]:
    """One knowledge-review decision as the step-up binds it. ``accept`` names the proposal
    (``subject_id``) and the digest of its text, with an optional note; ``confirm`` the digest of
    the unconfirmed text and the instructions' revision; ``allow_changes`` the Hunt permissions'
    revision; ``dismiss`` the finding, a reason and a note; ``reopen`` the finding and a note;
    ``retract`` the interpretation entry and a note; ``retract_hunt`` the Hunt and a note."""
    if decision not in KNOWLEDGE_DECISIONS:
        raise ApprovalError(f"unknown knowledge decision {decision!r}")
    target = str(target_id or "").strip().lower()
    if not _UUID.fullmatch(target):
        raise ApprovalError(f"{target_id!r} is not a target id")
    subject = str(subject_id or "").strip().lower() or None
    digest = str(text_sha256 or "").strip() or None
    if decision == "release_marker":
        if release_label is not None and (not isinstance(release_label, str) or not release_label.strip()
                                          or len(release_label) > 120 or _inert(release_label) != release_label):
            raise ApprovalError("release label must be one readable line, at most 120 characters")
        if released_at is not None:
            try:
                from datetime import datetime
                if datetime.fromisoformat(released_at.replace('Z', '+00:00')).tzinfo is None:
                    raise ValueError('timezone required')
            except (ValueError, TypeError, AttributeError) as exc:
                raise ApprovalError("released_at must be an ISO timestamp with a timezone") from exc
        bound = {"label": release_label, "released_at": released_at}
        digest = hashlib.sha256(json.dumps(bound, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()
    elif release_label is not None or released_at is not None:
        raise ApprovalError("only a release marker carries release fields")
    if decision in KNOWLEDGE_SUBJECT and (subject is None or not _UUID.fullmatch(subject)):
        raise ApprovalError(f"{decision} names the record it decides (an id)")
    if decision not in KNOWLEDGE_SUBJECT and subject is not None:
        raise ApprovalError(f"{decision} names no other record")
    if decision in KNOWLEDGE_TEXT and (digest is None or not re.fullmatch(r"[0-9a-f]{64}", digest)):
        raise ApprovalError("the server did not give the digest of the text shown; nothing was decided")
    if decision not in KNOWLEDGE_TEXT and digest is not None:
        raise ApprovalError(f"{decision} names no text")
    if decision in KNOWLEDGE_REVISION:
        if type(expected_revision) is not int or expected_revision < 0:
            raise ApprovalError("the server did not give the revision that was shown; nothing was decided")
    elif expected_revision is not None:
        raise ApprovalError(f"{decision} is not bound to a revision")
    if (reason is not None) != (decision == "dismiss") or (reason is not None and reason not in DISMISSAL_REASONS):
        raise ApprovalError(f"dismissing names one reason of {', '.join(DISMISSAL_REASONS)}; nothing else does")
    if decision in KNOWLEDGE_NOTE_REQUIRED and not (note or "").strip():
        raise ApprovalError(f"{decision} needs a note (why)")
    if note is not None and (decision not in KNOWLEDGE_NOTE_REQUIRED | {"accept"}
                             or not note or len(note) > MAX_NOTE_CHARACTERS):
        raise ApprovalError(f"a note goes with accept, dismiss, reopen and retract, 1 to {MAX_NOTE_CHARACTERS} "
                            "characters")
    if note is not None and _inert(note.replace("\n", " ")) != note.replace("\n", " "):
        raise ApprovalError("a note may not contain control, bidirectional or invisible formatting characters")
    result = {"decision": decision, "target_id": target, "subject_id": subject, "text_sha256": digest,
              "expected_revision": expected_revision, "reason": reason, "note": note}
    if decision == "release_marker":
        result.update(release_label=release_label, released_at=released_at)
    return result


SECRET_ACTIONS = {"reveal": "show you the value of", "grants": "let another target's Hunts use",
                  "promote": "move into a credential profile"}


def reference_decision(action: str, target_id: str, reference: str, payload: Mapping[str, Any]) -> dict[str, Any]:
    """One decision on a discovered secret (Enterprise 2.10) as the step-up binds it: the exact
    route and body the gateway then sends to the engine as you."""
    if action not in SECRET_ACTIONS:
        raise ApprovalError(f"unknown secret decision {action!r}")
    target, ref_id = str(target_id or "").strip().lower(), str(reference or "").strip().lower()
    if not _UUID.fullmatch(target) or not _UUID.fullmatch(ref_id):
        raise ApprovalError("a secret decision names a target id and a secret id")
    return {"decision": "secret_decision", "method": "POST",
            "path": f"/targets/{target}/discovered-secrets/{ref_id}/{action}", "payload": dict(payload)}


def _knowledge_summary(entry: Mapping[str, Any]) -> str:
    if entry.get("decision") == "secret_decision":
        parts = str(entry.get("path") or "").split("/")
        target, ref_id, action = (parts[2], parts[4], parts[5]) if len(parts) == 6 else ("?", "?", "?")
        extra = entry.get("payload") or {}
        where = f" (to target {extra.get('target_id')})" if action == "grants" else ""
        return (f"Your step-up will {SECRET_ACTIONS.get(action, action)} secret {ref_id} of target "
                f"{target}{where}, and nothing else. If you did not just choose this here, press Ctrl-C.")
    subject = entry.get("subject_id")
    what = {
        "accept": f"accept proposal {subject}",
        "confirm": f"confirm the agent-written instructions at revision {entry.get('expected_revision')}",
        "allow_changes": ("let Hunts edit the instructions (Hunt permissions revision "
                          f"{entry.get('expected_revision')})"),
        "dismiss": f"dismiss finding {subject} as {entry.get('reason')}",
        "reopen": f"reopen finding {subject}",
        "retract": f"retract interpretation {subject}",
        "retract_hunt": f"retract every active interpretation Hunt {subject} wrote",
        "release_marker": f"declare release {entry.get('release_label')!r} at {entry.get('released_at') or 'now'}",
    }[str(entry.get("decision"))]
    digest = f", text {str(entry['text_sha256'])[:12]}" if entry.get("text_sha256") else ""
    return (f"Your step-up will {what} on target {entry.get('target_id')}{digest}, and nothing else. "
            "If you did not just choose this here, press Ctrl-C.")


def decide_knowledge(stepup: "StepUp", entry: Mapping[str, Any]) -> tuple[int, Any]:
    """Enterprise: step up for this one decision; the gateway applies it after the proof and
    answers with the engine's status and body (``(status, body)`` like ``send``)."""
    with stepup.terminal.lines():
        # Said again right where the code is asked for: what this code (or key touch) decides.
        stepup.terminal.say(_knowledge_summary(entry))
        try:
            challenge, _ = stepup.begin("knowledge_decision", {"knowledge": dict(entry)})
        except GatewayRefused as exc:
            if exc.code == "request_invalid" and exc.status == 422:
                raise ApprovalError(
                    "this ShakerScan Enterprise gateway cannot take knowledge-review decisions from the "
                    f"terminal ({exc}); it needs a gateway release with terminal knowledge review. "
                    "Nothing was decided."
                ) from exc
            raise
        proof = stepup.prove(challenge)
        try:
            result = stepup.finish(challenge, proof)
        except (GatewayRefused, StepUpUnavailable):
            raise
        except ApprovalError as exc:  # sent, and no answer: the gateway may have applied it
            raise OutcomeUnknown(f"no answer from the gateway after the step-up ({exc})") from exc
    applied = result.get("knowledge") if isinstance(result.get("knowledge"), Mapping) else {}
    if applied.get("outcome") == "unknown":
        raise OutcomeUnknown(_detail_text(applied.get("error")))
    status = applied.get("http_status")
    if not isinstance(status, int):
        raise ApprovalError("the gateway answered without the decision's outcome; check the review again")
    body = applied.get("result") if _ok(status) else applied.get("error")
    if isinstance(body, Mapping):
        body = {**body, "decided_by": result.get("decided_by")}
    return status, body


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
           session: Mapping[str, Any] | None = None, confirmed: bool = False,
           approver: dict[str, Any] | None = None) -> int:
    """Decide ``requests`` with one proof: one step-up (or the open approver ``session``) on
    Enterprise, one local confirmation on OSS (``confirmed``: the --watch keypress was it).
    ``approver`` receives the account the gateway named as approving (``account``), so a watch
    names it once and passes it to every later decision."""
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
    stepup.named = bool(approver and approver.get("named"))
    challenge, _ = stepup.begin("permission_decision", {"decisions": entries})
    if approver is not None and stepup.account:
        approver["account"] = stepup.account
        approver["named"] = stepup.named
    if session is not None:
        proof = {"method": "approver_session", "session_id": session["session_id"],
                 "session_secret": session["secret"]()}
    else:
        what = "" if len(entries) == 1 else f" these {len(entries)} requests"
        stepup.prompt = f"Touch your security key to {decision}{what} (Ctrl-C to cancel)..."
        proof = stepup.prove(challenge)
    result = stepup.finish(challenge, proof)
    via = str(result.get("decision_via") or "terminal_stepup").replace("_", " ")
    webauthn = challenge.get("webauthn") if isinstance(challenge.get("webauthn"), Mapping) else {}
    if proof.get("method") == "security_key" and webauthn.get("userVerification") == "discouraged":
        via = "security-key touch"  # the gateway asked a touch only (user presence, no PIN)
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
    terminal.require(person_runs="shakerscan approve --watch" + (f" --hunt {shlex.quote(hunt_id)}" if hunt_id else ""))
    seconds = max(60, min(int(minutes) * 60, SESSION_SECONDS))
    opened_session: dict[str, Any] = {}
    # Installed before the step-up, so no moment leaves an opened approver session unrevoked.
    restore_signals = _signals_end_the_watch()
    try:
        return _watch(send, terminal, enterprise=enterprise, origin=origin, hunt_id=hunt_id, seconds=seconds,
                      account=account, method=method, poll_seconds=poll_seconds, sleep=sleep, opened=opened_session)
    except KeyboardInterrupt as exc:
        if enterprise and not opened_session:
            with contextlib.suppress(OSError, ValueError):
                terminal.say("\nstopped; no approver session was opened")
        else:
            with contextlib.suppress(OSError, ValueError):
                terminal.say("\n" + ("approver session ended" if enterprise else "stopped watching for permission requests"))
        # Ctrl-C is the person ending the watch (0); a signal from elsewhere exits 128+N.
        return 128 + exc.signum if isinstance(exc, Terminated) else 0
    finally:
        restore_signals()
        if opened_session:
            _revoke(send, terminal, opened_session["session_id"], opened_session["secret"])


def _watch(send: Send, terminal: Terminal, *, enterprise: bool, origin: str, hunt_id: str | None, seconds: int,
           account: str | None, method: str | None, poll_seconds: float, sleep: Callable[[float], None],
           opened: dict[str, Any]) -> int:
    """The watch itself; ``opened`` receives the approver session the moment it exists.

    When the gateway's administrator requires a security-key touch for each decision, the gateway
    opens no approver session (``touch_required``): the watch then asks for one touch per
    decision (``allow a[l]l`` decides every request shown with one touch)."""
    session: dict[str, Any] | None = None
    touch_mode = False
    if enterprise:
        stepup = StepUp(send, origin, terminal, account=account, method=method)
        try:
            challenge, _ = stepup.begin("approver_session", {"session": {"ttl_seconds": seconds}})
        except GatewayRefused as exc:
            if exc.code != "touch_required":
                raise
            touch_mode = True
            terminal.say("Each decision is one touch of your security key (required on this installation).")
            unready = security_key_readiness()
            if unready and "python-fido2" in unready:
                raise ApprovalError(unready + "; nothing was decided")
            if unready:
                terminal.say(f"note: {unready.split(';')[0]}; plug it in before you decide")
        else:
            answer = stepup.finish(challenge, stepup.prove(challenge)).get("session") or {}
            if not answer.get("session_id") or not answer.get("session_secret"):
                raise ApprovalError("the gateway answered without an approver session; nothing was opened")
            session = {"session_id": str(answer["session_id"]), "secret": _HeldSecret(str(answer["session_secret"]))}
            opened.update(session)
            terminal.say(f"approver session open until {answer.get('expires_at') or f'{seconds // 60} minutes from now'} "
                         "(held in this process only; Ctrl-C ends it)")
        account = stepup.account
    # Who approves: named by the gateway at the first decision of a touch-mode watch (whose
    # approver session it refused before naming anyone), then passed to every later one, so it is
    # said once and the gateway's description is not read again for each decision.
    approver: dict[str, Any] = {"account": account}
    # Only a gateway that says it serves the feed is read (an older one would audit a refusal).
    decisions_elsewhere = (
        PersonDecisionFeed(send) if enterprise and gateway_features(send)["names_approver"] else None
    )
    deadline = time.monotonic() + seconds
    seen: set[str] = set()
    retry: list[dict[str, Any]] = []
    where = f"Hunt {hunt_id}" if hunt_id else "every open Hunt"
    # O2: on an open-source engine nothing was printed until a request arrived, and the end said
    # "approver session ended" although there is no session there.
    ended = "approver session ended" if enterprise else "stopped watching for permission requests"

    ended_prompt: list[str] = []  # what replaced the last prompt, announced with the next one

    def still_pending(request: Mapping[str, Any]) -> Callable[[], bool]:
        """Asked while the prompt waits: the watch keeps polling the request it shows."""
        def check() -> bool:
            if time.monotonic() >= deadline:
                return False
            try:
                current = find_request(send, str(request["id"]), str(request["hunt_id"]))
            except RequestGone:
                # A 404: the request ended with its Hunt. It will never be decided here.
                terminal.say(f"  {request.get('title')}: no longer there (it ended with its Hunt)")
                ended_prompt.append(f"request {request['id']} ended")
                return False
            except ApprovalError:
                return True  # a failed read is not a decision; keep the prompt and try again
            if current.get("status") == "pending":
                return True
            terminal.say(f"  {current.get('title') or request.get('title')}: {current.get('status')} elsewhere"
                         + (f" by {current.get('decided_by')}" if current.get("decided_by") else ""))
            ended_prompt.append(f"request {request['id']} ended ({current.get('status')})")
            return False
        return check

    feed = PendingFeed(send, hunt_id)
    delay = poll_seconds
    with terminal.keypresses():
        terminal.say(f"watching {where} for permission requests... (Ctrl-C to stop)")
        while time.monotonic() < deadline:
            shown = False
            for line in decisions_elsewhere.poll() if decisions_elsewhere else ():
                terminal.say(line)
            # A request whose touch failed is shown again first (the feed brings only changes).
            polled, retry[:] = [*retry, *feed.poll()], []
            fresh = list({str(item["id"]): item for item in polled if str(item["id"]) not in seen}.values())
            if len(fresh) > 1 and touch_mode:
                # One touch can decide every request shown (a set of up to 50).
                terminal.say(f"{len(fresh)} new requests:")
                for request in fresh:
                    terminal.say(render_request(request))
            for index, request in enumerate(fresh):
                if str(request["id"]) in seen:
                    continue
                seen.add(str(request["id"]))
                shown = True
                if ended_prompt:
                    # The switch race: a key meant for the request that just ended must not
                    # decide this one. Say what changed; key() takes only a fresh key.
                    terminal.say(f"{ended_prompt.pop()}; now showing request {request['id']} "
                                 "(press a new key for it)")
                    ended_prompt.clear()
                if not (len(fresh) > 1 and touch_mode):
                    terminal.say(render_request(request))
                else:
                    terminal.say(f"[{index + 1}/{len(fresh)}] {_inert(str(request.get('title') or request['id']))}")
                remember = "r" if request.get("remember_supported") else ""
                rest = [item for item in fresh[index:] if item is request or str(item["id"]) not in seen]
                every = "l" if touch_mode and len(rest) > 1 else ""
                choice = terminal.key(
                    "  [a]llow" + ("  [r]emember for the target" if remember else "")
                    + (f"  allow a[l]l {len(rest)} shown" if every else "") + "  [d]eny  [s]kip  [q]uit: ",
                    "ads" + remember + every + "q", keep_waiting=still_pending(request), interval=poll_seconds,
                )
                if choice == "q":
                    terminal.say(ended)
                    return 0
                if choice == "l":
                    # One touch per set of up to 50 (the gateway's set size): every request shown.
                    seen.update(str(item["id"]) for item in rest)
                    for start in range(0, len(rest), 50):
                        chunk = rest[start:start + 50]
                        if not _touch_decision(terminal, seen, retry, chunk, lambda chunk=chunk: decide(
                                send, terminal, chunk, "allow", enterprise=enterprise, origin=origin,
                                account=approver["account"], method=method, session=None, confirmed=False,
                                approver=approver)):
                            for item in rest[start + 50:]:
                                seen.discard(str(item["id"]))
                                retry.append(item)
                            break
                    break
                if choice in {"a", "r", "d"}:
                    def one(request=request, choice=choice) -> None:
                        decide(send, terminal, [request], "deny" if choice == "d" else "allow",
                               enterprise=enterprise, origin=origin, remember=choice == "r",
                               account=approver["account"], method=method, session=session,
                               confirmed=not enterprise, approver=approver)
                    if touch_mode:
                        _touch_decision(terminal, seen, retry, [request], one)
                    else:
                        one()
                if time.monotonic() >= deadline:
                    break
            # Each read that brings nothing new doubles the wait before the next, up to
            # WATCH_MAX_POLL_SECONDS; a request shown starts again from poll_seconds.
            if shown:
                delay = poll_seconds
            sleep(min(delay, max(0.0, deadline - time.monotonic())))
            delay = min(delay * 2, max(poll_seconds, WATCH_MAX_POLL_SECONDS))
    terminal.say(f"{ended} (time limit)")
    return 0


# Refusals a touch-mode watch never asks again for: retrying them cannot succeed in this watch.
FINAL_REFUSALS = frozenset({
    "security_key_not_registered", "security_key_unavailable", "person_unknown", "account_unknown",
    "role_insufficient", "stepup_locked", "token_invalid",
})


def _touch_decision(terminal: Terminal, seen: set[str], retry: list[dict[str, Any]],
                    requests: Sequence[Mapping[str, Any]], run: Callable[[], Any]) -> bool:
    """One decision of a touch-mode watch: a touch that fails (no touch in time, the wrong key,
    a key pulled out) or that the person cancels with Ctrl-C leaves the requests pending, says
    why, and the watch goes on showing them; only a signal from elsewhere ends it here."""
    try:
        run()
        return True
    except Terminated:
        raise
    except KeyboardInterrupt:
        reason = "touch cancelled"
    except (OutcomeUnknown, RequestGone):
        raise
    except GatewayRefused as exc:
        if exc.code in FINAL_REFUSALS:
            # Asking again cannot help (no key registered, the person or account gone, locked
            # out): said once, and the watch ends instead of asking on every poll.
            raise
        reason = f"not decided: {_inert(str(exc))[:300]}"
    except ApprovalError as exc:
        reason = f"not decided: {_inert(str(exc))[:300]}"
    for request in requests:
        seen.discard(str(request["id"]))
        retry.append(dict(request))
    which = "the request stays pending and is" if len(requests) == 1 else "they stay pending and are"
    terminal.say(f"  {reason}; {which} shown again (q quits)")
    return False


# --- the person decisions of every connection of this person (Enterprise, --watch) -------------

PERSON_FEED_PATH = "/_enterprise/person-decisions"
PERSON_FEED_SCHEMA = "shakerscan-person-decisions/v1"
_DECISION_WORDS = {
    "budget.raise": "raise a Hunt's budget",
    "target.authorize": "authorize a target for active testing",
    "credential.share": "share a saved credential with another target",
    "approval_receipt": "write a scope or approval receipt",
    "hunt_authority.widen": "widen a target's Hunt permissions",
    "shell_plan.confirm": "confirm a device SSH plan",
    "authorization_investigation.approve": "approve an authorization investigation",
    "device.locator": "move a device to a new address",
    "device.lockout": "acknowledge a device credential's lockout",
    "device.policy": "choose a device's automation policy",
    "device.verify": "confirm authorization to probe a device's service",
    "secret.reactivate": "reactivate a discovered secret",
    "secret.expiry": "change a discovered secret's expiry",
    "target.environment": "change the environment a target or device is judged in",
}


class PersonDecisionFeed:
    """``GET /_enterprise/person-decisions``: decisions only a person should make, made through
    any connection that acts for the same person (made with a token, proved by a key touch, or
    refused), for --watch to print as lines. Read only on a gateway that reports it serves it
    (gateway_features); one that answers without the feed's schema is left alone after that."""

    def __init__(self, send: Send) -> None:
        self.send, self.after, self.supported = send, None, True

    def poll(self) -> list[str]:
        if not self.supported:
            return []
        path = PERSON_FEED_PATH + (f"?after={int(self.after)}" if self.after is not None else "")
        try:
            status, body = self.send("GET", path)
        except ApprovalError:
            return []
        if not _ok(status) or not isinstance(body, Mapping) or body.get("schema_version") != PERSON_FEED_SCHEMA:
            self.supported = not (status in FEED_ABSENT or _ok(status))
            return []
        if isinstance(body.get("after"), int):
            self.after = body["after"]
        return [person_decision_line(item) for item in body.get("decisions") or () if isinstance(item, Mapping)]


def person_decision_line(item: Mapping[str, Any]) -> str:
    when = time.strftime("%H:%M:%S", time.localtime(item["at"])) if isinstance(item.get("at"), int) else "--:--:--"
    kind = str(item.get("decision") or "")
    what = _DECISION_WORDS.get(kind, _inert(kind[:60]) or "a person's decision")
    where = _inert(f"{item.get('method') or ''} {item.get('path') or ''}".strip()[:200])
    said = _inert(str(item.get("summary") or ""))[:300]
    via = _inert(str(item.get("connection") or "another connection")[:100])
    made = item.get("made")
    if made == "proved":
        # Written once the engine answered: `security_key`, or `security_key_<status>` when it
        # refused the request the person touched for (nothing was decided then).
        outcome = str(item.get("outcome") or "")
        refused = outcome.startswith("security_key_")
        head = ("proved by key touch, not applied (the engine answered HTTP "
                f"{_inert(outcome[13:])[:10]})" if refused else "decided by key touch")
    elif made == "refused":
        head = "refused, a key touch is required"
        if run := _refused_command(item):
            head += f" (run in your terminal: {run})"
    else:
        outcome = str(item.get("outcome") or "")
        refused = outcome.startswith("unproven_")
        head = "made with a token, no touch" + (f" (the engine answered HTTP {_inert(outcome[9:])[:10]})" if refused else "")
    if said:
        # The gateway's own words for what was decided (every limit a raise set, the host).
        return f"[{when}] {head}: {said} via connection {via}"
    return f"[{when}] {head}: {what} ({where}) via connection {via}"


_ID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


def _refused_command(item: Mapping[str, Any]) -> str:
    """The command that decides a refused decision the watch shows, when the feed row says enough
    without the request's body: a refused submission's target (the target's authorization, never
    the agent's work), a target's own authorization, a budget raise (its limits are the agent's
    request: named as placeholders). Else "" (the agent's own output names the command)."""
    target = str(item.get("target_id") or "")
    path = str(item.get("path") or "")
    parts = [part for part in path.split("/") if part]
    if item.get("decision") == "target.authorize" and _ID.fullmatch(target):
        return f"shakerscan targets authorize {target.lower()}"
    if len(parts) == 3 and parts[0] == "targets" and parts[2] == "authorization" and _ID.fullmatch(parts[1]):
        return f"shakerscan targets authorize {parts[1].lower()}"
    if len(parts) == 3 and parts[0] == "hunts" and parts[2] == "budget-amendments" and _ID.fullmatch(parts[1]):
        return f"shakerscan hunt budget raise {parts[1].lower()} --limit NAME=N"
    return ""


class Terminated(KeyboardInterrupt):
    """SIGTERM or SIGHUP during --watch: handled as Ctrl-C, and the exit status says which."""

    def __init__(self, signum: int) -> None:
        super().__init__(signum)
        self.signum = signum


def _signals_end_the_watch() -> Callable[[], None]:
    """SIGTERM and SIGHUP end the watch the way Ctrl-C does, so its ``finally`` runs: the
    terminal leaves keypress mode and the approver session is revoked (best effort). Without
    this a closed terminal window or a ``kill`` left the terminal without echo and the session
    open. Returns the function that puts the previous handlers back."""
    import signal

    def interrupt(signum: int, frame: Any) -> None:
        raise Terminated(signum)

    previous: dict[int, Any] = {}
    for name in ("SIGTERM", "SIGHUP"):
        number = getattr(signal, name, None)
        if number is None:
            continue
        try:
            previous[number] = signal.signal(number, interrupt)
        except (ValueError, OSError):  # not the main thread, or not supported here
            continue

    def restore() -> None:
        for number, handler in previous.items():
            try:
                signal.signal(number, handler)
            except (ValueError, OSError, TypeError):
                pass

    return restore


def _revoke(send: Send, terminal: Terminal, session_id: str, held: _HeldSecret) -> None:
    """Best effort, bounded by REVOKE_TIMEOUT_SECONDS; a second Ctrl-C skips it. The secret is
    wiped whatever happens."""
    revoked = False
    try:
        status, _ = send("POST", SESSION_REVOKE_PATH, {
            "schema_version": "shakerscan-approval-session-revoke/v1",
            "session_id": session_id, "session_secret": held(),
        }, timeout=REVOKE_TIMEOUT_SECONDS)
        revoked = _ok(status)
    except (ApprovalError, KeyboardInterrupt):
        pass
    finally:
        held.wipe()
    if not revoked:
        with contextlib.suppress(OSError, ValueError):
            terminal.say("could not revoke the approver session at the gateway; it expires on its own")


# --- the commands ------------------------------------------------------------------------------


def _person_runs(command: str, args: Any) -> str:
    """The approve or deny command the person runs in their own terminal, naming the pending
    request the agent named (or every pending one)."""
    words = [f"shakerscan {command}"]
    if args.all_pending:
        words.append("--all-pending")
    elif args.request_id:
        words.append(shlex.quote(str(args.request_id)))
    else:
        words.append("<request-id>")
    if args.hunt:
        words.append(f"--hunt {shlex.quote(str(args.hunt))}")
    return " ".join(words)


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
    terminal.require(person_runs=_person_runs(command, args))
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
    parser.add_argument("--method", choices=("totp", "security_key", "sso"),
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
    "APPROVAL_SCHEMA_PREFIX", "ApprovalError", "BEGIN_PATH", "EXIT_NOT_AT_TERMINAL", "GatewayRefused",
    "NotAtTerminal", "OutcomeUnknown", "terminal_output",
    "instance_kind", "FINISH_PATH", "PREAUTHORIZATION_HEADER",
    "REVOKE_TIMEOUT_SECONDS", "RequestGone", "SESSION_REVOKE_PATH", "StepUp", "StepUpUnavailable", "Terminal", "add_arguments",
    "assertion_json", "decide", "decide_knowledge", "decision_entry", "expected_challenge", "find_request",
    "knowledge_entry", "list_pending", "preauthorize", "safety_budget_words",
    "render_request", "run", "set_digest", "set_document", "wait_for", "watch",
]
