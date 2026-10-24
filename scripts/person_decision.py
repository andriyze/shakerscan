"""A person's decision an Enterprise gateway asks a security-key touch for, in the person's terminal.

An administrator of an Enterprise gateway can require a security-key touch for the decisions only
a person should make (raising a Hunt's budget, authorizing a target for active testing, sharing a
saved credential, widening a target's Hunt permissions, ...) when a terminal sends them with the
connection's token. The gateway then refuses such a request::

    HTTP 403, header x-shakerscan-step-up: required
    {"detail": {"error": "person_decision_required", "decision": "<kind>",
                "summary": "<the decision in plain words>", "proof": "security_key", "message"}}

and every command of this client completes it the same way, in the person's own terminal only:

1. ``POST /_enterprise/approvals/begin`` with purpose ``person_decision`` and the exact request
   (method, path with its query, the body bytes) answers a WebAuthn challenge over a document that
   binds that request. The client checks the document names this request (method, path, query,
   SHA-256 of the body), that the set digest is the document's, and that the challenge is
   SHA-256(nonce || set digest). A gateway that cannot name the decision in full, or a person with
   no key registered, is refused here, before anything is asked of a key;
2. it shows the decision in the words the challenge signs (the document's summary), and only
   those;
3. the person touches a security key registered to their account (user presence; python-fido2
   over USB; no PIN unless the gateway asks for one). Without a key here it says so, and over SSH
   it names the command to run on the computer the key is plugged into;
4. ``finish`` answers a one-time grant valid for that request through this connection;
5. the request is sent again, once, unchanged, with the ``X-ShakerScan-Person-Proof`` header.

A refused submission (a scan, Hunt start, retest or network scan of a target nobody authorized:
the refusal carries ``submission`` and the ``target_id``) started nothing. The person's decision
is the target's authorization, never the submission itself: in the person's own terminal the
touch authorizes the target and the same request is sent once more; anywhere else the command the
person is given is ``shakerscan targets authorize <target-id>``, and whoever sent the submission
sends it again (with the same Idempotency-Key, if it had one) only after the person says they
decided, so the work never runs twice.

Without an interactive terminal, or inside an agent that ``shakerscan agent`` launched
(SHAKERSCAN_AGENT_NAME), it never prompts and never opens a key: it raises PersonDecisionRefused,
one line that names the decision and the command the person runs in their own terminal, and the
command exits 3 (refused, nothing ran). An interactive terminal is stdin and stdout both
terminals (the prompt goes to stdout): a command whose input is piped or redirected
(``shakerscan api ... < /dev/null``, any script feeding it) never counts as the person, and nor
does one whose output is (``shakerscan scan ... --json | jq`` or ``| tee log`` in the person's own
terminal refuses with the command to run without the pipe), the rule every command that asks the
person follows (hunt_approve.terminal_output). No option skips the touch. Ctrl-C at the touch
cancels it (PersonDecisionCancelled, exit 130); nothing changes.

A Hunt start past its session's safety budget (decision ``hunt.start``: under the switch, the
Hunts of one agent session share one safety budget) is the start itself: in the person's own
terminal the touch starts it; anywhere else the person's command is that same start through
``shakerscan api POST /hunts``, and whoever sent it does not send it again (it would start twice).

A decision the gateway says no touch from a terminal confirms yet (``proof: browser``: a device
SSH plan's confirmation, an authorization investigation's approval, whose commands or proposal a
terminal is not shown) is never begun: the line says to make it in the browser, and the command
exits 3.

With no key plugged in, the touch waits for one to be inserted ("Insert your security key"), for
a bounded time within the challenge's life, instead of failing; over SSH, in WSL without the key
passed through and in a container, where a key plugged into the computer cannot arrive, it says
so at once.

The decision is shown whole, wrapped, never cut: the gateway offers no proof for a summary longer
than a terminal shows (MAX_SUMMARY), and this client refuses to ask for a touch for one either.

What a touch proves: a person was at the key. A program running as the same computer user can
change this client or start a request of its own the moment the person expects to touch; touch
only for a prompt you started, and read the decision it names.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shlex
import sys
import textwrap
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
# Ctrl-C at the touch: cancelled, nothing changed (the shell's own convention for SIGINT).
EXIT_CANCELLED = 130
MAX_BODY = 48 * 1024
# The longest request body a `shakerscan api` command names inline; a longer one is saved to a
# file the command names (``@FILE``), so neither the agent's output nor the person's shell
# history carries a line of up to the whole body.
INLINE_BODY = 1024
# The longest decision shown (the gateway's own bound): a longer one is never touched for.
MAX_SUMMARY = 1000
WRAP = 100
TIMEOUT_SECONDS = 30.0


class PersonDecisionError(Exception):
    """The touch could not be completed; nothing was changed. Printed without a traceback."""


class PersonDecisionCancelled(PersonDecisionError):
    """The person pressed Ctrl-C at the touch; nothing was changed (exit 130)."""


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
    """A person at a terminal: stdin and stdout are terminals, and this is not an agent that
    `shakerscan agent` launched. An agent's tool call has no terminal, and a command whose output
    is piped (``--json | jq``) is answered with the command to run without the pipe. The same rule
    as every other command that asks the person (hunt_approve.terminal_output: approve, --watch,
    agent --allow)."""
    approve = _approve()
    return approve.terminal_output(stdin or sys.stdin, stdout or sys.stdout, environ=environ) is not None


def summary_lines(text: Any) -> list[str]:
    """The decision, whole, wrapped for a terminal and indented."""
    shown = _inert(text, MAX_SUMMARY + 1)
    return textwrap.wrap(shown, WRAP, initial_indent="  ", subsequent_indent="    ",
                         break_long_words=True, break_on_hyphens=False) or ["  " + shown]


# ---- the person's command --------------------------------------------------------------------


_UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
# A Hunt budget limit's name as `shakerscan hunt budget raise --limit NAME=N` takes it: lower-case
# letters and underscores. A body with any other name is named through `shakerscan api` instead.
_LIMIT_NAME = re.compile(r"[a-z_]{1,64}")
_SECRET = re.compile(r"/targets/([^/]+)/discovered-secrets/([^/]+)/(state|expiry)")


def decisions_directory() -> str:
    """Where the client saves a person's request bodies too long to name inline, and the only
    place ``shakerscan api ... @FILE`` reads one from: ``decisions/`` in the client's
    configuration directory (``$SHAKERSCAN_CONFIG_DIR`` or ``~/.config/shakerscan``)."""
    base = os.environ.get("SHAKERSCAN_CONFIG_DIR") or os.path.join(os.path.expanduser("~"), ".config", "shakerscan")
    return os.path.join(base, "decisions")


def saved_body(body: bytes) -> str | None:
    """Where a request body too long to name inline is saved for the person's command: the
    client's decisions directory (decisions_directory), ``<digest>.json``, readable by this user
    only, kept a week (SAVED_SECONDS); None when it cannot be written. The touch still shows what
    the gateway reads from the body the person's command sends."""
    directory = decisions_directory()
    path = os.path.join(directory, hashlib.sha256(body).hexdigest()[:24] + ".json")
    try:
        os.makedirs(directory, mode=0o700, exist_ok=True)
        _prune_saved(directory)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(body)
        os.chmod(path, 0o600)
    except OSError:
        return None
    return path


# A saved request body is kept this long for the person's command, then removed the next time one
# is saved.
SAVED_SECONDS = 7 * 86400


def _prune_saved(directory: str) -> None:
    import time

    cutoff = time.time() - SAVED_SECONDS
    try:
        names = os.listdir(directory)
    except OSError:
        return
    for name in names:
        if not re.fullmatch(r"[0-9a-f]{24}\.json", name):
            continue
        where = os.path.join(directory, name)
        try:
            if os.lstat(where).st_mtime < cutoff:
                os.unlink(where)
        except OSError:
            pass


def _word(value: Any) -> str | None:
    """``value`` as one shell word of a command, or None when it could be read as an option
    (it starts with "-"): a value an agent's request carried never becomes an option of the
    person's command (``--url=...`` would send the person's connection elsewhere)."""
    text = str(value)
    return None if not text or text.startswith("-") else shlex.quote(text)


def person_command(method: str, path: str, body: bytes | None, detail: Mapping[str, Any] | None = None) -> str:
    """The command the person runs in their own terminal to make this decision: the dedicated
    command where there is one (a budget raise, a target's authorization), else exactly this
    request through ``shakerscan api``. For a refused submission (``detail`` names a
    ``submission``) it is always the target's authorization, by the ``target_id`` the gateway
    names, and never the submission itself: the person would otherwise run the agent's scan or
    retest as their own, and it would run twice. Every value taken from the request is one quoted
    shell word, never an option (_word)."""
    route = urllib.parse.urlsplit(path).path
    parts = [part for part in route.split("/") if part]
    try:
        payload = json.loads(body) if body else None
    except (ValueError, UnicodeDecodeError):
        payload = None
    payload = payload if isinstance(payload, dict) else None
    detail = detail if isinstance(detail, Mapping) else {}
    if detail.get("decision") == HUNT_START:
        # The person's decision is this start itself (past its session's safety budget): their
        # own terminal sends exactly it, and the agent never sends it again.
        return _api_command(method, path, body)
    named = str(detail.get("target_id") or "")
    if detail.get("submission") and _UUID.fullmatch(named):
        return f"shakerscan targets authorize {named.lower()}"

    def authorize(value: Any) -> str | None:
        word = _word(value)
        return f"shakerscan targets authorize {word}" if word else None

    found: str | None = None
    if method == "POST" and route == "/targets" and payload and isinstance(payload.get("url"), str) \
            and payload.get("authorized_by") is not None:
        # Registered first, then authorized on its own (the gateway names its environment then).
        found = authorize(payload["url"])
    elif method == "POST" and route == "/targets/hosts" and payload and isinstance(payload.get("locator"), str) \
            and payload.get("approved_by") is not None:
        found = authorize("host://" + payload["locator"])
    elif method == "POST" and len(parts) == 3 and parts[0] == "hunts" and parts[2] == "budget-amendments" and payload:
        limits = payload.get("limits") if isinstance(payload.get("limits"), dict) else {}
        # Only plain limit names: a name from the agent's body is never an option of the person's
        # command (`--limit --url=...=40` read as the client's own --url).
        pairs = [f"--limit {shlex.quote(f'{key}={value}')}" for key, value in sorted(limits.items())
                 if isinstance(key, str) and _LIMIT_NAME.fullmatch(key) and type(value) is int]
        hunt = _word(parts[1])
        if hunt and pairs and len(pairs) == len(limits):
            resume = " --resume" if payload.get("resume") is True else ""
            found = f"shakerscan hunt budget raise {hunt} " + " ".join(pairs) + resume
    elif method == "POST" and len(parts) == 3 and parts[0] == "targets" and parts[2] == "authorization":
        if (payload or {}).get("risk_tier") in (None, "active"):
            found = authorize(parts[1])
    elif method == "POST" and route == "/scans" and payload and isinstance(payload.get("target"), str):
        found = authorize(payload["target"])
    elif method == "POST" and route == "/hunts" and payload and isinstance(payload.get("target_id"), str):
        found = authorize(payload["target_id"])
    elif method == "POST" and len(parts) == 3 and parts[0] in {"targets", "devices"} \
            and parts[2] in ({"scan", "network-scans"} if parts[0] == "targets" else {"scan"}):
        # A device is authorized under the same route as a target (its id).
        found = authorize(parts[1])
    if found:
        return found
    if detail.get("submission") or (method == "POST" and route in {"/scans", "/hunts"}):
        # A submission whose target is not named here as one word: never the submission itself.
        # TARGET-ID: a placeholder a shell takes as one plain word when pasted whole (no quote to
        # wait on, no `<` to read a file from), which `shakerscan targets authorize` refuses.
        return "shakerscan targets authorize " + PLACEHOLDER
    if method == "POST" and payload and (secret := _SECRET.fullmatch(route)):
        target, reference = _word(secret.group(1)), _word(secret.group(2))
        if target and reference and secret.group(3) == "state" and payload == {"state": "active"}:
            return f"shakerscan secrets reactivate {target} {reference}"
        if target and reference and secret.group(3) == "expiry" and set(payload) == {"days"} \
                and type(payload["days"]) is int:
            return f"shakerscan secrets expiry {target} {reference} --days {payload['days']}"
    return _api_command(method, path, body)


def _api_command(method: str, path: str, body: bytes | None) -> str:
    """Exactly this request through ``shakerscan api``: its body inline when short, else saved
    to the decisions directory and named as ``@FILE``."""
    text = body.decode("utf-8", "replace") if body else ""
    request = "shakerscan api " + " ".join(shlex.quote(part) for part in (method, path))
    if len(text) <= INLINE_BODY:
        return request + (" " + shlex.quote(text) if text else "")
    saved = saved_body(body or b"")
    if saved:
        return f"{request} {shlex.quote('@' + saved)}"
    return f"{request} @request.json (request.json: the {len(body or b'')}-byte JSON body this request carried)"


def refusal_line(detail: Mapping[str, Any], command: str) -> str:
    """One line for an agent's tool call: the decision (whole, as the gateway said it), that
    nothing changed, for a refused submission not to send it again until the person said the
    target is authorized, and last the person's command (its body made inert: it may carry any
    bytes), with nothing after it: a copy that takes the line's end takes no punctuation into the
    command."""
    summary = _inert(detail.get("summary") or detail.get("decision") or "a person's decision", MAX_SUMMARY)
    if detail.get("proof") == BROWSER:
        return f"person decision required: {summary}. Nothing was changed. {BROWSER_ONLY}"
    line = f"person decision required: {summary}. Nothing was changed."
    if detail.get("decision") == HUNT_START:
        line = f"person decision required: {summary}. {START_ONCE}"
    if detail.get("submission"):
        line += SUBMISSION_AGAIN
    return line + (" The person runs this in their own terminal and touches their security key: "
                   + _inert(command, 4 * MAX_BODY))


# A refused submission started nothing. It is sent again only after the person said they
# authorized the target (with its Idempotency-Key, if it had one), so the work never runs twice.
SUBMISSION_AGAIN = (
    " Nothing was started either. Do not send this request again until the person says the "
    "target is authorized; then send it once (with the same Idempotency-Key, if it had one)."
)
# The target of a refused submission no value of the request names as one word.
PLACEHOLDER = "TARGET-ID"
# A Hunt start past its session's safety budget: the person's own terminal starts it.
HUNT_START = "hunt.start"
START_ONCE = (
    "Nothing was started. Do not send this start again: the person's command starts it, and "
    "then you continue with the Hunt it reports."
)
# A decision no touch from a terminal confirms yet (the gateway's `proof: browser`).
BROWSER = "browser"
BROWSER_ONLY = (
    "The person makes this decision in the browser (the Hunt page shows what it approves in "
    "full); no security-key touch from a terminal confirms it yet."
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


def _refused(status: int, body: Any, *, decision: Mapping[str, Any] | None = None) -> PersonDecisionError:
    """The gateway's refusal, in the person's words: before any touch (``decision``, the refusal
    the request got: the decision is named, from its words, and no touch was asked), or of the
    touch itself."""
    text = _approve()._detail_text(body, 1200)
    code = str(body.get("error") or "refused") if isinstance(body, Mapping) else "refused"
    if decision is not None:
        named = _inert(decision.get("summary") or decision.get("decision") or "this decision", MAX_SUMMARY)
        return PersonDecisionError(f"{named}: no touch was asked ({code}): {text}; nothing was changed")
    return PersonDecisionError(f"the gateway did not accept the touch ({code}, HTTP {status}): {text}; nothing was changed")


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
    """Ask the person, at this terminal, for one touch for exactly this request; the grant.
    ``detail`` is the refusal: its words are never shown as the decision (the person is shown
    only what the challenge signs), it only names the command to run where the key is."""
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
    try:
        return _touch(post, approve, terminal, origin=origin, method=method, path=path, body=body,
                      assertion=assertion, detail=detail)
    except KeyboardInterrupt:
        terminal.say("")
        raise PersonDecisionCancelled("cancelled; nothing was changed") from None


def _touch(post: Post, approve: Any, terminal: Any, *, origin: str, method: str, path: str, body: bytes,
           assertion: Callable[..., dict] | None, detail: Mapping[str, Any] | None = None) -> str:
    # Begin first: the gateway says whether a key is registered at all, and whether it can name
    # the decision, before the person is asked to plug anything in.
    status, challenge = post(BEGIN_PATH, {
        "schema_version": "shakerscan-approval-begin/v1", "purpose": "person_decision", "origin": origin.rstrip("/"),
        "person_decision": {"method": method, "path": path, "body": _b64url(body or b"")},
    })
    if not 200 <= status < 300 or not isinstance(challenge, Mapping):
        # Before any touch (no key registered, a decision the gateway cannot name, ...): the
        # decision is named from the refusal the request got, and nothing was asked of a key.
        raise _refused(status, challenge, decision=detail or {})
    document = check_challenge(challenge, origin=origin, method=method, path=path, body=body or b"")
    shown = document["person_decision"].get("summary")
    if not isinstance(shown, str) or not shown or len(shown) > MAX_SUMMARY:
        raise PersonDecisionError("the gateway's challenge does not say the decision in full; nothing was changed")
    # Only what the key signs is shown (the document's summary), never the refusal's words.
    terminal.say("This needs your decision (your administrator requires a security-key touch):")
    for line in summary_lines(shown):
        terminal.say(line)
    # A key that is only not plugged in yet is waited for by the assertion; python-fido2 missing,
    # or a key out of reach over SSH, cannot be helped by waiting.
    if assertion is None and (unready := approve.security_key_readiness(waiting=True)):
        if approve.key_out_of_reach():
            unready += f": {_inert(person_command(method, path, body, detail), 4 * MAX_BODY)}"
        raise PersonDecisionError(f"{unready}; nothing was changed")
    sign = assertion or approve.security_key_assertion
    try:
        # The key is chosen (when several can answer) before the person is told to touch.
        credential = sign(challenge["webauthn"], origin.rstrip("/"), terminal,
                          prompt="Touch your security key to approve (Ctrl-C to cancel)...",
                          insert_seconds=insert_seconds(challenge))
    except approve.ApprovalError as exc:
        raise PersonDecisionError(f"{exc}; nothing was changed") from exc
    status, result = post(FINISH_PATH, {
        "schema_version": "shakerscan-approval-finish/v1", "approval_id": challenge.get("approval_id"),
        "set_digest": challenge.get("set_digest"), "proof": {"method": "security_key", "credential": credential},
    })
    granted = result.get("person_decision") if isinstance(result, Mapping) else None
    if not 200 <= status < 300 or not isinstance(granted, Mapping) or not isinstance(granted.get("grant"), str):
        raise _refused(status, result)
    # The request is not applied yet: it is sent again now, and what the instance answers then
    # (applied, or refused because something changed meanwhile) is the command's own output.
    terminal.say("touch accepted for " + _inert(result.get("decided_by") or "you", 120)
                 + " (security-key touch); sending the request again...")
    return granted["grant"]


# How long the touch waits for a key to be inserted: within the challenge's own life (the
# gateway's expires_at), leaving time for the touch itself.
INSERT_SECONDS = 60.0
TOUCH_RESERVE_SECONDS = 30.0


def insert_seconds(challenge: Mapping[str, Any], now: float | None = None) -> float:
    """At most INSERT_SECONDS, and never so long that the challenge expires before the touch."""
    import datetime
    import time

    text = str(challenge.get("expires_at") or "")
    try:
        expires = datetime.datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return INSERT_SECONDS
    left = expires - (time.time() if now is None else now) - TOUCH_RESERVE_SECONDS
    return max(5.0, min(INSERT_SECONDS, left))


def handle(post: Post, *, origin: str, method: str, path: str, body: bytes | None, detail: Mapping[str, Any],
           resend: Callable[[str], Any], terminal: Any = None, environ: Mapping[str, str] | None = None,
           assertion: Callable[..., dict] | None = None) -> Any:
    """The refused request, completed: in an interactive terminal one touch and one resend (its
    answer is returned, whatever it is); anywhere else PersonDecisionRefused."""
    stdin = getattr(terminal, "stdin", None)
    stdout = getattr(terminal, "stdout", None)
    if detail.get("proof") == BROWSER:
        # Never begun, at a terminal or not: the gateway offers no touch for it.
        raise PersonDecisionRefused(refusal_line(detail, ""), detail=detail, command="")
    if not interactive(stdin, stdout, environ):
        command = person_command(method, path, body, detail)
        raise PersonDecisionRefused(refusal_line(detail, command), detail=detail, command=command)
    if terminal is None:
        terminal = _approve().Terminal(sys.stdin, sys.stdout)
    grant = complete(post, origin=origin, method=method, path=path, body=body or b"", detail=detail,
                     terminal=terminal, assertion=assertion)
    return resend(grant)


__all__ = [
    "ERROR", "EXIT_CANCELLED", "EXIT_REFUSED", "INLINE_BODY", "MAX_SUMMARY", "PROOF_HEADER",
    "PersonDecisionCancelled", "PersonDecisionError", "PersonDecisionRefused", "check_challenge", "complete",
    "detail_of", "handle", "interactive", "json_poster", "person_command", "refusal_line", "required",
    "saved_body", "summary_lines",
]
