"""Propose reusable settled Hunt steps for an operator to review when a Hunt finishes.

Finishing never writes a target recipe, whatever the target delegates. It files, or refreshes in
place, the target's one rolling proposal of retained checks
(``targets.instruction_proposals.refresh_retained_proposal``), which an operator accepts or
rejects with ``shakerscan knowledge review``. That proposal is never counted against the
proposals or saved actions a planner may write, and there is never more than one pending.

A step is proposed only when every field it carries is on its capability's allowlist
(``RETAINED_STEP_FIELDS``) and none carries a query value, request header, request body, browser
input, session or credential reference, or an origin other than the Hunt target's own host. The
inputs are read as the action ledger stored them. A path is left out when it has a query, a
redaction marker, a character outside letters, digits and ``/ _ . ~ -`` (quotes, ``$( )``,
encoded values), a dot segment, a token-like or letter-and-digit code segment, a letters-only
capability token (mixed case and long, or base64url-shaped), a word that names a credential
(token, pin, otp...) or a word that names an action (log out, delete, reboot, firmware, apply,
checkout, transfer, ban, purge, refund, redeem, migrate, merge, on, off, open...), as is any step
whose recorded input no longer validates.

The word list cannot know every action a target names, so the proposal does not claim its steps
are read-only: they are steps that completed and can be replayed, which a person reviews before
accepting. No step runs here; reusing one still runs the canonical capability under the new
Hunt's scope, approvals, credentials and budget.
"""
from __future__ import annotations

import json
import re
import urllib.parse
from collections.abc import Mapping, Sequence
from typing import Any
from uuid import UUID

from fastapi import HTTPException

try:
    from scanner_tools.unsafe_actions import contains_risky_keyword, path_may_change_state, semantic_text
    from scanner_tools.url_redaction import is_sensitive_label, redact_path
except ModuleNotFoundError:  # package import in host-side tests
    from scanner.scanner_tools.unsafe_actions import contains_risky_keyword, path_may_change_state, semantic_text
    from scanner.scanner_tools.url_redaction import is_sensitive_label, redact_path

from .finding_actions import http_origin, hunt_target_host, hunt_target_locator

RETAINED_ACTION_NAME = "Checks retained from finished Hunts"
RETAINED_INSTRUCTIONS = (
    "Steps that completed in earlier Hunts on this target and can be replayed, proposed for reuse. "
    "Review each step before accepting: a path can act on the target although its method reads. "
    "Each step runs under the new Hunt's scope, policy, credentials and budget; these steps grant "
    "no authority."
)
# Per capability, the only input fields a retained step may carry. A step with any other field
# (headers, query or body values, captures, sessions, principals, browser steps, search terms)
# is not proposed at all, rather than proposed without the field.
RETAINED_STEP_FIELDS: Mapping[str, frozenset[str]] = {
    "web.probe": frozenset({"origin"}),
    "web.crawl": frozenset({"origin"}),
    "web.browser_crawl": frozenset({"origin"}),
    "web.content_discover": frozenset({"origin", "wordlist"}),
    "javascript.analyze": frozenset({"path", "max_bytes"}),
    "artifact.inspect": frozenset({"path", "offset", "max_bytes"}),
    "http.request": frozenset({"method", "origin", "path", "follow_redirects"}),
    "browser.navigate": frozenset({"origin", "path", "wait_until", "timeout_ms", "max_requests"}),
    "tls.inspect": frozenset({"origin"}),
    "device.http.probe": frozenset({"method", "path", "origin_port"}),
    "sqli.verify": frozenset({"origin", "path"}),
    "xss.verify": frozenset({"origin", "path", "severity", "deep_domxss"}),
}
_READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_MARKERS = ("***", "redacted", "withheld")
# Letters, digits and ``/ _ . ~ -`` only: no quote, ``$( )``, ``;``, ``=``, ``@``, ``:``, ``%`` or
# other character a payload or an encoded value needs.
_PLAIN_PATH = re.compile(r"/[A-Za-z0-9/_.~-]{0,1999}")
# Words that make a GET act rather than read, beyond the crawler's interaction words: device
# controls and web state changes, matched as whole words. A path naming one is not proposed.
RETAINED_ACTION_WORDS = (
    "reboot", "restart", "shutdown", "shut down", "power off", "poweroff", "halt", "firmware",
    "upgrade", "downgrade", "flash", "factory", "apply", "commit", "goform", "exec", "execute", "cmd",
    "command", "shell", "install", "uninstall", "restore", "backup", "rollback", "deploy", "publish",
    "set", "enable", "toggle", "trigger", "checkout", "transfer", "pay", "payment", "purchase", "buy",
    "send", "withdraw", "deposit", "add", "activate", "activation", "subscribe", "invite", "accept",
    "decline", "unlock", "vote", "follow", "unfollow", "import", "upload",
    # Moderation, queues, jobs and caches.
    "ban", "unban", "block", "unblock", "kick", "mute", "unmute", "suspend", "unsuspend", "promote",
    "demote", "grant", "assign", "unassign", "purge", "flush", "clear", "empty", "drop", "truncate",
    "stop", "kill", "pause", "resume", "retry", "rerun", "replay", "rebuild", "reindex", "sync",
    "migrate", "merge", "close", "reopen", "archive", "unarchive", "lock", "confirm", "dismiss",
    # Orders, rewards and social actions.
    "refund", "redeem", "claim", "like", "unlike", "dislike", "star", "unstar", "share", "repost",
    "retweet", "resend", "notify",
    # Device and physical controls.
    "on", "off", "open", "arm", "disarm", "format", "mount", "unmount", "eject", "move", "ptz",
    "pan", "tilt", "zoom", "wake", "wol", "sleep", "dial", "call", "ring", "beep", "unpair", "pair",
)
# Letters only, both cases, and long or not shaped like a camelCase word: a capability token
# (``AbCdEfGhIjKlMnOp``, base64url ``ZXhhbXBsZQ``) rather than a route word (``userProfile``).
_CAMEL_WORD = re.compile(r"[A-Za-z][a-z]*(?:[A-Z][a-z]+)*")
_LETTER_TOKEN_MIN = 8
_LETTER_TOKEN_LONG = 12
# Words that name a credential or a one-time value, beyond the redaction's own labels.
_CREDENTIAL_WORDS = frozenset({"pin", "passcode", "passwd", "pwd", "otp", "mfa", "2fa", "totp"})
_LIMIT_ACTIONS = 2_000


def _object(value: Any) -> dict:
    try:
        decoded = json.loads(value) if isinstance(value, str) else value
    except (TypeError, ValueError):
        return {}
    return dict(decoded) if isinstance(decoded, Mapping) else {}


def _plain_value(value: Any) -> bool:
    if isinstance(value, bool) or value is None or (isinstance(value, int) and 0 <= value <= 10_000_000):
        return True
    if not isinstance(value, str) or len(value) > 2_000:
        return False
    lowered = value.lower()
    return not any(marker in lowered for marker in _MARKERS) and value.isprintable()


def _opaque(part: str) -> bool:
    """A run of letters and digits that alternates between them at least twice (``3f2a9c1b``,
    ``MTIzNDU2Nzg5MA``): an identifier or code, not a route word (``v1``, ``Category12``)."""
    kinds = [character.isdigit() for character in part if character.isalnum()]
    return sum(left != right for left, right in zip(kinds, kinds[1:])) >= 2


def _letter_token(text: str) -> bool:
    """Letters only and both cases, and either long or not a camelCase word."""
    if (len(text) < _LETTER_TOKEN_MIN or not text.isascii() or not text.isalpha()
            or text.islower() or text.isupper()):
        return False
    return len(text) >= _LETTER_TOKEN_LONG or _CAMEL_WORD.fullmatch(text) is None


def _plain_path(path: Any) -> bool:
    """A route with no query, fragment, encoded, masked or dot segment, no credential word or
    token-like value, and no word that names an action, so it may be proposed for review."""
    if not isinstance(path, str) or _PLAIN_PATH.fullmatch(path) is None:
        return False
    segments = path.split("/")[1:]
    if any(segment in {"", ".", ".."} for segment in segments[:-1]) or segments[-1] in {".", ".."}:
        return False
    words = semantic_text(path).split()
    return (
        redact_path(path) == path
        and not path_may_change_state(path)
        and not contains_risky_keyword((path,), RETAINED_ACTION_WORDS)
        and not any(is_sensitive_label(word) or word in _CREDENTIAL_WORDS for word in words)
        and not any(_opaque(part) or _letter_token(part) for part in re.split(r"[/_.~-]", path))
        and not any(_letter_token(segment.replace("-", "").replace("_", "")) for segment in segments)
    )


def _same_host_origin(origin: Any, host: str | None) -> bool:
    try:
        _scheme, origin_host, _port = http_origin(origin)
    except ValueError:
        return False
    parsed = urllib.parse.urlsplit(origin)
    return (bool(host) and origin_host == host and parsed.path in {"", "/"}
            and not parsed.query and not parsed.fragment)


def retained_step(name: str, values: Any, host: str | None) -> dict | None:
    """The step a completed action proposes for reuse, or None when it must not be proposed."""
    from runtime.capability_registry import CAPABILITY_REGISTRY

    allowed = RETAINED_STEP_FIELDS.get(name)
    if allowed is None or not isinstance(values, Mapping) or set(values) - allowed:
        return None
    if not all(_plain_value(value) for value in values.values()):
        return None
    method = values.get("method")
    if method is not None and str(method).upper() not in _READ_METHODS:
        return None
    if "path" in values and not _plain_path(values["path"]):
        return None
    if "origin" in values and not _same_host_origin(values["origin"], host):
        return None
    try:
        validated = CAPABILITY_REGISTRY.validate_hunt_input(name, dict(values))
    except ValueError:
        return None
    return {"capability": name, "input": validated}


def _identity(step: Mapping) -> str:
    return json.dumps([step.get("capability"), step.get("input")], sort_keys=True)


def recipe_steps(actions: Sequence[Mapping], host: str | None) -> tuple[list[dict], list[str]]:
    """Distinct reusable steps of a Hunt's completed actions, in order, with their action ids."""
    steps, evidence, seen = [], [], set()
    for action in actions:
        if action.get("status") != "completed":
            continue
        step = retained_step(str(action.get("capability_name") or ""),
                             _object(action.get("input_summary")).get("input"), host)
        if step is None or _identity(step) in seen:
            continue
        seen.add(_identity(step))
        steps.append(step)
        evidence.append(str(action["id"]))
    return steps, evidence


def merge_retained_steps(previous: Sequence[Mapping], new: Sequence[Mapping], *, saved: Sequence[Mapping],
                         limit: int) -> list[dict]:
    """The rolling proposal's steps: one copy of each, none already saved, the newest ``limit``."""
    known = {_identity(step) for step in saved}
    merged, seen = [], set()
    for step in [*previous, *new]:
        key = _identity(step)
        if key in seen or key in known:
            continue
        seen.add(key)
        merged.append({"capability": step["capability"], "input": dict(step["input"])})
    return merged[-limit:] if limit > 0 else []


async def retain_hunt_action(conn: Any, run: Mapping) -> dict | None:
    """Propose this Hunt's reusable steps in the target's rolling proposal; never save them.

    The finishing transaction already holds the target row (KEY SHARE, taken before the Hunt row),
    so nothing here takes a row lock on the target.
    """
    from targets.hunt_authority import authority_from_row, authority_row
    from targets.instruction_proposals import refresh_retained_proposal
    from .interpretations import notes_quarantined

    if notes_quarantined(run.get("notes")):
        return {"status": "skipped", "reason": "hunt_entries_retracted"}
    target = run.get("device_target_id") or run.get("target_id")
    if not target:
        return None
    authority_target = await authority_row(conn, target)
    if not authority_from_row(authority_target)["metadata_changes"]:
        return {"status": "skipped", "reason": "target_metadata_changes_disabled"}
    try:
        host, _origin = hunt_target_host(hunt_target_locator(run))
    except ValueError:
        return {"status": "skipped", "reason": "target_host_unknown"}
    # The newest completed actions, read back in the order they ran: the rolling proposal keeps
    # the newest steps, so a long Hunt's latest work is never cut off by its earliest.
    actions = await conn.fetch(
        """SELECT id, capability_name, status, input_summary FROM hunt_actions
           WHERE hunt_run_id=$1 AND status='completed'
           ORDER BY completed_at DESC, id DESC LIMIT $2""", run["id"], _LIMIT_ACTIONS,
    )
    steps, evidence = recipe_steps([dict(action) for action in reversed(actions)], host)
    if not steps:
        return {"status": "skipped", "reason": "no_reusable_steps"}
    return await refresh_retained_proposal(
        conn, authority_target["id"], steps=steps, evidence_refs=evidence,
        hunt_run_id=UUID(str(run["id"])), name=RETAINED_ACTION_NAME,
        instructions=RETAINED_INSTRUCTIONS, merge=merge_retained_steps,
    )


async def retain_hunt_action_safely(conn: Any, run: Mapping) -> dict:
    # An unavailable metadata store or a refused proposal must not lose the Hunt's debrief. The
    # savepoint rolls back only this optional write and exposes the failure.
    try:
        async with conn.transaction():
            return await retain_hunt_action(conn, run) or {"status": "skipped", "reason": "no_target"}
    except HTTPException as exc:
        return {"status": "not_saved", "reason": "proposal_refused", "status_code": exc.status_code}
    except Exception as exc:
        return {"status": "not_saved", "reason": f"proposal_error:{type(exc).__name__}"}
