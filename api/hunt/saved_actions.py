"""Propose reusable settled Hunt steps for an operator to review when a Hunt finishes.

Finishing never writes a target recipe, whatever the target delegates. It files, or refreshes in
place, the target's one rolling proposal of retained checks
(``targets.instruction_proposals.refresh_retained_proposal``), which an operator accepts or
rejects with ``shakerscan knowledge review``. That proposal is never counted against the
proposals or saved actions a planner may write, and there is never more than one pending.

A step is proposed only when every field it carries is on its capability's allowlist
(``RETAINED_STEP_FIELDS``) and none carries a query value, request header, request body, browser
input, session or credential reference, or an origin other than the Hunt target's own host. The
inputs are read as the action ledger stored them; a path with a query, a redaction marker, a
token-like or credential-labelled segment, or a word that names an action (log out, delete,
reset...) is left out, as is any step whose recorded input no longer validates. No step runs
here; reusing one still runs the canonical capability under the new Hunt's scope, approvals,
credentials and budget.
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
    from scanner_tools.unsafe_actions import navigation_url_is_safe
    from scanner_tools.url_redaction import redact_path
except ModuleNotFoundError:  # package import in host-side tests
    from scanner.scanner_tools.unsafe_actions import navigation_url_is_safe
    from scanner.scanner_tools.url_redaction import redact_path

from .finding_actions import http_origin, hunt_target_host, hunt_target_locator

RETAINED_ACTION_NAME = "Checks retained from finished Hunts"
RETAINED_INSTRUCTIONS = (
    "Read-only and verification steps that completed in earlier Hunts on this target, proposed "
    "for reuse. Each step runs under the new Hunt's scope, policy, credentials and budget; these "
    "steps grant no authority."
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
_PLAIN_PATH = re.compile(r"/[A-Za-z0-9/_.~:@!$&'()*+,;=-]{0,1999}")
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


def _plain_path(path: Any) -> bool:
    """A route with no query, fragment, encoded or masked part, credential-shaped segment or
    action word: the same request is safe to propose for another read of the target."""
    return (
        isinstance(path, str)
        and _PLAIN_PATH.fullmatch(path) is not None
        and not path.startswith("//")
        and redact_path(path) == path
        and navigation_url_is_safe(path)
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
    actions = await conn.fetch(
        """SELECT id, capability_name, status, input_summary FROM hunt_actions
           WHERE hunt_run_id=$1 AND status='completed'
           ORDER BY completed_at, id LIMIT $2""", run["id"], _LIMIT_ACTIONS,
    )
    steps, evidence = recipe_steps([dict(action) for action in actions], host)
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
