"""The methodology a Hunt's mapped surface calls for, inside the briefing the planner always reads.

The skill library was almost never used: in 305 lab Hunts a planner read a methodology once.
Start-time suggestions were made from the objective's words alone (a generic objective names no
technology), sat in a part of the start answer compact clients leave out, and needed a further
read call. Here the briefing's live part carries, on every read of the Hunt, the one or two
methodologies the target's mapped routes and inputs call for (a GraphQL endpoint, an upload, a
URL-taking parameter ...), each with its workflow steps and the evidence a finding needs, and
the call that reads the whole methodology. Advisory, like every skill: it binds nothing, grants
nothing and widens nothing.
"""
from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
import re
from typing import Any

MAX_SKILLS = 2
MAX_STEPS = 8
MAX_EVIDENCE = 4
MAX_LINE = 200
MAX_ENDPOINTS = 2_000

# Route and input shapes -> the signal words the skill library routes on (hunt/skills.suggest).
_PATH_SIGNALS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"graph(?:i)?ql", re.I), "graphql"),
    (re.compile(r"upload|attach|avatar|import|/files?(?:/|$)|media", re.I), "file upload"),
    (re.compile(r"oauth|authorize|openid|saml|sso", re.I), "oauth"),
    (re.compile(r"(?:^|/)(?:login|signin|sign-in|register|signup|reset|forgot|password)", re.I), "authentication"),
    (re.compile(r"websocket|socket\.io|/ws(?:/|$)|/sse(?:/|$)|events?/stream", re.I), "websocket"),
    (re.compile(r"\{[^}]*id[^}]*\}|/\d+(?:/|$)", re.I), "idor"),
    (re.compile(r"swagger|openapi|api-docs", re.I), "openapi"),
    (re.compile(r"actuator|debug|console|metrics|phpinfo|server-status", re.I), "debug_or_admin_surface"),
)
_PARAM_SIGNALS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"^(?:url|uri|callback|webhook|feed|image_?url|src|link|endpoint)$", re.I), "ssrf"),
    (re.compile(r"^(?:next|return(?:_?to|url)?|redirect(?:_?uri|_?url)?|dest(?:ination)?|continue|goto)$", re.I),
     "open redirect"),
    (re.compile(r"^(?:file(?:name)?|path|page|template|include|doc(?:ument)?|dir|folder|lang)$", re.I),
     "path traversal"),
    (re.compile(r"^(?:cmd|command|exec|ip|host(?:name)?|ping|domain|arg)$", re.I), "command injection"),
    (re.compile(r"^(?:q|query|search|filter|sort|order(?:by)?|where|id|user_?id|category)$", re.I), "sql injection"),
    (re.compile(r"^(?:token|jwt|access_?token|id_?token)$", re.I), "jwt"),
    (re.compile(r"^(?:role|is_?admin|admin|permissions?|group|plan|price|balance|credit)$", re.I),
     "mass assignment"),
)
_WORKFLOW = re.compile(r"^## Agent workflow\s*$", re.M)
_EVIDENCE = re.compile(r"^## Evidence required for a finding\s*$", re.M)


def _params(shape: str) -> list[str]:
    return [part for part in re.split(r"[^A-Za-z0-9_\-]+", str(shape or "")) if part][:40]


def surface_signals(rows: Iterable[Mapping[str, Any]], *, limit: int = 8) -> list[str]:
    """The signal words the mapped routes and inputs carry, the most frequent first."""
    counts: Counter[str] = Counter()
    for row in rows:
        path = str(row.get("path") or "")
        found = {signal for pattern, signal in _PATH_SIGNALS if pattern.search(path)}
        found |= {signal for name in _params(row.get("param_shape"))
                  for pattern, signal in _PARAM_SIGNALS if pattern.match(name)}
        content_type = str(row.get("content_type") or "").lower()
        if "xml" in content_type:
            found.add("xxe")
        if "multipart" in content_type:
            found.add("file upload")
        counts.update(found)
    # A rare, specific surface (one GraphQL endpoint) outranks a common one (many numeric ids).
    weight = {"idor": 0.25, "sql injection": 0.5, "authentication": 0.5}
    ranked = sorted(counts, key=lambda name: (-(counts[name] * weight.get(name, 1.0)), name))
    return ranked[:limit]


def _section(body: str, heading: re.Pattern[str]) -> str:
    match = heading.search(body)
    if not match:
        return ""
    rest = body[match.end():]
    end = re.search(r"^## ", rest, re.M)
    return rest[:end.start()] if end else rest


def checklist(body: str) -> dict[str, list[str]]:
    """The workflow step headings and the evidence lines of a methodology's text."""
    steps = [line.lstrip("#").strip()[:MAX_LINE] for line in _section(body, _WORKFLOW).splitlines()
             if line.startswith("### ")][:MAX_STEPS]
    evidence = [line.lstrip("- ").strip()[:MAX_LINE] for line in _section(body, _EVIDENCE).splitlines()
                if line.lstrip().startswith("- ")][:MAX_EVIDENCE]
    return {"steps": steps, "evidence": evidence}


def build_section(*, hunt_id: str, signals: list[str], objective: str, target_kind: str,
                  allowed_capabilities: Iterable[str] | None, library: Any = None) -> dict[str, Any]:
    from .skills import read_skill_body, skill_library
    if not signals:
        # Nothing mapped calls for a methodology yet; the objective's words alone matched the wrong
        # ones (a generic "authorization flaws" picked GraphQL and SSO).
        return {"signals": [], "methodologies": [],
                "note": "No mapped route or input calls for a methodology yet; this updates as the Hunt maps more."}
    library = library or skill_library()
    suggestions = library.suggest(goal=objective, target_kind=target_kind, signals=signals,
                                  allowed_capabilities=allowed_capabilities, limit=MAX_SKILLS)
    items = []
    for suggestion in suggestions[:MAX_SKILLS]:
        try:
            body = read_skill_body(library.require(suggestion["skill_id"]))
        except (KeyError, OSError):
            body = ""
        items.append({
            "skill_id": suggestion["skill_id"], "title": suggestion.get("title"),
            "why": suggestion.get("reason"), **checklist(body),
            "unavailable_capabilities": list((suggestion.get("execution") or {}).get("unavailable_capabilities") or [])[:8],
            "read": f"POST /hunts/{hunt_id}/skills/{suggestion['skill_id']}/read",
        })
    return {
        "signals": signals,
        "methodologies": items,
        "note": ("Methodologies matched to the routes and inputs mapped so far; advisory only (no "
                 "authority, scope or budget). Work the steps with the Hunt's capabilities, and read "
                 "the full text for the techniques and false-positive controls. A step no capability "
                 "can run is a coverage gap, not a clean result."),
    }


async def surface_rows(conn: Any, row: Mapping[str, Any]) -> list[dict[str, Any]]:
    """The routes and inputs this Hunt has reached: every path it sent (with its query names) and
    the routes its coverage report maps (with their inputs). The target inventory is only one of
    the sources: Continuous ASM, which fills it, may be off."""
    import urllib.parse
    rows: list[dict[str, Any]] = []
    sent = await conn.fetch(
        """SELECT DISTINCT url FROM http_transactions WHERE hunt_run_id=$1 LIMIT $2""",
        row.get("id"), MAX_ENDPOINTS)
    for item in sent:
        parts = urllib.parse.urlsplit(str(item["url"] or ""))
        names = [name for name, _value in urllib.parse.parse_qsl(parts.query, keep_blank_values=True)]
        rows.append({"path": parts.path or "/", "param_shape": "&".join(names), "content_type": None})
    from .coverage_map import load_coverage
    report = await load_coverage(conn, row) or {}
    for item in [*(report.get("open") or ()), *(report.get("signed_in") or ())]:
        method, _, route = str(item.get("endpoint") or "").partition(" ")
        rows.append({"path": route, "param_shape": "&".join(str(name) for name in item.get("params") or ()),
                     "content_type": None})
    return rows


async def briefing_section(conn: Any, row: Mapping[str, Any]) -> dict[str, Any]:
    if not row.get("target_id"):
        return {"signals": [], "methodologies": []}
    policy = row.get("policy_json") or {}
    if isinstance(policy, str):
        import json
        policy = json.loads(policy or "{}")
    allowed = policy.get("allowed_capabilities") if isinstance(policy, Mapping) else None
    return build_section(
        hunt_id=str(row.get("id")), signals=surface_signals(await surface_rows(conn, row)),
        objective=str(row.get("objective") or ""), target_kind=str(row.get("target_kind") or "web"),
        allowed_capabilities=allowed,
    )
