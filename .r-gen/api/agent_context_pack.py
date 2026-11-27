"""Honest, token-bounded context packer.

Ported from T3MP3ST ``src/orchestration/context-pack.ts`` (``packContext``). The design
principle is **no silent loss** (our ``trust-gate-antipatterns`` lesson: silent
truncation reads as coverage). Guarantees:

  1. an always-present MAP header listing every section (capped, with an explicit
     "N more (not listed — map capped for budget)" note — never a silent drop);
  2. relevance ranking by objective keywords + security hints (stable/deterministic);
  3. oversized sections head/tail-elided with a visible marker, never hard-truncated;
  4. an explicit ``included`` / ``dropped`` list + token telemetry so trimming is observable.

Generalized from T3MP3ST's file-oriented packer to heterogeneous DB-derived *sections*:
each item is ``{key, body, loc?, bytes?}``. Stdlib only — host-testable, flat-importable.
"""
from __future__ import annotations

import math
import re
from typing import Any

# Security-relevant path/content tokens get a ranking boost (T:context-pack.ts:134),
# extended with app-agnostic vuln-surface words useful for a live pentest pack.
SECURITY_HINTS: frozenset[str] = frozenset(
    {
        "route", "handler", "controller", "endpoint", "api",
        "auth", "login", "logout", "session", "token", "jwt", "oauth", "sso",
        "password", "secret", "key", "credential", "cookie",
        "role", "admin", "privilege", "permission", "tenant", "owner",
        "deserialize", "pickle", "yaml", "xml", "exec", "system", "eval", "spawn",
        "sql", "query", "nosql", "mongo", "graphql",
        "upload", "file", "path", "template", "render", "redirect",
        "user", "account", "basket", "cart", "order", "coupon", "payment", "wallet",
    }
)

_WORD = re.compile(r"[a-z0-9_]{3,}")
_ELISION = "\n\n…[middle elided for context budget]…\n\n"


def estimate_tokens(s: str) -> int:
    """Documented approximation (~4 chars/token), deliberately over-estimating so we
    under-fill rather than overflow. Port of ``estimateTokens`` (T:...:62)."""
    return math.ceil(len(s) / 4)


def _extract_keywords(*texts: str) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for t in texts:
        for w in _WORD.findall((t or "").lower()):
            if w not in seen:
                seen.add(w)
                ordered.append(w)
    return ordered


def _score_item(item: dict[str, Any], keywords: list[str]) -> int:
    key = str(item.get("key", "")).lower()
    body = str(item.get("body", "")).lower()
    score = 0
    for kw in keywords:
        if kw in key:
            score += 5
        occ = body.count(kw)
        if occ:
            score += min(occ, 20)
    for hint in SECURITY_HINTS:
        if hint in key:
            score += 4
        if hint in body:
            score += 1
    return score


def _render_body(body: str, token_budget: int) -> str:
    """Whole body if it fits; else head(0.6)/tail elision with a visible marker."""
    if token_budget <= 0:
        return ""
    if estimate_tokens(body) <= token_budget:
        return body
    char_budget = token_budget * 4 - len(_ELISION)
    if char_budget <= 0:
        return body[: token_budget * 4]
    head = int(char_budget * 0.6)
    tail = char_budget - head
    return body[:head] + _ELISION + (body[-tail:] if tail > 0 else "")


def pack_context(
    items: list[dict[str, Any]],
    *,
    token_budget: int,
    objective: str = "",
    prior_intel: str = "",
) -> dict[str, Any]:
    """Pack ``items`` into a token-bounded text blob with honest drop telemetry.

    Returns ``{text, included, dropped, tokens_used, token_budget}``.
    """
    token_budget = max(0, int(token_budget))
    items = [i for i in items if isinstance(i, dict)]

    keywords = _extract_keywords(objective, prior_intel)
    # Stable sort: score desc, then original index (deterministic).
    ranked = [it for _, it in sorted(enumerate(items), key=lambda p: (-_score_item(p[1], keywords), p[0]))]

    # --- always-present MAP header (reserve ~15% of budget) ---
    map_cap = max(200, int(token_budget * 0.15))
    map_lines = [f"=== CONTEXT MAP ({len(items)} sections) ==="]
    map_tokens = estimate_tokens(map_lines[0])
    listed = 0
    for it in ranked:
        rows = it.get("loc", 0)
        nbytes = it.get("bytes", len(str(it.get("body", ""))))
        line = f"  - {it.get('key', '?')} (~{rows} rows, {nbytes} bytes)"
        line_tokens = estimate_tokens(line)
        if listed >= 1 and map_tokens + line_tokens > map_cap:
            break
        map_lines.append(line)
        map_tokens += line_tokens
        listed += 1
    if listed < len(ranked):
        map_lines.append(
            f"  … {len(ranked) - listed} more sections (not listed — map capped for budget)"
        )
    map_text = "\n".join(map_lines)

    # --- pack bodies highest-score-first ---
    tokens_used = estimate_tokens(map_text)
    included: list[str] = []
    dropped: list[str] = []
    body_parts: list[str] = [map_text]
    for it in ranked:
        key = str(it.get("key", "?"))
        header = f"\n=== SECTION: {key} ===\n"
        header_cost = estimate_tokens(header)
        remaining = token_budget - tokens_used
        if remaining - header_cost < 8:
            dropped.append(key)
            continue
        rendered = _render_body(str(it.get("body", "")), remaining - header_cost)
        cost = header_cost + estimate_tokens(rendered)
        if included and tokens_used + cost > token_budget:
            dropped.append(key)
            continue
        body_parts.append(header + rendered)
        included.append(key)
        tokens_used += cost

    return {
        "text": "\n".join(body_parts),
        "included": included,
        "dropped": dropped,
        "tokens_used": tokens_used,
        "token_budget": token_budget,
    }
