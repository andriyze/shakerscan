"""Words that name a state-changing action, shared by every automated discovery path.

The browser crawler uses them to refuse clicking a control or following a link that looks like
an action (log out, delete, revoke...); parameter discovery uses the same words to leave such a
route alone. Identifiers are split on case and separators first, so ``logoutUser`` and
``delete_all`` are recognized, while a word inside another word (``runbook``) is not.

A path segment that looks like a one-time token (a magic link, a confirmation or unsubscribe
link) is also an action: requesting it may consume or confirm something.
"""

from __future__ import annotations

import math
import re
from typing import Any
import urllib.parse

RISKY_INTERACTION_KEYWORDS = (
    "logout", "log out", "sign out", "signout",
    "delete", "remove", "destroy", "erase",
    "cancel", "deactivate", "disable", "revoke",
    "reset", "clear all", "wipe", "start", "run", "launch",
    "submit", "save", "create", "update", "approve", "reject",
    "unsubscribe", "close account", "terminate",
)
RISKY_NAVIGATION_KEYWORDS = (
    "logout", "log out", "sign out", "signout",
    "delete", "remove", "destroy", "erase", "deactivate", "disable",
    "revoke", "reset", "clear all", "wipe", "unsubscribe",
    "close account", "terminate",
)

_TOKEN_SEGMENT = re.compile(r"[A-Za-z0-9_\-.~=+]{16,}")
_HEX_RUN = re.compile(r"[0-9a-fA-F]{20,}")
_TOKEN_MIN_ENTROPY_BITS = 3.0


def semantic_text(*values: Any) -> str:
    """Normalize camelCase and separators so action words cannot hide in identifiers."""
    combined = " ".join(str(value or "") for value in values)
    combined = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", combined)
    return re.sub(r"[^A-Za-z0-9]+", " ", combined).strip().lower()


def contains_risky_keyword(values: tuple[Any, ...], keywords: tuple[str, ...]) -> bool:
    combined = semantic_text(*values)
    if not combined:
        return False
    padded = f" {combined} "
    return any(f" {semantic_text(keyword)} " in padded for keyword in keywords)


def navigation_url_is_safe(value: str) -> bool:
    """Whether following a link to ``value`` cannot name an action."""
    parsed = urllib.parse.urlsplit(str(value or ""))
    return not contains_risky_keyword((parsed.path, parsed.fragment), RISKY_NAVIGATION_KEYWORDS)


def _entropy_bits(value: str) -> float:
    counts: dict[str, int] = {}
    for character in value:
        counts[character] = counts.get(character, 0) + 1
    total = float(len(value))
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def token_like_segment(segment: str) -> bool:
    """A path segment shaped like a one-time token: long, mixed letters and digits, random."""
    text = urllib.parse.unquote(str(segment or ""))
    if _HEX_RUN.search(text):
        return True
    if not _TOKEN_SEGMENT.fullmatch(text):
        return False
    has_digit = any(character.isdigit() for character in text)
    has_alpha = any(character.isalpha() for character in text)
    return has_digit and has_alpha and _entropy_bits(text) >= _TOKEN_MIN_ENTROPY_BITS


def path_may_change_state(path: str) -> bool:
    """Whether a GET of ``path`` may act rather than read: an action word in it (the crawler's
    interaction words, the broadest list) or a token-like segment."""
    text = str(path or "")
    if contains_risky_keyword((text,), RISKY_INTERACTION_KEYWORDS):
        return True
    return any(token_like_segment(segment) for segment in text.split("/") if segment)


__all__ = [
    "RISKY_INTERACTION_KEYWORDS", "RISKY_NAVIGATION_KEYWORDS", "contains_risky_keyword",
    "navigation_url_is_safe", "path_may_change_state", "semantic_text", "token_like_segment",
]
