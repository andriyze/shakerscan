"""Measured absent-response calibration for bounded content discovery.

Content discovery counts a response as a hit by status code. A host that answers
every unknown path the same way -- a blanket redirect to its canonical origin, or
a single-page application's catch-all 200 -- therefore reports the whole wordlist
as discovered surface. Inferring that from the shape of the hits alone is not
proof: several real moved routes look identical to a rewrite.

So measure it. A few high-entropy paths that cannot exist are probed alongside the
wordlist, inside the same exact request reservation, and their responses are the
negative control. A discovered path whose response is indistinguishable from a
path that certainly does not exist carries no evidence that it does.

These helpers are pure and content-free: they describe observations and never
send traffic, follow redirects, or widen scope.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any, Iterable, Mapping
import urllib.parse

from .redirect_evidence import REDIRECT_STATUSES, http_origin, redirect_destination

# A leading dot keeps the probe off any routable namespace, and the digest keeps
# it out of any wordlist or real deployment.
CONTROL_PATH_PREFIX = ".shakerscan-absent-"
# Match the exact shape this module generates, so a target-supplied path that
# merely starts with the prefix cannot pose as our own measurement.
_CONTROL_SEGMENT = re.compile(re.escape(".shakerscan-absent-") + r"[0-9a-f]{16}")
# One absent path answering unusually is not a server-wide rule.
_MIN_AGREEING_CONTROLS = 2
# How the scanner projection marks a value it removed, raw and percent-encoded.
_REDACTION_MARKERS = ("<redacted>", "%3credacted%3e")
# Enough to distinguish a stable rewrite from one unlucky collision, small enough
# that it never meaningfully displaces real wordlist coverage.
DEFAULT_CONTROL_COUNT = 3
# Below this the reservation is too small to spend any of it on calibration.
MIN_CALIBRATED_REQUESTS = 20


def negative_control_entries(count: int, *, seed: str) -> tuple[str, ...]:
    """Return `count` wordlist entries that no deployment can serve."""
    entries: list[str] = []
    for index in range(max(0, int(count))):
        digest = hashlib.sha256(f"{seed}:{index}".encode()).hexdigest()[:16]
        entries.append(f"{CONTROL_PATH_PREFIX}{digest}")
    return tuple(entries)


def control_slot_count(request_limit: int) -> int:
    """How many of an exact request reservation to spend on calibration."""
    if int(request_limit) < MIN_CALIBRATED_REQUESTS:
        return 0
    return DEFAULT_CONTROL_COUNT


def with_negative_controls(
    entries: list[str], *, request_limit: int, seed: str,
) -> list[str]:
    """Spend a few of an exact request reservation on paths that cannot exist.

    Taken from inside the ceiling, never added to it, so the wire count and the
    reservation stay exactly as reconciled.
    """
    controls = negative_control_entries(control_slot_count(request_limit), seed=seed)
    if not controls or len(entries) <= len(controls):
        return list(entries)
    return list(entries[:len(entries) - len(controls)]) + list(controls)


def is_negative_control_url(url: Any) -> bool:
    """Whether an observation is one of the probes for a path that cannot exist."""
    try:
        path = urllib.parse.urlsplit(str(url or "")).path
    except ValueError:
        return False
    return any(
        _CONTROL_SEGMENT.fullmatch(segment)
        for segment in path.split("/")
    )


def _redaction_obscured(value: Any) -> bool:
    """Whether a URL arrives with a value the redactor has already replaced.

    The scanner projection removes secret-shaped path segments and every query
    value before these observations exist, so two URLs that differed only there
    are identical by the time they are compared.
    """
    text = str(value or "").lower()
    return any(marker in text for marker in _REDACTION_MARKERS)


def absent_response_signature(
    item: Mapping[str, Any],
) -> tuple[Any, ...] | None:
    """Describe a response only when two of them could not be told apart.

    Returns None when the observation cannot establish sameness. Content
    discovery reports a status, a length and a redirect location and nothing
    else, so two 200s of equal length are not demonstrably the same page: a
    real route that happens to match a catch-all's length is indistinguishable
    to this projection but not to a client, and suppressing it would remove a
    genuine endpoint before it was ever tested. Only an origin-wide rewrite --
    the same status forwarding the requested path unchanged to the same other
    origin -- is a rule rather than a coincidence.
    """
    status = item.get("status")
    if type(status) is not int or status not in REDIRECT_STATUSES:
        return None
    url = str(item.get("url") or "")
    source = http_origin(url)
    location = item.get("redirect_location")
    destination = redirect_destination(url, location) if location else None
    origin = http_origin(destination)
    if not source or not origin or source == origin:
        return None
    try:
        probed = urllib.parse.urlsplit(url)
        moved = urllib.parse.urlsplit(destination)
    except ValueError:
        return None
    # Whether the redirect only moved the origin is decided by the producer, on
    # the raw pair, before redaction. It cannot be re-derived here: redaction
    # strips the fragment outright and collapses every query value and
    # secret-shaped path segment to one marker, so /report?mode=summary ->
    # /report?mode=restricted and /admin -> /admin#/admin/users both arrive
    # looking like a blanket origin rewrite. Absent that fact, make no claim.
    if item.get("redirect_preserves_request_target") is not True:
        return None
    if _redaction_obscured(url) or _redaction_obscured(destination):
        return None
    if (moved.path or "/") != (probed.path or "/") or moved.query != probed.query:
        return None
    return ("origin_rewrite", status, source, origin)


def indistinguishable_from_absent(
    observations: Iterable[Mapping[str, Any]],
) -> frozenset[str]:
    """Return discovered URLs answered by the same rule as a measured absent path.

    Empty when the run carried no control probe, or when a single control
    disagreed with the others: one anomalous answer is not a server-wide rule,
    and this makes no claim it cannot support.
    """
    rows = [item for item in observations if isinstance(item, Mapping)]
    # Query variants, fragments and default-port spellings do not make the
    # same high-entropy path an independent control. A duplicate with conflicting
    # evidence invalidates that origin's calibration rather than winning a vote.
    by_origin: dict[str, dict[str, set[tuple[Any, ...] | None]]] = {}
    for item in rows:
        url = item.get("url")
        if not is_negative_control_url(url):
            continue
        source = http_origin(url)
        if source is None:
            continue
        path = urllib.parse.urlsplit(str(url)).path
        by_origin.setdefault(source, {}).setdefault(path, set()).add(
            absent_response_signature(item)
        )
    absent: set[tuple[Any, ...]] = set()
    for controls in by_origin.values():
        if len(controls) < _MIN_AGREEING_CONTROLS:
            continue
        signatures = set().union(*controls.values())
        if len(signatures) == 1 and None not in signatures:
            absent.update(signatures)
    if not absent:
        return frozenset()
    return frozenset(
        url
        for item in rows
        if not is_negative_control_url(item.get("url"))
        and (url := str(item.get("url") or ""))
        and absent_response_signature(item) in absent
    )


__all__ = [
    "CONTROL_PATH_PREFIX",
    "DEFAULT_CONTROL_COUNT",
    "MIN_CALIBRATED_REQUESTS",
    "absent_response_signature",
    "control_slot_count",
    "indistinguishable_from_absent",
    "is_negative_control_url",
    "negative_control_entries",
    "with_negative_controls",
]
