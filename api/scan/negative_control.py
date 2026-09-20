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
from typing import Any, Iterable, Mapping
import urllib.parse

from .redirect_evidence import REDIRECT_STATUSES, http_origin, redirect_destination

# A leading dot keeps the probe off any routable namespace, and the digest keeps
# it out of any wordlist or real deployment.
CONTROL_PATH_PREFIX = ".shakerscan-absent-"
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
        segment.startswith(CONTROL_PATH_PREFIX)
        for segment in path.split("/")
    )


def absent_response_signature(item: Mapping[str, Any]) -> tuple[Any, ...] | None:
    """Describe a response so an absent path and a claimed hit compare exactly.

    Two responses share a signature when a client could not tell them apart: the
    same status, the same redirect destination origin with the requested path
    carried through unchanged, and the same body length.
    """
    status = item.get("status")
    if type(status) is not int:
        return None
    url = str(item.get("url") or "")
    length = item.get("length")
    length = int(length) if type(length) is int else None
    if status in REDIRECT_STATUSES:
        location = item.get("redirect_location")
        destination = redirect_destination(url, location) if location else None
        origin = http_origin(destination)
        if not origin:
            return None
        try:
            probed = urllib.parse.urlsplit(url)
            moved = urllib.parse.urlsplit(destination)
        except ValueError:
            return None
        carried = (moved.path or "/") == (probed.path or "/")
        return ("redirect", status, origin, carried, length)
    return ("response", status, length)


def indistinguishable_from_absent(
    observations: Iterable[Mapping[str, Any]],
) -> frozenset[str]:
    """Return discovered URLs whose response matches a measured absent path.

    Empty when the run carried no control probe: without the measurement this
    makes no claim, and the caller keeps every observation.
    """
    rows = [item for item in observations if isinstance(item, Mapping)]
    controls = {
        signature
        for item in rows
        if is_negative_control_url(item.get("url"))
        and (signature := absent_response_signature(item)) is not None
    }
    if not controls:
        return frozenset()
    return frozenset(
        url
        for item in rows
        if not is_negative_control_url(item.get("url"))
        and (url := str(item.get("url") or ""))
        and absent_response_signature(item) in controls
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
