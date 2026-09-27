"""Which frozen origin serves a target that was entered without a scheme.

A target typed as ``example.com`` (or ``example.com:8080``) is admitted for both
``https://`` and ``http://`` on that authority: the operator did not choose, so admission
freezes both. Something still has to choose before any tool runs, and choosing by
preference alone was wrong in both directions -- an HTTP-only application was examined
over HTTPS that nobody answered, and an unreachable one was reported as if it had been
examined.

The choice is made during execution by one bounded, metered, target-bound probe: a single
read-only ``GET /`` per frozen origin of that authority, HTTPS first, stopping at the first
origin that answers with the application. It runs as the plan's ``transport.resolve``
action under its own budget reservation and receipt, so the requests count against the
Scan budget and every attempt -- answered or refused -- is kept as evidence. Every other
network action depends on it and runs against the origin it selected.

Rules the probe never bends:

* It only chooses among origins admission froze; it never adds one, never follows a
  redirect and never changes host.
* A target entered with an explicit ``http://`` or ``https://`` stays exact; the action
  then sends nothing.
* When no frozen origin answers, nothing is selected. The action fails with the
  connection errors, every dependent action is blocked, and the report says the
  application was not examined -- it does not quietly fall back to HTTPS.
"""
from __future__ import annotations

import urllib.parse
from typing import Any, Awaitable, Callable, Mapping, Sequence

try:
    from runtime.models import TargetBinding
    from runtime.request_collection_store import (
        RequestCollectionContractError,
        canonical_collection_origin,
    )
except ModuleNotFoundError:  # package imports in host-side tests
    from ..runtime.models import TargetBinding
    from ..runtime.request_collection_store import (
        RequestCollectionContractError,
        canonical_collection_origin,
    )

from .redirect_evidence import REDIRECT_STATUSES, http_origin, redirect_destination


TRANSPORT_ACTION_ID = "transport.resolve"
TRANSPORT_STAGE = "bind_target"
PROBE_TIMEOUT_SECONDS = 10
_SCHEME_PREFERENCE = ("https", "http")

# Outcomes of one probe attempt.
RESPONDED = "responded"
REDIRECTS_TO_FROZEN_ORIGIN = "redirects_to_frozen_origin"
REDIRECTS_OFF_ORIGIN = "redirects_off_origin"
UNREACHABLE = "unreachable"


def binding_admits_both_schemes(target: TargetBinding) -> bool:
    """Whether admission froze HTTP and HTTPS origins on the target's own host.

    That is what admission does for a target entered without a scheme, so a plan for such
    a binding carries ``transport.resolve``. The runtime target still decides whether the
    probe runs: an explicit scheme keeps the action traffic-free.
    """
    schemes = {
        urllib.parse.urlsplit(origin).scheme
        for origin in target.allowed_origins
        if urllib.parse.urlsplit(origin).hostname == target.canonical_host
    }
    return {"http", "https"} <= schemes


def transport_probe_budget() -> dict[str, int]:
    """One request per candidate origin, each bounded by the probe timeout."""
    return {
        "http_requests": len(_SCHEME_PREFERENCE),
        "tool_wall_seconds": len(_SCHEME_PREFERENCE) * PROBE_TIMEOUT_SECONDS,
    }


def transport_candidates(runtime_target: Any, target: TargetBinding) -> tuple[str, ...] | None:
    """The frozen origins a bare ``host[:port]`` runtime target may resolve to.

    ``None`` means the target names its scheme and stays exact. An empty tuple means a bare
    target with no frozen origin for its authority -- which admission never produces, so
    the caller must refuse rather than guess.
    """
    text = str(runtime_target or "").strip()
    if not text or "://" in text:
        return None
    try:
        parsed = urllib.parse.urlsplit(f"//{text}")
        _ = parsed.port
    except ValueError:
        return ()
    if (
        parsed.path not in {"", "/"} or parsed.query or parsed.fragment
        or parsed.username or parsed.password or not parsed.hostname
        or parsed.hostname.lower().rstrip(".") != target.canonical_host
    ):
        return ()
    candidates: list[str] = []
    for scheme in _SCHEME_PREFERENCE:
        try:
            origin = canonical_collection_origin(f"{scheme}://{parsed.netloc}")
        except RequestCollectionContractError:
            continue
        if origin in target.allowed_origins and origin not in candidates:
            candidates.append(origin)
    return tuple(candidates)


def scheme_less_target(url: Any) -> str:
    """``host[:port]`` of a stored target URL, for resubmitting a target typed without a scheme."""
    parsed = urllib.parse.urlsplit(str(url or "").strip())
    host = str(parsed.hostname or "")
    if not host:
        return str(url or "")
    display = f"[{host}]" if ":" in host else host
    return f"{display}:{parsed.port}" if parsed.port else display


def classify_attempt(
    origin: str, result: Mapping[str, Any], *, frozen_origins: Sequence[str],
) -> dict[str, Any]:
    """What one probe answer says about ``origin``, without following it."""
    response = result.get("response") if isinstance(result.get("response"), Mapping) else {}
    status = response.get("status")
    attempt: dict[str, Any] = {"origin": origin, "status": None, "outcome": UNREACHABLE}
    if type(status) is not int:
        attempt["error"] = str(result.get("error") or "no_response")[:300]
        return attempt
    attempt["status"] = status
    attempt["outcome"] = RESPONDED
    if status in REDIRECT_STATUSES:
        destination = http_origin(redirect_destination(origin, response.get("location")))
        if destination and destination != http_origin(origin):
            frozen = {http_origin(item) for item in frozen_origins}
            attempt["redirect_origin"] = destination
            attempt["outcome"] = (
                REDIRECTS_TO_FROZEN_ORIGIN if destination in frozen else REDIRECTS_OFF_ORIGIN
            )
    return attempt


def choose_effective_origin(attempts: Sequence[Mapping[str, Any]]) -> str | None:
    """The origin the Scan examines, or ``None`` when no frozen origin answered.

    An origin that serves the application wins, HTTPS first. When every answering origin
    only forwards elsewhere, the first of them is still examined -- it is reachable and in
    scope -- and finalization reports that the application behind the redirect was not.
    """
    for attempt in attempts:
        if attempt.get("outcome") == RESPONDED:
            return str(attempt["origin"])
    for attempt in attempts:
        if attempt.get("outcome") in {REDIRECTS_TO_FROZEN_ORIGIN, REDIRECTS_OFF_ORIGIN}:
            return str(attempt["origin"])
    return None


ProbeRequest = Callable[[str], Awaitable[Mapping[str, Any]]]


async def probe_transport(
    candidates: Sequence[str], request: ProbeRequest,
) -> tuple[list[dict[str, Any]], list[Mapping[str, Any]]]:
    """Probe candidates in order, stopping at the first that serves the application."""
    attempts: list[dict[str, Any]] = []
    raw: list[Mapping[str, Any]] = []
    for origin in candidates:
        result = dict(await request(origin))
        attempt = classify_attempt(origin, result, frozen_origins=candidates)
        attempts.append(attempt)
        raw.append(result)
        if attempt["outcome"] == RESPONDED:
            break
    return attempts, raw


def selected_origin(observations: Sequence[Mapping[str, Any]]) -> str | None:
    """The origin ``transport.resolve`` persisted as selected, if any."""
    for row in observations:
        if not isinstance(row, Mapping):
            continue
        probe = row.get("transport_probe")
        if isinstance(probe, Mapping) and probe.get("selected") is True:
            # Receipt redaction may render an origin as a URL with a root path.
            return http_origin(str(probe.get("origin") or ""))
    return None


def transport_summary(observations: Sequence[Mapping[str, Any]]) -> dict[str, Any] | None:
    """Content-free record of the probe for the report: attempts and the selection."""
    attempts = [
        {
            **dict(row["transport_probe"]),
            "origin": http_origin(str(row["transport_probe"].get("origin") or "")),
        }
        for row in observations
        if isinstance(row, Mapping) and isinstance(row.get("transport_probe"), Mapping)
    ]
    if not attempts:
        return None
    return {
        "effective_origin": next(
            (item["origin"] for item in attempts if item.get("selected") is True), None,
        ),
        "attempts": attempts,
    }


__all__ = [
    "PROBE_TIMEOUT_SECONDS",
    "TRANSPORT_ACTION_ID",
    "TRANSPORT_STAGE",
    "binding_admits_both_schemes",
    "choose_effective_origin",
    "classify_attempt",
    "probe_transport",
    "scheme_less_target",
    "selected_origin",
    "transport_candidates",
    "transport_probe_budget",
    "transport_summary",
]
