"""Open-redirect probe: does a redirect parameter send the browser to any URL it is given?

Candidates are discovered routes whose query declares a conventionally named redirect parameter
(``next``, ``returnUrl``, ``redirect_uri`` ...; ``scan.posture_findings.REDIRECT_PARAMETER_NAMES``).
Each is requested once with GET, that one parameter set to an out-of-scope, non-resolving canary
URL (``https://shakerscan-redirect-probe.invalid/``), and redirects are NOT followed: the canary
is never contacted. A redirect whose ``Location`` names the canary host is the proof; any other
answer (the application ignored the value, kept the user on-site, refused it) is not a finding.

Pure functions plus one bounded loop over an injected ``send``; scope, pinning and the archive
are the caller's transport's.
"""

from __future__ import annotations

import hashlib
import urllib.parse
from typing import Any, Awaitable, Callable, Iterable, Mapping

try:
    from scan.posture_findings import REDIRECT_CANARY_URL, is_redirect_parameter, redirects_to_canary
    from scan.work_manifests import ScanWorkManifestError, execution_url_for_endpoint
except ModuleNotFoundError:  # package import in host-side tests
    from ..scan.posture_findings import REDIRECT_CANARY_URL, is_redirect_parameter, redirects_to_canary
    from ..scan.work_manifests import ScanWorkManifestError, execution_url_for_endpoint

OPEN_REDIRECT_PARSER_VERSION = "open-redirect-probe/v1"
MAX_PARAMETERS_PER_ROUTE = 3
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


def probe_url(url: str, parameter: str) -> str:
    """``url`` with its query replaced by the one redirect parameter set to the canary."""
    parts = urllib.parse.urlsplit(url)
    query = urllib.parse.urlencode([(parameter, REDIRECT_CANARY_URL)])
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path or "/", query, ""))


def redirect_candidates(entries: Iterable[Mapping[str, Any]]) -> list[dict[str, str]]:
    """(route, parameter) pairs worth one probe, from value-free endpoint manifest entries."""
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for entry in entries:
        names = [
            str(name) for name in entry.get("query_parameter_names") or ()
            if is_redirect_parameter(name)
        ][:MAX_PARAMETERS_PER_ROUTE]
        for name in names:
            try:
                base = execution_url_for_endpoint(entry, parameter_name=name)
            except (ScanWorkManifestError, KeyError, TypeError, ValueError):
                continue
            url = probe_url(base, name)
            if url in seen:
                continue
            seen.add(url)
            out.append({
                "url": url, "parameter": name, "route_id": str(entry.get("route_id") or ""),
                "attempt_key": hashlib.sha256(url.encode()).hexdigest(),
            })
    return out


def _location(headers: Mapping[str, Any] | None) -> str:
    for name, value in (headers or {}).items():
        if str(name).lower() == "location":
            return str(value)[:2_000]
    return ""


SendResult = tuple[int | None, Mapping[str, Any] | None]


async def probe_candidate(candidate: Mapping[str, str], send: Callable[[str], Awaitable[SendResult]]) -> dict[str, Any]:
    """One request; a ``open_redirect_proof`` observation when Location names the canary."""
    status, headers = await send(candidate["url"])
    location = _location(headers)
    proven = isinstance(status, int) and status in _REDIRECT_STATUSES and redirects_to_canary(location)
    return {
        "kind": "open_redirect_proof",
        "url": candidate["url"],
        "parameter": candidate["parameter"],
        "route_id": candidate.get("route_id"),
        "status": status,
        # Only a Location that names the canary is kept: any other value is the application's
        # own redirect target and may carry its state.
        "location": location if proven else "",
        "proof_state": "verified" if proven else "not_proven",
    }


__all__ = [
    "MAX_PARAMETERS_PER_ROUTE", "OPEN_REDIRECT_PARSER_VERSION", "probe_candidate", "probe_url",
    "redirect_candidates",
]
