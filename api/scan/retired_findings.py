"""Resolve stored findings of kinds the scanner no longer reports, once a scan proves them covered.

Web findings never resolve on their own: a row stays ``active`` until someone triages it. When a
release stops reporting a kind of finding -- because another finding now carries it (the
baseline's missing-header finding absorbed the passive template's duplicate) or because it was
never a finding (HSTS over plain HTTP, which browsers ignore) -- the rows earlier scans wrote stay
active forever, beside the finding that replaced them.

``retire_superseded_findings`` closes exactly those rows, narrowly:

* only kinds listed in ``RETIRED_FINDING_KINDS`` (tool, template and header name, origin scheme);
* only on the origin this scan's baseline request observed (an application response whose
  security headers were recorded), so the replacing check actually ran there; a duplicate the
  baseline finding absorbed only for a header this scan's baseline finding reports missing;
* only ``active`` rows with no analyst verdict: accepted-risk, false-positive and analyst-judged
  rows are never touched;
* never a row this scan reported again (any of its identity keys).

A retired row becomes ``resolved`` (an existing status, so no schema change) with
``evidence.retired`` naming the kind, the reason and the scan. A later scan that reports it again
reopens it the usual way.

To retire another kind, add a ``RetiredFindingKind`` to ``RETIRED_FINDING_KINDS``.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, Iterable, Mapping
import urllib.parse

try:
    from finding_routes.list_schema import FINDING_ORIGIN_SQL
except ModuleNotFoundError:  # package import layout
    from ..finding_routes.list_schema import FINDING_ORIGIN_SQL


@dataclass(frozen=True)
class RetiredFindingKind:
    """One kind of stored finding the scanner no longer reports."""

    name: str
    reason: str
    tool: str
    template_id: str
    #: Lower-case header names (the template's matcher); the stored row names it in
    #: ``evidence.header_name`` (or, on older rows, ``evidence.matcher_name``).
    header_names: frozenset[str]
    #: Origin schemes the kind is retired on.
    schemes: frozenset[str] = frozenset({"http", "https"})
    #: True when another finding now carries this one: a header is retired only when this scan's
    #: baseline reported that same header missing on the origin. False when the kind is no
    #: longer a finding at all (retired once the baseline observed the origin).
    superseded_by_baseline: bool = False


_MISSING_HEADERS_TEMPLATE = "http-missing-security-headers"

RETIRED_FINDING_KINDS: tuple[RetiredFindingKind, ...] = (
    RetiredFindingKind(
        name="nuclei_missing_header_folded_into_baseline",
        reason="Reported by the baseline response's missing-header finding for this origin (2.11).",
        tool="nuclei",
        template_id=_MISSING_HEADERS_TEMPLATE,
        header_names=frozenset({
            "content-security-policy", "referrer-policy", "permissions-policy",
            "strict-transport-security",
        }),
        schemes=frozenset({"https"}),
        superseded_by_baseline=True,
    ),
    RetiredFindingKind(
        name="nuclei_missing_header_folded_into_baseline_http",
        reason="Reported by the baseline response's missing-header finding for this origin (2.11).",
        tool="nuclei",
        template_id=_MISSING_HEADERS_TEMPLATE,
        header_names=frozenset({"content-security-policy", "referrer-policy", "permissions-policy"}),
        schemes=frozenset({"http"}),
        superseded_by_baseline=True,
    ),
    RetiredFindingKind(
        name="nuclei_hsts_on_plain_http",
        reason="Browsers ignore HSTS received over plain HTTP; its absence there is not a finding (2.11).",
        tool="nuclei",
        template_id=_MISSING_HEADERS_TEMPLATE,
        header_names=frozenset({"strict-transport-security"}),
        schemes=frozenset({"http"}),
    ),
)


def _origin_spellings(url: Any) -> tuple[str, list[str]]:
    """The scheme and the spellings of ``url``'s origin a stored URL may use (default port or not)."""
    try:
        parsed = urllib.parse.urlsplit(str(url or "").strip())
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or "").lower().rstrip(".")
        port = parsed.port
    except ValueError:
        return "", []
    if scheme not in {"http", "https"} or not host:
        return "", []
    host = f"[{host}]" if ":" in host else host
    default = 443 if scheme == "https" else 80
    base = f"{scheme}://{host}"
    if port is None or port == default:
        return scheme, [base, f"{base}:{default}"]
    return scheme, [f"{base}:{port}"]


def baseline_missing_headers(report: Mapping[str, Any], origins: Iterable[str]) -> frozenset[str]:
    """Headers this scan's baseline finding reports missing on one of ``origins``."""
    wanted = set(origins)
    headers: set[str] = set()
    for finding in report.get("findings") or ():
        if not isinstance(finding, Mapping) or finding.get("tool") != "http_baseline":
            continue
        evidence = finding.get("evidence") if isinstance(finding.get("evidence"), Mapping) else {}
        check = str(evidence.get("check") or "")
        if check.startswith("missing_header_") and set(_origin_spellings(finding.get("url"))[1]) & wanted:
            headers.add(check.removeprefix("missing_header_").lower())
    return frozenset(headers)


def baseline_covered_origin(report: Mapping[str, Any]) -> str | None:
    """The origin whose security headers this scan's baseline response recorded, else None."""
    http = report.get("http") if isinstance(report.get("http"), Mapping) else {}
    if http.get("posture_observed") is not True:
        return None
    target = str(report.get("target") or "")
    return target if _origin_spellings(target)[1] else None


RETIRE_SQL = f"""
    UPDATE findings
    SET status = 'resolved', resolved_at = NOW(), updated_at = NOW(),
        evidence = COALESCE(evidence, '{{}}'::jsonb) || jsonb_build_object('retired', $7::jsonb)
    WHERE target_id = $1 AND status = 'active' AND analyst_verdict IS NULL
      AND tool = $2 AND evidence->>'template_id' = $3
      AND lower(COALESCE(evidence->>'header_name', evidence->>'matcher_name')) = ANY($4::text[])
      AND {FINDING_ORIGIN_SQL} = ANY($5::text[])
      AND NOT (fingerprint = ANY($6::text[]))
    RETURNING id
"""


async def retire_superseded_findings(
    conn: Any,
    *,
    target_id: Any,
    scan_id: Any,
    report: Mapping[str, Any],
    seen_fingerprints: Iterable[str],
    kinds: Iterable[RetiredFindingKind] = RETIRED_FINDING_KINDS,
) -> int:
    """Resolve this target's active rows of retired kinds on the origin this scan covered."""
    origin = baseline_covered_origin(report)
    if origin is None:
        return 0
    scheme, origins = _origin_spellings(origin)
    seen = sorted({str(value) for value in seen_fingerprints if value})
    superseding = baseline_missing_headers(report, origins)
    retired = 0
    for kind in kinds:
        if scheme not in kind.schemes:
            continue
        headers = kind.header_names & superseding if kind.superseded_by_baseline else kind.header_names
        if not headers:
            continue
        rows = await conn.fetch(
            RETIRE_SQL, target_id, kind.tool, kind.template_id, sorted(headers),
            origins, seen,
            json.dumps({"kind": kind.name, "reason": kind.reason, "scan_id": str(scan_id)}),
        )
        retired += len(rows)
    return retired


__all__ = [
    "RETIRED_FINDING_KINDS", "RETIRE_SQL", "RetiredFindingKind", "baseline_covered_origin", "baseline_missing_headers",
    "retire_superseded_findings",
]
