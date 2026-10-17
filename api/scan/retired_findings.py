"""Resolve stored findings of kinds the scanner no longer reports, once a scan proves them covered.

Web findings never resolve on their own: a row stays ``active`` until someone triages it. When a
release stops reporting a kind of finding -- because another finding now carries it (the
baseline's missing-header finding absorbed the passive template's duplicate; a verified exposure
proof absorbed the passive template's candidate for the same file) or because it was never a
finding (HSTS over plain HTTP, which browsers ignore) -- the rows earlier scans wrote stay active
forever, beside the finding that replaced them.

``retire_superseded_findings`` closes exactly those rows, narrowly:

* only after a scan whose finalized report says it completed (``scan_metadata.status ==
  "complete"``) and, from the worker, whose final coverage (after the action-receipt rollup) is
  ``complete`` and whose findings all saved: a partial, failed or cancelled scan, or one whose
  findings did not persist, retires nothing;
* only kinds listed in ``RETIRED_FINDING_KINDS``, each with its own predicate:

  - ``header``: tool, template and header name, origin scheme, and only on the origin this scan's
    baseline request observed (an application response whose security headers were recorded);
    a duplicate the baseline finding absorbed only for a header this scan's baseline finding
    reports missing on that origin, and only while that baseline finding's stored row (last seen
    by this scan, same origin and header) exists and is active or triaged;
  - ``exposure_proof``: a passive-pack template candidate (no header name) whose origin and path
    are those of an exposure THIS scan verified, whose template detects that proof's exposure
    class (``finalizer._TEMPLATE_EXPOSURE_CLASSES``) and whose severity does not exceed the
    proof's -- the same rule the finalizer folds a fresh candidate by -- and only while the
    proof's stored row (last seen by this scan, same origin, path and class) exists and is
    active or triaged;

* only ``active`` rows nobody has touched: no analyst verdict (ever set), no notes or verdict
  notes, no live finding exception (accepted-risk / approved), no retest queued or running, and
  never a row retired before and set back to ``active`` by an operator (its ``evidence.retired``
  survives a status change; a scan that reports the row again replaces its evidence). Rows with
  status ``accepted_risk`` or ``false_positive`` are not ``active`` and never touched. A row an
  operator reopened from some other ``resolved`` state carries no durable marker (no triage
  history is kept outside the optional gateway decision receipts), so it is indistinguishable
  from one nobody touched; an operator who wants such a row kept adds a note or a verdict;
* never a row this scan reported again (any of its identity keys, or last seen by this scan);
* bounded: each statement is limited to one target and the scan's origins (the partial
  ``idx_findings_active_target_origin`` index), updates at most ``RETIRE_BATCH_SIZE`` rows, and a
  scan retires at most ``RETIRE_MAX_ROWS_PER_SCAN`` rows in all -- the rest go on the next scan;
* idempotent: a retired row is ``resolved``, so a repeated call finds nothing to do.

A retired row becomes ``resolved`` (an existing status, so no schema change) with
``evidence.retired`` naming the kind, the reason, the release, the scan and what superseded it.
Readers tell it apart from a fix (``finding_routes.retirement``): it is labelled "retired by
release" and never counted as resolved in digests or "resolved within" filters. A later scan
that reports it again reopens it the usual way.

A pre-2.11 fleet node finalizes its scans with its own (older) finalizer, which still reports
the template duplicates beside the finding that superseded them. ``without_superseded_duplicates``
drops exactly those -- a retired kind whose superseding finding is in the same report -- before
the control plane saves the report's findings, so an older node's scan neither reopens a retired
row nor keeps it from being retired: the retirement does not flip-flop in a mixed fleet.

To retire another kind, add a ``RetiredFindingKind`` to ``RETIRED_FINDING_KINDS``.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, Awaitable, Callable, Iterable, Literal, Mapping
import urllib.parse
import uuid

try:
    from finding_routes.list_schema import FINDING_ORIGIN_SQL
except ModuleNotFoundError:  # package import layout
    from ..finding_routes.list_schema import FINDING_ORIGIN_SQL

from .finalizer import _SEVERITY_RANK, _TEMPLATE_EXPOSURE_CLASSES, _exposure_location
from .finding_identity import finding_identity_keys
from .posture_findings import OPT_IN_HEADERS

#: Rows one statement updates, and rows one scan retires in all.
RETIRE_BATCH_SIZE = 500
RETIRE_MAX_ROWS_PER_SCAN = 5_000
#: Verified exposure locations one scan retires against (a report is bounded; this bounds it twice).
_MAX_EXPOSURE_LOCATIONS = 200


@dataclass(frozen=True)
class RetiredFindingKind:
    """One kind of stored finding the scanner no longer reports."""

    name: str
    reason: str
    tool: str
    template_id: str
    #: Lower-case header names (the template's matcher); the stored row names it in
    #: ``evidence.header_name`` (or, on older rows, ``evidence.matcher_name``). Empty for an
    #: ``exposure_proof`` kind.
    header_names: frozenset[str] = frozenset()
    #: Origin schemes the kind is retired on.
    schemes: frozenset[str] = frozenset({"http", "https"})
    #: True when another finding now carries this one: a header is retired only when this scan's
    #: baseline reported that same header missing on the origin. False when the kind is no
    #: longer a finding at all (retired once the baseline observed the origin).
    superseded_by_baseline: bool = False
    #: ``header``: matched by header name on the baseline-observed origin. ``exposure_proof``:
    #: matched by origin and path to an exposure this scan verified, of one of ``exposure_classes``.
    predicate: Literal["header", "exposure_proof"] = "header"
    exposure_classes: frozenset[str] = frozenset()
    #: The release that stopped reporting the kind, shown as "Retired by release <release>".
    release: str = "2.11.0"


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
        name="nuclei_opt_in_header_absent",
        reason="An opt-in header whose absence is the browser default; not a finding (2.11).",
        tool="nuclei",
        template_id=_MISSING_HEADERS_TEMPLATE,
        header_names=OPT_IN_HEADERS,
    ),
    RetiredFindingKind(
        name="nuclei_hsts_on_plain_http",
        reason="Browsers ignore HSTS received over plain HTTP; its absence there is not a finding (2.11).",
        tool="nuclei",
        template_id=_MISSING_HEADERS_TEMPLATE,
        header_names=frozenset({"strict-transport-security"}),
        schemes=frozenset({"http"}),
    ),
    # One per template the finalizer folds into a verified exposure proof, so the two never drift.
    *(
        RetiredFindingKind(
            name=f"nuclei_{template_id.replace('-', '_')}_folded_into_exposure_proof",
            reason="Corroborating evidence on the verified exposure finding for the same file (2.11).",
            tool="nuclei",
            template_id=template_id,
            predicate="exposure_proof",
            exposure_classes=classes,
        )
        for template_id, classes in sorted(_TEMPLATE_EXPOSURE_CLASSES.items())
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


def scan_completed(report: Mapping[str, Any]) -> bool:
    """True only for a scan whose finalized report says every action completed."""
    metadata = report.get("scan_metadata") if isinstance(report.get("scan_metadata"), Mapping) else {}
    return (
        metadata.get("status") == "complete"
        and metadata.get("partial") is not True
        and metadata.get("cancelled") is not True
    )


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


def verified_exposure_locations(report: Mapping[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    """``(location, exposure_class) -> {origins, path, rank}`` for exposures this scan verified."""
    locations: dict[tuple[str, str], dict[str, Any]] = {}
    for finding in report.get("findings") or ():
        if (
            not isinstance(finding, Mapping)
            or finding.get("tool") != "shakerscan_exposure_probe"
            or finding.get("proof_state") != "verified"
        ):
            continue
        evidence = finding.get("evidence") if isinstance(finding.get("evidence"), Mapping) else {}
        exposure_class = str(evidence.get("exposure_class") or "")
        location = _exposure_location(finding.get("url"))
        _scheme, origins = _origin_spellings(finding.get("url"))
        rank = _SEVERITY_RANK.get(str(finding.get("severity") or "").lower())
        if not exposure_class or not location or not origins or rank is None:
            continue
        key = (location, exposure_class)
        if key not in locations and len(locations) >= _MAX_EXPOSURE_LOCATIONS:
            continue
        current = locations.get(key)
        if current is None or rank > current["rank"]:
            path = urllib.parse.urlsplit(str(finding.get("url"))).path.rstrip("/") or "/"
            locations[key] = {"origins": origins, "path": path, "rank": rank}
    return locations


_HEADER_SQL = "lower(COALESCE({t}evidence->>'header_name', {t}evidence->>'matcher_name'))"
_HEADER_PREDICATE = f"{_HEADER_SQL.format(t='')} = ANY($4::text[])"


def _path_sql(column: str) -> str:
    """A stored URL's path, normalised as finalizer._exposure_location does (no query, no trailing /)."""
    return f"COALESCE(NULLIF(rtrim(substring({column} from '^[^:/?#]+://[^/?#]*([^?#]*)'), '/'), ''), '/')"


_EXPOSURE_PREDICATE = f"COALESCE(evidence->>'header_name', '') = '' AND {_path_sql('url')} = ANY($4::text[])"

# The finding that now carries a retired row must itself be stored: last seen by this scan, on the
# same origin, and active or triaged. A report whose findings did not persist retires nothing.
_REPLACEMENT_SQL = """
          AND EXISTS (
              SELECT 1 FROM findings replacement
              WHERE replacement.target_id = $1 AND replacement.tool = '{tool}'
                AND replacement.last_seen_scan_id::text = $8::text
                AND replacement.status IN ('active', 'accepted_risk', 'false_positive')
                AND lower(substring(replacement.url from '^[^:/?#]+://[^/?#]*')) = ANY($5::text[])
                AND {match}
          )"""
_BASELINE_REPLACEMENT = _REPLACEMENT_SQL.format(
    tool="http_baseline",
    match=f"lower(replacement.evidence->>'check') = 'missing_header_' || {_HEADER_SQL.format(t='findings.')}",
)
_EXPOSURE_REPLACEMENT = _REPLACEMENT_SQL.format(
    tool="shakerscan_exposure_probe",
    match=f"replacement.evidence->>'exposure_class' = $11::text AND {_path_sql('replacement.url')} = ANY($4::text[])",
)


def _retire_sql(predicate: str, replacement: str = "") -> str:
    return f"""
    WITH doomed AS (
        SELECT id FROM findings
        WHERE target_id = $1 AND status = 'active'
          AND analyst_verdict IS NULL AND analyst_verdict_at IS NULL
          AND NULLIF(btrim(COALESCE(notes, '')), '') IS NULL
          AND NULLIF(btrim(COALESCE(analyst_verdict_notes, '')), '') IS NULL
          AND COALESCE(last_verification_status, '') NOT IN ('queued', 'running')
          AND NOT (COALESCE(evidence, '{{}}'::jsonb) ? 'retired')
          AND tool = $2 AND evidence->>'template_id' = $3
          AND {predicate}
          AND {FINDING_ORIGIN_SQL} = ANY($5::text[])
          AND NOT (fingerprint = ANY($6::text[]))
          AND last_seen_scan_id::text IS DISTINCT FROM $8::text
          AND ($9::text[] IS NULL OR lower(COALESCE(severity, '')) = ANY($9::text[]))
          AND NOT EXISTS (
              SELECT 1 FROM finding_exceptions exception
              WHERE (exception.finding_id = findings.id::text OR exception.fingerprint = findings.fingerprint)
                AND exception.status IN ('active', 'approved', 'accepted_risk')
          ){replacement}
        ORDER BY id
        LIMIT $10
        FOR UPDATE SKIP LOCKED
    )
    UPDATE findings
    SET status = 'resolved', resolved_at = NOW(), updated_at = NOW(),
        evidence = COALESCE(evidence, '{{}}'::jsonb) || jsonb_build_object('retired', $7::jsonb)
    FROM doomed
    WHERE findings.id = doomed.id
    RETURNING findings.id
"""


#: A kind that is no longer a finding at all (opt-in header, HSTS over plain HTTP).
RETIRE_SQL = _retire_sql(_HEADER_PREDICATE)
#: A header duplicate the baseline finding carries: that stored baseline row must exist.
RETIRE_BASELINE_SQL = _retire_sql(_HEADER_PREDICATE, _BASELINE_REPLACEMENT)
#: A template candidate a verified exposure proof carries: that stored proof row must exist ($11 = class).
RETIRE_EXPOSURE_SQL = _retire_sql(_EXPOSURE_PREDICATE, _EXPOSURE_REPLACEMENT)


@dataclass(frozen=True)
class _Retirement:
    """One statement's worth of rows: a kind, what it matches, and what superseded it."""

    kind: RetiredFindingKind
    sql: str
    values: list[str]
    origins: list[str]
    severities: list[str] | None
    superseded_by: dict[str, Any]
    extra: tuple[Any, ...] = ()

    def covers(self, finding: Mapping[str, Any]) -> bool:
        """True when ``finding`` (a report finding) is a row this statement would retire."""
        evidence = finding.get("evidence") if isinstance(finding.get("evidence"), Mapping) else {}
        if (
            finding.get("tool") != self.kind.tool
            or evidence.get("template_id") != self.kind.template_id
            or not set(_origin_spellings(finding.get("url"))[1]) & set(self.origins)
        ):
            return False
        if self.kind.predicate == "header":
            header = str(evidence.get("header_name") or evidence.get("matcher_name") or "").lower()
            return header in self.values
        try:
            path = urllib.parse.urlsplit(str(finding.get("url") or "")).path.rstrip("/") or "/"
        except ValueError:
            return False
        return (
            not evidence.get("header_name") and path in self.values
            and str(finding.get("severity") or "").lower() in (self.severities or ())
        )


def _retirements(report: Mapping[str, Any], kinds: Iterable[RetiredFindingKind]) -> list[_Retirement]:
    """What this report proves superseded, kind by kind (no completion check)."""
    statements: list[_Retirement] = []
    covered = baseline_covered_origin(report)
    scheme, baseline_origins = _origin_spellings(covered) if covered else ("", [])
    superseding = baseline_missing_headers(report, baseline_origins) if covered else frozenset()
    exposures = verified_exposure_locations(report)
    for kind in kinds:
        if kind.predicate == "header":
            if not covered or scheme not in kind.schemes:
                continue
            headers = kind.header_names & superseding if kind.superseded_by_baseline else kind.header_names
            if headers:
                sql = RETIRE_BASELINE_SQL if kind.superseded_by_baseline else RETIRE_SQL
                statements.append(_Retirement(kind, sql, sorted(headers), baseline_origins, None,
                                              {"origin": covered}))
        elif kind.predicate == "exposure_proof":
            for (location, exposure_class), proof in sorted(exposures.items()):
                if exposure_class not in kind.exposure_classes:
                    continue
                severities = sorted(name for name, rank in _SEVERITY_RANK.items() if rank <= proof["rank"])
                statements.append(_Retirement(
                    kind, RETIRE_EXPOSURE_SQL, [proof["path"]], proof["origins"], severities,
                    {"exposure_class": exposure_class, "location": location}, (exposure_class,),
                ))
    return statements


def without_superseded_duplicates(
    report: Any, findings: Iterable[Any] | None, *, kinds: Iterable[RetiredFindingKind] = RETIRED_FINDING_KINDS,
) -> list[Any]:
    """``findings`` without a retired kind whose superseding finding is in the same report.

    A current finalizer never reports one (it folds them); an older fleet node's finalizer does.
    Saving them would reopen the very rows a current scan retired.
    """
    findings = list(findings or ())
    if not isinstance(report, Mapping) or not findings:
        return findings
    statements = _retirements(report, kinds)
    if not statements:
        return findings
    return [
        finding for finding in findings
        if not (isinstance(finding, Mapping) and any(statement.covers(finding) for statement in statements))
    ]


async def retire_superseded_findings(
    conn: Any,
    *,
    target_id: Any,
    scan_id: Any,
    report: Mapping[str, Any],
    seen_fingerprints: Iterable[str],
    kinds: Iterable[RetiredFindingKind] = RETIRED_FINDING_KINDS,
    batch_size: int = RETIRE_BATCH_SIZE,
    max_rows: int = RETIRE_MAX_ROWS_PER_SCAN,
) -> int:
    """Resolve this target's active, untriaged rows of retired kinds that this scan proved covered."""
    if not scan_completed(report):
        return 0
    seen = sorted({str(value) for value in seen_fingerprints if value})
    scan = str(scan_id)
    retired = 0
    for statement in _retirements(report, kinds):
        kind = statement.kind
        record = json.dumps({
            "kind": kind.name, "reason": kind.reason, "release": kind.release, "scan_id": scan,
            "superseded_by": statement.superseded_by,
        })
        while retired < max_rows:
            limit = min(batch_size, max_rows - retired)
            rows = await conn.fetch(
                statement.sql, target_id, kind.tool, kind.template_id, statement.values, statement.origins,
                seen, record, scan, statement.severities, limit, *statement.extra,
            )
            retired += len(rows)
            if len(rows) < limit:
                break
    return retired


async def retire_after_scan(
    pool: Any,
    *,
    scan_id: str,
    target_id: str,
    report: Any,
    findings: Iterable[Any] | None,
    refresh_active_count: Callable[[Any, uuid.UUID], Awaitable[Any]],
    saved_count: int | None,
    coverage_status: str | None,
    log_prefix: str = "",
) -> int:
    """The worker's post-save step: retire superseded rows of one target, never raising.

    Runs after the scan's findings are saved, so a row this scan reports again is matched there
    and never retired here. ``findings`` is what the worker saved (``without_superseded_duplicates``
    of the report's); ``saved_count`` is what ``save_findings`` returned, ``None`` when it raised.
    Nothing is retired unless every one of them saved, or unless ``coverage_status`` -- the
    worker's final coverage after the action-receipt rollup, which can downgrade a report that
    still says ``complete`` -- is ``complete``. One transaction; the target's active count is
    refreshed after it.
    """
    if not isinstance(report, Mapping):
        return 0
    findings = [finding for finding in findings or () if isinstance(finding, Mapping)]
    if saved_count is None or saved_count != len(findings):
        print(f"{log_prefix}retire_superseded_findings skipped: findings were not all saved", flush=True)
        return 0
    if str(coverage_status or "").strip().lower() not in {"complete", "completed"}:
        return 0
    try:
        seen = {key for finding in findings for key in finding_identity_keys(finding)}
        target_uuid = uuid.UUID(str(target_id))
        async with pool.acquire() as conn:
            async with conn.transaction():
                retired = await retire_superseded_findings(
                    conn, target_id=target_uuid, scan_id=scan_id, report=report, seen_fingerprints=seen,
                )
            if retired:
                await refresh_active_count(conn, target_uuid)
    except Exception as exc:  # retirement is best-effort; the scan's own results stand
        print(f"{log_prefix}retire_superseded_findings error: {type(exc).__name__}", flush=True)
        return 0
    if retired:
        print(f"{log_prefix}Resolved {retired} finding(s) of retired kinds", flush=True)
    return retired


__all__ = [
    "RETIRED_FINDING_KINDS", "RETIRE_BASELINE_SQL", "RETIRE_BATCH_SIZE", "RETIRE_EXPOSURE_SQL",
    "RETIRE_MAX_ROWS_PER_SCAN", "RETIRE_SQL", "RetiredFindingKind", "baseline_covered_origin",
    "baseline_missing_headers", "retire_after_scan", "retire_superseded_findings", "scan_completed",
    "verified_exposure_locations", "without_superseded_duplicates",
]
