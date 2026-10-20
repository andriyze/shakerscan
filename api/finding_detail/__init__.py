"""Per-class finding detail ("the brief"): what is wrong, where, the proof, why it matters, how sure
we are, how to reproduce, a fix for the observed stack, how to verify, and why this severity.

The brief is computed on read from the stored finding only (no network, no scanner call), so the
page stays fast and historical findings gain it without a migration. Classes without a specific
renderer get the generic brief: the stored description and visible scalar evidence.
"""

from __future__ import annotations

from typing import Any, Mapping

from . import exposure, http, injection, other, posture, tls
from .common import DETAIL_SCHEMA, record, text
from .severity import severity_section

_CONFIRMED_NOTES = {
    "tls": "Read directly from the TLS handshake with this server; nothing is inferred.",
    "header": "Read from the scan's recorded response of this origin.",
    "cookie": "Read from the Set-Cookie header of the scan's recorded response.",
    "exposure": "The response matched a content signature for this class; the scanner did not rely on the status code alone.",
    "cors": "Read from the CORS headers of the scan's recorded response to the probe Origin.",
    "redirect": "Read from the Location header of the scan's recorded response; the redirect was not followed.",
    "dns": "Read from the DNS answers the scan recorded.",
}


def _builder(finding: Mapping[str, Any], evidence: Mapping[str, Any]):
    tool = text(finding.get("tool"), 80)
    check = text(evidence.get("check"), 120)
    if finding.get("source") == "ai_gate" or finding.get("ai_target_id"):
        return other.build_ai
    if tool == "tls.inspect":
        return tls.build
    if check.startswith("missing_header_") or (evidence.get("template_id") == "http-missing-security-headers" and evidence.get("header_name")):
        return http.build_missing_header
    if check.startswith("session_cookie_missing_"):
        return http.build_cookie
    if check.startswith("weak_header_"):
        return http.build_weak_header
    if check.startswith("cors_"):
        return posture.build_cors
    if check == "open_redirect":
        return posture.build_open_redirect
    if tool == "dns.inspect" and check:
        return posture.build_dns
    if tool == "shakerscan_exposure_probe" and evidence.get("exposure_class") == "graphql_introspection_enabled":
        return other.build_graphql_introspection
    if tool == "shakerscan_exposure_probe" and evidence.get("exposure_class"):
        return exposure.build
    if tool in {"shakerscan_sqli_proof", "sqlmap", "request_sqli_differential"}:
        return injection.build_sqli
    if tool == "shakerscan_nosqli_verify":
        return injection.build_nosqli
    if tool in {"dalfox", "shakerscan_browser_proof", "request_xss_differential"} or (
        str(finding.get("cwe") or "") == "CWE-79" and evidence.get("payload_sha256")
    ):
        return injection.build_xss
    if tool in {"smart_authz", "shakerscan_authz_surface"}:
        return injection.build_authz
    if tool == "shakerscan_graphql_probe":
        return other.build_graphql
    if tool == "subdomain_takeover":
        return other.build_takeover
    if tool == "nuclei" or evidence.get("template_id"):
        return other.build_template
    return other.build_generic


def _confidence(finding: Mapping[str, Any], evidence: Mapping[str, Any], family: str) -> dict[str, str]:
    state = text(finding.get("proof_state"), 40).lower()
    reason = text(finding.get("verification_reason"), 400)
    if finding.get("source") == "ai_gate" or finding.get("ai_target_id"):
        judge = text(evidence.get("judge_layer"), 60).replace("_", " ")
        return {"level": "likely" if state == "verified" else "tentative",
                "reason": f"Judged from the model's response{f' by the {judge}' if judge else ''}; model behaviour varies between runs, so retest before concluding."}
    if state == "verified" or finding.get("verified") is True:
        note = _CONFIRMED_NOTES.get(family, "")
        return {"level": "confirmed", "reason": " ".join(part for part in (reason + "." if reason and not reason.endswith(".") else reason, note) if part)}
    if state in {"likely_vulnerable", "suspected"} or finding.get("suspected") is True and state != "candidate":
        return {"level": "likely", "reason": reason or "A strong signal was observed, but the deterministic proof has not run or did not complete."}
    return {"level": "tentative", "reason": reason or "A pattern matched; nothing has confirmed the issue yet. Retest to prove or refute it."}


def build_finding_detail(finding: Mapping[str, Any]) -> dict[str, Any]:
    """The brief for one stored finding (already redacted by the read path)."""
    evidence = record(finding.get("evidence"))
    try:
        brief = _builder(finding, evidence)(finding, evidence) or other.build_generic(finding, evidence)
    except Exception:  # a malformed historical row falls back to the generic brief
        brief = other.build_generic(finding, evidence)
    if not brief.get("class"):
        brief = other.build_generic(finding, evidence)
    family = str(brief["class"]).split(".", 1)[0]
    brief = {key: value for key, value in brief.items() if value not in (None, "", [], {})}
    brief["schema"] = DETAIL_SCHEMA
    brief["confidence"] = _confidence(finding, evidence, family)
    brief["severity"] = severity_section(finding, evidence, )
    if "secret_refs" not in brief:
        refs = exposure.secret_refs(evidence)
        if refs:
            brief["secret_refs"] = refs
    return brief


# Related findings: the same certificate, origin or class on the same target.
#
# Each relation is its own bounded subquery filtered by its key (the certificate fingerprint, the
# URL's origin), so the page never sorts or scans a target's whole history: a target with 500k
# active findings still reads at most a few dozen rows. Both keys are indexed by the background
# builder (finding_routes/list_schema.py, idx_findings_active_target_origin and
# idx_findings_active_target_certificate); without those indexes the query is still correct.
try:
    from finding_routes.list_schema import FINDING_CERTIFICATE_SQL as CERTIFICATE_SQL, FINDING_ORIGIN_SQL as ORIGIN_SQL
except ModuleNotFoundError:  # package import layout
    from ..finding_routes.list_schema import FINDING_CERTIFICATE_SQL as CERTIFICATE_SQL, FINDING_ORIGIN_SQL as ORIGIN_SQL
_RELATED_COLUMNS = f"""id, title, severity, url, tool, status, last_seen_at,
           evidence->>'check' AS check_id,
           evidence->>'template_id' AS template_id,
           evidence->>'exposure_class' AS exposure_class,
           {CERTIFICATE_SQL} AS certificate_sha256"""
# What makes two findings of one tool the same check (``_check_key`` reads it the same way).
_CHECK_KEY_SQL = "COALESCE(NULLIF(evidence->>'check', ''), NULLIF(evidence->>'template_id', ''), title)"
_RELATED_BASE = "target_id = $1 AND id <> $2 AND status = 'active'"
_RELATED_PER_RELATION = 20
RELATED_SQL = f"""
    (SELECT {_RELATED_COLUMNS} FROM findings
     WHERE {_RELATED_BASE} AND $3::text IS NOT NULL AND {CERTIFICATE_SQL} = $3::text
     LIMIT {_RELATED_PER_RELATION})
    UNION ALL
    (SELECT {_RELATED_COLUMNS} FROM findings
     WHERE {_RELATED_BASE} AND $6::boolean AND {ORIGIN_SQL} = ANY($4::text[])
       AND evidence->>'exposure_class' IS NOT NULL
     LIMIT {_RELATED_PER_RELATION})
    UNION ALL
    (SELECT {_RELATED_COLUMNS} FROM findings
     WHERE {_RELATED_BASE} AND $5::text IS NOT NULL AND {ORIGIN_SQL} = ANY($4::text[]) AND tool = $5::text
       AND {_CHECK_KEY_SQL} = $7::text
     LIMIT {_RELATED_PER_RELATION})
    UNION ALL
    (SELECT {_RELATED_COLUMNS} FROM findings
     WHERE {_RELATED_BASE} AND {ORIGIN_SQL} = ANY($4::text[]) AND severity IN ('critical', 'high')
     LIMIT {_RELATED_PER_RELATION})
    UNION ALL
    (SELECT {_RELATED_COLUMNS} FROM findings
     WHERE {_RELATED_BASE} AND {ORIGIN_SQL} = ANY($4::text[]) AND severity = 'medium'
     LIMIT {_RELATED_PER_RELATION})
"""


def _check_key(check: Any, template_id: Any, title: Any) -> str:
    """The check a finding reports: the recorded check, else the template that matched, else
    the title. One tool runs many checks (every response-header rule is ``http_baseline``)."""
    for value in (check, template_id, title):
        if isinstance(value, str) and value:
            return value
    return ""


def _finding_origin(finding: Mapping[str, Any]) -> str:
    from .common import origin_of
    return origin_of(finding.get("url") or record(finding.get("evidence")).get("origin"))


def related_sql_args(finding: Mapping[str, Any]) -> tuple[Any, ...]:
    """The parameters of ``RELATED_SQL`` for ``finding`` (a stored row with ``target_id``)."""
    evidence = record(finding.get("evidence"))
    cert = text(evidence.get("certificate_sha256") or record(evidence.get("certificate")).get("sha256"), 64) or None
    origin = _finding_origin(finding)
    # A stored URL may spell the default port the shown origin omits.
    origins = []
    if origin:
        origins.append(origin.lower())
        scheme, _, authority = origin.partition("://")
        if ":" not in authority.rsplit("]", 1)[-1]:
            origins.append(f"{origin.lower()}:{443 if scheme == 'https' else 80}")
    return (
        finding["target_id"], finding["id"], cert, origins,
        text(finding.get("tool"), 80) or None, bool(text(evidence.get("exposure_class"), 80)),
        _check_key(evidence.get("check"), evidence.get("template_id"), finding.get("title")) or None,
    )


_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def related_findings(finding: Mapping[str, Any], rows: list[Mapping[str, Any]], limit: int = 8) -> list[dict[str, Any]]:
    """Rank ``rows`` (from ``RELATED_SQL``) by how they relate to ``finding``; bounded and value-free."""
    from .common import origin_of
    evidence = record(finding.get("evidence"))
    cert = text(evidence.get("certificate_sha256") or record(evidence.get("certificate")).get("sha256"), 64)
    origin = _finding_origin(finding)
    tool = text(finding.get("tool"), 80)
    check = _check_key(evidence.get("check"), evidence.get("template_id"), finding.get("title"))
    exposure_class = text(evidence.get("exposure_class"), 80)
    ranked: list[tuple[int, int, dict[str, Any]]] = []
    seen: set[str] = set()
    for row in rows:
        if str(row.get("id")) in seen:  # one row can answer several relation subqueries
            continue
        seen.add(str(row.get("id")))
        reason = ""
        priority = 9
        if cert and row.get("certificate_sha256") == cert:
            reason, priority = "Same certificate", 0
        elif exposure_class and row.get("exposure_class") and origin_of(row.get("url")) == origin:
            reason, priority = "Other exposed content on this origin", 1
        elif (tool and row.get("tool") == tool and check
              and _check_key(row.get("check_id"), row.get("template_id"), row.get("title")) == check
              and origin and origin_of(row.get("url")) == origin):
            reason, priority = "Same check on this origin", 2
        elif origin and origin_of(row.get("url")) == origin and _SEVERITY_RANK.get(str(row.get("severity")), 5) <= 2:
            reason, priority = "Other significant finding on this origin", 3
        if not reason:
            continue
        ranked.append((priority, _SEVERITY_RANK.get(str(row.get("severity")), 5), {
            "id": str(row.get("id")), "title": text(row.get("title"), 200), "severity": text(row.get("severity"), 20),
            "url": text(row.get("url"), 400), "relation": reason,
        }))
    ranked.sort(key=lambda item: (item[0], item[1]))
    return [item[2] for item in ranked[:limit]]


__all__ = ["RELATED_SQL", "build_finding_detail", "related_findings", "related_sql_args"]
