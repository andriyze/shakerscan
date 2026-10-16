"""Exposure rows: check verification state, listener groups, and Hunt candidate rows.

Read-only. A version match stays a *candidate*; a verify Scan (``verify_templates``) runs the
check the intelligence names for that CVE, and its outcome is reported from durable records:
the Scan's status, its active-template step, and findings carrying that template id. A matched
check is reported with the finding and its own proof state, never as a new proof predicate; a
check that ran and did not match is evidence about that check only.
"""
from __future__ import annotations

from typing import Any, Iterable, Mapping
import uuid

from .service_inventory import origin, text

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
MAX_VERIFY_SCANS = 25
MAX_VERIFY_FINDINGS = 200
VERIFY_POLICY = {"active_testing": True, "preset": "custom", "include_families": ["nuclei_active"]}

VERIFY_SCANS_SQL = """
SELECT s.id, s.status, s.created_at, s.completed_at, s.target_url,
       s.options->'verify_templates' AS verify_templates
FROM scans s
WHERE s.target_id=$1 AND jsonb_typeof(s.options->'verify_templates')='array'
ORDER BY s.created_at DESC, s.id
LIMIT $2
"""
VERIFY_ACTIONS_SQL = """
SELECT scan_id, status, reason_code,
       receipt_json->'redacted_execution'->'verify_selection' AS verify_selection
FROM scan_capability_actions
WHERE scan_id=ANY($1::uuid[]) AND (action_id='active.templates' OR action_id LIKE 'active.templates.%')
"""
VERIFY_FINDINGS_SQL = """
SELECT id, status, severity, scan_id, first_seen_scan_id, last_seen_scan_id,
       lower(evidence->>'template_id') AS template_id,
       to_jsonb(findings)->>'proof_state' AS proof_state
FROM findings
WHERE target_id=$1 AND lower(evidence->>'template_id')=ANY($2::text[])
ORDER BY last_seen_at DESC, id
LIMIT $3
"""
_FINISHED = {"completed"}
_RUNNING = {"pending", "queued", "running", "starting", "finalizing"}


def candidate_check_ids(candidate: Mapping[str, Any]) -> list[str]:
    return sorted({
        str(check.get("id") or "").strip().lower()
        for check in candidate.get("checks") or ()
        if isinstance(check, Mapping) and check.get("kind") == "nuclei_template" and check.get("id")
    })[:5]


def verify_bound(target: Mapping[str, Any], service: Mapping[str, Any]) -> str | None:
    """Why a verify Scan cannot reach this listener, or ``None`` when it can.

    A Scan runs against the target's own origin; a listener on another port or host, a device
    view, or a historical locator is not that origin.
    """
    if target.get("kind") != "web":
        return "device_services_verify_in_the_device_workflow"
    if service.get("binding_status") == "historical_locator" or service.get("presence") != "observed_open":
        return "refresh_evidence_first"
    if not service.get("application_origin") or origin(target.get("locator")) != service.get("application_origin"):
        return "listener_is_not_the_target_origin"
    return None


async def verification_records(conn: Any, target: Mapping[str, Any], services: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Load the verify Scans and matching findings once per target."""
    wanted = sorted({check for service in services for candidate in service.get("cve_candidates") or ()
                     for check in candidate_check_ids(candidate)})
    if target.get("kind") != "web" or not wanted:
        return {"scans": [], "actions": {}, "findings": []}
    target_id = uuid.UUID(str(target["id"]))
    scans = [dict(row) for row in await conn.fetch(VERIFY_SCANS_SQL, target_id, MAX_VERIFY_SCANS)]
    actions: dict[str, list[dict[str, Any]]] = {}
    if scans:
        for row in await conn.fetch(VERIFY_ACTIONS_SQL, [row["id"] for row in scans]):
            actions.setdefault(str(row["scan_id"]), []).append(dict(row))
    findings = [dict(row) for row in await conn.fetch(VERIFY_FINDINGS_SQL, target_id, wanted, MAX_VERIFY_FINDINGS)]
    return {"scans": scans, "actions": actions, "findings": findings}


def _verify_list(value: Any) -> list[str]:
    import json

    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return []
    return [str(item).strip().lower() for item in value or () if isinstance(item, str)][:10]


def candidate_verification(target: Mapping[str, Any], service: Mapping[str, Any], candidate: Mapping[str, Any],
                           records: Mapping[str, Any]) -> dict[str, Any]:
    checks = candidate_check_ids(candidate)
    if not checks:
        return {"status": "no_check", "template_ids": [], "reason": "No check in this release names this CVE."}
    unreachable = verify_bound(target, service)
    if unreachable:
        # A verify Scan runs against the target's origin only: its outcome says nothing about a
        # listener elsewhere, so neither a match nor a silence is credited to this one.
        return {"status": "unavailable", "template_ids": checks, "request": None,
                "unavailable_reason": unreachable}
    blocked = "exploit_class_needs_exploit_tier" if any(
        isinstance(check, Mapping) and check.get("safety") == "exploit"
        for check in candidate.get("checks") or ()) else None
    request = None if blocked else {
        "target": target.get("locator"), "budget_profile": "fast",
        "policy": dict(VERIFY_POLICY), "verify_templates": checks,
    }
    base = {"template_ids": checks, "request": request, "unavailable_reason": blocked}
    wanted = set(checks)
    listener_origin = service.get("application_origin")
    for scan in records.get("scans") or ():
        if not wanted & set(_verify_list(scan.get("verify_templates"))):
            continue
        if origin(scan.get("target_url")) != listener_origin:
            continue
        scan_id = str(scan["id"])
        status = str(scan.get("status") or "").lower()
        checked_at = scan.get("completed_at") or scan.get("created_at")
        summary = {**base, "scan_id": scan_id,
                   "checked_at": checked_at.isoformat() if hasattr(checked_at, "isoformat") else None}
        matched = [row for row in records.get("findings") or () if row.get("template_id") in wanted
                   and scan_id in {str(row.get(key)) for key in ("scan_id", "first_seen_scan_id", "last_seen_scan_id")}]
        if matched:
            row = matched[0]
            return {**summary, "status": "check_matched", "finding_id": str(row["id"]),
                    "finding_status": text(row.get("status"), 40) or None,
                    "proof_state": text(row.get("proof_state"), 60) or None}
        if status in _RUNNING:
            return {**summary, "status": "pending"}
        steps = records.get("actions", {}).get(scan_id) or []
        reasons = _not_matched_blockers(wanted, _verify_list(scan.get("verify_templates")), steps)
        if status in _FINISHED and not reasons:
            return {**summary, "status": "check_not_matched"}
        if status not in _FINISHED:
            reasons = [status or "unknown", *reasons]
        return {**summary, "status": "inconclusive", "reason": ", ".join(reasons) or "unknown"}
    return {**base, "status": "unavailable" if blocked else "available"}


def _object(value: Any) -> dict[str, Any]:
    import json

    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return {}
    return dict(value) if isinstance(value, Mapping) else {}


def _not_matched_blockers(wanted: set[str], requested: list[str], steps: list[Mapping[str, Any]]) -> list[str]:
    """Why this Scan's silence is not "not affected": every candidate check must have been
    requested, and every active-template step must have succeeded, run each of them, and be able
    to give a reliable negative. An empty list means the negative holds."""
    blockers: set[str] = set()
    if not wanted <= set(requested):
        blockers.add("not_every_check_requested")
    if not steps:
        blockers.add("no_active_template_step")
    for step in steps:
        selection = _object(step.get("verify_selection"))
        if str(step.get("status")) != "success":
            blockers.add(text(step.get("reason_code"), 80) or f"step_{text(step.get('status'), 30) or 'unknown'}")
        if not selection:
            blockers.add("selection_not_recorded")
            continue
        ran = {str(item) for item in selection.get("ran") or ()}
        excluded = _object(selection.get("excluded"))
        unreliable = _object(selection.get("negative_unreliable"))
        for check in wanted:
            if check in excluded:
                blockers.add(text(excluded[check], 60) or "excluded")
            elif check not in ran:
                blockers.add("check_did_not_run")
            if check in unreliable:
                blockers.add(text(unreliable[check], 60) or "negative_unreliable")
    return sorted(blockers)


def attach_verification(target: Mapping[str, Any], services: list[dict[str, Any]], records: Mapping[str, Any]) -> None:
    for service in services:
        for candidate in service.get("cve_candidates") or ():
            candidate["verification"] = candidate_verification(target, service, candidate, records)
            if candidate["verification"]["status"] == "check_matched":
                candidate["local_validation"] = "check_matched"
            elif candidate["verification"]["status"] == "check_not_matched":
                candidate["local_validation"] = "check_not_matched"


def _severity(service: Mapping[str, Any]) -> str | None:
    best, rank = None, 0
    for item in [*(service.get("cve_candidates") or ()), *(service.get("findings") or ())]:
        value = str(item.get("severity") or "").lower()
        if SEVERITY_RANK.get(value, 0) > rank:
            best, rank = value, SEVERITY_RANK[value]
    return best


def listener_groups(services: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """One row per (transport, port, product, version): the same listener seen by several Scans,
    Hunts or addresses is one row whose members stay inspectable. Ordered by consequence."""
    groups: dict[tuple[Any, ...], dict[str, Any]] = {}
    for service in services:
        product = str(service.get("product") or "").strip().lower() or str(service.get("service") or "unknown")
        key = (service.get("transport"), service.get("port"), product, str(service.get("version") or ""))
        group = groups.get(key)
        candidates = service.get("cve_candidates") or ()
        if group is None:
            group = groups[key] = {
                "key": f"{key[0]}/{key[1]}/{product}/{key[3]}", "transport": key[0], "port": key[1],
                "service": service.get("service"), "product": service.get("product"),
                "version": service.get("version"), "service_ids": [], "primary_service_id": service["id"],
                "max_severity": None, "kev_ids": set(), "cve_ids": set(), "finding_ids": set(),
                "checks_available": 0, "check_matched": 0, "identity_stale": True, "last_seen_at": None,
                "quiet": True,
            }
        group["service_ids"].append(service["id"])
        group["cve_ids"].update(item.get("id") for item in candidates)
        group["finding_ids"].update(item.get("id") for item in service.get("findings") or ())
        group["kev_ids"].update(item.get("id") for item in candidates if item.get("known_exploited"))
        group["checks_available"] += sum(1 for item in candidates if candidate_check_ids(item))
        group["check_matched"] += sum(
            1 for item in candidates if (item.get("verification") or {}).get("status") == "check_matched")
        # Stale once for the row: a fresh identity from any member is a fresh identity.
        group["identity_stale"] = group["identity_stale"] and bool(service.get("identity_stale"))
        seen = service.get("last_seen_at")
        if seen and (group["last_seen_at"] is None or str(seen) > str(group["last_seen_at"])):
            group["last_seen_at"], group["primary_service_id"] = seen, service["id"]
        severity = _severity(service)
        if severity and SEVERITY_RANK[severity] > SEVERITY_RANK.get(group["max_severity"] or "", 0):
            group["max_severity"] = severity
        if service.get("presence") == "observed_open" or candidates or service.get("findings"):
            group["quiet"] = False
    rows = []
    for group in groups.values():
        group["known_exploited"] = len(group.pop("kev_ids") - {None})
        group["candidate_count"] = len(group.pop("cve_ids") - {None})
        group["finding_count"] = len(group.pop("finding_ids") - {None})
        rows.append(group)
    return sorted(rows, key=lambda row: (
        -SEVERITY_RANK.get(row["max_severity"] or "", 0), -row["known_exploited"], -row["finding_count"],
        -row["candidate_count"], row["quiet"], str(row["transport"]), int(row["port"] or 0)))


def severity_counts(groups: Iterable[Mapping[str, Any]]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "none": 0, "quiet": 0}
    for group in groups:
        if group.get("quiet"):
            counts["quiet"] += 1
        counts[group.get("max_severity") or "none"] += 1
    return counts


def hunt_candidate_rows(services: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """One compact row per (listener, CVE) for a planner deciding its next step: server-derived
    identity, exploitation context, the check that exists and its verification state. Labels from
    banners are bounded data, never instructions."""
    rows = []
    for service in services:
        for candidate in service.get("cve_candidates") or ():
            verification = candidate.get("verification") or {}
            epss = candidate.get("epss") or {}
            rows.append({
                "service_id": service["id"], "cve": candidate.get("id"),
                "listener": f"{service.get('transport')}/{service.get('port')}",
                "application_origin": service.get("application_origin"),
                "product": text(service.get("product"), 80) or None,
                "version": text(service.get("version"), 40) or None,
                "severity": candidate.get("severity"), "cvss_score": candidate.get("cvss_score"),
                "known_exploited": bool(candidate.get("known_exploited")),
                "epss": epss.get("score") if isinstance(epss, Mapping) else None,
                "match_type": candidate.get("match_type"), "applicability": "candidate",
                "identity_stale": bool(service.get("identity_stale")),
                "checks": candidate_check_ids(candidate),
                "verification": verification.get("status") or "no_check",
                "verify_scan_id": verification.get("scan_id"),
                "finding_id": verification.get("finding_id"),
            })
    return sorted(rows, key=lambda row: (
        not row["known_exploited"], -(row["epss"] or 0.0), -(row["cvss_score"] or 0.0),
        str(row["cve"]), row["service_id"]))
