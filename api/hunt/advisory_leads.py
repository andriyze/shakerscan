"""Leads from advisories that match a target's observed services.

Service intelligence already matches advisories (known-exploited first) to the services a target
exposes and says which bundled check exists for each. Those matches were visible to a planner
that asked (query ``kind=service_intelligence``, ``view=candidates``). This puts the ones worth
acting on onto the shared lead board when a Hunt starts, so they are ranked with the rest of its
frontier.

A match is a candidate, never a finding: a version banner can be wrong, backported or stale. The
lead says which check to run; only that check's deterministic result verifies anything. Nothing
here runs traffic or grants authority.
"""
from __future__ import annotations

import re
from typing import Any, Mapping, Sequence
import uuid

from .followup_leads import record_leads

SOURCE = "advisory_intel"
FAMILY = "known_vulnerability"
#: Leads recorded per pass. Candidates arrive known-exploited first, then by EPSS and CVSS.
MAX_LEADS = 25
MAX_CANDIDATES = 500
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}")
CHECK_PATTERN = re.compile(r"[a-z0-9][a-z0-9._-]{0,119}")
LISTENER_PATTERN = re.compile(r"(tcp|udp)/\d{1,5}")
SEVERITIES = ("critical", "high", "medium", "low", "info")
#: A verify Scan already answered (or is answering) these.
SETTLED = frozenset({"check_matched", "check_not_matched", "pending"})


def advisory_proposals(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """The candidate rows worth a lead, as lead-board fields. Pure.

    Worth a lead: known exploited, or critical/high with a bundled check. Left out: a stale
    service identity, and a candidate a verify Scan already settled or is running. Only
    server-derived values reach the lead's text; banner labels stay in service intelligence.
    """
    proposals: list[dict[str, Any]] = []
    for row in rows:
        cve = str(row.get("cve") or "").upper()
        listener = str(row.get("listener") or "")
        try:
            service = str(uuid.UUID(str(row.get("service_id"))))
        except (ValueError, TypeError):
            continue
        if not CVE_PATTERN.fullmatch(cve) or not LISTENER_PATTERN.fullmatch(listener):
            continue
        if row.get("identity_stale") or row.get("verification") in SETTLED:
            continue
        severity = row.get("severity") if row.get("severity") in SEVERITIES else None
        checks = [check for check in row.get("checks") or () if isinstance(check, str) and CHECK_PATTERN.fullmatch(check)]
        exploited = bool(row.get("known_exploited"))
        if not exploited and not (checks and severity in {"critical", "high"}):
            continue
        how = (f"A bundled check exists ({', '.join(checks)}): run it against this listener."
               if checks else "No bundled check names this advisory: confirm the version another way first.")
        proposals.append({
            "family": FAMILY, "cwe": None,
            "title": f"{cve} advisory matches the service on {listener}",
            "description": (("Known to be exploited. " if exploited else "")
                            + "The observed product and version fall in this advisory's affected range. "
                            + "A banner match is a candidate, not a finding. " + how),
            "severity_guess": severity or "high", "confidence": 0.5 if exploited else 0.4,
            "dimensions": {"object_key": f"service:{service}", "proof_surface": cve.lower()},
            "endorsement": {"cve": cve, "service_id": service, "known_exploited": exploited, "checks": checks},
            "metadata": {"advisory": {"cve": cve, "service_id": service, "listener": listener,
                                      "known_exploited": exploited, "checks": checks,
                                      "match_type": row.get("match_type") if isinstance(row.get("match_type"), str) else None}},
        })
        if len(proposals) >= MAX_LEADS:
            break
    return proposals


async def _candidates(conn: Any, target: uuid.UUID, device: bool) -> list[Mapping[str, Any]]:
    try:
        from exposure.service_knowledge import query_service_knowledge
    except ModuleNotFoundError:  # package import layout
        from ..exposure.service_knowledge import query_service_knowledge
    page = await query_service_knowledge(
        conn, target_id=target, device=device, filters={"view": "candidates"}, limit=MAX_CANDIDATES)
    return list(page.get("rows") or [])


async def produce(conn: Any, target_id: Any, *, device: bool) -> dict[str, int]:
    """Record the advisory leads this target's services open and have not opened yet. Idempotent."""
    target = target_id if isinstance(target_id, uuid.UUID) else uuid.UUID(str(target_id))
    rows = await _candidates(conn, target, device)
    proposals = advisory_proposals(rows)
    if not proposals:
        return {"considered": len(rows), "created": 0, "endorsed": 0}
    async with conn.transaction():
        counts = await record_leads(conn, target, source=SOURCE, proposals=proposals, mark=("cve", "service_id"))
    return {"considered": len(rows), **counts}


__all__ = ["FAMILY", "MAX_LEADS", "SOURCE", "advisory_proposals", "produce"]
