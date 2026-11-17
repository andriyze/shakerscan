"""Leads that follow from a proven result.

A deterministically verified finding often opens a next step: a verified SSRF makes internal
services worth testing, a verified read BOLA makes the write methods of the same object worth
testing. This module turns verified findings of a target into leads on the shared lead board
(``hypotheses``), so every Hunt on the target sees them ranked with the rest of its frontier.

It produces leads only. A lead grants no authority, runs nothing and proves nothing: the Hunt that
takes it still passes scope, policy, approval and budget for every action, and only a
deterministic proof contract verifies a finding.

The table is keyed by vulnerability class, never by application, and stays small on purpose.
Strategy beyond it belongs to the planner, which records its own follow-ups with
``hypothesis.propose`` and ``derived_from``.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import sys
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit
import uuid

RULES_VERSION = "followup-leads/v1"
SOURCE = "proof_followup"
#: Verified findings read per pass, newest first.
MAX_FINDINGS = 50
#: A follow-up is a guess that a proof makes worth testing, so it starts below an evidenced lead.
CONFIDENCE = 0.35
HTTP_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})


@dataclass(frozen=True)
class FollowUp:
    """One lead a verified finding of a class opens."""

    rule: str
    family: str
    title: str
    description: str
    severity: str
    #: The route the lead is about is the proven one (False: the lead is target-wide).
    same_route: bool = True


@dataclass(frozen=True)
class ProvenClass:
    """A class of verified finding, recognised by its finding type or CWE."""

    name: str
    types: frozenset[str]
    cwes: frozenset[str]
    leads: tuple[FollowUp, ...]


def _proven(name: str, types: Sequence[str], cwes: Sequence[str], *leads: FollowUp) -> ProvenClass:
    return ProvenClass(name, frozenset(types), frozenset(cwes), tuple(leads))


CLASSES: tuple[ProvenClass, ...] = (
    _proven(
        "ssrf", ("ssrf",), ("CWE-918",),
        FollowUp("ssrf_internal_services", "ssrf",
                 "Internal services reachable through the verified SSRF",
                 "The server fetches a caller-chosen URL here. Test whether in-scope internal services answer "
                 "through it. Destination limits still apply to every request.", "high"),
    ),
    _proven(
        "sqli", ("sqli", "sql_injection"), ("CWE-89",),
        FollowUp("sqli_sibling_parameters", "sqli",
                 "Sibling parameters and routes built on the injectable query",
                 "One parameter reached the query unsanitised. Parameters and routes that share the same "
                 "handler or query builder often do too.", "high"),
        FollowUp("sqli_auth_bypass", "auth_bypass",
                 "Authentication checks that query the injectable store",
                 "If login, password reset or token lookup use the same data access path, test them for "
                 "injection-based bypass.", "high", same_route=False),
    ),
    _proven(
        "xss", ("xss", "dom_xss", "stored_xss", "reflected_xss"), ("CWE-79",),
        FollowUp("xss_other_sinks", "xss",
                 "Other pages that render the same value",
                 "The value is rendered without encoding here. Find other views of the same stored or "
                 "reflected value, including admin and export views.", "medium"),
        FollowUp("xss_state_change", "csrf",
                 "State-changing actions a same-origin script can drive",
                 "A script running in this origin bypasses cross-site request defences. Identify the sensitive "
                 "state-changing routes it could call as the victim.", "medium", same_route=False),
    ),
    _proven(
        "bola", ("bola", "idor"), ("CWE-639",),
        FollowUp("bola_write_methods", "bola",
                 "Write methods on the object route with verified cross-principal read",
                 "Another principal's object was readable here. Test update and delete on the same object "
                 "route with the same two principals.", "high"),
        FollowUp("bola_sibling_objects", "bola",
                 "Sibling object types owned the same way",
                 "Object types that share this route's ownership field or parent resource are usually "
                 "guarded by the same code.", "high", same_route=False),
    ),
    _proven(
        "bfla", ("bfla", "broken_function_level_authorization"), ("CWE-285", "CWE-862", "CWE-863"),
        FollowUp("bfla_sibling_functions", "bfla",
                 "Other privileged functions behind the same missing check",
                 "A lower-privileged principal reached a privileged function. Test the other functions "
                 "of the same controller or role boundary.", "high", same_route=False),
    ),
    _proven(
        "auth_bypass", ("auth_bypass", "broken_authentication"), ("CWE-287", "CWE-306"),
        FollowUp("auth_bypass_protected_routes", "bola",
                 "Object-level authorization behind the bypassed authentication",
                 "Routes that relied on authentication alone are now reachable. Test whether they check "
                 "ownership of the objects they return.", "high", same_route=False),
    ),
    _proven(
        "path_traversal", ("path_traversal", "lfi", "file_read"), ("CWE-22", "CWE-23", "CWE-98"),
        FollowUp("file_read_secrets", "data_exposure",
                 "Configuration and credential files readable through the verified file read",
                 "Files outside the intended directory are readable here. Check for application "
                 "configuration that discloses secrets; a disclosed credential goes through secret.try.",
                 "high"),
    ),
    _proven(
        "xxe", ("xxe",), ("CWE-611",),
        FollowUp("xxe_server_side_fetch", "ssrf",
                 "Server-side requests through the verified XML entity processing",
                 "The parser resolves external entities here. Test whether it fetches in-scope URLs "
                 "on the server's behalf.", "high"),
        FollowUp("xxe_file_read", "data_exposure",
                 "Local files readable through the verified XML entity processing",
                 "Test whether file entities return configuration that discloses secrets.", "high"),
    ),
    _proven(
        "open_redirect", ("open_redirect",), ("CWE-601",),
        FollowUp("redirect_token_leak", "oauth_redirect",
                 "Sign-in flows that accept the verified open redirect as a return address",
                 "An OAuth or SSO flow that allows this route as its redirect target can leak the "
                 "authorization code or token to another origin.", "medium", same_route=False),
    ),
    _proven(
        "data_exposure", ("data_exposure", "secret_exposure", "exposed_secret"), ("CWE-200", "CWE-312", "CWE-522", "CWE-798"),
        FollowUp("exposed_secret_reuse", "secret_reuse",
                 "Where the exposed secret authenticates",
                 "A secret was disclosed here. Use secret.try to learn which in-scope services accept it; "
                 "the value itself stays server-side.", "high", same_route=False),
    ),
    _proven(
        "mass_assignment", ("mass_assignment",), ("CWE-915",),
        FollowUp("mass_assignment_privilege", "privilege_escalation",
                 "Role and ownership fields writable through the verified mass assignment",
                 "The handler binds fields the client should not set. Test the fields that decide role, "
                 "tenant and ownership.", "high"),
    ),
    _proven(
        "jwt", ("jwt", "jwt_weakness"), ("CWE-347",),
        FollowUp("jwt_forged_claims", "bfla",
                 "Privileged routes that trust the weakly verified token",
                 "Token signatures are not properly verified. Test privileged routes with altered role "
                 "and subject claims.", "high", same_route=False),
    ),
    _proven(
        "cors", ("cors", "cors_misconfiguration"), ("CWE-942",),
        FollowUp("cors_sensitive_reads", "data_exposure",
                 "Sensitive responses readable cross-origin with credentials",
                 "A foreign origin is allowed with credentials. Identify the authenticated responses "
                 "that would be readable from it.", "medium", same_route=False),
    ),
)

_BY_TYPE = {name: item for item in CLASSES for name in item.types}
_BY_CWE = {name: item for item in CLASSES for name in item.cwes}


def _evidence(finding: Mapping[str, Any]) -> Mapping[str, Any]:
    value = finding.get("evidence")
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return {}
    return value if isinstance(value, Mapping) else {}


def proven_class(finding: Mapping[str, Any]) -> ProvenClass | None:
    """The class a verified finding belongs to: its declared type first, then its CWE."""
    evidence = _evidence(finding)
    for key in ("finding_type", "family", "check_family"):
        name = str(evidence.get(key) or "").strip().lower().replace("-", "_").replace(" ", "_")
        if name in _BY_TYPE:
            return _BY_TYPE[name]
    return _BY_CWE.get(str(finding.get("cwe") or "").strip().upper())


def _route(finding: Mapping[str, Any]) -> str | None:
    """The path of the proven URL. The query never travels: it can hold the payload or a secret."""
    try:
        path = urlsplit(str(finding.get("url") or "")).path
    except ValueError:
        return None
    return path[:512] or None


def lead_proposals(finding: Mapping[str, Any]) -> list[dict[str, Any]]:
    """The leads one verified finding opens, as lead-board fields. Pure."""
    proven = proven_class(finding)
    if proven is None:
        return []
    route = _route(finding)
    method = str(_evidence(finding).get("method") or "").strip().upper()
    finding_id = str(finding["id"])
    proposals = []
    for lead in proven.leads:
        dimensions: dict[str, str] = {"proof_surface": lead.rule}
        if lead.same_route:
            if route is None:
                continue
            dimensions["route"] = route
            if method in HTTP_METHODS:
                dimensions["method"] = method
        else:
            # A target-wide lead is one lead per proven finding, not one per target.
            dimensions["object_key"] = f"finding:{finding_id}"
        proposals.append({
            "rule": lead.rule, "family": lead.family, "title": lead.title, "description": lead.description,
            "severity_guess": lead.severity, "dimensions": dimensions, "finding_id": finding_id,
            "proven_class": proven.name,
        })
    return proposals


# --- persistence --------------------------------------------------------------------------------

async def record_leads(conn: Any, target: uuid.UUID, *, source: str, proposals: Sequence[Mapping[str, Any]],
                       mark: Sequence[str]) -> dict[str, int]:
    """Record a server producer's leads once each, inside the caller's transaction.

    ``mark`` names the endorsement fields that identify one proposal of this source (for example
    the finding and the rule). A proposal whose mark is already endorsed on a live lead is skipped.
    A lead another source already holds is endorsed, never rewritten. A lead an operator closed
    stays closed.
    """
    from .hunt_hypotheses import _shared

    created = endorsed = 0
    await conn.execute("SELECT pg_advisory_xact_lock(hashtext($1))", f"{source}-leads:{target}")
    recorded = {
        tuple(json.loads(row["endorsement"]).get(field) for field in mark) for row in await conn.fetch(
            """SELECT e::text AS endorsement FROM hypotheses h, jsonb_array_elements(h.endorsements) e
               WHERE h.target_id=$1 AND e->>'source'=$2 AND NOT (h.metadata_json ? 'hunt_withheld')""",
            target, source)}
    for proposal in proposals:
        endorsement = {"source": source, "created_by": source, "confidence": proposal["confidence"],
                       **proposal["endorsement"]}
        if tuple(endorsement.get(field) for field in mark) in recorded:
            continue

        def request(**overrides: Any) -> Any:
            return _shared("request_model")(**{**dict(
                source=source, family=proposal["family"], dedupe_key=f"{source}:{proposal['family']}",
                dedupe_dimensions=proposal["dimensions"], target_id=str(target),
                cwe=proposal.get("cwe"), title=proposal["title"], description=proposal["description"],
                severity_guess=proposal["severity_guess"], confidence=proposal["confidence"],
                endorsement=endorsement, created_by=source,
                metadata_json={**proposal["metadata"], "runtime_proof_required": True}), **overrides})

        canonical = _shared("canonical")(request())
        existing = await conn.fetchval(
            "SELECT 1 FROM hypotheses WHERE target_id=$1 AND family=$2 AND dedupe_key=$3",
            target, canonical["family"], canonical["dedupe_key"])
        if existing:
            # Another source's lead: add the endorsement, leave its text, lineage and confidence.
            await _shared("upsert")(conn, request(confidence=0.0, metadata_json={}))
            endorsed += 1
        else:
            await _shared("upsert")(conn, request())
            created += 1
        recorded.add(tuple(endorsement.get(field) for field in mark))
    return {"created": created, "endorsed": endorsed}


async def produce(conn: Any, target_id: Any) -> dict[str, int]:
    """Record the leads this target's verified findings open and have not opened yet. Idempotent."""
    target = target_id if isinstance(target_id, uuid.UUID) else uuid.UUID(str(target_id))
    async with conn.transaction():
        findings = await conn.fetch(
            """SELECT id, cwe, url, evidence FROM findings
               WHERE target_id=$1 AND status='active' AND last_verified_at IS NOT NULL
                 AND last_verification_verdict IN ('exploited','verified')
               ORDER BY last_verified_at DESC, id LIMIT $2""", target, MAX_FINDINGS)
        if not findings:
            return {"considered": 0, "created": 0, "endorsed": 0}
        proposals = [{
            "family": item["family"], "title": item["title"], "description": item["description"],
            "severity_guess": item["severity_guess"], "dimensions": item["dimensions"], "confidence": CONFIDENCE,
            "endorsement": {"rule": item["rule"], "rules_version": RULES_VERSION, "finding_id": item["finding_id"],
                            "derived_from": [item["finding_id"]]},
            "metadata": {"derived_from": [item["finding_id"]], "followup_rule": item["rule"],
                         "proven_class": item["proven_class"], "rules_version": RULES_VERSION},
        } for finding in findings for item in lead_proposals(dict(finding))]
        counts = await record_leads(conn, target, source=SOURCE, proposals=proposals, mark=("finding_id", "rule"))
    return {"considered": len(findings), **counts}


async def produce_quietly(conn: Any, target_id: Any) -> dict[str, int] | None:
    """``produce`` for callers whose own work must not fail on it."""
    if target_id is None:
        return None
    try:
        return await produce(conn, target_id)
    except Exception as exc:  # noqa: BLE001 - lead production is bookkeeping, never the caller's result
        print(f"[hunt] follow-up leads skipped: {type(exc).__name__}", file=sys.stderr, flush=True)
        return None


__all__ = [
    "CLASSES", "RULES_VERSION", "SOURCE", "lead_proposals", "produce", "produce_quietly", "proven_class",
    "record_leads",
]
