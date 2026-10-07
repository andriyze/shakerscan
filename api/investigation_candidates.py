"""Durable, non-authoritative hunt candidates shared by web and device planes.

Candidates are observations awaiting a registered server-side verifier. They never carry promotion
authority and are intentionally separate from finding proof state.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any


PLANES = frozenset({"web", "device"})
STATUSES = frozenset({
    "new", "verification_queued", "verifying", "verified", "refuted",
    "inconclusive", "blocked", "expired",
})
TERMINAL_STATUSES = frozenset({"verified", "refuted", "expired"})
IN_FLIGHT_STATUSES = frozenset({"verification_queued", "verifying"})
SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})
# Candidates keep a bounded evidence list; producers report anything beyond it.
MAX_CANDIDATE_EVIDENCE_REFS = 100

DEVICE_VERIFIER_CONTRACTS: dict[str, str] = {
    "device_service_exposure": "device.service_exposure",
    "device_tls": "device.tls",
    "device_auth_bypass": "device.auth_bypass",
    "device_control_authorization": "device.control_authorization",
    "device_firmware_advisory": "device.firmware_advisory",
    "device_ssh_posture": "device.ssh_posture",
}


# Schema installed by unified startup on every start, after the frozen baseline that creates the
# candidate tables, so fresh and already-converted instances both receive it. GET /hunts/{id} and
# the observation-ownership checks select observations by hunt_run_id.
CANDIDATE_SCHEMA_STATEMENTS = (
    """DO $$
    BEGIN
        IF to_regclass('investigation_candidate_observations') IS NOT NULL THEN
            CREATE INDEX IF NOT EXISTS idx_investigation_candidate_observations_hunt_run
            ON investigation_candidate_observations(hunt_run_id, candidate_id)
            WHERE hunt_run_id IS NOT NULL;
        END IF;
    END
    $$""",
)


class CandidateLifecycleError(ValueError):
    """A Hunt attempted an invalid candidate lifecycle transition."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _json_object(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return dict(value)
    if isinstance(value, str):
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError:
            return {}
        return dict(decoded) if isinstance(decoded, dict) else {}
    return {}


def _json_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return list(value)
    if isinstance(value, str):
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError:
            return []
        return list(decoded) if isinstance(decoded, list) else []
    return []


def canonical_family(value: Any) -> str:
    normalized = str(value or "unknown").strip().lower().replace("-", "_").replace(" ", "_")
    aliases = {
        "idor": "bola",
        "sql_injection": "sqli",
        "cross_site_scripting": "xss",
        "information_disclosure": "data_exposure",
        "service_exposure": "device_service_exposure",
        "tls": "device_tls",
        "firmware_advisory": "device_firmware_advisory",
        "ssh_posture": "device_ssh_posture",
        "control_authorization": "device_control_authorization",
    }
    return aliases.get(normalized, normalized)[:80] or "unknown"


# The published locus vocabulary, and the only keys that make up a candidate's identity. It names
# the natural keys (``path``, ``principal``, ``object_id``...) whose loss made unrelated issues
# collide on one fingerprint. A key outside it is still accepted and kept, as metadata outside the
# identity (``locus_metadata``): when it was part of the fingerprint, Hunts that described one
# issue with an extra key of their own (``paths``-style lists, ``evidence``, ``note``) each made
# their own candidate -- soak D4: ``.git`` x3 and ``/actuator/env`` x2 on one target. A value
# that does not fit the bounds below is refused, never truncated or dropped.
LOCUS_KEYS: dict[str, str] = {
    "method": "HTTP method, upper-cased",
    "route": "route template, e.g. /api/users/{id}",
    "path": "concrete request path, e.g. /.git-credentials",
    "paths": "set of concrete paths; order-insensitive; identity only, never a verification route",
    "url": "absolute URL",
    "origin": "scheme://host[:port] of the service",
    "parameter": "query/body/header parameter name",
    "input": "the input (field, header or prompt slot) the claim concerns",
    "operation": "the operation the claim concerns (e.g. read, update, tool call)",
    "object_id": "object identifier the claim concerns",
    "principal": "principal slot or role the claim concerns",
    "address": "IP address of the host",
    "host": "host name",
    "transport": "tcp or udp",
    "port": "integer 1-65535",
    "service_name": "network service name",
    "operation_id": "API operation identifier",
    "capability_id": "capability identifier",
    "scheme": "URL scheme",
    "collection_id": "request collection identifier",
    "request_id": "request identifier within a collection",
    "advisory_id": "advisory identifier",
    "cpe": "CPE string",
    "version": "software version",
    "host_key_fingerprint": "SSH host key fingerprint",
    "ai_boundary_context": "AI boundary context object (JSON, at most 16 KiB)",
}
LOCUS_SET_KEYS = frozenset({"paths"})
# Locus keys that name where a request goes. Each one is either a verification route source or
# identity only; the Hunt contract publishes which (see hunt.candidate_verification_preflight).
REQUEST_LOCATION_KEYS = frozenset({"route", "url", "path", "paths"})
MAX_LOCUS_KEYS = 32
MAX_LOCUS_BYTES = 16384
MAX_LOCUS_VALUE_CHARS = 1000
MAX_LOCUS_LIST_ITEMS = 100
_LOCUS_KEY_RE = re.compile(r"[a-z][a-z0-9_]{0,63}")


def _locus_scalar(key: str, item: Any) -> str:
    # Scalars are compared as text, exactly as before, so fingerprints of existing
    # candidates with documented keys do not change.
    text = str(item).strip()
    if key == "method":
        text = text.upper()
    if len(text) > MAX_LOCUS_VALUE_CHARS:
        raise ValueError(f"locus value for {key!r} exceeds {MAX_LOCUS_VALUE_CHARS} characters")
    return text


def _locus_port(item: Any) -> int:
    message = "locus port must be an integer from 1 to 65535"
    if isinstance(item, bool) or (isinstance(item, float) and not item.is_integer()):
        raise ValueError(message)
    try:
        port = int(item.strip()) if isinstance(item, str) else int(item)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError(message) from exc
    if not 1 <= port <= 65535:
        raise ValueError(message)
    return port


def canonical_locus(value: Any) -> dict[str, Any]:
    """Return the candidate identity locus: the ``LOCUS_KEYS`` of the normalized locus.

    The whole locus is validated first, so a malformed or oversized locus is refused whatever
    its keys. Keys outside the vocabulary are not part of the identity; ``locus_metadata``
    returns them.
    """
    normalized = normalized_locus(value)
    return {key: item for key, item in normalized.items() if key in LOCUS_KEYS}


def locus_metadata(value: Any) -> dict[str, Any]:
    """The normalized locus keys outside the published vocabulary: kept, never identity."""
    normalized = normalized_locus(value)
    return {key: item for key, item in normalized.items() if key not in LOCUS_KEYS}


def normalized_locus(value: Any) -> dict[str, Any]:
    """Normalize and bound a whole locus; documented keys are normalized, others preserved.

    Keys outside ``LOCUS_KEYS`` are kept (lower-case identifiers only). Values must be JSON; the
    result is bounded and an oversized or malformed locus is rejected instead of being
    truncated into a collision.
    """
    source = value if isinstance(value, dict) else {}
    result: dict[str, Any] = {}
    for raw_key in sorted(source, key=str):
        key = str(raw_key).strip().lower().replace("-", "_")
        item = source[raw_key]
        if item in (None, "", [], {}):
            continue
        if not _LOCUS_KEY_RE.fullmatch(key):
            raise ValueError(f"locus key {key[:64]!r} must be a lower-case identifier")
        if key in result:
            raise ValueError(f"locus key {key!r} is given more than once")
        if key == "ai_boundary_context" and isinstance(item, dict):
            # Preserve JSON types and take an independent copy. str(dict) both
            # corrupted the payload and truncated it through the scalar path.
            # Legacy string rows are not guessed or migrated here; the read-only
            # context inspector reports those as incomplete.
            try:
                encoded = json.dumps(item, allow_nan=False, separators=(",", ":"))
            except (TypeError, ValueError, RecursionError) as exc:
                raise ValueError("ai_boundary_context must contain finite JSON values") from exc
            if len(encoded.encode("utf-8")) > 16384:
                raise ValueError("ai_boundary_context exceeds 16384 bytes")
            result[key] = json.loads(encoded)
            continue
        if key == "port":
            result[key] = _locus_port(item)
            continue
        if isinstance(item, (list, tuple)):
            values = [
                _locus_scalar(key, element) if not isinstance(element, (dict, list)) else element
                for element in item
                if element not in (None, "", [], {})
            ]
            if key in LOCUS_SET_KEYS:
                # Order-insensitive identity: deduplicate and sort before any bound applies.
                values = sorted(
                    {json.dumps(element, sort_keys=True): element for element in values}.values(),
                    key=lambda element: json.dumps(element, sort_keys=True),
                )
            if len(values) > MAX_LOCUS_LIST_ITEMS:
                raise ValueError(
                    f"locus list {key!r} has more than {MAX_LOCUS_LIST_ITEMS} distinct items"
                )
            if values:
                result[key] = values
            continue
        result[key] = item if isinstance(item, dict) else _locus_scalar(key, item)
    if len(result) > MAX_LOCUS_KEYS:
        raise ValueError(f"locus has more than {MAX_LOCUS_KEYS} keys")
    try:
        encoded = json.dumps(result, sort_keys=True, allow_nan=False, separators=(",", ":"))
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValueError("locus must contain finite JSON values") from exc
    if len(encoded.encode("utf-8")) > MAX_LOCUS_BYTES:
        raise ValueError(f"locus exceeds {MAX_LOCUS_BYTES} bytes")
    return json.loads(encoded)


def candidate_fingerprint(
    *, plane: str, target_ref: str, family: Any, locus: Any,
) -> str:
    normalized_plane = str(plane or "").strip().lower()
    if normalized_plane not in PLANES:
        raise ValueError(f"unsupported candidate plane:{normalized_plane or 'empty'}")
    material = {
        "plane": normalized_plane,
        "target_ref": str(target_ref),
        "family": canonical_family(family),
        "locus": canonical_locus(locus),
    }
    return hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def normalize_candidate(
    *,
    plane: str,
    target_id: str | None = None,
    device_target_id: str | None = None,
    research_episode_id: str | None = None,
    agent_hunt_run_id: str | None = None,
    device_agent_run_id: str | None = None,
    hunt_run_id: str | None = None,
    family: Any,
    locus: Any,
    title: Any,
    claim: Any,
    severity: Any = "info",
    evidence_refs: Any = None,
    verifier_contract_id: Any = None,
    source_kind: Any = None,
) -> dict[str, Any]:
    normalized_plane = str(plane or "").strip().lower()
    if normalized_plane not in PLANES:
        raise ValueError(f"unsupported candidate plane:{normalized_plane or 'empty'}")
    if normalized_plane == "web" and (not target_id or device_target_id):
        raise ValueError("web candidates require target_id only")
    if normalized_plane == "device" and (not device_target_id or target_id):
        raise ValueError("device candidates require device_target_id only")
    target_ref = str(target_id or device_target_id)
    normalized_severity = str(severity or "info").strip().lower()
    if normalized_severity not in SEVERITIES:
        normalized_severity = "info"
    refs = list(dict.fromkeys(
        str(item).strip()[:120]
        for item in (evidence_refs or [])
        if str(item).strip()
    ))[:MAX_CANDIDATE_EVIDENCE_REFS]
    whole_locus = normalized_locus(locus)
    identity_locus = {key: item for key, item in whole_locus.items() if key in LOCUS_KEYS}
    extra_locus = {key: item for key, item in whole_locus.items() if key not in LOCUS_KEYS}
    normalized_family = canonical_family(family)
    if normalized_plane == "device":
        normalized_family = {
            "auth_bypass": "device_auth_bypass",
        }.get(normalized_family, normalized_family)
    normalized_verifier = (
        DEVICE_VERIFIER_CONTRACTS.get(normalized_family)
        if normalized_plane == "device"
        else (str(verifier_contract_id).strip()[:160] if verifier_contract_id else None)
    )
    return {
        "plane": normalized_plane,
        "target_id": str(target_id) if target_id else None,
        "device_target_id": str(device_target_id) if device_target_id else None,
        "research_episode_id": str(research_episode_id) if research_episode_id else None,
        "agent_hunt_run_id": str(agent_hunt_run_id) if agent_hunt_run_id else None,
        "device_agent_run_id": str(device_agent_run_id) if device_agent_run_id else None,
        "hunt_run_id": str(hunt_run_id) if hunt_run_id else None,
        "family": normalized_family,
        "canonical_locus": identity_locus,
        # Kept with each sighting (observation ledger) and named in the response.
        "locus_metadata": extra_locus,
        "title": str(title or "Investigation candidate").strip()[:300],
        "claim": str(claim or title or "Investigation candidate").strip()[:8000],
        "claimed_severity": normalized_severity,
        "evidence_refs": refs,
        "verifier_contract_id": normalized_verifier,
        "source_kind": str(source_kind or "hunt").strip()[:80],
        "fingerprint": candidate_fingerprint(
            plane=normalized_plane,
            target_ref=target_ref,
            family=normalized_family,
            locus=identity_locus,
        ),
    }


def _claim_identity(value: Any) -> str:
    return " ".join(str(value or "").split()).casefold()


def _same_claim(existing: Any, candidate: dict[str, Any]) -> bool:
    """Whether a stored row asserts the same issue as ``candidate``.

    The fingerprint (target, family, locus) is a dedup key, not proof that two claims describe one
    issue: an empty or coarse locus made a critical credential exposure and an unrelated RAG claim
    share a fingerprint. Equal title or equal claim text is required before two sightings merge.
    """
    return bool(
        _claim_identity(existing["claim"]) == _claim_identity(candidate["claim"])
        or _claim_identity(existing["title"]) == _claim_identity(candidate["title"])
    )


def claim_scoped_fingerprint(base_fingerprint: str, claim: Any) -> str:
    """Fingerprint for a distinct claim that shares its family and locus with another row."""
    material = f"{base_fingerprint}:claim:{_claim_identity(claim)}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


_INSERT_CANDIDATE_SQL = """INSERT INTO investigation_candidates (
       plane, target_id, device_target_id, research_episode_id, agent_hunt_run_id,
       device_agent_run_id, hunt_run_id,
       family, canonical_locus, title, claim, claimed_severity, evidence_refs,
       verifier_contract_id, source_kind, fingerprint, status, created_by
   ) VALUES (
       $1,$2::uuid,$3::uuid,$4::uuid,$5::uuid,$6::uuid,$7::uuid,$8,$9::jsonb,$10,$11,$12,$13::jsonb,
       $14,$15,$16,'new',$17
   )
   ON CONFLICT (fingerprint) DO NOTHING
   RETURNING id, status, fingerprint"""


async def _insert_or_match(
    conn: Any, candidate: dict[str, Any], fingerprint: str, created_by: str,
) -> tuple[Any, str]:
    """Insert a new row, or lock the existing row with this fingerprint."""
    for _attempt in range(3):
        row = await conn.fetchrow(
            _INSERT_CANDIDATE_SQL,
            candidate["plane"], candidate.get("target_id"), candidate.get("device_target_id"),
            candidate.get("research_episode_id"), candidate.get("agent_hunt_run_id"),
            candidate.get("device_agent_run_id"), candidate.get("hunt_run_id"), candidate["family"],
            json.dumps(candidate["canonical_locus"]), candidate["title"], candidate["claim"],
            candidate["claimed_severity"], json.dumps(candidate["evidence_refs"]),
            candidate.get("verifier_contract_id"), candidate.get("source_kind"), fingerprint,
            str(created_by or "hunt")[:120],
        )
        if row is not None:
            return row, "inserted"
        existing = await conn.fetchrow(
            """SELECT id, status, fingerprint, title, claim, claimed_severity, evidence_refs,
                      verifier_contract_id, source_kind
               FROM investigation_candidates WHERE fingerprint=$1 FOR UPDATE""",
            fingerprint,
        )
        if existing is not None:
            return existing, "existing"
    raise RuntimeError("candidate fingerprint conflicted without a visible row")


MAX_EVIDENCE_REFS = 100
# Fields a later sighting carries but never writes onto a stored row (see upsert_candidate).
_SIGHTING_FIELDS = (("title", "title"), ("claim", "claim"), ("severity", "claimed_severity"))


def _unapplied_fields(row: Any, candidate: dict[str, Any], refs_merged: bool) -> list[str]:
    fields = [
        name for name, column in _SIGHTING_FIELDS
        if str(row[column] or "") != str(candidate[column] or "")
    ]
    stored = {str(item) for item in _json_list(row["evidence_refs"])}
    if not refs_merged and not set(candidate["evidence_refs"]) <= stored:
        fields.append("evidence_refs")
    return fields


async def upsert_candidate(
    conn: Any,
    candidate: dict[str, Any],
    *,
    created_by: str,
    observation_context: dict[str, Any] | None = None,
    strict: bool = True,
    refresh_same_source: bool = False,
) -> dict[str, Any]:
    """Insert a candidate or merge a repeated sighting, and append one run-bound observation.

    A stored candidate's title, claim and severity are never replaced by a later sighting; the
    response lists what the sighting carried but did not write (``unapplied_fields``), which a
    Hunt corrects with PATCH. A sighting with the same claim merges its evidence references into
    the row; a different claim that shares the family and locus becomes its own row, and a later
    sighting of that claim merges into that row even after PATCH reworded it. Every sighting's
    own claim and provenance remain in the observation ledger. ``outcome`` reports what happened.

    A row is never changed while its verification is in flight, and evidence references are
    never truncated. With ``strict`` (planner-facing routes) either case raises
    ``CandidateLifecycleError`` (``candidate_verification_in_flight`` or
    ``candidate_evidence_limit``); otherwise the sighting is only observed and ``reason`` says
    why. Verified/refuted/expired rows are immutable: a later sighting only refreshes
    ``last_seen_at``. ``refresh_same_source`` lets a deterministic producer (an advisory
    correlation re-run on a newer snapshot) restate the title, claim and severity of a row that
    the same ``source_kind`` produced.
    """
    fingerprint = candidate["fingerprint"]
    extra_locus = dict(candidate.get("locus_metadata") or {})
    row, outcome = await _insert_or_match(conn, candidate, fingerprint, created_by)
    distinct_from: str | None = None
    if outcome == "existing" and not _same_claim(row, candidate):
        distinct_from = str(row["id"])
        fingerprint = claim_scoped_fingerprint(fingerprint, candidate["claim"])
        # This fingerprint is the claim's own identity. A row found here was created for this
        # claim; PATCH may since have reworded it, which makes it no less this claim's row.
        row, outcome = await _insert_or_match(conn, candidate, fingerprint, created_by)
    reason: str | None = None
    unapplied: list[str] = []
    if outcome == "existing":
        status = str(row["status"])
        merged_refs = list(dict.fromkeys(
            [str(item) for item in _json_list(row["evidence_refs"])]
            + list(candidate["evidence_refs"])
        ))
        if status in TERMINAL_STATUSES:
            reason = f"candidate_{status}"
        elif status in IN_FLIGHT_STATUSES:
            reason = "candidate_verification_in_flight"
            if strict:
                raise CandidateLifecycleError(
                    reason,
                    f"Candidate is {status}; wait for verification to settle before adding "
                    "evidence to it",
                )
        elif len(merged_refs) > MAX_EVIDENCE_REFS:
            reason = "candidate_evidence_limit"
            if strict:
                raise CandidateLifecycleError(
                    reason,
                    f"Merging would give the candidate {len(merged_refs)} evidence references; "
                    f"at most {MAX_EVIDENCE_REFS} are kept. Replace them with PATCH instead.",
                )
        refresh = bool(
            reason is None and refresh_same_source
            and str(row["source_kind"] or "") == str(candidate.get("source_kind") or "")
        )
        if reason is not None:
            outcome = "observed"
            await conn.execute(
                "UPDATE investigation_candidates SET last_seen_at=NOW() WHERE id=$1",
                row["id"],
            )
        elif refresh:
            outcome = "merged"
            await conn.execute(
                """UPDATE investigation_candidates
                   SET title=$4, claim=$5, claimed_severity=$6, evidence_refs=$2::jsonb,
                       verifier_contract_id=COALESCE(verifier_contract_id, $3),
                       last_seen_at=NOW(), updated_at=NOW()
                   WHERE id=$1""",
                row["id"], json.dumps(merged_refs), candidate.get("verifier_contract_id"),
                candidate["title"], candidate["claim"], candidate["claimed_severity"],
            )
        else:
            outcome = "merged"
            await conn.execute(
                """UPDATE investigation_candidates
                   SET evidence_refs=$2::jsonb,
                       verifier_contract_id=COALESCE(verifier_contract_id, $3),
                       last_seen_at=NOW(), updated_at=NOW()
                   WHERE id=$1""",
                row["id"], json.dumps(merged_refs), candidate.get("verifier_contract_id"),
            )
        if not refresh:
            unapplied = _unapplied_fields(row, candidate, refs_merged=reason is None)
    await conn.execute(
        """INSERT INTO investigation_candidate_observations (
               candidate_id, research_episode_id, agent_hunt_run_id, device_agent_run_id, hunt_run_id,
               source_kind, title, claim, claimed_severity, evidence_refs,
               verifier_contract_id, observation_context, created_by
           ) VALUES (
               $1,$2::uuid,$3::uuid,$4::uuid,$5::uuid,$6,$7,$8,$9,$10::jsonb,$11,$12::jsonb,$13
           )""",
        row["id"], candidate.get("research_episode_id"), candidate.get("agent_hunt_run_id"),
        candidate.get("device_agent_run_id"), candidate.get("hunt_run_id"), candidate.get("source_kind"), candidate["title"],
        candidate["claim"], candidate["claimed_severity"], json.dumps(candidate["evidence_refs"]),
        candidate.get("verifier_contract_id"), json.dumps({
            **(observation_context or {}),
            **({"locus_metadata": extra_locus} if extra_locus else {}),
        }),
        str(created_by or "hunt")[:120],
    )
    result = {
        "id": str(row["id"]),
        "status": str(row["status"]),
        "fingerprint": str(row["fingerprint"]),
        "inserted": outcome == "inserted",
        "outcome": outcome,
        "authoritative": False,
    }
    if distinct_from is not None:
        result["distinct_from_candidate_id"] = distinct_from
    if reason is not None:
        result["reason"] = reason
    if unapplied:
        result["unapplied_fields"] = unapplied
    if extra_locus:
        result["ignored_for_identity"] = sorted(extra_locus)
    return result


async def _hunt_owned_candidate(
    conn: Any, *, hunt_run_id: str, candidate_id: str,
) -> dict[str, Any]:
    """Lock one candidate that this exact Hunt produced or observed."""
    row = await conn.fetchrow(
        """SELECT c.* FROM investigation_candidates c
           WHERE c.id=$1::uuid
             AND EXISTS (
                 SELECT 1 FROM investigation_candidate_observations o
                 WHERE o.candidate_id=c.id AND o.hunt_run_id=$2::uuid
             )
           FOR UPDATE""",
        candidate_id,
        hunt_run_id,
    )
    if row is None:
        raise CandidateLifecycleError(
            "candidate_not_owned",
            "Candidate was not produced or observed by this Hunt",
        )
    return dict(row)


def _require_candidate_mutable(row: dict[str, Any]) -> None:
    status = str(row.get("status") or "")
    if status in TERMINAL_STATUSES:
        raise CandidateLifecycleError(
            "candidate_terminal",
            f"Candidate is {status}; its proof history is immutable",
        )
    if status in IN_FLIGHT_STATUSES:
        raise CandidateLifecycleError(
            "candidate_verification_in_flight",
            f"Candidate is {status}; wait for verification to settle before changing it",
        )


async def _append_hunt_lifecycle_observation(
    conn: Any,
    *,
    row: dict[str, Any],
    hunt_run_id: str,
    created_by: str,
    event: str,
    changed_fields: list[str],
) -> None:
    """Preserve an immutable before/after audit point for Hunt metadata edits."""
    await conn.execute(
        """INSERT INTO investigation_candidate_observations (
               candidate_id, hunt_run_id, source_kind, title, claim,
               claimed_severity, evidence_refs, verifier_contract_id,
               observation_context, created_by
           ) VALUES ($1,$2::uuid,$3,$4,$5,$6,$7::jsonb,$8,$9::jsonb,$10)""",
        row["id"],
        hunt_run_id,
        str(row.get("source_kind") or "hunt_v2")[:80],
        str(row.get("title") or "Investigation candidate")[:300],
        str(row.get("claim") or row.get("title") or "Investigation candidate")[:8000],
        str(row.get("claimed_severity") or "info"),
        json.dumps(_json_list(row.get("evidence_refs"))),
        row.get("verifier_contract_id"),
        json.dumps({
            "event": event,
            "changed_fields": sorted(set(changed_fields)),
            "authoritative": False,
            "verification_state_mutated": False,
        }),
        str(created_by or "hunt")[:120],
    )


async def update_candidate_for_hunt(
    conn: Any,
    *,
    hunt_run_id: str,
    candidate_id: str,
    changes: dict[str, Any],
    created_by: str,
) -> dict[str, Any]:
    """Update only non-authoritative metadata on a candidate owned by one Hunt.

    Family, locus, fingerprint, proof state, and verification identifiers are deliberately
    absent from ``changes``. Changing identity creates a new candidate; deterministic
    verification remains the only promotion path.
    """
    allowed = {
        "title", "claim", "severity", "evidence_refs", "verifier_contract_id",
    }
    unknown = sorted(set(changes) - allowed)
    if unknown:
        raise CandidateLifecycleError(
            "candidate_update_field_forbidden",
            f"Candidate update cannot change: {', '.join(unknown)}",
        )
    if not changes:
        raise CandidateLifecycleError(
            "candidate_update_empty", "Candidate update must change at least one field",
        )
    current = await _hunt_owned_candidate(
        conn, hunt_run_id=hunt_run_id, candidate_id=candidate_id,
    )
    _require_candidate_mutable(current)
    normalized = normalize_candidate(
        plane=str(current["plane"]),
        target_id=str(current["target_id"]) if current.get("target_id") else None,
        device_target_id=(
            str(current["device_target_id"])
            if current.get("device_target_id") else None
        ),
        hunt_run_id=hunt_run_id,
        family=current["family"],
        locus=_json_object(current.get("canonical_locus")),
        title=changes.get("title", current["title"]),
        claim=changes.get("claim", current["claim"]),
        severity=changes.get("severity", current["claimed_severity"]),
        evidence_refs=changes.get(
            "evidence_refs", _json_list(current.get("evidence_refs")),
        ),
        verifier_contract_id=(
            changes.get("verifier_contract_id")
            if "verifier_contract_id" in changes
            else current.get("verifier_contract_id")
        ),
        source_kind=current.get("source_kind") or "hunt_v2",
    )
    if not normalized["evidence_refs"]:
        raise CandidateLifecycleError(
            "candidate_evidence_required",
            "A Hunt candidate must retain at least one evidence reference",
        )
    updated = await conn.fetchrow(
        """UPDATE investigation_candidates
           SET title=$2, claim=$3, claimed_severity=$4, evidence_refs=$5::jsonb,
               verifier_contract_id=$6,
               status=CASE WHEN status IN ('inconclusive','blocked') THEN 'new' ELSE status END,
               latest_verification_id=CASE
                   WHEN status IN ('inconclusive','blocked') THEN NULL
                   ELSE latest_verification_id END,
               last_seen_at=NOW(), updated_at=NOW()
           WHERE id=$1
           RETURNING *""",
        current["id"],
        normalized["title"],
        normalized["claim"],
        normalized["claimed_severity"],
        json.dumps(normalized["evidence_refs"]),
        normalized.get("verifier_contract_id"),
    )
    updated_row = dict(updated)
    await _append_hunt_lifecycle_observation(
        conn,
        row=updated_row,
        hunt_run_id=hunt_run_id,
        created_by=created_by,
        event="candidate.updated",
        changed_fields=list(changes),
    )
    return {
        "id": str(updated_row["id"]),
        "status": str(updated_row["status"]),
        "updated_fields": sorted(changes),
        "authoritative": False,
        "verified": False,
    }


async def expire_candidate_for_hunt(
    conn: Any,
    *,
    hunt_run_id: str,
    candidate_id: str,
    created_by: str,
) -> dict[str, Any]:
    """Remove a Hunt candidate from active use while retaining its audit ledger."""
    current = await _hunt_owned_candidate(
        conn, hunt_run_id=hunt_run_id, candidate_id=candidate_id,
    )
    if str(current.get("status") or "") == "expired":
        return {
            "id": str(current["id"]),
            "status": "deleted",
            "candidate_status": "expired",
            "recoverable_audit_record": True,
            "idempotent_replay": True,
            "authoritative": False,
            "verified": False,
        }
    _require_candidate_mutable(current)
    expired = await conn.fetchrow(
        """UPDATE investigation_candidates
           SET status='expired', updated_at=NOW()
           WHERE id=$1
           RETURNING *""",
        current["id"],
    )
    expired_row = dict(expired)
    await _append_hunt_lifecycle_observation(
        conn,
        row=expired_row,
        hunt_run_id=hunt_run_id,
        created_by=created_by,
        event="candidate.deleted",
        changed_fields=["status"],
    )
    return {
        "id": str(expired_row["id"]),
        "status": "deleted",
        "candidate_status": "expired",
        "recoverable_audit_record": True,
        "authoritative": False,
        "verified": False,
    }
