"""Target-bound, evidence-linked finding mutations for the Hunt runtime.

These operations deliberately do not accept proof or verification fields.  A Hunt
may curate findings that it created, while deterministic proof contracts remain the
only path that can promote a finding to verified.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping, Sequence
import urllib.parse
import uuid

try:
    from redaction import redact_text
except ModuleNotFoundError:  # package import in host-side tests
    from scanner.redaction import redact_text


_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})
_STATUSES = frozenset({"active", "resolved", "false_positive", "accepted_risk"})
_EDITABLE_FIELDS = frozenset({"title", "description", "severity", "notes", "status"})


class HuntFindingActionError(ValueError):
    """A safe public rejection of a Hunt finding action."""


def _uuid(value: Any, label: str) -> uuid.UUID:
    try:
        return uuid.UUID(str(value or ""))
    except (TypeError, ValueError, AttributeError) as exc:
        raise HuntFindingActionError(f"Invalid {label}") from exc


def _bounded_text(value: Any, label: str, *, maximum: int, required: bool = False) -> str | None:
    text = str(value or "").strip()
    if required and not text:
        raise HuntFindingActionError(f"{label} is required")
    if len(text) > maximum:
        raise HuntFindingActionError(f"{label} exceeds {maximum} characters")
    return str(redact_text(text)) if text else None


def _finding_url(target_url: str, path: Any) -> str:
    value = str(path or "").strip()
    if not value:
        return target_url
    if len(value) > 2_000:
        raise HuntFindingActionError("path exceeds 2000 characters")
    try:
        base = urllib.parse.urlsplit(target_url)
        resolved = urllib.parse.urlsplit(urllib.parse.urljoin(target_url, value))
        same_port = resolved.port == base.port
    except ValueError as exc:
        raise HuntFindingActionError("Finding path is not a valid target URL") from exc
    if (
        resolved.scheme.lower() not in {"http", "https"}
        or resolved.hostname != base.hostname
        or not same_port
    ):
        raise HuntFindingActionError("Finding path must remain on the Hunt target origin")
    return urllib.parse.urlunsplit(
        (resolved.scheme, resolved.netloc, resolved.path or "/", resolved.query, "")
    )


async def _require_evidence_actions(
    conn: Any,
    *,
    hunt_id: uuid.UUID,
    current_action_id: uuid.UUID,
    values: Sequence[Any],
) -> list[str]:
    if not isinstance(values, (list, tuple)) or not values:
        raise HuntFindingActionError("At least one evidence_action_id is required")
    if len(values) > 50:
        raise HuntFindingActionError("At most 50 evidence actions may be linked")
    action_ids = sorted({_uuid(value, "evidence action id") for value in values}, key=str)
    if current_action_id in action_ids:
        raise HuntFindingActionError("The current finding action cannot cite itself as evidence")
    rows = await conn.fetch(
        """SELECT id FROM hunt_actions
           WHERE hunt_run_id=$1
             AND id=ANY($2::uuid[])
             AND status IN ('completed','partial')""",
        hunt_id,
        action_ids,
    )
    found = {row["id"] for row in rows}
    if found != set(action_ids):
        raise HuntFindingActionError(
            "Evidence actions must be completed or partial actions from this Hunt"
        )
    return [str(value) for value in action_ids]


async def _locked_run(conn: Any, hunt_id: uuid.UUID) -> Any:
    run = await conn.fetchrow(
        """SELECT id, status, target_kind, target_id, device_target_id, context_pack
           FROM hunt_runs WHERE id=$1 FOR UPDATE""",
        hunt_id,
    )
    if run is None:
        raise HuntFindingActionError("Hunt not found")
    if str(run["status"]) not in {"active", "awaiting_planner"}:
        raise HuntFindingActionError(f"Hunt is {run['status']}")
    return run


def _target_url(run: Any) -> str:
    raw = run["context_pack"]
    context = json.loads(raw) if isinstance(raw, str) else dict(raw or {})
    target = context.get("target") if isinstance(context.get("target"), Mapping) else {}
    return str(target.get("url") or target.get("locator") or "").strip()


async def _refresh_counts(conn: Any, run: Any) -> None:
    if run["target_id"] is not None:
        await conn.execute(
            """UPDATE targets t SET active_findings_count=(
                   SELECT COUNT(*) FROM findings f
                   WHERE f.target_id=t.id AND f.status='active'
               ), updated_at=NOW() WHERE t.id=$1""",
            run["target_id"],
        )
    if run["device_target_id"] is not None:
        await conn.execute(
            """UPDATE device_targets d SET active_findings_count=(
                   SELECT COUNT(*) FROM findings f
                   WHERE f.device_target_id=d.id AND f.status='active'
               ), updated_at=NOW() WHERE d.id=$1""",
            run["device_target_id"],
        )


async def create_hunt_finding(
    pool: Any,
    *,
    hunt_id: Any,
    action_id: Any,
    values: Mapping[str, Any],
) -> dict[str, Any]:
    hunt_uuid = _uuid(hunt_id, "hunt id")
    action_uuid = _uuid(action_id, "action id")
    title = _bounded_text(values.get("title"), "title", maximum=300, required=True)
    description = _bounded_text(
        values.get("description"), "description", maximum=20_000, required=True
    )
    severity = str(values.get("severity") or "").strip().lower()
    if severity not in _SEVERITIES:
        raise HuntFindingActionError("Invalid finding severity")
    evidence_summary = _bounded_text(
        values.get("evidence_summary"), "evidence_summary", maximum=8_000, required=True
    )
    notes = _bounded_text(values.get("notes"), "notes", maximum=8_000)

    async with pool.acquire() as conn:
        async with conn.transaction():
            run = await _locked_run(conn, hunt_uuid)
            evidence_action_ids = await _require_evidence_actions(
                conn,
                hunt_id=hunt_uuid,
                current_action_id=action_uuid,
                values=values.get("evidence_action_ids") or (),
            )
            target_url = _target_url(run)
            finding_url = _finding_url(target_url, values.get("path"))
            fingerprint = hashlib.sha256(
                json.dumps(
                    {
                        "hunt_id": str(hunt_uuid),
                        "target_id": str(run["target_id"] or run["device_target_id"]),
                        "title": title,
                        "url": finding_url,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest()
            evidence = {
                "schema_version": "hunt-finding-evidence/v1",
                "proof_state": "unverified",
                "authoritative": False,
                "summary": evidence_summary,
                "source_action_ids": evidence_action_ids,
                "hunt_id": str(hunt_uuid),
            }
            row = await conn.fetchrow(
                """INSERT INTO findings (
                       target_id, device_target_id, hunt_run_id, fingerprint,
                       title, description, severity, tool, url, evidence, notes,
                       source, status
                   ) VALUES ($1,$2,$3,$4,$5,$6,$7,'hunt',$8,$9::jsonb,$10,'deep_hunt','active')
                   RETURNING id, status, created_at""",
                run["target_id"],
                run["device_target_id"],
                hunt_uuid,
                fingerprint,
                title,
                description,
                severity,
                finding_url,
                json.dumps(evidence),
                notes,
            )
            await _refresh_counts(conn, run)
    return {
        "ok": True,
        "status": "success",
        "finding_id": str(row["id"]),
        "finding_status": str(row["status"]),
        "proof_state": "unverified",
        "authoritative": False,
        "observation": {
            "kind": "finding_mutation",
            "operation": "created",
            "finding_id": str(row["id"]),
            "status": str(row["status"]),
            "proof_state": "unverified",
        },
    }


async def update_hunt_finding(
    pool: Any,
    *,
    hunt_id: Any,
    action_id: Any,
    values: Mapping[str, Any],
) -> dict[str, Any]:
    hunt_uuid = _uuid(hunt_id, "hunt id")
    action_uuid = _uuid(action_id, "action id")
    finding_uuid = _uuid(values.get("finding_id"), "finding id")
    supplied = {key for key in _EDITABLE_FIELDS if key in values}
    if not supplied:
        raise HuntFindingActionError("At least one editable finding field is required")
    updates: dict[str, Any] = {}
    if "title" in supplied:
        updates["title"] = _bounded_text(values.get("title"), "title", maximum=300, required=True)
    if "description" in supplied:
        updates["description"] = _bounded_text(
            values.get("description"), "description", maximum=20_000, required=True
        )
    if "notes" in supplied:
        updates["notes"] = _bounded_text(values.get("notes"), "notes", maximum=8_000)
    if "severity" in supplied:
        severity = str(values.get("severity") or "").strip().lower()
        if severity not in _SEVERITIES:
            raise HuntFindingActionError("Invalid finding severity")
        updates["severity"] = severity
    if "status" in supplied:
        status = str(values.get("status") or "").strip().lower()
        if status not in _STATUSES:
            raise HuntFindingActionError("Invalid finding status")
        updates["status"] = status

    async with pool.acquire() as conn:
        async with conn.transaction():
            run = await _locked_run(conn, hunt_uuid)
            evidence_action_ids = await _require_evidence_actions(
                conn,
                hunt_id=hunt_uuid,
                current_action_id=action_uuid,
                values=values.get("evidence_action_ids") or (),
            )
            finding = await conn.fetchrow(
                """SELECT id, evidence, last_verified_at, verification_count
                   FROM findings
                   WHERE id=$1 AND hunt_run_id=$2 FOR UPDATE""",
                finding_uuid,
                hunt_uuid,
            )
            if finding is None:
                raise HuntFindingActionError("Finding was not created by this Hunt")
            if finding["last_verified_at"] is not None or int(finding["verification_count"] or 0) > 0:
                raise HuntFindingActionError(
                    "A finding with deterministic verification history cannot be edited by Hunt"
                )
            raw_evidence = finding["evidence"]
            evidence = json.loads(raw_evidence) if isinstance(raw_evidence, str) else dict(raw_evidence or {})
            audit = list(evidence.get("hunt_mutations") or [])
            audit.append({
                "action_id": str(action_uuid),
                "evidence_action_ids": evidence_action_ids,
                "fields": sorted(updates),
            })
            evidence["hunt_mutations"] = audit[-100:]
            assignments = []
            params: list[Any] = [finding_uuid, hunt_uuid]
            status_parameter: int | None = None
            for column, value in updates.items():
                params.append(value)
                assignments.append(f"{column}=${len(params)}")
                if column == "status":
                    status_parameter = len(params)
            params.append(json.dumps(evidence))
            assignments.append(f"evidence=${len(params)}::jsonb")
            if status_parameter is not None:
                assignments.append(
                    "resolved_at=CASE "
                    f"WHEN ${status_parameter}='active' THEN NULL "
                    "ELSE COALESCE(resolved_at,NOW()) END"
                )
            assignments.append("updated_at=NOW()")
            row = await conn.fetchrow(
                f"""UPDATE findings SET {', '.join(assignments)}
                    WHERE id=$1 AND hunt_run_id=$2
                    RETURNING id, status""",
                *params,
            )
            await _refresh_counts(conn, run)
    return {
        "ok": True,
        "status": "success",
        "finding_id": str(row["id"]),
        "finding_status": str(row["status"]),
        "proof_state": "unverified",
        "observation": {
            "kind": "finding_mutation",
            "operation": "updated",
            "finding_id": str(row["id"]),
            "status": str(row["status"]),
            "proof_state": "unverified",
        },
    }


async def delete_hunt_finding(
    pool: Any,
    *,
    hunt_id: Any,
    action_id: Any,
    values: Mapping[str, Any],
) -> dict[str, Any]:
    if values.get("confirm_delete") is not True:
        raise HuntFindingActionError("confirm_delete must be true")
    hunt_uuid = _uuid(hunt_id, "hunt id")
    action_uuid = _uuid(action_id, "action id")
    finding_uuid = _uuid(values.get("finding_id"), "finding id")
    async with pool.acquire() as conn:
        async with conn.transaction():
            run = await _locked_run(conn, hunt_uuid)
            await _require_evidence_actions(
                conn,
                hunt_id=hunt_uuid,
                current_action_id=action_uuid,
                values=values.get("evidence_action_ids") or (),
            )
            deleted = await conn.fetchrow(
                """DELETE FROM findings
                   WHERE id=$1 AND hunt_run_id=$2
                     AND last_verified_at IS NULL
                     AND COALESCE(verification_count,0)=0
                   RETURNING id""",
                finding_uuid,
                hunt_uuid,
            )
            if deleted is None:
                raise HuntFindingActionError(
                    "Finding was not created by this Hunt or has verification history"
                )
            await _refresh_counts(conn, run)
    return {
        "ok": True,
        "status": "success",
        "finding_id": str(deleted["id"]),
        "observation": {
            "kind": "finding_mutation",
            "operation": "deleted",
            "finding_id": str(deleted["id"]),
        },
    }
