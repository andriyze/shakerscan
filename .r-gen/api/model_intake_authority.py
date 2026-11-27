"""Model Intake authority-change invalidation.

Extracted verbatim from the api.py monolith. When a server-owned trust anchor or
policy profile changes, active admissions must fail closed: they move to
``reassessment_required``, every transition is recorded as an admission event,
and any deployment binding built on them is marked ``STALE``.

The function takes an open asyncpg connection so the caller keeps transaction
ownership; it holds no pool of its own and imports nothing from ``api.api``.
"""

from __future__ import annotations

import json
from typing import Any

try:
    from model_intake_admissions import REASSESSMENT_TRIGGERS
except ModuleNotFoundError:  # package import in host-side tests
    from .model_intake_admissions import REASSESSMENT_TRIGGERS


async def _invalidate_model_intake_authority_change(
    conn: Any,
    *,
    actor: str,
    trigger_type: str,
    reason: str,
    environments: list[str] | None = None,
    policy_profiles: list[str] | None = None,
) -> dict[str, int]:
    """Fail active admissions closed after a server-owned trust or policy mutation."""
    if trigger_type not in REASSESSMENT_TRIGGERS:
        raise ValueError("unsupported Model Intake authority-change trigger")
    normalized_environments = sorted({str(item).strip().lower() for item in environments or [] if str(item).strip()})
    normalized_profiles = sorted({str(item).strip() for item in policy_profiles or [] if str(item).strip()})
    invalidated = await conn.fetch(
        """
        UPDATE model_intake_admissions
        SET status='reassessment_required',updated_at=NOW()
        WHERE status='active'
          AND ($1::text[] = '{}'::text[] OR COALESCE(target_environment,'') = ANY($1::text[]))
          AND ($2::text[] = '{}'::text[] OR COALESCE(policy_profile,'') = ANY($2::text[]))
        RETURNING id,statement_sha256
        """,
        normalized_environments,
        normalized_profiles,
    )
    admission_ids = [item["id"] for item in invalidated]
    for admission in invalidated:
        await conn.execute(
            """
            INSERT INTO model_intake_admission_events
                (admission_id,event_type,trigger_type,actor,reason,previous_status,new_status,
                 evidence_digest,metadata_json)
            VALUES ($1,'authority_changed',$2,$3,$4,'active','reassessment_required',$5,$6::jsonb)
            """,
            admission["id"],
            trigger_type,
            actor,
            reason,
            admission["statement_sha256"],
            json.dumps({
                "environments": normalized_environments,
                "policy_profiles": normalized_profiles,
            }),
        )
    stale_bindings = 0
    if admission_ids:
        binding_result = await conn.execute(
            """
            UPDATE model_intake_deployment_bindings
            SET verifier_status='STALE',observed_bundle_sha256=NULL,observed_at=NULL
            WHERE admission_id = ANY($1::uuid[]) AND verifier_status <> 'STALE'
            """,
            admission_ids,
        )
        try:
            stale_bindings = int(str(binding_result).rsplit(" ", 1)[-1])
        except ValueError:
            stale_bindings = 0
    return {
        "admissions_invalidated": len(invalidated),
        "deployment_bindings_staled": stale_bindings,
    }



__all__ = ["_invalidate_model_intake_authority_change"]
