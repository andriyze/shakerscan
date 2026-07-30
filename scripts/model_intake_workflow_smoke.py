#!/usr/bin/env python3
"""Exercise Model Intake evidence invalidation against a real PostgreSQL schema."""

from __future__ import annotations

import argparse
import asyncio
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import sys
import uuid

import asyncpg


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))
import api  # noqa: E402


async def _run(database_url: str) -> None:
    conn = await asyncpg.connect(database_url)
    transaction = conn.transaction()
    await transaction.start()
    try:
        suffix = uuid.uuid4().hex
        target_id = uuid.uuid4()
        scan_id = uuid.uuid4()
        submission_id = uuid.uuid4()
        admission_id = uuid.uuid4()
        artifact_sha256 = "a" * 64
        snapshot_sha256 = "b" * 64
        statement_sha256 = suffix.ljust(64, "0")[:64]
        bundle_sha256 = "c" * 64
        now = datetime.now(timezone.utc)

        await conn.execute(
            "INSERT INTO targets (id,url,name,discovery_source) VALUES ($1,$2,'workflow-smoke','model-intake')",
            target_id,
            f"https://workflow-{suffix}.invalid/model.safetensors",
        )
        await conn.execute(
            """
            INSERT INTO scans (id,target_id,target_url,status,scan_type,run_kind)
            VALUES ($1,$2,$3,'completed','model_intake','model_intake')
            """,
            scan_id,
            target_id,
            f"https://workflow-{suffix}.invalid/model.safetensors",
        )
        await conn.execute(
            """
            INSERT INTO model_intake_submissions
                (id,scan_id,requested_by,requested_environment,source_kind,source_reference_hash,state)
            VALUES ($1,$2,'workflow-smoke','production','https',$3,'admitted')
            """,
            submission_id,
            scan_id,
            "d" * 64,
        )
        await conn.execute(
            """
            INSERT INTO model_intake_admissions
                (id,scan_id,target_id,submission_id,artifact_sha256,repository_snapshot_sha256,
                 statement_sha256,admission_package,decision,status,schema_version,
                 deployment_bundle_sha256,evidence_manifest_sha256,policy_decision_sha256,
                 target_environment,issued_at,expires_at,reassessment_due_at)
            VALUES ($1,$2,$3,$4,$5,$6,$7,'{}'::jsonb,'allow','active','model-intake-admission/v2',
                    $8,$9,$10,'production',$11,$12,$12)
            """,
            admission_id,
            scan_id,
            target_id,
            submission_id,
            artifact_sha256,
            snapshot_sha256,
            statement_sha256,
            bundle_sha256,
            "e" * 64,
            "f" * 64,
            now,
            now + timedelta(days=1),
        )
        await conn.execute(
            """
            INSERT INTO model_intake_deployment_bindings
                (submission_id,admission_id,deployment_bundle_sha256,environment,
                 observed_bundle_sha256,verifier_status,observed_at)
            VALUES ($1,$2,$3,'production',$3,'PASS',NOW())
            """,
            submission_id,
            admission_id,
            bundle_sha256,
        )

        result = await api._reset_model_intake_for_new_evidence(
            conn,
            submission_id,
            actor="workflow-smoke",
            evidence_type="runtime_execution",
            evidence_id=str(uuid.uuid4()),
        )
        state = await conn.fetchval("SELECT state FROM model_intake_submissions WHERE id=$1", submission_id)
        admission_status = await conn.fetchval(
            "SELECT status FROM model_intake_admissions WHERE id=$1", admission_id
        )
        binding = await conn.fetchrow(
            "SELECT verifier_status,observed_bundle_sha256,observed_at FROM model_intake_deployment_bindings WHERE admission_id=$1",
            admission_id,
        )
        event_types = {
            row["event_type"]
            for row in await conn.fetch(
                "SELECT event_type FROM model_intake_submission_events WHERE submission_id=$1",
                submission_id,
            )
        }
        admission_events = {
            row["event_type"]
            for row in await conn.fetch(
                "SELECT event_type FROM model_intake_admission_events WHERE admission_id=$1",
                admission_id,
            )
        }

        assert result == {"admissions_invalidated": 1, "deployment_bindings_staled": 1}
        assert state == "evidence_ready"
        assert admission_status == "reassessment_required"
        assert dict(binding) == {
            "verifier_status": "STALE",
            "observed_bundle_sha256": None,
            "observed_at": None,
        }
        assert "authoritative_evidence_attached" in event_types
        assert "authoritative_evidence_changed" in admission_events
    finally:
        await transaction.rollback()
        await conn.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database-url", default=os.environ.get("DATABASE_URL"))
    args = parser.parse_args()
    if not args.database_url:
        parser.error("--database-url or DATABASE_URL is required")
    asyncio.run(_run(args.database_url))
    print('{"status":"passed","workflow":"model_intake_invalidation"}')
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
