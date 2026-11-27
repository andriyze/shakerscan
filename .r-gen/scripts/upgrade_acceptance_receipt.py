#!/usr/bin/env python3
"""Write the content-free stateful upgrade and rollback-boundary receipt."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline-version", required=True)
    parser.add_argument("--baseline-source-sha", required=True)
    parser.add_argument("--candidate-source-sha", required=True)
    for plane in ("scanner", "api", "ui"):
        parser.add_argument(f"--baseline-{plane}-image", required=True)
        parser.add_argument(f"--candidate-{plane}-image", required=True)
    parser.add_argument("--candidate-model-intake-image", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    for value in (args.baseline_source_sha, args.candidate_source_sha):
        if not re.fullmatch(r"[0-9a-f]{40}", value):
            parser.error("source identities must be full lowercase commit SHAs")
    baseline_images = {
        plane: getattr(args, f"baseline_{plane}_image") for plane in ("scanner", "api", "ui")
    }
    candidate_images = {
        plane: getattr(args, f"candidate_{plane}_image")
        for plane in ("scanner", "api", "ui", "model_intake")
    }
    for value in (*baseline_images.values(), *candidate_images.values()):
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
            parser.error("image identities must be exact sha256 digests")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-.][0-9A-Za-z.-]+)?", args.baseline_version):
        parser.error("baseline version must be an explicit release version")
    checks = {
        "previous_stable_runtime_migrations_twice": "pass",
        "representative_scan_and_pending_work_preserved": "pass",
        "legacy_hunt_preserved": "pass",
        "model_intake_submission_preserved": "pass",
        "legacy_credential_preserved": "pass",
        "ai_gate_target_preserved": "pass",
        "fleet_node_and_consumed_token_preserved": "pass",
        "evidence_object_preserved": "pass",
        "candidate_migrations_twice": "pass",
        "database_restart_preserved_state": "pass",
        "backup_restore_rollback_boundary": "pass",
        "previous_stable_api_ui_worker_boot_after_restore": "pass",
        "candidate_model_intake_worker_boot_after_upgrade": "pass",
        "redis_queue_and_lease_survive_upgrade_and_rollback": "pass",
    }
    receipt = {
        "schema_version": "stateful-upgrade-acceptance/v2",
        "status": "pass",
        "baseline": {
            "version": args.baseline_version,
            "source_sha": args.baseline_source_sha,
            "images": baseline_images,
        },
        "candidate": {
            "source_sha": args.candidate_source_sha,
            "images": candidate_images,
        },
        "rollback_boundary": "pre-upgrade pg_dump restore plus previous-stable runtime boot",
        "checks": checks,
    }
    receipt["receipt_sha256"] = hashlib.sha256(
        json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
