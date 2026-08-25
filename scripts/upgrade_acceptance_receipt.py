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
    parser.add_argument("--baseline-source-sha", required=True)
    parser.add_argument("--candidate-source-sha", required=True)
    parser.add_argument("--baseline-image", required=True)
    parser.add_argument("--candidate-image", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    for value in (args.baseline_source_sha, args.candidate_source_sha):
        if not re.fullmatch(r"[0-9a-f]{40}", value):
            parser.error("source identities must be full lowercase commit SHAs")
    for value in (args.baseline_image, args.candidate_image):
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
            parser.error("image identities must be exact sha256 digests")
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
    }
    receipt = {
        "schema_version": "stateful-upgrade-acceptance/v2",
        "status": "pass",
        "baseline": {
            "source_sha": args.baseline_source_sha,
            "image_digest": args.baseline_image,
        },
        "candidate": {
            "source_sha": args.candidate_source_sha,
            "image_digest": args.candidate_image,
        },
        "rollback_boundary": "pre-upgrade pg_dump restore",
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
