#!/usr/bin/env python3
"""Run every release-image external adapter against the counting fixture."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tests.e2e import harness as H  # noqa: E402
from tests.e2e import run_e2e as E2E  # noqa: E402
from tests.e2e.fixtures import fixtures_server as FX  # noqa: E402


def _worker_container(explicit: str | None) -> str:
    if explicit:
        return explicit
    result = subprocess.run(
        [
            "docker", "ps",
            "--filter", "label=com.docker.compose.project=shakerscan",
            "--filter", "label=com.docker.compose.service=worker",
            "--format", "{{.Names}}",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    names = sorted(line.strip() for line in result.stdout.splitlines() if line.strip())
    if not names:
        raise RuntimeError("no running release worker container is available")
    return names[0]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--worker-container")
    parser.add_argument("--json", action="store_true", dest="json_output")
    args = parser.parse_args(argv)

    H.preflight()
    worker = _worker_container(args.worker_container)
    server = FX.start(E2E.FIXTURES_PORT)
    try:
        command = [
            "docker", "exec",
            "-e", "SHAKERSCAN_BROKER_LEASE=1",
            worker,
            "python3", "/app/external_wire_acceptance.py",
            "--target", E2E.FIXTURES_BASE,
        ]
        result = subprocess.run(
            command,
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=300,
        )
        if result.returncode != 0:
            raise RuntimeError(
                "external wire acceptance failed: "
                f"{result.stderr.strip()[-8000:]}"
            )
        receipt = json.loads(result.stdout.strip().splitlines()[-1])
        if receipt.get("status") != "passed" or receipt.get("tool_count") != 9:
            raise RuntimeError(f"external wire acceptance is incomplete: {receipt}")
        if args.json_output:
            print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
        else:
            print("External tool wire ceilings: PASS")
            for case in receipt.get("cases") or []:
                print(
                    f"  {case['tool']}: status={case['status']} "
                    f"requests={case['target_observed_http_requests']} "
                    f"connections={case['target_observed_connections']}"
                )
        return 0
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    raise SystemExit(main())
