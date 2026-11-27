#!/usr/bin/env python3
"""Release gate for real local, outbound-broker, and parallel Scan parity."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from api.scan.parity import (  # noqa: E402
    compare_scan_semantic_parity,
    parity_artifact_is_truthful,
)
from tests.e2e import harness as H  # noqa: E402
from tests.e2e import run_e2e as E2E  # noqa: E402
from tests.e2e.fixtures import fixtures_server as FX  # noqa: E402


def _broker_node_id(explicit: str | None) -> str:
    if explicit:
        return explicit
    response = H.get("/fleet/nodes")
    nodes = response.get("nodes") if isinstance(response, dict) else None
    for node in nodes or []:
        if not isinstance(node, dict):
            continue
        transport = str(node.get("transport") or node.get("network_mode") or "")
        status = str(node.get("status") or "")
        if transport == "broker" and status in {"ready", "running", "active"}:
            node_id = str(node.get("id") or node.get("node_id") or "")
            if node_id:
                return node_id
    raise RuntimeError(
        "no ready outbound-only broker node is enrolled; real parity cannot be skipped"
    )


# The active work this gate exists to compare. Nuclei stays out because its
# template set is the noisiest and least deterministic comparator input, and
# BOLA needs two principals this lane does not carry.
PARITY_ACTIVE_FAMILIES = [
    "recon",
    "sensitive_exposure",
    "xss",
    "sqli",
    "nosqli",
]


def _submit(
    *,
    target: str,
    approval_id: str,
    collection: dict[str, str],
    placement: dict[str, str],
    parallel: bool,
) -> str:
    status, response = H.post("/scans", {
        "target": target,
        "budget_profile": "balanced",
        # Explicit custom preset with an exact include list. Setting only
        # active_testing leaves the preset at its passive default, so excluding
        # both Nuclei families resolved the whole workload to recon alone: the
        # gate compared two recon-only scans and could never have detected active
        # parity drift. Active testing grants permission; it does not select
        # families.
        "policy": {
            "active_testing": True,
            "allow_state_changing_http": True,
            "preset": "custom",
            "include_families": PARITY_ACTIVE_FAMILIES,
            "exclude_families": [],
        },
        "advanced": {
            "max_duration_seconds": 600,
            "max_http_requests": 2400,
            "max_state_changing_requests": 40,
            "max_endpoints": 80,
            "force_single_worker": not parallel,
        },
        "approval_receipt_id": approval_id,
        "request_collections": [collection],
        "options": {
            "require_current_workers": True,
            "placement": placement,
            "parallel": parallel,
            "shards": 2 if parallel else None,
        },
    })
    if status not in {200, 201, 202}:
        raise RuntimeError(f"Scan submission failed ({status}): {response}")
    scan_id = str(response.get("scan_id") or response.get("id") or "")
    if not scan_id:
        raise RuntimeError(f"Scan submission did not return a scan ID: {response}")
    if bool(response.get("parallel")) != parallel:
        raise RuntimeError(
            f"parallel authority was silently changed: requested={parallel} response={response}"
        )
    return scan_id


def _completed(scan_id: str, label: str) -> dict:
    scan = H.wait_for_scan(scan_id, timeout=1200, poll=8, label=label)
    if scan.get("status") != "completed":
        raise RuntimeError(
            f"{label} Scan did not complete cleanly: "
            f"status={scan.get('status')} error={scan.get('error_message')}"
        )
    if label == "parallel":
        if scan.get("scan_role") != "parent" or not scan.get("shards"):
            raise RuntimeError("parallel Scan did not produce durable child shards")
        if any(item.get("status") != "completed" for item in scan.get("shards") or []):
            raise RuntimeError("one or more parallel child shards did not complete")
    return scan


def _artifact(scan_id: str) -> dict:
    artifact = H.get(f"/scans/{scan_id}/parity-artifact")
    if not parity_artifact_is_truthful(artifact):
        raise RuntimeError(f"Scan {scan_id} produced a clean report with missing required work")
    return artifact


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--broker-node-id", default=os.environ.get("SHAKERSCAN_E2E_BROKER_NODE_ID"))
    parser.add_argument("--target-url", default=os.environ.get("SHAKERSCAN_E2E_PARITY_TARGET"))
    parser.add_argument("--expected-source-sha", default=os.environ.get("SHAKERSCAN_E2E_SOURCE_SHA"))
    parser.add_argument("--json", action="store_true", dest="json_output")
    args = parser.parse_args(argv)

    H.preflight()
    health = H.get("/health")
    expected_source_sha = str(args.expected_source_sha or "").strip().lower()
    if expected_source_sha:
        actual_source_sha = str(health.get("source_revision") or "").strip().lower()
        if (
            len(expected_source_sha) != 40
            or any(char not in "0123456789abcdef" for char in expected_source_sha)
        ):
            raise RuntimeError("expected source SHA must be a complete 40-character commit")
        if actual_source_sha != expected_source_sha:
            raise RuntimeError(
                "parity deployment source mismatch: "
                f"expected={expected_source_sha} actual={actual_source_sha or 'missing'}"
            )
    broker_node = _broker_node_id(args.broker_node_id)
    target_url = str(args.target_url or "").strip().rstrip("/")
    parsed_target = urlsplit(target_url) if target_url else None
    if parsed_target and (
        parsed_target.scheme not in {"http", "https"}
        or not parsed_target.hostname
        or parsed_target.username
        or parsed_target.password
    ):
        raise RuntimeError("parity target must be an HTTP(S) origin without credentials")
    server = None if target_url else FX.start(E2E.FIXTURES_PORT)
    try:
        target, approval_id, selections = E2E._dast_fixture_authority(
            target_url or E2E.FIXTURES_BASE,
            allowed_host=(parsed_target.hostname if parsed_target else E2E.HONEY_HOST),
        )
        scan_ids = {
            "local": _submit(
                target=target,
                approval_id=approval_id,
                collection=selections["parity"],
                placement={"node_id": "local"},
                parallel=False,
            ),
            "broker": _submit(
                target=target,
                approval_id=approval_id,
                collection=selections["parity"],
                placement={"node_id": broker_node},
                parallel=False,
            ),
            "parallel": _submit(
                target=target,
                approval_id=approval_id,
                collection=selections["parity"],
                placement={"node_scope": "remote"},
                parallel=True,
            ),
        }
        for label, scan_id in scan_ids.items():
            _completed(scan_id, label)
        artifacts = {label: _artifact(scan_id) for label, scan_id in scan_ids.items()}
        comparison = compare_scan_semantic_parity(artifacts)
        receipt = {
            **comparison,
            "scan_ids": scan_ids,
            "broker_node_id": broker_node,
            "all_artifacts_truthful": True,
            "source_revision": str(health.get("source_revision") or "unknown"),
            "build_fingerprint": str(health.get("build_fingerprint") or "unknown"),
        }
        if args.json_output:
            print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
        else:
            print(
                "V2 real local/broker/parallel parity: "
                f"{'PASS' if comparison['consistent'] else 'FAIL'}"
            )
            for label, scan_id in scan_ids.items():
                print(f"  {label}: {scan_id}")
            for item in comparison["comparisons"]:
                print(
                    f"  {item['baseline']} vs {item['candidate']}: "
                    f"{item['difference_count']} semantic difference(s)"
                )
        return 0 if comparison["consistent"] else 1
    finally:
        if server is not None:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    raise SystemExit(main())
