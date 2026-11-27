#!/usr/bin/env python3
"""Fail-closed CI/startup verifier for an exact Model Intake deployment bundle."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import urllib.error
import urllib.request


COMPONENT_FIELDS = (
    "model_artifact_sha256",
    "repository_snapshot_sha256",
    "custom_code_sha256",
    "tokenizer_sha256",
    "configuration_sha256",
    "runtime_image_digest",
    "loader_profile_sha256",
    "retrieval_application_digest",
    "index_schema_digest",
)


def verify(api_url: str, admission: dict, bundle: dict, token: str | None, timeout: int) -> dict:
    payload = {
        "admission_package": admission,
        "expected_bundle_sha256": bundle["bundle_sha256"],
        "expected_environment": bundle["target_environment"],
        "expected_components": {field: bundle[field] for field in COMPONENT_FIELDS if bundle.get(field)},
    }
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(
        api_url.rstrip("/") + "/model-intake/admissions/v2/verify",
        data=json.dumps(payload, separators=(",", ":")).encode(),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            result = json.loads(response.read(2_000_000))
    except (OSError, urllib.error.HTTPError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"deployment verification unavailable or rejected: {exc}") from exc
    if not isinstance(result, dict) or result.get("verified") is not True or result.get("deployment_observed") is not True:
        raise RuntimeError(f"deployment verification failed: {result}")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--api-url", required=True)
    parser.add_argument("--admission-package", required=True, type=Path)
    parser.add_argument("--deployment-bundle", required=True, type=Path)
    parser.add_argument("--token")
    parser.add_argument("--timeout", type=int, default=15)
    args = parser.parse_args()
    try:
        result = verify(
            args.api_url,
            json.loads(args.admission_package.read_text()),
            json.loads(args.deployment_bundle.read_text()),
            args.token,
            max(1, min(args.timeout, 60)),
        )
    except (KeyError, OSError, json.JSONDecodeError, RuntimeError) as exc:
        print(f"MODEL DEPLOYMENT DENIED: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({
        "status": "PASS",
        "admission_id": result.get("registry", {}).get("admission_id"),
        "statement_sha256": result.get("statement_sha256"),
        "deployment_observed": True,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
