"""Deterministic build-time functional checks for packaged intake adapters."""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from model_intake_scanners import EXTERNAL_SCANNERS, run_external_scanner


EXPECTED_STATUSES = {
    "modelscan": "FAIL",
    "fickling": "FAIL",
    "semgrep": "FAIL",
    "trivy": "FAIL",
}


def _sha256_json(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def run_self_test() -> dict[str, object]:
    specs = {spec.name: spec for spec in EXTERNAL_SCANNERS}
    subject = {"kind": "adapter_self_test", "digest": "deterministic-fixture-v1"}
    checks: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="model-intake-adapter-self-test-") as raw:
        root = Path(raw)
        unsafe_pickle = root / "unsafe.pkl"
        unsafe_pickle.write_bytes(b"\x80\x04cposix\nsystem\nq\x00.")
        unsafe_source = root / "unsafe.py"
        unsafe_source.write_text('import os\nos.system("id")\n', encoding="utf-8")
        safe_source = root / "safe.py"
        safe_source.write_text(
            'import torch\nfrom safetensors.torch import load_file\n'
            'def load(path):\n    return torch.load(path, weights_only=True, map_location="cpu")\n',
            encoding="utf-8",
        )
        review_source = root / "review.py"
        review_source.write_text(
            'import importlib\nimport torch\n'
            'def load(path):\n    importlib.import_module("reviewed_local_module")\n    return torch.load(path)\n',
            encoding="utf-8",
        )
        vulnerable_repo = root / "vulnerable-repository"
        vulnerable_repo.mkdir()
        (vulnerable_repo / "requirements.txt").write_text("requests==2.19.0\n", encoding="utf-8")
        targets = {
            "modelscan": unsafe_pickle,
            "fickling": unsafe_pickle,
            "semgrep": unsafe_source,
            "trivy": vulnerable_repo,
        }
        for name, expected in EXPECTED_STATUSES.items():
            spec = dataclasses.replace(specs[name], required=True)
            result = run_external_scanner(spec, targets[name], subject)
            actual = str(result.get("execution", {}).get("status") or "CRASHED")
            variants = []
            if name == "semgrep":
                for variant_name, target, variant_expected in (
                    ("safe", safe_source, "PASS"),
                    ("review", review_source, "WARNING"),
                ):
                    variant_result = run_external_scanner(spec, target, subject)
                    variant_actual = str(variant_result.get("execution", {}).get("status") or "CRASHED")
                    variants.append({
                        "name": variant_name,
                        "expected_status": variant_expected,
                        "actual_status": variant_actual,
                        "passed": variant_actual == variant_expected,
                        "evidence_sha256": variant_result.get("evidence_sha256"),
                    })
            checks.append({
                "name": name,
                "expected_status": expected,
                "actual_status": actual,
                "passed": actual == expected and all(bool(item["passed"]) for item in variants),
                "version": result.get("scanner", {}).get("version"),
                "evidence_sha256": result.get("evidence_sha256"),
                "variants": variants,
                "diagnostic": {
                    "summary": result.get("summary"),
                    "exit_code": result.get("execution", {}).get("exit_code"),
                    "error": result.get("execution", {}).get("error"),
                } if actual != expected else None,
            })
    receipt: dict[str, object] = {
        "schema_version": "model-intake-adapter-self-test/v1",
        "tested_at": datetime.now(timezone.utc).isoformat(),
        "fixture_sha256": _sha256_json({"revision": 2, "expected": EXPECTED_STATUSES, "semgrep_variants": ["safe", "review"]}),
        "status": "PASS" if all(bool(item["passed"]) for item in checks) else "FAIL",
        "checks": checks,
    }
    receipt["receipt_sha256"] = _sha256_json(receipt)
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    arguments = parser.parse_args()
    receipt = run_self_test()
    output = Path(arguments.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(receipt, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    print(json.dumps(receipt, sort_keys=True))
    return 0 if receipt["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
