"""Deterministic build-time functional checks for packaged intake adapters."""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from model_intake_scanners import EXTERNAL_SCANNERS, run_external_scanner


EXPECTED_STATUSES = {
    "modelscan": "FAIL",
    "fickling": "FAIL",
    "semgrep": "FAIL",
    "trivy": "FAIL",
    "osv-scanner": "FAIL",
    # Advisory data changes between release-image builds. The fixed runtime may
    # be clean or may carry review/block findings, but it must always complete.
    "pip-audit": "COMPLETE",
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
        # ModelScan advertises HDF5 coverage only when its h5py extra is
        # packaged. Keep a functional build-time proof so a bare ModelScan
        # install cannot silently turn common TensorFlow repositories into
        # incomplete scans again.
        safe_h5 = root / "safe.h5"
        modelscan_executable = shutil.which(specs["modelscan"].executable)
        if not modelscan_executable:
            raise RuntimeError("ModelScan executable is unavailable for its HDF5 self-test")
        modelscan_python = Path(modelscan_executable).resolve().with_name("python")
        subprocess.run(
            [
                str(modelscan_python),
                "-c",
                (
                    "import h5py,sys; "
                    "f=h5py.File(sys.argv[1], 'w'); "
                    "f.attrs['model_config']='{\"class_name\":\"Sequential\","
                    "\"config\":{\"layers\":[]}}'; f.close()"
                ),
                str(safe_h5),
            ],
            check=True,
            timeout=15,
        )
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
        dependency_evidence = root / "dependency-evidence"
        dependency_evidence.mkdir()
        (dependency_evidence / "requirements.txt").write_text("requests==2.19.0\n", encoding="utf-8")
        (dependency_evidence / "osv-scanner.json").write_text(json.dumps({
            "results": [{
                "source": {"path": "adapter-self-test", "type": "shakerscan-runtime-profile"},
                "packages": [{"package": {
                    "ecosystem": "PyPI", "name": "requests", "version": "2.19.0",
                }}],
            }],
        }), encoding="utf-8")
        pip_cache = json.loads(Path("/opt/pip-audit-cache/runtime-audit.json").read_text("utf-8"))
        (dependency_evidence / "runtime-components.json").write_text(json.dumps({
            "profile": {"id": pip_cache["profile_id"]},
            "components": pip_cache["components"],
        }), encoding="utf-8")
        targets = {
            "modelscan": unsafe_pickle,
            "fickling": unsafe_pickle,
            "semgrep": unsafe_source,
            "trivy": vulnerable_repo,
            "osv-scanner": dependency_evidence,
            "pip-audit": dependency_evidence,
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
            if name == "modelscan":
                h5_result = run_external_scanner(spec, safe_h5, subject)
                h5_actual = str(h5_result.get("execution", {}).get("status") or "CRASHED")
                variants.append({
                    "name": "safe_hdf5",
                    "expected_status": "PASS",
                    "actual_status": h5_actual,
                    "passed": h5_actual == "PASS",
                    "evidence_sha256": h5_result.get("evidence_sha256"),
                })
            passed = actual == expected
            if expected == "COMPLETE":
                passed = actual in {"PASS", "WARNING", "FAIL"}
            checks.append({
                "name": name,
                "expected_status": expected,
                "actual_status": actual,
                "passed": passed and all(bool(item["passed"]) for item in variants),
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
        "fixture_sha256": _sha256_json({
            "revision": 3,
            "expected": EXPECTED_STATUSES,
            "modelscan_variants": ["safe_hdf5"],
            "semgrep_variants": ["safe", "review"],
        }),
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
