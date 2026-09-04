"""The Model Intake toolchain lives in its own image, not in the scanner or API images.

The scanner and API images ship to every worker; the Model Intake artifact toolchain (semgrep,
modelscan, trivy, osv-scanner, their databases, and the pip-audit virtual environment that vendors
msgpack/setuptools) is ~2GB and only the Model Intake worker and sandbox need it. This split builds
it as an overlay on the exact scanner runtime -- the same base the API image uses -- so the Model
Intake services run the identical code and tool paths, while the scanner and API images shrink and
go free of the waived build-tool findings.
"""

from __future__ import annotations

import json
import pathlib

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCANNER = (ROOT / "scanner" / "Dockerfile").read_text(encoding="utf-8")
MI = (ROOT / "scanner" / "Dockerfile.model-intake").read_text(encoding="utf-8")


def test_the_scanner_image_no_longer_builds_the_model_intake_toolchain():
    for token in (
        "COPY scanner/model_intake_tools",
        "/opt/model-intake-tools/${tool}",
        "ARG TRIVY_VERSION",
        "ARG OSV_SCANNER_VERSION",
        "model_intake_safetensors_selftest.py",
        "model_intake_adapter_self_test.py",
        "/opt/tools/trivy --version",
    ):
        assert token not in SCANNER, f"scanner image still builds the toolchain: {token}"
    # The web/DAST toolchain stays and is still verified.
    assert "/opt/tools/katana -version" in SCANNER
    assert "/opt/tools/gungnir -h | head -1" in SCANNER


def test_the_model_intake_image_is_an_overlay_on_the_scanner_runtime():
    assert "ARG SCANNER_RUNTIME_IMAGE" in MI
    assert "FROM ${SCANNER_RUNTIME_IMAGE}" in MI
    # It carries the whole toolchain and runs the adapter self-test that gates the image.
    for token in (
        "COPY scanner/model_intake_tools /opt/model-intake-locks",
        "for tool in modelscan fickling semgrep safetensors pip-audit;",
        "ARG TRIVY_VERSION=0.73.0",
        "ARG OSV_SCANNER_VERSION=2.5.0",
        "model_intake_safetensors_selftest.py",
        "model_intake_adapter_self_test.py",
    ):
        assert token in MI, f"Model Intake image is missing {token}"
    # The scanner base purged the C toolchain and pip/venv machinery; the overlay restores them to
    # build the venvs, then purges again.
    assert "python3-pip-whl python3-setuptools-whl" in MI
    assert MI.count("apt-get purge -y --auto-remove") == 1


def test_the_waivers_move_to_the_model_intake_image_and_leave_scanner_and_api_clean():
    waivers = json.loads((ROOT / "security" / "image-vulnerability-waivers.json").read_text())["waivers"]
    by_image: dict[str, set[str]] = {}
    for w in waivers:
        by_image.setdefault(w["image"], set()).add(w["vulnerability_id"])
    assert by_image.get("model-intake") == {"CVE-2025-47273", "GHSA-6v7p-g79w-8964"}
    assert "scanner" not in by_image and "api" not in by_image
    validator = (ROOT / "scripts" / "validate_vulnerability_waivers.py").read_text()
    assert '"model-intake"' in validator


def _service(compose_path, name):
    return yaml.safe_load(compose_path.read_text(encoding="utf-8"))["services"][name]


def test_both_model_intake_services_run_the_model_intake_image():
    release = ROOT / "docker-compose.release.yml"
    for name in ("model-intake-worker", "model-intake-sandbox"):
        assert "MODEL_INTAKE_IMAGE" in _service(release, name)["image"], name
    dev = ROOT / "docker-compose.yml"
    for name in ("model-intake-worker", "model-intake-sandbox"):
        assert "MODEL_INTAKE_SANDBOX_IMAGE" in _service(dev, name)["image"], name


def test_the_local_build_builds_the_model_intake_overlay():
    scanner_sh = (ROOT / "scanner.sh").read_text(encoding="utf-8")
    assert "-f scanner/Dockerfile.model-intake" in scanner_sh
    assert "SCANNER_RUNTIME_IMAGE=${worker_image}" in scanner_sh
    # It is built after the worker runtime and reuses it, never rebuilding the scanner base.
    assert scanner_sh.index("scanner_runtime compose build") < scanner_sh.index("model_intake_overlay docker build")
