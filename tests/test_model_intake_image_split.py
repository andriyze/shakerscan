"""The Model Intake toolchain lives in its own image, not in the scanner or API images.

The scanner and API images ship to every worker; the Model Intake artifact toolchain (semgrep,
modelscan, trivy, osv-scanner, their databases, and the pip-audit virtual environment) is ~2GB and
only the Model Intake worker and sandbox need it. This split builds
it as an overlay on the exact scanner runtime -- the same base the API image uses -- so the Model
Intake services run the identical code and tool paths, while the scanner and API images shrink and
the release carries no build-tool vulnerability waivers.
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
    # The tiny Model Intake dependency locks stay in the scanner image: the runtime build
    # fingerprint hashes /opt/model-intake-locks, so all three images must carry them to stay on one
    # fingerprint. The heavy toolchain that consumes them does not.
    assert "COPY scanner/model_intake_tools /opt/model-intake-locks" in SCANNER


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


def test_the_release_images_have_no_vulnerability_waivers():
    waivers = json.loads((ROOT / "security" / "image-vulnerability-waivers.json").read_text())["waivers"]
    assert waivers == []
    validator = (ROOT / "scripts" / "validate_vulnerability_waivers.py").read_text()
    # The validator derives its image set from the canonical inventory, so the Model Intake
    # image is a known waiver target without a literal copy of the name.
    assert "release_image_inventory" in validator
    inventory = json.loads((ROOT / "install" / "release-images.json").read_text())
    assert "model_intake" in {item["key"] for item in inventory["images"]}


def test_model_intake_pip_audit_environment_removes_avoidable_build_tools():
    lock = (ROOT / "scanner" / "model_intake_tools" / "pip-audit.lock").read_text()

    # GHSA-6v7p-g79w-8964 affects msgpack <=1.2.0; 1.2.1 is the patched release.
    assert "msgpack==1.2.1" in lock
    assert "msgpack==1.2.0" not in lock
    # setuptools is seeded by some distro venv implementations but is not in the
    # hash-locked runtime graph. Remove it and prove it is absent during the build.
    # The four tool venvs lose pip (whose vendor.txt names msgpack 1.1.2 and setuptools 70.3.0)
    # and setuptools outright. pip-audit keeps pip for pip-api but loses the two vendored
    # packages; the build proves the stripped pip still serves pip-audit and its cache build.
    assert 'for tool in modelscan fickling semgrep safetensors; do' in MI
    assert '-m pip uninstall -y pip setuptools' in MI
    assert 'rm -rf "$vendor/msgpack" "$vendor/pkg_resources"' in MI
    assert "sed -i '/^msgpack==/d; /^setuptools==/d' \"$vendor/vendor.txt\"" in MI
    assert 'find_spec("pip._vendor.msgpack") is None' in MI
    assert MI.index('rm -rf "$vendor/msgpack"') < MI.index("/opt/tools/pip-audit-offline --build-cache")
    offline = (ROOT / "scanner" / "model_intake_tools" / "pip_audit_offline.py").read_text()
    assert "--disable-pip" in offline


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


def test_the_scanner_image_removes_the_base_images_virtualenv_remnants():
    # The Playwright base ships virtualenv, whose embedded pip wheels vendor msgpack and setuptools;
    # those were the only findings left on the scanner and API images after the toolchain split.
    assert "pip uninstall -y --break-system-packages virtualenv" in SCANNER
    assert "rm -rf /root/.cache/virtualenv /usr/local/bin/virtualenv" in SCANNER
    assert 'find_spec("virtualenv") is None' in SCANNER
    # The removal happens in the scanner base, which the API and Model Intake images build from.
    assert SCANNER.index("uninstall -y --break-system-packages virtualenv") < SCANNER.index("uninstall -y --break-system-packages pip")


def test_fleet_overlays_carry_no_model_intake_service():
    """Fleet workers never consume the Model Intake queue (worker_queue_policy), and after the
    split the fleet worker image has no toolchain, so a Model Intake sandbox on a fleet node
    would only fail on start. The overlays must not define one."""
    for name in ("docker-compose.worker.yml", "docker-compose.broker-worker.yml"):
        overlay = yaml.safe_load((ROOT / name).read_text(encoding="utf-8"))
        services = set((overlay.get("services") or {}).keys())
        assert not {s for s in services if "model-intake" in s}, (name, sorted(services))
        assert "model_intake_sandbox.py" not in (ROOT / name).read_text(encoding="utf-8")
