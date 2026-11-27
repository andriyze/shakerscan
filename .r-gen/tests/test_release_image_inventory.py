"""Every release-image consumer is bound to the canonical five-image inventory."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys

import yaml

ROOT = Path(__file__).resolve().parents[1]


def _load(relative: str, name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


inventory = _load("scripts/release_image_inventory.py", "release_image_inventory")


def test_inventory_is_exactly_the_five_published_images():
    assert inventory.IMAGE_KEYS == ("scanner", "api", "ui", "signer", "model_intake")
    assert set(inventory.LOCK_KEYS.values()) == {
        "SCANNER_IMAGE", "API_IMAGE", "UI_IMAGE", "SIGNER_IMAGE", "MODEL_INTAKE_IMAGE",
    }
    for image in inventory.RELEASE_IMAGES:
        assert (ROOT / image["dockerfile"]).is_file()


def test_generated_shell_projection_is_current_and_consumed():
    generator = _load(
        "scripts/generate_release_image_inventory.py", "generate_release_image_inventory"
    )
    assert (ROOT / "install" / "release-images.sh").read_text() == generator.render()
    scanner = (ROOT / "scanner.sh").read_text()
    assert '. "$SCRIPT_DIR/install/release-images.sh"' in scanner
    for installer_name in ("index.sh", "index.html"):
        installer = (ROOT / "install" / installer_name).read_text()
        assert 'install/release-images.json"' in installer
        assert 'install/release-images.sh"' in installer


def test_release_workflow_and_compose_name_the_inventory_set():
    workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "release-candidate.yml").read_text())
    targets = workflow["jobs"]["vulnerability-scan"]["strategy"]["matrix"]["target"]
    assert {item["name"].replace("-", "_") for item in targets} == set(inventory.IMAGE_KEYS)

    compose = yaml.safe_load((ROOT / "docker-compose.release.yml").read_text())["services"]
    for image in inventory.RELEASE_IMAGES:
        lock_key = image["lock_key"]
        for service in image["compose_services"]:
            assert lock_key in compose[service]["image"], (image["key"], service)


def test_python_release_tools_import_the_inventory_instead_of_copying_sets():
    for relative in (
        "scripts/release_ledger.py",
        "scripts/record_release_ledger.py",
        "scripts/certify_release_receipt.py",
        "scripts/release_preservation.py",
        "scripts/validate_vulnerability_waivers.py",
    ):
        source = (ROOT / relative).read_text()
        assert "release_image_inventory" in source, relative
    raw = json.loads((ROOT / "install" / "release-images.json").read_text())
    assert len(raw["images"]) == 5
