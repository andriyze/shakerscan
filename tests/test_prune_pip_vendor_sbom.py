"""pip's vendored SBOM must describe what the image actually ships.

The 2.2.0 strip deleted pip's vendored msgpack and pkg_resources but left ``bom.cdx.json``
naming them, and Trivy reported the deleted packages from the SBOM on every candidate. The pruner
removes exactly the deleted components and their dependency edges, keeps the rest so scanners
still see pip's other vendored packages, and rejects anything that is not a CycloneDX document.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scanner" / "model_intake_tools" / "prune_pip_vendor_sbom.py"

sys.path.insert(0, str(SCRIPT.parent))
import prune_pip_vendor_sbom  # noqa: E402

sys.path.pop(0)


def _sbom() -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {"name": "msgpack", "version": "1.1.2", "bom-ref": "pkg:pypi/msgpack@1.1.2"},
            {"name": "setuptools", "version": "70.3.0", "bom-ref": "pkg:pypi/setuptools@70.3.0"},
            {"name": "urllib3", "version": "2.5.0", "bom-ref": "pkg:pypi/urllib3@2.5.0"},
            {"name": "requests", "version": "2.32.5", "bom-ref": "pkg:pypi/requests@2.32.5"},
        ],
        "dependencies": [
            {"ref": "pkg:pypi/msgpack@1.1.2", "dependsOn": []},
            {"ref": "pkg:pypi/requests@2.32.5", "dependsOn": ["pkg:pypi/urllib3@2.5.0", "pkg:pypi/setuptools@70.3.0"]},
            {"ref": "pkg:pypi/setuptools@70.3.0", "dependsOn": []},
        ],
    }


def test_prune_removes_only_the_deleted_components_and_their_edges():
    document = _sbom()
    removed = prune_pip_vendor_sbom.prune_components(document, {"msgpack", "setuptools"})
    assert removed == ["msgpack", "setuptools"]
    assert [c["name"] for c in document["components"]] == ["urllib3", "requests"]
    assert document["dependencies"] == [
        {"ref": "pkg:pypi/requests@2.32.5", "dependsOn": ["pkg:pypi/urllib3@2.5.0"]},
    ]


def test_prune_tolerates_a_name_pip_no_longer_vendors():
    document = _sbom()
    removed = prune_pip_vendor_sbom.prune_components(document, {"msgpack", "nonexistent"})
    assert removed == ["msgpack"]
    assert "nonexistent" not in {c["name"] for c in document["components"]}


def test_prune_rejects_documents_that_are_not_cyclonedx():
    with pytest.raises(ValueError, match="CycloneDX"):
        prune_pip_vendor_sbom.prune_components({"components": []}, {"msgpack"})


def test_cli_rewrites_the_file_in_place_and_reports(tmp_path: Path):
    bom = tmp_path / "bom.cdx.json"
    bom.write_text(json.dumps(_sbom()), encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(SCRIPT), str(bom), "msgpack", "setuptools"],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "pruned ['msgpack', 'setuptools']" in result.stdout
    rewritten = json.loads(bom.read_text(encoding="utf-8"))
    assert {c["name"] for c in rewritten["components"]} == {"urllib3", "requests"}
    assert "msgpack" not in bom.read_text(encoding="utf-8")


def test_cli_fails_closed_on_a_non_sbom_file(tmp_path: Path):
    bogus = tmp_path / "bom.cdx.json"
    bogus.write_text("{}", encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(SCRIPT), str(bogus), "msgpack"],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 1
    assert "CycloneDX" in result.stderr
