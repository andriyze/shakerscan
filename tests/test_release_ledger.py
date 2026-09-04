"""The upgrade smoke reads previous-stable digests from the ledger, not from hardcoded literals."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _ledger():
    spec = importlib.util.spec_from_file_location("release_ledger_under_test", ROOT / "scripts" / "release_ledger.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ledger = _ledger()

SAMPLE = """
| Version | Git Commit | Scanner/Worker Image | API Image | UI Image | Model Intake Signer Image | Model Intake Image |
| --- | --- | --- | --- | --- | --- | --- |
| 9.9.9 | pending candidate | pending | pending | pending | pending |
| 0.8.18 | `9f87f7db` | `shakerscan/shakerscan-scanner:0.8.18` (`sha256:%s`) | `shakerscan/shakerscan-api:0.8.18` (`sha256:%s`) | `shakerscan/shakerscan-ui:0.8.18` (`sha256:%s`) | `shakerscan/shakerscan-model-intake-signer:0.8.18` (`sha256:%s`) |
| 0.8.14 | `82ecff77` (failed validation; not published) | not published | not published | not published | not published |
""" % ("a" * 64, "b" * 64, "c" * 64, "d" * 64)


def test_published_digests_are_read_per_image():
    assert ledger.published_image("0.8.18", "scanner", SAMPLE) == "shakerscan/shakerscan-scanner@sha256:" + "a" * 64
    assert ledger.published_image("0.8.18", "api", SAMPLE) == "shakerscan/shakerscan-api@sha256:" + "b" * 64
    assert ledger.published_image("0.8.18", "ui", SAMPLE) == "shakerscan/shakerscan-ui@sha256:" + "c" * 64
    assert ledger.published_image("0.8.18", "signer", SAMPLE) == "shakerscan/shakerscan-model-intake-signer@sha256:" + "d" * 64


def test_pending_or_unpublished_rows_fail_closed():
    with pytest.raises(ledger.LedgerError):
        ledger.published_image("9.9.9", "scanner", SAMPLE)
    with pytest.raises(ledger.LedgerError):
        ledger.published_image("0.8.14", "api", SAMPLE)
    with pytest.raises(ledger.LedgerError):
        ledger.published_image("0.0.1", "ui", SAMPLE)


def test_the_stable_channel_version_has_published_digests_in_the_real_ledger():
    stable = (ROOT / "install" / "STABLE_VERSION").read_text(encoding="utf-8").strip()
    for image in ("scanner", "api", "ui", "signer"):
        run = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "release_ledger.py"), "--version", stable, "--image", image],
            capture_output=True, text=True,
        )
        assert run.returncode == 0, run.stderr
        assert run.stdout.strip().startswith("shakerscan/")


def test_the_upgrade_smoke_derives_its_baseline_from_the_ledger():
    source = (ROOT / "scripts" / "upgrade_smoke.sh").read_text(encoding="utf-8")
    for variable, image in (("BASELINE_IMAGE", "scanner"), ("BASELINE_API_IMAGE", "api"), ("BASELINE_UI_IMAGE", "ui")):
        assert f'{variable}="${{{variable}:-$(python3 "$REPO_ROOT/scripts/release_ledger.py" --version "$BASELINE_VERSION" --image {image})}}"' in source
    assert "@sha256:" not in source.split("SCANNER_IMAGE=", 1)[0], "no hardcoded baseline digests remain"


def test_upgrade_certification_pins_the_oldest_supported_base():
    assert (ROOT / "install" / "OLDEST_SUPPORTED_UPGRADE_BASE").read_text().strip() == "0.8.18"
    workflow = (ROOT / ".github" / "workflows" / "release-candidate.yml").read_text()
    assert "install/OLDEST_SUPPORTED_UPGRADE_BASE" in workflow
    assert "upgrade-receipt-${baseline}.json" in workflow


def test_a_row_that_predates_the_model_intake_image_fails_closed():
    # 2.0.x rows carry four images; asking them for the Model Intake image must not index past the row.
    with pytest.raises(ledger.LedgerError, match="predates"):
        ledger.published_image("0.8.18", "model_intake", SAMPLE)
