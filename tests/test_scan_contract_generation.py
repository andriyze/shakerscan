from __future__ import annotations

from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))

from scan.contracts import public_scan_contract
from scripts import scan_cli


def test_generated_scan_types_match_the_server_contract():
    result = subprocess.run(
        [sys.executable, "scripts/generate_scan_contract.py", "--check"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr

    generated = (
        ROOT / "ui" / "src" / "lib" / "scanContract.generated.ts"
    ).read_text(encoding="utf-8")
    api_source = (ROOT / "ui" / "src" / "lib" / "api.ts").read_text(
        encoding="utf-8"
    )
    contract = public_scan_contract()

    assert list(contract["budget_profiles"]) == ["fast", "balanced", "thorough"]
    assert "SubmitScanScansPostRequest as ScanStartRequest" in generated
    assert "export interface ScanPublicContract" in generated
    assert "legacy_capability" not in generated
    assert "exhaustive" not in generated
    assert "interface ScanV2Request" not in api_source
    assert "interface ScanPublicContract" not in api_source
    assert "from './scanContract.generated'" in api_source
    assert "from './publicApi.generated'" in api_source


def test_scan_cli_budget_values_match_the_public_contract():
    parser = scan_cli._parser()
    action = next(
        item for item in parser._actions if item.dest == "budget_profile"
    )
    assert tuple(action.choices) == tuple(public_scan_contract()["budget_profiles"])


def test_hunt_generated_contract_was_regenerated_with_public_contract_additions():
    result = subprocess.run(
        [sys.executable, "scripts/generate_hunt_contract.py", "--check"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
