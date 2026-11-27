"""The isolated maintenance job must resolve the installed-style flat imports."""

import os
from pathlib import Path
import subprocess
import sys

import yaml


def test_maintenance_pythonpath_resolves_both_source_package_roots(tmp_path):
    root = Path(__file__).resolve().parents[1]
    workflow = yaml.safe_load(
        (root / ".github/workflows/maintenance-regressions.yml").read_text()
    )
    configured = workflow["jobs"]["metadata"]["env"].get("PYTHONPATH", "")
    # An isolated checkout layout prevents an installed package or earlier test
    # from masking the missing path that broke maintenance test collection.
    for relative in ("api/schedules/__init__.py", "api/retest_contract.py",
                     "scanner/scanner_tools/__init__.py"):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("")
    # Resolve GitHub's workspace expression as Actions does, but against the
    # isolated test checkout instead of leaking the real repository's imports.
    configured = configured.replace("${{ github.workspace }}", str(tmp_path))
    environment = {**os.environ, "PYTHONPATH": configured}
    result = subprocess.run(
        [sys.executable, "-S", "-c",
         "import schedules, retest_contract, scanner_tools"],
        cwd=tmp_path, env=environment, capture_output=True, text=True, timeout=10,
        check=False,
    )
    assert result.returncode == 0, result.stderr
