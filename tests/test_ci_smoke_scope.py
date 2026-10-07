"""The required smoke job spends integration time only when the changed paths need it."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ci_smoke_scope.py"
spec = importlib.util.spec_from_file_location("ci_smoke_scope", SCRIPT)
assert spec and spec.loader
scope = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scope)


def test_ui_copy_change_uses_ui_only_gate():
    assert scope.classify_paths(["ui/src/lib/labels.ts"]) == {
        "backend": False, "ui": True, "stack": False,
    }
    assert scope.python_mode(["ui/src/lib/labels.ts"]) == "ui"
    assert scope.e2e_area(["ui/src/lib/labels.ts"]) == "all"


def test_image_or_contract_change_keeps_stack_gate():
    for path in (
        "ui/Dockerfile", "ui/package-lock.json", "ui/next.config.js",
        "api/scan/contracts.py", "scripts/generate_public_api_contract.py",
        "ui/src/lib/publicApi.generated.ts",
    ):
        assert scope.classify_paths([path])["stack"], path
        assert scope.python_mode([path]) == "full", path


def test_backend_and_mixed_changes_keep_every_gate():
    for paths in (
        ["scanner/scan.py"], ["db/init.sql"],
        ["ui/src/lib/labels.ts", "api/api.py"],
        [".github/workflows/e2e-pr.yml"], ["scripts/ci_smoke_scope.py"],
        [".github/smoke-image-cache.hcl"], ["scripts/merge_e2e_scorecards.py"],
    ):
        assert scope.classify_paths(paths) == {
            "backend": True, "ui": True, "stack": True,
        }
        assert scope.python_mode(paths) == "full"


def test_isolated_backend_changes_select_one_e2e_area():
    cases = {
        "api/model_intake/runner.py": "model_intake",
        "scanner/scanner_tools/model_intake_archives.py": "model_intake",
        "api/ai_gate/boundary/runner.py": "ai_gate",
        "api/hunt/authorization_evidence.py": "hunt",
    }
    for path, expected in cases.items():
        assert scope.classify_paths([path])["backend"]
        assert scope.e2e_area([path]) == expected
        assert scope.e2e_area([path, "ui/src/lib/labels.ts"]) == expected
    assert scope.e2e_area(["api/hunt/run_router.py", "api/scan/jobs.py"]) == "all"
    assert scope.e2e_area(["api/hunt/run_router.py", "api/ai_gate/runner.py"]) == "all"
    assert scope.e2e_area(["api/hunt/run_router.py", "ui/src/lib/publicApi.generated.ts"]) == "all"


def test_unrelated_change_skips_smoke_work():
    assert scope.classify_paths(["docs/overview.md"]) == {
        "backend": False, "ui": False, "stack": False,
    }
    assert scope.python_mode(["docs/overview.md"]) == "skip"
    assert scope.python_mode(["docs/releases/2.6.0.md"]) == "full"
    assert scope.python_mode(["RELEASES.md", "install/STABLE_VERSION"]) == "full"


def test_cli_classifies_an_actual_commit_diff(tmp_path: Path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.email", "ci@example.test"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.name", "CI"], check=True)
    label = tmp_path / "ui" / "src" / "lib" / "labels.ts"
    label.parent.mkdir(parents=True)
    label.write_text("old\n")
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-qm", "base"], check=True)
    base = subprocess.check_output(["git", "-C", str(tmp_path), "rev-parse", "HEAD"], text=True).strip()
    label.write_text("new\n")
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-qam", "label"], check=True)
    head = subprocess.check_output(["git", "-C", str(tmp_path), "rev-parse", "HEAD"], text=True).strip()
    output = subprocess.check_output(
        [sys.executable, str(SCRIPT), "--base", base, "--head", head],
        cwd=tmp_path,
        text=True,
    )
    assert output.splitlines() == [
        "backend=false", "ui=true", "stack=false", "python_mode=ui", "e2e_area=all",
    ]


def test_cli_counts_the_old_path_when_runtime_code_is_moved(tmp_path: Path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.email", "ci@example.test"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.name", "CI"], check=True)
    original = tmp_path / "api" / "api.py"
    original.parent.mkdir(parents=True)
    original.write_text("x = 1\n")
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-qm", "base"], check=True)
    base = subprocess.check_output(["git", "-C", str(tmp_path), "rev-parse", "HEAD"], text=True).strip()
    moved = tmp_path / "docs" / "api.py"
    moved.parent.mkdir()
    original.rename(moved)
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-qm", "move"], check=True)
    head = subprocess.check_output(["git", "-C", str(tmp_path), "rev-parse", "HEAD"], text=True).strip()
    output = subprocess.check_output(
        [sys.executable, str(SCRIPT), "--base", base, "--head", head],
        cwd=tmp_path,
        text=True,
    )
    assert output.splitlines() == [
        "backend=true", "ui=true", "stack=true", "python_mode=full", "e2e_area=all",
    ]
