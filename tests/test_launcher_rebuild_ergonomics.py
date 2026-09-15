"""scanner.sh rebuild: scope inference, image change summary and the extended receipt.

The helpers are extracted from the launcher and executed in bash, the way the runtime
hardening tests already exercise the storage admission, so the contract is behavioral.
"""
from __future__ import annotations

import json
import shlex
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (ROOT / "scanner.sh").read_text()


def _slice(start_marker: str, end_marker: str) -> str:
    start = SCRIPT.index(start_marker)
    end = SCRIPT.index(end_marker, start)
    return SCRIPT[start:end]


SCOPE_HELPERS = _slice("rebuild_scope_for_paths() {", "\nrebuild_changed_paths() {")
IMAGE_HELPERS = _slice("rebuild_image_tags() {", "\nprint_build_summary() {")


def _bash(script: str, stdin: str = "") -> subprocess.CompletedProcess:
    return subprocess.run(["bash", "-c", script], input=stdin, text=True, capture_output=True, check=False)


def _scope(paths: list[str]) -> str:
    result = _bash(SCOPE_HELPERS + "\nrebuild_scope_for_paths", "\n".join(paths) + "\n")
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


def test_scope_is_the_smallest_family_that_covers_the_change():
    assert _scope(["ui/src/app/page.tsx", "ui/public/logo.png"]) == "ui"
    assert _scope(["api/worker.py"]) == "scanner"
    assert _scope(["scanner/Dockerfile", "scanner/scanner_tools/discovery.py"]) == "scanner"
    assert _scope(["api/worker.py", "ui/src/lib/api.ts"]) == "all"
    assert _scope(["api/model_intake_signer.Dockerfile"]) == "all", "the signer image is outside the scanner family"
    assert _scope(["scanner.sh"]) == "all"
    assert _scope(["docker-compose.yml"]) == "all"
    assert _scope(["install/MANIFEST.sha256"]) == "all"


def test_paths_that_reach_no_image_need_no_rebuild():
    assert _scope(["docs/releases/2.3.2.md", "README.md", "tests/test_x.py", ".github/workflows/ci.yml"]) == "none"
    assert _scope([]) == "none"
    assert _scope(["docs/a.md", "ui/src/x.ts"]) == "ui", "documentation never widens the scope"


def test_image_snapshot_diff_names_what_was_rebuilt():
    before = "shakerscan-worker:local=sha256:aaaaaaaaaaa\nshakerscan-api=sha256:bbbbbbbbbbb\nshakerscan-ui=\n"
    after = "shakerscan-worker:local=sha256:aaaaaaaaaaa\nshakerscan-api=sha256:ccccccccccc\nshakerscan-ui=sha256:ddddddddddd\nshakerscan-model-intake-signer=\n"
    script = IMAGE_HELPERS + f"\ndiff_image_snapshots {shlex.quote(before)} {shlex.quote(after)}"
    result = _bash(script)
    assert result.returncode == 0, result.stderr
    rows = {line.split()[0]: line.split()[3] for line in result.stdout.strip().splitlines()}
    assert rows == {
        "shakerscan-worker:local": "unchanged",
        "shakerscan-api": "rebuilt",
        "shakerscan-ui": "new",
        "shakerscan-model-intake-signer": "missing",
    }


def test_receipt_carries_steps_images_dirty_paths_and_smoke(tmp_path):
    start = SCRIPT.index("docker_storage_free_kb() {")
    end = SCRIPT.index("\nbuild_local_scanner_family() {", start)
    helpers = SCRIPT[start:end]
    receipt = tmp_path / "build-receipt.json"
    harness = f"""
set +e
RED=''; BLUE=''; YELLOW=''; GREEN=''; NC=''
GIT_COMMIT=test-revision
BUILD_RECEIPT_FILE={shlex.quote(str(receipt))}
BUILD_RECEIPT_ACTIVE=0
BUILD_RECEIPT_OPERATION=''
BUILD_RECEIPT_PHASE=not_started
BUILD_RECEIPT_STARTED_AT=''
docker() {{ return 1; }}
git() {{ if [ "$1" = status ]; then printf 'M  api/worker.py\\n?? ui/public/logo.png\\n'; fi; return 0; }}
{helpers}
begin_build_receipt rebuild scanner
BUILD_STEP_TIMINGS="scanner_runtime=12 api_overlay=3 "
BUILD_IMAGE_RESULTS="shakerscan-worker:local sha256:aaa sha256:bbb rebuilt
shakerscan-api - sha256:ccc new"
BUILD_SMOKE_RESULT=passed
write_build_receipt completed 0
"""
    result = _bash(harness)
    assert result.returncode == 0, result.stderr
    payload = json.loads(receipt.read_text())
    assert payload["schema_version"] == "shakerscan-build-receipt/v1"
    assert payload["scope"] == "scanner" and payload["status"] == "completed"
    assert payload["steps"] == [{"phase": "scanner_runtime", "seconds": 12}, {"phase": "api_overlay", "seconds": 3}]
    assert payload["images"] == [
        {"tag": "shakerscan-worker:local", "before": "sha256:aaa", "after": "sha256:bbb", "result": "rebuilt"},
        {"tag": "shakerscan-api", "before": None, "after": "sha256:ccc", "result": "new"},
    ]
    assert payload["dirty_paths"] == ["api/worker.py", "ui/public/logo.png"]
    assert payload["smoke"] == "passed"


def test_launcher_documents_the_new_rebuild_options():
    assert "--no-smoke  Skip the post-rebuild execution smoke" in SCRIPT
    assert "auto        Smallest scope covering changes since the last build (default)" in SCRIPT
    assert "post_rebuild_smoke || { fail_build 1" in SCRIPT, "a failed smoke fails the rebuild"
