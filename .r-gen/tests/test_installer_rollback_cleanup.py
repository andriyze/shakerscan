"""Exercise the real cleanup shell function with a restricted Docker stand-in."""
from pathlib import Path
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _cleanup_function():
    text = (ROOT / "install/index.sh").read_text()
    return text[text.index("cleanup_activated_rollback() {"):text.index("commit_staged_downloads() {")]


def _run(tmp_path, *, image=True, docker_ok=True, symlink=False):
    script = tmp_path / "cleanup.sh"
    script.write_text('''#!/bin/sh
set -eu
cd "$1"
INSTALL_DIR="$PWD/install"
INSTALL_BACKUP="$INSTALL_DIR.shakerscan-rollback.$$"
mkdir "$INSTALL_DIR" outside
printf 'keep' > "$INSTALL_DIR/active-data"
printf 'keep' > outside/sentinel
''' + ('ln -s "$PWD/outside" "$INSTALL_BACKUP"\n' if symlink else '''mkdir -p "$INSTALL_BACKUP/results"
printf old > "$INSTALL_BACKUP/results/result.json"
ln -s "$PWD/outside" "$INSTALL_BACKUP/external-link"
''') + ('''printf 'API_IMAGE=shakerscan/shakerscan-api@sha256:%s\\n' aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa > "$INSTALL_DIR/release-image-lock.env"
''' if image else '') + '''# Simulate the unprivileged removal failing on container-owned directories.
rm() { return 1; }
docker() {
    printf '%s\\n' "$*" >> docker.calls
    case "$1" in
        image) return 0 ;;
        run)
''' + ('            return 1\n' if not docker_ok else '''            # Model only the requested find -xdev operation. The mount root is
            # the obsolete sibling, never the active install or a symlink target.
            find "$INSTALL_BACKUP" -xdev -depth -mindepth 1 -delete
''') + '''            ;;
        *) return 1 ;;
    esac
}
''' + _cleanup_function() + '''
cleanup_activated_rollback
[ -f "$INSTALL_DIR/active-data" ]
[ -f outside/sentinel ]
if [ -e "$INSTALL_BACKUP" ]; then printf 'remaining\\n'; fi
''')
    result = subprocess.run(["sh", str(script), str(tmp_path)], text=True, capture_output=True)
    assert result.returncode == 0, result.stderr
    return result, (tmp_path / "docker.calls").read_text() if (tmp_path / "docker.calls").exists() else ""


def test_root_owned_backup_uses_only_a_pinned_local_image_and_restricted_mount(tmp_path):
    result, calls = _run(tmp_path)
    assert "remaining" not in result.stdout
    run = next(line for line in calls.splitlines() if line.startswith("run "))
    assert "--pull=never" in run and "--network none" in run
    assert "--read-only" in run and "--cap-drop ALL" in run
    assert "--cap-add DAC_OVERRIDE" in run and "--security-opt no-new-privileges" in run
    assert "shakerscan-rollback." in run and ",dst=/rollback" in run
    assert "@sha256:" in run
    assert "/var/run/docker.sock" not in run
    assert "find /rollback -xdev -depth -mindepth 1 -delete" in run
    assert not result.stderr


@pytest.mark.parametrize(("image", "docker_ok"), [(False, True), (True, False)])
def test_failed_optional_cleanup_preserves_backup_and_successful_install(tmp_path, image, docker_ok):
    result, calls = _run(tmp_path, image=image, docker_ok=docker_ok)
    assert "remaining" in result.stdout
    assert result.stderr.count("Warning:") == 1
    assert "rollback files remain at" in result.stderr
    if not image:
        assert "run " not in calls


def test_cleanup_refuses_a_symlink_backup_without_launching_a_container(tmp_path):
    result, calls = _run(tmp_path, symlink=True)
    assert "remaining" in result.stdout
    assert calls == ""
