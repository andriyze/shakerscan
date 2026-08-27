"""An upgrade must remove the files the new version no longer ships.

Installation was committed with an overlaying `cp -R`, so a file that an older release installed
stayed on disk forever. A reproduced 0.8.18 -> V2 upgrade kept retired legacy command files, which
then looked installed and supported. The installer now records the files it owns and removes the
ones a later version dropped -- and only those, so operator data living in the same tree (results,
.env, backups) is never touched.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "install" / "index.sh"


def _harness(tmp_path: Path, ships: list[str]) -> Path:
    """Run only the installer's staging/commit/prune functions against a local tree."""
    source = INSTALLER.read_text(encoding="utf-8")
    functions = []
    for name in ("download", "cleanup_install_stage", "prune_retired_files",
                 "commit_staged_downloads"):
        start = source.index(f"{name}() {{")
        depth, index = 0, start
        while True:
            if source[index] == "{":
                depth += 1
            elif source[index] == "}":
                depth -= 1
                if depth == 0:
                    break
            index += 1
        functions.append(source[start:index + 1])

    downloads = "\n".join(
        f'download "src/{item}" "$INSTALL_DIR/{item}"' for item in ships
    )
    script = tmp_path / "harness.sh"
    script.write_text(
        "#!/bin/sh\nset -eu\n"
        f'INSTALL_DIR="{tmp_path}/install"\n'
        f'INSTALL_STAGE="{tmp_path}/stage"\n'
        'OWNED_MANIFEST_NAME=".shakerscan-installed-files"\n'
        'fail() { printf "Error: %s\\n" "$*" >&2; exit 1; }\n'
        # Stand in for the network: every "download" writes a marker file.
        'curl() { for arg in "$@"; do case "$prev" in -o) printf "content\\n" > "$arg";; esac; '
        'prev="$arg"; done; }\nprev=""\n'
        + "\n".join(functions) + "\n"
        'mkdir -p "$INSTALL_DIR" "$INSTALL_STAGE"\n'
        + downloads + "\n"
        "commit_staged_downloads\n",
        encoding="utf-8",
    )
    return script


def _install(tmp_path: Path, ships: list[str]):
    script = _harness(tmp_path, ships)
    run = subprocess.run(["sh", str(script)], capture_output=True, text=True)
    assert run.returncode == 0, run.stdout + run.stderr
    return tmp_path / "install"


def test_an_upgrade_removes_a_file_the_new_version_stopped_shipping(tmp_path):
    install = _install(tmp_path, ["api/kept.py", "api/retired.py"])
    assert (install / "api" / "retired.py").exists()

    # The next release drops api/retired.py.
    (tmp_path / "stage").mkdir(exist_ok=True)
    _install(tmp_path, ["api/kept.py"])
    assert (install / "api" / "kept.py").exists()
    assert not (install / "api" / "retired.py").exists(), (
        "a file the new version no longer ships must not survive the upgrade"
    )


def test_operator_data_in_the_same_tree_is_never_removed(tmp_path):
    install = _install(tmp_path, ["api/kept.py"])
    (install / "results").mkdir(exist_ok=True)
    (install / "results" / "scan.json").write_text("{}", encoding="utf-8")
    (install / ".env").write_text("SECRET=1", encoding="utf-8")

    _install(tmp_path, ["api/kept.py"])
    assert (install / "results" / "scan.json").exists(), "installer must not touch operator data"
    assert (install / ".env").read_text(encoding="utf-8") == "SECRET=1"


def test_a_first_install_prunes_nothing(tmp_path):
    install = _install(tmp_path, ["api/kept.py"])
    assert (install / "api" / "kept.py").exists()
    assert (install / ".shakerscan-installed-files").exists()


def test_a_manifest_entry_cannot_escape_the_installation_directory(tmp_path):
    _install(tmp_path, ["api/kept.py"])
    outside = tmp_path / "outside.txt"
    outside.write_text("do not delete", encoding="utf-8")
    # A previous manifest is data on disk; a hostile or corrupted one must not delete elsewhere.
    manifest = tmp_path / "install" / ".shakerscan-installed-files"
    manifest.write_text(
        f"api/kept.py\n../outside.txt\n/etc/passwd\n", encoding="utf-8")

    _install(tmp_path, ["api/kept.py"])
    assert outside.exists(), "a relative escape in the manifest must be refused"
    assert Path("/etc/passwd").exists()
