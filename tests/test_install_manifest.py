"""The hosted installer must refuse any runtime file that does not match the release manifest.

Images are digest-pinned and attested, but the host-side runtime (launcher, compose files, schema,
CLI modules, skills) was fetched file by file from a mutable git tag with nothing binding it to the
certified candidate. `install/MANIFEST.sha256` now lists every downloaded path, the installer verifies
each file against it, and the manifest's own digest is checked against the published image lock.
"""

from __future__ import annotations

import hashlib
import importlib.util
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "install" / "index.sh"
MANIFEST = ROOT / "install" / "MANIFEST.sha256"


def _generator():
    path = ROOT / "scripts" / "generate_install_manifest.py"
    spec = importlib.util.spec_from_file_location("install_manifest_under_test", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


generator = _generator()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_the_committed_manifest_is_current_and_lists_no_self_reference():
    assert MANIFEST.read_text(encoding="utf-8") == generator.render_manifest()
    assert "install/MANIFEST.sha256" not in MANIFEST.read_text(encoding="utf-8")


def test_manifest_expands_installer_loops_and_rejects_duplicates():
    source = (
        'download "$REPO_RAW_BASE/scanner.sh" "$INSTALL_DIR/scanner.sh"\n'
        "for item in \\\n    a.md \\\n    b.md; do\n"
        '    download "$REPO_RAW_BASE/skills/web/$item" "$INSTALL_DIR/skills/web/$item"\n'
        "done\n"
        "for binding in \\\n    X=1 \\\n    Y=2; do\n    key=1\ndone\n"
    )
    assert generator.installer_paths(source) == ["scanner.sh", "skills/web/a.md", "skills/web/b.md"]
    with pytest.raises(generator.ManifestError):
        generator.installer_paths(source + 'download "$REPO_RAW_BASE/scanner.sh" "$INSTALL_DIR/x"\n')


def _release_tree(tmp_path: Path) -> Path:
    """A file:// release tree holding exactly the files the installer downloads."""
    tree = tmp_path / "tree"
    for line in MANIFEST.read_text(encoding="utf-8").splitlines():
        relative = line.split("  ", 1)[1]
        target = tree / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, target)
    (tree / "install").mkdir(exist_ok=True)
    shutil.copy2(MANIFEST, tree / "install" / "MANIFEST.sha256")
    return tree


def _lock(tmp_path: Path, tree: Path, manifest_digest: str | None = None) -> Path:
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    assets = tmp_path / "assets" / f"v{version}"
    assets.mkdir(parents=True, exist_ok=True)
    digest = manifest_digest or _sha256(tree / "install" / "MANIFEST.sha256")
    (assets / "release-image-lock.env").write_text(
        "SCANNER_IMAGE=shakerscan/shakerscan-scanner@sha256:" + "1" * 64 + "\n"
        "API_IMAGE=shakerscan/shakerscan-api@sha256:" + "2" * 64 + "\n"
        "UI_IMAGE=shakerscan/shakerscan-ui@sha256:" + "3" * 64 + "\n"
        "SIGNER_IMAGE=shakerscan/shakerscan-model-intake-signer@sha256:" + "4" * 64 + "\n"
        "MODEL_INTAKE_IMAGE=shakerscan/shakerscan-model-intake@sha256:" + "5" * 64 + "\n"
        f"RUNTIME_MANIFEST_SHA256={digest}\n",
        encoding="utf-8",
    )
    return tmp_path / "assets"


def _install(tmp_path: Path, tree: Path, assets: Path) -> subprocess.CompletedProcess:
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    env = {
        **os.environ,
        "HOME": str(home),
        "SHAKERSCAN_HOME": str(home / ".shakerscan"),
        "SHAKERSCAN_BIN_DIR": str(home / ".local" / "bin"),
        "SHAKERSCAN_RAW_BASE": f"file://{tree}",
        "SHAKERSCAN_RELEASE_ASSET_ROOT": f"file://{assets}",
        "SHAKERSCAN_START": "0",
        "SHAKERSCAN_DISABLE_IMAGE_LOCK": "1",
        "SHELL": "/bin/bash",
    }
    return subprocess.run(
        ["sh", str(INSTALLER)], env=env, capture_output=True, text=True, cwd=tmp_path,
    )


def test_a_matching_tree_installs_and_keeps_the_manifest(tmp_path):
    tree = _release_tree(tmp_path)
    run = _install(tmp_path, tree, _lock(tmp_path, tree))
    assert run.returncode == 0, run.stdout + run.stderr
    installed = tmp_path / "home" / ".shakerscan"
    assert (installed / ".shakerscan-runtime-manifest.sha256").read_text() == MANIFEST.read_text()
    assert (installed / "scanner.sh").exists()


def test_a_tampered_runtime_file_is_refused_before_activation(tmp_path):
    tree = _release_tree(tmp_path)
    assets = _lock(tmp_path, tree)
    launcher = tree / "scanner.sh"
    launcher.write_text(launcher.read_text(encoding="utf-8") + "\n# tampered\n", encoding="utf-8")
    run = _install(tmp_path, tree, assets)
    assert run.returncode != 0
    assert "scanner.sh does not match the release manifest" in run.stderr
    assert not (tmp_path / "home" / ".shakerscan" / "scanner.sh").exists(), (
        "a failed verification must not activate a partial tree"
    )


def test_a_manifest_that_does_not_match_the_published_lock_is_refused(tmp_path):
    tree = _release_tree(tmp_path)
    assets = _lock(tmp_path, tree, manifest_digest="f" * 64)
    run = _install(tmp_path, tree, assets)
    assert run.returncode != 0
    assert "release manifest does not match the digest published" in run.stderr


def test_a_lock_without_the_manifest_digest_is_refused(tmp_path):
    tree = _release_tree(tmp_path)
    assets = _lock(tmp_path, tree)
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    lock = assets / f"v{version}" / "release-image-lock.env"
    lock.write_text(
        "".join(line for line in lock.read_text().splitlines(True) if "RUNTIME_MANIFEST" not in line)
    )
    run = _install(tmp_path, tree, assets)
    assert run.returncode != 0
    assert "does not record the runtime manifest digest" in run.stderr


def test_the_generator_check_mode_fails_on_a_stale_manifest(tmp_path, monkeypatch):
    stale = tmp_path / "MANIFEST.sha256"
    stale.write_text("0" * 64 + "  scanner.sh\n", encoding="utf-8")
    monkeypatch.setattr(generator, "MANIFEST", stale)
    assert generator.main(["--check"]) == 1
    generator.main([])
    assert stale.read_text(encoding="utf-8") == generator.render_manifest()
    assert generator.main(["--check"]) == 0
