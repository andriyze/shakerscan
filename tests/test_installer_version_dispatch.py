"""A hosted installer must not install one revision's manifest from another revision's tag.

`install/index.sh` carries the file manifest of the revision it ships with, and it also resolves
the stable channel. Served directly -- the documented static deployment path -- it therefore
resolved `STABLE_VERSION`, pointed itself at that older tag, and then requested its own newer
manifest from it. Files that exist only in the newer tree 404, and the count grows with every file
added to the manifest.

`install/bootstrap.sh` already does the right thing: resolve, then run *that tag's* installer.
`index.sh` now performs the same handover, so the manifest and the tree always come from one
revision.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "install" / "index.sh"
HOSTED = ROOT / "install" / "index.html"


def _source() -> str:
    return INSTALLER.read_text(encoding="utf-8")


def test_the_installer_is_valid_posix_shell():
    subprocess.run(["sh", "-n", str(INSTALLER)], check=True)


def test_channel_resolution_hands_over_to_that_versions_installer():
    source = _source()
    resolve = source.index('stable_raw="$(curl -fsSL "$CHANNEL_RAW_BASE/install/STABLE_VERSION")"')
    handover = source.index('curl -fsSL "$REPO_RAW_BASE/install/index.sh"')
    assert resolve < handover, "the handover must follow channel resolution"
    assert 'sh "$delegate" "$@"' in source
    assert 'exit "$delegate_status"' in source, (
        "the delegated installer's exit status must be the installer's own"
    )


def test_an_explicit_raw_base_still_installs_directly():
    # SHAKERSCAN_RAW_BASE is both the development escape hatch and the recursion guard: the
    # delegated installer sees it set and installs rather than resolving again.
    source = _source()
    guard = source.index('if [ -z "$REPO_RAW_BASE" ]; then')
    handover = source.index('curl -fsSL "$REPO_RAW_BASE/install/index.sh"')
    assert guard < handover, "the handover must sit inside the unresolved-base branch"
    assert 'REPO_RAW_BASE="${SHAKERSCAN_RAW_BASE:-}"' in source


def test_an_explicit_install_version_does_not_delegate():
    # A pinned version already names its tag; its own manifest is the one being asked for.
    source = _source()
    pinned = source.index('if [ -n "$INSTALL_VERSION" ]; then')
    handover = source.index('curl -fsSL "$REPO_RAW_BASE/install/index.sh"')
    else_branch = source.index("    else\n", pinned)
    assert pinned < else_branch < handover


def test_the_temporary_installer_is_removed_on_both_paths():
    source = _source()
    assert source.count('rm -f -- "$delegate"') >= 2, (
        "the downloaded installer must be removed whether the download fails or the run completes"
    )


def test_the_hosted_copy_is_byte_identical():
    # index.html is served as the static payload; a drifted copy silently serves old behaviour.
    assert HOSTED.read_text(encoding="utf-8") == _source()


def test_the_manifest_and_the_dispatch_cannot_disagree_about_the_base():
    # Every download line resolves against REPO_RAW_BASE, so once the handover has run the child
    # installs entirely from the tag it was fetched from.
    source = _source()
    downloads = re.findall(r'download "([^"]+)"', source)
    assert downloads, "the installer must still carry a manifest"
    # The image lock is a published release asset rather than a source file, so it resolves against
    # its own root; every source path must follow the base the handover established.
    source_paths = [item for item in downloads if not item.startswith("$RELEASE_ASSET_ROOT/")]
    assert len(source_paths) > 50, "the source manifest should be the bulk of the downloads"
    assert all(item.startswith("$REPO_RAW_BASE/") for item in source_paths)


# --- Behavioural checks -----------------------------------------------------------------------
# The assertions above read the script. These run it, with only its two network reads redirected to
# local files, so the handover is proven rather than inferred.

def _runnable_installer(tmp_path: Path) -> tuple[Path, Path]:
    channel = tmp_path / "STABLE_VERSION"
    channel.write_text("0.8.18\n", encoding="utf-8")
    probe = tmp_path / "handover_probe.sh"
    probe.write_text(
        "#!/bin/sh\n"
        "echo DELEGATED\n"
        'echo "base=${SHAKERSCAN_RAW_BASE:-unset}"\n'
        'echo "version=${SHAKERSCAN_INSTALL_VERSION:-unset}"\n'
        'echo "args=$*"\n'
        "exit 7\n",
        encoding="utf-8",
    )
    probe.chmod(0o755)
    source = INSTALLER.read_text(encoding="utf-8")
    source = source.replace(
        'curl -fsSL "$CHANNEL_RAW_BASE/install/STABLE_VERSION"', f"cat {channel}", 1)
    source = source.replace(
        'curl -fsSL "$REPO_RAW_BASE/install/index.sh" -o "$delegate"',
        f'cp {probe} "$delegate"', 1)
    script = tmp_path / "index_under_test.sh"
    script.write_text(source, encoding="utf-8")
    return script, probe


def test_resolving_the_channel_runs_that_tags_installer(tmp_path):
    script, _ = _runnable_installer(tmp_path)
    run = subprocess.run(["sh", str(script), "--flag"], capture_output=True, text=True)
    assert "DELEGATED" in run.stdout, run.stdout + run.stderr
    # The tag it resolved, passed as the recursion guard so the child installs instead of resolving.
    assert "base=https://raw.githubusercontent.com/andriyze/shakerscan/v0.8.18" in run.stdout
    assert "version=0.8.18" in run.stdout
    assert "args=--flag" in run.stdout, "arguments must reach the delegated installer"
    # A failure inside the real installer must not be reported as success by the dispatcher.
    assert run.returncode == 7


def test_an_explicit_base_installs_without_delegating(tmp_path):
    script, _ = _runnable_installer(tmp_path)
    run = subprocess.run(
        ["sh", str(script)], capture_output=True, text=True,
        env={"PATH": "/usr/bin:/bin", "HOME": str(tmp_path),
             "SHAKERSCAN_RAW_BASE": "https://example.invalid/base"},
    )
    assert "DELEGATED" not in run.stdout
    assert "Source:            https://example.invalid/base" in run.stdout
