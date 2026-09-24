"""The frozen-source installer must download every agent command and agent the repository ships.

The list in install/index.sh is hand-maintained; a command added under .claude/ without an
installer line only fails in the release certify installer smoke, hours after the PR merged.
"""
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
INSTALLER_COPIES = ("install/index.sh", "install/index.html")


def installer_downloads(copy: str) -> set[str]:
    text = (ROOT / copy).read_text()
    return set(re.findall(r'download "\$REPO_RAW_BASE/(\.claude/[^"]+)"', text))


@pytest.mark.parametrize("copy", INSTALLER_COPIES)
@pytest.mark.parametrize("subdir", ["commands", "agents"])
def test_installer_downloads_every_shipped_claude_asset(copy, subdir):
    shipped = {str(p.relative_to(ROOT)) for p in (ROOT / ".claude" / subdir).glob("*.md")}
    assert shipped, f"no {subdir} found"
    missing = shipped - installer_downloads(copy)
    assert not missing, f"{copy} does not download: {sorted(missing)}"


def test_installer_copies_are_identical():
    assert (ROOT / INSTALLER_COPIES[0]).read_bytes() == (ROOT / INSTALLER_COPIES[1]).read_bytes()
