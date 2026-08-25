from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REFERENCE = ROOT / "docs" / "functionality-reference.md"


def _canonical_scan_sections() -> str:
    text = REFERENCE.read_text(encoding="utf-8")
    start = text.index("## 2. System architecture")
    end = text.index("## 10. Attack-surface management")
    canonical = text[start:end]
    return " ".join(canonical.split())


def test_canonical_architecture_sections_do_not_advertise_legacy_scan_engines():
    canonical = _canonical_scan_sections().lower()
    forbidden = (
        "scan type controls",
        "smart scan",
        "full scan",
        "aggressive scan",
        "smart engine",
        "smart orchestrator",
        "monolithic scanner is canonical",
    )
    assert [phrase for phrase in forbidden if phrase in canonical] == []
    assert "exactly one deterministic engine" in canonical
    assert "scan-action-plan/v1" in canonical
    assert "two-phase continuation" in canonical
    assert "local, broker, and parallel execution" in canonical
    assert "scan.finalize" in canonical


def test_public_scan_commands_are_v2_and_secret_free():
    command = (ROOT / ".claude" / "commands" / "scan.md").read_text(encoding="utf-8")
    skill = (ROOT / "skills" / "shakerscan" / "SKILL.md").read_text(encoding="utf-8")
    combined = command + skill
    assert '"scan_type"' not in combined
    assert '"budget_profile"' in command
    assert '"policy"' in command
    assert "raw credentials" in command.lower()
    assert "auth_header" not in combined
    assert "auth_cookies" not in combined


def test_legacy_slash_commands_are_removed():
    for name in ("scan-full.md", "scan-smart.md"):
        assert not (ROOT / ".claude" / "commands" / name).exists()


def test_inventory_separates_canonical_and_internal_surfaces():
    text = REFERENCE.read_text(encoding="utf-8")
    assert "Canonical `scanner.sh` commands" in text
    assert "Deprecated compatibility aliases" not in text
    assert "### Internal Compatibility Scanner Flags" in text
    assert "### Internal Compatibility Scanner Module Inventory" in text
    assert "Deprecated Scan-name shims" not in text
