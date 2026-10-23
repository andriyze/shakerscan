"""The public coverage documents name exactly the families a Scan runs.

The functionality reference once listed nine Scan families while the engine had eleven, and the
OWASP coverage matrix marked SSRF as covered although a Scan refuses the `ssrf` family. These
tests tie both documents to `SCAN_V2_FAMILY_NAMES` and to the families a Scan refuses.
"""

from __future__ import annotations

import os
from pathlib import Path
import re
import sys

import pytest


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

from check_registry import CHECK_REGISTRY  # noqa: E402
from scan.contracts import SCAN_V2_FAMILY_NAMES, resolve_scan_contract  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]
REFERENCE = ROOT / "docs" / "functionality-reference.md"
MATRIX = ROOT / "docs" / "owasp-coverage-matrix.md"
PLANNED_FAMILIES = ("ssrf", "lfi", "rce", "business_logic")
NUMBER_WORDS = {
    9: "nine", 10: "ten", 11: "eleven", 12: "twelve", 13: "thirteen", 14: "fourteen",
    15: "fifteen", 16: "sixteen",
}
NOT_SCAN_FAMILIES = sorted(
    {spec.name for spec in CHECK_REGISTRY} - set(SCAN_V2_FAMILY_NAMES)
)


def _flat(path: Path) -> str:
    return " ".join(path.read_text(encoding="utf-8").split())


def _names(snippet: str) -> list[str]:
    return sorted(re.findall(r"`([a-z_]+)`", snippet))


def _match(pattern: str, text: str) -> re.Match[str]:
    match = re.search(pattern, text)
    assert match is not None, f"documentation no longer contains: {pattern}"
    return match


def test_every_planned_family_is_still_registered_and_not_a_scan_family():
    assert set(PLANNED_FAMILIES) <= set(NOT_SCAN_FAMILIES)
    assert len(SCAN_V2_FAMILY_NAMES) in NUMBER_WORDS


@pytest.mark.parametrize("family", (*PLANNED_FAMILIES, "command_injection"))
def test_a_scan_refuses_each_planned_family_by_name(family):
    with pytest.raises(ValueError, match="not implemented by canonical Scan"):
        resolve_scan_contract(policy={"active_testing": True, "include_families": [family]})


@pytest.mark.parametrize("family", NOT_SCAN_FAMILIES)
def test_a_scan_refuses_every_registered_family_outside_the_scan_families(family):
    with pytest.raises(ValueError, match="not implemented by canonical Scan"):
        resolve_scan_contract(policy={"active_testing": True, "include_families": [family]})


def test_reference_names_exactly_the_scan_families():
    text = _flat(REFERENCE)
    count = NUMBER_WORDS[len(SCAN_V2_FAMILY_NAMES)]
    compiler = _match(
        r"The canonical action compiler implements (\w+) families: (.*?)\(`SCAN_V2_FAMILY_NAMES`",
        text,
    )
    assert compiler.group(1) == count
    assert _names(compiler.group(2)) == sorted(SCAN_V2_FAMILY_NAMES)
    presets = _match(r"The canonical Scan families are (.*?)\(`api/scan/contracts\.py`\)", text)
    assert _names(presets.group(1)) == sorted(SCAN_V2_FAMILY_NAMES)
    assert f"a registry family outside the {count} is refused" in text
    assert f"A Scan runs its {count} families" in text


def test_matrix_names_exactly_the_scan_families_and_the_refused_ones():
    text = _flat(MATRIX)
    counted = _match(r"- the (\w+) Scan families: (.*?);", text)
    assert counted.group(1) == NUMBER_WORDS[len(SCAN_V2_FAMILY_NAMES)]
    assert _names(counted.group(2)) == sorted(SCAN_V2_FAMILY_NAMES)
    refused = _match(r"- registered families that are not Scan families\. (.*?);", text)
    named = set(_names(refused.group(1))) - {"command_injection"}
    assert named == set(NOT_SCAN_FAMILIES)


def _matrix_status(row_id: str) -> str:
    for line in MATRIX.read_text(encoding="utf-8").splitlines():
        cells = [cell.strip() for cell in line.split("|")]
        if len(cells) > 3 and cells[1] == row_id:
            return cells[3]
    raise AssertionError(f"matrix row {row_id} is missing")


@pytest.mark.parametrize(
    ("family", "rows"),
    (("ssrf", ("A10", "API7")), ("business_logic", ("A04", "API6"))),
)
def test_matrix_does_not_mark_a_category_covered_by_a_refused_family(family, rows):
    assert family not in SCAN_V2_FAMILY_NAMES, (
        f"{family} is now a Scan family: re-check matrix rows {rows} and update this test"
    )
    for row in rows:
        assert _matrix_status(row) == "❌", row
