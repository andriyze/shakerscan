import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import release_gates  # noqa: E402


EXPECTED_GATES = {
    "test:no-phantom-tools",
    "test:no-benchmark-fitting",
    "test:no-ai-verified",
    "test:evidence-provenance",
    "test:fleet-current",
    "test:planner-scope",
    "test:planner-risk",
    "test:planner-no-shell",
}


def test_release_gate_names_match_roadmap_contract():
    assert set(release_gates.GATES) == EXPECTED_GATES


def test_release_gate_mapping_points_at_existing_tests():
    assert release_gates.validate_gate_mapping() == []
    assert all(release_gates.GATES[name] for name in EXPECTED_GATES)


def test_release_gate_selector_resolution_is_ordered_and_rejects_unknown():
    selectors = release_gates.selectors_for(["test:planner-no-shell", "test:no-phantom-tools"])

    assert selectors[0].startswith("tests/test_command_arsenal.py")
    assert any("test_tool_status_release_gate_blocks_phantom_runnable_adapter" in item for item in selectors)

    try:
        release_gates.selectors_for(["test:not-real"])
    except ValueError as exc:
        assert "unknown release gate" in str(exc)
    else:
        raise AssertionError("unknown gate should raise")
