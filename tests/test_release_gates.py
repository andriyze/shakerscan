import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import release_gates  # noqa: E402


EXPECTED_GATES = {
    "test:no-phantom-tools",
    "test:no-benchmark-fitting",
    "test:no-ai-verified",
    "test:mcp-read-only",
    "test:hypothesis-proof-promotion",
    "test:evidence-provenance",
    "test:fleet-current",
    "test:planner-scope",
    "test:planner-risk",
    "test:planner-no-shell",
    "test:scanner-proof-truth",
    "test:scanner-registry-coverage",
    "test:scanner-bounds",
    "test:scanner-auth-quality",
    "test:v2-fault-injection",
    "test:v2-security-invariants",
    "test:v2-detection-parity",
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


def test_release_gate_runner_loads_canonical_api_packages(monkeypatch):
    calls = []

    def fake_call(command, *, cwd, env):
        calls.append((command, cwd, env))
        return 0

    monkeypatch.setattr(release_gates.subprocess, "call", fake_call)

    assert release_gates.run_gates(["test:v2-fault-injection"]) == 0
    assert len(calls) == 1
    command, cwd, env = calls[0]
    assert command[:4] == [sys.executable, "-m", "pytest", "-q"]
    assert cwd == release_gates.REPO_ROOT
    assert env["PYTHONPATH"].split(release_gates.os.pathsep)[0] == str(release_gates.REPO_ROOT / "api")
