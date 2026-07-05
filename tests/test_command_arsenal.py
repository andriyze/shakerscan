import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))

import command_arsenal as arsenal  # noqa: E402


def test_command_catalog_is_read_only_by_default():
    payload = arsenal.describe_commands()

    assert payload["schema_version"] == arsenal.ARSENAL_SCHEMA_VERSION
    assert payload["maturity"] == "read_only"
    assert payload["execution_enabled"] is False
    assert "read_only" in payload["status_labels"]
    assert "dangerous" in payload["risk_tiers"]
    assert payload["result_schema"]["dry_run"] == "boolean"


def test_command_catalog_contains_required_initial_commands():
    payload = arsenal.describe_commands()
    commands = {item["name"]: item for item in payload["commands"]}

    for name in (
        "target.list",
        "target.get",
        "asm.gaps",
        "asm.activity",
        "scan.result",
        "finding.list",
        "finding.get",
        "ai_target.list",
        "model_intake.trust_preview",
        "evidence.get",
        "deployment.decision",
        "tool.status",
    ):
        assert name in commands
        assert commands[name]["status"] == "read_only"
        assert commands[name]["risk_tier"] == "read_only"


def test_state_changing_commands_are_gated_not_executable_shortcuts():
    payload = arsenal.describe_commands()
    commands = {item["name"]: item for item in payload["commands"]}

    for name in ("asm.improve", "scan.focused_family", "finding.retest", "ai_gate.replay_probe", "model_intake.scan"):
        cmd = commands[name]
        assert cmd["status"] == "gated"
        assert "confirm_authorized" in cmd["required_confirmations"]
        assert cmd["scope_fields"]
        assert cmd["evidence_contract"]
        assert "execute_shell" not in cmd["name"]


def test_tool_status_catalog_is_honest_without_version_probe(monkeypatch):
    monkeypatch.setattr(arsenal.shutil, "which", lambda _name: None)
    monkeypatch.setattr(arsenal.os.path, "exists", lambda _path: False)
    monkeypatch.setattr(arsenal.os, "access", lambda *_args: False)

    payload = arsenal.describe_tools(probe_versions=False)
    tools = {item["tool_name"]: item for item in payload["tools"]}

    assert payload["maturity"] == "read_only"
    assert payload["probe_versions"] is False
    assert tools["nuclei"]["status"] == "wired"
    assert tools["sqlmap"]["status"] == "wired"
    assert tools["sqlmap"]["expected_status"] == "gated"
    assert tools["ai_gate_probe_executor"]["status"] == "runnable"
    assert tools["model_intake_signature_verifier"]["version"] == "internal"
    assert "runnable" in payload["status_labels"]


def test_tool_status_can_probe_installed_version(monkeypatch):
    monkeypatch.setattr(arsenal.shutil, "which", lambda name: f"/usr/bin/{name}" if name == "nuclei" else None)
    monkeypatch.setattr(arsenal.os.path, "exists", lambda _path: False)
    monkeypatch.setattr(arsenal.os, "access", lambda *_args: False)
    monkeypatch.setattr(arsenal, "_probe_version", lambda *_args, **_kwargs: ("nuclei v3.0.0", None))

    payload = arsenal.describe_tools(probe_versions=True)
    tools = {item["tool_name"]: item for item in payload["tools"]}

    assert tools["nuclei"]["status"] == "runnable"
    assert tools["nuclei"]["binary_path"] == "/usr/bin/nuclei"
    assert tools["nuclei"]["version"] == "nuclei v3.0.0"
