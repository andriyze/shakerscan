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
        "operation_plan.list",
        "agent_context_pack.list",
        "agent_decision_trace.list",
        "local_agent.list",
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

    for name in (
        "asm.improve",
        "scan.focused_family",
        "finding.retest",
        "ai_gate.replay_probe",
        "model_intake.scan",
        "approval.record",
    ):
        cmd = commands[name]
        assert cmd["status"] == "gated"
        assert "confirm_authorized" in cmd["required_confirmations"]
        assert cmd["scope_fields"]
        assert cmd["evidence_contract"]
        assert "execute_shell" not in cmd["name"]


def test_scope_preview_is_dry_run_not_execution():
    payload = arsenal.describe_commands()
    commands = {item["name"]: item for item in payload["commands"]}

    cmd = commands["scope.preview"]
    assert cmd["status"] == "dry_run"
    assert cmd["risk_tier"] == "read_only"
    assert cmd["path"] == "/arsenal/scope/preview"
    assert "scope_receipt" in cmd["evidence_contract"]


def test_operation_plan_preview_is_dry_run_not_execution():
    payload = arsenal.describe_commands()
    commands = {item["name"]: item for item in payload["commands"]}

    cmd = commands["operation_plan.preview"]
    assert cmd["status"] == "dry_run"
    assert cmd["risk_tier"] == "read_only"
    assert cmd["path"] == "/arsenal/plans"
    assert "operation_plan" in cmd["evidence_contract"]


def test_agent_context_pack_record_is_dry_run_not_execution():
    payload = arsenal.describe_commands()
    commands = {item["name"]: item for item in payload["commands"]}

    cmd = commands["agent_context_pack.record"]
    assert cmd["status"] == "dry_run"
    assert cmd["risk_tier"] == "read_only"
    assert cmd["path"] == "/arsenal/context-packs"
    assert "context_pack" in cmd["evidence_contract"]


def test_agent_decision_trace_record_is_dry_run_not_execution():
    payload = arsenal.describe_commands()
    commands = {item["name"]: item for item in payload["commands"]}

    cmd = commands["agent_decision_trace.record"]
    assert cmd["status"] == "dry_run"
    assert cmd["risk_tier"] == "read_only"
    assert cmd["path"] == "/arsenal/decision-traces"
    assert "decision_trace" in cmd["evidence_contract"]


def test_approval_record_is_gated_not_execution():
    payload = arsenal.describe_commands()
    commands = {item["name"]: item for item in payload["commands"]}

    cmd = commands["approval.record"]
    assert cmd["status"] == "gated"
    assert cmd["path"] == "/arsenal/approvals"
    assert "confirm_authorized" in cmd["required_confirmations"]
    assert "approval_receipt" in cmd["evidence_contract"]


def test_gated_commands_advertise_approval_receipts():
    payload = arsenal.describe_commands()
    commands = {item["name"]: item for item in payload["commands"]}

    for name in (
        "asm.improve",
        "scan.focused_family",
        "finding.retest",
        "ai_gate.replay_probe",
        "model_intake.scan",
    ):
        assert "approval_receipt_id" in commands[name]["parameters_schema"]


def test_mission_contract_catalog_is_contract_only():
    payload = arsenal.describe_contracts()

    assert payload["schema_version"] == arsenal.ARSENAL_SCHEMA_VERSION
    assert payload["maturity"] == "contract_only"
    assert payload["execution_enabled"] is False
    assert set(payload["contract_names"]) >= {
        "OperationPlan",
        "AgentContextPack",
        "AgentDecisionTrace",
        "ScopeReceipt",
        "ApprovalReceipt",
        "ToolReceipt",
        "CampaignAction",
        "Hypothesis",
        "EvidenceInstance",
    }


def test_contracts_encode_planner_and_secret_boundaries():
    payload = arsenal.describe_contracts()
    contracts = payload["contracts"]

    assert "raw_transcripts" in payload["secret_policy"]["never_inline"]
    assert "authorization_headers" in payload["secret_policy"]["never_inline"]
    assert "scope_receipt_id" in payload["secret_policy"]["allowed_refs"]
    assert "plan is dry-run until state-changing actions receive scope and approval receipts" in contracts["OperationPlan"]["invariants"]
    assert "chain_of_thought" in contracts["AgentDecisionTrace"]["forbidden_fields"]
    assert "raw_private_key" in contracts["AgentDecisionTrace"]["forbidden_fields"]
    assert "redirect_out_of_scope" in contracts["ScopeReceipt"]["fields"]["checks"]
    assert "parser failure cannot create verified findings" in contracts["ToolReceipt"]["invariants"]
    assert "hypotheses cannot directly alter finding proof_state or severity" in contracts["Hypothesis"]["invariants"]


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


def test_local_agent_catalog_is_read_only_and_does_not_read_auth(monkeypatch):
    monkeypatch.setattr(arsenal.shutil, "which", lambda name: f"/usr/local/bin/{name}" if name == "codex" else None)
    monkeypatch.setattr(arsenal.os.path, "exists", lambda path: path.endswith("/.codex/auth.json"))

    payload = arsenal.describe_local_agents()
    agents = {item["agent"]: item for item in payload["agents"]}

    assert payload["execution_enabled"] is False
    assert payload["planner_execution_enabled"] is False
    assert payload["auth_policy"]["auth_artifact_contents_read"] is False
    assert agents["codex"]["status"] == "available"
    assert agents["codex"]["auth_detected"] is True
    assert agents["codex"]["auth_artifact_contents_read"] is False
    assert agents["codex"]["planner_execution_enabled"] is False
    assert agents["claude-code"]["status"] == "missing"


def test_local_agent_list_command_is_read_only():
    payload = arsenal.describe_commands()
    commands = {item["name"]: item for item in payload["commands"]}

    cmd = commands["local_agent.list"]
    assert cmd["status"] == "read_only"
    assert cmd["risk_tier"] == "read_only"
    assert cmd["path"] == "/agents/local"
    assert "local_agent_capability_rows" in cmd["evidence_contract"]
