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
        "target.principals",
        "target.principal_matrix",
        "asm.gaps",
        "asm.activity",
        "scan.result",
        "finding.list",
        "finding.get",
        "ai_target.list",
        "model_intake.trust_preview",
        "operation_plan.list",
        "campaign_action.list",
        "hypothesis.list",
        "refuter_review.list",
        "refuter_review.summary",
        "agent_context_pack.list",
        "agent_decision_trace.list",
        "local_agent.list",
        "evidence.get",
        "evidence.export_manifest",
        "evidence_instance.list",
        "tool_receipt.list",
        "deployment.decision",
        "tool.status",
    ):
        assert name in commands
        assert commands[name]["status"] == "read_only"
        assert commands[name]["risk_tier"] == "read_only"


def test_refuter_review_commands_do_not_mutate_findings_directly():
    payload = arsenal.describe_commands()
    commands = {item["name"]: item for item in payload["commands"]}

    list_cmd = commands["refuter_review.list"]
    summary_cmd = commands["refuter_review.summary"]
    record_cmd = commands["refuter_review.record"]

    assert list_cmd["status"] == "read_only"
    assert summary_cmd["status"] == "read_only"
    assert record_cmd["status"] == "dry_run"
    assert record_cmd["risk_tier"] == "read_only"
    assert list_cmd["path"] == "/arsenal/refuter-reviews"
    assert summary_cmd["path"] == "/arsenal/refuter-reviews/summary"
    assert record_cmd["path"] == "/arsenal/refuter-reviews"
    assert "refuter_candidates" in summary_cmd["evidence_contract"]
    assert "verdict_basis" in record_cmd["parameters_schema"]
    assert "refuter_review_row" in record_cmd["evidence_contract"]


def test_tool_receipt_and_evidence_instance_commands_are_record_only():
    payload = arsenal.describe_commands()
    commands = {item["name"]: item for item in payload["commands"]}

    receipt_list = commands["tool_receipt.list"]
    receipt_record = commands["tool_receipt.record"]
    instance_list = commands["evidence_instance.list"]
    instance_record = commands["evidence_instance.record"]

    assert receipt_list["status"] == "read_only"
    assert instance_list["status"] == "read_only"
    assert receipt_record["status"] == "dry_run"
    assert instance_record["status"] == "dry_run"
    assert receipt_record["risk_tier"] == "read_only"
    assert instance_record["risk_tier"] == "read_only"
    assert receipt_record["path"] == "/arsenal/tool-receipts"
    assert instance_record["path"] == "/evidence/instances"
    assert "parser_status" in receipt_record["parameters_schema"]
    assert "proof_state" in instance_record["parameters_schema"]


def test_evidence_manifest_and_retention_commands_are_bounded():
    payload = arsenal.describe_commands()
    commands = {item["name"]: item for item in payload["commands"]}

    manifest = commands["evidence.export_manifest"]
    sweep = commands["evidence.retention_sweep"]

    assert manifest["status"] == "read_only"
    assert manifest["path"] == "/evidence/export-manifest"
    assert "manifest_hash" in manifest["evidence_contract"]
    assert sweep["status"] == "dry_run"
    assert sweep["risk_tier"] == "read_only"
    assert sweep["path"] == "/evidence/retention/sweep"
    assert sweep["parameters_schema"]["dry_run"]["default"] is True


def test_target_principal_matrix_commands_are_non_executing_inventory():
    payload = arsenal.describe_commands()
    commands = {item["name"]: item for item in payload["commands"]}

    principals = commands["target.principals"]
    matrix = commands["target.principal_matrix"]
    record = commands["target.principal_matrix.record"]

    assert principals["status"] == "read_only"
    assert matrix["status"] == "read_only"
    assert record["status"] == "dry_run"
    assert record["risk_tier"] == "read_only"
    assert principals["path"] == "/targets/{target_id}/principals"
    assert matrix["path"] == "/targets/{target_id}/principal-matrix"
    assert record["path"] == "/targets/{target_id}/principal-matrix"
    assert "expected_access" in record["parameters_schema"]


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


def test_agent_context_pack_generate_from_target_is_dry_run_not_execution():
    payload = arsenal.describe_commands()
    commands = {item["name"]: item for item in payload["commands"]}

    cmd = commands["agent_context_pack.generate_from_target"]
    assert cmd["status"] == "dry_run"
    assert cmd["risk_tier"] == "read_only"
    assert cmd["path"] == "/arsenal/context-packs/from-target"
    assert cmd["scope_fields"] == ["target_id"]
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


def test_command_result_list_is_read_only_command():
    payload = arsenal.describe_commands()
    commands = {item["name"]: item for item in payload["commands"]}

    cmd = commands["command_result.list"]
    assert cmd["status"] == "read_only"
    assert cmd["risk_tier"] == "read_only"
    assert cmd["method"] == "GET"
    assert cmd["path"] == "/arsenal/command-results"
    assert "command_result_rows" in cmd["evidence_contract"]


def test_mission_timeline_is_read_only_command():
    payload = arsenal.describe_commands()
    commands = {item["name"]: item for item in payload["commands"]}

    cmd = commands["mission.timeline"]
    assert cmd["status"] == "read_only"
    assert cmd["risk_tier"] == "read_only"
    assert cmd["method"] == "GET"
    assert cmd["path"] == "/timeline"
    assert "timeline_events" in cmd["evidence_contract"]


def test_campaign_action_list_is_read_only_command():
    payload = arsenal.describe_commands()
    commands = {item["name"]: item for item in payload["commands"]}

    cmd = commands["campaign_action.list"]
    assert cmd["status"] == "read_only"
    assert cmd["risk_tier"] == "read_only"
    assert cmd["method"] == "GET"
    assert cmd["path"] == "/arsenal/campaign-actions"
    assert "campaign_action_rows" in cmd["evidence_contract"]


def test_hypothesis_commands_do_not_execute_scanners_or_create_findings():
    payload = arsenal.describe_commands()
    commands = {item["name"]: item for item in payload["commands"]}

    list_cmd = commands["hypothesis.list"]
    report_cmd = commands["hypothesis.situation_report"]
    record_cmd = commands["hypothesis.record"]
    claim_cmd = commands["hypothesis.claim"]

    assert list_cmd["status"] == "read_only"
    assert report_cmd["status"] == "read_only"
    assert record_cmd["status"] == "dry_run"
    assert claim_cmd["status"] == "dry_run"
    assert report_cmd["risk_tier"] == "read_only"
    assert record_cmd["risk_tier"] == "read_only"
    assert claim_cmd["risk_tier"] == "read_only"
    assert report_cmd["path"] == "/arsenal/hypotheses/situation-report"
    assert "hottest_unclaimed" in report_cmd["evidence_contract"]
    assert "missing_preconditions" in report_cmd["evidence_contract"]
    assert record_cmd["path"] == "/arsenal/hypotheses"
    assert "dedupe_dimensions" in record_cmd["parameters_schema"]
    assert claim_cmd["path"] == "/arsenal/hypotheses/{hypothesis_id}/claim"
    assert "hypothesis_row" in record_cmd["evidence_contract"]
    signal_cmd = commands["hypothesis.signal"]
    assert signal_cmd["status"] == "dry_run"
    assert signal_cmd["risk_tier"] == "read_only"
    assert signal_cmd["path"] == "/arsenal/hypotheses/{hypothesis_id}/signals"
    assert "hypothesis_row" in signal_cmd["evidence_contract"]


def test_graph_hypothesis_generation_is_dry_run_read_only_risk():
    payload = arsenal.describe_commands()
    commands = {item["name"]: item for item in payload["commands"]}

    cmd = commands["hypothesis.generate_from_graph"]
    assert cmd["status"] == "dry_run"
    assert cmd["risk_tier"] == "read_only"
    assert cmd["method"] == "POST"
    assert cmd["path"] == "/targets/{target_id}/graph/hypotheses"
    assert "hypothesis_rows" in cmd["evidence_contract"]


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
        "CommandResult",
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
    assert "queued command results cannot mark findings verified" in contracts["CommandResult"]["invariants"]
    assert "parser failure cannot create verified findings" in contracts["ToolReceipt"]["invariants"]
    assert "recording a receipt cannot run a tool or create findings" in contracts["ToolReceipt"]["invariants"]
    assert contracts["ToolReceipt"]["status"] == "dry_run"
    assert contracts["EvidenceInstance"]["status"] == "dry_run"
    assert "evidence instances enumerate observations but do not directly update canonical findings" in contracts["EvidenceInstance"]["invariants"]
    assert "hypotheses cannot directly alter finding proof_state or severity" in contracts["Hypothesis"]["invariants"]
    assert "target/family/dedupe dimensions identify a lead across signal sources" in contracts["Hypothesis"]["invariants"]
    assert "effective_status" in contracts["Hypothesis"]["fields"]
    assert "claimable" in contracts["Hypothesis"]["fields"]
    assert "TargetPrincipal" in contracts
    assert "EndpointPrincipalExpectation" in contracts
    assert "expectations are planning facts only and cannot create findings" in contracts["EndpointPrincipalExpectation"]["invariants"]
    assert "RefuterReview" in contracts
    assert "recording a refuter review cannot directly update proof_state, severity, findings, hypotheses, or deployment gates" in contracts["RefuterReview"]["invariants"]


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
    assert payload["release_gate"]["name"] == "no_phantom_tools"
    assert payload["release_gate"]["status"] == "pass"
    assert payload["release_gate"]["execution_enabled"] is False


def test_tool_status_release_gate_passes_current_catalog_without_probe(monkeypatch):
    monkeypatch.setattr(arsenal.shutil, "which", lambda _name: None)
    monkeypatch.setattr(arsenal.os.path, "exists", lambda _path: False)
    monkeypatch.setattr(arsenal.os, "access", lambda *_args: False)

    payload = arsenal.describe_tools(probe_versions=False)

    assert payload["release_gate"]["status"] == "pass"
    assert payload["release_gate"]["violations"] == []
    assert payload["release_gate"]["checked_count"] == len(payload["tools"])
    assert set(payload["release_gate"]["allowed_statuses"]) == set(arsenal.TOOL_STATUSES)


def test_tool_status_release_gate_blocks_phantom_runnable_adapter():
    phantom = {
        "tool_name": "phantom-sqli",
        "status": "runnable",
        "expected_status": "runnable",
        "binary_path": None,
        "version": None,
        "version_command": ["phantom-sqli", "--version"],
        "evidence_parser": "phantom-json-v1",
        "proof_contract": "phantom-proof",
    }

    gate = arsenal._tool_status_release_gate([phantom])

    assert gate["status"] == "fail"
    codes = {item["code"] for item in gate["violations"]}
    assert "phantom_binary_claim" in codes
    assert "phantom_expected_status" in codes


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
    assert payload["release_gate"]["status"] == "pass"


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


def test_local_agent_plan_command_is_dry_run_not_execution():
    payload = arsenal.describe_commands()
    commands = {item["name"]: item for item in payload["commands"]}

    cmd = commands["local_agent.plan_dry_run"]
    assert cmd["status"] == "dry_run"
    assert cmd["risk_tier"] == "read_only"
    assert cmd["path"] == "/agents/local/plan"
    assert cmd["scope_fields"] == ["context_pack_id"]
    assert "operation_plan" in cmd["evidence_contract"]


def test_local_agent_test_command_is_harmless_ping():
    payload = arsenal.describe_commands()
    commands = {item["name"]: item for item in payload["commands"]}

    cmd = commands["local_agent.test"]
    assert cmd["status"] == "dry_run"
    assert cmd["risk_tier"] == "read_only"
    assert cmd["method"] == "POST"
    assert cmd["path"] == "/agents/local/test"
    assert "ping_result" in cmd["evidence_contract"]
    assert "environment_api_keys" in cmd["redaction_contract"]
    assert "prompts" in cmd["redaction_contract"]


def test_local_agent_test_missing_binary_does_not_spawn_or_prompt(monkeypatch):
    monkeypatch.setattr(arsenal.shutil, "which", lambda name: None)

    result = arsenal.test_local_agent_capability("codex")

    assert result["status"] == "missing"
    assert result["reason"] == "binary_not_detected"
    assert result["process_spawned"] is False
    assert result["prompt_sent"] is False
    assert result["planner_execution_enabled"] is False
    assert result["scanner_work_queued"] is False
    assert result["auth_artifact_contents_read"] is False


def test_local_agent_test_strips_sensitive_env_and_truncates_output(monkeypatch):
    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        captured["env"] = kwargs["env"]

        class Proc:
            returncode = 0
            stdout = "codex version 1.2.3\n" + ("x" * 5000)
            stderr = ""

        return Proc()

    monkeypatch.setattr(arsenal.shutil, "which", lambda name: "/usr/local/bin/codex" if name == "codex" else None)
    monkeypatch.setattr(arsenal.os.path, "exists", lambda path: False)
    monkeypatch.setenv("OPENAI_API_KEY", "secret")
    monkeypatch.setenv("SAFE_FOR_TEST", "visible")
    monkeypatch.setattr(arsenal.subprocess, "run", fake_run)

    result = arsenal.test_local_agent_capability("codex", timeout_seconds=5, max_output_bytes=256)

    assert captured["argv"] == ["/usr/local/bin/codex", "--version"]
    assert "OPENAI_API_KEY" not in captured["env"]
    assert captured["env"]["SAFE_FOR_TEST"] == "visible"
    assert result["status"] == "passed"
    assert result["ok"] is True
    assert result["process_spawned"] is True
    assert result["prompt_sent"] is False
    assert result["local_agent_spawned"] is False
    assert result["planner_execution_enabled"] is False
    assert result["scanner_work_queued"] is False
    assert result["environment_policy"]["provider_api_keys_stripped"] is True
    assert result["environment_policy"]["sensitive_values_returned"] is False
    assert result["environment_policy"]["stripped_variable_count"] >= 1
    assert result["output_truncated"] is True
    assert result["output_bytes_captured"] <= 256
    assert result["version"] == "codex version 1.2.3"


def test_local_agent_test_rejects_unknown_agent():
    try:
        arsenal.test_local_agent_capability("unknown-agent")
    except ValueError as exc:
        assert "Unknown local agent" in str(exc)
    else:
        raise AssertionError("expected ValueError")
