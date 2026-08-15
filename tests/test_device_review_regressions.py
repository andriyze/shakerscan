"""Source-level seams for device persistence and product isolation regressions.

The behavior-heavy parser/protocol tests live in their respective modules. These
assertions keep API/database wiring visible without importing the full FastAPI
runtime on lightweight developer hosts.
"""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_device_result_uses_the_shared_nul_sanitizer_before_returning():
    source = (ROOT / "api" / "worker.py").read_text()
    branch = source[source.index('if options.get("run_kind") == "device_posture"'):]
    branch = branch[:branch.index('if options.get("run_kind") in MODEL_INTAKE_RUN_KINDS')]
    assert "_strip_null_bytes(result)" in branch


def test_device_scan_enforces_the_state_change_approval_policy():
    source = (ROOT / "api" / "api.py").read_text()
    endpoint = source[source.index('@app.post("/devices/{device_id}/scan")'):]
    endpoint = endpoint[:endpoint.index('@app.get("/device-scans")')]
    assert "_require_approval_receipt_if_policy_enabled" in endpoint
    assert 'action_name="device.scan"' in endpoint


def test_dashboard_queries_explicitly_exclude_the_device_product_plane():
    source = (ROOT / "api" / "api.py").read_text()
    action_center = source[source.index("async def _build_dashboard_action_center"):]
    action_center = action_center[:action_center.index('@app.get("/dashboard")')]
    dashboard = source[source.index('@app.get("/dashboard")'):]
    dashboard = dashboard[:dashboard.index('@app.get("/exposure/graph")')]
    assert "COALESCE(source, '') <> 'device'" in action_center
    assert "device_target_id IS NULL" in action_center
    assert "COALESCE(source, '') <> 'device'" in dashboard
    assert "device_target_id IS NULL" in dashboard
    assert "device_web_origin" in dashboard


def test_bootstrap_schema_contains_device_agent_runs():
    init_sql = (ROOT / "db" / "init.sql").read_text()
    assert "CREATE TABLE device_agent_runs" in init_sql
    assert "device_target_id UUID NOT NULL REFERENCES device_targets(id) ON DELETE CASCADE" in init_sql
