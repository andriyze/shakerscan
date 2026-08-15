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
    assert "_validate_approval_receipt_for_action" in endpoint
    assert 'action_name="device.scan"' in endpoint
    assert '"resolved_budget"' in endpoint
    assert "DEVICE_SCAN_MAX_DURATION_MINUTES[request.profile]" in endpoint


def test_device_agent_revalidates_the_session_receipt_on_every_turn():
    source = (ROOT / "api" / "api.py").read_text()
    start = source[source.index('@app.post("/devices/{device_id}/agent/session")'):]
    start = start[:start.index('@app.get("/device-agent/session/{run_id}")')]
    reply = source[source.index('@app.post("/device-agent/session/{run_id}/reply")'):]
    reply = reply[:reply.index('@app.post("/device-agent/session/{run_id}/cancel")')]
    assert "_device_posture_enabled" in start
    assert "_validate_approval_receipt_for_action" in start
    assert "_validate_approval_receipt_for_action" in reply
    assert 'action_name="device.agent.session"' in reply


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
    assert "idx_device_agent_runs_one_active_per_device" in init_sql
    assert "idx_scans_one_active_device_posture" in init_sql


def test_device_findings_use_atomic_conflict_upsert():
    source = (ROOT / "api" / "worker.py").read_text()
    function = source[source.index("async def save_device_findings"):]
    function = function[:function.index("async def persist_device_inventory")]
    assert "ON CONFLICT (device_target_id, fingerprint)" in function
    assert "DO UPDATE SET" in function
    assert "SELECT id, status, resurfaced_count FROM findings" not in function


def test_device_children_have_redis_identity_and_dedicated_heartbeats():
    source = (ROOT / "api" / "worker.py").read_text()
    children = source[source.index("async def run_device_web_children"):]
    children = children[:children.index("async def process_scan_job")]
    assert '"scan_id": child_scan_id' in children
    assert "target=send_heartbeats" in children
    assert "_scan_cancel_requested(parent_scan_id)" in children


def test_device_worker_rechecks_feature_flag_and_injects_cancel_guard():
    source = (ROOT / "api" / "worker.py").read_text()
    branch = source[source.index('if options.get("run_kind") == "device_posture"'):]
    branch = branch[:branch.index('if options.get("run_kind") in MODEL_INTAKE_RUN_KINDS')]
    assert "DEVICE_POSTURE_ENABLED" in branch
    assert 'device_options["_cancel_check"]' in branch


def test_web_retest_endpoints_reject_device_findings():
    source = (ROOT / "api" / "api.py").read_text()
    single = source[source.index('@app.post("/findings/{finding_id:path}/retest")'):]
    single = single[:single.index('@app.get("/retests/finding/{finding_id:path}")')]
    bulk = source[source.index("async def bulk_retest_findings"):]
    bulk = bulk.split("\n@app.", 1)[0]
    assert 'finding_data.get("source") == "device"' in single
    assert 'finding_data.get("device_target_id")' in single
    assert "device_findings_require_device_rescan" in bulk


def test_device_credentials_are_bound_encrypted_and_resolved_only_in_worker_memory():
    api = (ROOT / "api" / "api.py").read_text()
    worker = (ROOT / "api" / "worker.py").read_text()
    schema = (ROOT / "db" / "init.sql").read_text()
    assert "CREATE TABLE device_credential_profiles" in schema
    assert "Credential encryption is not configured" in api
    assert "device_credential_profiles" in api
    assert "_hydrate_device_scan_credentials" in worker
    assert 'hydrated["_resolved_device_credentials"]' in worker
    assert 'runtime_child_options["auth_header"]' in worker
    assert 'runtime_child_options["auth_cookies"]' in worker
    assert '"login_password": str(web_credential.get("secret")' in worker


def test_device_auth_requires_authenticated_safety_and_never_enters_agent_transcript():
    api = (ROOT / "api" / "api.py").read_text()
    assert "Credentialed device scans require safety_profile=authenticated_active" in api
    assert "Credentialed device investigations require safety_profile=authenticated_active" in api
    assert '"credentials_visible_to_planner": False' in api
