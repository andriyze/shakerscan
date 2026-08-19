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
    assert 'else "device.scan"' in endpoint
    assert "_DEVICE_AGENT_PARENT_AUTHORITY" in endpoint
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
    assert '"inconclusive_observations": inconclusive_observations' in source
    assert '"confirmed_open": len(confirmed_services)' in source


def test_device_agent_shell_is_immutable_user_confirmed_and_remote_only():
    source = (ROOT / "api" / "api.py").read_text()
    endpoint = source[source.index('@app.post("/device-agent/session/{run_id}/shell-plans/{plan_id}/confirm")'):]
    endpoint = endpoint[:endpoint.index('@app.post("/device-agent/session/{run_id}/reply")')]
    scanner = (ROOT / "scanner" / "scanner_tools" / "ssh_scanner.py").read_text()
    assert "confirm_exact_commands" in endpoint
    assert "confirm_remote_device_effects" in endpoint
    assert "device_shell.validate_shell_plan" in endpoint
    assert "confirmed_plan_digest" in endpoint
    assert "expected_host_key_fingerprint" in source
    assert "pty_allocated" in scanner and "stdin_forwarded" in scanner
    assert "subprocess" not in endpoint


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
    assert "idx_scans_one_active_device_traffic" in init_sql


def test_device_locator_changes_preserve_identity_and_history():
    api = (ROOT / "api" / "api.py").read_text()
    schema = (ROOT / "db" / "init.sql").read_text()
    migration = (ROOT / "api" / "retest_contract.py").read_text()
    endpoint = api[api.index('@app.post("/devices/{device_id}/locator")'):]
    endpoint = endpoint[:endpoint.index('@app.delete("/devices/{device_id}")')]
    helper = api[api.index("async def _change_device_primary_locator"):]
    helper = helper[:helper.index("def _public_device_credential_profile")]

    assert "CREATE TABLE device_locator_history" in schema
    assert "CREATE TABLE IF NOT EXISTS device_locator_history" in migration
    assert "device_target_id UUID NOT NULL REFERENCES device_targets(id) ON DELETE CASCADE" in schema
    assert "UPDATE device_targets SET primary_locator" in helper
    assert "INSERT INTO device_locator_history" in helper
    assert "confirm_same_device" in endpoint
    assert "active connected-device scan or probe" in helper
    assert "active AI device investigation" in helper
    assert "INSERT INTO device_targets" not in endpoint


def test_device_detail_exposes_current_locator_and_bounded_history():
    api = (ROOT / "api" / "api.py").read_text()
    detail = api[api.index('@app.get("/devices/{device_id}")'):]
    detail = detail[:detail.index('@app.patch("/devices/{device_id}")')]
    ui = (ROOT / "ui" / "src" / "app" / "devices" / "[id]" / "page.tsx").read_text()

    assert "device_locator_history" in detail
    assert "LIMIT 50" in detail
    assert '"locator_history"' in detail
    assert "Permanent device ID" in ui
    assert "Change address" in ui
    assert "same physical device" in ui


def test_device_detail_supports_display_name_changes_without_changing_identity():
    api = (ROOT / "api" / "api.py").read_text()
    api_client = (ROOT / "ui" / "src" / "lib" / "api.ts").read_text()
    ui = (ROOT / "ui" / "src" / "app" / "devices" / "[id]" / "page.tsx").read_text()
    endpoint = api[api.index('@app.patch("/devices/{device_id}")'):]
    endpoint = endpoint[:endpoint.index('@app.post("/devices/{device_id}/locator")')]

    assert 'detail="Device name cannot be empty"' in endpoint
    assert 'payload["name"] = normalized_name' in endpoint
    assert "export async function renameDevice" in api_client
    assert "Rename connected device" in ui
    assert "This changes the display name only" in ui


def test_device_detail_scopes_udp_uncertainty_to_the_latest_posture_scan():
    api = (ROOT / "api" / "api.py").read_text()
    detail = api[api.index('@app.get("/devices/{device_id}")'):]
    detail = detail[:detail.index('@app.patch("/devices/{device_id}")')]
    ui = (ROOT / "ui" / "src" / "app" / "devices" / "[id]" / "page.tsx").read_text()

    assert "state='open|filtered' AND scan_id=$2" in detail
    assert 'row["last_scan_id"]' in detail
    assert "Unconfirmed port probes" in ui
    assert "They are not confirmed open" in ui
    assert "details hidden by default" in ui
    assert "Not confirmed open" in ui


def test_device_detail_makes_exact_scan_open_ports_prominent():
    api_client = (ROOT / "ui" / "src" / "lib" / "api.ts").read_text()
    ui = (ROOT / "ui" / "src" / "app" / "devices" / "[id]" / "page.tsx").read_text()

    assert "useSearchParams" in ui
    assert "searchParams.get('scan')" in ui
    assert "getScan(selectedScanId)" in ui
    assert "next.device_target_id !== deviceId" in ui
    assert "Open ports in this scan" in ui
    assert "Only services positively confirmed by the selected scan are shown." in ui
    assert "Previously observed on this device" in ui
    assert "This does not prove they are currently closed." in ui
    assert "Confirmed responses only. Silent or ambiguous probes are never shown as open." in ui
    assert "show open ports" in ui
    assert "Track scan activity" in ui
    assert "export async function getScan(id: string): Promise<Scan>" in api_client


def test_device_views_expose_last_scan_reachability_without_assuming_online():
    api = (ROOT / "api" / "api.py").read_text()
    worker = (ROOT / "api" / "worker.py").read_text()
    detail_ui = (ROOT / "ui" / "src" / "app" / "devices" / "[id]" / "page.tsx").read_text()
    list_ui = (ROOT / "ui" / "src" / "app" / "devices" / "page.tsx").read_text()

    assert "AS last_reachability" in api
    assert '"reachability": device_payload.get("last_reachability")' in api
    assert 'reachability.get("status") != "online"' in worker
    assert "Device reachability not checked" in detail_ui
    assert "service accessibility still being assessed" in detail_ui
    assert "Reachability: not checked" in list_ui


def test_device_hunt_is_the_consistent_user_facing_agent_name():
    detail_ui = (ROOT / "ui" / "src" / "app" / "devices" / "[id]" / "page.tsx").read_text()
    hunt_ui = (ROOT / "ui" / "src" / "app" / "devices" / "[id]" / "agent" / "page.tsx").read_text()
    skill = (ROOT / "skills" / "device-hunt" / "SKILL.md").read_text()
    skill_index = (ROOT / "skills" / "README.md").read_text()
    product_model = (ROOT / "docs" / "product-model.md").read_text()

    assert "> Device Hunt</Link>" in detail_ui
    assert 'title="Device Hunt"' in hunt_ui
    assert "Start Device Hunt" in hunt_ui
    assert "name: device-hunt" in skill and "ShakerScan Device Hunt" in skill
    assert "[`device-hunt`](device-hunt/SKILL.md)" in skill_index
    assert "## Device Hunt" in product_model


def test_device_hunt_ui_restores_active_runs_and_persists_new_run_urls():
    api_client = (ROOT / "ui" / "src" / "lib" / "api.ts").read_text()
    hunt_ui = (ROOT / "ui" / "src" / "app" / "devices" / "[id]" / "agent" / "page.tsx").read_text()

    assert "export async function listDeviceAgentSessions" in api_client
    assert "device_target_id" in api_client
    assert "listDeviceAgentSessions({ device_target_id: deviceId" in hunt_ui
    assert "recent.runs.find((run) => !TERMINAL.has(run.status))" in hunt_ui
    assert "window.history.replaceState" in hunt_ui
    assert "?run=${encodeURIComponent(value.id)}" in hunt_ui


def test_device_hunt_history_is_durable_linkable_and_visible_from_the_device():
    api = (ROOT / "api" / "api.py").read_text()
    api_client = (ROOT / "ui" / "src" / "lib" / "api.ts").read_text()
    hunt_ui = (ROOT / "ui" / "src" / "app" / "devices" / "[id]" / "agent" / "page.tsx").read_text()
    detail_ui = (ROOT / "ui" / "src" / "app" / "devices" / "[id]" / "page.tsx").read_text()
    listing = api[api.index('@app.get("/device-agent/runs")'):]
    listing = listing[:listing.index("# AI GATE TARGETS")]

    assert "SELECT COUNT(*) FROM device_agent_runs" in listing
    assert "device_agent_actions" in listing
    assert "investigation_candidates" in listing
    assert '"actions": [_device_agent_action_public' in api
    assert '"candidate_summary"' in api
    assert "actions: Array<{" in api_client
    assert "Device Hunt history" in hunt_ui
    assert "Action and scan ledger" in hunt_ui
    assert "Open scan" in hunt_ui
    assert "Recent Device Hunt investigations" in detail_ui
    assert "listDeviceAgentSessions({ device_target_id: deviceId, limit: 5 })" in detail_ui


def test_device_findings_use_atomic_conflict_upsert():
    source = (ROOT / "api" / "worker.py").read_text()
    function = source[source.index("async def save_device_findings"):]
    function = function[:function.index("async def persist_device_inventory")]
    assert "ON CONFLICT (device_target_id, fingerprint)" in function
    assert "DO UPDATE SET" in function
    assert "SELECT id, status, resurfaced_count FROM findings" not in function
    assert "candidate_uuid, verification_id, str(finding_id), device_uuid" in function


def test_device_service_verifier_carries_candidate_contract_to_the_worker():
    source = (ROOT / "api" / "api.py").read_text()
    function = source[source.index('async def verify_device_service') :]
    function = function[: function.index('\n\n@app.get("/device-scans")')]

    assert 'candidate_uuid = _device_uuid(request.candidate_id, "candidate")' in function
    assert '"candidate_id": str(candidate_uuid) if candidate_uuid else None' in function
    assert '"proof_contract_id": str(candidate["verifier_contract_id"] or "")' in function
    assert "SET status='verification_queued'" in function
    assert "Candidate verification must use its exact transport/port locus" in function


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
    assert "run_pinned_device_web_scan" in worker
    assert 'credential=web_credential' in worker
    assert 'payload.pop("secret_preview", None)' in api
    assert "device_credential_attempts" in schema


def test_device_auth_requires_authenticated_safety_and_never_enters_agent_transcript():
    api = (ROOT / "api" / "api.py").read_text()
    worker = (ROOT / "api" / "worker.py").read_text()
    assert "Credentialed device scans require safety_profile=authenticated_active" in api
    assert "Credentialed device investigations require safety_profile=authenticated_active" in api
    assert '"credentials_visible_to_planner": False' in api
    assert 'device credentials require safety_profile=authenticated_active' in worker


def test_device_request_collections_are_encrypted_pinned_and_agent_bounded():
    api = (ROOT / "api" / "api.py").read_text()
    worker = (ROOT / "api" / "worker.py").read_text()
    agent = (ROOT / "api" / "device_agent.py").read_text()
    schema = (ROOT / "db" / "init.sql").read_text()
    web = (ROOT / "scanner" / "scanner_tools" / "device_web.py").read_text()
    formats = (ROOT / "scanner" / "scanner_tools" / "device_request_formats.py").read_text()
    ui = (ROOT / "ui" / "src" / "app" / "devices" / "[id]" / "page.tsx").read_text()
    hunt = (ROOT / "ui" / "src" / "app" / "devices" / "[id]" / "agent" / "page.tsx").read_text()

    assert "CREATE TABLE device_request_collections" in schema
    assert "encrypted_payload TEXT NOT NULL" in schema
    assert "'postman_collection','har','openapi'" in schema
    assert '@app.post("/devices/{device_id}/request-collections")' in api
    assert "Encrypted storage is required for device request collections" in api
    assert 'summary = _json_object(payload.get("summary_json"))' in api
    assert "WHERE device_request_collections.is_active=false" in api
    update_start = api.index('@app.patch("/devices/{device_id}/request-collections/{collection_id}")')
    update_end = api.index('@app.delete("/devices/{device_id}/request-collections/{collection_id}")', update_start)
    assert "is_active=true" not in api[update_start:update_end]
    assert "_hydrate_device_request_collections" in worker
    assert 'hydrated["_resolved_device_request_collections"]' in worker
    assert "external_host_blocked" in web
    assert "state_changing_request_not_confirmed" in web
    assert "resolve_imported_requests" in web
    assert 'format_name="har"' in formats
    assert 'format_name="openapi"' in formats
    assert "external_refs_ignored" in formats
    assert '"inspect_request_collections"' in agent
    assert "include_imported_requests" in agent
    assert '"request_collection_secrets_visible_to_planner": False' in api
    assert "Import API requests" in ui
    assert "Use real imported API requests" in ui
    assert "Bind imported API requests" in hunt
    assert "libpcap0.8" in (ROOT / "scanner" / "Dockerfile").read_text()
    assert "allow_untrusted_tls_credentials" in api
    assert "untrusted_tls_credentials_not_confirmed" in web


def test_device_scan_activity_is_structured_and_user_facing():
    api = (ROOT / "api" / "api.py").read_text()
    worker = (ROOT / "api" / "worker.py").read_text()
    ui = (ROOT / "ui" / "src" / "app" / "devices" / "[id]" / "page.tsx").read_text()
    assert '@app.get("/scans/{scan_id}/device-activity")' in api
    assert "_append_device_activity" in worker
    assert "Meaningful events only; commands, payloads, and secrets are hidden." in ui
    assert "getDeviceScanActivity" in ui


def test_legacy_policy_upgrade_matches_numeric_json_port_arrays():
    migration = (ROOT / "api" / "retest_contract.py").read_text()
    upgrade = migration[migration.index("UPDATE device_policies AS policy"):]
    upgrade = upgrade[:upgrade.index("CREATE TABLE IF NOT EXISTS device_targets")]

    # JSONB `?|` only matches string array members, while policy ports are JSON
    # numbers. Expanding as text makes both fresh and legacy numeric arrays match.
    assert "jsonb_array_elements_text" in upgrade
    assert "denied_port.value IN ('21','23','2323')" in upgrade
    assert "(rule->'ports') ?|" not in upgrade
