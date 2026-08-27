"""Source-level seams for device persistence and product isolation regressions.

The behavior-heavy parser/protocol tests live in their respective modules. These
assertions keep API/database wiring visible without importing the full FastAPI
runtime on lightweight developer hosts.
"""

from pathlib import Path

from tests.api_sources import (
    api_tree_source, definition_source, route_is_declared, route_source,
)


ROOT = Path(__file__).resolve().parents[1]


def test_device_result_uses_the_shared_nul_sanitizer_before_returning():
    source = (ROOT / "api" / "worker_handlers" / "device.py").read_text()
    branch = source[source.index("async def run_posture("):]
    assert "self.services.strip_null_bytes(result)" in branch


def test_device_scan_enforces_the_state_change_approval_policy():
    source = api_tree_source()
    endpoint = route_source("POST", "/devices/{device_id}/scan")
    assert "_validate_approval_receipt_for_action" in endpoint
    assert 'else "device.scan"' in endpoint
    assert "_DEVICE_AGENT_PARENT_AUTHORITY" in endpoint
    assert '"resolved_budget"' in endpoint
    assert "DEVICE_SCAN_MAX_DURATION_MINUTES[request.profile]" in endpoint


def test_device_agent_revalidates_the_session_receipt_on_every_turn():
    """The legacy per-turn revalidation is now the canonical capability path.

    start/reply are deleted; every device turn goes through
    POST /hunts/{hunt_id}/capabilities/{name}, which revalidates the approval
    receipt on each action rather than trusting the one taken at session start.
    """
    source = api_tree_source()
    turn = (
        route_source("POST", "/hunts/{hunt_id}/capabilities/{capability_name:path}")
        + definition_source("_execute_hunt_capability_lifecycle")
    )
    assert "_validate_approval_receipt_for_action" in turn
    assert "revalidate" in turn
    # Device posture must still gate every device surface that can reach a host.
    assert "_device_posture_enabled" in source
    assert '"inconclusive_observations": inconclusive_observations' in source
    assert '"confirmed_open": len(confirmed_services)' in source


def test_device_agent_shell_is_immutable_user_confirmed_and_remote_only():
    source = api_tree_source()
    # The legacy confirmation route is deleted; the same immutable,
    # user-confirmed, remote-only contract is enforced by canonical Hunt.
    endpoint = route_source("POST", "/hunts/{hunt_id}/shell-plans/{plan_id}/confirm")
    scanner = (ROOT / "scanner" / "scanner_tools" / "ssh_scanner.py").read_text()
    assert "confirm_exact_commands" in endpoint
    assert "confirm_remote_device_effects" in endpoint
    assert "device_shell.validate_shell_plan" in endpoint
    assert "confirmed_plan_digest" in endpoint
    assert "expected_host_key_fingerprint" in source
    assert "pty_allocated" in scanner and "stdin_forwarded" in scanner
    assert "subprocess" not in endpoint


def test_dashboard_queries_explicitly_exclude_the_device_product_plane():
    action_center = definition_source("_build_dashboard_action_center")
    dashboard = route_source("GET", "/dashboard")
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
    api = api_tree_source()
    schema = (ROOT / "db" / "init.sql").read_text()
    migration = (ROOT / "api" / "retest_contract.py").read_text()
    endpoint = route_source("POST", "/devices/{device_id}/locator")
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
    api = api_tree_source()
    detail = route_source("GET", "/devices/{device_id}")
    ui = (ROOT / "ui" / "src" / "app" / "devices" / "[id]" / "page.tsx").read_text()

    assert "device_locator_history" in detail
    assert "LIMIT 50" in detail
    assert '"locator_history"' in detail
    assert "Permanent device ID" in ui
    assert "Change address" in ui
    assert "same physical device" in ui


def test_device_detail_supports_display_name_changes_without_changing_identity():
    api = api_tree_source()
    api_client = (ROOT / "ui" / "src" / "lib" / "api.ts").read_text()
    ui = (ROOT / "ui" / "src" / "app" / "devices" / "[id]" / "page.tsx").read_text()
    endpoint = route_source("PATCH", "/devices/{device_id}")

    assert 'detail="Device name cannot be empty"' in endpoint
    assert 'payload["name"] = normalized_name' in endpoint
    assert "export async function renameDevice" in api_client
    assert "Rename connected device" in ui
    assert "This changes the display name only" in ui


def test_device_detail_scopes_udp_uncertainty_to_the_latest_posture_scan():
    api = api_tree_source()
    detail = route_source("GET", "/devices/{device_id}")
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
    api = api_tree_source()
    worker = (ROOT / "api" / "worker.py").read_text()
    detail_ui = (ROOT / "ui" / "src" / "app" / "devices" / "[id]" / "page.tsx").read_text()
    presentation = (ROOT / "ui" / "src" / "lib" / "deviceScanPresentation.mjs").read_text()
    list_ui = (ROOT / "ui" / "src" / "app" / "devices" / "page.tsx").read_text()

    assert "AS last_reachability" in api
    assert '"reachability": device_payload.get("last_reachability")' in api
    assert 'reachability.get("status") != "online"' in worker
    assert "Device reachability not checked" in detail_ui
    assert "deviceReachabilityServiceSummary" in detail_ui
    assert "service accessibility still being assessed" in presentation
    assert "previously confirmed service" in presentation
    assert "Reachability: not checked" in list_ui


def test_device_overviews_preserve_latest_posture_completeness():
    api = api_tree_source()
    detail_ui = (ROOT / "ui" / "src" / "app" / "devices" / "[id]" / "page.tsx").read_text()
    list_ui = (ROOT / "ui" / "src" / "app" / "devices" / "page.tsx").read_text()

    assert api.count("AS last_posture_complete") >= 2
    assert api.count("AS last_posture_decision") >= 2
    assert "deviceTargetScorePresentation(device)" in detail_ui
    assert "deviceTargetScorePresentation(device)" in list_ui
    assert "Provisional ${posture.grade}" in list_ui


def test_device_list_uses_bounded_reachability_summary():
    api = api_tree_source()
    listing = route_source("GET", "/devices")
    detail = route_source("GET", "/devices/{device_id}")

    assert "- 'attempts' - 'nmap_host_discovery'" in listing
    assert "- 'attempts' - 'nmap_host_discovery'" not in detail


def test_device_hunt_compatibility_routes_to_unified_hunt():
    detail_ui = (ROOT / "ui" / "src" / "app" / "devices" / "[id]" / "page.tsx").read_text()
    hunt_ui = (ROOT / "ui" / "src" / "app" / "devices" / "[id]" / "agent" / "page.tsx").read_text()
    skill = (ROOT / "skills" / "device-hunt" / "SKILL.md").read_text()
    skill_index = (ROOT / "skills" / "README.md").read_text()
    assert "href={`/devices/${device.id}/agent`}" in detail_ui
    assert "new URLSearchParams({ target: id })" in hunt_ui
    assert "redirect(`/hunt?${query.toString()}`)" in hunt_ui
    assert "name: device-hunt" in skill and "compatibility" in skill.lower()
    assert "[`device-hunt`](device-hunt/SKILL.md)" in skill_index
    assert "../hunt/SKILL.md" in skill


def test_unified_hunt_client_and_device_redirect_are_wired():
    api_client = (ROOT / "ui" / "src" / "lib" / "api.ts").read_text()
    hunt_client = (ROOT / "ui" / "src" / "lib" / "huntV2.ts").read_text()
    hunt_ui = (ROOT / "ui" / "src" / "app" / "devices" / "[id]" / "agent" / "page.tsx").read_text()

    generic_hunt = (ROOT / "ui" / "src" / "app" / "hunt" / "page.tsx").read_text()
    assert "export async function startHuntV2Native" in hunt_client
    assert "startAgentHuntSession" not in api_client
    assert "startDeviceAgentSession" not in api_client
    assert "export async function getHuntV2" in hunt_client
    assert "export async function getHuntV2" not in api_client
    assert "new URLSearchParams({ target: id })" in hunt_ui
    assert "redirect(`/hunt?${query.toString()}`)" in hunt_ui
    assert "startHuntV2Native" in generic_hunt
    assert "target_id" in generic_hunt


def test_unified_hunt_history_is_durable_and_target_bound():
    api = api_tree_source()
    hunt_router = (ROOT / "api" / "hunt" / "run_router.py").read_text()
    hunt_client = (ROOT / "ui" / "src" / "lib" / "huntV2.ts").read_text()
    hunt_ui = (ROOT / "ui" / "src" / "app" / "devices" / "[id]" / "agent" / "page.tsx").read_text()
    detail_ui = (ROOT / "ui" / "src" / "app" / "devices" / "[id]" / "page.tsx").read_text()
    assert "CREATE TABLE IF NOT EXISTS hunt_runs" in (ROOT / "api" / "retest_contract.py").read_text()
    assert route_is_declared("GET", "/hunts")
    assert route_is_declared("GET", "/hunts/{hunt_id}")
    assert "app.include_router(hunt_run_router)" in api
    assert "target_id" in hunt_client
    assert "new URLSearchParams({ target: id })" in hunt_ui
    assert "query.set('legacy_run', run)" in hunt_ui
    assert "redirect(`/hunt?${query.toString()}`)" in hunt_ui
    assert "href={`/devices/${device.id}/agent`}" in detail_ui


def test_device_findings_use_atomic_conflict_upsert():
    source = (ROOT / "api" / "worker.py").read_text()
    function = source[source.index("async def save_device_findings"):]
    function = function[:function.index("async def persist_device_inventory")]
    assert "ON CONFLICT (device_target_id, fingerprint)" in function
    assert "DO UPDATE SET" in function
    assert "SELECT id, status, resurfaced_count FROM findings" not in function
    assert "candidate_uuid, verification_id, str(finding_id), device_uuid" in function


def test_device_service_verifier_carries_candidate_contract_to_the_worker():
    function = definition_source("verify_device_service")

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
    source = (ROOT / "api" / "worker_handlers" / "device.py").read_text()
    branch = source[source.index("async def run_posture("):]
    assert "self.enabled()" in branch
    assert "DEVICE_POSTURE_ENABLED" in source
    assert 'device_options["_cancel_check"]' in branch


def test_web_retest_endpoints_reject_device_findings():
    source = api_tree_source()
    single = route_source("POST", "/findings/{finding_id:path}/retest")
    bulk = source[source.index("async def bulk_retest_findings"):]
    bulk = bulk.split("\n@app.", 1)[0]
    assert 'finding_data.get("source") == "device"' in single
    assert 'finding_data.get("device_target_id")' in single
    assert "device_findings_require_device_rescan" in bulk


def test_device_credentials_are_bound_encrypted_and_resolved_only_in_worker_memory():
    api = api_tree_source()
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
    api = api_tree_source()
    worker = (ROOT / "api" / "worker.py").read_text()
    assert "Credentialed device scans require safety_profile=authenticated_active" in api
    # The investigation-start copy lived in the deleted legacy session handler.
    # Canonical device Hunt enforces the same rule in the worker, immediately
    # before credentials are resolved -- asserted below against worker.py.
    assert '"credentials_visible_to_planner": False' in api
    assert 'device credentials require safety_profile=authenticated_active' in worker


def test_device_request_collections_are_encrypted_pinned_and_agent_bounded():
    api = api_tree_source()
    collection_api = (ROOT / "api" / "request_collection_api.py").read_text()
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
    assert route_is_declared("POST", "/devices/{device_id}/request-collections")
    assert "Encrypted storage is required for device request collections" in api
    assert 'summary = _json_object(payload.get("summary_json"))' in api
    assert "WHERE device_request_collections.is_active=false" in api
    update_handler = route_source(
        "PATCH", "/devices/{device_id}/request-collections/{collection_id}"
    )
    assert "is_active=true" not in update_handler
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
    assert "new URLSearchParams({ target: id })" in hunt
    assert "redirect(`/hunt?${query.toString()}`)" in hunt
    assert "CREATE TABLE request_collections" in schema
    assert route_is_declared("POST", "/request-collections")
    assert "libpcap0.8" in (ROOT / "scanner" / "Dockerfile").read_text()
    assert "allow_untrusted_tls_credentials" in api
    assert "untrusted_tls_credentials_not_confirmed" in web


def test_device_scan_activity_is_structured_and_user_facing():
    api = api_tree_source()
    worker = (ROOT / "api" / "worker.py").read_text()
    ui = (ROOT / "ui" / "src" / "app" / "devices" / "[id]" / "page.tsx").read_text()
    assert route_is_declared("GET", "/scans/{scan_id}/device-activity")
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
