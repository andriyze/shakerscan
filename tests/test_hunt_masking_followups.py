"""Masking follow-ups after #398: gaps the reviews listed as pre-existing, each reproduced first.

1. Capability outputs published a plain SHA-256 of target response data (authz.verify, request
   replays and mutations, SQLi/NoSQLi proofs, NSE, browser console text, device tools, workflow
   receipts): an offline guessing oracle for any secret in it, recognised by the masking or not.
2. ``<input type="password" value="...">`` was masked only when its name looked secret.
3. ``artifact.inspect`` learned dump columns from a 64 KB head cut mid-statement.
4. ``http.experiment`` selected values were guarded by name only, and a value extracted into a
   later step's path was shown in that step's request.

Every value below is a synthetic unit fixture, never a real secret.
"""

from __future__ import annotations

import ast
import asyncio
import html
import json
import random
import sys
from pathlib import Path

import httpx
import pytest

import tests.test_hunt_withheld_values_separators as hostile
from api.capabilities import artifact as artifact_capability
from api.http_experiment import response_summary

masking = sys.modules[artifact_capability.mask_body_text.__module__]
ROOT = Path(__file__).resolve().parents[1]
ACTION = "00000000-0000-4000-8000-0000000009b1"
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0.c2lnbmF0dXJlYnl0ZXM"
TOKEN = "Qx7vKpWz9kLmTy3mNbPb8nVcRc2hXz"


def _hunt(callable_, *args, **kwargs):
    collector = masking.WithheldValues(ACTION)
    with masking.collecting_withheld_values(collector):
        return callable_(*args, **kwargs), collector


# --- 1. No plain digest of response data in a published output ---------------------------------

# (module, the expressions whose plain digests were published). Each now uses the keyed digest.
PUBLISHED_DIGESTS = {
    "api/capabilities/authz_modes.py": ["hashlib.sha256(body)"],
    "api/capabilities/authz_selected.py": ["hashlib.sha256(owner_doc"],
    "api/runtime/request_replay_executor.py": ["hashlib.sha256(result.response_body)"],
    "api/capabilities/request_mutation.py": ["hashlib.sha256(result.response_body)"],
    "api/capabilities/sqli_proof.py": ["_sha256(control.response_body)", "_sha256(payload.response_body)"],
    "api/capabilities/nosqli_verify.py": ["_sha256(result.response_body)", "_sha256(literal.response_body)"],
    "api/capabilities/nse_http_transport.py": ["hashlib.sha256(response.response_body)"],
    "api/capabilities/browser.py": ["hashlib.sha256(text.encode())", "hashlib.sha256(message.encode())"],
    "api/capabilities/nse.py": ["hashlib.sha256(script_output"],
    "api/device_agent.py": ["hashlib.sha256(body_bytes)", "hashlib.sha256(encoded_value"],
    "api/devices/router.py": ['hashlib.sha256(bytes(replay.get("body")'],
    "api/workflow_experiment.py": ["hashlib.sha256(rendered_value", "hashlib.sha256(value.encode())"],
    "api/scan/action_adapter.py": ["hashlib.sha256(result.response_body)"],
    "scanner/scanner_tools/device_application.py": ["hashlib.sha256(body)", "hashlib.sha256(response_body)"],
    "scanner/scanner_tools/device_control_plane.py": ["hashlib.sha256(response_body)",
                                                      'hashlib.sha256(bytes(describe.get("body")'],
    "scanner/scanner_tools/device_web.py": ["hashlib.sha256(negative_body)", "hashlib.sha256(anonymous_body)",
                                            '"response_sha256": hashlib.sha256(response_body)'],
    "scanner/scanner_tools/discovery.py": ['hashlib.sha256(body_text', 'hashlib.sha256(response_body'],
    "scanner/scanner_tools/active_checks.py": ["hashlib.sha256(content_bytes)"],
    "scanner/scanner_tools/proof_of_exploit.py": ['hashlib.sha256(body.encode']
}


# Every plain hashlib.sha256/md5/sha1 call in the modules that build planner, agent, finding,
# evidence or export output (and the stores that hold them), found by AST, so a call split over
# lines is found too. Each one is listed by file and function with why it is not a digest of
# target response text. A new one fails until it is keyed or listed with its reason.
_SCANNED = ("api/capabilities", "api/hunt", "api/scan", "api/devices", "api/device_agent.py",
            "api/workflow_experiment.py", "api/http_experiment.py", "api/runtime/request_replay_executor.py",
            "scanner/scanner_tools", "api/evidence_storage.py", "api/runtime/observation_store.py",
            "api/runtime/sealed_inputs.py")
REASONS = {
    "integrity": "integrity of stored or transported content, compared with its own recorded digest",
    "finding": "a finding or record identity built from engine fields (title, URL, host, ids)",
    "canonical": "a canonical digest of an engine-built record (plan, manifest, attempt, proof)",
    "request": "a digest of request-side input the planner or operator supplied, never response text",
    "model": "model intake artifacts, keys and statements, not target responses",
    "public": "public material (certificates, host keys) whose digest is its fingerprint",
    "protocol": "the protocol requires it (HIBP k-anonymity SHA-1, PKCE S256)",
    "inprocess": "compared within one process and never published",
    "redacted": "the digest of text already redacted (or value-free) and shown beside it",
    "token": "a server-issued lease or idempotency token, matched by its digest",
    "compat": "matches digests recorded before 2.9.0 (comparison only, never published)",
}
ALLOWED_PLAIN_DIGESTS = {
    # Integration with 2.9.0: these hash validated conditions or already-visible metadata,
    # never target response bodies or selected secret values.
    ("api/hunt/interpretations.py", "conditions_digest"): "request",
    ("api/hunt/interpretations.py", "experiment_key"): "request",
    ("api/hunt/interpretations.py", "knowledge_document"): "integrity",
    ("api/hunt/knowledge_continue.py", "_with_authority"): "canonical",
    ("api/hunt/knowledge_dependencies.py", "_sha"): "redacted",
    ("api/scan/action_adapter.py", "_graphql_verify_batch"): "canonical",
    # recon_active: the response digest only compares two answers inside one action and is
    # never emitted (leads carry status and length); the list digest is of our own bundled file.
    ("api/scan/recon_active_actions.py", "_signature"): "inprocess",
    ("api/capabilities/recon_active.py", "load_bundled_list"): "integrity",
    ("api/capabilities/artifact.py", "_window_recorder"): "integrity",
    ("api/capabilities/artifact.py", "record"): "integrity",
    ("api/capabilities/auth.py", "_session_evidence_digest"): "redacted",
    ("api/capabilities/authz.py", "_identity_digest"): "finding",
    ("api/capabilities/authz.py", "authz_route_inventory_digest"): "canonical",
    ("api/capabilities/authz_modes.py", "verify_function_authorization"): "request",
    ("api/capabilities/authz_selected.py", "request_digest"): "canonical",
    ("api/capabilities/browser.py", "_execute_browser_action"): "request",
    ("api/capabilities/browser.py", "prepare"): "request",
    ("api/capabilities/browser_login_action.py", "prepare"): "request",
    ("api/capabilities/browser_steps.py", "browser_surface"): "redacted",
    ("api/capabilities/http.py", "_read_bounded_response"): "integrity",
    ("api/capabilities/nosqli_verify.py", "execute"): "request",
    ("api/capabilities/sqli_proof.py", "_sha256"): "request",
    ("api/capabilities/ssh_command_worker.py", "execute"): "request",
    ("api/capabilities/ssh_transport.py", "connect"): "public",
    ("api/capabilities/tls.py", "_certificate_chain_summary"): "public",
    # Presented public DER certificates have standard interoperable SHA-256 fingerprints.
    ("api/capabilities/tls.py", "_chain_details"): "public",
    ("api/capabilities/tls.py", "inspect_tls_origin"): "public",
    ("api/devices/collection_environments.py", "hydrate_environment"): "request",
    ("api/devices/router.py", "_execute_device_capability_operation"): "canonical",
    ("api/devices/router.py", "_verify_device_control_authorization_candidate"): "canonical",
    ("api/devices/router.py", "_verify_device_firmware_candidate"): "canonical",
    ("api/devices/worker_inputs.py", "hydrate_device_request_collections"): "request",
    ("api/evidence_storage.py", "_hydrate_s3_evidence"): "integrity",
    ("api/evidence_storage.py", "_inline_content_digests"): "integrity",
    ("api/evidence_storage.py", "_s3_signed_headers"): "integrity",
    ("api/evidence_storage.py", "hydrate_evidence_content"): "integrity",
    ("api/evidence_storage.py", "serialize_evidence_content"): "integrity",
    ("api/hunt/authorization_evidence.py", "attributed_outcome"): "token",
    ("api/hunt/authorization_evidence.py", "digest"): "canonical",
    ("api/hunt/authz_findings.py", "authz_finding_records"): "finding",
    ("api/hunt/boundary_discovery.py", "build_boundary_discovery"): "canonical",
    ("api/hunt/budget_amendments.py", "apply_budget_amendment"): "token",
    ("api/hunt/capability_reservations.py", "hunt_capability_action_digest"): "canonical",
    ("api/hunt/coverage_ledger.py", "coverage_fingerprint"): "finding",
    ("api/hunt/deterministic_findings.py", "_verified_xss_fingerprint"): "finding",
    ("api/hunt/endpoint_grouping.py", "as_row"): "finding",
    ("api/hunt/finding_actions.py", "create_hunt_finding"): "finding",
    ("api/hunt/fragment_xss_proof.py", "hunt_browser_xss_proof_adapter"): "request",
    ("api/hunt/interaction_router.py", "_execute_hunt_capability_lifecycle"): "request",
    ("api/hunt/interaction_router.py", "_hunt_confirmed_shell_capability_input"): "request",
    ("api/hunt/interaction_router.py", "_hunt_redacted_capability_input"): "request",
    ("api/hunt/investigation_memory.py", "key"): "finding",
    ("api/hunt/knowledge.py", "_endpoint_group_page"): "request",
    ("api/hunt/knowledge.py", "query_knowledge_page"): "request",
    ("api/hunt/permission_bounds.py", "digest"): "canonical",
    ("api/hunt/permission_grants.py", "_key_digest"): "canonical",
    ("api/hunt/permission_store.py", "canonical_digest"): "canonical",
    ("api/hunt/planner_lease.py", "accepts"): "token",
    ("api/hunt/planner_lease.py", "write_lease"): "token",
    ("api/hunt/skills.py", "build_skill_spec"): "request",
    ("api/hunt/skills.py", "read_skill_body"): "request",
    ("api/hunt/ssh_routing.py", "worker_key"): "finding",
    ("api/hunt/ssh_routing.py", "worker_queue"): "canonical",
    ("api/hunt/ssh_stream.py", "stream_ssh_command"): "request",
    ("api/runtime/observation_store.py", "load"): "integrity",
    ("api/runtime/observation_store.py", "persist"): "integrity",
    ("api/runtime/sealed_inputs.py", "open_private_input"): "integrity",
    ("api/runtime/sealed_inputs.py", "seal_private_input"): "integrity",
    ("api/scan/action_adapter.py", "_authz_surface_batch"): "canonical",
    ("api/scan/action_adapter.py", "_batch_candidate_id"): "canonical",
    ("api/scan/action_adapter.py", "_exposure_probe_batch"): "canonical",
    ("api/scan/action_adapter.py", "_external"): "canonical",
    ("api/scan/action_adapter.py", "_external_batch"): "canonical",
    ("api/scan/action_adapter.py", "_nosqli_verify_batch"): "canonical",
    ("api/scan/action_adapter.py", "_request_mutation_batch"): "canonical",
    ("api/scan/action_adapter.py", "_sqli_proof_batch"): "canonical",
    ("api/scan/action_adapter.py", "_xss_browser_proof_batch"): "canonical",
    ("api/scan/action_adapter.py", "run_stage"): "canonical",
    ("api/scan/action_plan.py", "_digest"): "canonical",
    ("api/scan/action_plan.py", "digest_input_bindings"): "canonical",
    ("api/scan/capability_execution.py", "scan_capability_action_digest"): "canonical",
    ("api/scan/capability_result.py", "__post_init__"): "canonical",
    ("api/scan/continuation.py", "_digest"): "canonical",
    ("api/scan/execution.py", "digest"): "canonical",
    ("api/scan/execution_backend.py", "_token_hash"): "token",
    ("api/scan/executor.py", "_digest"): "canonical",
    ("api/scan/external_process.py", "_canonical_digest"): "canonical",
    ("api/scan/finalizer.py", "_finding_identity"): "finding",
    ("api/scan/finalizer.py", "finalize_scan_report"): "integrity",
    ("api/scan/finding_identity.py", "_untemplated_fingerprint"): "finding",
    ("api/scan/finding_identity.py", "canonical_finding_fingerprint"): "finding",
    ("api/scan/finding_identity.py", "finding_identity_keys"): "finding",
    ("api/scan/finding_reconciliation.py", "legacy_finding_fingerprint"): "finding",
    ("api/scan/jobs.py", "payload_digest"): "canonical",
    ("api/scan/jobs.py", "scan_job_options_digest"): "canonical",
    ("api/scan/negative_control.py", "negative_control_entries"): "request",
    ("api/scan/parallel_compiler.py", "_digest"): "canonical",
    ("api/scan/parallel_compiler.py", "_work_partition_digest"): "canonical",
    ("api/scan/parallel_compiler.py", "parallel_action_occurrence_id"): "canonical",
    ("api/scan/parallel_inputs.py", "_owner_slot"): "canonical",
    ("api/scan/parity.py", "_finding_identity"): "finding",
    ("api/scan/parity.py", "build_scan_semantic_parity_artifact"): "canonical",
    ("api/scan/placement_transport.py", "_read_private_file"): "integrity",
    ("api/scan/placement_transport.py", "write_private_placement_bundle"): "integrity",
    ("api/scan/report_rebuild.py", "rebuild_scan_report"): "integrity",
    ("api/scan/sqli_stages.py", "stage_attempt_id"): "canonical",
    ("api/scan/stage_store.py", "_history_digest"): "canonical",
    ("api/scan/stage_store.py", "stage_row_digest"): "canonical",
    ("api/scan/stages/__init__.py", "_history_digest"): "canonical",
    ("api/scan/work_manifests.py", "_digest"): "canonical",
    ("api/workflow_experiment.py", "_create_object_readback"): "compat",
    ("api/workflow_experiment.py", "_value_fingerprint"): "inprocess",
    ("scanner/scanner_tools/access_control_checks.py", "authz_resource_replay_test"): "finding",
    ("scanner/scanner_tools/access_control_checks.py", "check_bola"): "finding",
    ("scanner/scanner_tools/access_control_checks.py", "check_bola_enumeration"): "finding",
    ("scanner/scanner_tools/access_control_checks.py", "check_bola_multi_user"): "finding",
    ("scanner/scanner_tools/access_control_checks.py", "check_mass_assignment"): "finding",
    ("scanner/scanner_tools/access_control_checks.py", "check_vertical_privilege_escalation"): "finding",
    ("scanner/scanner_tools/access_control_checks.py", "format_findings_for_scanner"): "finding",
    ("scanner/scanner_tools/access_control_checks.py", "smart_auth_access_test"): "finding",
    ("scanner/scanner_tools/access_control_checks.py", "smart_bola_test"): "finding",
    ("scanner/scanner_tools/asn_discovery.py", "_generate_findings"): "finding",
    ("scanner/scanner_tools/breach_check.py", "check_password_pwned"): "protocol",
    ("scanner/scanner_tools/breach_check.py", "generate_breach_findings"): "finding",
    ("scanner/scanner_tools/build_fingerprint.py", "hash_source_files"): "integrity",
    ("scanner/scanner_tools/common.py", "_output_artifact"): "redacted",
    ("scanner/scanner_tools/common.py", "_record_subprocess_receipt"): "redacted",
    ("scanner/scanner_tools/critical_checks.py", "test_default_credentials"): "finding",
    ("scanner/scanner_tools/deduplication_engine.py", "consolidate_graphql_findings"): "finding",
    ("scanner/scanner_tools/deduplication_engine.py", "generate_grouping_key"): "finding",
    ("scanner/scanner_tools/device_advisories.py", "_load_pinned_snapshot"): "integrity",
    # Signed intelligence bundles: the manifest names the snapshot's digest; a key id is the
    # fingerprint of a public key; a verify manifest entry binds a template id to the pinned bundle.
    ("scanner/scanner_tools/intel_bundle.py", "build_manifest"): "integrity",
    ("scanner/scanner_tools/intel_bundle.py", "key_id_for"): "public",
    ("api/scan/verify_templates.py", "_digest"): "canonical",
    ("scanner/scanner_tools/device_application.py", "_application_finding"): "finding",
    ("scanner/scanner_tools/device_control_plane.py", "_control_plane_finding"): "finding",
    ("scanner/scanner_tools/device_evidence.py", "_stable_id"): "finding",
    ("scanner/scanner_tools/device_postman.py", "resolve_requests"): "request",
    ("scanner/scanner_tools/device_postman.py", "validate_and_summarize"): "request",
    ("scanner/scanner_tools/device_posture.py", "evaluate_service_policy"): "finding",
    ("scanner/scanner_tools/device_request_formats.py", "_digest"): "canonical",
    ("scanner/scanner_tools/device_request_formats.py", "_request_id"): "canonical",
    ("scanner/scanner_tools/device_shell.py", "shell_plan_digest"): "canonical",
    ("scanner/scanner_tools/device_web.py", "_dir_discovery_findings"): "finding",
    ("scanner/scanner_tools/device_web.py", "_request"): "public",
    ("scanner/scanner_tools/device_web.py", "_request_finding"): "finding",
    ("scanner/scanner_tools/device_web.py", "_run_imported_requests"): "request",
    ("scanner/scanner_tools/device_web.py", "_security_header_findings"): "finding",
    ("scanner/scanner_tools/device_web.py", "add"): "finding",
    ("scanner/scanner_tools/device_web.py", "run_pinned_device_web_scan"): "finding",
    ("scanner/scanner_tools/discovery.py", "_run_ffuf_on_path"): "request",
    ("scanner/scanner_tools/discovery.py", "enhanced_tech_fingerprinting"): "finding",
    ("scanner/scanner_tools/finding_validator.py", "generate_finding_fingerprint"): "finding",
    ("scanner/scanner_tools/model_intake.py", "_acquire_huggingface_repository_snapshot"): "model",
    ("scanner/scanner_tools/model_intake.py", "_generate_aibom"): "model",
    ("scanner/scanner_tools/model_intake.py", "_inspect_safetensors"): "model",
    ("scanner/scanner_tools/model_intake.py", "_normalize_huggingface_manifest"): "model",
    ("scanner/scanner_tools/model_intake.py", "_public_key_sha256"): "model",
    ("scanner/scanner_tools/model_intake.py", "run_model_intake_scan"): "model",
    ("scanner/scanner_tools/model_intake_acquisition.py", "_hash_file"): "model",
    ("scanner/scanner_tools/model_intake_acquisition.py", "download_http_to_quarantine"): "model",
    ("scanner/scanner_tools/model_intake_acquisition.py", "quarantine_local_file"): "model",
    ("scanner/scanner_tools/model_intake_adapter_self_test.py", "_sha256_json"): "model",
    ("scanner/scanner_tools/model_intake_admission.py", "_public_key_fingerprint"): "model",
    ("scanner/scanner_tools/model_intake_admission.py", "build_technical_candidate"): "model",
    ("scanner/scanner_tools/model_intake_admission.py", "sign_statement"): "model",
    ("scanner/scanner_tools/model_intake_admission.py", "verify_package"): "model",
    ("scanner/scanner_tools/model_intake_attestation.py", "_public_key_fingerprint"): "model",
    ("scanner/scanner_tools/model_intake_attestation.py", "verify_dsse_in_toto"): "model",
    ("scanner/scanner_tools/model_intake_evaluation.py", "_digest"): "model",
    ("scanner/scanner_tools/model_intake_licenses.py", "_digest"): "model",
    ("scanner/scanner_tools/model_intake_runtime.py", "_sha256"): "model",
    ("scanner/scanner_tools/model_intake_runtime.py", "_tensor_ref"): "model",
    ("scanner/scanner_tools/model_intake_safetensors_runtime.py", "_sha256"): "model",
    ("scanner/scanner_tools/model_intake_safetensors_selftest.py", "_digest"): "model",
    ("scanner/scanner_tools/model_intake_sandbox.py", "_request_binding"): "model",
    ("scanner/scanner_tools/model_intake_sandbox.py", "_sha256_json"): "model",
    ("scanner/scanner_tools/model_intake_sandbox.py", "inspect_quarantine_object"): "model",
    ("scanner/scanner_tools/model_intake_scanners.py", "_default_external_parser"): "model",
    ("scanner/scanner_tools/model_intake_scanners.py", "_hash_path"): "model",
    ("scanner/scanner_tools/model_intake_scanners.py", "_output_digest"): "model",
    ("scanner/scanner_tools/model_intake_scanners.py", "_parse_external_scanner"): "model",
    ("scanner/scanner_tools/model_intake_scanners.py", "_sha256_json"): "model",
    ("scanner/scanner_tools/model_intake_scanners.py", "run_builtin_secret_scan"): "model",
    ("scanner/scanner_tools/model_intake_scanners.py", "run_external_scanner"): "model",
    ("scanner/scanner_tools/network_services.py", "_generate_findings"): "finding",
    ("scanner/scanner_tools/oauth_tests.py", "generate_pkce_pair"): "protocol",
    ("scanner/scanner_tools/race_condition_tests.py", "analyze_race_responses"): "inprocess",
    ("scanner/scanner_tools/request_replay.py", "_sha256"): "request",
    ("scanner/scanner_tools/sarif_output.py", "create_result"): "finding",
    ("scanner/scanner_tools/sarif_output.py", "generate_finding_fingerprint"): "finding",
    ("scanner/scanner_tools/scan_delta.py", "extract_finding_id"): "finding",
    ("scanner/scanner_tools/smtp_scanner.py", "_generate_smtp_findings"): "finding",
    ("scanner/scanner_tools/ssh_scanner.py", "_execute_ssh_shell_plan"): "request",
    ("scanner/scanner_tools/ssh_scanner.py", "ssh_host_key_fingerprint"): "public",
    ("scanner/scanner_tools/vendor_risk.py", "generate_vendor_findings"): "finding",
}


def _plain_digest_calls():
    """(file, enclosing function) of every plain hashlib digest call in _SCANNED."""
    found = set()
    for root in _SCANNED:
        path = ROOT / root
        for source in (sorted(path.rglob("*.py")) if path.is_dir() else [path]):
            tree = ast.parse(source.read_text(encoding="utf-8"))
            for function in ast.walk(tree):
                if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                for call in ast.walk(function):
                    if (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
                            and call.func.attr in {"sha256", "md5", "sha1"}
                            and isinstance(call.func.value, ast.Name) and call.func.value.id == "hashlib"):
                        found.add((str(source.relative_to(ROOT)), function.name))
    return found


def test_every_plain_digest_is_keyed_or_listed_with_its_reason():
    found = _plain_digest_calls()
    assert sorted(found - set(ALLOWED_PLAIN_DIGESTS)) == []
    assert all(reason in REASONS for reason in ALLOWED_PLAIN_DIGESTS.values())


def test_the_allowlist_holds_no_stale_entry():
    assert sorted(set(ALLOWED_PLAIN_DIGESTS) - _plain_digest_calls()) == []


@pytest.mark.parametrize("module", sorted(PUBLISHED_DIGESTS))
def test_no_plain_digest_of_response_data_is_published(module):
    source = (ROOT / module).read_text(encoding="utf-8")
    ast.parse(source)
    for expression in PUBLISHED_DIGESTS[module]:
        assert expression not in source, (module, expression)


def test_device_state_observations_publish_keyed_digests():
    from api import device_agent

    observation = device_agent.control_state_observation({"status": 200, "body": f'{{"token":"{TOKEN}"}}'.encode()})
    assert observation["body_sha256"].startswith("scrypt-")
    value = device_agent.control_json_pointer_value({"status": 200, "body": f'{{"pin":"{TOKEN}"}}'}, "/pin")
    assert value["found"] and value["value_sha256"].startswith("scrypt-")
    # Comparisons still hold within one installation.
    again = device_agent.control_state_observation({"status": 200, "body": f'{{"token":"{TOKEN}"}}'.encode()})
    assert again["body_sha256"] == observation["body_sha256"]


# --- 2. Password inputs, whatever their name ----------------------------------------------------

def _password_input(value: str, rng: random.Random) -> str:
    attributes = [
        rng.choice(['type="password"', "type='password'", "type=password", 'TYPE="PassWord"']),
        rng.choice(['name="p"', 'name="field_7"', 'id="x1"', ""]),
        rng.choice(['value="' + html.escape(value) + '"', "value='" + html.escape(value, quote=True) + "'"]),
    ]
    rng.shuffle(attributes)
    return "<form><input " + " ".join(item for item in attributes if item) + "></form>"


def test_password_inputs_are_withheld_whatever_their_name():
    rng = random.Random(2903)
    for value in hostile.HOSTILE[:24]:
        if len(value) > 2000:
            continue
        body = _password_input(value, rng)
        template = masking.mask_body_text(_password_input("Zz", random.Random(0)))
        for shown in (masking.mask_body_text(body), _hunt(masking.mask_body_text, body)[0]):
            assert hostile._hostile_leaks(shown, value, template) == [], body


def test_a_password_input_value_is_a_reference_that_binds_it():
    shown, collector = _hunt(masking.mask_body_text, '<input value="Hunter2Pass!x" type="password" name="p">')
    assert shown == '<input value="[withheld:1]" type="password" name="p">'
    assert collector.values == ["Hunter2Pass!x"]


@pytest.mark.parametrize("text", [
    '<input type="text" name="q" value="hello world">',
    '<p>type="password" value="shown in prose"</p>',
    '<input type="hidden" name="page" value="2">',
])
def test_other_inputs_and_prose_are_unchanged(text):
    assert masking.mask_body_text(text) == text


# --- 3. A head cut mid-statement teaches no columns ---------------------------------------------

def test_a_create_table_cut_by_the_head_teaches_nothing_from_its_cut_list():
    assert artifact_capability._whole_statements("a\nCREATE TABLE users (id int,\n name text,\n p") == "a\n"
    assert artifact_capability._whole_statements("CREATE TABLE t (a int);\nINSERT INTO t") == (
        "CREATE TABLE t (a int);\n")


def test_a_dump_head_read_past_the_probe_learns_the_whole_column_list():
    head = "-- " + "x" * (artifact_capability.HEAD_PROBE_BYTES - 30 - 4) + "\n"
    dump = head + "CREATE TABLE users (id int, name text, password text);\n"
    assert len(head) < artifact_capability.HEAD_PROBE_BYTES < len(dump)
    row = "INSERT INTO users VALUES (1,'bob','Zq9vLmT4pRw2Hq');\n"
    collector = masking.WithheldValues(ACTION)
    tables: dict = {}
    for read in (dump.encode()[:artifact_capability.HEAD_PROBE_BYTES], dump.encode()[:artifact_capability.HEAD_READ_BYTES]):
        tables = {}
        collector.sql_tables = {"/backup.sql": tables}
        artifact_capability._learn_head(collector, tables, "/backup.sql", read, {"content-type": "application/sql"})
        columns = [value for key, value in tables.items() if not key.startswith("\0")]
        assert ["id", "name", "p"] not in columns  # never the cut list
    later = masking.WithheldValues(ACTION)
    later.sql_tables, later.sql_path, later.sql_dump_like = collector.sql_tables, "/backup.sql", True
    with masking.collecting_withheld_values(later):
        shown = masking.mask_body_text(row, window=True)
    assert "Zq9vLmT4pRw2Hq" not in shown


# --- 4. Selected and extracted values -----------------------------------------------------------

def _selected(document: dict, paths: list[str], *, hunt: bool):
    body = json.dumps(document).encode()
    response = httpx.Response(200, headers={"content-type": "application/json"}, content=body)
    if hunt:
        return _hunt(response_summary, response, body, selected_json_paths=paths)
    return response_summary(response, body, selected_json_paths=paths), None


@pytest.mark.parametrize("hunt", [False, True])
def test_a_selected_value_is_masked_by_its_shape(hunt):
    document = {"data": {"jwt": JWT, "auth": f"Bearer {TOKEN}", "opaque": TOKEN, "role": "admin", "id": 42}}
    paths = ["$.data.jwt", "$.data.auth", "$.data.opaque", "$.data.role", "$.data.id"]
    summary, collector = _selected(document, paths, hunt=hunt)
    selected = summary["selected_json"]
    text = json.dumps(selected)
    for secret in (JWT, TOKEN):
        assert secret not in text, secret
    assert selected["$.data.role"] == "admin" and selected["$.data.id"] == 42
    assert selected["$.data.auth"].startswith("Bearer ") or selected["$.data.auth"].startswith("***")
    if hunt:
        assert JWT in collector.values and TOKEN in collector.values
        assert {entry["marker"] for entry in summary["withheld_values"]} >= {"[withheld:1]"}
    else:
        assert selected["$.data.opaque"].startswith("*** (withheld scrypt-")


def test_two_different_secrets_still_read_as_a_change():
    from api.http_experiment import compare_summaries

    first, _ = _selected({"v": "Aa1" + TOKEN}, ["$.v"], hunt=False)
    second, _ = _selected({"v": "Bb2" + TOKEN}, ["$.v"], hunt=False)
    same, _ = _selected({"v": "Aa1" + TOKEN}, ["$.v"], hunt=False)
    assert ("Aa1" + TOKEN) not in json.dumps(first["selected_json"])
    assert compare_summaries(first, second)["selected_json_changed"]
    assert not compare_summaries(first, same)["selected_json_changed"]


def test_an_extracted_value_rendered_into_a_path_is_not_shown():
    from api import http_experiment as experiment

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/login":
            return httpx.Response(200, json={"session": {"next": TOKEN}})
        return httpx.Response(200, json={"ok": True})

    payload = {
        "steps": [
            {"label": "control", "method": "GET", "path": "/login",
             "extract": [{"name": "next_id", "source": "json", "path": "$.session.next"}]},
            {"label": "candidate", "method": "GET", "path": "/r/${next_id}", "compare_to": "control"},
        ],
    }
    seen: list[str] = []
    transport = httpx.MockTransport(lambda request: (seen.append(request.url.path), handler(request))[1])
    result = asyncio.run(experiment.execute_experiment("https://example.test", payload, transport=transport))
    assert seen == ["/login", f"/r/{TOKEN}"]  # the value was sent
    text = json.dumps(result)
    assert TOKEN not in text
    assert result["observations"][1]["request"]["path"] == "/r/${next_id}"


# --- Review of the follow-up ------------------------------------------------------------------

def test_the_guard_finds_a_multi_line_call(tmp_path, monkeypatch):
    module = tmp_path / "api" / "capabilities"
    module.mkdir(parents=True)
    (module / "probe.py").write_text("import hashlib\n\ndef f(response):\n    return hashlib.sha256(\n        response.body\n    ).hexdigest()\n")
    monkeypatch.setattr(sys.modules[__name__], "ROOT", tmp_path)
    monkeypatch.setattr(sys.modules[__name__], "_SCANNED", ("api/capabilities",))
    assert _plain_digest_calls() == {("api/capabilities/probe.py", "f")}


def test_a_masked_export_carries_no_plain_digest_of_the_raw_body():
    """Already so on main (``_plan`` drops recorded digests from every masked export); pinned here
    because the review of this change read the export path as publishing them."""
    from api.runtime.http_archive_reader import export_document

    body = f"DB_PASSWORD={TOKEN}\n"
    import hashlib

    plain = hashlib.sha256(body.encode()).hexdigest()
    row = {"id": "00000000-0000-4000-8000-0000000009b9", "plane": "hunt", "sequence": 0,
           "hunt_run_id": ACTION, "hunt_action_id": ACTION, "capability_name": "http.request",
           "method": "GET", "url": "https://h.fixture.test/.env", "status_code": 200,
           "request_headers": {}, "request_body": None, "response_headers": {},
           "response_body": body, "response_body_sha256": plain, "metadata_json": {}}
    masked = json.dumps(export_document([row], export_format="transactions", redaction="redacted",
                                        owner={"hunt_id": ACTION}, total=1))
    assert plain not in masked and TOKEN not in masked
    assert '"sha256": null' in masked


@pytest.mark.parametrize("text, secret", [
    ('<input type="password" value="a>b Hunter2xx">', "Hunter2xx"),
    ('<input type=password name=x value="' + "A" * 5000 + 'Hunter2xx"><p>after</p>', "Hunter2xx"),
    ('<input type="password" value="open Hunter2xx', "Hunter2xx"),
    ('<input type="password" value="open Hunter2xx\n<p>x</p>', "Hunter2xx"),
    ("<input\ttype = 'pass&#119;ord'\nvalue=Hunter2xx/>", "Hunter2xx"),
])
def test_password_input_bypasses_are_closed(text, secret):
    for shown in (masking.mask_body_text(text), _hunt(masking.mask_body_text, text)[0]):
        assert secret not in shown, shown
    assert "<p>after</p>" in masking.mask_body_text(text) or "after" not in text


def test_password_input_scanning_is_linear():
    import time

    for text in ('<input "' * 40_000, '<input type=password value="x' * 12_000, "<input type=password value=x>" * 12_000):
        started = time.perf_counter()
        masking.mask_body_text(text)
        assert time.perf_counter() - started < 5


@pytest.mark.parametrize("text", [
    "CREATE TABLE users (id int, note text DEFAULT 'a;b',\n pw\n",
    "CREATE TABLE users (id int, n text COMMENT 'x; y',\n -- legacy; keep\n pw\n",
    "CREATE TABLE `us;ers` (id int,\n /* a; b */ pw\n",
])
def test_a_semicolon_inside_a_cut_column_list_teaches_nothing(text):
    assert artifact_capability._whole_statements(text) == ""


def test_closed_column_lists_are_kept():
    text = "CREATE TABLE t (a int, b text DEFAULT 'x;y', c text COMMENT 'p; q') ENGINE=InnoDB\n;\n"
    assert artifact_capability._whole_statements(text) == text


def test_selected_descriptors_and_arrays_follow_the_body_rules():
    assert masking.mask_selected_value({"name": "password", "value": "Winter2023"})["value"] == "***"
    assert masking.mask_selected_value([{"key": "DB_PASSWORD", "value": "Winter2023x"}])[0]["value"] == "***"


@pytest.mark.parametrize("text", ["Basic authentication required", "token validation failed",
                                  "basic subscription plan", "admin", "ROLE_ADMIN"])
def test_prose_and_roles_are_not_read_as_credentials(text):
    assert masking.mask_selected_string(text) == text


def test_a_bearer_credential_in_a_selected_value_is_withheld():
    assert TOKEN not in masking.mask_selected_string(f"Bearer {TOKEN}")
    assert "abcDEF123456xyz" not in masking.mask_selected_string("Bearer abcDEF123456xyz")


# --- Redaction is total: text shaped like a broken URL never raises --------------------------

_URL_ATOMS = ("x://", "scheme://", "http://", "https://", "redis://", "host", "[", "]", ":", "port", "[::1",
              "@", "u:pw", ":99999", ":abc", "/", "?", "#", "token=", "access_token=", "&", "%", "%40",
              "%5B", " ", "\n", '"', "'", "{", "}", "é", "\x00")
BROKEN_URLS = [
    "x://host[", "scheme://host[:port]", "http://[::1", "http://u:pw@h:99999/?token=abc",
    "http://u:pw@h:abc/", "The origin must be scheme://host[:port] with nothing else.",
    "origin: scheme://host[:port] of the service", "http://[::1]:99999/x?token=a",
]


def _hostile_url_strings(count: int, seed: int) -> list[str]:
    rng = random.Random(seed)
    return BROKEN_URLS + ["".join(rng.choice(_URL_ATOMS) for _ in range(rng.randint(1, 24)))
                          for _ in range(count)]


def test_redaction_entry_points_never_raise_on_url_shaped_text():
    import api.api as api_module
    from scanner.redaction import redact_sensitive, redact_text, redact_url_credentials
    from scanner.scanner_tools.url_redaction import redact_url

    entry_points = (
        redact_url_credentials, redact_text, redact_url,
        lambda text: redact_sensitive({"description": text, "nested": [text]}, redact_strings=True, scrub_text=True),
        api_module._redact_agent_payload, api_module._redact_agent_text,
        masking.mask_body_text, masking.mask_url_secrets, masking.withhold_url_userinfo,
        lambda text: masking.bounded_public_url(text, 200),
        masking.mask_url_userinfo_redacted,
    )
    for text in _hostile_url_strings(3_000, seed=4051):
        for entry in entry_points:
            entry(text)  # raises nothing
        with masking.collecting_withheld_values(masking.WithheldValues(ACTION)):
            masking.mask_body_text(text)
            masking.bounded_public_url(text, 200)


def test_an_unparseable_url_still_has_its_credentials_withheld():
    from scanner.redaction import redact_url_credentials

    shown = redact_url_credentials("http://u:Pw0rdSecret9@h:99999/?access_token=Tk0123456789&x=1")
    assert "Pw0rdSecret9" not in shown and "Tk0123456789" not in shown and "x=1" in shown


def test_a_record_with_a_broken_url_shaped_description_exports():
    from api.runtime.http_archive_reader import export_document

    row = {"id": "00000000-0000-4000-8000-0000000009ba", "plane": "hunt", "sequence": 0,
           "hunt_run_id": ACTION, "hunt_action_id": ACTION, "capability_name": "http.request",
           "method": "GET", "url": "https://h.fixture.test/x", "status_code": 200,
           "request_headers": {"x-origin": "scheme://host[:port]"}, "request_body": None,
           "response_headers": {"link": "<http://[::1>; rel=next"},
           "response_body": "origin: scheme://host[:port] http://u:pw@h:99999/",
           "metadata_json": {"description": "The origin must be scheme://host[:port]"}}
    for redaction in ("redacted", "raw"):
        export_document([row], export_format="transactions", redaction=redaction,
                        owner={"hunt_id": ACTION}, total=1)


# --- Review of #405 (09c352b7) ----------------------------------------------------------------

def test_proof_events_are_digested_cheaply_and_boundedly():
    import time

    from api.capabilities import browser

    events: list[dict] = []
    started = time.perf_counter()
    for index in range(2_000):
        events.append({"message_sha256": browser._event_digest(events, f"log {index}")})
    assert time.perf_counter() - started < 1.0  # HMAC, never scrypt, per event
    digested = [event["message_sha256"] for event in events if event["message_sha256"]]
    assert len(digested) == browser.MAX_DIGESTED_PROOF_EVENTS
    assert all(item.startswith("hmac-sha256-") for item in digested)


@pytest.mark.parametrize("module, function", [
    ("api.capabilities.request_mutation", "_body_sha256"),
])
def test_per_probe_digests_are_hmac(module, function):
    import importlib
    import types

    helper = getattr(importlib.import_module(module), function)
    assert helper(types.SimpleNamespace(response_body=TOKEN.encode())).startswith("hmac-sha256-")


def test_withheld_jwts_carry_only_keyed_digests():
    import base64

    def segment(value):
        return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")

    token = ".".join((segment({"alg": "HS256"}), segment({"role": "anon"}), "signaturebytes"))
    import hashlib

    plain = hashlib.sha256(token.encode()).hexdigest()
    analysis = artifact_capability.analyze_javascript_bytes(f'const t="{token}";'.encode())
    assert plain not in json.dumps(analysis)
    assert analysis["jwt_observations"][0]["token_sha256"].startswith("hmac-sha256-")
    marker = artifact_capability._jwt_replacement(artifact_capability._JWT_RE.search(token))
    assert plain[:16] not in marker and marker.startswith("<jwt:")


def test_resource_ids_carry_only_keyed_digests():
    source = (ROOT / "api/capabilities/authz_selected.py").read_text() + (ROOT / "api/capabilities/authz.py").read_text() \
        + (ROOT / "api/hunt/authorization_service.py").read_text()
    assert "resource_id_sha256\": hashlib" not in source and "resource_id_sha256=hashlib" not in source
    assert source.count("keyed_body_digest(") >= 4


@pytest.mark.parametrize("query", [
    "?API%5FKEY={s}", "?token+={s}", "?%74oken={s}", "?Api-Key={s}", "?x=1&token={s}", "?client_secret={s}",
    "/p;token={s}",
])
@pytest.mark.parametrize("base", ["http://h:99999", "http://[::1", "http://h:80"])
def test_url_redaction_reads_parameter_names_as_a_server_does(base, query):
    from scanner.redaction import redact_url_credentials

    assert TOKEN not in redact_url_credentials(base + "/" + query.format(s=TOKEN))


@pytest.mark.parametrize("text", [
    'html = "<input type=\\"password\\" value=\\"Hn4tGhPb8nVcQ\\">";',
    'html = "\\u003cinput type=\\u0022password\\u0022 value=\\u0022Hn4tGhPb8nVcQ\\u0022\\u003e";',
    "&lt;input type=&quot;password&quot; value=&quot;Hn4tGhPb8nVcQ&quot;&gt;",
    "el.innerHTML = '<input type=\"password\" value=\"Hn4tGhPb8nVcQ\">';",
])
def test_escaped_password_inputs_are_withheld(text):
    for shown in (masking.mask_body_text(text), _hunt(masking.mask_body_text, text)[0]):
        assert "Hn4tGhPb8nVcQ" not in shown, shown


def test_two_unreferenceable_selected_values_still_read_as_a_change():
    """A value over the reference size limit is ``***`` inside a Hunt; it carries its keyed
    digest, so two such values in one experiment still compare different."""
    from api.http_experiment import compare_summaries

    collector = masking.WithheldValues(ACTION)
    summaries = []
    for value in ("Bearer Aa1" + TOKEN * 300, "Bearer Bb2" + TOKEN * 300):  # one over-limit credential each
        body = json.dumps({"v": value}).encode()
        with masking.collecting_withheld_values(collector):
            summaries.append(response_summary(httpx.Response(200, headers={"content-type": "application/json"},
                                                             content=body), body, selected_json_paths=["$.v"]))
    first, second = summaries
    assert first["selected_json"]["$.v"].startswith("Bearer *** (withheld scrypt-")
    assert TOKEN not in json.dumps(first["selected_json"])
    assert compare_summaries(first, second)["selected_json_changed"]
