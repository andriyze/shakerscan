#!/usr/bin/env python3
"""
ShakerScan API - Open Source Edition
FastAPI server with PostgreSQL persistence and Redis queue.
"""

import asyncio
import base64
import copy
import contextvars
import fnmatch
import hashlib
import hmac
import http
import io
import importlib
import ipaddress
import json
import logging
import math
import os
import random
import re
import secrets
import shlex
import shutil
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile
from collections import Counter
from contextlib import asynccontextmanager
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated, Any, Literal, Mapping, Optional, Sequence, Union
from zoneinfo import ZoneInfo

import asyncpg
import redis
try:
    from release_identity import build_fingerprint as release_build_fingerprint
    from release_identity import load_release_identity
    from release_identity import published_scanner_version
except ModuleNotFoundError:
    from scanner.release_identity import build_fingerprint as release_build_fingerprint
    from scanner.release_identity import load_release_identity
    from scanner.release_identity import published_scanner_version
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response, JSONResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

try:
    from app_lifecycle import ApiLifecycleDependencies, create_api_lifespan
except ModuleNotFoundError:
    from api.app_lifecycle import ApiLifecycleDependencies, create_api_lifespan

try:
    from scanner_tools.build_fingerprint import hash_source_files, runtime_file_map, source_file_map
except ModuleNotFoundError:
    from scanner.scanner_tools.build_fingerprint import hash_source_files, runtime_file_map, source_file_map

try:
    from scanner_tools.device_posture import DEVICE_PROFILES, normalize_device_locator
except ModuleNotFoundError:
    from scanner.scanner_tools.device_posture import DEVICE_PROFILES, normalize_device_locator

try:
    from scanner_tools.device_safety import safety_profile_catalog, validate_safety_request
except ModuleNotFoundError:
    from scanner.scanner_tools.device_safety import safety_profile_catalog, validate_safety_request

try:
    from scanner_tools import device_shell
    from scanner_tools import device_advisories
except ModuleNotFoundError:
    from scanner.scanner_tools import device_shell
    from scanner.scanner_tools import device_advisories

try:
    from scanner_tools.request_collections import (
        RequestImportError,
        RequestSelector,
        page_index as page_request_collection_index,
        select_requests as select_request_collection_requests,
        validate_and_index as validate_and_index_request_collection,
        validate_request_collection as validate_device_request_collection,
    )
except ModuleNotFoundError:
    from scanner.scanner_tools.request_collections import (
        RequestImportError,
        RequestSelector,
        page_index as page_request_collection_index,
        select_requests as select_request_collection_requests,
        validate_and_index as validate_and_index_request_collection,
        validate_request_collection as validate_device_request_collection,
    )

try:
    from scanner_tools.request_replay import build_selected_replay_plan
except ModuleNotFoundError:
    from scanner.scanner_tools.request_replay import build_selected_replay_plan

try:
    from scanner_tools.device_request_formats import resolve_imported_requests as _resolve_imported_device_requests
    from scanner_tools.device_web import (
        paired_reverse_request as _device_paired_reverse_request,
        public_device_response_headers as _device_public_response_headers,
        request_pinned_device_control_http as _device_request_pinned_control_http,
        request_pinned_device_http as _device_request_pinned_http,
        strip_credential_headers as _device_strip_credential_headers,
    )
except ModuleNotFoundError:
    from scanner.scanner_tools.device_request_formats import resolve_imported_requests as _resolve_imported_device_requests
    from scanner.scanner_tools.device_web import (
        paired_reverse_request as _device_paired_reverse_request,
        public_device_response_headers as _device_public_response_headers,
        request_pinned_device_control_http as _device_request_pinned_control_http,
        request_pinned_device_http as _device_request_pinned_http,
        strip_credential_headers as _device_strip_credential_headers,
    )

try:
    from scanner_tools.model_intake_acquisition import acquisition_policy as _model_acquisition_policy
    from scanner_tools.model_intake_acquisition import download_http as _model_download_http
except ModuleNotFoundError:
    from scanner.scanner_tools.model_intake_acquisition import acquisition_policy as _model_acquisition_policy
    from scanner.scanner_tools.model_intake_acquisition import download_http as _model_download_http

try:
    from scanner_tools.model_intake_registry import adapter_capabilities as _model_adapter_capabilities
    from scanner_tools.model_intake_registry import adapter_catalog as _model_adapter_catalog
except ModuleNotFoundError:
    from scanner.scanner_tools.model_intake_registry import adapter_capabilities as _model_adapter_capabilities
    from scanner.scanner_tools.model_intake_registry import adapter_catalog as _model_adapter_catalog

try:
    from scanner_tools.model_intake_scanners import (
        scan_materialized_snapshot as _scan_materialized_model_snapshot,
        scanner_adapter_readiness as _model_scanner_adapter_readiness,
    )
except ModuleNotFoundError:
    from scanner.scanner_tools.model_intake_scanners import (
        scan_materialized_snapshot as _scan_materialized_model_snapshot,
        scanner_adapter_readiness as _model_scanner_adapter_readiness,
    )

try:
    from scanner_tools.model_intake_providers import provider_readiness as _model_provider_readiness
except ModuleNotFoundError:
    from scanner.scanner_tools.model_intake_providers import provider_readiness as _model_provider_readiness

try:
    from scanner_tools.model_intake_admission import (
        trusted_public_keys_from_env as _model_admission_trusted_keys,
        verify_package as _verify_model_admission_package,
    )
except ModuleNotFoundError:
    from scanner.scanner_tools.model_intake_admission import (
        trusted_public_keys_from_env as _model_admission_trusted_keys,
        verify_package as _verify_model_admission_package,
    )

try:
    from scanner_tools.model_intake_evaluation import evaluate as _evaluate_model_intake_request
except ModuleNotFoundError:
    from scanner.scanner_tools.model_intake_evaluation import evaluate as _evaluate_model_intake_request

try:
    from model_intake_admissions import REASSESSMENT_TRIGGERS, triggered_status as _model_admission_triggered_status
except ModuleNotFoundError:
    from api.model_intake_admissions import REASSESSMENT_TRIGGERS, triggered_status as _model_admission_triggered_status

try:
    from model_intake_control_plane import (
        AdmissionContractError as _ModelAdmissionContractError,
        LocalPemSigner as _ModelLocalPemSigner,
        build_approval_receipt as _build_model_approval_receipt,
        build_deployment_bundle as _build_model_deployment_bundle,
        evaluate_policy as _evaluate_model_admission_policy,
        freeze_evidence_manifest as _freeze_model_evidence_manifest,
        issue_admission_v2 as _issue_model_admission_v2,
        policy_bundle_identity as _model_policy_bundle_identity,
        verify_admission_v2 as _verify_model_admission_v2,
    )

except ModuleNotFoundError:
    from api.model_intake_control_plane import (
        AdmissionContractError as _ModelAdmissionContractError,
        LocalPemSigner as _ModelLocalPemSigner,
        build_approval_receipt as _build_model_approval_receipt,
        build_deployment_bundle as _build_model_deployment_bundle,
        evaluate_policy as _evaluate_model_admission_policy,
        freeze_evidence_manifest as _freeze_model_evidence_manifest,
        issue_admission_v2 as _issue_model_admission_v2,
        policy_bundle_identity as _model_policy_bundle_identity,
        verify_admission_v2 as _verify_model_admission_v2,
    )

try:
    from model_intake_runner_receipts import (
        EVIDENCE_POLICY as _MODEL_RUNNER_EVIDENCE_POLICY,
        verify_runner_envelope as _verify_model_runner_envelope,
    )
except ModuleNotFoundError:
    from api.model_intake_runner_receipts import (
        EVIDENCE_POLICY as _MODEL_RUNNER_EVIDENCE_POLICY,
        verify_runner_envelope as _verify_model_runner_envelope,
    )

try:
    from model_intake_loader_profiles import resolve_conversion_profile as _resolve_model_conversion_profile
    from model_intake_loader_profiles import resolve_loader_profile as _resolve_model_loader_profile
    from model_intake_runner_controller import firecracker_readiness as _model_firecracker_readiness
    from model_intake_runner_controller import runner_memory_admission as _model_runner_memory_admission
except ModuleNotFoundError:
    from api.model_intake_loader_profiles import resolve_conversion_profile as _resolve_model_conversion_profile
    from api.model_intake_loader_profiles import resolve_loader_profile as _resolve_model_loader_profile
    from api.model_intake_runner_controller import firecracker_readiness as _model_firecracker_readiness
    from api.model_intake_runner_controller import runner_memory_admission as _model_runner_memory_admission

try:
    from model_intake_agent import (
        embedding_test_plan as _model_intake_embedding_test_plan,
        parse_planner_reply as _parse_model_intake_planner_reply,
        planner_prompt as _model_intake_planner_prompt,
    )
except ModuleNotFoundError:
    from api.model_intake_agent import (
        embedding_test_plan as _model_intake_embedding_test_plan,
        parse_planner_reply as _parse_model_intake_planner_reply,
        planner_prompt as _model_intake_planner_prompt,
    )

try:
    from model_intake_runner_evaluation import derive_embedding_evaluation as _derive_model_runner_embedding_evaluation
except ModuleNotFoundError:
    from api.model_intake_runner_evaluation import derive_embedding_evaluation as _derive_model_runner_embedding_evaluation

try:
    from model_intake_runner_inputs import suite_identity as _model_intake_runner_input_suite
except ModuleNotFoundError:
    from api.model_intake_runner_inputs import suite_identity as _model_intake_runner_input_suite

try:
    from model_intake_components import component_identities as _model_intake_component_identities
except ModuleNotFoundError:
    from api.model_intake_components import component_identities as _model_intake_component_identities

try:
    from model_intake_sbom import (
        build_model_intake_cyclonedx as _build_model_intake_cyclonedx,
        build_model_intake_license_bom as _build_model_intake_license_bom,
        build_model_intake_spdx as _build_model_intake_spdx,
        model_intake_bom_completeness as _model_intake_bom_completeness,
        model_intake_license_display as _model_intake_license_display,
        render_third_party_notices_draft as _render_model_intake_third_party_notices,
    )
except ModuleNotFoundError:
    from api.model_intake_sbom import (
        build_model_intake_cyclonedx as _build_model_intake_cyclonedx,
        build_model_intake_license_bom as _build_model_intake_license_bom,
        build_model_intake_spdx as _build_model_intake_spdx,
        model_intake_bom_completeness as _model_intake_bom_completeness,
        model_intake_license_display as _model_intake_license_display,
        render_third_party_notices_draft as _render_model_intake_third_party_notices,
    )

try:
    from model_intake_reporting import (
        EXTERNAL_APPROVAL_REQUIREMENTS as _MODEL_INTAKE_EXTERNAL_REQUIREMENTS,
        SHAKERSCAN_CHECK_CATALOG as _MODEL_INTAKE_CHECK_CATALOG,
        apply_automatic_review_context as _apply_model_intake_automatic_review_context,
        build_model_intake_report as _build_model_intake_report,
        model_intake_report_to_sarif as _model_intake_report_to_sarif,
        render_model_intake_html as _render_model_intake_html,
    )
except ModuleNotFoundError:
    from api.model_intake_reporting import (
        EXTERNAL_APPROVAL_REQUIREMENTS as _MODEL_INTAKE_EXTERNAL_REQUIREMENTS,
        SHAKERSCAN_CHECK_CATALOG as _MODEL_INTAKE_CHECK_CATALOG,
        apply_automatic_review_context as _apply_model_intake_automatic_review_context,
        build_model_intake_report as _build_model_intake_report,
        model_intake_report_to_sarif as _model_intake_report_to_sarif,
        render_model_intake_html as _render_model_intake_html,
    )

try:
    from scanner_tools.model_intake_retention import execute_cleanup as _execute_model_quarantine_cleanup
    from scanner_tools.model_intake_retention import plan_cleanup as _plan_model_quarantine_cleanup
except ModuleNotFoundError:
    from scanner.scanner_tools.model_intake_retention import execute_cleanup as _execute_model_quarantine_cleanup
    from scanner.scanner_tools.model_intake_retention import plan_cleanup as _plan_model_quarantine_cleanup

try:
    from constants import SMART_SCAN_BUDGETS, resolve_scan_budget, resolve_or_consume_budget
except ModuleNotFoundError as exc:
    if exc.name != "constants":
        raise
    from scanner.constants import SMART_SCAN_BUDGETS, resolve_scan_budget, resolve_or_consume_budget

try:
    from redaction import (
        SENSITIVE_KEYS,
        SENSITIVE_KEY_FRAGMENTS,
        is_sensitive_key,
        mask_secret,
        redact_sensitive,
        redact_text,
    )
except ModuleNotFoundError as exc:
    if exc.name != "redaction":
        raise
    from scanner.redaction import (
        SENSITIVE_KEYS,
        SENSITIVE_KEY_FRAGMENTS,
        is_sensitive_key,
        mask_secret,
        redact_sensitive,
        redact_text,
    )

try:
    from secret_store import decrypt_secret, encrypt_secret, encryption_enabled
except ModuleNotFoundError:
    from api.secret_store import decrypt_secret, encrypt_secret, encryption_enabled

try:
    from ai_control_requirements import AI_CONTROL_REQUIREMENTS
except ModuleNotFoundError:
    from api.ai_control_requirements import AI_CONTROL_REQUIREMENTS

DEVICE_RUN_KINDS = {"device_posture", "device_probe", "device_web_dast"}
DEVICE_FINDING_SOURCE = "device"





try:
    from evidence_triage import (
        build_evidence_with_triage as _build_evidence_with_triage,
        redact_finding_evidence as _redact_finding_evidence,
    )
except ModuleNotFoundError as exc:
    if exc.name != "evidence_triage":
        raise
    from api.evidence_triage import (
        build_evidence_with_triage as _build_evidence_with_triage,
        redact_finding_evidence as _redact_finding_evidence,
    )

try:
    from evidence_storage import delete_remote_evidence_object, hydrate_evidence_content, local_evidence_path
except ModuleNotFoundError as exc:
    if exc.name != "evidence_storage":
        raise
    from api.evidence_storage import delete_remote_evidence_object, hydrate_evidence_content, local_evidence_path

try:
    from artifact_storage import (
        ArtifactStorageError,
        delete_object as delete_artifact_object,
        object_key as artifact_object_key,
        read_bytes as read_artifact_bytes,
        store_bytes as store_artifact_bytes,
        storage_health as artifact_storage_health,
        upsert_manifest as upsert_artifact_manifest,
    )
except ModuleNotFoundError as exc:
    if exc.name != "artifact_storage":
        raise
    from api.artifact_storage import (
        ArtifactStorageError,
        delete_object as delete_artifact_object,
        object_key as artifact_object_key,
        read_bytes as read_artifact_bytes,
        store_bytes as store_artifact_bytes,
        storage_health as artifact_storage_health,
        upsert_manifest as upsert_artifact_manifest,
    )

try:
    from scan_verification_state import scan_time_verification_fields as _scan_time_verification_fields
except ModuleNotFoundError as exc:
    if exc.name != "scan_verification_state":
        raise
    from api.scan_verification_state import scan_time_verification_fields as _scan_time_verification_fields

from retest_contract import (
    AI_ONLY_RETEST_TYPES,
    DEFAULT_REPLAY_PAYLOADS,
    SUPPORTED_RETEST_TYPES,
    SUPPORTED_RETEST_VERDICTS,
    VerificationPolicy,
    backfill_campaign_scan_finding_links,
    build_replay_commands,
    build_retest_job_payload,
    extract_auth_context,
    infer_retest_inputs,
    infer_type_from_title_tool,
    normalize_retest_type,
    parse_json_field,
    run_schema_migrations,
    validate_retest_job_payload,
)
try:
    from serialization import (
        _str_list,
        row_to_dict,
        _decode_json_value,
        _json_object,
        _decode_jsonb_scalar,
    )
except ModuleNotFoundError:  # package import in host-side tests
    from api.serialization import (
        _str_list,
        row_to_dict,
        _decode_json_value,
        _json_object,
        _decode_jsonb_scalar,
    )
try:
    from api_utils import (
        LEGACY_SCAN_WRITE_FIELDS,
        SEVERITY_ORDER,
        _ARSENAL_CREATED_BY_CONTEXT,
        _QUEUE_HANDOFF_CONFIRMATION_KEY,
        _target_credential_profile_status,
        _parse_iso_datetime,
        _record_map,
        extract_root_domain,
        utc_now,
        utc_now_iso,
        _clean_string_list,
        _content_free_hash,
        _graph_get,
        _graph_list,
        _parse_graph_json,
        _scan_completion_flags,
        _severity_sort_value,
        _short_url_label,
        _direct_query_value,
        _int_or_none,
        _iso_or_none,
        _json_safe_row,
        _optional_uuid,
        _row_value,
        _uuid_or_400,
    )
except ModuleNotFoundError:  # package import in host-side tests
    from api.api_utils import (
        LEGACY_SCAN_WRITE_FIELDS,
        SEVERITY_ORDER,
        _ARSENAL_CREATED_BY_CONTEXT,
        _QUEUE_HANDOFF_CONFIRMATION_KEY,
        _target_credential_profile_status,
        _parse_iso_datetime,
        _record_map,
        extract_root_domain,
        utc_now,
        utc_now_iso,
        _clean_string_list,
        _content_free_hash,
        _graph_get,
        _graph_list,
        _parse_graph_json,
        _scan_completion_flags,
        _severity_sort_value,
        _short_url_label,
        _direct_query_value,
        _int_or_none,
        _iso_or_none,
        _json_safe_row,
        _optional_uuid,
        _row_value,
        _uuid_or_400,
    )
try:
    from request_models import (
        HypothesisRequest, ScanAdvancedLimits, ScanOptions, ScanPublicCompatibilityOptions,
        ScanRequest,
        ScanPublicPlacement, _ScanRequestBase,
    )
except ModuleNotFoundError:  # package import in host-side tests
    from api.request_models import (
        HypothesisRequest, ScanAdvancedLimits, ScanOptions, ScanPublicCompatibilityOptions,
        ScanRequest,
        ScanPublicPlacement, _ScanRequestBase,
    )
import parallel_scan
import asm_inventory
import adjudicate
import hypothesis_lifecycle
import hypothesis_scheduler
import family_proof
import invariant_contracts
import invariant_proposals
import source_ingest
import agent_context_pack
import agent_loop
import agent_provenance
import agent_text_toolcalls
import agent_tools
import agent_budget
try:
    from scan.contracts import (
        ResolvedScanContract,
        SCAN_AUTHENTICATION_KEYS,
        bind_scan_scope_receipt,
        resolve_scan_contract,
    )
    from scan.collection_replay import (
        EXECUTABLE_REPLAY_POLICIES,
        ScanCollectionReplayContractError,
        narrow_replay_plan_to_request_manifest,
        scan_replay_authorization,
        scan_replay_selector,
    )
    from scan.jobs import (
        CanonicalScanJob,
        CanonicalScanJobError,
        SCAN_JOB_SCHEMA,
        admitted_credential_profile_ids,
        admitted_request_collection_job_refs,
    )
    from scan.job_runtime import (
        CanonicalScanJobMaterializationError,
        materialize_canonical_scan_job,
    )
    from scan.worker_dispatch import (
        is_deterministic_dast,
        prepare_worker_dispatch,
    )
    from scan.executor import build_native_scan_execution
    from scan.action_plan import (
        ScanActionPlan,
        ScanActionPlanCompiler,
        ScanActionPlanError,
        credential_profile_action_refs,
        request_collection_action_refs,
    )
    from scan.action_store import PostgresScanActionStore
    from scan.activity import parallel_scan_activity_lines
    from scan.action_budget_reconciliation import scan_action_budget_reconciliation
    from scan.operational_metrics import (
        record_operational_event,
        scan_operational_metrics,
    )
    from scan.compatibility import (
        compatibility_snapshot,
        record_compatibility_call,
    )
    from scan.authorization import (
        ActionAuthorityDecision,
        revalidate_scan_action_authority,
    )
    from scan.execution_backend import (
        ActionAlreadyTerminal,
        ActionLease,
        ActionLeaseLost,
        PostgresScanExecutionBackend,
        ScanExecutionBackendError,
    )
    from runtime.receipts import CapabilityReceipt
    from runtime.observation_store import PostgresObservationManifestStore
    from scan.manifest_store import PostgresScanManifestStore, ScanManifestStoreError
    from scan.work_manifests import (
        ScanWorkManifest,
        ScanWorkManifestError,
        ScanWorkManifestReference,
        build_candidate_manifest,
        build_canonical_scan_nuclei_template_manifest,
        build_endpoint_manifest,
        build_request_candidate_manifest,
        build_request_manifest,
        route_id as scan_manifest_route_id,
        unique_work_manifest_reference_dicts,
        work_manifest_references_in,
    )
    from scan.budget_allocator import (
        ScanBudgetAllocationError,
        allocate_scan_action_plan,
    )
    from scan.continuation import (
        ContinuationBudgetCeiling,
        ScanContinuationAllocation,
        ScanContinuationError,
        ScanPlanRevision,
        amended_scan_plan_revision,
        build_discovery_continuation_manifests,
        merge_scan_action_continuation,
    )
    from scan.stage_store import (
        PostgresScanStageCheckpointStore,
        ScanStageCheckpointError,
    )
    from scan.parallel_compiler import summarize_parallel_action_coverage
    from scan.surface_manifest import build_scan_surface_manifest
    from scan.private_inputs import (
        BROKER_PRIVATE_SCAN_INPUT_SCHEMA,
        private_replay_plan_payload,
    )
    from scan.private_state import (
        SCAN_PRIVATE_STATE_KEY_OPTION,
        generate_scan_private_state_key,
    )
    from scan.broker_execution import (
        BrokerScanExecutionError,
        heartbeat_broker_scan_execution,
        reserve_broker_scan_execution,
        settle_broker_scan_execution,
    )
    from scan.read_router import (
        PUBLIC_SCAN_ACTIONS_SQL as _PUBLIC_SCAN_ACTIONS_SQL,
        configure_scan_read_router,
        get_scan_actions,
        get_scan_capabilities,
        get_scan_coverage,
        get_scan_parity_artifact,
        get_scan_public_contract,
        load_public_scan_execution_explanation as _load_public_scan_execution_explanation,
        public_scan_execution_explanation as _public_scan_execution_explanation,
        router as scan_read_router,
    )
except ModuleNotFoundError:
    from api.scan.contracts import (
        ResolvedScanContract,
        SCAN_AUTHENTICATION_KEYS,
        bind_scan_scope_receipt,
        resolve_scan_contract,
    )
    from api.scan.collection_replay import (
        EXECUTABLE_REPLAY_POLICIES,
        ScanCollectionReplayContractError,
        narrow_replay_plan_to_request_manifest,
        scan_replay_authorization,
        scan_replay_selector,
    )
    from api.scan.jobs import (
        CanonicalScanJob,
        CanonicalScanJobError,
        SCAN_JOB_SCHEMA,
        admitted_credential_profile_ids,
        admitted_request_collection_job_refs,
    )
    from api.scan.job_runtime import (
        CanonicalScanJobMaterializationError,
        materialize_canonical_scan_job,
    )
    from api.scan.worker_dispatch import (
        is_deterministic_dast,
        prepare_worker_dispatch,
    )
    from api.scan.executor import build_native_scan_execution
    from api.scan.action_plan import (
        ScanActionPlan,
        ScanActionPlanCompiler,
        ScanActionPlanError,
        credential_profile_action_refs,
        request_collection_action_refs,
    )
    from api.scan.action_store import PostgresScanActionStore
    from api.scan.activity import parallel_scan_activity_lines
    from api.scan.action_budget_reconciliation import scan_action_budget_reconciliation
    from api.scan.operational_metrics import (
        record_operational_event,
        scan_operational_metrics,
    )
    from api.scan.compatibility import (
        compatibility_snapshot,
        record_compatibility_call,
    )
    from api.scan.authorization import (
        ActionAuthorityDecision,
        revalidate_scan_action_authority,
    )
    from api.scan.execution_backend import (
        ActionAlreadyTerminal,
        ActionLease,
        ActionLeaseLost,
        PostgresScanExecutionBackend,
        ScanExecutionBackendError,
    )
    from api.runtime.receipts import CapabilityReceipt
    from api.runtime.observation_store import PostgresObservationManifestStore
    from api.scan.manifest_store import PostgresScanManifestStore, ScanManifestStoreError
    from api.scan.work_manifests import (
        ScanWorkManifest,
        ScanWorkManifestError,
        ScanWorkManifestReference,
        build_candidate_manifest,
        build_canonical_scan_nuclei_template_manifest,
        build_endpoint_manifest,
        build_request_candidate_manifest,
        build_request_manifest,
        route_id as scan_manifest_route_id,
        unique_work_manifest_reference_dicts,
        work_manifest_references_in,
    )
    from api.scan.budget_allocator import (
        ScanBudgetAllocationError,
        allocate_scan_action_plan,
    )
    from api.scan.continuation import (
        ContinuationBudgetCeiling,
        ScanContinuationAllocation,
        ScanContinuationError,
        ScanPlanRevision,
        amended_scan_plan_revision,
        build_discovery_continuation_manifests,
        merge_scan_action_continuation,
    )
    from api.scan.stage_store import (
        PostgresScanStageCheckpointStore,
        ScanStageCheckpointError,
    )
    from api.scan.parallel_compiler import summarize_parallel_action_coverage
    from api.scan.surface_manifest import build_scan_surface_manifest
    from api.scan.private_inputs import (
        BROKER_PRIVATE_SCAN_INPUT_SCHEMA,
        private_replay_plan_payload,
    )
    from api.scan.private_state import (
        SCAN_PRIVATE_STATE_KEY_OPTION,
        generate_scan_private_state_key,
    )
    from api.scan.broker_execution import (
        BrokerScanExecutionError,
        heartbeat_broker_scan_execution,
        reserve_broker_scan_execution,
        settle_broker_scan_execution,
    )
    from api.scan.read_router import (
        PUBLIC_SCAN_ACTIONS_SQL as _PUBLIC_SCAN_ACTIONS_SQL,
        configure_scan_read_router,
        get_scan_actions,
        get_scan_capabilities,
        get_scan_coverage,
        get_scan_parity_artifact,
        get_scan_public_contract,
        load_public_scan_execution_explanation as _load_public_scan_execution_explanation,
        public_scan_execution_explanation as _public_scan_execution_explanation,
        router as scan_read_router,
    )
try:
    from request_collection_api import (
        _request_collection_json_digest,
        _request_collection_owner_binding,
        configure_request_collection_router,
        request_collection_selector as _request_collection_selector,
        router as request_collection_router,
        select_request_collection_index_rows as _select_request_collection_index_rows,
    )
except ModuleNotFoundError:
    from api.request_collection_api import (
        _request_collection_json_digest,
        _request_collection_owner_binding,
        configure_request_collection_router,
        request_collection_selector as _request_collection_selector,
        router as request_collection_router,
        select_request_collection_index_rows as _select_request_collection_index_rows,
    )
try:
    from hunt.action_dispatcher import (
        HUNT_ACTION_DISPATCHER,
        HuntActionRequest,
        HuntActionResult,
        RegisteredHuntAdapterFactory,
    )
    from hunt.action_service import (
        HUNT_ACTION_SERVICE,
        HuntActionInputError,
        HuntActionLifecycle,
        HuntActionNotFound,
    )
    from hunt.capability_reservations import (
        hunt_capability_action_digest,
        hunt_capability_lease_seconds,
        terminalize_hunt_capability,
    )
    from hunt.capability_executor import (
        CapabilityExecutionContext,
        CapabilityExecutor,
    )
    from hunt.device_policy import DeviceHuntPolicyState
    from capabilities.inline import (
        ControlPlaneExecutionAdapter,
        DeviceExecutionAdapter,
        HttpRequestExecutionAdapter,
        TlsInspectionExecutionAdapter,
    )
    from capabilities.http import execute_bound_http_request
    from capabilities.tls import inspect_tls_origin
    from hunt.contracts import allowed_capability_names
    from hunt.start_contract import (
        HUNT_BUDGET_SCHEMA,
        HuntStartContract,
        bind_validated_receipts,
    )
    from hunt.legacy import LegacyHuntIsolationMiddleware
    from hunt.run_router import (
        HuntFinishRequest,
        cancel_hunt,
        configure_hunt_run_router,
        finish_hunt,
        get_hunt,
        list_hunts,
        resume_hunt,
        router as hunt_run_router,
    )
    from hunt.run_service import (
        HuntRunService,
        hunt_run_or_404 as _hunt_run_or_404,
        public_hunt_run as _hunt_public,
    )
except ModuleNotFoundError:
    from api.hunt.action_dispatcher import (
        HUNT_ACTION_DISPATCHER,
        HuntActionRequest,
        HuntActionResult,
        RegisteredHuntAdapterFactory,
    )
    from api.hunt.action_service import (
        HUNT_ACTION_SERVICE,
        HuntActionInputError,
        HuntActionLifecycle,
        HuntActionNotFound,
    )
    from api.hunt.capability_reservations import (
        hunt_capability_action_digest,
        hunt_capability_lease_seconds,
        terminalize_hunt_capability,
    )
    from api.hunt.capability_executor import (
        CapabilityExecutionContext,
        CapabilityExecutor,
    )
    from api.hunt.device_policy import DeviceHuntPolicyState
    from api.capabilities.inline import (
        ControlPlaneExecutionAdapter,
        DeviceExecutionAdapter,
        HttpRequestExecutionAdapter,
        TlsInspectionExecutionAdapter,
    )
    from api.capabilities.http import execute_bound_http_request
    from api.capabilities.tls import inspect_tls_origin
    from api.hunt.contracts import allowed_capability_names
    from api.hunt.start_contract import (
        HUNT_BUDGET_SCHEMA,
        HuntStartContract,
        bind_validated_receipts,
    )
    from api.hunt.legacy import LegacyHuntIsolationMiddleware
    from api.hunt.run_router import (
        HuntFinishRequest,
        cancel_hunt,
        configure_hunt_run_router,
        finish_hunt,
        get_hunt,
        list_hunts,
        resume_hunt,
        router as hunt_run_router,
    )
    from api.hunt.run_service import (
        HuntRunService,
        hunt_run_or_404 as _hunt_run_or_404,
        public_hunt_run as _hunt_public,
    )
try:
    from runtime.budget_reservations import DurableBudgetReservation
    from runtime.budgets import BudgetExceeded, reconcile_budget_snapshot, reserve_budget_snapshot
    from runtime.credential_refs import (
        CredentialReferenceError,
        select_hunt_principal_reference,
        validate_generic_credential_references,
    )
    from runtime.auth_session_store import PostgresAuthSessionStore
    from runtime.credential_store import CredentialStoreError, PostgresCredentialProfileStore
    from runtime.credential_resolver import (
        CredentialResolutionError,
        WorkerCredentialResolver,
        validate_worker_credential_authority,
    )
    from runtime.credential_migration import (
        LegacyCredentialMigrationError,
        sync_legacy_ai_principal_credential,
        sync_legacy_ai_target_credential,
        sync_legacy_device_credential,
        sync_legacy_web_credential,
        sync_legacy_web_credential_by_name,
    )
    from runtime.models import ScanPolicy, TargetBinding
    from runtime.reservation_store import PostgresBudgetReservationStore
    from runtime.request_collection_store import (
        REPLAY_POLICIES as REQUEST_COLLECTION_REPLAY_POLICIES,
        RequestCollectionContractError,
        RequestCollectionSelection,
        canonical_collection_origin,
        canonical_collection_origins,
        request_collection_selection_digest,
    )
    from runtime.scan_credentials import (
        ScanCredentialError,
        admit_scan_credential_profiles,
        bind_resolved_scan_credential,
        scan_credential_allows_capability,
        scan_credential_resolution_capability,
    )
    from runtime.sealed_inputs import (
        SealedInputError,
        seal_private_input,
        validate_sealed_input_public_key,
    )
    from capabilities.network import CapabilityInputError, network_capability_adapter
    from capabilities.browser import BrowserCapabilityInputError, browser_capability_adapter
except ModuleNotFoundError:
    from api.runtime.budget_reservations import DurableBudgetReservation
    from api.runtime.budgets import BudgetExceeded, reconcile_budget_snapshot, reserve_budget_snapshot
    from api.runtime.credential_refs import (
        CredentialReferenceError,
        select_hunt_principal_reference,
        validate_generic_credential_references,
    )
    from api.runtime.auth_session_store import PostgresAuthSessionStore
    from api.runtime.credential_store import CredentialStoreError, PostgresCredentialProfileStore
    from api.runtime.credential_resolver import (
        CredentialResolutionError,
        WorkerCredentialResolver,
        validate_worker_credential_authority,
    )
    from api.runtime.credential_migration import (
        LegacyCredentialMigrationError,
        sync_legacy_ai_principal_credential,
        sync_legacy_ai_target_credential,
        sync_legacy_device_credential,
        sync_legacy_web_credential,
        sync_legacy_web_credential_by_name,
    )
    from api.runtime.models import ScanPolicy, TargetBinding
    from api.runtime.reservation_store import PostgresBudgetReservationStore
    from api.runtime.request_collection_store import (
        REPLAY_POLICIES as REQUEST_COLLECTION_REPLAY_POLICIES,
        RequestCollectionContractError,
        RequestCollectionSelection,
        canonical_collection_origin,
        canonical_collection_origins,
        request_collection_selection_digest,
    )
    from api.runtime.scan_credentials import (
        ScanCredentialError,
        admit_scan_credential_profiles,
        bind_resolved_scan_credential,
        scan_credential_allows_capability,
        scan_credential_resolution_capability,
    )
    from api.runtime.sealed_inputs import (
        SealedInputError,
        seal_private_input,
        validate_sealed_input_public_key,
    )
    from api.capabilities.network import CapabilityInputError, network_capability_adapter
    from api.capabilities.browser import BrowserCapabilityInputError, browser_capability_adapter
import device_agent
import device_capabilities
import investigation_candidates
from job_queue import (
    DEFAULT_WORKER_TOOL_COMMANDS,
    QueueLease,
    RouteCapacityExceeded,
    acknowledge_lease,
    clear_unleased,
    enqueue_job,
    heartbeat_lease,
    lease_job,
    normalize_placement,
    pending_depth,
    qualified_route_queues,
    queue_payloads,
    stream_key,
    worker_matches_placement,
)
from http_experiment import (
    MAX_BODY_BYTES,
    MAX_REDIRECT_HOPS,
    REDIRECT_STATUSES,
    ExperimentContractError,
    compare_summaries,
    execute_experiment,
    response_summary,
    rewrite_method_for_redirect,
    validate_next_hop,
)
from workflow_experiment import (
    WorkflowContractError,
    execute_workflow,
    normalize_workflow,
    server_corroborated_predicate_bindings,
    server_corroborated_predicates,
    validate_principal_contexts,
)
from research_agent import (
    GATED_RESEARCH_COMMANDS,
    READ_ONLY_RESEARCH_COMMANDS,
    RESEARCH_DECISION_VERSION,
    RESEARCH_EPISODE_VERSION,
    RESEARCH_OBSERVATION_VERSION,
    RISK_TIER_ORDER as RESEARCH_RISK_TIER_ORDER,
    TARGET_BOUND_COMMANDS,
    TERMINAL_EPISODE_STATUSES,
    action_cost as _research_action_cost,
    apply_cost as _research_apply_cost,
    budget_violations as _research_budget_violations,
    canonical_hash as _research_canonical_hash,
    command_projection as _research_command_projection,
    normalize_budget_limits as _research_normalize_budget_limits,
    normalize_budget_used as _research_normalize_budget_used,
    remaining_budget as _research_remaining_budget,
    validate_decision as _research_validate_decision,
)
from target_dedupe import (
    TargetMergeBlockedError,
    canonical_target_key as _canonical_target_key,
    canonical_web_host as _canonical_web_host,
    ensure_no_executing_retention_previews as _ensure_target_merge_safe,
    merge_target_group as _merge_target_group,
    plan_canonical_merges,
)
import check_registry

try:
    from fleet import (
        FleetAuthenticationError,
        FleetBootstrapConfig,
        FleetConfigurationError,
        FleetConflictError,
        FleetEnrollmentError,
        authenticate_node as _authenticate_fleet_node,
        consume_connection_bundle as _consume_fleet_connection_bundle,
        create_join_token as _create_fleet_join_token,
        distribute_worker_count as _distribute_fleet_worker_count,
        enroll_node as _enroll_fleet_node,
        generate_secret as _generate_fleet_secret,
        hash_secret as _hash_fleet_secret,
        public_node as _public_fleet_node,
        record_heartbeat as _record_fleet_heartbeat,
        record_node_event as _record_fleet_node_event,
        revoke_join_token as _revoke_fleet_join_token,
        socket_peer_is_overlay as _fleet_peer_is_overlay,
    )
except ModuleNotFoundError:
    from api.fleet import (
        FleetAuthenticationError,
        FleetBootstrapConfig,
        FleetConfigurationError,
        FleetConflictError,
        FleetEnrollmentError,
        authenticate_node as _authenticate_fleet_node,
        consume_connection_bundle as _consume_fleet_connection_bundle,
        create_join_token as _create_fleet_join_token,
        distribute_worker_count as _distribute_fleet_worker_count,
        enroll_node as _enroll_fleet_node,
        generate_secret as _generate_fleet_secret,
        hash_secret as _hash_fleet_secret,
        public_node as _public_fleet_node,
        record_heartbeat as _record_fleet_heartbeat,
        record_node_event as _record_fleet_node_event,
        revoke_join_token as _revoke_fleet_join_token,
        socket_peer_is_overlay as _fleet_peer_is_overlay,
    )

try:
    from action_scope import (
        evaluate_runtime_destination_scope,
        evaluate_scope,
        receipt_to_dict,
        runtime_scope_guard_from_scope as _runtime_scope_guard_from_scope,
    )
    from command_arsenal import describe_contracts as describe_arsenal_contracts
    from command_arsenal import describe_commands as describe_arsenal_commands
    from command_arsenal import describe_local_agents
    from command_arsenal import describe_tools as describe_arsenal_tools
    from command_arsenal import test_local_agent_capability
    from command_arsenal import validate_command_parameters as _validate_command_parameters
except ModuleNotFoundError as exc:
    if exc.name not in {"command_arsenal", "action_scope"}:
        raise
    from api.action_scope import (
        evaluate_runtime_destination_scope,
        evaluate_scope,
        receipt_to_dict,
        runtime_scope_guard_from_scope as _runtime_scope_guard_from_scope,
    )
    from api.command_arsenal import describe_contracts as describe_arsenal_contracts
    from api.command_arsenal import describe_commands as describe_arsenal_commands
    from api.command_arsenal import describe_local_agents
    from api.command_arsenal import describe_tools as describe_arsenal_tools
    from api.command_arsenal import test_local_agent_capability
    from api.command_arsenal import validate_command_parameters as _validate_command_parameters


try:
    from ai_demo_scenarios import get_ai_test_scenarios
except ModuleNotFoundError as exc:
    if exc.name != "ai_demo_scenarios":
        raise
    from api.ai_demo_scenarios import get_ai_test_scenarios

try:
    from ai_redteam_artifacts import (
        build_ai_redteam_report,
        render_ai_redteam_markdown,
    )
except ModuleNotFoundError as exc:
    if exc.name != "ai_redteam_artifacts":
        raise
    from api.ai_redteam_artifacts import (
        build_ai_redteam_report,
        render_ai_redteam_markdown,
    )

try:
    from ai_gate.targets.rest_json import (
        append_query_params as ai_append_query_params,
        build_headers as ai_build_headers,
        build_url as ai_build_url,
        extract_response_text as ai_extract_response_text,
        replace_placeholders as ai_replace_placeholders,
    )
except ModuleNotFoundError as exc:
    if exc.name not in {"ai_gate", "ai_gate.targets", "ai_gate.targets.rest_json"}:
        raise
    from api.ai_gate.targets.rest_json import (
        append_query_params as ai_append_query_params,
        build_headers as ai_build_headers,
        build_url as ai_build_url,
        extract_response_text as ai_extract_response_text,
        replace_placeholders as ai_replace_placeholders,
    )

try:
    from ai_assurance import (
        build_agent_blast_radius,
        build_ai_inventory,
        run_mcp_live_readiness_probe,
    )
except ModuleNotFoundError as exc:
    if exc.name != "ai_assurance":
        raise
    from api.ai_assurance import (
        build_agent_blast_radius,
        build_ai_inventory,
        run_mcp_live_readiness_probe,
    )

# Configuration
REDIS_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379')
DATABASE_URL = os.environ.get('DATABASE_URL', 'postgresql://scanner:scanner@localhost:5432/scanner')
RESULTS_DIR = Path(os.environ.get('RESULTS_DIR', '/results'))
QUEUE_NAME = 'scan_jobs'
RETEST_QUEUE_NAME = os.environ.get("RETEST_QUEUE_NAME", "retest_jobs")
DEVICE_QUEUE_NAME = os.environ.get("DEVICE_QUEUE_NAME", "device_scan_jobs")
AGENT_TOOL_QUEUE_NAME = os.environ.get("AGENT_TOOL_QUEUE_NAME", "agent_tool_jobs")
# Broker execution happens on independently memory-bounded remote hosts. Keep
# its admission semaphore separate from the control plane's local worker slots;
# otherwise a small control plane serializes a large remote fleet (or one local
# scan consumes remote capacity) even though no remote model/DAST workload runs
# on the control-plane host.
HEARTBEAT_TIMEOUT_MINUTES = 5  # Mark scan stale if no heartbeat for this long
FINALIZATION_HEARTBEAT_TIMEOUT_MINUTES = int(
    # Post-active phases (validation/attack-chains/grading) are CPU-heavy and emit
    # few heartbeats; on large (raised-budget §3) scans they legitimately run long.
    # 15 min reaped completed work; 30 gives margin while the resilient heartbeat
    # thread (worker) keeps writing.
    os.environ.get("FINALIZATION_HEARTBEAT_TIMEOUT_MINUTES", "30")
)
STALE_CHECK_INTERVAL_SECONDS = 60  # How often to check for stale scans
# §9: when an ASM-policy schedule's enqueue fails, retry after this short backoff
# instead of advancing a full cadence (so a transient failure doesn't silently skip
# a coverage wave). Kept well above the checker interval to avoid tight retries.
ASM_SCHEDULE_RETRY_MINUTES = int(os.environ.get("ASM_SCHEDULE_RETRY_MINUTES", "15"))
# A parent row runs no scanner subprocess; it is finalized by the merge job once
# all shards are terminal. If a shard is lost from the queue it never goes terminal
# and the parent hangs forever. Reap parents running past this generous threshold.
PARENT_STALE_TIMEOUT_MINUTES = int(os.environ.get("PARENT_STALE_TIMEOUT_MINUTES", "90"))
SCHEDULE_CHECK_INTERVAL_SECONDS = 60  # How often to check for due schedules
try:
    ASM_DISPATCH_INTERVAL_SECONDS = int(os.environ.get("SHAKERSCAN_ASM_DISPATCH_INTERVAL", "60"))
except (TypeError, ValueError):
    ASM_DISPATCH_INTERVAL_SECONDS = 60  # How often the continuous ASM dispatcher ticks
# Grace minutes added to a scan's max_duration before the stale-checker safety
# net force-terminates it, so the scanner's own termination (which returns
# recovered results) wins the race on slow targets.
try:
    STALE_DURATION_GRACE_MINUTES = float(os.environ.get("SHAKERSCAN_STALE_DURATION_GRACE_MIN", "5"))
except (TypeError, ValueError):
    STALE_DURATION_GRACE_MINUTES = 5.0
logger = logging.getLogger(__name__)

# Maximum allowed duration per scan type (minutes) - safety net
MAX_SCAN_DURATION = {
    'quick': 15,
    'standard': 45,
    'deep': 120,
    'full': 600,       # 10 hours
    'aggressive': 600,  # 10 hours
    'smart': 360,
}







def _parallel_shard_contribution(shard: dict[str, Any]) -> dict[str, Any]:
    """Summarize child shard work without returning the full child report."""
    report = _decode_json_value(shard.get('result'))
    options = _decode_json_value(shard.get('options')) or {}
    if not isinstance(report, dict):
        report = {}
    if not isinstance(options, dict):
        options = {}
    active = report.get('active_checks') if isinstance(report.get('active_checks'), dict) else {}
    custom_endpoints = options.get('custom_endpoints') if isinstance(options.get('custom_endpoints'), list) else []
    attempts = active.get('endpoint_attempts') if isinstance(active.get('endpoint_attempts'), list) else []
    attempt_statuses: dict[str, int] = {}
    for attempt in attempts:
        if not isinstance(attempt, dict):
            continue
        status = str(attempt.get('status') or 'unknown').strip().lower() or 'unknown'
        attempt_statuses[status] = attempt_statuses.get(status, 0) + 1
    scope = active.get('check_family_scope') if isinstance(active.get('check_family_scope'), dict) else {}
    requested_family = (
        scope.get('requested_family')
        or scope.get('focused_family')
        or options.get('asm_check_family')
        or options.get('check_family')
    )
    budget = options.get('custom_budget') if isinstance(options.get('custom_budget'), dict) else {}
    contribution = {
        'assigned_endpoints': len(custom_endpoints),
        'attempted_endpoints': len(attempts) if attempts else _int_or_none(active.get('endpoint_attempts_total')),
        'attempt_statuses': attempt_statuses,
        'active_worklist_total': _int_or_none(active.get('active_worklist_total')),
        'active_endpoints_selected': _int_or_none(active.get('active_endpoints_selected')),
        'active_endpoint_budget': _int_or_none(active.get('active_endpoint_budget') or budget.get('active_max_endpoints')),
        'active_max_seconds': _int_or_none(budget.get('active_max_seconds')),
        'budget_profile': options.get('budget_profile'),
        'check_family': requested_family or 'all',
        'auth_state': asm_inventory.auth_state_from_options(options),
        'per_endpoint_telemetry': bool(active.get('per_endpoint_telemetry')) or bool(attempts),
    }
    return {key: value for key, value in contribution.items() if value not in (None, {}, [])}


def _public_parallel_shard(row: dict[str, Any]) -> dict[str, Any]:
    shard = dict(row)
    shard['contribution'] = _parallel_shard_contribution(shard)
    shard.pop('result', None)
    shard.pop('options', None)
    return shard


def _add_rollup_bucket_value(bucket: dict[str, Any], key: str, value: int) -> None:
    if value:
        bucket[key] = int(bucket.get(key) or 0) + int(value)


def _parallel_shard_contribution_rollup(shards: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Aggregate per-shard contribution facts for parent scan detail."""
    totals: dict[str, Any] = {}
    by_auth_state: dict[str, dict[str, Any]] = {}
    by_check_family: dict[str, dict[str, Any]] = {}
    attempt_statuses: dict[str, int] = {}
    numeric_fields = (
        'assigned_endpoints',
        'attempted_endpoints',
        'active_worklist_total',
        'active_endpoints_selected',
        'active_endpoint_budget',
        'active_max_seconds',
    )
    shards_with_contribution = 0
    telemetry_shards = 0

    for shard in shards:
        contribution = shard.get('contribution') if isinstance(shard.get('contribution'), dict) else {}
        duration_seconds = _int_or_none(shard.get('duration_seconds')) or 0
        shard_has_fact = bool(duration_seconds)
        for field in numeric_fields:
            value = _int_or_none(contribution.get(field)) or 0
            if value:
                totals[field] = int(totals.get(field) or 0) + value
                shard_has_fact = True

        statuses = contribution.get('attempt_statuses') if isinstance(contribution.get('attempt_statuses'), dict) else {}
        for status, raw_count in statuses.items():
            count = _int_or_none(raw_count) or 0
            if count <= 0:
                continue
            key = str(status or 'unknown')
            attempt_statuses[key] = attempt_statuses.get(key, 0) + count
            shard_has_fact = True

        if contribution.get('per_endpoint_telemetry'):
            telemetry_shards += 1
            shard_has_fact = True
        if duration_seconds:
            totals['duration_seconds'] = int(totals.get('duration_seconds') or 0) + duration_seconds

        if not shard_has_fact:
            continue
        shards_with_contribution += 1
        auth_state = str(contribution.get('auth_state') or 'unknown')
        family = str(contribution.get('check_family') or 'all')
        for bucket_map, bucket_key in ((by_auth_state, auth_state), (by_check_family, family)):
            bucket = bucket_map.setdefault(bucket_key, {'shards': 0})
            bucket['shards'] += 1
            for field in numeric_fields:
                _add_rollup_bucket_value(bucket, field, _int_or_none(contribution.get(field)) or 0)
            _add_rollup_bucket_value(bucket, 'duration_seconds', duration_seconds)
            if contribution.get('per_endpoint_telemetry'):
                bucket['telemetry_shards'] = int(bucket.get('telemetry_shards') or 0) + 1

    if not shards_with_contribution:
        return None
    if attempt_statuses:
        totals['attempt_statuses'] = attempt_statuses
    if by_auth_state:
        totals['by_auth_state'] = by_auth_state
    if by_check_family:
        totals['by_check_family'] = by_check_family
    totals['shards_with_contribution'] = shards_with_contribution
    if telemetry_shards:
        totals['telemetry_shards'] = telemetry_shards
    active_seconds = int(totals.get('active_max_seconds') or 0)
    duration = int(totals.get('duration_seconds') or 0)
    if active_seconds > 0 and duration > 0:
        totals['active_budget_utilization'] = round(min(1.0, duration / active_seconds), 3)
    return totals


def _attach_parallel_shard_rollup(result: dict[str, Any], shards: list[dict[str, Any]]) -> None:
    """Attach shard rollup and derive live parent progress from child progress."""
    terminal = {'completed', 'failed', 'cancelled'}
    progress_values = [int(s.get('progress') or 0) for s in shards]
    average_progress = int(round(sum(progress_values) / len(progress_values))) if progress_values else 0
    public_shards = [_public_parallel_shard(shard) for shard in shards]
    result['shards'] = public_shards
    result['shard_rollup'] = {
        'total': len(shards),
        'completed': sum(1 for s in shards if s.get('status') == 'completed'),
        'failed': sum(1 for s in shards if s.get('status') == 'failed'),
        'cancelled': sum(1 for s in shards if s.get('status') == 'cancelled'),
        'partial': sum(
            1 for s in shards
            if s.get('status') == 'completed' and s.get('current_phase') == 'partial'
        ),
        'running': sum(1 for s in shards if s.get('status') == 'running'),
        'pending': sum(1 for s in shards if s.get('status') == 'pending'),
        'terminal': sum(1 for s in shards if s.get('status') in terminal),
        'average_progress': average_progress,
    }
    contribution_rollup = _parallel_shard_contribution_rollup(public_shards)
    if contribution_rollup:
        result['shard_rollup']['contribution'] = contribution_rollup
    if shards and result.get('status') in {'pending', 'running'}:
        # Execution owns 20-90% of logical progress. Child-local scanners may
        # report 0-100, but must never drive the parent to 94% before fan-out or
        # make it regress when the stage changes.
        result['progress'] = min(90, 20 + int(round(average_progress * 0.70)))


def get_redis():
    """Get Redis connection."""
    return redis.from_url(REDIS_URL, decode_responses=True)


def _redis_text(value: Any) -> str:
    """Normalize Redis replies across decoded clients, raw clients, and test doubles."""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", "replace")
    return str(value)


def _decode_redis_hash(raw: Any) -> dict[str, str]:
    if not isinstance(raw, dict):
        return {}
    return {_redis_text(key): _redis_text(value) for key, value in raw.items()}


def _asm_domain_rate_key(root_domain: str) -> str:
    return asm_inventory.domain_rate_key(root_domain)




def _reserve_asm_domain_rate(r, root_domain: str, cap: int, amount: int) -> int:
    """Reserve endpoint budget before queuing an ASM batch.

    The DB count only sees endpoints after they finish. This Redis counter
    closes the race where several targets under one root all queue full batches
    in the same dispatcher tick and exceed the per-hour domain cap.
    """
    try:
        cap = max(0, int(cap or 0))
        amount = max(0, int(amount or 0))
    except (TypeError, ValueError):
        return 0
    if amount <= 0:
        return 0
    if not root_domain or cap <= 0:
        return amount
    try:
        return asm_inventory.reserve_domain_rate(r, root_domain, cap, amount)
    except Exception as exc:
        print(f"[asm] domain rate reservation failed for {root_domain}: {exc}", flush=True)
        return 0


def _is_truthy(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _normalize_severity(value: Any, default: str = "high") -> str:
    candidate = str(value or "").strip().lower()
    if candidate in SEVERITY_ORDER:
        return candidate
    return default












# Sensitive-key matching + value masking live in the shared scanner.redaction
# module so the API and Model Intake cannot drift out of sync. These names are
# kept as thin aliases for the existing call sites.
SENSITIVE_SCAN_OPTION_KEYS = SENSITIVE_KEYS
SENSITIVE_SCAN_OPTION_KEY_FRAGMENTS = SENSITIVE_KEY_FRAGMENTS
_is_sensitive_scan_option_key = is_sensitive_key


def _sanitize_scan_options(value: Any) -> Any:
    """Decode scan options and mask sensitive credentials before returning."""
    options = _decode_json_value(value)
    if not isinstance(options, dict):
        return options
    return redact_sensitive(options)


_SCAN_LIST_OPTION_KEYS = {
    "auth_header", "auth_cookies", "auth_headers_json", "auth_scenario_json",
    "login_username", "login_password", "user2_header", "user2_cookies",
    "budget_profile", "scan_generation", "legacy_scan_type", "parallel_strategy",
    "complete_artifact_download", "complete_repository_snapshot", "expected_sha256",
}
_SCAN_DETAIL_ONLY_FIELDS = {
    "result", "result_partial", "delta", "execution_context", "policy_json",
    "budget_json", "budget_used_json", "coverage_json", "scan_job_payload",
    "scan_job_digest", "scan_action_plan_json", "scan_action_plan_digest",
    "scan_action_plan_schema", "scan_continuation_allocation_json",
    "scan_continuation_allocation_digest", "scan_continuation_applied_at",
}


def _scan_list_options(value: Any) -> dict[str, Any]:
    """Return only option facts used by scan/model-intake list surfaces.

    Full redacted options remain available from ``GET /scans/{id}``. Keeping
    job manifests and provider metadata out of list rows prevents a 50-row
    refresh from repeatedly transferring megabytes of detail-only data.
    """
    options = _sanitize_scan_options(value)
    if not isinstance(options, dict):
        return {}
    summary = {
        key: options[key]
        for key in _SCAN_LIST_OPTION_KEYS
        if key in options
    }
    metadata = options.get("metadata_json")
    if isinstance(metadata, dict):
        provider = metadata.get("provider_resolution")
        if isinstance(provider, dict):
            summary["metadata_json"] = {
                "provider_resolution": {
                    key: provider[key]
                    for key in ("provider", "source_kind")
                    if key in provider
                }
            }
    return summary














def _default_ai_settings() -> dict[str, Any]:
    shared_ai_url = os.environ.get("AI_URL", "").strip()
    shared_ai_key = os.environ.get("AI_API_KEY", "").strip()
    shared_ai_model = os.environ.get("AI_MODEL", "").strip()
    shared_ai_fallback = os.environ.get("AI_FALLBACK_MODEL", "").strip()

    return {
        "ai_url": shared_ai_url,
        "ai_api_key": shared_ai_key,
        "ai_model": shared_ai_model,
        "ai_model_fallback": shared_ai_fallback,
        "ai_mask_host": os.environ.get("AI_MASK_HOST", "example.com"),
        "ai_scan_classification_enabled": _is_truthy(
            os.environ.get("AI_SCAN_CLASSIFICATION_ENABLED", "false"),
            default=False,
        ),
        "ai_classify_min_severity": _normalize_severity(
            os.environ.get("AI_CLASSIFY_MIN_SEVERITY", os.environ.get("AI_VERIFY_MIN_SEVERITY", "high")),
            default=_normalize_severity(os.environ.get("AI_VERIFY_MIN_SEVERITY", "high"), default="high"),
        ),
        "ai_verify_enabled": _is_truthy(os.environ.get("AI_VERIFY_ENABLED", "false"), default=False),
        "ai_verify_min_severity": _normalize_severity(os.environ.get("AI_VERIFY_MIN_SEVERITY", "high"), default="high"),
        "auto_retest_on_scan_complete": _is_truthy(
            os.environ.get("AUTO_RETEST_ON_SCAN_COMPLETE", "true"),
            default=True,
        ),
        "auto_retest_min_severity": _normalize_severity(
            os.environ.get("AUTO_RETEST_MIN_SEVERITY", "medium"),
            default="medium",
        ),
        "auto_retest_max_per_scan": _normalize_non_negative_int(
            os.environ.get("AUTO_RETEST_MAX_PER_SCAN", "25"),
            default=25,
        ),
        # Unified verification policy fields (canonical names)
        "verification_min_severity": _normalize_severity(
            os.environ.get("VERIFICATION_MIN_SEVERITY")
            or os.environ.get("AUTO_RETEST_MIN_SEVERITY", "medium"),
            default="medium",
        ),
        "ai_escalation_min_severity": _normalize_severity(
            os.environ.get("AI_ESCALATION_MIN_SEVERITY")
            or os.environ.get("AI_VERIFY_MIN_SEVERITY", "high"),
            default="high",
        ),
        "proof_required_for_smart": _is_truthy(
            os.environ.get("PROOF_REQUIRED_FOR_SMART", "false"),
            default=False,
        ),
        "auto_fp_on_retest": _is_truthy(
            os.environ.get("AUTO_FP_ON_RETEST", "false"),
            default=False,
        ),
        "auto_fp_min_confidence": _normalize_confidence(
            os.environ.get("AUTO_FP_MIN_CONFIDENCE", "0.9"), default=0.9
        ),
        "demo_mode_enabled": _is_truthy(
            os.environ.get("AI_DEMO_MODE_ENABLED", "false"),
            default=False,
        ),
        "demo_honey_public_url": os.environ.get("AI_DEMO_HONEY_PUBLIC_URL", "").strip(),
        "demo_honey_scanner_url": os.environ.get("AI_DEMO_HONEY_SCANNER_URL", "").strip(),
    }


def _load_effective_ai_settings() -> dict[str, Any]:
    settings = _default_ai_settings()
    try:
        r = get_redis()
        overrides = r.hgetall(AI_SETTINGS_KEY) or {}
    except Exception:
        overrides = {}

    if "ai_url" in overrides:
        settings["ai_url"] = str(overrides.get("ai_url") or "")
    if "ai_api_key" in overrides:
        settings["ai_api_key"] = str(overrides.get("ai_api_key") or "")
    if "ai_model" in overrides:
        settings["ai_model"] = str(overrides.get("ai_model") or "")
    if "ai_model_fallback" in overrides:
        settings["ai_model_fallback"] = str(overrides.get("ai_model_fallback") or "")
    if "ai_mask_host" in overrides:
        settings["ai_mask_host"] = str(overrides.get("ai_mask_host") or "")
    if "ai_scan_classification_enabled" in overrides:
        settings["ai_scan_classification_enabled"] = _is_truthy(
            overrides.get("ai_scan_classification_enabled"),
            default=settings["ai_scan_classification_enabled"],
        )
    if "ai_classify_min_severity" in overrides:
        settings["ai_classify_min_severity"] = _normalize_severity(
            overrides.get("ai_classify_min_severity"),
            default=settings["ai_classify_min_severity"],
        )
    if "ai_verify_enabled" in overrides:
        settings["ai_verify_enabled"] = _is_truthy(overrides.get("ai_verify_enabled"), default=settings["ai_verify_enabled"])
    if "ai_verify_min_severity" in overrides:
        settings["ai_verify_min_severity"] = _normalize_severity(
            overrides.get("ai_verify_min_severity"), default=settings["ai_verify_min_severity"]
        )

    if "ai_classify_min_severity" not in overrides:
        settings["ai_classify_min_severity"] = settings["ai_verify_min_severity"]
    if "auto_retest_on_scan_complete" in overrides:
        settings["auto_retest_on_scan_complete"] = _is_truthy(
            overrides.get("auto_retest_on_scan_complete"),
            default=settings["auto_retest_on_scan_complete"],
        )
    if "auto_retest_min_severity" in overrides:
        settings["auto_retest_min_severity"] = _normalize_severity(
            overrides.get("auto_retest_min_severity"),
            default=settings["auto_retest_min_severity"],
        )
    if "auto_retest_max_per_scan" in overrides:
        settings["auto_retest_max_per_scan"] = _normalize_non_negative_int(
            overrides.get("auto_retest_max_per_scan"),
            default=int(settings["auto_retest_max_per_scan"]),
        )
    settings["ai_classify_min_severity"] = _normalize_severity(
        settings.get("ai_classify_min_severity"),
        default=settings.get("ai_verify_min_severity") or "high",
    )
    # Unified policy fields: apply overrides and keep bidirectional sync
    if "verification_min_severity" in overrides:
        settings["verification_min_severity"] = _normalize_severity(
            overrides.get("verification_min_severity"), default=settings["verification_min_severity"]
        )
        settings["auto_retest_min_severity"] = settings["verification_min_severity"]
    else:
        settings["verification_min_severity"] = settings["auto_retest_min_severity"]
    if "ai_escalation_min_severity" in overrides:
        settings["ai_escalation_min_severity"] = _normalize_severity(
            overrides.get("ai_escalation_min_severity"), default=settings["ai_escalation_min_severity"]
        )
        settings["ai_verify_min_severity"] = settings["ai_escalation_min_severity"]
    else:
        settings["ai_escalation_min_severity"] = settings["ai_verify_min_severity"]
    if "proof_required_for_smart" in overrides:
        settings["proof_required_for_smart"] = _is_truthy(
            overrides.get("proof_required_for_smart"), default=settings["proof_required_for_smart"]
        )
    if "auto_fp_on_retest" in overrides:
        settings["auto_fp_on_retest"] = _is_truthy(
            overrides.get("auto_fp_on_retest"), default=settings["auto_fp_on_retest"]
        )
    if "auto_fp_min_confidence" in overrides:
        settings["auto_fp_min_confidence"] = _normalize_confidence(
            overrides.get("auto_fp_min_confidence"), default=settings["auto_fp_min_confidence"]
        )
    if "demo_mode_enabled" in overrides:
        settings["demo_mode_enabled"] = _is_truthy(
            overrides.get("demo_mode_enabled"), default=settings["demo_mode_enabled"]
        )
    if "demo_honey_public_url" in overrides:
        settings["demo_honey_public_url"] = _coerce_demo_base_url(
            overrides.get("demo_honey_public_url"),
            default=settings["demo_honey_public_url"],
        )
    if "demo_honey_scanner_url" in overrides:
        settings["demo_honey_scanner_url"] = _coerce_demo_base_url(
            overrides.get("demo_honey_scanner_url"),
            default=settings["demo_honey_scanner_url"],
        )
    return settings












def _default_asm_enabled_setting() -> bool:
    return _is_truthy(
        os.environ.get("DEFAULT_ASM_ENABLED", os.environ.get("ASM_DEFAULT_ENABLED", "true")),
        default=True,
    )






def _normalize_research_planner_mode(value: Any, default: str = "agent") -> str:
    candidate = str(value or "").strip().lower()
    if candidate in {"agent", "local_codex", "configured_ai"}:
        return candidate
    return default


def _load_effective_automation_settings() -> dict[str, Any]:
    settings: dict[str, Any] = {
        "default_asm_enabled": _default_asm_enabled_setting(),
        "default_asm_config": _safe_default_asm_config({}),
        "approval_receipts_required_for_state_changing_actions": _is_truthy(
            os.environ.get("APPROVAL_RECEIPTS_REQUIRED_FOR_STATE_CHANGING_ACTIONS", "false"),
            default=False,
        ),
        "default_research_planner_mode": _normalize_research_planner_mode(
            os.environ.get("DEFAULT_RESEARCH_PLANNER_MODE", "agent"),
        ),
    }
    try:
        r = get_redis()
        overrides = r.hgetall(AUTOMATION_SETTINGS_KEY) or {}
    except Exception:
        overrides = {}

    if "default_asm_enabled" in overrides:
        settings["default_asm_enabled"] = _is_truthy(
            overrides.get("default_asm_enabled"),
            default=settings["default_asm_enabled"],
        )
    if "default_asm_config" in overrides:
        settings["default_asm_config"] = _safe_default_asm_config(
            _decode_json_value(overrides.get("default_asm_config"))
        )
    if "approval_receipts_required_for_state_changing_actions" in overrides:
        settings["approval_receipts_required_for_state_changing_actions"] = _is_truthy(
            overrides.get("approval_receipts_required_for_state_changing_actions"),
            default=settings["approval_receipts_required_for_state_changing_actions"],
        )
    if "default_research_planner_mode" in overrides:
        settings["default_research_planner_mode"] = _normalize_research_planner_mode(
            overrides.get("default_research_planner_mode"),
            default=settings["default_research_planner_mode"],
        )
    return settings




def _approval_receipts_required_for_state_changing_actions() -> bool:
    """Redis/env-cached view of the approval policy (non-authoritative fallback)."""
    return bool(
        _load_effective_automation_settings().get(APPROVAL_POLICY_SETTING_KEY)
    )






async def _approval_receipts_required(conn) -> bool:
    """Authoritative approval-policy read.

    Postgres (``app_settings``) is the durable source of truth so the security
    gate cannot silently fail open when the Redis settings hash is flushed. Only
    when no durable row exists do we fall back to the legacy Redis/env view, so
    upgrades and pre-existing configs keep working until the next write persists
    the flag to Postgres.
    """
    durable = await _read_durable_setting(conn, APPROVAL_POLICY_SETTING_KEY)
    if durable is not None:
        return _is_truthy(durable, default=False)
    return _approval_receipts_required_for_state_changing_actions()


async def _require_approval_receipt_if_policy_enabled(
    conn,
    approval_receipt_id: str | None,
    *,
    action_name: str = "state_changing_action",
    command: str | None = None,
    risk_tier: str = "active",
    created_by: str | None = None,
) -> None:
    if approval_receipt_id:
        return
    if not await _approval_receipts_required(conn):
        return
    await _record_blocked_command_result(
        conn,
        action_name=action_name,
        command=command,
        risk_tier=risk_tier,
        status="approval_required",
        blocked_by=["approval_receipt_required"],
        operator_message=(
            f"Blocked {_command_from_action(action_name)}: approval receipt required by automation policy"
        ),
        created_by=created_by,
    )
    raise HTTPException(
        status_code=409,
        detail={
            "error": "approval_receipt_required",
            "message": (
                "Approval receipts are required for state-changing actions by automation policy. "
                "Create a scope receipt and approval receipt, then retry with approval_receipt_id."
            ),
            "action": action_name,
        },
    )










def _scan_option_was_explicit(options: Any, field: str) -> bool:
    return field in getattr(options, "model_fields_set", set())


def _custom_endpoint_count(options_payload: dict[str, Any]) -> int:
    endpoints = options_payload.get("custom_endpoints")
    if not isinstance(endpoints, list):
        return 0
    seen: set[str] = set()
    for endpoint in endpoints:
        if not isinstance(endpoint, str):
            continue
        value = endpoint.strip()
        if value:
            seen.add(value)
    return len(seen)


def _auto_shard_eligibility(
    active_testing: bool, options_payload: dict[str, Any],
) -> tuple[bool, str]:
    endpoint_count = _custom_endpoint_count(options_payload)
    if endpoint_count >= 2:
        return True, f"{endpoint_count} explicit endpoints can be split by scope"
    # A focused check_family scan (sqli/xss/bola/auth) is a deep single-family
    # pass. Auto-sharding it into broad `coverage` dilutes that family's budget
    # and adds the slow recon+merge path (observed: a focused SQLi scan hung in
    # coverage and found nothing, while the direct pass found the login SQLi).
    # Focused scans therefore run DIRECT; only broad scans fan out.
    family = check_registry.normalize_check_family(_scan_check_family_value(options_payload))
    if family and family != "all":
        return False, f"focused {family} scan runs direct (auto-sharding would dilute the family pass)"
    if active_testing:
        return True, "active Scan can fan out endpoint coverage across workers"
    return False, "passive Scan has no endpoint list and no active families to shard"


def _resolve_auto_parallel_strategy(
    strategy: Any,
    active_testing: bool,
    options_payload: dict[str, Any],
) -> str:
    """Resolve auto-sharding to the concrete strategy we will store/execute."""
    normalized = _normalize_parallel_strategy(strategy, default="auto")
    # A focused check_family scan must never run the broad `coverage` strategy:
    # that fans out broad/sqli/xss lanes and dilutes (or skips) the requested
    # family. `coverage_family` with a single requested family runs ONLY that
    # family across endpoint slices, so it parallelizes without diluting. This
    # holds for both explicit `coverage` and the auto path below.
    focused = bool(
        (lambda fam: fam and fam != "all")(
            check_registry.normalize_check_family(_scan_check_family_value(options_payload))
        )
    )
    if focused and normalized == "coverage":
        return "coverage_family"
    if normalized != "auto":
        return normalized
    endpoint_count = _custom_endpoint_count(options_payload)
    if endpoint_count >= 2:
        return "scope"
    # Authenticated active scans: prefer the additive auth split so a primary
    # credential ADDS an authenticated pass on top of the anonymous baseline
    # instead of REPLACING it (which silently drops anonymous-only findings like
    # unauthenticated SQLi). Each auth_split shard is a full smart scan — no
    # family/scope fragmentation of the global+browser checks — and the authed
    # shard keeps user1+user2 so cross-user BOLA still runs. Focused-family scans
    # keep coverage_family (they need per-family endpoint slicing).
    has_primary_auth = any(options_payload.get(k) for k in parallel_scan._PRIMARY_AUTH_KEYS)
    if has_primary_auth and not focused and active_testing:
        return "auth_split"
    if active_testing:
        return "coverage_family" if focused else "coverage"
    return "family"


def _build_canonical_scan_options_payload(
    options: Any,
    contract: ResolvedScanContract,
    *,
    defer_family_preconditions: bool = False,
) -> dict[str, Any]:
    """Build private worker inputs without resurrecting a legacy Scan identity."""
    options_payload = options.model_dump() if hasattr(options, "model_dump") else options.dict()
    for key in ("scan_type", "quick", "thorough"):
        options_payload.pop(key, None)
    policy = contract.policy
    budget = contract.budget
    scanner_budget = {
        "max_duration_minutes": max(1, (budget.max_duration_seconds + 59) // 60),
        "request_max": budget.max_http_requests,
        "max_urls": budget.max_endpoints,
        "browser_max_pages": min(budget.max_browser_actions, budget.max_endpoints),
        "api_probe_limit": budget.max_endpoints,
        "phase4_max_seconds": budget.max_tool_wall_seconds,
        "nuclei_max_targets": budget.max_endpoints,
        "active_worklist_max": budget.max_endpoints,
    }
    if policy.active_testing:
        scanner_budget.update({
            "active_max_seconds": budget.max_tool_wall_seconds,
            "active_max_endpoints": budget.max_endpoints,
        })
    options_payload.update({
        "active": policy.active_testing,
        "network_discovery": policy.network_discovery,
        "subfinder": policy.subdomain_discovery,
        "budget_profile": contract.budget_profile,
        "custom_budget": dict(scanner_budget),
        "resolved_budget": {
            **scanner_budget,
            "budget_profile": contract.budget_profile,
            "budget_source": "canonical_plan",
        },
    })
    options_payload, _family = _apply_scan_check_family_policy(
        options_payload,
        enforce_preconditions=not defer_family_preconditions,
    )
    options_payload.update(contract.option_metadata())
    return options_payload


def _apply_auto_sharding_policy(
    options: Any,
    options_payload: dict[str, Any],
    active_testing: bool,
) -> tuple[bool, int | None]:
    """Resolve whether this scan should become a parallel parent.

    Explicit per-scan intent wins. If `parallel` is omitted, the global
    scan-execution setting can turn eligible scans into parent scans.
    """
    if _scan_option_was_explicit(options, "parallel"):
        if options.parallel:
            options_payload["parallel"] = True
            if not options_payload.get("shards"):
                options_payload["shards"] = "auto"
            options_payload["shard_strategy"] = _resolve_auto_parallel_strategy(
                options_payload.get("shard_strategy"),
                active_testing,
                options_payload,
            )
            # Size fan-out from CURRENT (non-stale) capacity so a mixed fleet can't
            # spawn shards that run old code (docs proposed-next-steps §3).
            return True, _current_scan_worker_count_best_effort()
        options_payload["parallel"] = False
        return False, None

    settings = _load_effective_scan_execution_settings()
    if not settings.get("auto_sharding_enabled"):
        options_payload["parallel"] = False
        return False, None

    eligible, reason = _auto_shard_eligibility(active_testing, options_payload)
    if not eligible:
        options_payload["parallel"] = False
        return False, None

    worker_count = _current_scan_worker_count_best_effort()
    min_workers = max(1, int(settings.get("auto_sharding_min_workers") or 2))
    if worker_count is not None and worker_count < min_workers:
        options_payload["parallel"] = False
        options_payload["auto_sharding_reason"] = (
            f"auto-sharding skipped: {worker_count} current-build worker(s), "
            f"minimum is {min_workers}"
        )
        return False, worker_count

    strategy = _resolve_auto_parallel_strategy(
        settings.get("auto_sharding_strategy"),
        active_testing,
        options_payload,
    )
    max_shards = _normalize_auto_shard_count(settings.get("auto_sharding_max_shards"), default=4)
    if _custom_endpoint_count(options_payload) < 2 and active_testing:
        if strategy == "family":
            max_shards = min(max_shards, len(parallel_scan.FAMILY_SHARD_LABELS))
    requested_shards: Any = "auto"
    if worker_count is not None:
        requested_shards = max(2, min(max_shards, worker_count))

    options_payload["parallel"] = True
    options_payload["shards"] = requested_shards
    options_payload["shard_strategy"] = strategy
    options_payload["auto_sharded"] = True
    options_payload["auto_sharding_reason"] = reason
    return True, worker_count










def _has_primary_auth_context(options: dict[str, Any]) -> bool:
    return check_registry.has_primary_auth_context(options or {})


def _has_second_user_auth_context(options: dict[str, Any]) -> bool:
    return check_registry.has_second_user_auth_context(options or {})




def _scan_check_family_value(options_payload: dict[str, Any]) -> Any:
    return (
        options_payload.get("check_family")
        or options_payload.get("asm_check_family")
        or options_payload.get("coverage_attempt_family")
    )


def _apply_scan_check_family_policy(
    options_payload: dict[str, Any],
    *,
    enforce_preconditions: bool = True,
) -> tuple[dict[str, Any], str | None]:
    """Apply the shared DAST family policy to a public POST /scans payload."""
    try:
        opts, family = check_registry.apply_scan_focus(
            options_payload,
            _scan_check_family_value(options_payload),
        )
        if enforce_preconditions:
            check_registry.enforce_family_preconditions(
                family,
                opts,
                exploit_depth=bool(opts.get("exploit_depth")),
            )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return opts, family








def _coerce_demo_base_url(value: Any, *, default: str = "") -> str:
    try:
        return _validate_demo_base_url(value, default=default)
    except HTTPException:
        return ""










def generate_finding_fingerprint(finding: dict) -> str:
    """Generate a unique fingerprint for deduplication."""
    scanner_id = finding.get('id', '')
    if scanner_id:
        return scanner_id
    key_parts = [
        finding.get('title', ''),
        finding.get('tool', ''),
        finding.get('url', ''),
        finding.get('cwe', '')
    ]
    key_string = '|'.join(str(p) for p in key_parts)
    return hashlib.sha256(key_string.encode()).hexdigest()[:16]


def _scan_result_verification_overrides(scan_result: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    if not isinstance(scan_result, dict):
        return {}

    overrides: dict[str, dict[str, Any]] = {}
    for finding in scan_result.get("findings") or []:
        if not isinstance(finding, dict):
            continue
        fields = _scan_time_verification_fields(finding)
        if not fields:
            continue
        fingerprint = generate_finding_fingerprint(finding)
        if fingerprint:
            overrides[fingerprint] = fields
    return overrides


_NUCLEI_NOT_EXECUTED_COVERAGE_GAP = "Nuclei templates not executed - check nuclei configuration or timeouts"


# Inference sources that are counted directly from nuclei stats vs. estimated
# from coarser wave/duration signals. Estimates are flagged so the UI can show
# coverage as approximate rather than presenting a guess as a measured count.
_NUCLEI_APPROXIMATE_RUN_SOURCES = {"staged_nuclei_wave_tags", "staged_nuclei_wave_estimate"}


def _infer_nuclei_templates_run(scan_result: dict[str, Any]) -> tuple[int, str | None]:
    """Best-effort count of nuclei templates run, with its provenance.

    Returns ``(count, source)``. ``source`` identifies where the number came
    from so callers can distinguish measured counts from coarse estimates.
    """
    discovery = scan_result.get("discovery") if isinstance(scan_result.get("discovery"), dict) else {}
    nuclei = discovery.get("nuclei") if isinstance(discovery.get("nuclei"), dict) else {}
    if not nuclei:
        return 0, None

    for key in ("templates_executed", "templates_used"):
        try:
            value = int(nuclei.get(key) or 0)
        except (TypeError, ValueError):
            value = 0
        if value > 0:
            return value, "nuclei_templates_executed"

    stats = nuclei.get("statistics") if isinstance(nuclei.get("statistics"), dict) else {}
    for key in ("templates_executed", "templates_loaded"):
        try:
            value = int(stats.get(key) or 0)
        except (TypeError, ValueError):
            value = 0
        if value > 0:
            return value, "nuclei_statistics"

    if nuclei.get("scan_completed") is not True:
        return 0, None

    wave_tags: set[str] = set()
    for wave in nuclei.get("wave_stats") or []:
        if not isinstance(wave, dict):
            continue
        for tag in wave.get("tags") or []:
            if tag:
                wave_tags.add(str(tag))
    if wave_tags:
        return len(wave_tags), "staged_nuclei_wave_tags"

    try:
        waves_completed = int(nuclei.get("waves_completed") or 0)
    except (TypeError, ValueError):
        waves_completed = 0
    try:
        duration = int(nuclei.get("total_duration_seconds") or 0)
    except (TypeError, ValueError):
        duration = 0
    if waves_completed > 0 or duration > 0:
        return max(1, waves_completed), "staged_nuclei_wave_estimate"
    return 0, None


def _normalize_scan_result_for_api(scan_result: Any) -> Any:
    if not isinstance(scan_result, dict):
        return scan_result

    parallel = scan_result.get("parallel")
    merge = (
        parallel.get("canonical_action_execution")
        if isinstance(parallel, dict) else None
    )
    if isinstance(merge, dict) and isinstance(merge.get("actions"), list):
        current_coverage = (
            scan_result.get("coverage")
            if isinstance(scan_result.get("coverage"), dict) else {}
        )
        current_reliability = (
            current_coverage.get("grade_reliability")
            if isinstance(current_coverage.get("grade_reliability"), dict) else {}
        )
        extra_reasons = list(current_reliability.get("reasons") or ())
        verification = (
            scan_result.get("verification_summary")
            if isinstance(scan_result.get("verification_summary"), dict) else {}
        )
        if int(verification.get("unproven_critical_high") or 0) > 0:
            extra_reasons.append("unproven_critical_high")
        scan_result["coverage"] = summarize_parallel_action_coverage(
            merge,
            additional_reliability_reasons=extra_reasons,
        )

    inferred_nuclei_run, inferred_source = _infer_nuclei_templates_run(scan_result)
    if inferred_nuclei_run > 0:
        smart_coverage = scan_result.setdefault("smart_coverage", {})
        if isinstance(smart_coverage, dict):
            nuclei_cov = smart_coverage.setdefault("nuclei_templates", {})
            if isinstance(nuclei_cov, dict):
                try:
                    current_run = int(nuclei_cov.get("run") or 0)
                except (TypeError, ValueError):
                    current_run = 0
                if current_run <= 0:
                    nuclei_cov["run"] = inferred_nuclei_run
                    nuclei_cov.setdefault("matched", 0)
                    nuclei_cov.setdefault("hit_rate", 0.0)
                    nuclei_cov.setdefault("by_category", {})
                    nuclei_cov["run_source"] = inferred_source or "inferred"
                    nuclei_cov["run_approximate"] = inferred_source in _NUCLEI_APPROXIMATE_RUN_SOURCES

        coverage_gaps = scan_result.get("coverage_gaps")
        if isinstance(coverage_gaps, dict) and isinstance(coverage_gaps.get("issues"), list):
            issues = [
                issue for issue in coverage_gaps.get("issues") or []
                if issue != _NUCLEI_NOT_EXECUTED_COVERAGE_GAP
            ]
            coverage_gaps["issues"] = issues
            coverage_gaps["count"] = len(issues)

    return scan_result


def synthesize_degraded_result(
    *,
    target_url: str | None = None,
    scan_type: str | None = None,
    status: str | None = None,
    phase: str | None = None,
    progress: int | None = None,
    error_message: str | None = None,
    findings: list | None = None,
    score: Any = None,
    grade: Any = None,
    diagnostics: dict | None = None,
) -> dict[str, Any]:
    """Build a minimal but durable result for a scan that ended without a full report.

    A terminal scan (failed/cancelled/timed-out) must never leave `scans.result`
    NULL — that makes `/result` 404 and the trust boundary "a scan that did work
    has a recoverable result" collapses (docs proposed-next-steps §1). This produces
    a self-describing degraded report that the UI/API can render: it carries the
    termination reason, the phase/progress reached, any recovered findings, and the
    explicit `grade_reliable=false` / `degraded=true` markers so a degraded scan can
    never masquerade as a clean security result.
    """
    findings = findings or []
    short_reason = (error_message or "Scan ended without a complete report").split("\n", 1)[0][:300]
    meta: dict[str, Any] = {
        "status": status or "failed",
        "partial": bool(findings),
        "degraded": True,
        "grade_reliable": False,
        "finalization_error": short_reason,
        "terminated_at_phase": phase,
        "progress_at_termination": progress,
    }
    if diagnostics:
        meta["failure_diagnostics"] = diagnostics
    return {
        "target": target_url,
        "scan_type": scan_type,
        "findings": findings,
        "result": {
            "score": score,
            "grade": grade,
            "grade_reliable": False,
            "summary": f"Degraded result — {short_reason}",
        },
        "scan_metadata": meta,
        "degraded": True,
        "error": error_message,
    }










async def ensure_verification_schema(pool: asyncpg.Pool):
    """Ensure verification schema exists for upgraded installations."""
    await run_schema_migrations(pool)


async def save_findings_from_partial(conn, scan_id: uuid.UUID, target_id: uuid.UUID, findings: list):
    """Save findings from partial results to database with deduplication."""
    if not findings:
        return 0

    saved_count = 0
    for finding in findings:
        fingerprint = generate_finding_fingerprint(finding)
        evidence_with_triage = _redact_finding_evidence(_build_evidence_with_triage(finding))
        evidence_json = json.dumps(evidence_with_triage) if evidence_with_triage else None
        ai_recommendations_json = json.dumps(finding.get('ai_recommendations')) if finding.get('ai_recommendations') else None
        ai_classification_source = finding.get('ai_classification_source')

        # Check if this finding already exists for this target
        existing = await conn.fetchrow("""
            SELECT id, status, resurfaced_count
            FROM findings
            WHERE target_id = $1 AND fingerprint = $2
        """, target_id, fingerprint)

        if existing:
            # Update existing finding
            if existing['status'] == 'resolved':
                await conn.execute("""
                    UPDATE findings SET
                        status = 'active',
                        resolved_at = NULL,
                        last_seen_at = NOW(),
                        resurfaced_count = $1,
                        scan_id = $2,
                        title = $3,
                        description = $4,
                        severity = $5,
                        cvss_score = $6,
                        tool = $7,
                        cwe = $8,
                        cwe_name = $9,
                        owasp = $10,
                        url = $11,
                        evidence = $12,
                        ai_verdict = $13,
                        ai_confidence = $14,
                        ai_rationale = $15,
                        ai_recommendations = $16,
                        ai_classification_source = $17,
                        updated_at = NOW()
                    WHERE id = $18
                """,
                    existing['resurfaced_count'] + 1,
                    scan_id,
                    finding.get('title'),
                    finding.get('description'),
                    finding.get('severity', 'info'),
                    finding.get('cvss_score'),
                    finding.get('tool'),
                    finding.get('cwe'),
                    finding.get('cwe_name'),
                    finding.get('owasp'),
                    finding.get('url'),
                    evidence_json,
                    finding.get('ai_verdict'),
                    finding.get('ai_confidence'),
                    finding.get('ai_rationale'),
                    ai_recommendations_json,
                    ai_classification_source,
                    existing['id'],
                )
            else:
                await conn.execute("""
                    UPDATE findings SET
                        last_seen_at = NOW(),
                        scan_id = $1,
                        title = $2,
                        description = $3,
                        severity = $4,
                        cvss_score = $5,
                        tool = $6,
                        cwe = $7,
                        cwe_name = $8,
                        owasp = $9,
                        url = $10,
                        evidence = $11,
                        ai_verdict = $12,
                        ai_confidence = $13,
                        ai_rationale = $14,
                        ai_recommendations = $15,
                        ai_classification_source = $16,
                        updated_at = NOW()
                    WHERE id = $17
                """,
                    scan_id,
                    finding.get('title'),
                    finding.get('description'),
                    finding.get('severity', 'info'),
                    finding.get('cvss_score'),
                    finding.get('tool'),
                    finding.get('cwe'),
                    finding.get('cwe_name'),
                    finding.get('owasp'),
                    finding.get('url'),
                    evidence_json,
                    finding.get('ai_verdict'),
                    finding.get('ai_confidence'),
                    finding.get('ai_rationale'),
                    ai_recommendations_json,
                    ai_classification_source,
                    existing['id'],
                )
            saved_count += 1
        else:
            # Insert new finding
            await conn.execute("""
                INSERT INTO findings (
                    scan_id, target_id, fingerprint, title, description,
                    severity, cvss_score, tool, cwe, cwe_name, owasp,
                    url, evidence, ai_verdict, ai_confidence, ai_rationale, ai_recommendations, ai_classification_source
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
            """,
                scan_id,
                target_id,
                fingerprint,
                finding.get('title'),
                finding.get('description'),
                finding.get('severity', 'info'),
                finding.get('cvss_score'),
                finding.get('tool'),
                finding.get('cwe'),
                finding.get('cwe_name'),
                finding.get('owasp'),
                finding.get('url'),
                evidence_json,
                finding.get('ai_verdict'),
                finding.get('ai_confidence'),
                finding.get('ai_rationale'),
                ai_recommendations_json,
                ai_classification_source,
            )
            saved_count += 1

    return saved_count


async def cleanup_stale_scans(pool: asyncpg.Pool):
    """Check for and mark stale scans as failed.

    A scan is considered stale if:
    1. No heartbeat received for timeout window (adaptive near finalization), OR
    2. Running longer than MAX_SCAN_DURATION for its scan type
    """
    r = get_redis()
    now = utc_now()

    async with pool.acquire() as conn:
        # Get all running scans. Parent rows of a parallel scan never run a
        # scanner subprocess (they only wait on shards) so they emit no
        # heartbeat; they are finalized by the merge job and reconciled below,
        # so exclude them from heartbeat/duration staleness here.
        running_scans = await conn.fetch("""
            SELECT id, job_id, scan_type, started_at, target_id, current_phase,
                   progress, options, scan_role, parent_scan_id
            FROM scans
            WHERE status = 'running' AND started_at IS NOT NULL
              AND (scan_role IS NULL OR scan_role <> 'parent')
        """)

        for scan in running_scans:
            scan_id = str(scan['id'])
            scan_type = scan['scan_type'] or 'standard'
            options = _decode_json_value(scan['options']) or {}
            started_at = scan['started_at']
            current_phase = (scan['current_phase'] or '').lower()
            progress = int(scan['progress'] or 0)

            heartbeat_timeout_minutes = HEARTBEAT_TIMEOUT_MINUTES
            if progress >= 95 or current_phase in {"validation", "attack_chains", "finalizing"}:
                heartbeat_timeout_minutes = max(
                    HEARTBEAT_TIMEOUT_MINUTES,
                    FINALIZATION_HEARTBEAT_TIMEOUT_MINUTES,
                )

            is_stale = False
            duration_exceeded = False
            reason = ""

            # Check 1: Heartbeat timeout
            # Look for job with this scan_id
            job_keys = r.keys("job:*")
            heartbeat_found = False

            for key in job_keys:
                job_data = _decode_redis_hash(r.hgetall(key))
                if job_data.get('scan_id') == scan_id or _redis_text(key).endswith(scan_id):
                    heartbeat_str = job_data.get('heartbeat')
                    if heartbeat_str:
                        try:
                            heartbeat_time = datetime.fromisoformat(heartbeat_str.replace('Z', '+00:00').replace('+00:00', ''))
                            heartbeat_age = (now - heartbeat_time).total_seconds() / 60
                            heartbeat_found = True

                            if heartbeat_age > heartbeat_timeout_minutes:
                                is_stale = True
                                reason = (
                                    f"No heartbeat for {heartbeat_age:.1f} minutes "
                                    f"(timeout {heartbeat_timeout_minutes} min, "
                                    f"phase={current_phase or 'unknown'}, progress={progress})"
                                )
                        except (ValueError, TypeError):
                            pass
                    break

            # If no heartbeat found at all and scan started beyond timeout, it's stale
            if not heartbeat_found:
                scan_age = (now - started_at.replace(tzinfo=None)).total_seconds() / 60
                if scan_age > heartbeat_timeout_minutes:
                    is_stale = True
                    reason = (
                        f"No heartbeat found, scan started {scan_age:.1f} minutes ago "
                        f"(timeout {heartbeat_timeout_minutes} min)"
                    )

            # Check 2: Max duration exceeded (safety net)
            if not is_stale and started_at:
                # Consume the budget contract stamped at submission rather than
                # re-resolving it here (docs §4) — the duration guard must use the
                # SAME max_duration the scan was planned with, or it can reap a scan
                # that is still inside its real budget.
                effective_budget_profile = options.get("budget_profile") if isinstance(options, dict) else None
                if isinstance(options, dict) and options.get("thorough_params") and not effective_budget_profile and not options.get("custom_budget"):
                    effective_budget_profile = "thorough"
                resolved_budget = resolve_or_consume_budget(
                    scan_type,
                    options=options if isinstance(options, dict) else None,
                    budget_profile=effective_budget_profile,
                    custom_budget=options.get("custom_budget") if isinstance(options, dict) else None,
                )
                max_duration = int(resolved_budget.get("max_duration_minutes") or MAX_SCAN_DURATION.get(scan_type, 120))
                scan_duration = (now - started_at.replace(tzinfo=None)).total_seconds() / 60

                # Grace buffer so the safety net doesn't pre-empt a scan the
                # instant it reaches its budget: the scanner's own termination
                # (which returns recovered results -> 'completed') should win the
                # race. Without this, a slow target (e.g. a high-latency API)
                # that runs slightly past budget gets marked 'failed' even though
                # results are seconds from being returned.
                duration_grace = max(STALE_DURATION_GRACE_MINUTES, max_duration * 0.5)
                if scan_duration > max_duration + duration_grace:
                    is_stale = True
                    duration_exceeded = True
                    reason = f"Exceeded max duration ({scan_duration:.0f} min > {max_duration} min for {scan_type} scan)"

            # Mark stale scan terminal (failed, or completed-partial when it
            # merely hit its time budget but recovered results — decided below).
            if is_stale:
                print(f"[cleanup] Terminating scan {scan_id[:8]}: {reason}", flush=True)

                # The fixed V2 graph checkpoints only content-free orchestration
                # metadata. Recover it independently from the legacy report file:
                # it is trustworthy partial state, but never enough to turn a
                # crashed scan into a successful or clean security result.
                canonical_stage_checkpoint = None
                stage_checkpoint_phase = None
                if scan.get("job_id"):
                    try:
                        canonical_stage_checkpoint = await (
                            PostgresScanStageCheckpointStore().load_prefix(
                                conn,
                                scan_id=scan_id,
                                job_id=str(scan["job_id"]),
                            )
                        )
                        if canonical_stage_checkpoint:
                            stage_checkpoint_phase = str(
                                canonical_stage_checkpoint.get("last_stage") or ""
                            ) or None
                    except ScanStageCheckpointError as exc:
                        print(
                            f"[cleanup] Rejected corrupt stage checkpoint for "
                            f"scan {scan_id[:8]}: {exc}",
                            flush=True,
                        )

                # Try to recover partial results from checkpoint file
                partial_result = None
                checkpoint_phase = None
                checkpoint_file = RESULTS_DIR / f"{scan_id}_checkpoint.json"
                try:
                    if checkpoint_file.exists():
                        with open(checkpoint_file) as f:
                            checkpoint_data = json.load(f)
                        partial_result = checkpoint_data.get("report")
                        checkpoint_phase = checkpoint_data.get("phase")
                        print(f"[cleanup] Found checkpoint at phase '{checkpoint_phase}' for scan {scan_id[:8]}", flush=True)
                        # Clean up checkpoint file
                        checkpoint_file.unlink()
                except Exception as e:
                    print(f"[cleanup] Failed to read checkpoint: {e}", flush=True)

                # Cross-node workers mirror checkpoints to the central artifact
                # plane. Recover the latest hash-verified object when the
                # control plane cannot see that worker's local /results mount.
                if partial_result is None:
                    try:
                        checkpoint_artifact = await conn.fetchrow(
                            """
                            SELECT storage_uri, content_sha256
                            FROM scan_artifacts
                            WHERE scan_id=$1 AND artifact_type='checkpoint'
                              AND status='available' AND deleted_at IS NULL
                            ORDER BY updated_at DESC
                            LIMIT 1
                            """,
                            scan["id"],
                        )
                        if checkpoint_artifact:
                            checkpoint_raw = await asyncio.to_thread(
                                read_artifact_bytes,
                                results_dir=RESULTS_DIR,
                                storage_uri=str(checkpoint_artifact["storage_uri"]),
                                expected_sha256=str(checkpoint_artifact["content_sha256"]),
                            )
                            checkpoint_data = json.loads(checkpoint_raw.decode("utf-8"))
                            partial_result = checkpoint_data.get("report")
                            checkpoint_phase = checkpoint_data.get("phase")
                            print(
                                f"[cleanup] Recovered central checkpoint at phase "
                                f"'{checkpoint_phase}' for scan {scan_id[:8]}",
                                flush=True,
                            )
                    except Exception as e:
                        print(f"[cleanup] Failed to read central checkpoint: {e}", flush=True)

                # Try to get last few log lines for debugging
                last_logs = None
                try:
                    log_lines = r.lrange(f"scan:{scan_id}:logs", -20, -1)
                    if log_lines:
                        last_logs = "\n".join(_redis_text(line) for line in log_lines)
                except Exception:
                    pass

                error_msg = f"Scan terminated: {reason}"
                if checkpoint_phase:
                    error_msg += f"\nPartial results recovered from phase: {checkpoint_phase}"
                if stage_checkpoint_phase:
                    error_msg += (
                        "\nDurable stage checkpoint recovered through phase: "
                        f"{stage_checkpoint_phase}"
                    )
                if last_logs:
                    error_msg += f"\n\nLast logs:\n{last_logs}"

                # Extract score/grade from partial result if available
                partial_score = None
                partial_grade = None
                partial_findings_count = 0
                if partial_result:
                    result_section = partial_result.get("result", {})
                    partial_score = result_section.get("score")
                    partial_grade = result_section.get("grade")
                    partial_findings_count = len(partial_result.get("findings", []))
                    # Mark as partial in metadata
                    if "scan_metadata" not in partial_result:
                        partial_result["scan_metadata"] = {}
                    partial_result["scan_metadata"]["partial"] = True
                    partial_result["scan_metadata"]["terminated_reason"] = reason
                    partial_result["scan_metadata"]["terminated_at_phase"] = checkpoint_phase

                # A scan that reached its TIME BUDGET but recovered partial
                # results (with a checkpoint) is a soft success, not a failure:
                # it ran to its configured limit and produced findings. Mark it
                # 'completed' (partial) so parallel rollups and the Scans list
                # don't show alarming failures for shards/scans that contributed
                # results. A genuine hang/crash (no heartbeat, Check 1) or a
                # duration-exceed with NO recoverable results stays 'failed'.
                # Status is decided from the REAL checkpoint, before we synthesize a
                # placeholder result below — a synthesized result must not flip a
                # genuine hang into a fake 'completed'.
                recovered_from_checkpoint = partial_result is not None
                stale_status = 'completed' if (duration_exceeded and recovered_from_checkpoint) else 'failed'
                stale_phase = 'completed' if stale_status == 'completed' else 'terminated'

                # Never persist a NULL result for a terminal scan: even a genuine
                # hang/crash with no checkpoint gets a self-describing degraded
                # result so /result returns an explanation instead of 404 (docs §1).
                if partial_result is None:
                    partial_result = synthesize_degraded_result(
                        scan_type=scan_type,
                        status=stale_status,
                        phase=current_phase or None,
                        progress=progress,
                        error_message=error_msg,
                    )
                if canonical_stage_checkpoint:
                    partial_result["canonical_stage_checkpoint"] = dict(
                        canonical_stage_checkpoint
                    )
                    metadata = partial_result.setdefault("scan_metadata", {})
                    if isinstance(metadata, dict):
                        metadata["durable_stage_checkpoint_recovered"] = True
                        metadata["terminated_at_phase"] = (
                            checkpoint_phase or stage_checkpoint_phase
                        )
                await conn.execute("""
                    UPDATE scans
                    SET status = $8,
                        error_message = $1,
                        completed_at = $2,
                        result = $3,
                        score = $4,
                        grade = $5,
                        findings_count = $6,
                        progress = 100,
                        current_phase = $9
                    WHERE id = $7
                """, error_msg, now, json.dumps(partial_result) if partial_result else None,
                    partial_score, partial_grade, partial_findings_count, scan['id'],
                    stale_status, stale_phase)

                # Save partial findings to findings table so they appear in /findings
                partial_findings = partial_result.get("findings", []) if partial_result else []
                target_id = scan['target_id']
                if partial_findings and target_id:
                    saved = await save_findings_from_partial(conn, scan['id'], target_id, partial_findings)
                    print(f"[cleanup] Saved {saved} findings from partial results for scan {scan_id[:8]}", flush=True)

                # If this was a shard of a parallel scan, its parent may now have
                # all children terminal — make sure the merge gets enqueued so the
                # parent doesn't hang forever on a crashed shard.
                parent_id = scan['parent_scan_id']
                if parent_id:
                    try:
                        await parallel_scan.reconcile_parallel_parent(
                            conn, str(parent_id), get_redis(), QUEUE_NAME
                        )
                    except Exception as e:
                        print(f"[cleanup] parent reconcile error for {str(parent_id)[:8]}: {e}", flush=True)


async def cleanup_stale_parents(pool: asyncpg.Pool):
    """Finalize parent scans that would otherwise hang forever.

    A parent waits on its shards and is finalized by the merge job. If a shard is
    lost from the queue (``pending`` in the DB but never queued/dequeued in Redis)
    it never reaches a terminal state, the merge never enqueues, and the parent
    stays ``running`` indefinitely (observed: a 9h parent with 21 orphaned pending
    shards on an empty queue). For parents running past a generous threshold, fail
    the orphaned (queue-missing) pending shards, then reconcile so the parent
    merges/finalizes instead of hanging.
    """
    r = get_redis()
    now = utc_now()
    async with pool.acquire() as conn:
        parents = await conn.fetch(
            """
            SELECT id FROM scans
            WHERE status = 'running' AND scan_role = 'parent' AND started_at IS NOT NULL
              AND started_at < $1
            """,
            now - timedelta(minutes=PARENT_STALE_TIMEOUT_MINUTES),
        )
        if not parents:
            return
        # Snapshot queued job_ids once for orphan detection. If the queue can't be
        # read, leave pending children alone (conservative — never fail a child we
        # can't prove is orphaned).
        queued_job_ids: set[str] | None = set()
        try:
            for raw in queue_payloads(r, QUEUE_NAME):
                try:
                    jid = json.loads(raw).get("job_id")
                except Exception:
                    continue
                if jid:
                    queued_job_ids.add(str(jid))
        except Exception:
            queued_job_ids = None

        for parent in parents:
            parent_id = str(parent["id"])
            pending = await conn.fetch(
                "SELECT id, job_id FROM scans WHERE parent_scan_id = $1 AND status = 'pending'",
                parent["id"],
            )
            failed = 0
            for child in pending:
                jid = str(child["job_id"]) if child["job_id"] else None
                if queued_job_ids is not None and jid not in queued_job_ids:
                    await conn.execute(
                        """
                        UPDATE scans SET status = 'failed', current_phase = 'terminated',
                               completed_at = $1,
                               error_message = 'orphaned shard: pending but not in scan queue (stale-parent reaper)'
                        WHERE id = $2 AND status = 'pending'
                        """,
                        now, child["id"],
                    )
                    failed += 1
            if failed:
                print(f"[cleanup] stale parent {parent_id[:8]}: failed {failed} orphaned pending shard(s)", flush=True)
            try:
                await parallel_scan.reconcile_parallel_parent(conn, parent_id, r, QUEUE_NAME)
            except Exception as e:
                print(f"[cleanup] stale-parent reconcile error for {parent_id[:8]}: {e}", flush=True)


async def cleanup_stale_device_lifecycle(pool: asyncpg.Pool) -> None:
    """Recover device queue and agent planning states left by process crashes."""
    r = get_redis()
    now = utc_now()
    try:
        queued_job_ids = {
            str(json.loads(raw).get("job_id") or "")
            for raw in queue_payloads(r, DEVICE_QUEUE_NAME)
        }
    except Exception:
        # Queue visibility is required before declaring a pending job orphaned.
        queued_job_ids = None
    async with pool.acquire() as conn:
        if queued_job_ids is not None:
            pending = await conn.fetch(
                """SELECT id, job_id FROM scans
                   WHERE run_kind IN ('device_posture','device_probe') AND status IN ('pending','queued')
                     AND created_at < $1""",
                now - timedelta(minutes=10),
            )
            for scan in pending:
                job_id = str(scan["job_id"] or "")
                if job_id in queued_job_ids:
                    continue
                job_state = _decode_redis_hash(r.hgetall(f"job:{job_id}")) if job_id else {}
                if str(job_state.get("status") or "") == "running" and job_state.get("heartbeat"):
                    continue
                await conn.execute(
                    """UPDATE scans
                       SET status='failed', progress=100, current_phase='queue_handoff_failed',
                           completed_at=NOW(),
                           error_message='Device scan was pending but no queue lease remained'
                       WHERE id=$1 AND status IN ('pending','queued')""",
                    scan["id"],
                )
                if job_id:
                    r.hset(f"job:{job_id}", mapping={
                        "status": "failed",
                        "progress": "100",
                        "current_phase": "queue_handoff_failed",
                    })
                    r.expire(f"job:{job_id}", 86400)
        await conn.execute(
            """UPDATE device_agent_runs
               SET status='awaiting_planner', planning_token=NULL,
                   stop_reason='planning_lease_recovered', updated_at=NOW()
               WHERE status='planning' AND updated_at < $1""",
            now - timedelta(minutes=10),
        )


async def cleanup_orphaned_scan_queue_handoffs(pool: asyncpg.Pool) -> int:
    """Fail old local Scan rows only when no queued payload or live lease remains."""
    r = get_redis()
    try:
        queued_job_ids = {
            str((json.loads(raw) if isinstance(raw, str) else {}).get("job_id") or "")
            for raw in queue_payloads(r, QUEUE_NAME, include_leased=True)
        }
    except Exception:
        # Queue visibility is authoritative for this repair. Never infer an
        # orphan when Redis cannot prove the payload/lease is absent.
        return 0

    repaired = 0
    now = utc_now()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """SELECT id, job_id, parent_scan_id
               FROM scans
               WHERE status IN ('pending','queued')
                 AND COALESCE(run_kind, 'web_dast') NOT IN ('device_posture','device_probe','device_web_dast')
                 AND created_at < $1""",
            now - timedelta(minutes=10),
        )
        for row in rows:
            job_id = str(row.get("job_id") or "")
            if job_id and job_id in queued_job_ids:
                continue
            job_state = _decode_redis_hash(r.hgetall(f"job:{job_id}")) if job_id else {}
            if str(job_state.get("status") or "") == "running" and job_state.get("heartbeat"):
                continue
            updated = await conn.fetchrow(
                """UPDATE scans
                   SET status='failed', progress=100, current_phase='queue_handoff_lost',
                       completed_at=NOW(),
                       error_message='Scan was pending but no queue entry or live lease remained after 10 minutes. No target traffic was started; retry this Scan.'
                   WHERE id=$1 AND status IN ('pending','queued')
                   RETURNING id, parent_scan_id""",
                row["id"],
            )
            if not updated:
                continue
            repaired += 1
            if job_id:
                r.hset(f"job:{job_id}", mapping={
                    "status": "failed",
                    "progress": "100",
                    "current_phase": "queue_handoff_lost",
                    "error": "Queue entry or live lease was lost before execution",
                })
                r.expire(f"job:{job_id}", 86400)
            parent_id = updated.get("parent_scan_id")
            if parent_id:
                await parallel_scan.reconcile_parallel_parent(
                    conn, str(parent_id), r, QUEUE_NAME
                )
    if repaired:
        print(f"[cleanup] failed {repaired} orphaned pending Scan handoff(s)", flush=True)
    return repaired


async def recover_parallel_orchestration(pool: asyncpg.Pool) -> int:
    """Recover the DB->queue seams of staged parallel execution.

    Discovery results and the complete fan-out set are durable in Postgres. A
    process/Redis restart may lose the small continuation or confirmation window;
    this recreates it without rerunning target traffic or duplicating shards.
    """
    r = get_redis()
    repaired = 0
    async with pool.acquire() as conn:
        discoveries = await conn.fetch(
            """
            SELECT p.id, p.job_id, p.target_url, p.options, p.scan_generation,
                   p.scan_job_payload,
                   d.id AS discovery_id, d.status AS discovery_status
            FROM scans p
            JOIN LATERAL (
                SELECT id, status FROM scans
                WHERE parent_scan_id=p.id AND scan_role=$1
                ORDER BY created_at DESC LIMIT 1
            ) d ON true
            WHERE p.scan_role='parent' AND p.status='running'
              AND p.options->>'parallel_stage'='discovery'
              AND d.status IN ('completed','failed')
            """,
            parallel_scan.PARALLEL_DISCOVERY_ROLE,
        )
        for row in discoveries:
            parent_id = str(row['id'])
            guard = parallel_scan.discovery_continue_guard_key(parent_id)
            if not r.set(guard, '1', nx=True, ex=86400):
                continue
            options = parse_json_field(row.get('options')) or {}
            if str(row.get('scan_generation') or '') == 'v2':
                try:
                    parent_job = CanonicalScanJob.from_payload(
                        parse_json_field(row.get('scan_job_payload')) or {}
                    )
                    payload = parent_job.payload()
                    payload.update({
                        'type': parallel_scan.PLAN_JOB_TYPE,
                        'plan_stage': 'fanout',
                        'discovery_scan_id': str(row['discovery_id']),
                        'parallel_worker_count': min(
                            max(0, int(options.get('worker_fleet_size_at_submit') or 0)),
                            parent_job.execution_plan.budget.max_workers,
                        ),
                        'placement': {'node_scope': 'local'},
                        'attempt': 1,
                        'plan_version': parallel_scan.PLAN_VERSION,
                    })
                    CanonicalScanJob.from_queue_payload(payload)
                except CanonicalScanJobError:
                    r.delete(guard)
                    logger.exception(
                        "Refused invalid V2 parallel discovery continuation for %s",
                        parent_id,
                    )
                    continue
            else:
                payload = {
                    'type': parallel_scan.PLAN_JOB_TYPE,
                    'job_id': str(row.get('job_id') or parent_id),
                    'scan_id': parent_id,
                    'target': str(row.get('target_url') or ''),
                    'options': options,
                    'plan_stage': 'fanout',
                    'discovery_scan_id': str(row['discovery_id']),
                    'parallel_worker_count': int(options.get('worker_fleet_size_at_submit') or 0),
                    'placement': {'node_scope': 'local'},
                    'attempt': 1,
                    'plan_version': parallel_scan.PLAN_VERSION,
                    'submitted_at': utc_now_iso(),
                }
            try:
                enqueue_job(r, QUEUE_NAME, payload)
                repaired += 1
            except Exception:
                r.delete(guard)
                logger.exception("Failed to recover parallel discovery continuation for %s", parent_id)

        # A crash after child-row commit but before the final fan-out marker
        # leaves a complete, inspectable set. After a short grace period, fail
        # only unconfirmed handoffs and open the merge barrier.
        fanouts = await conn.fetch(
            """
            SELECT id, shard_count, options FROM scans
            WHERE scan_role='parent' AND status='running'
              AND options->>'parallel_stage'='fanout'
              AND options->>'parallel_fanout_complete'='false'
            """
        )
        now = utc_now()
        for parent in fanouts:
            options = parse_json_field(parent.get('options')) or {}
            started = _parse_iso_datetime(options.get('parallel_fanout_started_at'))
            if started is None or (now.replace(tzinfo=timezone.utc) - started).total_seconds() < 120:
                continue
            expected = int(
                options.get(parallel_scan.PARALLEL_EXPECTED_SHARDS_KEY)
                or parent.get('shard_count')
                or 0
            )
            children = await conn.fetch(
                """
                SELECT id, status, options FROM scans
                WHERE parent_scan_id=$1 AND scan_role='shard'
                """,
                parent['id'],
            )
            if expected < 1 or len(children) != expected:
                continue
            for child in children:
                child_options = parse_json_field(child.get('options')) or {}
                if child['status'] == 'pending' and child_options.get('queue_handoff_confirmed') is False:
                    await conn.execute(
                        """
                        UPDATE scans SET status='failed', progress=100,
                            current_phase='queue_handoff_failed', completed_at=NOW(),
                            error_message='Shard queue handoff was not confirmed before recovery deadline'
                        WHERE id=$1 AND status='pending'
                        """,
                        child['id'],
                    )
            options[parallel_scan.PARALLEL_FANOUT_COMPLETE_KEY] = True
            options['parallel_stage'] = 'execution'
            await conn.execute(
                "UPDATE scans SET options=$2, current_phase='parallel_execution' WHERE id=$1",
                parent['id'], json.dumps(options),
            )
            await parallel_scan.reconcile_parallel_parent(
                conn, str(parent['id']), r, QUEUE_NAME
            )
            repaired += 1

        # A worker can terminate a shard before entering the ordinary execution
        # wrapper (for example, when a persisted V2 authority envelope fails
        # closed after a deploy). Older workers did not reconcile the logical
        # parent on that early return. Recover those already-terminal families on
        # every orchestration sweep instead of displaying a permanently running
        # parent until the much longer stale-parent reaper fires.
        terminal_families = await conn.fetch(
            """
            SELECT p.id
            FROM scans p
            WHERE p.scan_role='parent' AND p.status='running'
              AND p.options->>'parallel_fanout_complete'='true'
              AND EXISTS (
                  SELECT 1 FROM scans c
                  WHERE c.parent_scan_id=p.id AND c.scan_role='shard'
              )
              AND NOT EXISTS (
                  SELECT 1 FROM scans c
                  WHERE c.parent_scan_id=p.id AND c.scan_role='shard'
                    AND c.status NOT IN ('completed','failed','cancelled')
              )
            """
        )
        for parent in terminal_families:
            enqueued = await parallel_scan.reconcile_parallel_parent(
                conn, str(parent['id']), r, QUEUE_NAME
            )
            if enqueued:
                repaired += 1
    return repaired


async def stale_scan_checker(pool: asyncpg.Pool):
    """Background task to periodically check for stale scans."""
    print("[cleanup] Stale scan checker started", flush=True)
    while True:
        try:
            await asyncio.sleep(STALE_CHECK_INTERVAL_SECONDS)
            await recover_parallel_orchestration(pool)
            await cleanup_stale_scans(pool)
            await cleanup_stale_parents(pool)
            await cleanup_stale_device_lifecycle(pool)
            await cleanup_orphaned_scan_queue_handoffs(pool)
            await cleanup_expired_auth_sessions_once(pool)
        except asyncio.CancelledError:
            print("[cleanup] Stale scan checker stopped", flush=True)
            break
        except Exception as e:
            print(f"[cleanup] Error checking stale scans: {e}", flush=True)




async def run_due_schedules(pool: asyncpg.Pool):
    """Check for and execute due scheduled target actions.

    Connection lifetime: acquire a connection only to fetch the due list, then
    release it. Each due schedule then re-acquires for its own short-lived
    transaction. Previously this method pinned a single connection across the
    entire loop, which could starve the shared API pool when many schedules
    fire together or when a single schedule got slow (e.g. Redis push delay).
    """
    r = get_redis()
    now = utc_now()

    async with pool.acquire() as conn:
        due_schedules = await conn.fetch("""
            SELECT s.*, t.url as target_url
            FROM schedules s
            JOIN targets t ON s.target_id = t.id
            WHERE s.is_active = true AND s.next_run_at <= $1
        """, now)

    for schedule in due_schedules:
        schedule_id = schedule['id']
        target_id = schedule['target_id']
        target_url = schedule['target_url']
        scan_type = str(schedule['scan_type'] or '')
        try:
            schedule_kind = _schedule_kind_from_row(schedule)
        except ValueError as exc:
            print(f"[scheduler] Skipping schedule {str(schedule_id)[:8]}: {exc}", flush=True)
            continue
        if schedule_kind == "evidence_retention_sweep":
            async with pool.acquire() as conn:
                await conn.execute(
                    "UPDATE schedules SET is_active = false, updated_at = NOW() WHERE id = $1",
                    schedule_id,
                )
            print(
                f"[scheduler] Disabled legacy evidence retention schedule {str(schedule_id)[:8]}; "
                "retention now requires an interactive exact-preview approval",
                flush=True,
            )
            continue

        scan_options = dict(_schedule_options_dict(schedule['scan_options']))

        async with pool.acquire() as conn:
            # Check if target already has a running/pending scan
            existing = await conn.fetchval("""
                SELECT COUNT(*) FROM scans
                WHERE target_id = $1 AND status IN ('pending', 'queued', 'running')
            """, target_id)

            if existing > 0:
                print(f"[scheduler] Skipping schedule {str(schedule_id)[:8]}: target already has active scan", flush=True)
                if schedule_kind == 'asm_improve':
                    await _persist_asm_decision(
                        conn,
                        target_id,
                        {
                            "action": "none",
                            "reason": "target already has an active scan",
                            "blocked_by": "active_scan",
                            "next_eligible_at": None,
                            "daily_cap_remaining": None,
                            "rate_cap_remaining": None,
                            "claimable": None,
                            "tested_today": None,
                        },
                        source="schedule",
                    )
                # Recalculate next_run_at anyway so we don't keep retrying every 60s
                next_run = calculate_next_run(
                    schedule['frequency'],
                    schedule['day_of_week'],
                    schedule['time_of_day'] or '02:00',
                    schedule['timezone'] or 'UTC',
                    schedule['jitter_minutes'] or 0
                )
                await conn.execute("""
                    UPDATE schedules SET next_run_at = $1, updated_at = NOW() WHERE id = $2
                """, next_run, schedule_id)
                continue

            # Create scan record + queue job (reuse scan submission logic)
            job_id = str(uuid.uuid4())
            scan_id = str(uuid.uuid4())

            # Use the shared helper so JSONB shapes (raw string vs decoded
            # dict, depending on asyncpg version / column type) are handled
            # consistently with the rest of the codebase.
            # §9: ASM-aware schedule. schedule_kind='asm_improve' queues a bounded coverage
            # wave (test if claimable, else recon) instead of a full scan — the
            # "keep this target covered" cadence, spread across the schedule. Legacy
            # rows that still carry scan_options.kind are normalized before this point.
            if schedule_kind == 'asm_improve':
                asm_opts = {k: v for k, v in scan_options.items() if k != 'kind'}
                _asm_ok = False
                try:
                    cfg_row = await conn.fetchrow(
                        "SELECT asm_config FROM targets WHERE id = $1", target_id)
                    cfg = asm_inventory.merge_asm_config({
                        **(_decode_asm_config(cfg_row["asm_config"]) if cfg_row else {}),
                        **{k: v for k, v in asm_opts.items() if k in {"batch_size", "stale_days", "exploit_depth"}},
                    })
                    check_family = _validate_asm_check_family_value(asm_opts.get("check_family"))
                    endpoint_filter = _validate_asm_endpoint_filter_value(asm_opts.get("endpoint_filter"))
                    claimable = await asm_inventory.claimable_count(
                        conn,
                        str(target_id),
                        stale_days=cfg["stale_days"],
                        check_family=check_family,
                        endpoint_filter=endpoint_filter,
                    )
                    if claimable > 0:
                        enq = await _enqueue_asm_exploit_batch(
                            conn, r, str(target_id), target_url, asm_opts,
                            batch_size=min(cfg["batch_size"], claimable),
                            stale_days=cfg["stale_days"], exploit_depth=cfg["exploit_depth"],
                            check_family=check_family,
                            endpoint_filter=endpoint_filter,
                            triggered_by="schedule")
                        await conn.execute(
                            "UPDATE targets SET asm_last_test_at = NOW() WHERE id = $1", target_id)
                        _asm_kind = "test"
                    else:
                        enq = await _enqueue_asm_recon(
                            conn, r, str(target_id), target_url, asm_opts, triggered_by="schedule")
                        await conn.execute(
                            "UPDATE targets SET asm_last_recon_at = NOW() WHERE id = $1", target_id)
                        _asm_kind = "recon"
                    _asm_ok = True
                    print(f"[scheduler] ASM improve ({_asm_kind}) queued for schedule "
                          f"{str(schedule_id)[:8]} -> {str(enq.get('scan_id', ''))[:8]}", flush=True)
                    await _persist_asm_decision(
                        conn,
                        target_id,
                        {
                            "action": _asm_kind,
                            "reason": f"scheduled ASM {_asm_kind} queued",
                            "blocked_by": None,
                            "next_eligible_at": None,
                            "daily_cap_remaining": None,
                            "rate_cap_remaining": None,
                            "claimable": claimable,
                            "tested_today": None,
                        },
                        source="schedule",
                        active_scan_ids=[str(enq.get("scan_id"))] if enq.get("scan_id") else None,
                    )
                except Exception as exc:
                    print(f"[scheduler] ASM improve failed for schedule {str(schedule_id)[:8]}: {exc}", flush=True)
                    await _persist_asm_decision(
                        conn,
                        target_id,
                        {
                            "action": "none",
                            "reason": f"scheduled ASM improve failed: {exc}",
                            "blocked_by": "enqueue_failed",
                            "next_eligible_at": None,
                            "daily_cap_remaining": None,
                            "rate_cap_remaining": None,
                            "claimable": None,
                            "tested_today": None,
                        },
                        source="schedule",
                    )
                if _asm_ok:
                    # Wave queued: advance to the normal cadence and stamp last_run_at.
                    next_run = calculate_next_run(
                        schedule["frequency"], schedule["day_of_week"],
                        schedule["time_of_day"] or "02:00", schedule["timezone"] or "UTC",
                        schedule["jitter_minutes"] or 0)
                    await conn.execute(
                        "UPDATE schedules SET last_run_at = NOW(), next_run_at = $1, updated_at = NOW() WHERE id = $2",
                        next_run, schedule_id)
                else:
                    # Enqueue failed (no silent skip): retry on the next checker tick
                    # via a short backoff, and do NOT stamp last_run_at so the missed
                    # wave is visible and re-attempted instead of waiting a full cycle.
                    retry_at = now + timedelta(minutes=ASM_SCHEDULE_RETRY_MINUTES)
                    await conn.execute(
                        "UPDATE schedules SET next_run_at = $1, updated_at = NOW() WHERE id = $2",
                        retry_at, schedule_id)
                continue

            # Normal schedules are canonical V2 admission inputs. Startup
            # migration rewrites historical rows; execution never translates a
            # legacy identity into fresh authority.
            canonical_schedule = True
            legacy_schedule_fields = sorted(
                LEGACY_SCAN_WRITE_FIELDS.intersection(scan_options)
            )
            if scan_type != "scan" or legacy_schedule_fields:
                print(
                    f"[scheduler] Skipping schedule {str(schedule_id)[:8]}: "
                    "legacy Scan authority was not migrated",
                    flush=True,
                )
                await conn.execute(
                    "UPDATE schedules SET is_active=false, updated_at=NOW() WHERE id=$1",
                    schedule_id,
                )
                continue
            try:
                scan_contract = resolve_scan_contract(
                    budget_profile=scan_options.get("budget_profile"),
                    policy=scan_options.pop("policy", None),
                    advanced=scan_options.pop("advanced", None),
                    approval_receipt_id=scan_options.get("approval_receipt_id"),
                )
            except ValueError as exc:
                print(f"[scheduler] Skipping schedule {str(schedule_id)[:8]}: {exc}", flush=True)
                continue
            scan_options["budget_profile"] = scan_contract.budget_profile
            scan_options["active"] = scan_contract.policy.active_testing
            scan_options["subfinder"] = scan_contract.policy.subdomain_discovery
            scan_options_model = ScanOptions(**scan_options)
            active_testing = scan_contract.policy.active_testing
            if active_testing and scan_options_model.public:
                print(
                    f"[scheduler] Skipping schedule {str(schedule_id)[:8]}: "
                    "public option is incompatible with active testing",
                    flush=True,
                )
                next_run = calculate_next_run(
                    schedule['frequency'],
                    schedule['day_of_week'],
                    schedule['time_of_day'] or '02:00',
                    schedule['timezone'] or 'UTC',
                    schedule['jitter_minutes'] or 0
                )
                await conn.execute("""
                    UPDATE schedules SET next_run_at = $1, updated_at = NOW() WHERE id = $2
                """, next_run, schedule_id)
                continue
            scan_options = _build_canonical_scan_options_payload(
                scan_options_model,
                scan_contract,
            )
            scan_options, _family = _apply_scan_check_family_policy(scan_options)
            parallel_enabled, parallel_worker_count = _apply_auto_sharding_policy(
                scan_options_model,
                scan_options,
                active_testing,
            )
            scan_role = 'parent' if parallel_enabled else 'standalone'

            canonical_job = None
            scan_action_plan = None
            scan_continuation_allocation: ScanContinuationAllocation | None = None
            request_work_manifests: tuple[ScanWorkManifest, ...] = ()
            endpoint_work_manifest: ScanWorkManifest | None = None
            candidate_work_manifest: ScanWorkManifest | None = None
            request_candidate_work_manifest: ScanWorkManifest | None = None
            template_work_manifest: ScanWorkManifest | None = None
            if canonical_schedule:
                scheduled_bindings = [
                    dict(item)
                    for item in scan_options.get("request_collections") or ()
                    if isinstance(item, Mapping)
                ]
                (
                    scheduled_collection_refs,
                    scheduled_collection_endpoints,
                    scheduled_manifest_requests,
                ) = await _generic_collection_refs(
                    conn,
                    target_id=target_id,
                    target_kind="web",
                    bindings=scheduled_bindings,
                )
                scan_options["request_collections"] = scheduled_collection_refs
                if scheduled_collection_endpoints:
                    scan_options["custom_endpoints"] = list(dict.fromkeys((
                        *list(scan_options.get("custom_endpoints") or ()),
                        *scheduled_collection_endpoints,
                    )))[:2000]
                scheduled_executable_refs = _executable_scan_collection_refs(
                    scheduled_collection_refs
                )
                if scheduled_executable_refs:
                    scan_options["runtime_scope_guard"] = (
                        await _freeze_scan_collection_target_binding(
                            target_id=target_id,
                            target_kind="web",
                            target_url=target_url,
                            refs=scheduled_executable_refs,
                            existing_guard=scan_options.get("runtime_scope_guard"),
                        )
                    )
                scan_options["runtime_scope_guard"] = await _freeze_scan_target_binding(
                    target_id=target_id,
                    target_kind="web",
                    target_url=target_url,
                    scope_receipt_id=scan_contract.policy.scope_receipt_id,
                    scheme_inferred=False,
                    existing_guard=scan_options.get("runtime_scope_guard"),
                )
                target_guard = scan_options["runtime_scope_guard"]
                target_binding = TargetBinding(
                    target_id=str(target_id),
                    target_kind="web",
                    canonical_host=target_guard.get("canonical_host"),
                    allowed_origins=tuple(target_guard.get("allowed_origins") or ()),
                    allowed_addresses=tuple(target_guard.get("allowed_addresses") or ()),
                    allowed_root_domains=tuple(target_guard.get("allowed_root_domains") or ()),
                    environment=str(target_guard.get("environment") or "unknown"),
                    scope_receipt_id=scan_contract.policy.scope_receipt_id,
                )
                (
                    request_work_manifests,
                    scheduled_request_manifest_refs,
                ) = _compile_scan_request_work_manifests(
                    scan_id=scan_id,
                    target_binding=target_binding,
                    collection_refs=scheduled_executable_refs,
                    selection_requests=scheduled_manifest_requests,
                    options=scan_options,
                )
                if scheduled_request_manifest_refs:
                    scan_options["request_manifest_refs"] = (
                        scheduled_request_manifest_refs
                    )
                (
                    endpoint_work_manifest,
                    candidate_work_manifest,
                ) = _compile_scan_admission_surface_work_manifests(
                    scan_id=scan_id,
                    target_url=target_url,
                    scan_contract=scan_contract,
                    target_binding=target_binding,
                    options=scan_options,
                    request_manifests=request_work_manifests,
                )
                endpoint_work_manifest_ref = (
                    endpoint_work_manifest.reference().canonical_dict()
                )
                candidate_work_manifest_ref = (
                    candidate_work_manifest.reference().canonical_dict()
                )
                request_candidate_work_manifest = (
                    _compile_scan_request_candidate_work_manifest(
                        request_manifests=request_work_manifests,
                        maximum=scan_contract.budget.max_state_changing_requests,
                    )
                )
                scan_options["endpoint_manifest_id"] = str(
                    endpoint_work_manifest.manifest_id
                )
                scan_options["endpoint_manifest_ref"] = (
                    endpoint_work_manifest_ref
                )
                scan_options["candidate_manifest_ref"] = (
                    candidate_work_manifest_ref
                )
                if (
                    request_candidate_work_manifest is not None
                    and request_candidate_work_manifest.entries
                ):
                    scan_options["request_candidate_manifest_ref"] = (
                        request_candidate_work_manifest.reference().canonical_dict()
                    )
                template_work_manifest = _compile_scan_template_work_manifest(
                    scan_id=scan_id,
                    scan_contract=scan_contract,
                    target_binding=target_binding,
                )
                if template_work_manifest is not None:
                    scan_options["template_manifest_ref"] = (
                        template_work_manifest.reference().canonical_dict()
                    )
                canonical_job = CanonicalScanJob.create(
                    job_id=job_id,
                    scan_id=scan_id,
                    target=target_binding,
                    execution_plan=scan_contract.execution_plan,
                    request_collections=admitted_request_collection_job_refs(
                        scheduled_collection_refs
                    ),
                    credential_profile_ids=admitted_credential_profile_ids(
                        [
                            dict(item) for item in scan_options.get("credential_profile_refs") or ()
                            if isinstance(item, Mapping)
                        ]
                    ),
                    endpoint_manifest_id=str(
                        endpoint_work_manifest.manifest_id
                    ),
                )
                try:
                    (
                        scan_action_plan,
                        scan_continuation_allocation,
                    ) = _compile_scan_admission_action_authority(
                        scan_id=scan_id,
                        scan_contract=scan_contract,
                        target_binding=target_binding,
                        credential_refs=[
                            dict(item)
                            for item in scan_options.get("credential_profile_refs") or ()
                            if isinstance(item, Mapping)
                        ],
                        request_collection_refs=scheduled_executable_refs,
                        request_manifest_refs=scheduled_request_manifest_refs,
                        endpoint_manifest_ref=endpoint_work_manifest_ref,
                        candidate_manifest_ref=(
                            candidate_work_manifest_ref
                            if candidate_work_manifest.entries else None
                        ),
                        request_candidate_manifest_ref=(
                            request_candidate_work_manifest.reference().canonical_dict()
                            if request_candidate_work_manifest is not None
                            and request_candidate_work_manifest.entries else None
                        ),
                        template_manifest_ref=(
                            template_work_manifest.reference().canonical_dict()
                            if template_work_manifest is not None else None
                        ),
                    )
                    if scan_continuation_allocation is not None:
                        scan_options["scan_continuation_allocation_digest"] = (
                            scan_continuation_allocation.allocation_digest
                        )
                except (ScanActionPlanError, ScanBudgetAllocationError) as exc:
                    print(
                        f"[scheduler] Skipping schedule {str(schedule_id)[:8]}: {exc}",
                        flush=True,
                    )
                    continue

            if canonical_job is None or scan_action_plan is None:
                raise RuntimeError(
                    "normal schedule did not compile canonical Scan authority"
                )

            async with conn.transaction():
                await conn.execute("""
                    INSERT INTO scans (
                        id, target_id, target_url, job_id, status, options, scan_type, scan_role,
                        scan_generation, policy_json, budget_json, coverage_status, coverage_json,
                        scan_job_payload, scan_job_digest
                    ) VALUES ($1, $2, $3, $4, 'pending', $5, $6, $7, $8, $9, $10, $11, $12,
                              $13, $14)
                """, uuid.UUID(scan_id), target_id, target_url, job_id,
                     json.dumps(scan_options), "scan", scan_role,
                     "v2",
                     json.dumps(scan_options.get("scan_policy") or {}),
                     json.dumps(scan_options.get("resolved_scan_budget") or {}),
                     "pending",
                     json.dumps({"status": "pending", "reasons": []}),
                     json.dumps(canonical_job.payload()),
                     canonical_job.payload_digest)
                action_store = PostgresScanActionStore()
                await action_store.persist_plan(
                    conn, plan=scan_action_plan,
                )
                if scan_continuation_allocation is not None:
                    await action_store.persist_continuation_allocation(
                        conn,
                        allocation=scan_continuation_allocation,
                        parent_plan=scan_action_plan,
                    )
                for manifest in request_work_manifests:
                    await PostgresScanManifestStore().persist(
                        conn, manifest=manifest,
                    )
                for manifest in (
                    endpoint_work_manifest, candidate_work_manifest,
                    request_candidate_work_manifest,
                ):
                    if manifest is not None:
                        await PostgresScanManifestStore().persist(
                            conn, manifest=manifest,
                        )
                if template_work_manifest is not None:
                    await PostgresScanManifestStore().persist(
                        conn, manifest=template_work_manifest,
                    )

        job_data = canonical_job.queue_payload(
            placement=(
                scan_options.get("placement")
                if isinstance(scan_options.get("placement"), Mapping) else None
            ),
        )
        if parallel_enabled:
            _configure_scan_plan_job(job_data, parallel_worker_count)

        try:
            enqueue_job(r, QUEUE_NAME, job_data)
        except Exception as exc:
            # Do not advance the schedule if Redis failed to accept the queue
            # item. Mark the inserted scan failed so the next scheduler pass can
            # retry the still-due schedule instead of being blocked by a
            # phantom pending scan that no worker can ever receive.
            async with pool.acquire() as conn:
                await conn.execute("""
                    UPDATE scans
                    SET status = 'failed', error_message = $1, completed_at = NOW()
                    WHERE id = $2
                """, f"scheduled enqueue failed: {exc}", uuid.UUID(scan_id))
            print(
                f"[scheduler] Failed to enqueue scheduled scan {scan_id[:8]} for schedule "
                f"{str(schedule_id)[:8]}: {exc}",
                flush=True,
            )
            continue

        try:
            r.hset(f"job:{job_id}", mapping={'status': 'queued', 'target': target_url})
        except Exception as exc:
            print(
                f"[scheduler] Scheduled scan {scan_id[:8]} queued, but Redis job status update failed: {exc}",
                flush=True,
            )

        next_run = calculate_next_run(
            schedule['frequency'],
            schedule['day_of_week'],
            schedule['time_of_day'] or '02:00',
            schedule['timezone'] or 'UTC',
            schedule['jitter_minutes'] or 0
        )
        async with pool.acquire() as conn:
            await conn.execute("""
                UPDATE schedules SET last_run_at = $1, next_run_at = $2, updated_at = NOW()
                WHERE id = $3
            """, now, next_run, schedule_id)

        print(f"[scheduler] Triggered Scan {scan_id[:8]} for schedule {str(schedule_id)[:8]} ({target_url})", flush=True)


async def schedule_runner(pool: asyncpg.Pool):
    """Background task to periodically check and run due schedules."""
    print("[scheduler] Schedule runner started", flush=True)
    while True:
        try:
            await asyncio.sleep(SCHEDULE_CHECK_INTERVAL_SECONDS)
            await run_due_schedules(pool)
        except asyncio.CancelledError:
            print("[scheduler] Schedule runner stopped", flush=True)
            break
        except Exception as e:
            print(f"[scheduler] Error running schedules: {e}", flush=True)


async def run_asm_dispatch(pool: asyncpg.Pool):
    """One tick of the Continuous ASM dispatcher (docs §16 Phase 3/4): for each
    ASM-enabled target, pick at most ONE action (recon or exploit batch) within
    its freshness/rate/window budget and enqueue it. Never stacks load on a
    target (the crash lesson) and honours a per-root-domain rate cap."""
    r = get_redis()
    now = utc_now()

    async with pool.acquire() as conn:
        targets = await conn.fetch("""
            SELECT id, url, root_domain, scan_options, asm_config,
                   asm_last_test_at, asm_last_recon_at
            FROM targets
            WHERE asm_enabled = true AND is_active = true
        """)

    for t in targets:
        target_id = str(t['id'])
        target_url = t['url']
        root_domain = t['root_domain']
        raw_config = _decode_asm_config(t['asm_config'])
        cfg = asm_inventory.merge_asm_config(raw_config)
        try:
            async with pool.acquire() as conn:
                active = await conn.fetchval("""
                    SELECT COUNT(*) FROM scans
                    WHERE target_id = $1 AND status IN ('pending', 'queued', 'running')
                """, t['id'])
                claimable = await asm_inventory.claimable_count(conn, target_id, stale_days=cfg['stale_days'])
                tested_today = await asm_inventory.tested_recently_count(conn, target_id, hours=24)
                domain_rate_exceeded = False
                cap = cfg['max_requests_per_hour_per_domain']
                used = 0
                if cap > 0 and root_domain:
                    used = await asm_inventory.domain_tested_recently_count(conn, root_domain, hours=1)
                    reserved = _asm_reserved_count(r, root_domain)
                    domain_rate_exceeded = (used + reserved) >= cap

                decision = asm_inventory.decide_asm_action(
                    now=now,
                    last_test_at=t['asm_last_test_at'],
                    last_recon_at=t['asm_last_recon_at'],
                    has_active_scan=bool(active and active > 0),
                    claimable=claimable,
                    tested_today=tested_today,
                    domain_rate_exceeded=domain_rate_exceeded,
                    domain_rate_remaining=max(0, cap - used - reserved) if cap > 0 and root_domain else None,
                    config=raw_config,
                )
                action = decision['action']
                if action == 'none':
                    active_ids = await _asm_active_scan_ids(conn, target_id) if decision.get("blocked_by") == "active_scan" else None
                    await _persist_asm_decision(
                        conn,
                        target_id,
                        decision,
                        source="dispatcher",
                        active_scan_ids=active_ids,
                    )
                    continue

                base_opts = _decode_json_value(t['scan_options']) or {}
                if not isinstance(base_opts, dict):
                    base_opts = {}
                if action == 'recon':
                    enq = await _enqueue_asm_recon(conn, r, target_id, target_url, base_opts)
                    await conn.execute("UPDATE targets SET asm_last_recon_at = NOW() WHERE id = $1", t['id'])
                    await _persist_asm_decision(
                        conn,
                        target_id,
                        {**decision, "active_scan_id": enq["scan_id"], "active_scan_ids": [enq["scan_id"]]},
                        source="dispatcher",
                        active_scan_ids=[enq["scan_id"]],
                    )
                    print(f"[asm] recon queued for {target_url} -> scan {enq['scan_id'][:8]}", flush=True)
                elif action == 'test':
                    dispatch_batch_size = min(cfg['batch_size'], claimable)
                    daily_cap = cfg['daily_endpoint_cap']
                    if daily_cap > 0:
                        dispatch_batch_size = min(dispatch_batch_size, max(0, daily_cap - tested_today))
                    if cap > 0 and root_domain:
                        dispatch_batch_size = _reserve_asm_domain_rate(
                            r,
                            root_domain,
                            max(0, cap - used),
                            dispatch_batch_size,
                        )
                    if dispatch_batch_size <= 0:
                        await _persist_asm_decision(
                            conn,
                            target_id,
                            {**decision, "action": "none", "reason": "no dispatch budget remaining", "blocked_by": "rate_or_daily_cap"},
                            source="dispatcher",
                        )
                        continue
                    enq = await _enqueue_asm_exploit_batch(
                        conn, r, target_id, target_url, base_opts,
                        batch_size=dispatch_batch_size, stale_days=cfg['stale_days'],
                        exploit_depth=cfg['exploit_depth'], triggered_by='dispatcher',
                        domain_rate_reserved=dispatch_batch_size,
                    )
                    await conn.execute("UPDATE targets SET asm_last_test_at = NOW() WHERE id = $1", t['id'])
                    await _persist_asm_decision(
                        conn,
                        target_id,
                        {**decision, "active_scan_id": enq["scan_id"], "active_scan_ids": [enq["scan_id"]]},
                        source="dispatcher",
                        active_scan_ids=[enq["scan_id"]],
                    )
                    print(f"[asm] test batch queued for {target_url} "
                          f"({dispatch_batch_size} eps, {claimable} claimable) -> scan {enq['scan_id'][:8]}", flush=True)
        except Exception as e:
            print(f"[asm] dispatch error for {target_url}: {e}", flush=True)


async def asm_dispatcher(pool: asyncpg.Pool):
    """Background loop driving Continuous ASM (docs §16 Phase 3)."""
    print("[asm] Continuous ASM dispatcher started", flush=True)
    while True:
        try:
            await asyncio.sleep(ASM_DISPATCH_INTERVAL_SECONDS)
            await run_asm_dispatch(pool)
        except asyncio.CancelledError:
            print("[asm] Continuous ASM dispatcher stopped", flush=True)
            break
        except Exception as e:
            print(f"[asm] dispatcher error: {e}", flush=True)


# Database connection pool
db_pool: Optional[asyncpg.Pool] = None
_auth_session_store = PostgresAuthSessionStore()


async def cleanup_expired_auth_sessions_once(
    pool: asyncpg.Pool,
    *,
    limit: int = 500,
) -> int:
    """Destroy a bounded batch of expired worker-only session ciphertext."""

    async with pool.acquire() as conn:
        return await _auth_session_store.expire_stale(conn, limit=limit)


async def cleanup_expired_scan_artifacts_once(
    pool: asyncpg.Pool,
    *,
    limit: int = 100,
) -> dict[str, int]:
    """Claim, delete, and tombstone expired artifact objects centrally."""
    batch_limit = max(1, min(int(limit), 500))
    async with pool.acquire() as conn:
        async with conn.transaction():
            # A control-plane crash after claiming an object is recoverable.
            await conn.execute(
                """
                UPDATE scan_artifacts
                SET status='available', updated_at=NOW()
                WHERE status='deleting'
                  AND updated_at < NOW() - INTERVAL '15 minutes'
                """
            )
            rows = await conn.fetch(
                """
                WITH candidates AS (
                    SELECT id
                    FROM scan_artifacts
                    WHERE status='available'
                      AND expires_at IS NOT NULL
                      AND expires_at <= NOW()
                    ORDER BY expires_at, id
                    FOR UPDATE SKIP LOCKED
                    LIMIT $1
                )
                UPDATE scan_artifacts sa
                SET status='deleting', updated_at=NOW()
                FROM candidates
                WHERE sa.id=candidates.id
                RETURNING sa.id, sa.storage_uri
                """,
                batch_limit,
            )

    deleted = 0
    failed = 0
    for row in rows:
        error: str | None = None
        try:
            await asyncio.to_thread(
                delete_artifact_object,
                str(row["storage_uri"]),
                results_dir=RESULTS_DIR,
            )
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"[:500]
        async with pool.acquire() as conn:
            if error is None:
                await conn.execute(
                    """
                    UPDATE scan_artifacts
                    SET status='deleted', deleted_at=NOW(), updated_at=NOW(),
                        metadata=metadata || jsonb_build_object(
                            'retention_deleted_at', NOW()::text
                        )
                    WHERE id=$1 AND status='deleting'
                    """,
                    row["id"],
                )
                deleted += 1
            else:
                await conn.execute(
                    """
                    UPDATE scan_artifacts
                    SET status='available', updated_at=NOW(),
                        metadata=metadata || jsonb_build_object(
                            'retention_delete_error', $2::text,
                            'retention_delete_retry_at', NOW()::text
                        )
                    WHERE id=$1 AND status='deleting'
                    """,
                    row["id"],
                    error,
                )
                failed += 1
    return {"claimed": len(rows), "deleted": deleted, "failed": failed}


async def scan_artifact_retention_runner(pool: asyncpg.Pool) -> None:
    interval = max(60, _int_env("ARTIFACT_RETENTION_SWEEP_SECONDS", 3600))
    while True:
        try:
            outcome = await cleanup_expired_scan_artifacts_once(pool)
            if outcome["claimed"]:
                print(f"[artifact-retention] {outcome}", flush=True)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            print(
                f"[artifact-retention] sweep failed: {type(exc).__name__}: {exc}",
                flush=True,
            )
        await asyncio.sleep(interval)


def _int_env(name: str, default: int) -> int:
    """Coerce an env var to int, falling back to default on bad values."""
    try:
        raw = os.environ.get(name)
        return int(raw) if raw is not None and raw != "" else default
    except (TypeError, ValueError):
        return default




def _set_database_pool(pool: Any) -> None:
    """Publish the one live pool to legacy helpers during router extraction."""
    global db_pool
    db_pool = pool


lifespan = create_api_lifespan(ApiLifecycleDependencies(
    database_url=DATABASE_URL,
    create_pool=lambda *args, **kwargs: asyncpg.create_pool(*args, **kwargs),
    int_env=lambda name, default: _int_env(name, default),
    set_pool=_set_database_pool,
    ensure_schema=lambda pool: ensure_verification_schema(pool),
    publish_max_active_scans=lambda: _publish_max_active_scans(),
    publish_scanner_version=lambda: _publish_scanner_version(),
    fleet_edge_mode=lambda: os.environ.get("FLEET_EDGE_MODE", "").strip().lower()
    in {"1", "true", "yes", "on"},
    background_controllers=(
        ("stale_scan_checker", lambda pool: stale_scan_checker(pool)),
        ("schedule_runner", lambda pool: schedule_runner(pool)),
        ("asm_dispatcher", lambda pool: asm_dispatcher(pool)),
        ("research_autopilot_runner", lambda pool: research_autopilot_runner(pool)),
        (
            "scan_artifact_retention_runner",
            lambda pool: scan_artifact_retention_runner(pool),
        ),
        (
            "model_intake_automatic_review_runner",
            lambda pool: model_intake_automatic_review_runner(pool),
        ),
    ),
))


app = FastAPI(
    title="ShakerScan API",
    description="Open Source Dynamic Application Security Testing Scanner",
    version="1.0.0",
    lifespan=lifespan
)

try:
    from credential_api import router as credential_router
    from credential_api import public_credential_validation_errors
except ModuleNotFoundError:
    from api.credential_api import router as credential_router
    from api.credential_api import public_credential_validation_errors

try:
    from public_api_contract import (
        PublicV2BodyLimitMiddleware,
        PublicV2IdempotencyMiddleware,
        add_public_v2_idempotency_openapi,
        public_v2_surface,
    )
except ModuleNotFoundError:
    from api.public_api_contract import (
        PublicV2BodyLimitMiddleware,
        PublicV2IdempotencyMiddleware,
        add_public_v2_idempotency_openapi,
        public_v2_surface,
    )

app.include_router(credential_router)
configure_scan_read_router(lambda: db_pool)
app.include_router(scan_read_router)
configure_request_collection_router(lambda: db_pool)
app.include_router(request_collection_router)
try:
    from ai_gate.catalog_router import router as ai_catalog_router
except ModuleNotFoundError:  # package import in host-side tests
    from api.ai_gate.catalog_router import router as ai_catalog_router
app.include_router(ai_catalog_router)
try:
    from policy_profiles.router import (
        PolicyProfileRequest,
        _validate_policy_profile_required_anchor_ids,
        configure_policy_profile_router,
        create_policy_profile,
        delete_policy_profile,
        list_policy_profiles,
        router as policy_profile_router,
        update_policy_profile,
    )
except ModuleNotFoundError:  # package import in host-side tests
    from api.policy_profiles.router import (
        PolicyProfileRequest,
        _validate_policy_profile_required_anchor_ids,
        configure_policy_profile_router,
        create_policy_profile,
        delete_policy_profile,
        list_policy_profiles,
        router as policy_profile_router,
        update_policy_profile,
    )
configure_policy_profile_router(lambda: db_pool)
app.include_router(policy_profile_router)
try:
    from operations.router import (
        ACTION_CENTER_PRIORITY_ORDER,
        _action_center_item,
        _ai_requirement_applies,
        _build_dashboard_action_center,
        _build_dashboard_product_status,
        _dashboard_product_status_item,
        _metadata_has_any,
        _missing_ai_control_labels,
        dashboard,
        get_artifact_storage_health,
        configure_operations_router,
        router as operations_router,
        DEVICE_WEB_ORIGIN_ROLE,
        RETEST_RUNNING_TIMEOUT_MINUTES,
        TIMELINE_STATUSES,
        _SCAN_STATUS_TO_TIMELINE,
        _campaign_action_timeline_event,
        _command_result_timeline_event,
        _evidence_instance_timeline_event,
        _export_event_timeline_event,
        _hidden_scan_roles_for_list,
        _public_export_event_row,
        _refuter_review_timeline_event,
        _scan_timeline_event,
        _schedule_timeline_event,
        _set_cli_v1_deprecation_headers,
        _timeline_scan_status,
        _timeline_sort_key,
        clear_queue,
        get_cli_v1_scan,
        get_compose_context,
        get_discovery,
        get_latest_result,
        get_system_resources,
        gungnir_start,
        gungnir_status,
        gungnir_stop,
        list_cli_v1_findings,
        list_discovery_runs,
        list_results,
        mission_timeline,
        queue_stats,
        start_discovery,
    )
except ModuleNotFoundError:  # package import in host-side tests
    from api.operations.router import (
        ACTION_CENTER_PRIORITY_ORDER,
        _action_center_item,
        _ai_requirement_applies,
        _build_dashboard_action_center,
        _build_dashboard_product_status,
        _dashboard_product_status_item,
        _metadata_has_any,
        _missing_ai_control_labels,
        dashboard,
        get_artifact_storage_health,
        configure_operations_router,
        router as operations_router,
        DEVICE_WEB_ORIGIN_ROLE,
        RETEST_RUNNING_TIMEOUT_MINUTES,
        TIMELINE_STATUSES,
        _SCAN_STATUS_TO_TIMELINE,
        _campaign_action_timeline_event,
        _command_result_timeline_event,
        _evidence_instance_timeline_event,
        _export_event_timeline_event,
        _hidden_scan_roles_for_list,
        _public_export_event_row,
        _refuter_review_timeline_event,
        _scan_timeline_event,
        _schedule_timeline_event,
        _set_cli_v1_deprecation_headers,
        _timeline_scan_status,
        _timeline_sort_key,
        clear_queue,
        get_cli_v1_scan,
        get_compose_context,
        get_discovery,
        get_latest_result,
        get_system_resources,
        gungnir_start,
        gungnir_status,
        gungnir_stop,
        list_cli_v1_findings,
        list_discovery_runs,
        list_results,
        mission_timeline,
        queue_stats,
        start_discovery,
    )
configure_operations_router(
    lambda: db_pool,
    get_redis=lambda *a, **k: get_redis(*a, **k),
    enqueue_job=lambda *a, **k: enqueue_job(*a, **k),
    docker_socket_request=lambda *a, **k: docker_socket_request(*a, **k),
    results_dir=lambda: RESULTS_DIR,
    get_scan=lambda *a, **k: get_scan(*a, **k),
    worker_freshness_snapshot=lambda *a, **k: _worker_freshness_snapshot(*a, **k),
)
app.include_router(operations_router)
try:
    from settings_routes.router import (
        AISettingsProbeRequest,
        AISettingsUpdate,
        AutomationSettingsUpdate,
        ScanExecutionSettingsUpdate,
        configure_settings_router,
        router as settings_router,
        AI_SETTINGS_KEY,
        APPROVAL_POLICY_SETTING_KEY,
        AUTOMATION_SETTINGS_KEY,
        AUTO_SHARD_MAX_SHARDS,
        LOCAL_ENV_FILE,
        ResearchDecisionRequest,
        SCAN_SETTINGS_KEY,
        _EXPERIMENT_WORKFLOW_TEMPLATES,
        _MASS_ASSIGNMENT_CREATE_TEMPLATE,
        _automation_settings_with_durable_flags,
        _bind_research_decision_to_observation,
        _default_scan_execution_settings,
        _infer_blank_read_only_command,
        _load_effective_scan_execution_settings,
        _load_probe_ai_provider,
        _load_research_ai_provider,
        _mask_secret,
        _merge_safe_default_asm_config,
        _normalize_auto_shard_count,
        _normalize_confidence,
        _normalize_env_value,
        _normalize_non_negative_int,
        _normalize_parallel_strategy,
        _persist_env_updates,
        _probe_ai_provider,
        _read_durable_setting,
        _research_decision_json_schema,
        _research_intent_tokens,
        _research_planner_messages,
        _research_provider_contract_error,
        _research_requested_input_is_in_observation,
        _research_selected_experiment_templates,
        _running_scan_worker_container_ids_best_effort,
        _running_scan_worker_count_best_effort,
        _safe_default_asm_config,
        _sanitize_ai_settings_response,
        _sanitize_automation_settings_response,
        _sanitize_scan_execution_settings_response,
        _scan_execution_update_mapping,
        _write_durable_setting,
        get_ai_settings,
        get_automation_settings,
        get_scan_execution_settings,
        test_ai_settings,
        update_ai_settings,
        update_automation_settings,
        update_scan_execution_settings,
    )
except ModuleNotFoundError:  # package import in host-side tests
    from api.settings_routes.router import (
        AISettingsProbeRequest,
        AISettingsUpdate,
        AutomationSettingsUpdate,
        ScanExecutionSettingsUpdate,
        configure_settings_router,
        router as settings_router,
        AI_SETTINGS_KEY,
        APPROVAL_POLICY_SETTING_KEY,
        AUTOMATION_SETTINGS_KEY,
        AUTO_SHARD_MAX_SHARDS,
        LOCAL_ENV_FILE,
        ResearchDecisionRequest,
        SCAN_SETTINGS_KEY,
        _EXPERIMENT_WORKFLOW_TEMPLATES,
        _MASS_ASSIGNMENT_CREATE_TEMPLATE,
        _automation_settings_with_durable_flags,
        _bind_research_decision_to_observation,
        _default_scan_execution_settings,
        _infer_blank_read_only_command,
        _load_effective_scan_execution_settings,
        _load_probe_ai_provider,
        _load_research_ai_provider,
        _mask_secret,
        _merge_safe_default_asm_config,
        _normalize_auto_shard_count,
        _normalize_confidence,
        _normalize_env_value,
        _normalize_non_negative_int,
        _normalize_parallel_strategy,
        _persist_env_updates,
        _probe_ai_provider,
        _read_durable_setting,
        _research_decision_json_schema,
        _research_intent_tokens,
        _research_planner_messages,
        _research_provider_contract_error,
        _research_requested_input_is_in_observation,
        _research_selected_experiment_templates,
        _running_scan_worker_container_ids_best_effort,
        _running_scan_worker_count_best_effort,
        _safe_default_asm_config,
        _sanitize_ai_settings_response,
        _sanitize_automation_settings_response,
        _sanitize_scan_execution_settings_response,
        _scan_execution_update_mapping,
        _write_durable_setting,
        get_ai_settings,
        get_automation_settings,
        get_scan_execution_settings,
        test_ai_settings,
        update_ai_settings,
        update_automation_settings,
        update_scan_execution_settings,
    )
configure_settings_router(
    lambda: db_pool,
    get_redis=lambda *a, **k: get_redis(*a, **k),
    is_truthy=lambda *a, **k: _is_truthy(*a, **k),
    normalize_severity=lambda *a, **k: _normalize_severity(*a, **k),
    load_effective_ai_settings=lambda *a, **k: _load_effective_ai_settings(*a, **k),
    load_effective_automation_settings=lambda *a, **k: _load_effective_automation_settings(*a, **k),
    normalize_research_planner_mode=lambda *a, **k: _normalize_research_planner_mode(*a, **k),
    bounded_research_payload=lambda *a, **k: _bounded_research_payload(*a, **k),
    is_local_scan_worker_container=lambda *a, **k: _is_local_scan_worker_container(*a, **k),
    local_compose_project_best_effort=lambda *a, **k: _local_compose_project_best_effort(*a, **k),
    docker_socket_request=lambda *a, **k: docker_socket_request(*a, **k),
)
app.include_router(settings_router)
try:
    from model_intake.router import (
        POLICY_PROFILES,
        configure_model_intake_router,
        _model_intake_auto_runner_memory_ready,
        _model_intake_auto_runner_readiness_grace_active,
        router as model_intake_router,
        HF_MODEL_INFO_MAX_BYTES,
        MODEL_INTAKE_ADMISSION_FORBIDDEN_FIELDS,
        MODEL_INTAKE_ADMISSION_FORBIDDEN_METADATA_KEYS,
        MODEL_INTAKE_COMMON_ARTIFACTS,
        MODEL_INTAKE_DEPENDENCY_FILES,
        MODEL_INTAKE_EXECUTABLE_EXTENSIONS,
        MODEL_INTAKE_GUEST_KERNEL_SHA256,
        MODEL_INTAKE_GUEST_KERNEL_URL,
        MODEL_INTAKE_GUEST_ROOTFS_INPUTS,
        MODEL_INTAKE_METADATA_FILES,
        MODEL_INTAKE_REPOSITORY_MANIFEST_MAX_FILES,
        MODEL_INTAKE_RISKY_EXTENSIONS,
        MODEL_INTAKE_SAFER_EXTENSIONS,
        MODEL_INTAKE_TOKENIZER_FILES,
        ModelAdmissionV2VerifyRequest,
        ModelApprovalCreateRequest,
        ModelEvidenceFreezeRequest,
        ModelIntakeAdmissionRevokeRequest,
        ModelIntakeAdmissionVerifyRequest,
        ModelIntakeAgentReplyRequest,
        ModelIntakeAgentSessionRequest,
        ModelIntakeAutomaticReviewRequest,
        ModelIntakeReassessmentEventRequest,
        ModelIntakeResolveRequest,
        ModelIntakeRetentionCleanupRequest,
        ModelIntakeScanRequest,
        ModelIntakeTrustAnchorRequest,
        ModelLoaderProfileResolveRequest,
        ModelPolicyDecisionCreateRequest,
        ModelPromotionRequest,
        ModelRunnerEvidenceReceiptRequest,
        ModelRunnerJobCreateRequest,
        ModelRunnerStorageCleanupRequest,
        ModelSubmissionRequest,
        ModelSubmissionStaticRunRequest,
        _MODEL_INTAKE_PROVIDER_AUTHORITY_KEYS,
        _MODEL_INTAKE_STAGE_LOCK,
        _MODEL_INTAKE_STAGE_LOG_LINES,
        _apply_model_intake_policy_profile_requirements,
        _call_model_intake_signer,
        _detect_model_intake_platform,
        _enrich_model_intake_scan_request,
        _execute_model_intake_agent_action,
        _expand_model_intake_policy_profile_requirements,
        _expand_model_intake_saved_trust_anchors,
        _expire_model_intake_admissions,
        _hf_api_model_info,
        _hf_candidate_score,
        _hf_file_candidates,
        _hf_files_named,
        _hf_metadata_from_model_info,
        _hf_repo_file_inventory,
        _hf_repo_file_record,
        _hf_repo_path_status,
        _hf_repository_manifest,
        _import_embedding_hint_readers,
        _import_model_intake_helpers,
        _is_azure_blob_hostname,
        _is_hf_ref,
        _is_s3_hostname,
        _looks_like_hf_repo_id,
        _merge_model_intake_trust_anchor_material,
        _model_intake_artifact_size_bytes,
        _model_intake_auto_timeline,
        _model_intake_automatic_review_payload,
        _model_intake_content_free_coverage,
        _model_intake_conversion_output_usable,
        _model_intake_converted_snapshot_materialization,
        _model_intake_effective_inspection_complete,
        _model_intake_evidence_export,
        _model_intake_evidence_matches_bundle,
        _model_intake_finding_summary,
        _model_intake_forbidden_metadata_paths,
        _model_intake_guest_rootfs_inputs_sha256,
        _model_intake_policy_bundle_sha256,
        _model_intake_present_pending_controls,
        _model_intake_provider_resolution_failed_metadata,
        _model_intake_repository_manifest_summary,
        _model_intake_required_static_checks,
        _model_intake_runner_http,
        _model_intake_runner_readiness_snapshot,
        _model_intake_safe_file_list,
        _model_intake_safe_relative_path,
        _model_intake_scanner_result_summaries,
        _model_intake_snapshot_custom_code_sha256,
        _model_intake_snapshot_materialization,
        _model_intake_stage_dir,
        _model_intake_stage_log,
        _model_intake_stage_manifest,
        _model_intake_stage_run,
        _model_intake_stage_set,
        _model_intake_static_evidence_status,
        _model_intake_status_map,
        _model_intake_transition_is_allowed,
        _model_intake_untrusted_runner_claims,
        _model_intake_uuid,
        _model_intake_value_is_nonempty,
        _persist_model_intake_runner_evidence,
        _prepare_model_intake_rescan_options,
        _register_and_rescan_converted_snapshot,
        _reset_model_intake_for_new_evidence,
        _resolve_huggingface_model_intake,
        _sanitize_model_intake_preflight_authority,
        _sha256_file,
        _strip_model_intake_governance_metadata,
        _transition_model_intake_submission,
        _validate_model_intake_admission_request_authority,
        _validate_model_intake_trust_anchor_request,
        _verify_model_intake_admission_v2_request,
        _write_model_intake_stage_manifest,
        attach_model_intake_runner_evidence,
        attach_model_intake_static_run,
        cancel_model_intake_agent_session,
        cleanup_model_intake_quarantine,
        create_model_intake_agent_session,
        create_model_intake_approval,
        create_model_intake_automatic_review,
        create_model_intake_policy_decision,
        create_model_intake_reassessment_event,
        create_model_intake_runner_job,
        create_model_intake_submission,
        create_model_intake_trust_anchor,
        deactivate_model_intake_trust_anchor,
        download_model_intake_license_bom,
        download_model_intake_sbom,
        download_model_intake_third_party_notices,
        freeze_model_intake_evidence,
        get_model_intake_admission,
        get_model_intake_agent_session,
        get_model_intake_automatic_review,
        get_model_intake_automatic_review_report,
        get_model_intake_evidence_export,
        get_model_intake_submission,
        get_model_intake_submission_report,
        list_model_intake_admissions,
        list_model_intake_agent_sessions,
        list_model_intake_automatic_reviews,
        list_model_intake_runner_jobs,
        list_model_intake_submissions,
        list_model_intake_trust_anchors,
        model_intake_capabilities,
        model_intake_check_catalog,
        model_intake_embedding_configuration,
        model_intake_operator_session,
        model_intake_provider_readiness,
        model_intake_runner_bundle,
        model_intake_runner_install_plan,
        model_intake_runner_readiness,
        model_intake_runner_stage,
        model_intake_runner_stage_status,
        model_intake_runner_storage,
        model_intake_runner_storage_cleanup,
        model_intake_sbom_summary,
        model_intake_scanner_readiness,
        observe_model_intake_deployment_v2,
        promote_model_intake_submission,
        refresh_model_intake_runner_job,
        reply_model_intake_agent_session,
        rescan_model_intake_target,
        resolve_model_intake,
        resolve_model_intake_conversion_profile,
        resolve_model_intake_loader_profile,
        revoke_model_intake_admission,
        scan_model_intake,
        update_model_intake_trust_anchor,
        verify_model_intake_admission,
        verify_model_intake_admission_v2,
    )
except ModuleNotFoundError:  # package import in host-side tests
    from api.model_intake.router import (
        POLICY_PROFILES,
        configure_model_intake_router,
        _model_intake_auto_runner_memory_ready,
        _model_intake_auto_runner_readiness_grace_active,
        router as model_intake_router,
        HF_MODEL_INFO_MAX_BYTES,
        MODEL_INTAKE_ADMISSION_FORBIDDEN_FIELDS,
        MODEL_INTAKE_ADMISSION_FORBIDDEN_METADATA_KEYS,
        MODEL_INTAKE_COMMON_ARTIFACTS,
        MODEL_INTAKE_DEPENDENCY_FILES,
        MODEL_INTAKE_EXECUTABLE_EXTENSIONS,
        MODEL_INTAKE_GUEST_KERNEL_SHA256,
        MODEL_INTAKE_GUEST_KERNEL_URL,
        MODEL_INTAKE_GUEST_ROOTFS_INPUTS,
        MODEL_INTAKE_METADATA_FILES,
        MODEL_INTAKE_REPOSITORY_MANIFEST_MAX_FILES,
        MODEL_INTAKE_RISKY_EXTENSIONS,
        MODEL_INTAKE_SAFER_EXTENSIONS,
        MODEL_INTAKE_TOKENIZER_FILES,
        ModelAdmissionV2VerifyRequest,
        ModelApprovalCreateRequest,
        ModelEvidenceFreezeRequest,
        ModelIntakeAdmissionRevokeRequest,
        ModelIntakeAdmissionVerifyRequest,
        ModelIntakeAgentReplyRequest,
        ModelIntakeAgentSessionRequest,
        ModelIntakeAutomaticReviewRequest,
        ModelIntakeReassessmentEventRequest,
        ModelIntakeResolveRequest,
        ModelIntakeRetentionCleanupRequest,
        ModelIntakeScanRequest,
        ModelIntakeTrustAnchorRequest,
        ModelLoaderProfileResolveRequest,
        ModelPolicyDecisionCreateRequest,
        ModelPromotionRequest,
        ModelRunnerEvidenceReceiptRequest,
        ModelRunnerJobCreateRequest,
        ModelRunnerStorageCleanupRequest,
        ModelSubmissionRequest,
        ModelSubmissionStaticRunRequest,
        _MODEL_INTAKE_PROVIDER_AUTHORITY_KEYS,
        _MODEL_INTAKE_STAGE_LOCK,
        _MODEL_INTAKE_STAGE_LOG_LINES,
        _apply_model_intake_policy_profile_requirements,
        _call_model_intake_signer,
        _detect_model_intake_platform,
        _enrich_model_intake_scan_request,
        _execute_model_intake_agent_action,
        _expand_model_intake_policy_profile_requirements,
        _expand_model_intake_saved_trust_anchors,
        _expire_model_intake_admissions,
        _hf_api_model_info,
        _hf_candidate_score,
        _hf_file_candidates,
        _hf_files_named,
        _hf_metadata_from_model_info,
        _hf_repo_file_inventory,
        _hf_repo_file_record,
        _hf_repo_path_status,
        _hf_repository_manifest,
        _import_embedding_hint_readers,
        _import_model_intake_helpers,
        _is_azure_blob_hostname,
        _is_hf_ref,
        _is_s3_hostname,
        _looks_like_hf_repo_id,
        _merge_model_intake_trust_anchor_material,
        _model_intake_artifact_size_bytes,
        _model_intake_auto_timeline,
        _model_intake_automatic_review_payload,
        _model_intake_content_free_coverage,
        _model_intake_conversion_output_usable,
        _model_intake_converted_snapshot_materialization,
        _model_intake_effective_inspection_complete,
        _model_intake_evidence_export,
        _model_intake_evidence_matches_bundle,
        _model_intake_finding_summary,
        _model_intake_forbidden_metadata_paths,
        _model_intake_guest_rootfs_inputs_sha256,
        _model_intake_policy_bundle_sha256,
        _model_intake_present_pending_controls,
        _model_intake_provider_resolution_failed_metadata,
        _model_intake_repository_manifest_summary,
        _model_intake_required_static_checks,
        _model_intake_runner_http,
        _model_intake_runner_readiness_snapshot,
        _model_intake_safe_file_list,
        _model_intake_safe_relative_path,
        _model_intake_scanner_result_summaries,
        _model_intake_snapshot_custom_code_sha256,
        _model_intake_snapshot_materialization,
        _model_intake_stage_dir,
        _model_intake_stage_log,
        _model_intake_stage_manifest,
        _model_intake_stage_run,
        _model_intake_stage_set,
        _model_intake_static_evidence_status,
        _model_intake_status_map,
        _model_intake_transition_is_allowed,
        _model_intake_untrusted_runner_claims,
        _model_intake_uuid,
        _model_intake_value_is_nonempty,
        _persist_model_intake_runner_evidence,
        _prepare_model_intake_rescan_options,
        _register_and_rescan_converted_snapshot,
        _reset_model_intake_for_new_evidence,
        _resolve_huggingface_model_intake,
        _sanitize_model_intake_preflight_authority,
        _sha256_file,
        _strip_model_intake_governance_metadata,
        _transition_model_intake_submission,
        _validate_model_intake_admission_request_authority,
        _validate_model_intake_trust_anchor_request,
        _verify_model_intake_admission_v2_request,
        _write_model_intake_stage_manifest,
        attach_model_intake_runner_evidence,
        attach_model_intake_static_run,
        cancel_model_intake_agent_session,
        cleanup_model_intake_quarantine,
        create_model_intake_agent_session,
        create_model_intake_approval,
        create_model_intake_automatic_review,
        create_model_intake_policy_decision,
        create_model_intake_reassessment_event,
        create_model_intake_runner_job,
        create_model_intake_submission,
        create_model_intake_trust_anchor,
        deactivate_model_intake_trust_anchor,
        download_model_intake_license_bom,
        download_model_intake_sbom,
        download_model_intake_third_party_notices,
        freeze_model_intake_evidence,
        get_model_intake_admission,
        get_model_intake_agent_session,
        get_model_intake_automatic_review,
        get_model_intake_automatic_review_report,
        get_model_intake_evidence_export,
        get_model_intake_submission,
        get_model_intake_submission_report,
        list_model_intake_admissions,
        list_model_intake_agent_sessions,
        list_model_intake_automatic_reviews,
        list_model_intake_runner_jobs,
        list_model_intake_submissions,
        list_model_intake_trust_anchors,
        model_intake_capabilities,
        model_intake_check_catalog,
        model_intake_embedding_configuration,
        model_intake_operator_session,
        model_intake_provider_readiness,
        model_intake_runner_bundle,
        model_intake_runner_install_plan,
        model_intake_runner_readiness,
        model_intake_runner_stage,
        model_intake_runner_stage_status,
        model_intake_runner_storage,
        model_intake_runner_storage_cleanup,
        model_intake_sbom_summary,
        model_intake_scanner_readiness,
        observe_model_intake_deployment_v2,
        promote_model_intake_submission,
        refresh_model_intake_runner_job,
        reply_model_intake_agent_session,
        rescan_model_intake_target,
        resolve_model_intake,
        resolve_model_intake_conversion_profile,
        resolve_model_intake_loader_profile,
        revoke_model_intake_admission,
        scan_model_intake,
        update_model_intake_trust_anchor,
        verify_model_intake_admission,
        verify_model_intake_admission_v2,
    )
configure_model_intake_router(
    lambda: db_pool,
    get_redis=lambda *a, **k: get_redis(*a, **k),
    sanitize_scan_options=lambda *a, **k: _sanitize_scan_options(*a, **k),
    model_intake_json_object=lambda *a, **k: _model_intake_json_object(*a, **k),
    results_dir=lambda: RESULTS_DIR,
    validate_approval_receipt_for_action=lambda *a, **k: _validate_approval_receipt_for_action(*a, **k),
    require_approval_receipt_if_policy_enabled=lambda *a, **k: _require_approval_receipt_if_policy_enabled(*a, **k),
    record_command_result=lambda *a, **k: _record_command_result(*a, **k),
    worker_freshness_snapshot=lambda *a, **k: _worker_freshness_snapshot(*a, **k),
)
app.include_router(model_intake_router)
try:
    from fleet_routes.router import (
        configure_fleet_router,
        router as fleet_router,
        BROKER_ACTIVE_SLOTS_KEY,
        BROKER_INGEST_QUEUE_NAME,
        BROKER_LEASE_SECONDS,
        BROKER_MAX_DELIVERY_ATTEMPTS,
        BROKER_MAX_RESULT_BYTES,
        BrokerActionAuthorityRequest,
        BrokerActionCancelStatusRequest,
        BrokerActionLeaseRequest,
        BrokerActionResultRequest,
        BrokerActionWorkManifestRequest,
        BrokerLeaseHeartbeatRequest,
        BrokerLeaseRequest,
        BrokerResultRequest,
        BrokerScanContinuationRequest,
        FleetDesiredStateRequest,
        FleetHeartbeatRequest,
        FleetJoinTokenRequest,
        FleetNodeJoinRequest,
        FleetScaleRequest,
        SCAN_BUDGET_PROFILES,
        _BROKER_PRIVATE_INPUT_CAPABILITIES,
        _BROKER_PRIVATE_OPTION_KEYS,
        _BROKER_SLOT_LUA,
        _FLEET_JOIN_RATE_LIMIT_LUA,
        _broker_action_context,
        _broker_action_plan_requires_local_private_inputs,
        _broker_action_work_manifest_references,
        _broker_active_scan_cap,
        _broker_authenticated_node,
        _broker_execution_projection,
        _broker_job_has_private_inputs,
        _broker_json_array,
        _broker_json_object,
        _broker_lease_row,
        _broker_node_labels,
        _broker_private_replay_plan,
        _broker_release_slot,
        _broker_reserve_request_budget,
        _broker_slot_id,
        _broker_submitted_action_lease,
        _broker_take_or_refresh_slot,
        _broker_target_authority,
        _broker_target_binding_from_options,
        _broker_target_key,
        _build_broker_private_scan_payload,
        _compute_broker_active_scan_cap,
        _control_plane_broker_ingest_payload,
        _fail_broker_scan_and_reconcile_parent,
        _fleet_acceptance_lease_probe,
        _fleet_bootstrap_config,
        _fleet_ca_certificate_pem,
        _fleet_connection_bundle,
        _fleet_node_is_schedulable,
        _fleet_request_is_https,
        _hydrate_broker_generic_scan_credentials,
        _hydrate_broker_job_options,
        _mark_broker_budget_wait,
        _materialize_broker_scan_continuation,
        _materialize_control_plane_scan_job_v2,
        _queue_lease_from_broker_row,
        _require_fleet_https,
        _require_fleet_join_rate_limit,
        _resolve_runtime_target_addresses,
        _revalidate_broker_action_authority,
        _split_broker_private_options,
        _trusted_fleet_gateway_request,
        cancel_broker_scan_action,
        continue_broker_scan_action_plan,
        create_fleet_join_token,
        fleet_public_health,
        get_broker_scan_action_observations,
        get_broker_scan_action_status,
        get_broker_scan_action_work_manifest,
        get_broker_scan_cancel_status,
        get_fleet_connection_bundle,
        get_fleet_node_activity,
        get_fleet_node_events,
        get_fleet_node_state,
        heartbeat_broker_job,
        heartbeat_broker_scan_action,
        heartbeat_fleet_node,
        join_fleet_node,
        lease_broker_job,
        lease_broker_scan_action,
        list_fleet_nodes,
        revoke_fleet_join_token,
        revoke_fleet_node,
        rotate_fleet_node_credential,
        run_fleet_acceptance_lease_probe,
        scale_fleet_workers,
        settle_broker_scan_action,
        submit_broker_job_result,
        update_fleet_node_state,
        upload_broker_job_artifact,
    )
except ModuleNotFoundError:  # package import in host-side tests
    from api.fleet_routes.router import (
        configure_fleet_router,
        router as fleet_router,
        BROKER_ACTIVE_SLOTS_KEY,
        BROKER_INGEST_QUEUE_NAME,
        BROKER_LEASE_SECONDS,
        BROKER_MAX_DELIVERY_ATTEMPTS,
        BROKER_MAX_RESULT_BYTES,
        BrokerActionAuthorityRequest,
        BrokerActionCancelStatusRequest,
        BrokerActionLeaseRequest,
        BrokerActionResultRequest,
        BrokerActionWorkManifestRequest,
        BrokerLeaseHeartbeatRequest,
        BrokerLeaseRequest,
        BrokerResultRequest,
        BrokerScanContinuationRequest,
        FleetDesiredStateRequest,
        FleetHeartbeatRequest,
        FleetJoinTokenRequest,
        FleetNodeJoinRequest,
        FleetScaleRequest,
        SCAN_BUDGET_PROFILES,
        _BROKER_PRIVATE_INPUT_CAPABILITIES,
        _BROKER_PRIVATE_OPTION_KEYS,
        _BROKER_SLOT_LUA,
        _FLEET_JOIN_RATE_LIMIT_LUA,
        _broker_action_context,
        _broker_action_plan_requires_local_private_inputs,
        _broker_action_work_manifest_references,
        _broker_active_scan_cap,
        _broker_authenticated_node,
        _broker_execution_projection,
        _broker_job_has_private_inputs,
        _broker_json_array,
        _broker_json_object,
        _broker_lease_row,
        _broker_node_labels,
        _broker_private_replay_plan,
        _broker_release_slot,
        _broker_reserve_request_budget,
        _broker_slot_id,
        _broker_submitted_action_lease,
        _broker_take_or_refresh_slot,
        _broker_target_authority,
        _broker_target_binding_from_options,
        _broker_target_key,
        _build_broker_private_scan_payload,
        _compute_broker_active_scan_cap,
        _control_plane_broker_ingest_payload,
        _fail_broker_scan_and_reconcile_parent,
        _fleet_acceptance_lease_probe,
        _fleet_bootstrap_config,
        _fleet_ca_certificate_pem,
        _fleet_connection_bundle,
        _fleet_node_is_schedulable,
        _fleet_request_is_https,
        _hydrate_broker_generic_scan_credentials,
        _hydrate_broker_job_options,
        _mark_broker_budget_wait,
        _materialize_broker_scan_continuation,
        _materialize_control_plane_scan_job_v2,
        _queue_lease_from_broker_row,
        _require_fleet_https,
        _require_fleet_join_rate_limit,
        _resolve_runtime_target_addresses,
        _revalidate_broker_action_authority,
        _split_broker_private_options,
        _trusted_fleet_gateway_request,
        cancel_broker_scan_action,
        continue_broker_scan_action_plan,
        create_fleet_join_token,
        fleet_public_health,
        get_broker_scan_action_observations,
        get_broker_scan_action_status,
        get_broker_scan_action_work_manifest,
        get_broker_scan_cancel_status,
        get_fleet_connection_bundle,
        get_fleet_node_activity,
        get_fleet_node_events,
        get_fleet_node_state,
        heartbeat_broker_job,
        heartbeat_broker_scan_action,
        heartbeat_fleet_node,
        join_fleet_node,
        lease_broker_job,
        lease_broker_scan_action,
        list_fleet_nodes,
        revoke_fleet_join_token,
        revoke_fleet_node,
        rotate_fleet_node_credential,
        run_fleet_acceptance_lease_probe,
        scale_fleet_workers,
        settle_broker_scan_action,
        submit_broker_job_result,
        update_fleet_node_state,
        upload_broker_job_artifact,
    )
configure_fleet_router(
    lambda: db_pool,
    get_redis=lambda *a, **k: get_redis(*a, **k),
    int_env=lambda *a, **k: _int_env(*a, **k),
    results_dir=lambda: RESULTS_DIR,
    health=lambda *a, **k: health(*a, **k),
)
app.include_router(fleet_router)
try:
    from ai_targets.router import (
        configure_ai_targets_router,
        router as ai_targets_router,
        AIDemoRunRequest,
        AIFindingRetestRequest,
        AIMCPLiveReadinessRequest,
        AIOpsRouterRequest,
        AIScanReplayRequest,
        AITargetConnectivityTestRequest,
        AITargetCreate,
        AITargetCredential,
        AITargetPrincipalCreate,
        AITargetPrincipalUpdate,
        AITargetScanRequest,
        AITargetUpdate,
        AI_AUTH_KINDS,
        AI_DEMO_DEFAULT_SCENARIOS,
        AI_ENVIRONMENTS,
        AI_GATE_GENERIC_AUTH_KINDS,
        AI_GATE_GENERIC_CREDENTIAL_CAPABILITY,
        AI_PRINCIPAL_ROLES,
        AI_PROBE_PACKS,
        AI_SCAN_PROFILES,
        AI_STREAMING_MODES,
        AI_TARGET_METHODS,
        AI_TARGET_TYPES,
        _ai_campaign_context_from_scan,
        _ai_campaign_evidence_manifest_summary,
        _ai_campaign_history_entry,
        _ai_demo_target_sql_predicate,
        _ai_finding_probe_context,
        _ai_ops_call,
        _ai_ops_has_auth_context,
        _ai_ops_prompt_text,
        _ai_ops_scan_body,
        _ai_principal_ref,
        _ai_production_confirmation_reason,
        _ai_readiness_trend,
        _ai_readiness_trend_points,
        _ai_scan_options_from_row,
        _ai_target_response,
        _ai_target_run_kind,
        _ai_transcript_sensitive_allowed,
        _anonymous_ai_runtime_credential,
        _build_ai_campaign_history,
        _build_ai_credential_db_record,
        _build_ai_finding_retest_scan_options,
        _build_ai_ops_router_plan,
        _build_ai_scan_replay_plan,
        _build_ai_target_campaign_history,
        _build_ai_target_campaign_history_export,
        _build_ai_worker_options,
        _contains_prompt_placeholder,
        _demo_request_template_with_prompt,
        _demo_target_url,
        _fetch_honey_ai_gate_registry,
        _fetch_json_url,
        _generic_ai_credential_ref,
        _generic_credential_store,
        _mask_ai_headers_for_preview,
        _normalize_ai_endpoint_url,
        _normalize_ai_headers_template,
        _normalize_ai_method,
        _normalize_ai_principal_label,
        _normalize_ai_principal_role,
        _normalize_ai_request_template,
        _normalize_ai_streaming_mode,
        _normalize_ai_target_type,
        _normalize_demo_base_url,
        _normalize_multi_header_pairs,
        _parse_multi_header_lines,
        _queue_ai_target_scan,
        _reject_api_side_ai_credential_preflight,
        _resolve_ai_gate_credential_profile,
        _resolve_ai_gate_credential_refs,
        _run_ai_target_connectivity_probe,
        _sanitize_ai_credential,
        _sanitize_ai_principal,
        _sync_ai_principal_credential_profile,
        _sync_ai_target_credential_profile,
        _validate_demo_base_url,
        ai_ops_route,
        create_ai_target,
        create_ai_target_principal,
        delete_ai_target,
        delete_ai_target_principal,
        get_ai_inventory,
        get_ai_scan_campaign_history,
        get_ai_scan_transcript,
        get_ai_target_campaign_history,
        get_ai_target_campaign_history_export,
        get_ai_target_runtime_risk,
        list_ai_surface_attempts,
        list_ai_surfaces,
        list_ai_target_principals,
        list_ai_targets,
        list_ai_test_scenarios,
        purge_ai_scan_transcript,
        replay_ai_scan,
        retest_ai_finding,
        run_ai_honey_demo,
        scan_ai_target,
        sync_ai_surfaces,
        test_ai_target_connectivity,
        test_ai_target_mcp_live_readiness,
        update_ai_target,
        update_ai_target_principal,
    )
except ModuleNotFoundError:  # package import in host-side tests
    from api.ai_targets.router import (
        configure_ai_targets_router,
        router as ai_targets_router,
        AIDemoRunRequest,
        AIFindingRetestRequest,
        AIMCPLiveReadinessRequest,
        AIOpsRouterRequest,
        AIScanReplayRequest,
        AITargetConnectivityTestRequest,
        AITargetCreate,
        AITargetCredential,
        AITargetPrincipalCreate,
        AITargetPrincipalUpdate,
        AITargetScanRequest,
        AITargetUpdate,
        AI_AUTH_KINDS,
        AI_DEMO_DEFAULT_SCENARIOS,
        AI_ENVIRONMENTS,
        AI_GATE_GENERIC_AUTH_KINDS,
        AI_GATE_GENERIC_CREDENTIAL_CAPABILITY,
        AI_PRINCIPAL_ROLES,
        AI_PROBE_PACKS,
        AI_SCAN_PROFILES,
        AI_STREAMING_MODES,
        AI_TARGET_METHODS,
        AI_TARGET_TYPES,
        _ai_campaign_context_from_scan,
        _ai_campaign_evidence_manifest_summary,
        _ai_campaign_history_entry,
        _ai_demo_target_sql_predicate,
        _ai_finding_probe_context,
        _ai_ops_call,
        _ai_ops_has_auth_context,
        _ai_ops_prompt_text,
        _ai_ops_scan_body,
        _ai_principal_ref,
        _ai_production_confirmation_reason,
        _ai_readiness_trend,
        _ai_readiness_trend_points,
        _ai_scan_options_from_row,
        _ai_target_response,
        _ai_target_run_kind,
        _ai_transcript_sensitive_allowed,
        _anonymous_ai_runtime_credential,
        _build_ai_campaign_history,
        _build_ai_credential_db_record,
        _build_ai_finding_retest_scan_options,
        _build_ai_ops_router_plan,
        _build_ai_scan_replay_plan,
        _build_ai_target_campaign_history,
        _build_ai_target_campaign_history_export,
        _build_ai_worker_options,
        _contains_prompt_placeholder,
        _demo_request_template_with_prompt,
        _demo_target_url,
        _fetch_honey_ai_gate_registry,
        _fetch_json_url,
        _generic_ai_credential_ref,
        _generic_credential_store,
        _mask_ai_headers_for_preview,
        _normalize_ai_endpoint_url,
        _normalize_ai_headers_template,
        _normalize_ai_method,
        _normalize_ai_principal_label,
        _normalize_ai_principal_role,
        _normalize_ai_request_template,
        _normalize_ai_streaming_mode,
        _normalize_ai_target_type,
        _normalize_demo_base_url,
        _normalize_multi_header_pairs,
        _parse_multi_header_lines,
        _queue_ai_target_scan,
        _reject_api_side_ai_credential_preflight,
        _resolve_ai_gate_credential_profile,
        _resolve_ai_gate_credential_refs,
        _run_ai_target_connectivity_probe,
        _sanitize_ai_credential,
        _sanitize_ai_principal,
        _sync_ai_principal_credential_profile,
        _sync_ai_target_credential_profile,
        _validate_demo_base_url,
        ai_ops_route,
        create_ai_target,
        create_ai_target_principal,
        delete_ai_target,
        delete_ai_target_principal,
        get_ai_inventory,
        get_ai_scan_campaign_history,
        get_ai_scan_transcript,
        get_ai_target_campaign_history,
        get_ai_target_campaign_history_export,
        get_ai_target_runtime_risk,
        list_ai_surface_attempts,
        list_ai_surfaces,
        list_ai_target_principals,
        list_ai_targets,
        list_ai_test_scenarios,
        purge_ai_scan_transcript,
        replay_ai_scan,
        retest_ai_finding,
        run_ai_honey_demo,
        scan_ai_target,
        sync_ai_surfaces,
        test_ai_target_connectivity,
        test_ai_target_mcp_live_readiness,
        update_ai_target,
        update_ai_target_principal,
    )
configure_ai_targets_router(
    lambda: db_pool,
    get_redis=lambda *a, **k: get_redis(*a, **k),
    enqueue_job=lambda *a, **k: enqueue_job(*a, **k),
    load_effective_ai_settings=lambda *a, **k: _load_effective_ai_settings(*a, **k),
    sanitize_scan_options=lambda *a, **k: _sanitize_scan_options(*a, **k),
    ai_ops_execute_enabled=lambda *a, **k: _ai_ops_execute_enabled(*a, **k),
    legacy_credential_migration_http_error=lambda *a, **k: _legacy_credential_migration_http_error(*a, **k),
    submit_scan=lambda *a, **k: submit_scan(*a, **k),
    validate_approval_receipt_for_action=lambda *a, **k: _validate_approval_receipt_for_action(*a, **k),
    record_command_result=lambda *a, **k: _record_command_result(*a, **k),
)
app.include_router(ai_targets_router)
try:
    from targets.router import (
        asm_check_families,
        configure_targets_router,
        router as targets_router,
        AsmImproveRequest,
        AsmPolicyUpdate,
        AsmPruneRequest,
        AsmReconRequest,
        AsmTestRequest,
        DedupeTargetsRequest,
        ScanInternalCompatibilityRequest,
        TargetCreate,
        TargetCredentialProfileCreate,
        TargetCredentialProfileRotate,
        TargetCredentialProfileUpdate,
        TargetEndpointExpectationRequest,
        TargetInvariantCompileRequest,
        TargetInvariantContractApproval,
        TargetInvariantContractCreate,
        TargetInvariantContractRetire,
        TargetInvariantHypothesisRequest,
        TargetNormalizationError,
        TargetPrincipalAutoProvisionRequest,
        TargetPrincipalCreate,
        TargetPrincipalUpdate,
        TargetScanRequest,
        TargetUpdate,
        _AUTH_SESSION_ROUTE_TOKENS,
        _AUTO_PROVISION_SEMAPHORE,
        _ID_PATH_SEGMENT,
        _MAX_AUTO_PROVISION_PRINCIPALS,
        _MAX_AUTO_PROVISION_RESPONSE_BYTES,
        _PRIVILEGED_FUNCTION_TOKENS,
        _RESEARCH_DISPATCH_CORRELATION_KEY,
        _SENSITIVE_FIELD_TOKENS,
        _application_graph_context_for_hypotheses,
        _application_graph_hypothesis_requests,
        _apply_asm_check_family,
        _asm_active_scan_ids,
        _asm_queue_handoff_readback_confirmed,
        _asm_recommendation,
        _asm_recommended_campaigns,
        _asm_reserved_count,
        _asm_scheduler_state,
        _attach_target_note,
        _authz_template_replay_path,
        _auto_persist_invariant_drafts,
        _auto_provision_principals,
        _auto_provisioning_config,
        _build_asm_campaign_timeline,
        _canonical_asm_scan_options,
        _compile_asm_scan_authority,
        _confirm_asm_queue_handoff,
        _current_research_dispatch_correlation,
        _decode_asm_config,
        _decode_target_scan_options,
        _dedupe_canonical_target_rows,
        _default_asm_config_for_new_web_target,
        _default_asm_enabled_for_new_web_target,
        _empty_application_graph_context,
        _endpoint_inventory_hypothesis_requests,
        _enforce_asm_family_preconditions,
        _enqueue_asm_exploit_batch,
        _enqueue_asm_recon,
        _event_time,
        _fail_asm_queue_handoff,
        _graph_object_label,
        _graph_route_label,
        _graph_row_payload,
        _invariant_hypothesis_request,
        _load_application_graph_context_for_hypotheses,
        _load_hypothesis_situation_report,
        _mask_ai_target_secret,
        _normalize_asm_check_family,
        _normalize_target_auth_state,
        _normalize_target_credential_profile_name,
        _normalize_target_credential_secret,
        _normalize_target_endpoint_method,
        _normalize_target_endpoint_path,
        _normalize_target_principal_label,
        _normalize_target_principal_role,
        _persist_asm_scan_authority,
        _principal_matrix_context_for_graph_hypothesis,
        _principal_slot_conflict,
        _provision_json_path,
        _public_asm_decision,
        _public_target_credential_profile_row,
        _public_target_endpoint_expectation_row,
        _public_target_invariant_contract_row,
        _public_target_principal_row,
        _public_target_row,
        _render_provision_template,
        _research_auth_session_route,
        _scan_role_label,
        _target_credential_profile_values,
        _validate_asm_check_family_value,
        _validate_asm_endpoint_filter_value,
        approve_target_invariant_contract,
        asm_activity,
        asm_coverage,
        asm_diff,
        asm_gaps,
        asm_get_policy,
        asm_improve,
        asm_list_endpoints,
        asm_prune,
        asm_recon,
        asm_set_policy,
        asm_test,
        auto_provision_target_principals,
        compile_target_invariant_rule,
        create_target,
        create_target_credential_profile,
        create_target_invariant_contract,
        create_target_principal,
        dedupe_targets,
        delete_target,
        delete_target_credential_profile,
        delete_target_principal,
        delete_target_principal_expectation,
        generate_application_graph_hypotheses,
        generate_endpoint_inventory_hypotheses,
        generate_target_invariant_hypotheses,
        get_application_graph,
        get_target,
        get_target_invariant_verification_plan,
        is_root_domain,
        list_domains,
        list_target_credential_profiles,
        list_target_invariant_contracts,
        list_target_principal_matrix,
        list_target_principals,
        list_targets,
        list_targets_grouped,
        normalize_target_url,
        retire_target_invariant_contract,
        rotate_target_credential_profile,
        scan_target,
        update_target,
        update_target_credential_profile,
        update_target_principal,
        upsert_target_principal_matrix,
    )
except ModuleNotFoundError:  # package import in host-side tests
    from api.targets.router import (
        asm_check_families,
        configure_targets_router,
        router as targets_router,
        AsmImproveRequest,
        AsmPolicyUpdate,
        AsmPruneRequest,
        AsmReconRequest,
        AsmTestRequest,
        DedupeTargetsRequest,
        ScanInternalCompatibilityRequest,
        TargetCreate,
        TargetCredentialProfileCreate,
        TargetCredentialProfileRotate,
        TargetCredentialProfileUpdate,
        TargetEndpointExpectationRequest,
        TargetInvariantCompileRequest,
        TargetInvariantContractApproval,
        TargetInvariantContractCreate,
        TargetInvariantContractRetire,
        TargetInvariantHypothesisRequest,
        TargetNormalizationError,
        TargetPrincipalAutoProvisionRequest,
        TargetPrincipalCreate,
        TargetPrincipalUpdate,
        TargetScanRequest,
        TargetUpdate,
        _AUTH_SESSION_ROUTE_TOKENS,
        _AUTO_PROVISION_SEMAPHORE,
        _ID_PATH_SEGMENT,
        _MAX_AUTO_PROVISION_PRINCIPALS,
        _MAX_AUTO_PROVISION_RESPONSE_BYTES,
        _PRIVILEGED_FUNCTION_TOKENS,
        _RESEARCH_DISPATCH_CORRELATION_KEY,
        _SENSITIVE_FIELD_TOKENS,
        _application_graph_context_for_hypotheses,
        _application_graph_hypothesis_requests,
        _apply_asm_check_family,
        _asm_active_scan_ids,
        _asm_queue_handoff_readback_confirmed,
        _asm_recommendation,
        _asm_recommended_campaigns,
        _asm_reserved_count,
        _asm_scheduler_state,
        _attach_target_note,
        _authz_template_replay_path,
        _auto_persist_invariant_drafts,
        _auto_provision_principals,
        _auto_provisioning_config,
        _build_asm_campaign_timeline,
        _canonical_asm_scan_options,
        _compile_asm_scan_authority,
        _confirm_asm_queue_handoff,
        _current_research_dispatch_correlation,
        _decode_asm_config,
        _decode_target_scan_options,
        _dedupe_canonical_target_rows,
        _default_asm_config_for_new_web_target,
        _default_asm_enabled_for_new_web_target,
        _empty_application_graph_context,
        _endpoint_inventory_hypothesis_requests,
        _enforce_asm_family_preconditions,
        _enqueue_asm_exploit_batch,
        _enqueue_asm_recon,
        _event_time,
        _fail_asm_queue_handoff,
        _graph_object_label,
        _graph_route_label,
        _graph_row_payload,
        _invariant_hypothesis_request,
        _load_application_graph_context_for_hypotheses,
        _load_hypothesis_situation_report,
        _mask_ai_target_secret,
        _normalize_asm_check_family,
        _normalize_target_auth_state,
        _normalize_target_credential_profile_name,
        _normalize_target_credential_secret,
        _normalize_target_endpoint_method,
        _normalize_target_endpoint_path,
        _normalize_target_principal_label,
        _normalize_target_principal_role,
        _persist_asm_scan_authority,
        _principal_matrix_context_for_graph_hypothesis,
        _principal_slot_conflict,
        _provision_json_path,
        _public_asm_decision,
        _public_target_credential_profile_row,
        _public_target_endpoint_expectation_row,
        _public_target_invariant_contract_row,
        _public_target_principal_row,
        _public_target_row,
        _render_provision_template,
        _research_auth_session_route,
        _scan_role_label,
        _target_credential_profile_values,
        _validate_asm_check_family_value,
        _validate_asm_endpoint_filter_value,
        approve_target_invariant_contract,
        asm_activity,
        asm_coverage,
        asm_diff,
        asm_gaps,
        asm_get_policy,
        asm_improve,
        asm_list_endpoints,
        asm_prune,
        asm_recon,
        asm_set_policy,
        asm_test,
        auto_provision_target_principals,
        compile_target_invariant_rule,
        create_target,
        create_target_credential_profile,
        create_target_invariant_contract,
        create_target_principal,
        dedupe_targets,
        delete_target,
        delete_target_credential_profile,
        delete_target_principal,
        delete_target_principal_expectation,
        generate_application_graph_hypotheses,
        generate_endpoint_inventory_hypotheses,
        generate_target_invariant_hypotheses,
        get_application_graph,
        get_target,
        get_target_invariant_verification_plan,
        is_root_domain,
        list_domains,
        list_target_credential_profiles,
        list_target_invariant_contracts,
        list_target_principal_matrix,
        list_target_principals,
        list_targets,
        list_targets_grouped,
        normalize_target_url,
        retire_target_invariant_contract,
        rotate_target_credential_profile,
        scan_target,
        update_target,
        update_target_credential_profile,
        update_target_principal,
        upsert_target_principal_matrix,
    )
configure_targets_router(
    lambda: db_pool,
    # All resolved lazily: hubs defined later in this module; late resolution
    # also keeps existing test patches of these names effective.
    get_redis=lambda *a, **k: get_redis(*a, **k),
    enqueue_job=lambda *a, **k: enqueue_job(*a, **k),
    json_size_bytes=lambda *a, **k: _json_size_bytes(*a, **k),
    legacy_credential_migration_http_error=lambda *a, **k: _legacy_credential_migration_http_error(*a, **k),
    canonical_vulnerability_route=lambda *a, **k: _canonical_vulnerability_route(*a, **k),
    provision_same_origin_url=lambda *a, **k: _provision_same_origin_url(*a, **k),
    load_effective_automation_settings=lambda *a, **k: _load_effective_automation_settings(*a, **k),
    safe_default_asm_config=lambda *a, **k: _safe_default_asm_config(*a, **k),
    sanitize_scan_options=lambda *a, **k: _sanitize_scan_options(*a, **k),
    redact_agent_payload=lambda *a, **k: _redact_agent_payload(*a, **k),
    redact_agent_text=lambda *a, **k: _redact_agent_text(*a, **k),
    freeze_scan_target_binding=lambda *a, **k: _freeze_scan_target_binding(*a, **k),
    compile_scan_template_work_manifest=lambda *a, **k: _compile_scan_template_work_manifest(*a, **k),
    public_hypothesis_row=lambda *a, **k: _public_hypothesis_row(*a, **k),
    submit_scan=lambda *a, **k: _submit_scan(*a, **k),
    validate_approval_receipt_for_action=lambda *a, **k: _validate_approval_receipt_for_action(*a, **k),
    record_command_result=lambda *a, **k: _record_command_result(*a, **k),
    upsert_hypothesis=lambda *a, **k: _upsert_hypothesis(*a, **k),
    hypothesis_situation_report=lambda *a, **k: _hypothesis_situation_report(*a, **k),
    compile_scan_admission_action_authority=lambda *a, **k: _compile_scan_admission_action_authority(*a, **k),
    compile_scan_admission_surface_work_manifests=lambda *a, **k: _compile_scan_admission_surface_work_manifests(*a, **k),
    model=lambda name: globals()[name],
)
app.include_router(targets_router)
try:
    from devices.router import (
        DEVICE_QUEUE_NAME,
        DeviceAgentReplyRequest,
        DeviceAgentShellConfirmRequest,
        DevicePolicyCreate,
        DevicePolicyUpdate,
        DeviceScanRequest,
        DeviceTargetCreate,
        _HUNT_DEVICE_QUEUE_CORRELATION,
        _QUEUE_HANDOFF_CONFIRMATION_KEY,
        _build_device_agent_context_pack,
        list_device_scans,
        _confirm_device_queue_handoff,
        _device_agent_credential_reference,
        _device_confirmed_web_origins,
        _device_verify_candidate_tool,
        _redact_device_http_body_preview,
        _redact_hunt_path_query,
        _verify_device_control_authorization_candidate,
        _verify_device_firmware_candidate,
        _scan_queue_handoff_confirmed,
        _target_credential_profile_status,
        _validate_device_policy_rules,
        _decode_device_row,
        _device_agent_run_public,
        _device_uuid,
        _device_worker_readiness,
        _hunt_device_queue_metadata,
        _public_device_credential_profile,
        _public_device_request_collection,
        _sanitize_device_agent_value,
        configure_devices_router,
        router as devices_router,
        scan_device,
    )
except ModuleNotFoundError:  # package import in host-side tests
    from api.devices.router import (
        DEVICE_QUEUE_NAME,
        DeviceAgentReplyRequest,
        DeviceAgentShellConfirmRequest,
        DevicePolicyCreate,
        DevicePolicyUpdate,
        DeviceScanRequest,
        DeviceTargetCreate,
        _HUNT_DEVICE_QUEUE_CORRELATION,
        _QUEUE_HANDOFF_CONFIRMATION_KEY,
        _build_device_agent_context_pack,
        list_device_scans,
        _confirm_device_queue_handoff,
        _device_agent_credential_reference,
        _device_confirmed_web_origins,
        _device_verify_candidate_tool,
        _redact_device_http_body_preview,
        _redact_hunt_path_query,
        _verify_device_control_authorization_candidate,
        _verify_device_firmware_candidate,
        _scan_queue_handoff_confirmed,
        _target_credential_profile_status,
        _validate_device_policy_rules,
        _decode_device_row,
        _device_agent_run_public,
        _device_uuid,
        _device_worker_readiness,
        _hunt_device_queue_metadata,
        _public_device_credential_profile,
        _public_device_request_collection,
        _sanitize_device_agent_value,
        configure_devices_router,
        router as devices_router,
        scan_device,
    )
configure_devices_router(
    lambda: db_pool,
    # All resolved lazily: hubs defined later in this module, and late
    # resolution keeps existing test patches of these names effective.
    get_redis=lambda *a, **k: get_redis(*a, **k),
    enqueue_job=lambda *a, **k: enqueue_job(*a, **k),
    current_scanner_version=lambda *a, **k: current_scanner_version(*a, **k),
    expected_build_fingerprint=lambda *a, **k: expected_build_fingerprint(*a, **k),
    worker_build_current=lambda *a, **k: worker_build_current(*a, **k),
    sync_legacy_device_credential=lambda *a, **k: sync_legacy_device_credential(*a, **k),
    legacy_credential_migration_http_error=lambda *a, **k: _legacy_credential_migration_http_error(*a, **k),
    normalize_credential_profile_name=lambda *a, **k: _normalize_target_credential_profile_name(*a, **k),
    redact_agent_payload=lambda *a, **k: _redact_agent_payload(*a, **k),
    validate_approval_receipt=lambda *a, **k: _validate_approval_receipt_for_action(*a, **k),
    record_command_result=lambda *a, **k: _record_command_result(*a, **k),
    mark_scan_enqueue_failed=lambda *a, **k: _mark_scan_enqueue_failed(*a, **k),
)
app.include_router(devices_router)
try:
    from finding_routes.router import (
        BulkFindingUpdateRequest,
        FindingRetestRequest,
        FindingUpdate,
        FindingsBulkRetestRequest,
        FindingsCleanup,
        ManualFindingCreate,
        _CANDIDATE_OPEN_STATUSES,
        _enqueue_finding_retest_unlocked,
        _scan_time_verification_fields,
        enqueue_finding_retest,
        extract_retest_inputs,
        finding_proof_fields,
        get_finding_record,
        infer_retest_type,
        mark_retest_enqueue_failed,
        _FINDING_DETAIL_ONLY_FIELDS,
        _candidate_to_pseudo_finding,
        _merge_findings_and_candidates,
        _public_evidence_object_row,
        _refresh_device_active_finding_counts,
        _refresh_finding_owner_counts,
        _refresh_web_active_finding_counts,
        _source_type_filter_sql,
        _strip_pagination_for_count,
        bulk_retest_findings,
        bulk_update_findings,
        cleanup_findings,
        configure_findings_router,
        create_manual_finding,
        delete_finding,
        get_finding,
        list_finding_evidence,
        list_findings,
        retest_finding,
        router as findings_router,
        update_finding,
    )
except ModuleNotFoundError:  # package import in host-side tests
    from api.finding_routes.router import (
        BulkFindingUpdateRequest,
        FindingRetestRequest,
        FindingUpdate,
        FindingsBulkRetestRequest,
        FindingsCleanup,
        ManualFindingCreate,
        _CANDIDATE_OPEN_STATUSES,
        _enqueue_finding_retest_unlocked,
        _scan_time_verification_fields,
        enqueue_finding_retest,
        extract_retest_inputs,
        finding_proof_fields,
        get_finding_record,
        infer_retest_type,
        mark_retest_enqueue_failed,
        _FINDING_DETAIL_ONLY_FIELDS,
        _candidate_to_pseudo_finding,
        _merge_findings_and_candidates,
        _public_evidence_object_row,
        _refresh_device_active_finding_counts,
        _refresh_finding_owner_counts,
        _refresh_web_active_finding_counts,
        _source_type_filter_sql,
        _strip_pagination_for_count,
        bulk_retest_findings,
        bulk_update_findings,
        cleanup_findings,
        configure_findings_router,
        create_manual_finding,
        delete_finding,
        get_finding,
        list_finding_evidence,
        list_findings,
        retest_finding,
        router as findings_router,
        update_finding,
    )
configure_findings_router(
    lambda: db_pool,
    # All resolved lazily: these are hubs defined later in this module, and late
    # resolution keeps existing test patches of these names effective.
    get_redis=lambda *a, **k: get_redis(*a, **k),
    enqueue_job=lambda *a, **k: enqueue_job(*a, **k),
    results_dir=lambda: RESULTS_DIR,
    load_effective_ai_settings=lambda *a, **k: _load_effective_ai_settings(*a, **k),
    asm_enabled_default=lambda *a, **k: _default_asm_enabled_for_new_web_target(*a, **k),
    asm_config_default=lambda *a, **k: _default_asm_config_for_new_web_target(*a, **k),
    validate_approval_receipt=lambda *a, **k: _validate_approval_receipt_for_action(*a, **k),
    require_approval_receipt=lambda *a, **k: _require_approval_receipt_if_policy_enabled(*a, **k),
    record_command_result=lambda *a, **k: _record_command_result(*a, **k),
    record_blocked_command_result=lambda *a, **k: _record_blocked_command_result(*a, **k),
)
app.include_router(findings_router)
try:
    from schedules.router import (
        SCHEDULE_HEALTH_LOOKBACK_DAYS,
        ScheduleCreate,
        ScheduleUpdate,
        VALID_SCHEDULE_KINDS,
        _normalize_schedule_kind,
        _schedule_health_from_failures,
        _schedule_health_map_for_schedules,
        _schedule_kind_from_row,
        _schedule_options_dict,
        calculate_next_run,
        configure_schedule_router,
        create_schedule,
        delete_schedule,
        get_schedule,
        list_schedules,
        router as schedule_router,
        update_schedule,
    )
except ModuleNotFoundError:  # package import in host-side tests
    from api.schedules.router import (
        SCHEDULE_HEALTH_LOOKBACK_DAYS,
        ScheduleCreate,
        ScheduleUpdate,
        VALID_SCHEDULE_KINDS,
        _normalize_schedule_kind,
        _schedule_health_from_failures,
        _schedule_health_map_for_schedules,
        _schedule_kind_from_row,
        _schedule_options_dict,
        calculate_next_run,
        configure_schedule_router,
        create_schedule,
        delete_schedule,
        get_schedule,
        list_schedules,
        router as schedule_router,
        update_schedule,
    )
configure_schedule_router(lambda: db_pool)
app.include_router(schedule_router)
try:
    from finding_exceptions.router import (
        FindingExceptionLifecycleSweepRequest,
        FindingExceptionRequest,
        _finding_exception_lifecycle_sweep,
        configure_finding_exception_router,
        create_finding_exception,
        delete_finding_exception,
        finding_exception_lifecycle_sweep,
        list_finding_exceptions,
        router as finding_exception_router,
        update_finding_exception,
    )
except ModuleNotFoundError:  # package import in host-side tests
    from api.finding_exceptions.router import (
        FindingExceptionLifecycleSweepRequest,
        FindingExceptionRequest,
        _finding_exception_lifecycle_sweep,
        configure_finding_exception_router,
        create_finding_exception,
        delete_finding_exception,
        finding_exception_lifecycle_sweep,
        list_finding_exceptions,
        router as finding_exception_router,
        update_finding_exception,
    )
configure_finding_exception_router(
    lambda: db_pool,
    # Resolved lazily: both hubs are defined later in this module.
    approval_validator=lambda *a, **k: _validate_approval_receipt_for_action(*a, **k),
    command_recorder=lambda *a, **k: _record_command_result(*a, **k),
)
app.include_router(finding_exception_router)
try:
    from exposure.router import (
        _build_exposure_graph,
        _focus_exposure_subgraph,
        configure_exposure_router,
        exposure_assets,
        exposure_attack_paths,
        exposure_changes,
        exposure_graph,
        exposure_nodes,
        router as exposure_router,
    )
except ModuleNotFoundError:  # package import in host-side tests
    from api.exposure.router import (
        _build_exposure_graph,
        _focus_exposure_subgraph,
        configure_exposure_router,
        exposure_assets,
        exposure_attack_paths,
        exposure_changes,
        exposure_graph,
        exposure_nodes,
        router as exposure_router,
    )
configure_exposure_router(lambda: db_pool)
app.include_router(exposure_router)
try:
    from interactive.router import (
        EndpointTestRequest,
        SessionActionRequest,
        SessionFindingCreate,
        SessionStartRequest,
        configure_interactive_router,
        create_session_finding,
        end_session,
        get_session_state,
        list_sessions,
        router as interactive_router,
        session_action,
        session_screenshot,
        session_screenshot_raw,
        session_test_endpoint,
        start_session,
    )
except ModuleNotFoundError:  # package import in host-side tests
    from api.interactive.router import (
        EndpointTestRequest,
        SessionActionRequest,
        SessionFindingCreate,
        SessionStartRequest,
        configure_interactive_router,
        create_session_finding,
        end_session,
        get_session_state,
        list_sessions,
        router as interactive_router,
        session_action,
        session_screenshot,
        session_screenshot_raw,
        session_test_endpoint,
        start_session,
    )
configure_interactive_router(
    lambda: db_pool,
    # Resolved lazily: these read runtime settings defined later in this module.
    results_dir_provider=lambda: RESULTS_DIR,
    asm_enabled_default=lambda *a, **k: _default_asm_enabled_for_new_web_target(*a, **k),
    asm_config_default=lambda *a, **k: _default_asm_config_for_new_web_target(*a, **k),
)
app.include_router(interactive_router)
try:
    from arsenal_routes.router import (
        configure_arsenal_router,
        router as arsenal_router,
        AgentDecisionTraceStep,
        OperationPlanAction,
        AgentContextPackFromTargetRequest,
        AgentContextPackRequest,
        AgentDecisionTraceRequest,
        ApprovalReceiptRequest,
        ApprovalReceiptRevocationRequest,
        ArsenalExecuteRequest,
        AuthzReplayExecuteRequest,
        AuthzReplayPromoteRequest,
        BENCHMARK_FAMILY_CWE,
        BENCHMARK_HYPOTHESIS_VERSION,
        BENCHMARK_PROOF_SURFACE,
        BenchmarkFollowupHypothesisItem,
        BenchmarkHypothesisRequest,
        CampaignActionLinkRequest,
        CampaignRequest,
        FamilyProofHandoffRequest,
        HypothesisCampaignPlanRequest,
        HypothesisClaimRequest,
        HypothesisProofReconcileRequest,
        HypothesisSignalRequest,
        HypothesisTransitionRequest,
        OperationPlanRequest,
        PLANNER_HYPOTHESIS_VERSION,
        PlannerHypothesisRequest,
        REFUTER_BENCHMARK_DELTA_MIN_BASELINE,
        REFUTER_BENCHMARK_RECALL_DELTA,
        REFUTER_BENCHMARK_VERIFIED_DELTA,
        REFUTER_FINDING_DELTA_MIN_ABSOLUTE,
        REFUTER_FINDING_DELTA_MIN_BASELINE,
        REFUTER_FINDING_DELTA_MULTIPLIER,
        REFUTER_VERDICT_BASES,
        RESEARCH_EXPERIMENT_OUTCOMES,
        RESEARCH_PRIMARY_CREDENTIAL_FAMILIES,
        RESEARCH_RECON_COMMANDS,
        RESEARCH_SECOND_USER_FAMILIES,
        RESEARCH_SURFACE_MIN_AUTHENTICATED_ROUTES,
        RESEARCH_SURFACE_MIN_EXECUTABLE_ROUTES,
        RESEARCH_SURFACE_MIN_UNIQUE_ROUTES,
        RefuterReviewDeriveVerdictRequest,
        RefuterReviewExecuteRequest,
        RefuterReviewQueueRequest,
        RefuterReviewRequest,
        SOURCE_INGEST_DEFAULT_IGNORED_PATHS,
        SOURCE_INGEST_HTTP_METHODS,
        SOURCE_INGEST_VERSION,
        ScopePreviewRequest,
        SourceIngestFile,
        SourceIngestHint,
        SourceIngestRequest,
        ToolReceiptRequest,
        _ArsenalQueryRequest,
        _RESEARCH_EXPERIMENT_DEDUPE_COMMANDS,
        _active_commands_for_context,
        _append_hypothesis_signal,
        _apply_refuter_negative_gate,
        _arsenal_adapter_pending_response,
        _arsenal_dispatch_agent_context_pack_generate_from_target,
        _arsenal_dispatch_agent_context_pack_list,
        _arsenal_dispatch_agent_context_pack_record,
        _arsenal_dispatch_agent_decision_trace_list,
        _arsenal_dispatch_agent_decision_trace_record,
        _arsenal_dispatch_ai_gate_replay_probe,
        _arsenal_dispatch_ai_gate_scan,
        _arsenal_dispatch_ai_gate_target_history_export,
        _arsenal_dispatch_ai_target_list,
        _arsenal_dispatch_asm_activity,
        _arsenal_dispatch_asm_gaps,
        _arsenal_dispatch_asm_improve,
        _arsenal_dispatch_asm_recon,
        _arsenal_dispatch_asm_test,
        _arsenal_dispatch_authz_promote_replay_finding,
        _arsenal_dispatch_authz_replay_plan,
        _arsenal_dispatch_campaign_action_list,
        _arsenal_dispatch_campaign_create,
        _arsenal_dispatch_campaign_get,
        _arsenal_dispatch_campaign_link_action,
        _arsenal_dispatch_campaign_list,
        _arsenal_dispatch_command_result_list,
        _arsenal_dispatch_deployment_decision,
        _arsenal_dispatch_evidence_export_bundle,
        _arsenal_dispatch_evidence_export_manifest,
        _arsenal_dispatch_evidence_get,
        _arsenal_dispatch_evidence_instance_list,
        _arsenal_dispatch_evidence_instance_record,
        _arsenal_dispatch_evidence_retention_sweep,
        _arsenal_dispatch_exposure_graph_get,
        _arsenal_dispatch_finding_exception_lifecycle_sweep,
        _arsenal_dispatch_finding_get,
        _arsenal_dispatch_finding_list,
        _arsenal_dispatch_finding_retest,
        _arsenal_dispatch_http_diff,
        _arsenal_dispatch_hypothesis_claim,
        _arsenal_dispatch_hypothesis_generate_from_benchmark,
        _arsenal_dispatch_hypothesis_generate_from_graph,
        _arsenal_dispatch_hypothesis_generate_from_plan,
        _arsenal_dispatch_hypothesis_generate_from_source,
        _arsenal_dispatch_hypothesis_list,
        _arsenal_dispatch_hypothesis_plan_campaign,
        _arsenal_dispatch_hypothesis_reconcile_proof,
        _arsenal_dispatch_hypothesis_record,
        _arsenal_dispatch_hypothesis_signal,
        _arsenal_dispatch_hypothesis_situation_report,
        _arsenal_dispatch_local_agent_list,
        _arsenal_dispatch_local_agent_parse_plan,
        _arsenal_dispatch_local_agent_plan_dry_run,
        _arsenal_dispatch_local_agent_test,
        _arsenal_dispatch_mission_timeline,
        _arsenal_dispatch_model_intake_evidence_export,
        _arsenal_dispatch_model_intake_scan,
        _arsenal_dispatch_model_intake_trust_preview,
        _arsenal_dispatch_operation_plan_list,
        _arsenal_dispatch_operation_plan_preview,
        _arsenal_dispatch_refuter_review_derive_verdict,
        _arsenal_dispatch_refuter_review_execute_plan,
        _arsenal_dispatch_refuter_review_list,
        _arsenal_dispatch_refuter_review_queue_from_summary,
        _arsenal_dispatch_refuter_review_record,
        _arsenal_dispatch_refuter_review_summary,
        _arsenal_dispatch_scan_focused_family,
        _arsenal_dispatch_scan_result,
        _arsenal_dispatch_scope_preview,
        _arsenal_dispatch_target_get,
        _arsenal_dispatch_target_invariant_approve,
        _arsenal_dispatch_target_invariant_compile,
        _arsenal_dispatch_target_invariant_hypotheses,
        _arsenal_dispatch_target_invariant_record,
        _arsenal_dispatch_target_invariant_retire,
        _arsenal_dispatch_target_invariant_verification_plan,
        _arsenal_dispatch_target_invariants,
        _arsenal_dispatch_target_list,
        _arsenal_dispatch_target_principal_matrix,
        _arsenal_dispatch_target_principal_matrix_record,
        _arsenal_dispatch_target_principals,
        _arsenal_dispatch_tool_receipt_list,
        _arsenal_dispatch_tool_receipt_record,
        _arsenal_dispatch_tool_status,
        _arsenal_dispatch_workflow,
        _arsenal_execute_detached,
        _arsenal_gated_adapters,
        _arsenal_model_fields,
        _arsenal_readonly_adapters,
        _authz_replay_path_is_template,
        _authz_replay_plan_from_hypothesis_action,
        _benchmark_followup_to_hypothesis_request,
        _benchmark_scorecard_rows,
        _benchmark_win_delta_refuter_signal,
        _benchmark_win_delta_refuter_signals,
        _build_agent_context_pack_from_target,
        _campaign_action_effective_status,
        _campaign_deployment_impact,
        _campaign_live_finding_impact,
        _campaign_type_for_hypothesis_family,
        _canonical_agent_context_pack,
        _canonical_agent_decision_trace,
        _canonical_context_hash,
        _canonical_coverage_key,
        _canonical_hypothesis_signal,
        _canonical_operation_plan,
        _canonical_refuter_review,
        _command_result_response_row,
        _derive_refuter_review_verdict,
        _endpoint_hint_from_parameters,
        _execute_refuter_review_plan,
        _finding_coverage_key,
        _finding_delta_refuter_signal,
        _finding_delta_refuter_signals,
        _finding_delta_target_stats,
        _finding_family_route_method,
        _finding_refuter_trigger,
        _finding_vulnerability_key,
        _generate_hypotheses_from_benchmark_followups,
        _generate_hypotheses_from_operation_plan,
        _hypothesis_dimensions_match_finding,
        _hypothesis_family_matches_finding,
        _hypothesis_route_matches_finding,
        _hypothesis_structured_values,
        _hypothesis_subject_matches_finding,
        _hypothesis_verification_ids,
        _load_benchmark_scorecard_artifacts,
        _load_refuter_work_summary,
        _normalized_web_origins,
        _openapi_file_hints,
        _operation_plan_allowed_commands,
        _optional_database_savepoint,
        _persist_agent_context_pack,
        _persist_campaign,
        _persist_operation_plan,
        _plan_campaign_from_hypothesis,
        _planner_action_family_and_proof,
        _planner_action_to_hypothesis_request,
        _public_agent_context_pack_row,
        _public_agent_decision_trace_row,
        _public_approval_receipt_row,
        _public_command_result_row,
        _public_operation_plan_row,
        _public_refuter_review_row,
        _public_scope_receipt_row,
        _public_tool_receipt_row,
        _reconcile_hypothesis_proof,
        _record_refuter_review,
        _refuter_automation_plan_for_finding,
        _refuter_counterevidence_corroborates,
        _refuter_finding_automation_plan,
        _refuter_review_from_verification_outcome,
        _refuter_review_requests_from_summary,
        _refuter_verification_reference_valid,
        _refuter_work_summary,
        _research_action_dedupe_comparable,
        _research_action_semantic_dimension,
        _research_campaign_readiness,
        _research_campaign_yield_metrics,
        _research_exhausted_families,
        _research_experiment_failure_detail,
        _research_experiment_outcome,
        _research_family_readiness_requirements,
        _research_hypothesis_coverage_key,
        _research_hypothesis_experiment_contract,
        _research_hypothesis_matches_live_surface,
        _research_hypothesis_provability,
        _research_hypothesis_route,
        _research_hypothesis_vulnerability_key,
        _research_known_coverage_keys,
        _research_known_vulnerability_keys,
        _research_net_new_finding_count,
        _risk_tier_for_hypothesis_action,
        _route_file_hints,
        _savepoint_fetch,
        _schema_property_paths,
        _select_refuter_automation_step,
        _select_research_hypothesis_context,
        _source_files_to_hints,
        _source_hint_family_and_action,
        _source_hint_route,
        _source_hint_to_hypothesis_request,
        _source_ingest_path_ignored,
        _source_ingest_risk_hints,
        _target_credential_precondition_signals,
        _target_id_from_plan_action,
        _target_web_origins,
        _validate_agent_context_pack,
        _validate_agent_decision_trace,
        _validate_arsenal_execute_request,
        _validate_campaign_action_for_execution,
        _validate_operation_plan,
        arsenal_agent_context_packs,
        arsenal_agent_decision_traces,
        arsenal_append_hypothesis_signal,
        arsenal_campaign_actions,
        arsenal_campaign_detail,
        arsenal_campaigns,
        arsenal_claim_hypothesis,
        arsenal_command_results,
        arsenal_commands,
        arsenal_contracts,
        arsenal_create_agent_context_pack,
        arsenal_create_agent_context_pack_from_target,
        arsenal_create_agent_decision_trace,
        arsenal_create_approval,
        arsenal_create_campaign,
        arsenal_create_operation_plan,
        arsenal_derive_refuter_review_verdict,
        arsenal_execute,
        arsenal_execute_authz_replay,
        arsenal_execute_refuter_review_plan,
        arsenal_family_proof_contracts,
        arsenal_family_proof_evaluate,
        arsenal_finding_refuter_panel,
        arsenal_generate_hypotheses_from_benchmark,
        arsenal_generate_hypotheses_from_plan,
        arsenal_generate_hypotheses_from_source,
        arsenal_hypotheses,
        arsenal_hypothesis_situation_report,
        arsenal_link_campaign_action,
        arsenal_operation_plans,
        arsenal_plan_hypothesis_campaign,
        arsenal_promote_authz_replay,
        arsenal_queue_refuter_reviews_from_summary,
        arsenal_reconcile_hypothesis_proof,
        arsenal_record_hypothesis,
        arsenal_record_refuter_review,
        arsenal_record_tool_receipt,
        arsenal_refuter_review_summary,
        arsenal_refuter_reviews,
        arsenal_revoke_approval,
        arsenal_schedule_hypotheses,
        arsenal_scope_preview,
        arsenal_tool_receipts,
        arsenal_tools,
        arsenal_transition_hypothesis,
    )
except ModuleNotFoundError:  # package import in host-side tests
    from api.arsenal_routes.router import (
        configure_arsenal_router,
        router as arsenal_router,
        AgentDecisionTraceStep,
        OperationPlanAction,
        AgentContextPackFromTargetRequest,
        AgentContextPackRequest,
        AgentDecisionTraceRequest,
        ApprovalReceiptRequest,
        ApprovalReceiptRevocationRequest,
        ArsenalExecuteRequest,
        AuthzReplayExecuteRequest,
        AuthzReplayPromoteRequest,
        BENCHMARK_FAMILY_CWE,
        BENCHMARK_HYPOTHESIS_VERSION,
        BENCHMARK_PROOF_SURFACE,
        BenchmarkFollowupHypothesisItem,
        BenchmarkHypothesisRequest,
        CampaignActionLinkRequest,
        CampaignRequest,
        FamilyProofHandoffRequest,
        HypothesisCampaignPlanRequest,
        HypothesisClaimRequest,
        HypothesisProofReconcileRequest,
        HypothesisSignalRequest,
        HypothesisTransitionRequest,
        OperationPlanRequest,
        PLANNER_HYPOTHESIS_VERSION,
        PlannerHypothesisRequest,
        REFUTER_BENCHMARK_DELTA_MIN_BASELINE,
        REFUTER_BENCHMARK_RECALL_DELTA,
        REFUTER_BENCHMARK_VERIFIED_DELTA,
        REFUTER_FINDING_DELTA_MIN_ABSOLUTE,
        REFUTER_FINDING_DELTA_MIN_BASELINE,
        REFUTER_FINDING_DELTA_MULTIPLIER,
        REFUTER_VERDICT_BASES,
        RESEARCH_EXPERIMENT_OUTCOMES,
        RESEARCH_PRIMARY_CREDENTIAL_FAMILIES,
        RESEARCH_RECON_COMMANDS,
        RESEARCH_SECOND_USER_FAMILIES,
        RESEARCH_SURFACE_MIN_AUTHENTICATED_ROUTES,
        RESEARCH_SURFACE_MIN_EXECUTABLE_ROUTES,
        RESEARCH_SURFACE_MIN_UNIQUE_ROUTES,
        RefuterReviewDeriveVerdictRequest,
        RefuterReviewExecuteRequest,
        RefuterReviewQueueRequest,
        RefuterReviewRequest,
        SOURCE_INGEST_DEFAULT_IGNORED_PATHS,
        SOURCE_INGEST_HTTP_METHODS,
        SOURCE_INGEST_VERSION,
        ScopePreviewRequest,
        SourceIngestFile,
        SourceIngestHint,
        SourceIngestRequest,
        ToolReceiptRequest,
        _ArsenalQueryRequest,
        _RESEARCH_EXPERIMENT_DEDUPE_COMMANDS,
        _active_commands_for_context,
        _append_hypothesis_signal,
        _apply_refuter_negative_gate,
        _arsenal_adapter_pending_response,
        _arsenal_dispatch_agent_context_pack_generate_from_target,
        _arsenal_dispatch_agent_context_pack_list,
        _arsenal_dispatch_agent_context_pack_record,
        _arsenal_dispatch_agent_decision_trace_list,
        _arsenal_dispatch_agent_decision_trace_record,
        _arsenal_dispatch_ai_gate_replay_probe,
        _arsenal_dispatch_ai_gate_scan,
        _arsenal_dispatch_ai_gate_target_history_export,
        _arsenal_dispatch_ai_target_list,
        _arsenal_dispatch_asm_activity,
        _arsenal_dispatch_asm_gaps,
        _arsenal_dispatch_asm_improve,
        _arsenal_dispatch_asm_recon,
        _arsenal_dispatch_asm_test,
        _arsenal_dispatch_authz_promote_replay_finding,
        _arsenal_dispatch_authz_replay_plan,
        _arsenal_dispatch_campaign_action_list,
        _arsenal_dispatch_campaign_create,
        _arsenal_dispatch_campaign_get,
        _arsenal_dispatch_campaign_link_action,
        _arsenal_dispatch_campaign_list,
        _arsenal_dispatch_command_result_list,
        _arsenal_dispatch_deployment_decision,
        _arsenal_dispatch_evidence_export_bundle,
        _arsenal_dispatch_evidence_export_manifest,
        _arsenal_dispatch_evidence_get,
        _arsenal_dispatch_evidence_instance_list,
        _arsenal_dispatch_evidence_instance_record,
        _arsenal_dispatch_evidence_retention_sweep,
        _arsenal_dispatch_exposure_graph_get,
        _arsenal_dispatch_finding_exception_lifecycle_sweep,
        _arsenal_dispatch_finding_get,
        _arsenal_dispatch_finding_list,
        _arsenal_dispatch_finding_retest,
        _arsenal_dispatch_http_diff,
        _arsenal_dispatch_hypothesis_claim,
        _arsenal_dispatch_hypothesis_generate_from_benchmark,
        _arsenal_dispatch_hypothesis_generate_from_graph,
        _arsenal_dispatch_hypothesis_generate_from_plan,
        _arsenal_dispatch_hypothesis_generate_from_source,
        _arsenal_dispatch_hypothesis_list,
        _arsenal_dispatch_hypothesis_plan_campaign,
        _arsenal_dispatch_hypothesis_reconcile_proof,
        _arsenal_dispatch_hypothesis_record,
        _arsenal_dispatch_hypothesis_signal,
        _arsenal_dispatch_hypothesis_situation_report,
        _arsenal_dispatch_local_agent_list,
        _arsenal_dispatch_local_agent_parse_plan,
        _arsenal_dispatch_local_agent_plan_dry_run,
        _arsenal_dispatch_local_agent_test,
        _arsenal_dispatch_mission_timeline,
        _arsenal_dispatch_model_intake_evidence_export,
        _arsenal_dispatch_model_intake_scan,
        _arsenal_dispatch_model_intake_trust_preview,
        _arsenal_dispatch_operation_plan_list,
        _arsenal_dispatch_operation_plan_preview,
        _arsenal_dispatch_refuter_review_derive_verdict,
        _arsenal_dispatch_refuter_review_execute_plan,
        _arsenal_dispatch_refuter_review_list,
        _arsenal_dispatch_refuter_review_queue_from_summary,
        _arsenal_dispatch_refuter_review_record,
        _arsenal_dispatch_refuter_review_summary,
        _arsenal_dispatch_scan_focused_family,
        _arsenal_dispatch_scan_result,
        _arsenal_dispatch_scope_preview,
        _arsenal_dispatch_target_get,
        _arsenal_dispatch_target_invariant_approve,
        _arsenal_dispatch_target_invariant_compile,
        _arsenal_dispatch_target_invariant_hypotheses,
        _arsenal_dispatch_target_invariant_record,
        _arsenal_dispatch_target_invariant_retire,
        _arsenal_dispatch_target_invariant_verification_plan,
        _arsenal_dispatch_target_invariants,
        _arsenal_dispatch_target_list,
        _arsenal_dispatch_target_principal_matrix,
        _arsenal_dispatch_target_principal_matrix_record,
        _arsenal_dispatch_target_principals,
        _arsenal_dispatch_tool_receipt_list,
        _arsenal_dispatch_tool_receipt_record,
        _arsenal_dispatch_tool_status,
        _arsenal_dispatch_workflow,
        _arsenal_execute_detached,
        _arsenal_gated_adapters,
        _arsenal_model_fields,
        _arsenal_readonly_adapters,
        _authz_replay_path_is_template,
        _authz_replay_plan_from_hypothesis_action,
        _benchmark_followup_to_hypothesis_request,
        _benchmark_scorecard_rows,
        _benchmark_win_delta_refuter_signal,
        _benchmark_win_delta_refuter_signals,
        _build_agent_context_pack_from_target,
        _campaign_action_effective_status,
        _campaign_deployment_impact,
        _campaign_live_finding_impact,
        _campaign_type_for_hypothesis_family,
        _canonical_agent_context_pack,
        _canonical_agent_decision_trace,
        _canonical_context_hash,
        _canonical_coverage_key,
        _canonical_hypothesis_signal,
        _canonical_operation_plan,
        _canonical_refuter_review,
        _command_result_response_row,
        _derive_refuter_review_verdict,
        _endpoint_hint_from_parameters,
        _execute_refuter_review_plan,
        _finding_coverage_key,
        _finding_delta_refuter_signal,
        _finding_delta_refuter_signals,
        _finding_delta_target_stats,
        _finding_family_route_method,
        _finding_refuter_trigger,
        _finding_vulnerability_key,
        _generate_hypotheses_from_benchmark_followups,
        _generate_hypotheses_from_operation_plan,
        _hypothesis_dimensions_match_finding,
        _hypothesis_family_matches_finding,
        _hypothesis_route_matches_finding,
        _hypothesis_structured_values,
        _hypothesis_subject_matches_finding,
        _hypothesis_verification_ids,
        _load_benchmark_scorecard_artifacts,
        _load_refuter_work_summary,
        _normalized_web_origins,
        _openapi_file_hints,
        _operation_plan_allowed_commands,
        _optional_database_savepoint,
        _persist_agent_context_pack,
        _persist_campaign,
        _persist_operation_plan,
        _plan_campaign_from_hypothesis,
        _planner_action_family_and_proof,
        _planner_action_to_hypothesis_request,
        _public_agent_context_pack_row,
        _public_agent_decision_trace_row,
        _public_approval_receipt_row,
        _public_command_result_row,
        _public_operation_plan_row,
        _public_refuter_review_row,
        _public_scope_receipt_row,
        _public_tool_receipt_row,
        _reconcile_hypothesis_proof,
        _record_refuter_review,
        _refuter_automation_plan_for_finding,
        _refuter_counterevidence_corroborates,
        _refuter_finding_automation_plan,
        _refuter_review_from_verification_outcome,
        _refuter_review_requests_from_summary,
        _refuter_verification_reference_valid,
        _refuter_work_summary,
        _research_action_dedupe_comparable,
        _research_action_semantic_dimension,
        _research_campaign_readiness,
        _research_campaign_yield_metrics,
        _research_exhausted_families,
        _research_experiment_failure_detail,
        _research_experiment_outcome,
        _research_family_readiness_requirements,
        _research_hypothesis_coverage_key,
        _research_hypothesis_experiment_contract,
        _research_hypothesis_matches_live_surface,
        _research_hypothesis_provability,
        _research_hypothesis_route,
        _research_hypothesis_vulnerability_key,
        _research_known_coverage_keys,
        _research_known_vulnerability_keys,
        _research_net_new_finding_count,
        _risk_tier_for_hypothesis_action,
        _route_file_hints,
        _savepoint_fetch,
        _schema_property_paths,
        _select_refuter_automation_step,
        _select_research_hypothesis_context,
        _source_files_to_hints,
        _source_hint_family_and_action,
        _source_hint_route,
        _source_hint_to_hypothesis_request,
        _source_ingest_path_ignored,
        _source_ingest_risk_hints,
        _target_credential_precondition_signals,
        _target_id_from_plan_action,
        _target_web_origins,
        _validate_agent_context_pack,
        _validate_agent_decision_trace,
        _validate_arsenal_execute_request,
        _validate_campaign_action_for_execution,
        _validate_operation_plan,
        arsenal_agent_context_packs,
        arsenal_agent_decision_traces,
        arsenal_append_hypothesis_signal,
        arsenal_campaign_actions,
        arsenal_campaign_detail,
        arsenal_campaigns,
        arsenal_claim_hypothesis,
        arsenal_command_results,
        arsenal_commands,
        arsenal_contracts,
        arsenal_create_agent_context_pack,
        arsenal_create_agent_context_pack_from_target,
        arsenal_create_agent_decision_trace,
        arsenal_create_approval,
        arsenal_create_campaign,
        arsenal_create_operation_plan,
        arsenal_derive_refuter_review_verdict,
        arsenal_execute,
        arsenal_execute_authz_replay,
        arsenal_execute_refuter_review_plan,
        arsenal_family_proof_contracts,
        arsenal_family_proof_evaluate,
        arsenal_finding_refuter_panel,
        arsenal_generate_hypotheses_from_benchmark,
        arsenal_generate_hypotheses_from_plan,
        arsenal_generate_hypotheses_from_source,
        arsenal_hypotheses,
        arsenal_hypothesis_situation_report,
        arsenal_link_campaign_action,
        arsenal_operation_plans,
        arsenal_plan_hypothesis_campaign,
        arsenal_promote_authz_replay,
        arsenal_queue_refuter_reviews_from_summary,
        arsenal_reconcile_hypothesis_proof,
        arsenal_record_hypothesis,
        arsenal_record_refuter_review,
        arsenal_record_tool_receipt,
        arsenal_refuter_review_summary,
        arsenal_refuter_reviews,
        arsenal_revoke_approval,
        arsenal_schedule_hypotheses,
        arsenal_scope_preview,
        arsenal_tool_receipts,
        arsenal_tools,
        arsenal_transition_hypothesis,
    )
configure_arsenal_router(
    lambda: db_pool,
    EVIDENCE_RETENTION_DAYS=lambda: EVIDENCE_RETENTION_DAYS,
    EVIDENCE_RETENTION_PREVIEW_FIELDS=lambda: EVIDENCE_RETENTION_PREVIEW_FIELDS,
    EvidenceRetentionSweepRequest=lambda: EvidenceRetentionSweepRequest,
    FORBIDDEN_AGENT_CONTEXT_KEYS=lambda: FORBIDDEN_AGENT_CONTEXT_KEYS,
    LocalAgentPlanParseRequest=lambda: LocalAgentPlanParseRequest,
    LocalAgentPlanRequest=lambda: LocalAgentPlanRequest,
    LocalAgentTestRequest=lambda: LocalAgentTestRequest,
    RESEARCH_LAUNCH_PROFILES=lambda: RESEARCH_LAUNCH_PROFILES,
    RESEARCH_SEMANTIC_FALSIFICATION_LIMIT=lambda: RESEARCH_SEMANTIC_FALSIFICATION_LIMIT,
    _active_workflow_cancellations=lambda: _active_workflow_cancellations,
    _ai_ops_execute_enabled=lambda: _ai_ops_execute_enabled,
    _arsenal_action_state=lambda: _arsenal_action_state,
    _bounded_research_payload=lambda: _bounded_research_payload,
    _canonical_vulnerability_key=lambda: _canonical_vulnerability_key,
    _canonical_vulnerability_route=lambda: _canonical_vulnerability_route,
    _contains_forbidden_context_key=lambda: _contains_forbidden_context_key,
    _evidence_retention_preview_payload=lambda: _evidence_retention_preview_payload,
    _execute_authz_replay_plan=lambda: _execute_authz_replay_plan,
    _execute_workflow_runtime=lambda: _execute_workflow_runtime,
    _inject_create_mass_assignment_credentials=lambda: _inject_create_mass_assignment_credentials,
    _link_command_result_to_campaign=lambda: _link_command_result_to_campaign,
    _link_command_result_to_campaign_action=lambda: _link_command_result_to_campaign_action,
    _median=lambda: _median,
    _normalize_hypothesis_dedupe_value=lambda: _normalize_hypothesis_dedupe_value,
    _parse_hypothesis_time=lambda: _parse_hypothesis_time,
    _promote_authz_replay_finding=lambda: _promote_authz_replay_finding,
    _promote_trusted_workflow_finding=lambda: _promote_trusted_workflow_finding,
    _public_campaign_action_row=lambda: _public_campaign_action_row,
    _public_campaign_row=lambda: _public_campaign_row,
    _public_hypothesis_row=lambda: _public_hypothesis_row,
    _record_blocked_command_result=lambda: _record_blocked_command_result,
    _record_command_result=lambda: _record_command_result,
    _record_evidence_instance=lambda: _record_evidence_instance,
    _record_tool_receipt=lambda: _record_tool_receipt,
    _redact_agent_payload=lambda: _redact_agent_payload,
    _redact_agent_text=lambda: _redact_agent_text,
    _research_campaign_budget_snapshot=lambda: _research_campaign_budget_snapshot,
    _research_finding_family=lambda: _research_finding_family,
    _research_vulnerability_dimensions=lambda: _research_vulnerability_dimensions,
    _resolve_workflow_principal_contexts=lambda: _resolve_workflow_principal_contexts,
    _sanitize_scan_options=lambda: _sanitize_scan_options,
    _server_materialize_create_ma=lambda: _server_materialize_create_ma,
    _submit_scan=lambda: _submit_scan,
    _trusted_workflow_family_proof=lambda: _trusted_workflow_family_proof,
    _upsert_hypothesis=lambda: _upsert_hypothesis,
    _validate_approval_receipt_for_action=lambda: _validate_approval_receipt_for_action,
    evidence_export_bundle=lambda: evidence_export_bundle,
    evidence_export_manifest=lambda: evidence_export_manifest,
    evidence_retention_sweep=lambda: evidence_retention_sweep,
    get_evidence_object=lambda: get_evidence_object,
    get_redis=lambda: get_redis,
    get_scan_deployment_decision=lambda: get_scan_deployment_decision,
    get_scan_result=lambda: get_scan_result,
    list_evidence_instances=lambda: list_evidence_instances,
    local_agent_dry_run_plan=lambda: local_agent_dry_run_plan,
    local_agent_parse_candidate_plan=lambda: local_agent_parse_candidate_plan,
    local_agent_test=lambda: local_agent_test,
    local_agents=lambda: local_agents,
    record_evidence_instance=lambda: record_evidence_instance,
    results_dir=lambda: RESULTS_DIR,
)
app.include_router(arsenal_router)
try:
    from evidence_routes.router import (
        configure_evidence_router,
        router as evidence_router,
        EVIDENCE_RETENTION_DAYS,
        EVIDENCE_RETENTION_PREVIEW_FIELDS,
        EVIDENCE_RETENTION_PREVIEW_SCHEMA_VERSION,
        EVIDENCE_RETENTION_PREVIEW_TTL_SECONDS,
        EVIDENCE_RETENTION_PROTECTED_CLASSES,
        EvidenceInstanceRequest,
        EvidenceRetentionSweepRequest,
        _acquire_evidence_retention_blob_locks,
        _acquire_evidence_retention_identity_locks,
        _delete_local_evidence_files,
        _delete_remote_evidence_objects,
        _enrich_evidence_retention_candidates,
        _evidence_export_archive_bytes,
        _evidence_export_archive_descriptor,
        _evidence_export_bundle_descriptor,
        _evidence_export_manifest,
        _evidence_manifest_entry,
        _evidence_retention_blob_lock_keys,
        _evidence_retention_candidate,
        _evidence_retention_candidate_snapshot,
        _evidence_retention_candidates,
        _evidence_retention_criteria,
        _evidence_retention_identity_lock_keys,
        _evidence_retention_links_match_target,
        _evidence_retention_policy_hash,
        _evidence_retention_preview_hash,
        _evidence_retention_preview_payload,
        _evidence_retention_request_from_preview,
        _evidence_retention_row_matches_snapshot,
        _evidence_retention_sweep,
        _evidence_storage_backend,
        _public_evidence_instance_row,
        _public_evidence_instance_summary,
        _public_evidence_retention_execution,
        _release_evidence_retention_blob_locks,
        _release_evidence_retention_identity_locks,
        _run_evidence_retention_deletion_io,
        _validate_evidence_retention_preview_payload,
        evidence_export_bundle,
        evidence_export_manifest,
        evidence_retention_sweep,
        get_evidence_instance,
        get_evidence_object,
        list_evidence_instances,
        list_evidence_retention_executions,
        record_evidence_instance,
    )
except ModuleNotFoundError:  # package import in host-side tests
    from api.evidence_routes.router import (
        configure_evidence_router,
        router as evidence_router,
        EVIDENCE_RETENTION_DAYS,
        EVIDENCE_RETENTION_PREVIEW_FIELDS,
        EVIDENCE_RETENTION_PREVIEW_SCHEMA_VERSION,
        EVIDENCE_RETENTION_PREVIEW_TTL_SECONDS,
        EVIDENCE_RETENTION_PROTECTED_CLASSES,
        EvidenceInstanceRequest,
        EvidenceRetentionSweepRequest,
        _acquire_evidence_retention_blob_locks,
        _acquire_evidence_retention_identity_locks,
        _delete_local_evidence_files,
        _delete_remote_evidence_objects,
        _enrich_evidence_retention_candidates,
        _evidence_export_archive_bytes,
        _evidence_export_archive_descriptor,
        _evidence_export_bundle_descriptor,
        _evidence_export_manifest,
        _evidence_manifest_entry,
        _evidence_retention_blob_lock_keys,
        _evidence_retention_candidate,
        _evidence_retention_candidate_snapshot,
        _evidence_retention_candidates,
        _evidence_retention_criteria,
        _evidence_retention_identity_lock_keys,
        _evidence_retention_links_match_target,
        _evidence_retention_policy_hash,
        _evidence_retention_preview_hash,
        _evidence_retention_preview_payload,
        _evidence_retention_request_from_preview,
        _evidence_retention_row_matches_snapshot,
        _evidence_retention_sweep,
        _evidence_storage_backend,
        _public_evidence_instance_row,
        _public_evidence_instance_summary,
        _public_evidence_retention_execution,
        _release_evidence_retention_blob_locks,
        _release_evidence_retention_identity_locks,
        _run_evidence_retention_deletion_io,
        _validate_evidence_retention_preview_payload,
        evidence_export_bundle,
        evidence_export_manifest,
        evidence_retention_sweep,
        get_evidence_instance,
        get_evidence_object,
        list_evidence_instances,
        list_evidence_retention_executions,
        record_evidence_instance,
    )
configure_evidence_router(
    lambda: db_pool,
    _parse_hypothesis_time=lambda: _parse_hypothesis_time,
    _record_command_result=lambda: _record_command_result,
    _record_evidence_instance=lambda: _record_evidence_instance,
    _record_export_event=lambda: _record_export_event,
    _redact_agent_payload=lambda: _redact_agent_payload,
    _validate_approval_receipt_for_action=lambda: _validate_approval_receipt_for_action,
    results_dir=lambda: RESULTS_DIR,
)
app.include_router(evidence_router)
try:
    from local_agent_routes.router import (
        configure_local_agent_router,
        router as local_agent_router,
        LOCAL_AGENT_HIDDEN_EXECUTION_KEY_FIELDS,
        LOCAL_AGENT_HIDDEN_EXECUTION_PATTERN,
        LOCAL_AGENT_PLAN_FIELDS,
        LocalAgentPlanParseRequest,
        LocalAgentPlanRequest,
        LocalAgentTestRequest,
        _build_local_agent_dry_run_plan,
        _choose_local_agent_plan_action,
        _find_hidden_local_agent_execution_requests,
        _parse_local_agent_candidate_plan,
        _strict_local_agent_json_object,
        local_agent_dry_run_plan,
        local_agent_parse_candidate_plan,
        local_agent_test,
        local_agents,
    )
except ModuleNotFoundError:  # package import in host-side tests
    from api.local_agent_routes.router import (
        configure_local_agent_router,
        router as local_agent_router,
        LOCAL_AGENT_HIDDEN_EXECUTION_KEY_FIELDS,
        LOCAL_AGENT_HIDDEN_EXECUTION_PATTERN,
        LOCAL_AGENT_PLAN_FIELDS,
        LocalAgentPlanParseRequest,
        LocalAgentPlanRequest,
        LocalAgentTestRequest,
        _build_local_agent_dry_run_plan,
        _choose_local_agent_plan_action,
        _find_hidden_local_agent_execution_requests,
        _parse_local_agent_candidate_plan,
        _strict_local_agent_json_object,
        local_agent_dry_run_plan,
        local_agent_parse_candidate_plan,
        local_agent_test,
        local_agents,
    )
configure_local_agent_router(
    lambda: db_pool,
    _context_pack_payload_from_row=lambda: _context_pack_payload_from_row,
    _context_pack_target_scope=lambda: _context_pack_target_scope,
    _disallowed_commands_from_context=lambda: _disallowed_commands_from_context,
    _json_size_bytes=lambda: _json_size_bytes,
    _validate_bounded_agent_parameters=lambda: _validate_bounded_agent_parameters,
    _validate_candidate_target_scope=lambda: _validate_candidate_target_scope,
)
app.include_router(local_agent_router)
try:
    from hunt.interaction_router import (
        configure_hunt_interaction_router,
        router as hunt_interaction_router,
        _AGENT_MUTATING_VERIFY_FAMILIES,
        HuntCandidateRequest,
        HuntCapabilityRequest,
        HuntQueryRequest,
        _AGENT_TOOL_MAX_QUERY_ROWS,
        _agent_tool_query_kb,
        _enqueue_canonical_browser_capability,
        _enqueue_canonical_http_capability,
        _enqueue_canonical_network_capability,
        _enqueue_canonical_scanner_capability,
        _enqueue_hunt_replay_capability,
        _execute_hunt_candidate_verification,
        _execute_hunt_capability_lifecycle,
        _hunt_bound_collection,
        _hunt_bound_selector,
        _hunt_collection_selector,
        _hunt_confirmed_shell_capability_input,
        _hunt_confirmed_shell_dispatch,
        _hunt_device_adapter_execution_state,
        _hunt_device_ssh_proposal_delta,
        _hunt_json,
        _hunt_ledger_limits,
        _hunt_managed_principal_reference,
        _hunt_nonexecuting_actual,
        _hunt_redacted_capability_input,
        _hunt_select_collection,
        _merge_hunt_device_control_context,
        _merge_hunt_device_http_context,
        _merge_hunt_device_queue_context,
        _merge_hunt_device_ssh_proposal_context,
        confirm_hunt_shell_plan,
        create_hunt_candidate,
        execute_hunt_capability,
        query_hunt,
        verify_hunt_candidate,
    )
except ModuleNotFoundError:  # package import in host-side tests
    from api.hunt.interaction_router import (
        configure_hunt_interaction_router,
        router as hunt_interaction_router,
        _AGENT_MUTATING_VERIFY_FAMILIES,
        HuntCandidateRequest,
        HuntCapabilityRequest,
        HuntQueryRequest,
        _AGENT_TOOL_MAX_QUERY_ROWS,
        _agent_tool_query_kb,
        _enqueue_canonical_browser_capability,
        _enqueue_canonical_http_capability,
        _enqueue_canonical_network_capability,
        _enqueue_canonical_scanner_capability,
        _enqueue_hunt_replay_capability,
        _execute_hunt_candidate_verification,
        _execute_hunt_capability_lifecycle,
        _hunt_bound_collection,
        _hunt_bound_selector,
        _hunt_collection_selector,
        _hunt_confirmed_shell_capability_input,
        _hunt_confirmed_shell_dispatch,
        _hunt_device_adapter_execution_state,
        _hunt_device_ssh_proposal_delta,
        _hunt_json,
        _hunt_ledger_limits,
        _hunt_managed_principal_reference,
        _hunt_nonexecuting_actual,
        _hunt_redacted_capability_input,
        _hunt_select_collection,
        _merge_hunt_device_control_context,
        _merge_hunt_device_http_context,
        _merge_hunt_device_queue_context,
        _merge_hunt_device_ssh_proposal_context,
        confirm_hunt_shell_plan,
        create_hunt_candidate,
        execute_hunt_capability,
        query_hunt,
        verify_hunt_candidate,
    )
configure_hunt_interaction_router(
    lambda: db_pool,
    AGENT_TOOL_QUEUE_NAME=lambda: AGENT_TOOL_QUEUE_NAME,
    _validate_approval_receipt_for_action=lambda: _validate_approval_receipt_for_action,
    _verify_suspected_finding_workflow=lambda: _verify_suspected_finding_workflow,
    enqueue_job=lambda: enqueue_job,
    get_redis=lambda: get_redis,
)
app.include_router(hunt_interaction_router)


@app.post("/scans/{scan_id}/cancel")
async def cancel_scan(scan_id: str):
    """Cancel a running or pending scan."""
    r = get_redis()
    child_rows = []
    parent_to_reconcile = None

    async with db_pool.acquire() as conn:
        # Check scan exists and is cancellable
        scan = await conn.fetchrow(
            """
            SELECT id, status, target_url, job_id, scan_role, parent_scan_id, run_kind
            FROM scans WHERE id = $1
            """,
            uuid.UUID(scan_id)
        )
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        if scan['status'] not in ('pending', 'running', 'queued'):
            raise HTTPException(
                status_code=400,
                detail=f"Cannot cancel scan with status '{scan['status']}'"
            )

        device_traffic_running = (
            str(scan['run_kind'] or '') in {'device_posture', 'device_probe'}
            and str(scan['status']) == 'running'
        )
        requested_status = 'cancelling' if device_traffic_running else 'cancelled'

        # Device traffic stays locked in ``cancelling`` until the worker has
        # reaped its in-flight process group and acknowledges terminal state.
        await conn.execute("""
            UPDATE scans
            SET status = $2,
                error_message = 'Cancelled by user',
                completed_at = CASE WHEN $2='cancelled' THEN NOW() ELSE NULL END,
                progress = CASE WHEN $2='cancelled' THEN 100 ELSE progress END,
                current_phase = $2
            WHERE id = $1
        """, uuid.UUID(scan_id), requested_status)

        if scan['scan_role'] == 'parent' or str(scan['run_kind'] or '') == 'device_posture':
            # Fan out cancellation to queued/running child shards. Workers may
            # still finish their subprocesses, but completion handlers must not
            # overwrite these terminal rows.
            child_rows = await conn.fetch("""
                UPDATE scans
                SET status = 'cancelled',
                    error_message = 'Cancelled by parent scan',
                    completed_at = NOW(),
                    progress = 100,
                    current_phase = 'cancelled'
                WHERE parent_scan_id = $1
                  AND status IN ('pending', 'queued', 'running')
                RETURNING id, job_id
            """, uuid.UUID(scan_id))
            try:
                r.set(parallel_scan.merge_guard_key(scan_id), "cancelled", nx=True, ex=86400)
            except Exception:
                pass
        elif scan['scan_role'] == 'shard' and scan['parent_scan_id']:
            parent_to_reconcile = str(scan['parent_scan_id'])

    # Signal worker to stop via Redis (set cancel flag)
    # Workers should check this flag periodically
    r.set(f"scan:{scan_id}:cancel", "1", ex=86400)
    for child in child_rows:
        r.set(f"scan:{str(child['id'])}:cancel", "1", ex=86400)

    # Also update known job hashes in Redis so UI/queue status reflects the
    # cancellation immediately.
    job_ids = [scan['job_id']] + [child['job_id'] for child in child_rows]
    for job_id in job_ids:
        if job_id:
            r.hset(
                f"job:{job_id}",
                mapping={
                    'status': requested_status if job_id == scan['job_id'] else 'cancelled',
                    'progress': '100' if requested_status == 'cancelled' or job_id != scan['job_id'] else str(0),
                    'current_phase': requested_status if job_id == scan['job_id'] else 'cancelled',
                },
            )
            r.expire(f"job:{job_id}", 86400)

    # Backward-compatible fallback for older/odd job hashes.
    for key in r.keys("job:*"):
        job_data = r.hgetall(key)
        if job_data.get('scan_id') == scan_id:
            r.hset(key, 'status', 'cancelled')
            break

    if parent_to_reconcile:
        async with db_pool.acquire() as conn:
            await parallel_scan.reconcile_parallel_parent(
                conn, parent_to_reconcile, r, QUEUE_NAME
            )

    return {
        "status": requested_status,
        "scan_id": scan_id,
        "target": scan['target_url'],
        "cancelled_child_shards": len(child_rows),
        "message": "Cancellation requested; device traffic remains locked until the worker stops" if requested_status == "cancelling" else "Scan cancelled successfully"
    }

try:
    from research_routes.router import (
        cancel_workflow_experiment,
        configure_research_router,
        router as research_router,
        RESEARCH_ASM_FAMILIES,
        RESEARCH_AUTOPILOT_HEARTBEAT_SECONDS,
        RESEARCH_AUTOPILOT_LEASE_SECONDS,
        RESEARCH_BUDGET_KEYS,
        RESEARCH_CAMPAIGN_FAMILIES,
        RESEARCH_DEFAULT_CAMPAIGN_FAMILIES,
        RESEARCH_INCONCLUSIVE_ACTUATOR_LIMIT,
        RESEARCH_LAUNCH_PROFILES,
        RESEARCH_MAX_OBSERVATIONS_PER_EPISODE,
        RESEARCH_MISSION_COMMANDS,
        RESEARCH_OBSERVATION_MAX_BYTES,
        RESEARCH_PLANNER_MODES,
        RESEARCH_PREFLIGHT_CLAIM_TTL_SECONDS,
        RESEARCH_PREFLIGHT_MAX_ATTEMPTS,
        RESEARCH_PREFLIGHT_RESERVED_COST,
        RESEARCH_PREFLIGHT_TRANSIENT_RETRY_SECONDS,
        RESEARCH_RECON_ACTION_CAP,
        RESEARCH_SEMANTIC_FALSIFICATION_LIMIT,
        ResearchAutopilotRequest,
        ResearchCampaignControlRequest,
        ResearchCampaignLaunchRequest,
        ResearchEpisodeRequest,
        ResearchLaunchRequest,
        ResearchObservationRequest,
        ResearchPlannerStepRequest,
        _RESEARCH_FOCUSED_ENDPOINT_METHODS,
        _active_workflow_cancellations,
        _build_research_observation,
        _compact_research_observation_pack,
        _mark_research_model_budget_exhausted,
        _materialize_research_invariant_hypotheses,
        _plan_research_episode_step,
        _public_research_decision_row,
        _public_research_episode_row,
        _public_research_event_row,
        _public_research_observation_row,
        _reconcile_research_gap_recommendations,
        _record_research_hypothesis_outcome,
        _record_research_planner_failure,
        _research_action_contains_secret_material,
        _research_action_planner_projection,
        _research_action_vulnerability_keys,
        _research_async_work,
        _research_autobind_hypothesis,
        _research_autonomous_parameter_schema,
        _research_campaign_budget_limits,
        _research_campaign_budget_remaining,
        _research_campaign_budget_violations,
        _research_campaign_episode_budget_available,
        _research_campaign_episode_budget_limits,
        _research_campaign_exhaustion_snapshot,
        _research_campaign_retest_cap_reached,
        _research_campaign_self_repair,
        _research_canonicalize_action_shape,
        _research_canonicalize_experiment_steps_alias,
        _research_canonicalize_hypothesis_binding,
        _research_canonicalize_workflow_wrapper,
        _research_command_catalog,
        _research_command_views,
        _research_configured_planner_ready,
        _research_decision_action_is_excluded,
        _research_decision_hypothesis_is_excluded,
        _research_dispatch_async_ref,
        _research_episode_detail,
        _research_episode_or_404,
        _research_episode_planner_mode,
        _research_experiment_projection,
        _research_family_is_allowed,
        _research_family_scope_keys,
        _research_finding_is_web,
        _research_focus_snapshot,
        _research_forbidden_control_paths,
        _research_graph_with_preflight_provenance,
        _research_inferred_planning_contracts,
        _research_intensity_campaign_families,
        _research_is_consecutive_duplicate_action,
        _research_latest_action_result,
        _research_launch_planner_mode,
        _research_lease_heartbeat,
        _research_linked_work_outcome,
        _research_maybe_auto_provision_principals,
        _research_mission,
        _research_normalize_focused_endpoint,
        _research_normalize_injection_payloads,
        _research_parameterized_action_cost,
        _research_planner_kind,
        _research_preflight_claim_is_stale,
        _research_preflight_error_is_transient,
        _research_preflight_scan_options,
        _research_prepare_action,
        _research_previous_result_digest,
        _research_read_result_projection,
        _research_recent_actions,
        _research_recommended_actions,
        _research_selected_hypothesis_contracts,
        _research_semantic_policy_violations,
        _research_subtract_cost,
        _research_workflow_surface_violations,
        _reuse_research_launch_episode,
        _savepoint_fetchrow,
        _settle_research_awaiting_observation,
        _validate_research_intensity_families,
        cancel_research_episode,
        control_research_campaign,
        create_research_episode,
        get_research_episode,
        launch_research_campaign,
        launch_research_episode,
        list_research_episodes,
        plan_research_episode_step,
        refresh_research_observation,
        research_episode_benchmark,
        research_readiness,
        set_research_episode_autopilot,
        settle_research_episode,
        submit_research_decision,
    )
except ModuleNotFoundError:  # package import in host-side tests
    from api.research_routes.router import (
        cancel_workflow_experiment,
        configure_research_router,
        router as research_router,
        RESEARCH_ASM_FAMILIES,
        RESEARCH_AUTOPILOT_HEARTBEAT_SECONDS,
        RESEARCH_AUTOPILOT_LEASE_SECONDS,
        RESEARCH_BUDGET_KEYS,
        RESEARCH_CAMPAIGN_FAMILIES,
        RESEARCH_DEFAULT_CAMPAIGN_FAMILIES,
        RESEARCH_INCONCLUSIVE_ACTUATOR_LIMIT,
        RESEARCH_LAUNCH_PROFILES,
        RESEARCH_MAX_OBSERVATIONS_PER_EPISODE,
        RESEARCH_MISSION_COMMANDS,
        RESEARCH_OBSERVATION_MAX_BYTES,
        RESEARCH_PLANNER_MODES,
        RESEARCH_PREFLIGHT_CLAIM_TTL_SECONDS,
        RESEARCH_PREFLIGHT_MAX_ATTEMPTS,
        RESEARCH_PREFLIGHT_RESERVED_COST,
        RESEARCH_PREFLIGHT_TRANSIENT_RETRY_SECONDS,
        RESEARCH_RECON_ACTION_CAP,
        RESEARCH_SEMANTIC_FALSIFICATION_LIMIT,
        ResearchAutopilotRequest,
        ResearchCampaignControlRequest,
        ResearchCampaignLaunchRequest,
        ResearchEpisodeRequest,
        ResearchLaunchRequest,
        ResearchObservationRequest,
        ResearchPlannerStepRequest,
        _RESEARCH_FOCUSED_ENDPOINT_METHODS,
        _active_workflow_cancellations,
        _build_research_observation,
        _compact_research_observation_pack,
        _mark_research_model_budget_exhausted,
        _materialize_research_invariant_hypotheses,
        _plan_research_episode_step,
        _public_research_decision_row,
        _public_research_episode_row,
        _public_research_event_row,
        _public_research_observation_row,
        _reconcile_research_gap_recommendations,
        _record_research_hypothesis_outcome,
        _record_research_planner_failure,
        _research_action_contains_secret_material,
        _research_action_planner_projection,
        _research_action_vulnerability_keys,
        _research_async_work,
        _research_autobind_hypothesis,
        _research_autonomous_parameter_schema,
        _research_campaign_budget_limits,
        _research_campaign_budget_remaining,
        _research_campaign_budget_violations,
        _research_campaign_episode_budget_available,
        _research_campaign_episode_budget_limits,
        _research_campaign_exhaustion_snapshot,
        _research_campaign_retest_cap_reached,
        _research_campaign_self_repair,
        _research_canonicalize_action_shape,
        _research_canonicalize_experiment_steps_alias,
        _research_canonicalize_hypothesis_binding,
        _research_canonicalize_workflow_wrapper,
        _research_command_catalog,
        _research_command_views,
        _research_configured_planner_ready,
        _research_decision_action_is_excluded,
        _research_decision_hypothesis_is_excluded,
        _research_dispatch_async_ref,
        _research_episode_detail,
        _research_episode_or_404,
        _research_episode_planner_mode,
        _research_experiment_projection,
        _research_family_is_allowed,
        _research_family_scope_keys,
        _research_finding_is_web,
        _research_focus_snapshot,
        _research_forbidden_control_paths,
        _research_graph_with_preflight_provenance,
        _research_inferred_planning_contracts,
        _research_intensity_campaign_families,
        _research_is_consecutive_duplicate_action,
        _research_latest_action_result,
        _research_launch_planner_mode,
        _research_lease_heartbeat,
        _research_linked_work_outcome,
        _research_maybe_auto_provision_principals,
        _research_mission,
        _research_normalize_focused_endpoint,
        _research_normalize_injection_payloads,
        _research_parameterized_action_cost,
        _research_planner_kind,
        _research_preflight_claim_is_stale,
        _research_preflight_error_is_transient,
        _research_preflight_scan_options,
        _research_prepare_action,
        _research_previous_result_digest,
        _research_read_result_projection,
        _research_recent_actions,
        _research_recommended_actions,
        _research_selected_hypothesis_contracts,
        _research_semantic_policy_violations,
        _research_subtract_cost,
        _research_workflow_surface_violations,
        _reuse_research_launch_episode,
        _savepoint_fetchrow,
        _settle_research_awaiting_observation,
        _validate_research_intensity_families,
        cancel_research_episode,
        control_research_campaign,
        create_research_episode,
        get_research_episode,
        launch_research_campaign,
        launch_research_episode,
        list_research_episodes,
        plan_research_episode_step,
        refresh_research_observation,
        research_episode_benchmark,
        research_readiness,
        set_research_episode_autopilot,
        settle_research_episode,
        submit_research_decision,
    )
configure_research_router(
    lambda: db_pool,
    cancel_scan=lambda: cancel_scan,
    FORBIDDEN_AGENT_CONTEXT_KEYS=lambda: FORBIDDEN_AGENT_CONTEXT_KEYS,
    _ai_ops_execute_enabled=lambda: _ai_ops_execute_enabled,
    _json_size_bytes=lambda: _json_size_bytes,
    _load_effective_ai_settings=lambda: _load_effective_ai_settings,
    _load_effective_automation_settings=lambda: _load_effective_automation_settings,
    _normalize_research_planner_mode=lambda: _normalize_research_planner_mode,
    _record_command_result=lambda: _record_command_result,
    _record_research_event=lambda: _record_research_event,
    _validate_approval_receipt_for_action=lambda: _validate_approval_receipt_for_action,
    _validate_bounded_agent_parameters=lambda: _validate_bounded_agent_parameters,
    get_redis=lambda: get_redis,
)
app.include_router(research_router)
try:
    from agent_routes.router import (
        configure_agent_router,
        router as agent_router,
        AGENT_TOOL_WORKER_BUILD_REGISTRY_KEY,
        AgentHuntReplyRequest,
        AgentHuntRequest,
        AgentHuntSessionStartRequest,
        AgentToolExecuteRequest,
        AgentVerifyRequest,
        _AGENT_AUTO_VERIFY_EXCLUDED_FAMILIES,
        _AGENT_AUTO_VERIFY_LIMIT,
        _AGENT_AUTO_VERIFY_SKIP_REPORT_LIMIT,
        _AGENT_DAST_RETEST_FAMILIES,
        _AGENT_HUNT_DEFAULT_ITERATIONS,
        _AGENT_HUNT_MAX_ITERATIONS,
        _AGENT_HUNT_TRANSCRIPT_SOFT_CAP,
        _AGENT_MAX_TOOLS_PER_TURN,
        _AGENT_ROUTE_ONLY_RETEST_FAMILIES,
        _AGENT_TOOL_HTTP_TIMEOUT_SECONDS,
        _AGENT_UNVERIFIABLE_FAMILY_REPORT_LIMIT,
        _AGENT_VERIFY_REQUEST_RESERVATIONS,
        _AGENT_VERIFY_SECONDS_RESERVATIONS,
        _agent_apply_reply,
        _agent_auto_queue_dast_retests,
        _agent_auto_verify,
        _agent_context_pack_sections,
        _agent_finalize_and_persist,
        _agent_finalize_gate,
        _agent_finding_locus,
        _agent_hunt_run_or_404,
        _agent_hunt_run_public,
        _agent_new_state,
        _agent_pack_compact,
        _agent_persist_suspected_findings,
        _agent_planner_reply,
        _agent_planner_turn_token_reservation,
        _agent_resolve_ref,
        _agent_run_final_status,
        _agent_run_summary_receipt,
        _agent_seed_state,
        _agent_tool_diff,
        _agent_tool_http_request,
        _agent_tool_note,
        _agent_tool_run_tool,
        _agent_tool_worker_readiness,
        _agent_trim_transcript,
        _enqueue_agent_scanner_tool,
        _execute_agent_tool,
        _persist_agent_suspected_finding,
        _resolve_agent_target_addresses,
        _resolve_hunt_origin,
        _resolve_hunt_tool_url,
        _run_agent_hunt,
        cancel_agent_hunt_session,
        execute_agent_tool_endpoint,
        get_agent_context_pack,
        get_agent_hunt_session,
        get_agent_tool_readiness,
        get_agent_two_tier_findings,
        list_agent_hunt_runs,
        run_agent_hunt_endpoint,
        start_agent_hunt_session,
        submit_agent_hunt_reply,
        verify_suspected_agent_finding,
    )
except ModuleNotFoundError:  # package import in host-side tests
    from api.agent_routes.router import (
        configure_agent_router,
        router as agent_router,
        AGENT_TOOL_WORKER_BUILD_REGISTRY_KEY,
        AgentHuntReplyRequest,
        AgentHuntRequest,
        AgentHuntSessionStartRequest,
        AgentToolExecuteRequest,
        AgentVerifyRequest,
        _AGENT_AUTO_VERIFY_EXCLUDED_FAMILIES,
        _AGENT_AUTO_VERIFY_LIMIT,
        _AGENT_AUTO_VERIFY_SKIP_REPORT_LIMIT,
        _AGENT_DAST_RETEST_FAMILIES,
        _AGENT_HUNT_DEFAULT_ITERATIONS,
        _AGENT_HUNT_MAX_ITERATIONS,
        _AGENT_HUNT_TRANSCRIPT_SOFT_CAP,
        _AGENT_MAX_TOOLS_PER_TURN,
        _AGENT_ROUTE_ONLY_RETEST_FAMILIES,
        _AGENT_TOOL_HTTP_TIMEOUT_SECONDS,
        _AGENT_UNVERIFIABLE_FAMILY_REPORT_LIMIT,
        _AGENT_VERIFY_REQUEST_RESERVATIONS,
        _AGENT_VERIFY_SECONDS_RESERVATIONS,
        _agent_apply_reply,
        _agent_auto_queue_dast_retests,
        _agent_auto_verify,
        _agent_context_pack_sections,
        _agent_finalize_and_persist,
        _agent_finalize_gate,
        _agent_finding_locus,
        _agent_hunt_run_or_404,
        _agent_hunt_run_public,
        _agent_new_state,
        _agent_pack_compact,
        _agent_persist_suspected_findings,
        _agent_planner_reply,
        _agent_planner_turn_token_reservation,
        _agent_resolve_ref,
        _agent_run_final_status,
        _agent_run_summary_receipt,
        _agent_seed_state,
        _agent_tool_diff,
        _agent_tool_http_request,
        _agent_tool_note,
        _agent_tool_run_tool,
        _agent_tool_worker_readiness,
        _agent_trim_transcript,
        _enqueue_agent_scanner_tool,
        _execute_agent_tool,
        _persist_agent_suspected_finding,
        _resolve_agent_target_addresses,
        _resolve_hunt_origin,
        _resolve_hunt_tool_url,
        _run_agent_hunt,
        cancel_agent_hunt_session,
        execute_agent_tool_endpoint,
        get_agent_context_pack,
        get_agent_hunt_session,
        get_agent_tool_readiness,
        get_agent_two_tier_findings,
        list_agent_hunt_runs,
        run_agent_hunt_endpoint,
        start_agent_hunt_session,
        submit_agent_hunt_reply,
        verify_suspected_agent_finding,
    )
configure_agent_router(
    lambda: db_pool,
    AGENT_TOOL_QUEUE_NAME=lambda: AGENT_TOOL_QUEUE_NAME,
    _AGENT_VERIFIABLE_FAMILIES=lambda: _AGENT_VERIFIABLE_FAMILIES,
    _ai_ops_execute_enabled=lambda: _ai_ops_execute_enabled,
    _load_effective_ai_settings=lambda: _load_effective_ai_settings,
    _provision_same_origin_url=lambda: _provision_same_origin_url,
    _require_approval_receipt_if_policy_enabled=lambda: _require_approval_receipt_if_policy_enabled,
    _validate_approval_receipt_for_action=lambda: _validate_approval_receipt_for_action,
    _verify_suspected_finding_workflow=lambda: _verify_suspected_finding_workflow,
    current_scanner_version=lambda: current_scanner_version,
    enqueue_job=lambda: enqueue_job,
    expected_build_fingerprint=lambda: expected_build_fingerprint,
    get_redis=lambda: get_redis,
    worker_build_current=lambda: worker_build_current,
)
app.include_router(agent_router)
try:
    from investigation_routes.router import (
        configure_investigation_router,
        router as investigation_router,
        _public_investigation_candidate,
        get_investigation_candidate,
        list_investigation_candidates,
    )
except ModuleNotFoundError:  # package import in host-side tests
    from api.investigation_routes.router import (
        configure_investigation_router,
        router as investigation_router,
        _public_investigation_candidate,
        get_investigation_candidate,
        list_investigation_candidates,
    )
configure_investigation_router(lambda: db_pool)
app.include_router(investigation_router)
try:
    from retest_routes.router import (
        configure_retest_router,
        router as retest_router,
        get_retest,
        list_finding_retests,
    )
except ModuleNotFoundError:  # package import in host-side tests
    from api.retest_routes.router import (
        configure_retest_router,
        router as retest_router,
        get_retest,
        list_finding_retests,
    )
configure_retest_router(lambda: db_pool)
app.include_router(retest_router)

# CORS for UI.
#
# SECURITY (audit P0-1): the API is tokenless and the UI issues no credentialed requests, so
# `allow_origins=["*"]` with `allow_credentials=True` was a footgun — Starlette resolves that pair by
# REFLECTING the caller's Origin and returning Access-Control-Allow-Credentials: true, letting any web
# page the operator visits read every API response (findings, targets, settings) and drive scans from
# the victim's browser. We instead allow only the UI's own origin(s). Defaults cover the local UI on
# the standard/hostable ports; remote deployments add their public origin via env. Credentials are OFF
# because there are none to send, and OFF avoids the reflect-with-credentials behavior entirely.
def _cors_allow_origins() -> list[str]:
    ui_port = os.environ.get("SHAKERSCAN_UI_PORT", "3000")
    defaults = [
        f"http://localhost:{ui_port}", f"http://127.0.0.1:{ui_port}",
        "http://localhost:3000", "http://127.0.0.1:3000",
    ]
    public_host = os.environ.get("SHAKERSCAN_PUBLIC_HOST", "").strip()
    if public_host:
        for scheme in ("https", "http"):
            defaults.append(f"{scheme}://{public_host}")
            defaults.append(f"{scheme}://{public_host}:{ui_port}")
    extra = os.environ.get("SHAKERSCAN_CORS_ALLOW_ORIGINS", "")
    defaults.extend(o.strip() for o in extra.split(",") if o.strip())
    # de-dupe, preserve order
    seen: set[str] = set()
    return [o for o in defaults if not (o in seen or seen.add(o))]


_cors_kwargs: dict[str, Any] = {
    "allow_origins": _cors_allow_origins(),
    "allow_credentials": False,
    "allow_methods": ["*"],
    "allow_headers": ["*"],
    # The Hunt launcher fail-closes unless the browser can prove that the
    # canonical V2 endpoint admitted the request. CORS hides non-safelisted
    # response headers unless they are explicitly exposed.
    "expose_headers": ["x-shakerscan-hunt-contract"],
}
# Optional regex for dynamic remote origins (e.g. a Tailscale MagicDNS name) without listing each.
_cors_regex = os.environ.get("SHAKERSCAN_CORS_ALLOW_ORIGIN_REGEX", "").strip()
if _cors_regex:
    _cors_kwargs["allow_origin_regex"] = _cors_regex
app.add_middleware(CORSMiddleware, **_cors_kwargs)


def _origin_is_allowed(origin: str, allowed_origins: Sequence[str], allow_origin_regex: str = "") -> bool:
    """Apply the same exact/regex origin decision to actual unsafe requests as CORS preflights.

    CORS response headers are not a CSRF boundary: browsers still dispatch simple cross-origin POSTs
    and merely hide the response. ShakerScan intentionally remains friendly to curl/agents (which do
    not send Origin), while browser requests that do carry Origin must come from the configured UI.
    """
    normalized = str(origin or "").strip()
    if not normalized:
        return True
    if "*" in allowed_origins:
        return True
    if normalized in allowed_origins:
        return True
    if allow_origin_regex:
        try:
            return re.fullmatch(allow_origin_regex, normalized) is not None
        except re.error:
            # Invalid security configuration fails closed for browser mutations.
            return False
    return False


class UnsafeOriginGuardMiddleware:
    """Reject disallowed browser-origin mutations before endpoint code executes.

    Safe/read-only methods retain ordinary CORS behavior, and non-browser clients remain compatible
    because requests without an Origin header are accepted.
    """

    _SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

    def __init__(self, app: Any, *, allow_origins: Sequence[str], allow_origin_regex: str = ""):
        self.app = app
        self.allow_origins = tuple(allow_origins)
        self.allow_origin_regex = allow_origin_regex

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") == "http" and str(scope.get("method") or "GET").upper() not in self._SAFE_METHODS:
            headers = {
                key.decode("latin-1").lower(): value.decode("latin-1")
                for key, value in scope.get("headers") or []
            }
            origin = headers.get("origin", "")
            if origin and not _origin_is_allowed(origin, self.allow_origins, self.allow_origin_regex):
                body = json.dumps({"detail": "Cross-origin browser mutation is not allowed"}).encode("utf-8")
                await send({
                    "type": "http.response.start",
                    "status": 403,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"content-length", str(len(body)).encode("ascii")),
                        (b"vary", b"Origin"),
                    ],
                })
                await send({"type": "http.response.body", "body": body})
                return
        await self.app(scope, receive, send)


app.add_middleware(
    UnsafeOriginGuardMiddleware,
    allow_origins=_cors_kwargs["allow_origins"],
    allow_origin_regex=str(_cors_kwargs.get("allow_origin_regex") or ""),
)


app.add_middleware(LegacyHuntIsolationMiddleware)
app.add_middleware(PublicV2IdempotencyMiddleware)
app.add_middleware(PublicV2BodyLimitMiddleware)

_fastapi_openapi = getattr(app, "openapi", None)
if callable(_fastapi_openapi):
    def _public_v2_openapi() -> dict[str, Any]:
        return add_public_v2_idempotency_openapi(_fastapi_openapi())

    app.openapi = _public_v2_openapi


@app.exception_handler(RequestValidationError)
async def _request_validation_error_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    # FastAPI's default 422 body includes rejected input. That is useful for ordinary
    # forms but unsafe for credential creation, where the rejected value may be a key,
    # token, password, or private key. Preserve the standard handler everywhere else.
    if public_v2_surface(request.url.path) is not None or request.url.path == "/api/v1/scan":
        return JSONResponse(
            status_code=422,
            content={"detail": public_credential_validation_errors(exc.errors())},
        )
    return await request_validation_exception_handler(request, exc)


@app.exception_handler(ValueError)
async def _value_error_handler(request: Request, exc: ValueError) -> JSONResponse:
    """Convert raw uuid.UUID parse failures into client errors without masking
    unrelated internal ValueErrors as bad requests."""
    if "hexadecimal UUID" not in str(exc):
        raise exc
    logger.info("Invalid UUID path/query parameter on %s %s: %s", request.method, request.url.path, exc)
    return JSONResponse(status_code=400, content={"detail": "Invalid request parameter"})


# ============================================================
# PYDANTIC MODELS
# ============================================================









def _scan_authentication_value_present(value: Any) -> bool:
    """Return whether an auth field carries executable private material."""
    if isinstance(value, bool):
        return value
    return value not in (None, "", [], {})




def _new_legacy_scan_fields(options: ScanOptions) -> list[str]:
    """Return caller-supplied legacy identity fields, including explicit false."""
    return sorted(LEGACY_SCAN_WRITE_FIELDS.intersection(options.model_fields_set))






































class _BatchRequestBase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    targets: list[str] = Field(min_length=1, max_length=50)
    target_kind: Literal["web", "api"] = "web"
    budget_profile: Optional[Literal["fast", "balanced", "thorough"]] = None
    policy: Optional[dict[str, Any]] = None
    request_collections: list[dict[str, Any]] = Field(default_factory=list, max_length=16)
    credential_profile_ids: list[str] = Field(default_factory=list, max_length=2)
    advanced: Optional[ScanAdvancedLimits] = None
    approval_receipt_id: Optional[str] = None
    options: ScanPublicCompatibilityOptions = Field(
        default_factory=ScanPublicCompatibilityOptions,
    )


class BatchRequest(_BatchRequestBase):
    """Canonical secret-free batch submission."""










































































































































































































































def _configure_scan_plan_job(
    job_data: dict[str, Any], parallel_worker_count: int | None = None
) -> None:
    """Keep control-plane orchestration local while preserving shard placement.

    ``process_scan_plan_job`` needs direct Postgres and Redis access, which an
    outbound-only broker worker deliberately never receives. The requested
    execution placement remains in ``options`` and is copied to child shards;
    this top-level placement controls only the plan job's queue route.
    """
    job_data["type"] = parallel_scan.PLAN_JOB_TYPE
    job_data["placement"] = {"node_scope": "local"}
    job_data["attempt"] = 1
    job_data["plan_version"] = parallel_scan.PLAN_VERSION
    if parallel_worker_count is not None:
        job_data["parallel_worker_count"] = parallel_worker_count














try:
    from model_intake_authority import _invalidate_model_intake_authority_change
except ModuleNotFoundError:  # package import in host-side tests
    from api.model_intake_authority import _invalidate_model_intake_authority_change
try:
    from operator_auth import (
        _MODEL_INTAKE_APPROVAL_ROLES,
        _MODEL_INTAKE_LOCAL_SESSION_MAX_SECONDS,
        _MODEL_INTAKE_LOCAL_SESSION_VERSION,
        _fleet_bearer_credential,
        _mint_model_intake_local_session,
        _model_intake_authenticated_subject,
        _model_intake_automatic_system_request,
        _model_intake_configured_operator_credentials,
        _model_intake_local_session_allowed,
        _model_intake_local_session_valid,
        _model_intake_operator_credential,
        _model_intake_operator_roles,
        _model_intake_submission_subject,
        _require_fleet_operator,
        _require_model_intake_operator,
    )
except ModuleNotFoundError:  # package import in host-side tests
    from api.operator_auth import (
        _MODEL_INTAKE_APPROVAL_ROLES,
        _MODEL_INTAKE_LOCAL_SESSION_MAX_SECONDS,
        _MODEL_INTAKE_LOCAL_SESSION_VERSION,
        _fleet_bearer_credential,
        _mint_model_intake_local_session,
        _model_intake_authenticated_subject,
        _model_intake_automatic_system_request,
        _model_intake_configured_operator_credentials,
        _model_intake_local_session_allowed,
        _model_intake_local_session_valid,
        _model_intake_operator_credential,
        _model_intake_operator_roles,
        _model_intake_submission_subject,
        _require_fleet_operator,
        _require_model_intake_operator,
    )
























































def _is_ai_demo_target_row(row: dict[str, Any]) -> bool:
    metadata = _decode_json_value(row.get("metadata_json")) or {}
    demo_flag = metadata.get("shakerscan_demo")
    return (
        demo_flag is True
        or str(demo_flag).strip().lower() == "true"
        or bool(metadata.get("calibration_run"))
        or "honey_scenario_id" in metadata
        or "safe_fixture" in metadata
        or "expected_shakerscan_findings" in metadata
    )




















def _deployment_gate_findings(findings: Any, *, minimum: str = "high", limit: int = 20) -> list[dict[str, Any]]:
    if not isinstance(findings, list):
        return []
    threshold = SEVERITY_ORDER.get(minimum, SEVERITY_ORDER["high"])
    selected: list[dict[str, Any]] = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        severity = str(finding.get("severity") or "info").lower()
        if SEVERITY_ORDER.get(severity, 0) < threshold:
            continue
        selected.append({
            "id": finding.get("id") or finding.get("source_finding_id"),
            "fingerprint": finding.get("fingerprint"),
            "title": finding.get("title"),
            "severity": severity,
            "tool": finding.get("tool"),
            "url": finding.get("url"),
        })
    selected.sort(key=lambda item: SEVERITY_ORDER.get(str(item.get("severity")), 0), reverse=True)
    return selected[:limit]


def _deployment_gate_required_evidence_missing(
    result: dict[str, Any], product: str, *, strict_model_intake: bool = False
) -> list[dict[str, Any]]:
    missing: list[dict[str, Any]] = []
    if product == "dast":
        meta = result.get("scan_metadata") if isinstance(result.get("scan_metadata"), dict) else {}
        result_block = result.get("result") if isinstance(result.get("result"), dict) else {}
        incomplete = bool(
            result.get("technical_outcome") == "INCOMPLETE"
            or meta.get("partial")
            or meta.get("degraded")
            or meta.get("grade_reliable") is False
            or result_block.get("grade_reliable") is False
        )
        if incomplete:
            missing.append({
                "id": "dast_complete_execution",
                "label": "Complete DAST execution",
                "status": "incomplete",
            })
    elif product == "ai_gate":
        ai_gate = result.get("ai_gate") if isinstance(result.get("ai_gate"), dict) else {}
        execution_plan = ai_gate.get("execution_plan") if isinstance(ai_gate.get("execution_plan"), dict) else {}
        quality_gate = execution_plan.get("judging_quality_gate") if isinstance(execution_plan.get("judging_quality_gate"), dict) else {}
        if quality_gate.get("judging_required") and not quality_gate.get("judging_completed"):
            missing.append({
                "id": "semantic_judging",
                "label": "Semantic judging",
                "status": quality_gate.get("status") or "judging_required",
            })
    elif product == "model_intake":
        model_intake = result.get("model_intake") if isinstance(result.get("model_intake"), dict) else {}
        checks = model_intake.get("checks") if isinstance(model_intake.get("checks"), dict) else {}
        for key, value in checks.items():
            if value is False:
                missing.append({"id": str(key), "label": str(key).replace("_", " "), "status": "failed"})
            elif value is None and (strict_model_intake or key in {"signature_verification", "approval_evidence"}):
                # A strict policy profile promotes EVERY indeterminate intake check to
                # required evidence; the default only requires signature/approval.
                missing.append({"id": str(key), "label": str(key).replace("_", " "), "status": "missing"})
    return missing


def _model_intake_policy_anchor_missing(result: dict[str, Any], policy_profile: dict[str, Any]) -> list[dict[str, Any]]:
    if not bool(policy_profile.get("strict_model_intake")):
        return []
    required_ids = _str_list(_decode_json_value(policy_profile.get("required_trust_anchor_ids")))
    if not required_ids:
        return []
    model_intake = result.get("model_intake") if isinstance(result.get("model_intake"), dict) else {}
    summary = model_intake.get("summary") if isinstance(model_intake.get("summary"), dict) else {}
    if summary.get("signature_trusted_root") is True:
        return []
    verified = summary.get("signature_verified") or summary.get("signature_cryptographically_verified")
    return [{
        "id": "policy_required_trust_anchors",
        "label": "Policy-required trust anchors",
        "status": "untrusted" if verified else "missing",
        "required_trust_anchor_ids": required_ids,
        "policy_profile": policy_profile.get("name") or policy_profile.get("id"),
        "signature_trusted_root": summary.get("signature_trusted_root"),
        "signature_verification_status": summary.get("signature_verification_status"),
    }]


def _exception_hygiene_summary(
    exceptions: list[dict[str, Any]],
    applied_exceptions: list[dict[str, Any]],
    *,
    exceptions_disabled: bool = False,
) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    expiring_cutoff = now + timedelta(days=7)
    summary = {
        "total": len(exceptions),
        "applied_count": len(applied_exceptions),
        "profile_disables_exceptions": bool(exceptions_disabled),
        "expired": 0,
        "expiring_soon": 0,
        "missing_owner": 0,
        "missing_approver": 0,
        "missing_compensating_controls": 0,
        "missing_expiry": 0,
        "inactive_or_revoked": 0,
        "review_required": 0,
    }
    for item in exceptions:
        status = str(item.get("status") or item.get("decision") or "active").strip().lower()
        expires_at = _parse_iso_datetime(item.get("expires_at") or item.get("expiry"))
        weak = False
        if status not in {"active", "approved", "accepted_risk"}:
            summary["inactive_or_revoked"] += 1
            weak = True
        if expires_at is None:
            summary["missing_expiry"] += 1
            weak = True
        elif expires_at <= now or status == "expired":
            summary["expired"] += 1
            weak = True
        elif expires_at <= expiring_cutoff:
            summary["expiring_soon"] += 1
            weak = True
        if not item.get("owner"):
            summary["missing_owner"] += 1
            weak = True
        if not item.get("approved_by") and not item.get("approver"):
            summary["missing_approver"] += 1
            weak = True
        if not item.get("compensating_controls"):
            summary["missing_compensating_controls"] += 1
            weak = True
        if weak:
            summary["review_required"] += 1
    return summary




def _policy_profile_for_scan(
    scan: dict[str, Any],
    result: dict[str, Any],
    product: str,
    db_profiles: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    options = _sanitize_scan_options(scan.get("options")) if scan.get("options") is not None else {}
    raw_options = _decode_json_value(scan.get("options")) if scan.get("options") is not None else {}
    policy_profile = ""
    if isinstance(raw_options, dict):
        policy_profile = str(
            raw_options.get("policy_profile")
            or raw_options.get("ai_environment")
            or raw_options.get("environment")
            or ""
        ).strip().lower()
    if not policy_profile and product == "ai_gate":
        ai_gate = result.get("ai_gate") if isinstance(result.get("ai_gate"), dict) else {}
        decision = ai_gate.get("decision") if isinstance(ai_gate.get("decision"), dict) else {}
        policy_profile = str(decision.get("environment") or "").strip().lower()
    if not policy_profile and product == "model_intake":
        summary = (result.get("model_intake") or {}).get("summary") if isinstance(result.get("model_intake"), dict) else {}
        policy_profile = str((summary or {}).get("deployment_environment") or "").strip().lower()
    # A durable DB-backed policy profile (R4) for this environment/name overrides
    # the built-in defaults.
    db_profiles = db_profiles or {}
    db_match = db_profiles.get(policy_profile)
    if db_match is None and isinstance(raw_options, dict):
        requested = str(raw_options.get("policy_profile") or "").strip().lower()
        db_match = db_profiles.get(requested)
    if db_match:
        profile = dict(db_match)
        profile.setdefault("id", policy_profile or profile.get("environment") or "custom")
        profile["source"] = "db"
        return profile
    if policy_profile not in POLICY_PROFILES:
        policy_profile = "production" if product in {"ai_gate", "model_intake"} else "staging"
    profile = dict(POLICY_PROFILES[policy_profile])
    profile["id"] = policy_profile
    profile["source"] = "builtin"
    if isinstance(options, dict) and options.get("policy_profile"):
        profile["requested_profile"] = options.get("policy_profile")
    return profile


def _exception_records(
    scan: dict[str, Any],
    result: dict[str, Any],
    db_exceptions: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    # Requests, scanner output, and imported reports are evidence, not authority
    # sources. Only durable exception rows loaded by the API may weaken a gate.
    return [item for item in (db_exceptions or []) if isinstance(item, dict)]




def _active_exception_keys(exceptions: list[dict[str, Any]]) -> tuple[set[str], set[str]]:
    """Return the (finding_id, fingerprint) keys of currently-effective exceptions.

    An exception may be keyed on a concrete ``finding_id`` and/or a durable
    ``fingerprint`` (the registry accepts either). Both forms are honored so a
    fingerprint-scoped exception covers a matching finding even when its row id
    differs across scans.
    """
    now = datetime.now(timezone.utc)
    active_ids: set[str] = set()
    active_fingerprints: set[str] = set()
    for item in exceptions:
        finding_id = str(item.get("finding_id") or item.get("id") or "").strip()
        fingerprint = str(item.get("fingerprint") or "").strip()
        if not finding_id and not fingerprint:
            continue
        status = str(item.get("status") or item.get("decision") or "active").strip().lower()
        if status not in {"active", "approved", "accepted_risk"}:
            continue
        expires_at = _parse_iso_datetime(item.get("expires_at") or item.get("expiry"))
        if expires_at is None or expires_at <= now:
            continue
        if not item.get("approved_by") and not item.get("approver"):
            continue
        if finding_id:
            active_ids.add(finding_id)
        if fingerprint:
            active_fingerprints.add(fingerprint)
    return active_ids, active_fingerprints


def _apply_policy_exceptions(
    blocking_findings: list[dict[str, Any]],
    exceptions: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    active_ids, active_fingerprints = _active_exception_keys(exceptions)
    if not active_ids and not active_fingerprints:
        return blocking_findings, []
    remaining: list[dict[str, Any]] = []
    applied: list[dict[str, Any]] = []
    for finding in blocking_findings:
        finding_id = str(finding.get("id") or "")
        fingerprint = str(finding.get("fingerprint") or "")
        if (finding_id and finding_id in active_ids) or (
            fingerprint and fingerprint in active_fingerprints
        ):
            applied.append(finding)
        else:
            remaining.append(finding)
    return remaining, applied


def build_deployment_decision(
    scan: dict[str, Any],
    *,
    db_policy_profiles: dict[str, dict[str, Any]] | None = None,
    db_exceptions: list[dict[str, Any]] | None = None,
    target_active_findings: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    result = _decode_json_value(scan.get("result")) or {}
    run_kind = str(scan.get("run_kind") or "")
    scan_type = str(scan.get("scan_type") or "")
    product = "dast"
    policy_name = "dast-default-v1"
    raw_decision = "needs_review"
    rationale = "Scan has not completed or has no deployment decision."
    findings = result.get("findings") if isinstance(result, dict) else []

    product_for_policy = "dast"
    if run_kind in DEVICE_RUN_KINDS or (isinstance(result, dict) and result.get("device_posture")):
        product_for_policy = "device_posture"
    elif isinstance(result, dict) and (result.get("ai_gate") or run_kind.startswith("ai_")):
        product_for_policy = "ai_gate"
    elif isinstance(result, dict) and (result.get("model_intake") or run_kind == "model_intake"):
        product_for_policy = "model_intake"
    policy_profile = _policy_profile_for_scan(scan, result if isinstance(result, dict) else {}, product_for_policy, db_profiles=db_policy_profiles)

    if run_kind in DEVICE_RUN_KINDS or (isinstance(result, dict) and result.get("device_posture")):
        product = "device_posture"
        posture = result.get("device_posture") if isinstance(result.get("device_posture"), dict) else {}
        decision_obj = posture.get("decision") if isinstance(posture.get("decision"), dict) else {}
        raw_decision = str((decision_obj or {}).get("decision") or "needs_review")
        rationale = str((decision_obj or {}).get("rationale") or "Connected-device posture requires review.")
        policy_name = str((decision_obj or {}).get("policy_name") or policy_profile["name"])
    elif isinstance(result, dict) and (result.get("ai_gate") or run_kind.startswith("ai_")):
        product = "ai_gate"
        decision_obj = (result.get("ai_gate") or {}).get("decision") if isinstance(result.get("ai_gate"), dict) else {}
        raw_decision = str((decision_obj or {}).get("decision") or "needs_review")
        rationale = str((decision_obj or {}).get("rationale") or "AI Gate decision requires review.")
        policy_name = str((decision_obj or {}).get("policy_name") or policy_profile["name"])
    elif isinstance(result, dict) and (result.get("model_intake") or run_kind == "model_intake"):
        product = "model_intake"
        result_obj = result.get("result") if isinstance(result.get("result"), dict) else {}
        intake_decision = str(result_obj.get("decision") or "review")
        raw_decision = "needs_approval" if intake_decision == "review" else intake_decision
        rationale = str(result_obj.get("decision_reason") or "Model Intake decision requires review.")
        policy_name = policy_profile["name"]
    elif isinstance(result, dict) and scan.get("status") == "completed":
        blocking = _deployment_gate_findings(findings)
        if blocking:
            raw_decision = "block"
            rationale = f"{len(blocking)} high/critical finding(s) require a block before deploy."
        else:
            raw_decision = "allow"
            rationale = "No high/critical findings met the deployment block threshold."
        policy_name = f"{scan_type or 'scan'}-default-v1"

    if raw_decision == "review":
        raw_decision = "needs_approval"
    if raw_decision not in {"allow", "needs_approval", "needs_review", "block"}:
        raw_decision = "needs_review"

    missing = _deployment_gate_required_evidence_missing(
        result if isinstance(result, dict) else {},
        product,
        strict_model_intake=bool(policy_profile.get("strict_model_intake")),
    )
    if product == "model_intake" and isinstance(result, dict):
        missing.extend(_model_intake_policy_anchor_missing(result, policy_profile))
    if raw_decision == "allow" and missing:
        raw_decision = "needs_review"
        rationale = "Required deployment evidence is missing or incomplete."
    blocking_findings = _deployment_gate_findings(
        findings,
        minimum=str(policy_profile.get("minimum_block_severity") or "high"),
    )
    # A DAST deploy gate must reflect the TARGET's unresolved risk, not just this one
    # scan's result: an active critical/high from a prior scan that this run did not
    # re-detect still blocks deploy (fail-closed). Merge the target's active blocking
    # findings in, deduped by id/fingerprint, for the DAST product only (AI Gate and
    # Model Intake carry their own decision objects). Exceptions below still apply.
    if product == "dast" and target_active_findings:
        seen_keys = {str(f.get("id") or "") for f in blocking_findings if f.get("id")}
        seen_keys |= {str(f.get("fingerprint") or "") for f in blocking_findings if f.get("fingerprint")}
        for extra in _deployment_gate_findings(
            target_active_findings,
            minimum=str(policy_profile.get("minimum_block_severity") or "high"),
        ):
            fid = str(extra.get("id") or "")
            ffp = str(extra.get("fingerprint") or "")
            if (fid and fid in seen_keys) or (ffp and ffp in seen_keys):
                continue
            extra["from_target_active"] = True
            blocking_findings.append(extra)
            if fid:
                seen_keys.add(fid)
            if ffp:
                seen_keys.add(ffp)
    exceptions = _exception_records(scan, result if isinstance(result, dict) else {}, db_exceptions=db_exceptions)
    # A policy-scoped exception (non-null policy_id) only applies when the scan is
    # evaluated under that exact policy profile — so a lenient-policy waiver cannot
    # silently suppress the same finding under a stricter policy.
    active_profile_id = str(policy_profile.get("profile_id") or "").strip()
    exceptions = [
        exc for exc in exceptions
        if not str(exc.get("policy_id") or "").strip()
        or str(exc.get("policy_id")).strip() == active_profile_id
    ]
    exceptions_disabled = policy_profile.get("allow_active_exceptions", True) is False
    if exceptions_disabled:
        # The active policy profile forbids exception-based suppression: blocking
        # findings stay blocking no matter how many active exceptions cover them.
        applied_exceptions: list[dict[str, Any]] = []
    else:
        blocking_findings, applied_exceptions = _apply_policy_exceptions(blocking_findings, exceptions)
    exception_summary = _exception_hygiene_summary(
        exceptions,
        applied_exceptions,
        exceptions_disabled=exceptions_disabled,
    )
    if blocking_findings and raw_decision == "allow":
        raw_decision = "block"
        rationale = f"{len(blocking_findings)} finding(s) meet the {policy_profile['id']} block threshold."
    if raw_decision == "block" and not blocking_findings and applied_exceptions:
        raw_decision = "needs_approval"
        rationale = "Blocking findings are covered by active time-bound policy exceptions."

    return {
        "scan_id": str(scan.get("id")),
        "status": scan.get("status"),
        "decision": raw_decision,
        "product": product,
        "policy_name": policy_name,
        "policy_profile": policy_profile["id"],
        "rationale": rationale,
        "blocking_findings": blocking_findings,
        "applied_exceptions": applied_exceptions,
        "exceptions_disabled_by_profile": exceptions_disabled,
        "exception_summary": exception_summary,
        "expired_or_invalid_exceptions": max(0, len(exceptions) - len(applied_exceptions)),
        "required_evidence_missing": missing,
        "score": scan.get("score") or (result.get("result") or {}).get("score") if isinstance(result, dict) else scan.get("score"),
        "grade": scan.get("grade") or (result.get("result") or {}).get("grade") if isinstance(result, dict) else scan.get("grade"),
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=int(policy_profile.get("expires_days") or 30))).isoformat(),
    }
































# Edge types that are pure structural plumbing (endpoint enumeration). They
# dominate edge volume and carry no exposure signal, so they are collapsed out
# of the rendered subgraph unless endpoints are explicitly requested.














































# ============================================================
# OWNED FLEET FOUNDATION
# ============================================================





























































































































# ============================================================
# HEALTH & INFO
# ============================================================

@app.get("/")
async def root():
    """API info."""
    return {
        "name": "ShakerScan API",
        "version": "1.0.0",
        "docs": "/docs",
        "endpoints": {
            "scans": "/scans",
            "targets": "/targets",
            "fleet_nodes": "/fleet/nodes",
            "ai_targets": "/ai/targets",
            "ai_inventory": "/ai/inventory",
            "ai_test_scenarios": "/ai/test-scenarios",
            "ai_learning_guide": "/ai/learning-guide",
            "ai_test_cases": "/ai/test-cases",
            "model_intake": "/model-intake/scan",
            "model_intake_resolve": "/model-intake/resolve",
            "findings": "/findings",
            "discovery": "/discovery",
            "exposure_graph": "/exposure/graph",
            "dashboard": "/dashboard",
            "queue": "/queue/stats"
        }
    }






def _hash_source_files(file_map: dict) -> Optional[str]:
    """Hash runtime source files keyed by logical name (basename), stable order.

    Immutable build identity that detects drift even when GIT_COMMIT is unset:
    keyed by basename so the API (hashing the host checkout) and a worker (hashing
    /app) yield the SAME checksum when the code matches, and differ when it doesn't.
    """
    import hashlib
    h = hashlib.sha256()
    hashed = 0
    for name in sorted(file_map):
        try:
            with open(file_map[name], "rb") as fh:
                h.update(name.encode())
                h.update(b"\0")
                h.update(fh.read())
            hashed += 1
        except OSError:
            continue
    return h.hexdigest()[:16] if hashed else None


def expected_build_fingerprint() -> Optional[str]:
    """Source checksum of the CURRENT checkout (host bind-mount at /workspace),
    falling back to the API's own /app runtime. This is the 'current build' the UI
    compares each scan's / worker's reported fingerprint against."""
    # Must match (by basename) scanner.SCANNER_FINGERPRINT_FILES and the worker's
    # report set, including worker.py and the output-shaping modules, so a worker
    # running stale orchestration/output code is not reported as build_current.
    workspace_fingerprint = hash_source_files(source_file_map(), require_all=True)
    if workspace_fingerprint:
        return release_build_fingerprint(workspace_fingerprint)
    return release_build_fingerprint(hash_source_files(runtime_file_map(), require_all=True))


def _git_head(repo: str = "/workspace") -> Optional[str]:
    """Resolve the complete commit of a mounted checkout without a git binary."""
    try:
        git_dir = os.path.join(repo, ".git")
        head = open(os.path.join(git_dir, "HEAD")).read().strip()
        if head.startswith("ref:"):
            ref = head.split(" ", 1)[1].strip()
            loose = os.path.join(git_dir, ref)
            if os.path.exists(loose):
                return open(loose).read().strip()
            packed = os.path.join(git_dir, "packed-refs")
            if os.path.exists(packed):
                for line in open(packed):
                    line = line.strip()
                    if line and not line.startswith(("#", "^")) and line.endswith(ref):
                        return line.split()[0]
            return None
        return head if len(head) >= 7 else None
    except Exception:
        return None


def _git_head_short(repo: str = "/workspace") -> Optional[str]:
    head = _git_head(repo)
    return head[:7] if head else None


def current_source_revision() -> str:
    """Return the immutable full source revision represented by this runtime."""
    identity = load_release_identity()
    if identity.image_built:
        return identity.source_revision
    return str(os.environ.get("GIT_COMMIT") or _git_head() or identity.source_revision or "unknown")


def current_scanner_version() -> str:
    """Human build label used by API/workers to detect mixed deployments.

    Official images use the immutable image-layer release manifest. Development
    images retain the live-checkout commit fallback needed by bind-mounted source.
    """
    return published_scanner_version(
        # scanner.sh stamps one deployment label across the images. Prefer it over the live
        # workspace HEAD so a uniformly rebuilt dirty snapshot stays uniformly labelled.
        os.environ.get("SCANNER_VERSION")
        or os.environ.get("GIT_COMMIT")
        or _git_head_short()
        or "dev"
    )


def _publish_scanner_version() -> str:
    """Publish the authoritative release or development build label to Redis."""
    v = current_scanner_version()
    try:
        get_redis().set("shakerscan:scanner_version", v, ex=120)
    except Exception:
        pass
    return v


def worker_build_current(
    *,
    reported_fingerprint: Optional[str],
    reported_version: Optional[str],
    expected_fingerprint: Optional[str],
    expected_version: Optional[str],
) -> Optional[bool]:
    """Return whether a worker matches the API's current runtime identity.

    The source fingerprint catches most code changes, but it is deliberately a
    curated file set. The git/version label catches commits outside that set and
    prevents old scaled-out workers from being reported current after rebuilds.
    """
    if not reported_fingerprint and not reported_version:
        return None
    fingerprint_ok = (
        reported_fingerprint == expected_fingerprint
        if reported_fingerprint and expected_fingerprint
        else None
    )
    version_ok = (
        reported_version == expected_version
        if reported_version and expected_version
        else None
    )
    # The source fingerprint is the authoritative currency signal — it now covers
    # every detection/orchestration module. The git version label is volatile (it
    # is the real commit, and workers snapshot the published value once at startup),
    # so a current worker that snapshotted a slightly older label would look falsely
    # stale if version had to match too. Trust the fingerprint when we have it; fall
    # back to the version label only when no fingerprint is reported.
    if fingerprint_ok is not None:
        return fingerprint_ok
    return version_ok


def _worker_freshness_snapshot() -> dict:
    """Fleet build-freshness snapshot for scan-submit guards/metadata (§2).

    Returns fleet_size, running, stale/pending counts, stale/pending names, and
    the expected build fingerprint. Best-effort: when Docker/Redis are unavailable,
    returns available=False so callers fail open (never block a scan on missing
    telemetry).
    """
    snap = {
        "available": False,
        "fleet_size": 0,
        "running": 0,
        "current_count": 0,
        "stale_count": 0,
        "stale_names": [],
        "pending_count": 0,
        "pending_names": [],
        "expected_build_fingerprint": expected_build_fingerprint(),
    }
    try:
        filters = urllib.parse.quote('{"name":["worker"]}')
        status, containers = docker_socket_request(
            "GET", f"/containers/json?all=true&filters={filters}")
        if status != 200 or not isinstance(containers, list):
            return snap
        expected_fp = snap["expected_build_fingerprint"]
        expected_version = current_scanner_version()
        try:
            wb_raw = get_redis().hgetall("shakerscan:worker_build") or {}
        except Exception:
            wb_raw = {}
        wb: dict = {}
        for host, raw in wb_raw.items():
            hs = host.decode() if isinstance(host, bytes) else str(host)
            rs = raw.decode() if isinstance(raw, bytes) else raw
            try:
                wb[hs.lower()] = json.loads(rs)
            except Exception:
                continue

        def _bfc(cid: str):
            cid = (cid or "").lower()
            for hs, info in wb.items():
                if hs and cid.startswith(hs):
                    return info
            return None

        compose_project = _local_compose_project_best_effort()
        if not compose_project:
            return snap
        snap["available"] = True
        for c in containers:
            names = c.get("Names", [])
            name = names[0].lstrip("/") if names else ""
            if not _is_local_scan_worker_container(c, compose_project=compose_project):
                continue
            snap["fleet_size"] += 1
            is_running = c.get("State") == "running"
            if is_running:
                snap["running"] += 1
            else:
                continue
            info = _bfc(c.get("Id", "")) or {}
            cur = worker_build_current(
                reported_fingerprint=info.get("build_fingerprint"),
                reported_version=info.get("scanner_version"),
                expected_fingerprint=expected_fp,
                expected_version=expected_version,
            )
            if cur is False:
                snap["stale_count"] += 1
                snap["stale_names"].append(name)
            elif cur is None:
                snap["pending_count"] += 1
                snap["pending_names"].append(name)
            else:
                snap["current_count"] += 1
    except Exception:
        pass
    return snap


_WORKER_BUILD_REPORT_MAX_AGE_SECONDS = 120
_WORKER_BUILD_REPORT_CLOCK_SKEW_SECONDS = 30


def _worker_build_report_summary(
    raw_reports: Any,
    *,
    expected_fingerprint: Optional[str],
    expected_version: Optional[str],
    expected_count: Optional[int] = None,
    now: Optional[datetime] = None,
) -> dict[str, Any]:
    """Summarize worker-authored build heartbeats against an external fleet denominator.

    This is display telemetry for /health, not the benchmark/submit authority. Freshness prevents
    stopped-container hash entries from poisoning the sidebar forever; expected_count prevents a
    silent or busy worker from disappearing and making a partial fleet look uniform.
    """
    current_time = now or datetime.now(timezone.utc)
    if current_time.tzinfo is None:
        current_time = current_time.replace(tzinfo=timezone.utc)
    reports: list[dict[str, Any]] = []
    for raw in (raw_reports or {}).values():
        value = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw
        try:
            report = json.loads(value) if isinstance(value, str) else dict(value)
            reported_at = datetime.fromisoformat(str(report.get("reported_at") or "").replace("Z", "+00:00"))
            if reported_at.tzinfo is None:
                reported_at = reported_at.replace(tzinfo=timezone.utc)
            age = (current_time - reported_at.astimezone(timezone.utc)).total_seconds()
            if -_WORKER_BUILD_REPORT_CLOCK_SKEW_SECONDS <= age <= _WORKER_BUILD_REPORT_MAX_AGE_SECONDS:
                reports.append(report)
        except (TypeError, ValueError, json.JSONDecodeError):
            continue

    current_count = 0
    stale_count = 0
    pending_count = 0
    for report in reports:
        state = worker_build_current(
            reported_fingerprint=report.get("build_fingerprint"),
            reported_version=report.get("scanner_version"),
            expected_fingerprint=expected_fingerprint,
            expected_version=expected_version,
        )
        if state is True:
            current_count += 1
        elif state is False:
            stale_count += 1
        else:
            pending_count += 1
    normalized_expected = max(0, int(expected_count)) if expected_count is not None else None
    count_gap = abs(normalized_expected - len(reports)) if normalized_expected is not None else 0
    pending_count += count_gap
    uniform = (
        bool(reports)
        and normalized_expected is not None
        and len(reports) == normalized_expected
        and stale_count == 0
        and pending_count == 0
    )
    return {
        "available": bool(reports) or bool(normalized_expected),
        "expected_count": normalized_expected,
        "reported_count": len(reports),
        "current_count": current_count,
        "stale_count": stale_count,
        "pending_count": pending_count,
        "fleet_uniform": uniform,
        # Labels are presentation only. When fingerprints prove uniformity, use the API's expected
        # label instead of comparing volatile worker snapshots as if they were safety authority.
        "scanner_version": expected_version if uniform else None,
    }


def _orphaned_worker_build_report_hosts(
    report_hosts: Any,
    running_container_ids: Any,
) -> list[str]:
    """Return worker-report hash fields that do not map to a live scan worker."""
    live_ids = [str(value or "").lower() for value in (running_container_ids or []) if value]
    return [
        str(host or "").lower()
        for host in (report_hosts or [])
        if host and not any(container_id.startswith(str(host).lower()) for container_id in live_ids)
    ]


def _live_worker_build_reports(raw_reports: Any, running_local_ids: Optional[list[str]]) -> dict[Any, Any]:
    """Drop superseded local-container reports while retaining remote-node reports."""
    if running_local_ids is None:
        return dict(raw_reports or {})
    live_ids = [str(value or "").lower() for value in running_local_ids if value]
    filtered: dict[Any, Any] = {}
    for host, raw in (raw_reports or {}).items():
        host_text = host.decode("utf-8", "replace") if isinstance(host, bytes) else str(host)
        value = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw
        try:
            report = json.loads(value) if isinstance(value, str) else dict(value)
        except (TypeError, ValueError, json.JSONDecodeError):
            report = {}
        if report.get("node_id") or any(container_id.startswith(host_text.lower()) for container_id in live_ids):
            filtered[host] = raw
    return filtered


@app.get("/health")
async def health():
    """Health check."""
    expected_fingerprint = expected_build_fingerprint()
    expected_version = current_scanner_version()
    expected_remote_workers: Optional[int] = None
    action_budget_reconciliation: dict[str, Any] = {
        "status": "unavailable",
        "inconsistent_count": 0,
    }
    legacy_compatibility = compatibility_snapshot(None)
    try:
        async with db_pool.acquire() as conn:
            await conn.fetchval("SELECT 1")
            try:
                action_budget_reconciliation = (
                    await scan_action_budget_reconciliation(conn)
                )
            except Exception:
                action_budget_reconciliation = {
                    "status": "unavailable",
                    "inconsistent_count": 0,
                }
            try:
                expected_remote_workers = int(await conn.fetchval(
                    """
                    SELECT COALESCE(SUM(active_worker_count), 0)
                    FROM nodes
                    WHERE status <> 'disabled'
                      AND last_heartbeat_at >= NOW() - ($1::int * INTERVAL '1 second')
                      AND COALESCE(labels->>'transport', 'overlay') <> 'broker'
                    """,
                    max(60, _int_env("FLEET_HEARTBEAT_TIMEOUT_SECONDS", HEARTBEAT_TIMEOUT_MINUTES * 60)),
                ) or 0)
            except Exception:
                expected_remote_workers = None
        db_ok = True
    except Exception:
        db_ok = False

    running_local_worker_ids = await asyncio.to_thread(_running_scan_worker_container_ids_best_effort)
    expected_local_workers = len(running_local_worker_ids) if running_local_worker_ids is not None else None
    expected_worker_count = (
        (expected_local_workers or 0) + (expected_remote_workers or 0)
        if expected_local_workers is not None or expected_remote_workers is not None
        else None
    )

    try:
        r = get_redis()
        r.ping()
        redis_ok = True
        legacy_compatibility = compatibility_snapshot(r)
        worker_build = _worker_build_report_summary(
            _live_worker_build_reports(
                r.hgetall("shakerscan:worker_build") or {},
                running_local_worker_ids,
            ),
            expected_fingerprint=expected_fingerprint,
            expected_version=expected_version,
            expected_count=expected_worker_count,
        )
    except Exception:
        redis_ok = False
        worker_build = _worker_build_report_summary(
            {},
            expected_fingerprint=expected_fingerprint,
            expected_version=expected_version,
            expected_count=expected_worker_count,
        )

    artifact_storage = await asyncio.to_thread(
        artifact_storage_health,
        results_dir=RESULTS_DIR,
        write_probe=False,
    )
    artifacts_ok = artifact_storage.get("status") != "error"

    return {
        "status": (
            "healthy"
            if db_ok and redis_ok and artifacts_ok
            and action_budget_reconciliation.get("status") != "degraded"
            else "degraded"
        ),
        "database": "ok" if db_ok else "error",
        "redis": "ok" if redis_ok else "error",
        "artifact_storage": artifact_storage,
        # Current build identity. scanner_version is the human label (git short sha
        # when set, else "dev"); build_fingerprint is a source-tree checksum that
        # differs whenever the runtime code differs — so the UI can flag a scan or
        # worker on a stale image even when scanner_version is "dev" on both.
        "scanner_version": expected_version,
        "source_revision": current_source_revision(),
        "build_fingerprint": expected_fingerprint,
        "worker_build": worker_build,
        "scan_action_budget_reconciliation": action_budget_reconciliation,
        "legacy_compatibility": legacy_compatibility,
        "device_worker": _device_worker_readiness(),
        "agent_tool_worker": _agent_tool_worker_readiness(),
        "fleet": fleet_feature_state(),
    }


@app.get("/metrics/v2")
async def get_v2_operational_metrics():
    """Expose content-free canonical runtime counters and actionable alerts."""
    running_worker_ids = await asyncio.to_thread(
        _running_scan_worker_container_ids_best_effort
    )
    try:
        redis_client = get_redis()
        raw_reports = _live_worker_build_reports(
            redis_client.hgetall("shakerscan:worker_build") or {},
            running_worker_ids,
        )
    except Exception:
        redis_client = None
        raw_reports = {}
    worker_build = _worker_build_report_summary(
        raw_reports,
        expected_fingerprint=expected_build_fingerprint(),
        expected_version=current_scanner_version(),
        expected_count=(
            len(running_worker_ids) if running_worker_ids is not None else None
        ),
    )
    legacy = compatibility_snapshot(redis_client)
    async with db_pool.acquire() as conn:
        try:
            reconciliation = await scan_action_budget_reconciliation(conn)
        except Exception:
            reconciliation = {
                "status": "unavailable",
                "inconsistent_count": 0,
            }
        metrics = await scan_operational_metrics(
            conn,
            redis_client=redis_client,
            reconciliation=reconciliation,
            worker_fingerprint_mismatches=(
                int(worker_build.get("stale_count") or 0)
                + int(worker_build.get("pending_count") or 0)
            ),
            legacy_compatibility_calls=int(legacy.get("total_calls") or 0),
        )
    metrics["worker_build"] = worker_build
    metrics["legacy_compatibility"] = legacy
    return metrics
























# ============================================================
# MODEL INTAKE
# ============================================================



















































def _model_intake_json_object(value: Any) -> dict[str, Any]:
    decoded = _decode_json_value(value)
    return decoded if isinstance(decoded, dict) else {}




















def _model_intake_attention_items(static_payload: Any) -> list[dict[str, Any]]:
    """Merge duplicate AST/Semgrep observations into useful review items."""
    payload = _model_intake_json_object(static_payload)
    merged: dict[str, dict[str, Any]] = {}
    for scanner in payload.get("scanner_results") or []:
        if not isinstance(scanner, dict):
            continue
        scanner_name = str(scanner.get("name") or "scanner")
        for finding in scanner.get("findings") or []:
            if not isinstance(finding, dict):
                continue
            path = str(finding.get("path") or "")
            line = finding.get("line") if isinstance(finding.get("line"), int) else None
            finding_id = str(finding.get("id") or finding.get("rule_id") or "finding")
            key = f"{path}:{line}" if path and line else finding_id
            title = str(
                finding.get("message") or finding.get("call")
                or finding_id.replace("_", " ")
            )
            if finding_id == "license_file_missing":
                title = "Repository has no license or NOTICE source file; the publisher declaration is recorded separately."
            current = merged.setdefault(key, {
                "title": title[:500], "severity": str(finding.get("severity") or "review"),
                "path": path or None, "line": line, "scanners": [],
            })
            if finding.get("message"):
                current["title"] = title[:500]
            if scanner_name not in current["scanners"]:
                current["scanners"].append(scanner_name)
    return list(merged.values())[:20]





























def _model_intake_automatic_control_statuses(
    records: list[dict[str, Any]],
) -> dict[str, str]:
    """Project evidence records into user-facing, decision-specific controls.

    Runner receipt ``status`` is intentionally conservative: containment,
    signer trust, resource telemetry, and the actual model operation can all
    make it fail.  Reusing that aggregate status for every named control tells
    an operator that conversion or inference failed when those operations may
    have succeeded.  This projection keeps every failure blocking while naming
    the control that actually failed.
    """
    output: dict[str, str] = {}
    rank = {
        "PASS": 0,
        "NOT_APPLICABLE": 0,
        "WARNING": 1,
        "REVIEW": 1,
        "REVIEW_REQUIRED": 1,
        "INCOMPLETE": 2,
        "UNSUPPORTED": 2,
        "TIMEOUT": 3,
        "ERROR": 3,
        "CRASHED": 4,
        "FAIL": 4,
    }

    def record(control: str, status: str) -> None:
        normalized = str(status or "INCOMPLETE").upper()
        current = output.get(control)
        if current is None or rank.get(normalized, 2) > rank.get(current, 2):
            output[control] = normalized

    for item in records:
        evidence_type = str(item.get("evidence_type") or "")
        raw_status = str(item.get("status") or "INCOMPLETE").upper()
        if evidence_type not in {"conversion_equivalence", "runtime_execution"}:
            record(evidence_type, raw_status)
            continue
        envelope = _model_intake_json_object(item.get("signature_envelope"))
        payload = _model_intake_untrusted_runner_claims(envelope)
        observations = _model_intake_json_object(payload.get("observations"))
        phases = _model_intake_json_object(observations.get("phases"))
        phase_pass = bool(phases) and all(
            str(value.get("status") if isinstance(value, dict) else value).upper() == "PASS"
            for value in phases.values()
        )
        if evidence_type == "conversion_equivalence":
            record(
                evidence_type,
                "PASS" if _model_intake_conversion_output_usable(payload) else raw_status,
            )
        else:
            execution_pass = observations.get("status") == "PASS" and phase_pass
            record(evidence_type, "PASS" if execution_pass else raw_status)

        network = _model_intake_json_object(observations.get("network_telemetry"))
        attempt_count = network.get("attempt_count")
        lost_events = network.get("lost_events")
        firewall_drops = network.get("host_firewall_drop_count")
        if any(
            isinstance(value, int) and not isinstance(value, bool) and value > 0
            for value in (attempt_count, firewall_drops)
        ):
            network_status = "FAIL"
        elif (
            network.get("complete") is True
            and network.get("no_network_device") is True
            and network.get("overflowed") is False
            and attempt_count == 0
            and lost_events == 0
            and firewall_drops == 0
        ):
            network_status = "PASS"
        else:
            network_status = "INCOMPLETE"
        record("network_isolation", network_status)
        resources = _model_intake_json_object(observations.get("resource_telemetry"))
        record("resource_envelope", "PASS" if resources.get("complete") is True else "INCOMPLETE")
    return output















































































# Server-owned. The caller supplies no URL, digest, or path, so staging cannot be
# pointed at another host or made to write outside the results volume.










































































_MODEL_INTAKE_AUTO_TERMINAL_STATES = {
    "technical_review_complete", "attention_required", "failed", "cancelled",
}










async def _update_model_intake_automatic_review(
    conn: Any,
    review: Any,
    *,
    state: str,
    current_step: str,
    progress: int,
    event: str,
    technical_outcome: str | None = None,
    error: dict[str, Any] | None = None,
    pending_controls: list[dict[str, Any]] | None = None,
    fields: dict[str, Any] | None = None,
) -> None:
    timeline = _model_intake_auto_timeline(review["timeline_json"])
    timeline.append({
        "event": event,
        "state": state,
        "at": utc_now_iso(),
    })
    allowed = {
        "submission_id", "conversion_job_id", "calibration_job_id", "runtime_job_id",
        "deployment_bundle_json", "known_answer_embedding_sha256",
    }
    updates = {key: value for key, value in (fields or {}).items() if key in allowed}
    assignments = [
        "state=$2", "current_step=$3", "progress=$4", "technical_outcome=$5",
        "timeline_json=$6::jsonb", "error_json=$7::jsonb", "pending_controls=$8::jsonb",
        "updated_at=NOW()",
    ]
    args: list[Any] = [
        review["id"], state, current_step, max(0, min(progress, 100)), technical_outcome,
        json.dumps(timeline), json.dumps(error) if error else None,
        json.dumps(pending_controls or []),
    ]
    for key, value in updates.items():
        args.append(json.dumps(value) if key == "deployment_bundle_json" else value)
        cast = "::jsonb" if key == "deployment_bundle_json" else ""
        assignments.append(f"{key}=${len(args)}{cast}")
    if state in _MODEL_INTAKE_AUTO_TERMINAL_STATES:
        assignments.append("completed_at=COALESCE(completed_at,NOW())")
    await conn.execute(
        f"UPDATE model_intake_automatic_reviews SET {','.join(assignments)} WHERE id=$1",
        *args,
    )


def _model_intake_auto_embedding_bundle(
    authoritative: dict[str, Any],
    published: dict[str, Any],
) -> dict[str, Any]:
    bundle = dict(authoritative.get("deployment_bundle") or {})
    dimension = int(published.get("dimension") or 0)
    max_sequence_length = int(published.get("max_sequence_length") or 0)
    if dimension <= 0 or max_sequence_length <= 0:
        missing = []
        if dimension <= 0:
            missing.append("embedding dimension")
        if max_sequence_length <= 0:
            missing.append("maximum sequence length")
        raise ValueError("The pinned model revision does not publish " + " and ".join(missing))
    # These values describe the fixed ShakerScan guest harness, not a claimed
    # corporate serving configuration: the guest performs attention-mask mean
    # pooling, emits float32 vectors, and does not normalize them.
    bundle["embedding_configuration"] = {
        "dimension": dimension,
        "pooling": "attention-mask-mean",
        "normalization": False,
        "max_sequence_length": max_sequence_length,
        "precision": "float32",
    }
    bundle["retrieval_application_digest"] = None
    bundle["index_schema_digest"] = None
    return bundle


def _model_intake_auto_observed_embedding(job: dict[str, Any]) -> str | None:
    result = _model_intake_json_object(job.get("result_json"))
    payload = result.get("payload") if isinstance(result.get("payload"), dict) else {}
    observations = payload.get("observations") if isinstance(payload.get("observations"), dict) else {}
    digest = str(observations.get("embedding_output_sha256") or "").lower()
    return digest if re.fullmatch(r"[0-9a-f]{64}", digest) else None


async def _model_intake_auto_memory_mib(
    conn: Any,
    submission_id: str,
    bundle: dict[str, Any],
    *,
    operation: str,
) -> int:
    """Size a bounded guest for the exact artifact, without model allowlists."""
    if operation not in {"conversion", "calibration", "runtime"}:
        raise ValueError("unsupported automatic-review runner operation")
    artifact_sha = str(bundle.get("model_artifact_sha256") or "")
    size = await conn.fetchval(
        """SELECT size_bytes FROM model_intake_subjects
           WHERE submission_id=$1 AND subject_kind='artifact' AND sha256=$2
           ORDER BY created_at DESC LIMIT 1""",
        uuid.UUID(str(submission_id)),
        artifact_sha,
    )
    if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
        raise RuntimeError(
            "The exact model artifact size is unavailable; refusing to guess a Firecracker memory envelope. "
            "Reacquire the complete artifact and start a new review."
        )
    artifact_mib = math.ceil(size / (1024 * 1024))
    # Conversion and embedding equivalence transiently materialize the source
    # state dictionary, converted tensors, model parameters, and inference
    # buffers. Smaller conversion defaults proved insufficient for real
    # multi-gigabyte repositories. Calibration/runtime load only the converted
    # exact subject and do not retain both serialization forms, so carrying the
    # conversion multiplier into those jobs needlessly rejects an otherwise
    # safe 16 GiB runner. Every operation remains cgroup-enforced and fails
    # closed if its measured envelope is insufficient.
    artifact_multiplier = 4 if operation == "conversion" else 2
    requested = max(4096, 3072 + artifact_mib * artifact_multiplier)
    rounded = int(math.ceil(requested / 512) * 512)
    configured_cap_raw = os.getenv("MODEL_INTAKE_AUTO_MAX_MEMORY_MIB", "13312")
    try:
        configured_cap = max(4096, min(262144, int(configured_cap_raw)))
    except (TypeError, ValueError) as exc:
        raise RuntimeError(
            "MODEL_INTAKE_AUTO_MAX_MEMORY_MIB must be an integer number of MiB, "
            f"not {configured_cap_raw!r}."
        ) from exc
    if rounded > configured_cap:
        raise RuntimeError(
            "The exact model needs an estimated "
            f"{rounded} MiB Firecracker {operation} envelope, above this runner's automatic-review cap "
            f"of {configured_cap} MiB. Use a larger runner and raise "
            "MODEL_INTAKE_AUTO_MAX_MEMORY_MIB, then start a new review."
        )
    return rounded








async def _advance_model_intake_automatic_review(conn: Any, review: Any) -> None:
    """Advance exactly one durable step; every action is replay-safe at its state boundary."""
    state = str(review["state"])
    system_request = _model_intake_automatic_system_request()
    scan_id = review["scan_id"]
    if state == "static_scan_pending":
        scan = await conn.fetchrow(
            "SELECT id,status,target_url,result,error_message FROM scans WHERE id=$1",
            scan_id,
        )
        if not scan:
            raise RuntimeError("automatic review scan record disappeared")
        scan_status = str(scan["status"])
        if scan_status in {"pending", "queued", "running"}:
            return
        if scan_status != "completed":
            await _update_model_intake_automatic_review(
                conn, review, state="failed", current_step="static_scan", progress=100,
                event="static_scan_failed", technical_outcome="INCOMPLETE",
                error={"code": "static_scan_failed", "message": str(scan["error_message"] or scan_status)},
            )
            return
        result = _model_intake_json_object(scan["result"])
        intake = result.get("model_intake") if isinstance(result.get("model_intake"), dict) else {}
        summary = intake.get("summary") if isinstance(intake.get("summary"), dict) else {}
        artifact_sha = str(summary.get("sha256") or "").lower()
        submission_response = await create_model_intake_submission(
            ModelSubmissionRequest(
                source=str(scan["target_url"]),
                source_kind=str(review["source_kind"]),
                intended_environment=str(review["requested_environment"]),
                intended_use={
                    "workflow": "automatic_technical_review",
                    "runtime_contract": "shakerscan-fixed-embedding-harness/v1",
                },
                expected_artifact_sha256=artifact_sha if re.fullmatch(r"[0-9a-f]{64}", artifact_sha) else None,
                declared_metadata={"automatic_review_id": str(review["id"])},
            ),
            system_request,
        )
        submission_id = submission_response["submission"]["id"]
        await _update_model_intake_automatic_review(
            conn, review, state="static_evidence_pending", current_step="bind_static_evidence",
            progress=45, event="controlled_submission_created",
            fields={"submission_id": uuid.UUID(str(submission_id))},
        )
        return

    submission_id = str(review["submission_id"] or "")
    if not submission_id:
        raise RuntimeError("automatic review lost its controlled submission")
    if state == "static_evidence_pending":
        await attach_model_intake_static_run(
            submission_id,
            ModelSubmissionStaticRunRequest(scan_id=str(scan_id)),
            system_request,
        )
        await _update_model_intake_automatic_review(
            conn, review, state="runner_prepare", current_step="prepare_isolated_runtime",
            progress=55, event="static_evidence_bound",
        )
        return

    if state == "runner_prepare":
        readiness = await asyncio.to_thread(_model_intake_runner_readiness_snapshot)
        if readiness.get("ready") is not True or readiness.get("status") != "READY":
            # The runner or its bridge can restart independently of the durable
            # controller. Keep the review replayable through a short bounded
            # outage; a continuously unavailable runner still fails closed.
            if _model_intake_auto_runner_readiness_grace_active(review):
                return
            await _update_model_intake_automatic_review(
                conn, review, state="attention_required", current_step="microvm_unavailable",
                progress=100, event="microvm_unavailable", technical_outcome="INCOMPLETE",
                pending_controls=[{
                    "control": "isolated_runtime",
                    "status": "NOT_RUN",
                    "action": "Install or repair the Model Intake microVM runner, then start a new automatic review.",
                    "detail": (
                        f"Runner status {str(readiness.get('status') or 'NOT_READY')}: "
                        f"{str(readiness.get('unsupported_reason') or readiness.get('reason') or readiness.get('detail') or 'Firecracker/KVM runner is unavailable')[:400]}"
                    ),
                }],
            )
            return
        try:
            authoritative = await model_intake_runner_bundle(
                submission_id, system_request, operation="calibration"
            )
        except HTTPException as runtime_error:
            try:
                conversion = await model_intake_runner_bundle(
                    submission_id, system_request, operation="conversion"
                )
            except HTTPException:
                # runner-bundle performs its own readiness verification because
                # it is also a public API operation. If the runner disappeared
                # between the controller's probe and this call, retry from the
                # durable runner_prepare state instead of misclassifying a
                # transient outage as an unsupported model format.
                readiness_after_error = await asyncio.to_thread(
                    _model_intake_runner_readiness_snapshot
                )
                if (
                    readiness_after_error.get("ready") is not True
                    or readiness_after_error.get("status") != "READY"
                ):
                    return
                detail = runtime_error.detail
                message = (
                    str(detail.get("message") or detail.get("error") or detail)
                    if isinstance(detail, dict) else str(detail)
                )
                await _update_model_intake_automatic_review(
                    conn, review, state="attention_required",
                    current_step="runtime_profile_unavailable", progress=100,
                    event="runtime_profile_unavailable", technical_outcome="INCOMPLETE",
                    pending_controls=[{
                        "control": "isolated_runtime",
                        "status": "UNSUPPORTED",
                        "action": (
                            "ShakerScan has no fixed Firecracker loader/conversion profile for this exact "
                            "format and repository. Static reports and bills of materials remain useful, "
                            "but the model cannot pass runtime qualification in this release."
                        ),
                        "detail": message[:500],
                    }],
                )
                return
            published = await model_intake_embedding_configuration(submission_id, system_request)
            if not published.get("available"):
                raise ValueError("The pinned model revision does not publish a usable embedding contract")
            conversion_bundle = _model_intake_auto_embedding_bundle(conversion, published)
            memory_mib = await _model_intake_auto_memory_mib(
                conn, submission_id, conversion_bundle, operation="conversion",
            )
            if not await _model_intake_auto_runner_memory_ready(review, memory_mib):
                return
            response = await create_model_intake_runner_job(
                submission_id,
                ModelRunnerJobCreateRequest(
                    operation="conversion", deployment_bundle=conversion_bundle,
                    known_answer_inputs=[], vcpu_count=2, memory_mib=memory_mib,
                    timeout_seconds=1800,
                ),
                system_request,
            )
            await _update_model_intake_automatic_review(
                conn, review, state="conversion_running", current_step="convert_unsafe_serialization",
                progress=60, event="conversion_queued",
                fields={
                    "conversion_job_id": uuid.UUID(str(response["job"]["id"])),
                    "deployment_bundle_json": conversion_bundle,
                },
            )
            return
        published = await model_intake_embedding_configuration(submission_id, system_request)
        if not published.get("available"):
            raise ValueError("The pinned model revision does not publish a usable embedding contract")
        bundle = _model_intake_auto_embedding_bundle(authoritative, published)
        await _update_model_intake_automatic_review(
            conn, review, state="calibration_pending", current_step="calibrate_known_answers",
            progress=62, event="runtime_subjects_prepared",
            fields={"deployment_bundle_json": bundle},
        )
        return

    if state == "conversion_running":
        response = await refresh_model_intake_runner_job(
            submission_id, str(review["conversion_job_id"]), system_request
        )
        job = response["job"]
        if str(job.get("state")) in {"pending", "running"}:
            return
        if str(job.get("state")) != "completed":
            raise RuntimeError(str(
                _model_intake_json_object(job.get("error_json")).get("message")
                or "controlled conversion failed"
            ))
        rescan = response.get("conversion_rescan")
        next_subjects = (
            rescan.get("next_runtime_subjects") if isinstance(rescan, dict) else None
        )
        if not isinstance(next_subjects, dict) or not next_subjects.get("loader_profile_sha256"):
            raise RuntimeError("conversion completed without an equivalent, strictly rescanned runtime subject")
        published = await model_intake_embedding_configuration(submission_id, system_request)
        if not published.get("available"):
            raise ValueError("The pinned model revision does not publish a usable embedding contract")
        bundle = _model_intake_auto_embedding_bundle(
            {"deployment_bundle": {
                **next_subjects,
                "target_environment": str(review["requested_environment"]),
            }},
            published,
        )
        await _update_model_intake_automatic_review(
            conn, review, state="calibration_pending", current_step="calibrate_converted_model",
            progress=68, event="conversion_registered_and_rescanned",
            fields={"deployment_bundle_json": bundle},
        )
        return

    bundle = _model_intake_json_object(review["deployment_bundle_json"])
    if state == "calibration_pending":
        memory_mib = await _model_intake_auto_memory_mib(
            conn, submission_id, bundle, operation="calibration",
        )
        if not await _model_intake_auto_runner_memory_ready(review, memory_mib):
            return
        response = await create_model_intake_runner_job(
            submission_id,
            ModelRunnerJobCreateRequest(
                operation="calibration", deployment_bundle=bundle,
                known_answer_inputs=[], vcpu_count=1, memory_mib=memory_mib, timeout_seconds=900,
            ),
            system_request,
        )
        await _update_model_intake_automatic_review(
            conn, review, state="calibration_running", current_step="calibrate_known_answers",
            progress=70, event="calibration_queued",
            fields={
                "calibration_job_id": uuid.UUID(str(response["job"]["id"])),
                "deployment_bundle_json": bundle,
            },
        )
        return

    if state == "calibration_running":
        response = await refresh_model_intake_runner_job(
            submission_id, str(review["calibration_job_id"]), system_request
        )
        job = response["job"]
        if str(job.get("state")) in {"pending", "running"}:
            return
        if str(job.get("state")) != "completed":
            raise RuntimeError(str(_model_intake_json_object(job.get("error_json")).get("message") or "calibration failed"))
        digest = _model_intake_auto_observed_embedding(job)
        if not digest:
            raise RuntimeError("calibration completed without a bounded embedding digest")
        await _update_model_intake_automatic_review(
            conn, review, state="runtime_pending", current_step="verify_known_answers",
            progress=75, event="calibration_digest_recorded",
            fields={"known_answer_embedding_sha256": digest},
        )
        return

    if state == "runtime_pending":
        memory_mib = await _model_intake_auto_memory_mib(
            conn, submission_id, bundle, operation="runtime",
        )
        if not await _model_intake_auto_runner_memory_ready(review, memory_mib):
            return
        response = await create_model_intake_runner_job(
            submission_id,
            ModelRunnerJobCreateRequest(
                operation="runtime", deployment_bundle=bundle, known_answer_inputs=[],
                known_answer_embedding_sha256=str(review["known_answer_embedding_sha256"]),
                vcpu_count=1, memory_mib=memory_mib, timeout_seconds=900,
            ),
            system_request,
        )
        await _update_model_intake_automatic_review(
            conn, review, state="runtime_running", current_step="isolated_load_and_inference",
            progress=82, event="runtime_verification_queued",
            fields={"runtime_job_id": uuid.UUID(str(response["job"]["id"]))},
        )
        return

    if state == "runtime_running":
        response = await refresh_model_intake_runner_job(
            submission_id, str(review["runtime_job_id"]), system_request
        )
        job = response["job"]
        if str(job.get("state")) in {"pending", "running"}:
            return
        if str(job.get("state")) != "completed":
            raise RuntimeError(str(_model_intake_json_object(job.get("error_json")).get("message") or "runtime verification failed"))
        await _update_model_intake_automatic_review(
            conn, review, state="freeze_pending", current_step="freeze_technical_evidence",
            progress=92, event="runtime_verification_completed",
        )
        return

    if state == "freeze_pending":
        await freeze_model_intake_evidence(
            submission_id, ModelEvidenceFreezeRequest(deployment_bundle=bundle), system_request
        )
        evidence_rows = await conn.fetch(
            """SELECT DISTINCT ON (evidence_type) evidence_type,status,signature_envelope,payload_json
               FROM model_intake_evidence_records
               WHERE submission_id=$1
                 AND evidence_type IN (
                     'static_analysis','conversion_equivalence','runtime_execution',
                     'embedding_evaluation','data_plane_evaluation'
                 )
               ORDER BY evidence_type,created_at DESC""",
            uuid.UUID(submission_id),
        )
        evidence_status = _model_intake_automatic_control_statuses(
            [row_to_dict(item) for item in evidence_rows]
        )
        observed = set(evidence_status.values())
        if observed.intersection({"FAIL", "CRASHED"}):
            technical_outcome = "BLOCK"
        elif observed.intersection({"INCOMPLETE", "UNSUPPORTED", "TIMEOUT"}):
            technical_outcome = "INCOMPLETE"
        elif "WARNING" in observed:
            technical_outcome = "REVIEW_REQUIRED"
        else:
            technical_outcome = "PASS"
        pending = _model_intake_present_pending_controls([
            {
                "control": evidence_type,
                "status": status,
                "action": (
                    "Review the recorded evidence and resolve or rerun this technical check."
                ),
                **(
                    {
                        "summary": "Static analysis found items that need review.",
                        "items": _model_intake_attention_items(next(
                            (
                                item.get("payload_json") for item in map(row_to_dict, evidence_rows)
                                if str(item.get("evidence_type") or "") == "static_analysis"
                            ),
                            {},
                        )),
                    }
                    if evidence_type == "static_analysis" else {}
                ),
            }
            for evidence_type, status in sorted(evidence_status.items())
            if status != "PASS"
        ] + [
            {
                "control": "deployment_follow_up",
                "status": "OUTSIDE_REVIEW",
                "action": (
                    "Before deployment, confirm publisher trust, production signing, application/data-plane "
                    "controls, and any organization-required approvals."
                ),
            },
        ])
        await _update_model_intake_automatic_review(
            conn, review, state="technical_review_complete", current_step="review_results",
            progress=100, event="technical_evidence_frozen",
            technical_outcome=technical_outcome, pending_controls=pending,
        )


async def advance_model_intake_automatic_reviews(pool: asyncpg.Pool) -> None:
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT * FROM model_intake_automatic_reviews
            WHERE state <> ALL($1::text[])
            ORDER BY updated_at ASC LIMIT 8
            """,
            sorted(_MODEL_INTAKE_AUTO_TERMINAL_STATES),
        )
    for candidate in rows:
        async with pool.acquire() as conn, conn.transaction():
            locked = await conn.fetchval(
                "SELECT pg_try_advisory_xact_lock(hashtextextended($1::text,0))",
                str(candidate["id"]),
            )
            if not locked:
                continue
            review = await conn.fetchrow(
                "SELECT * FROM model_intake_automatic_reviews WHERE id=$1",
                candidate["id"],
            )
            if not review or str(review["state"]) in _MODEL_INTAKE_AUTO_TERMINAL_STATES:
                continue
            try:
                await _advance_model_intake_automatic_review(conn, review)
            except Exception as exc:
                logger.exception("Automatic Model Intake review %s failed", review["id"])
                await _update_model_intake_automatic_review(
                    conn, review, state="attention_required", current_step=str(review["current_step"]),
                    progress=100, event="automatic_step_failed", technical_outcome="INCOMPLETE",
                    error={"code": type(exc).__name__, "message": str(exc)[:2000]},
                    pending_controls=[{
                        "control": str(review["current_step"]), "status": "INCOMPLETE",
                        "action": "Review the recorded error, repair the prerequisite, and start a new automatic review.",
                    }],
                )


async def model_intake_automatic_review_runner(pool: asyncpg.Pool) -> None:
    print("[model-intake-auto] Automatic review controller started", flush=True)
    while True:
        try:
            await advance_model_intake_automatic_reviews(pool)
            await asyncio.sleep(5)
        except asyncio.CancelledError:
            print("[model-intake-auto] Automatic review controller stopped", flush=True)
            break
        except Exception as exc:
            logger.exception("Automatic Model Intake controller error: %s", exc)
            await asyncio.sleep(5)






















# ============================================================
# CONNECTED DEVICES
# ============================================================











































































































































# ============================================================
# AI GATE TARGETS
# ============================================================





































# ============================================================
# DASHBOARD
# ============================================================

















































# Action priority tiers, so the triage queue ranks the genuinely urgent few
# instead of flagging the majority of assets with an undifferentiated boolean.
















# ============================================================
# SCANS
# ============================================================

def _fleet_node_placement_labels(row: Any, _placement: dict[str, Any]) -> dict[str, Any]:
    raw_labels = row.get("labels") or {}
    if isinstance(raw_labels, str):
        try:
            raw_labels = json.loads(raw_labels)
        except json.JSONDecodeError:
            raw_labels = {}
    labels = dict(raw_labels) if isinstance(raw_labels, dict) else {}
    labels["node_id"] = str(row.get("id") or "").lower()
    labels["node_scope"] = "remote"
    if row.get("region"):
        labels["region"] = str(row.get("region"))
    # The standard image guarantees this baseline. Custom images must advertise
    # additional capabilities explicitly so admission never invents a requested tool.
    if "tools" not in labels and "capabilities" not in labels:
        labels["tools"] = sorted(DEFAULT_WORKER_TOOL_COMMANDS)
    if "budget_profiles" not in labels:
        labels["budget_profiles"] = sorted(SCAN_BUDGET_PROFILES)
    return labels


def _local_worker_placement_labels() -> dict[str, Any]:
    """Placement identity guaranteed by the bundled control-plane worker image."""
    return {
        "node_id": "local",
        "node_scope": "local",
        "transport": "local",
        "tools": sorted(DEFAULT_WORKER_TOOL_COMMANDS),
        "budget_profiles": sorted(SCAN_BUDGET_PROFILES),
    }


async def _require_reachable_fleet_placement(conn: Any, placement: dict[str, Any]) -> None:
    normalized = normalize_placement(placement)
    if not normalized:
        return
    local_workers = _current_scan_worker_count_best_effort()
    if (
        local_workers is not None
        and local_workers > 0
        and worker_matches_placement(_local_worker_placement_labels(), normalized)
    ):
        return
    stale_after = max(60, _int_env("FLEET_HEARTBEAT_TIMEOUT_SECONDS", HEARTBEAT_TIMEOUT_MINUTES * 60))
    rows = await conn.fetch(
        """
        SELECT id, region, labels
        FROM nodes
        WHERE status <> 'disabled'
          AND COALESCE(drain, false) = false
          AND COALESCE(active_worker_count, 0) > 0
          AND last_heartbeat_at >= NOW() - ($1::int * INTERVAL '1 second')
        ORDER BY created_at ASC
        """,
        stale_after,
    )
    if any(
        worker_matches_placement(_fleet_node_placement_labels(row, normalized), normalized)
        for row in rows
    ):
        return
    raise HTTPException(
        status_code=422,
        detail={
            "error": "unreachable_fleet_placement",
            "message": "No enrolled fleet node can satisfy every requested placement constraint.",
            "placement": normalized,
            "hint": "Join or relabel a matching node, or change the Fleet Placement constraints.",
        },
    )


async def _mark_scan_enqueue_failed(scan_id: str, message: str, command_result_id: Any = None) -> None:
    try:
        async with db_pool.acquire() as conn:
            await conn.execute(
                """
                UPDATE scans
                SET status='failed', error_message=$1, completed_at=NOW()
                WHERE id=$2 AND status='pending'
                """,
                message[:1000],
                uuid.UUID(scan_id),
            )
            if command_result_id:
                await conn.execute(
                    """
                    UPDATE command_results
                    SET status='failed', operator_message=$1
                    WHERE id=$2
                    """,
                    message[:1000],
                    uuid.UUID(str(command_result_id)),
                )
    except Exception:
        logger.exception("Failed to persist enqueue failure for scan %s", scan_id)








def _route_capacity_http_exception(exc: RouteCapacityExceeded) -> HTTPException:
    return HTTPException(
        status_code=429,
        detail={
            "error": "fleet_route_capacity_exceeded",
            "message": (
                f"Fleet placement route capacity ({exc.limit}) is currently exhausted; "
                "existing routed work must drain or be cleared before adding a new route."
            ),
            "route_limit": exc.limit,
        },
        headers={"Retry-After": "30"},
    )

async def _generic_collection_refs(
    conn: Any, *, target_id: Any = None, device_target_id: Any = None,
    target_kind: str | None = None,
    bindings: Sequence[Mapping[str, Any]] = (),
) -> tuple[
    list[dict[str, Any]],
    list[str],
    dict[str, list[dict[str, Any]]],
]:
    """Freeze exact target-bound selection refs and derive safe endpoint seeds."""
    requested: list[tuple[uuid.UUID, Mapping[str, Any]]] = []
    for raw in list(bindings)[:16]:
        # Prefer the public V2 selection identity so a complete
        # collection_id/binding_id/selection_id tuple cannot silently degrade
        # into a discovery-only collection reference.
        value = raw.get("selection_id") or raw.get("id") or raw.get("collection_id")
        if not value:
            raise HTTPException(status_code=422, detail="request collection binding requires id")
        requested.append((
            _uuid_or_400(str(value), "request collection or selection id"), raw,
        ))
    if not requested:
        return [], [], {}
    if len({value for value, _raw in requested}) != len(requested):
        raise HTTPException(status_code=422, detail="request collection references must be unique")
    normalized_kind = str(target_kind or ("device" if device_target_id else "web")).lower()
    if normalized_kind not in {"web", "api", "device"}:
        raise HTTPException(
            status_code=422,
            detail="request collections require a web, API, or device target",
        )
    bound_target_id = device_target_id if normalized_kind == "device" else target_id
    if not bound_target_id:
        raise HTTPException(status_code=422, detail="request collection target is missing")
    endpoints: list[str] = []
    refs: list[dict[str, Any]] = []
    manifest_requests: dict[str, list[dict[str, Any]]] = {}
    for reference_id, raw in requested:
        row = await conn.fetchrow(
            """SELECT rc.id, rc.target_id, rc.device_target_id, rc.name, rc.format,
                      rc.request_count, rc.safe_request_count,
                      rc.potentially_mutating_request_count, rc.payload_sha256,
                      s.id AS selection_id, s.binding_id AS selection_binding_id,
                      s.replay_policy, s.selector_json, s.selection_digest,
                      s.selected_request_count, s.selected_mutating_count
               FROM request_collections rc
               LEFT JOIN request_collection_selections s
                 ON s.collection_id=rc.id AND s.id=$1 AND s.is_active=true
               WHERE rc.is_active=true AND (rc.id=$1 OR s.id=$1)
               ORDER BY (s.id=$1) DESC LIMIT 1""",
            reference_id,
        )
        if not row:
            raise HTTPException(
                status_code=422,
                detail="request collection or selection is unavailable",
            )
        supplied_collection_id = str(raw.get("collection_id") or "").strip()
        if supplied_collection_id and supplied_collection_id != str(row["id"]):
            raise HTTPException(
                status_code=422,
                detail="request collection selection does not match collection_id",
            )
        supplied_selection_id = str(raw.get("selection_id") or "").strip()
        if supplied_selection_id and supplied_selection_id != str(
            row.get("selection_id") or ""
        ):
            raise HTTPException(
                status_code=422,
                detail="request collection selection_id is unavailable",
            )
        owner_id = row["device_target_id"] if normalized_kind == "device" else row["target_id"]
        if str(owner_id or "") != str(bound_target_id):
            raise HTTPException(
                status_code=422,
                detail="request collection is bound to another target",
            )
        binding = await conn.fetchrow(
            """SELECT b.*, e.payload_sha256 AS environment_sha256
               FROM request_collection_bindings b
               LEFT JOIN request_collection_environments e
                 ON e.id=b.environment_id AND e.is_active=true
               WHERE b.collection_id=$1 AND b.target_kind=$2 AND b.target_id=$3
                 AND b.is_active=true
               ORDER BY b.updated_at DESC LIMIT 1""",
            row["id"], normalized_kind, bound_target_id,
        )
        if not binding:
            raise HTTPException(
                status_code=422,
                detail="request collection has no exact active binding for this target",
            )
        supplied_binding_id = str(raw.get("binding_id") or "").strip()
        if supplied_binding_id and supplied_binding_id != str(binding["id"]):
            raise HTTPException(
                status_code=422,
                detail="request collection selection does not match binding_id",
            )
        selection_id = row.get("selection_id")
        if selection_id:
            if str(row.get("selection_binding_id") or "") != str(binding["id"]):
                raise HTTPException(
                    status_code=422,
                    detail="request collection selection belongs to another target binding",
                )
            selector = _request_collection_selector(
                _decode_json_value(row.get("selector_json")) or {}
            )
            replay_policy = str(row.get("replay_policy") or "")
            supplied_replay_policy = str(raw.get("replay_policy") or "").strip()
            if supplied_replay_policy and supplied_replay_policy != replay_policy:
                raise HTTPException(
                    status_code=422,
                    detail="request collection replay_policy does not match saved selection",
                )
            try:
                selection_digest = request_collection_selection_digest(
                    collection_id=row["id"],
                    payload_sha256=str(row["payload_sha256"]),
                    binding_id=binding["id"],
                    allowed_origins=(
                        _decode_json_value(binding.get("allowed_origins")) or []
                    ),
                    selector=selector,
                    replay_policy=replay_policy,
                    environment_sha256=binding.get("environment_sha256"),
                )
            except RequestCollectionContractError as exc:
                raise HTTPException(status_code=409, detail=str(exc)) from exc
            if selection_digest != str(row.get("selection_digest") or ""):
                raise HTTPException(
                    status_code=409,
                    detail="request collection selection changed after it was saved",
                )
        else:
            selector_raw = (
                raw.get("selector") if isinstance(raw.get("selector"), Mapping) else {}
            )
            selector = _request_collection_selector({
                **dict(selector_raw),
                "safe_methods_only": True,
            })
            replay_policy = "discovery_only"
            try:
                selection_digest = request_collection_selection_digest(
                    collection_id=row["id"],
                    payload_sha256=str(row["payload_sha256"]),
                    binding_id=binding["id"],
                    allowed_origins=(
                        _decode_json_value(binding.get("allowed_origins")) or []
                    ),
                    selector=selector,
                    replay_policy=replay_policy,
                    environment_sha256=binding.get("environment_sha256"),
                )
            except RequestCollectionContractError as exc:
                raise HTTPException(status_code=409, detail=str(exc)) from exc
        index_rows = await conn.fetch(
            """SELECT request_id, ordinal, folder, name, method, redacted_url,
                      normalized_path, body_mode, auth_type, tags_json,
                      safe_method, supported, content_type, body_field_names_json
               FROM request_collection_requests
               WHERE collection_id=$1 AND supported=true
               ORDER BY ordinal LIMIT 20000""",
            row["id"],
        )
        selected_rows = _select_request_collection_index_rows(index_rows, selector)
        execution_rows = (
            [item for item in selected_rows if item.get("safe_method")]
            if replay_policy == "safe_reads"
            else selected_rows
        )
        manifest_requests[selection_digest] = [
            {
                "request_id": str(item.get("request_id") or ""),
                "method": str(item.get("method") or "GET").upper(),
                "redacted_url": str(item.get("redacted_url") or ""),
                "normalized_path": str(item.get("normalized_path") or "/"),
                "auth_type": str(item.get("auth_type") or "none"),
                "body_mode": str(item.get("body_mode") or "none"),
                "content_type": str(item.get("content_type") or "none"),
                "body_field_names": list(
                    _decode_json_value(item.get("body_field_names_json")) or []
                ),
                "safe_method": bool(item.get("safe_method")),
                "allowed_origins": list(
                    _decode_json_value(binding.get("allowed_origins")) or []
                ),
            }
            for item in execution_rows
        ]
        for item in selected_rows:
            if not item.get("safe_method"):
                continue
            path = str(item["normalized_path"] or "").strip()
            if path:
                # Preserve only query parameter names from the already-redacted
                # collection index. Candidate compilation needs those names to
                # authorize deterministic XSS/SQLi checks, but no request value
                # belongs in the public endpoint seed or queue payload.
                redacted_url = str(item.get("redacted_url") or "").strip()
                query_names = sorted({
                    str(name)
                    for name, _value in urllib.parse.parse_qsl(
                        urllib.parse.urlsplit(redacted_url).query,
                        keep_blank_values=True,
                    )
                    if str(name)
                })
                query = urllib.parse.urlencode(
                    [(name, "") for name in query_names]
                )
                endpoint = f"{path}?{query}" if query else path
                endpoints.append(
                    f"{str(item['method']).upper()} {endpoint}"
                )
        refs.append({
            "collection_id": str(row["id"]), "name": row["name"], "format": row["format"],
            "request_count": int(row["request_count"] or 0),
            "selection_id": str(selection_id) if selection_id else None,
            "binding_id": str(binding["id"]),
            "environment_id": str(binding["environment_id"]) if binding.get("environment_id") else None,
            "target_kind": normalized_kind,
            "target_id": str(bound_target_id),
            "allowed_origins": list(_decode_json_value(binding.get("allowed_origins")) or []),
            "selector": selector.public_dict(),
            "replay_policy": replay_policy,
            "selection_digest": selection_digest,
            "selected_requests": len(execution_rows),
            "selected_safe_requests": sum(1 for item in execution_rows if item.get("safe_method")),
            "selected_mutating_requests": sum(1 for item in execution_rows if not item.get("safe_method")),
            "payload_sha256": row["payload_sha256"],
            "environment_sha256": binding.get("environment_sha256"),
            "secret_values_visible": False,
        })
    return refs, list(dict.fromkeys(endpoints))[:2000], manifest_requests


def _executable_scan_collection_refs(
    refs: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Return only saved selections that authorize worker-side exact replay."""
    return [
        dict(item)
        for item in refs
        if str(item.get("replay_policy") or "").strip().lower()
        in EXECUTABLE_REPLAY_POLICIES
        and int(item.get("selected_requests") or 0) > 0
    ]


async def _freeze_scan_collection_target_binding(
    *,
    target_id: Any,
    target_kind: str,
    target_url: str,
    refs: Sequence[Mapping[str, Any]],
    existing_guard: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Freeze the exact origins and DNS addresses used by Scan replay transport."""
    executable = _executable_scan_collection_refs(refs)
    if not executable:
        return dict(existing_guard or {})
    parsed_target = urllib.parse.urlsplit(str(target_url or ""))
    canonical_host = str(parsed_target.hostname or "").strip().lower().rstrip(".")
    if not canonical_host:
        raise HTTPException(
            status_code=422,
            detail="request collection replay requires a valid Scan target host",
        )
    allowed_origins: list[str] = []
    for ref in executable:
        for raw_origin in ref.get("allowed_origins") or ():
            try:
                origin = canonical_collection_origin(raw_origin)
            except RequestCollectionContractError as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from exc
            if urllib.parse.urlsplit(origin).hostname != canonical_host:
                raise HTTPException(
                    status_code=422,
                    detail="request collection replay origin is outside the Scan target host",
                )
            if origin not in allowed_origins:
                allowed_origins.append(origin)
    if not allowed_origins:
        raise HTTPException(
            status_code=422,
            detail="request collection replay requires an exact origin binding",
        )
    guard = dict(existing_guard or {})
    guard["allowed_origins"] = allowed_origins
    return await _freeze_scan_target_binding(
        target_id=target_id,
        target_kind=target_kind,
        target_url=target_url,
        scope_receipt_id=str(guard.get("scope_receipt_id") or "") or None,
        scheme_inferred=False,
        existing_guard=guard,
        subject="Scan request collection target",
    )


async def _freeze_scan_target_binding(
    *,
    target_id: Any,
    target_kind: str,
    target_url: str,
    scope_receipt_id: str | None,
    scheme_inferred: bool,
    existing_guard: Mapping[str, Any] | None = None,
    subject: str = "Scan target",
) -> dict[str, Any]:
    """Freeze the target authority used by every canonical Scan queue job."""
    parsed = urllib.parse.urlsplit(str(target_url or ""))
    canonical_host = str(parsed.hostname or "").strip().lower().rstrip(".")
    if parsed.scheme.lower() not in {"http", "https"} or not canonical_host:
        raise HTTPException(status_code=422, detail=f"{subject} is not a valid HTTP(S) origin")
    guard = dict(existing_guard or {})
    allowed_origins: list[str] = []
    for raw_origin in guard.get("allowed_origins") or ():
        try:
            origin = canonical_collection_origin(raw_origin)
        except RequestCollectionContractError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        if urllib.parse.urlsplit(origin).hostname != canonical_host:
            raise HTTPException(
                status_code=422, detail=f"{subject} binding contains another host"
            )
        if origin not in allowed_origins:
            allowed_origins.append(origin)
    schemes = ("http", "https") if scheme_inferred else (parsed.scheme.lower(),)
    for scheme in schemes:
        origin = canonical_collection_origin(f"{scheme}://{parsed.netloc}")
        if origin not in allowed_origins:
            allowed_origins.append(origin)
    roots = [
        str(item).strip().lower().rstrip(".")
        for item in guard.get("allowed_root_domains") or ()
        if str(item).strip()
    ] or [extract_root_domain(target_url) or canonical_host]
    allowed_addresses = await _resolve_runtime_target_addresses(
        target_url, subject=subject,
    )
    guard.update({
        "target_id": str(target_id),
        "target_kind": str(target_kind or "web").strip().lower(),
        "canonical_host": canonical_host,
        "allowed_origins": allowed_origins,
        "allowed_addresses": allowed_addresses,
        "allowed_root_domains": roots,
        "environment": str(guard.get("environment") or "unknown"),
        "scope_receipt_id": scope_receipt_id,
        "requires_runtime_destination_check": True,
        "requires_runtime_dns_check": True,
        "address_binding_source": "submission_dns_snapshot",
    })
    return guard


def _compile_scan_request_work_manifests(
    *,
    scan_id: str,
    target_binding: TargetBinding,
    collection_refs: Sequence[Mapping[str, Any]],
    selection_requests: Mapping[str, Sequence[Mapping[str, Any]]],
    options: Mapping[str, Any] | None = None,
) -> tuple[
    tuple[ScanWorkManifest, ...],
    dict[str, dict[str, Any]],
]:
    """Freeze each executable saved selection into its action-owned request list."""
    action_refs = sorted(
        request_collection_action_refs(collection_refs),
        key=lambda item: json.dumps(
            item, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        ),
    )
    manifests: list[ScanWorkManifest] = []
    references: dict[str, dict[str, Any]] = {}
    for index, action_ref in enumerate(action_refs):
        selection_digest = str(action_ref["selection_digest"])
        replay_policy = str(action_ref.get("replay_policy") or "")
        raw_requests = list(selection_requests.get(selection_digest) or ())
        maximum = int(action_ref.get("max_requests") or 0)
        if not raw_requests or maximum < 1:
            raise ScanActionPlanError(
                "request collection selection has no immutable request work"
            )
        entries: list[dict[str, Any]] = []
        for raw in raw_requests[:maximum]:
            allowed_origins = tuple(
                canonical_collection_origin(item)
                for item in raw.get("allowed_origins") or () if str(item)
            )
            redacted_url = str(raw.get("redacted_url") or "").strip()
            parsed = urllib.parse.urlsplit(redacted_url)
            if parsed.scheme and parsed.netloc:
                origin = urllib.parse.urlunsplit((
                    parsed.scheme, parsed.netloc, "", "", "",
                ))
            elif allowed_origins:
                origin = allowed_origins[0]
            else:
                raise ScanActionPlanError(
                    "request collection manifest has no exact origin"
                )
            try:
                origin = canonical_collection_origin(origin)
            except RequestCollectionContractError as exc:
                raise ScanActionPlanError(
                    "request collection manifest origin is invalid"
                ) from exc
            if origin not in allowed_origins:
                raise ScanActionPlanError(
                    "request collection manifest origin exceeds its binding"
                )
            origin_parts = urllib.parse.urlsplit(origin)
            scheme = str(origin_parts.scheme).lower()
            host = str(origin_parts.hostname or "").lower().rstrip(".")
            port = int(origin_parts.port or (443 if scheme == "https" else 80))
            method = str(raw.get("method") or "GET").upper()
            path = str(raw.get("normalized_path") or "/")
            query_names = sorted({
                str(name) for name, _value in urllib.parse.parse_qsl(
                    parsed.query, keep_blank_values=True,
                ) if str(name)
            })
            entries.append({
                "request_ref_id": str(raw.get("request_id") or ""),
                "route_id": scan_manifest_route_id(
                    target_binding_digest=target_binding.digest,
                    method=method,
                    scheme=scheme,
                    host=host,
                    port=port,
                    canonical_path=path,
                    query_parameter_names=query_names,
                ),
                "method": method,
                "auth_lane": (
                    "primary"
                    if str(raw.get("auth_type") or "none").lower() != "none"
                    else "anonymous"
                ),
                "selected_shard": None,
                "request_class": (
                    "safe_read" if bool(raw.get("safe_method"))
                    else "safe_authentication"
                    if replay_policy == "safe_authentication"
                    else "confirmed_mutation"
                ),
                "content_type": raw.get("content_type"),
                "body_field_names": list(raw.get("body_field_names") or ()),
                "selection_digest": selection_digest,
                "body_schema_digest": (
                    hashlib.sha256(json.dumps({
                        "content_type": raw.get("content_type"),
                        "body_field_names": sorted(raw.get("body_field_names") or ()),
                    }, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                    if raw.get("body_field_names") else None
                ),
            })
        manifest = build_request_manifest(
            scan_id=scan_id,
            target_binding_digest=target_binding.digest,
            source_action_ids=(f"inputs.collection_{index:02d}",),
            requests=entries,
            maximum=maximum,
        )
        manifests.append(manifest)
        references[selection_digest] = manifest.reference().canonical_dict()
    private_options = dict(options or {})
    if (
        private_options.get("auto_auth") is True
        and private_options.get("disposable_login_credentials") is True
        and private_options.get("login_url")
        and private_options.get("login_username")
        and private_options.get("login_password")
    ):
        login_url = urllib.parse.urljoin(
            target_binding.allowed_origins[0].rstrip("/") + "/",
            str(private_options["login_url"]),
        )
        parsed = urllib.parse.urlsplit(login_url)
        origin = canonical_collection_origin(urllib.parse.urlunsplit((
            parsed.scheme, parsed.netloc, "", "", "",
        )))
        if origin not in target_binding.allowed_origins or (
            parsed.hostname or ""
        ).lower().rstrip(".") != target_binding.canonical_host:
            raise ScanActionPlanError(
                "safe authentication workflow exceeds the frozen target"
            )
        field_names = ["email", "password"]
        selection_digest = hashlib.sha256(json.dumps({
            "schema_version": "safe-authentication-selection/v1",
            "target_binding_digest": target_binding.digest,
            "method": "POST",
            "path": parsed.path or "/",
            "query_names": sorted(name for name, _value in urllib.parse.parse_qsl(
                parsed.query, keep_blank_values=True,
            )),
            "content_type": "application/json",
            "body_field_names": field_names,
            "credential_class": "disposable",
        }, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        request_id = "credential-login:primary"
        manifest = build_request_manifest(
            scan_id=scan_id,
            target_binding_digest=target_binding.digest,
            source_action_ids=("inputs.auth_primary",),
            requests=({
                "request_ref_id": request_id,
                "route_id": scan_manifest_route_id(
                    target_binding_digest=target_binding.digest,
                    method="POST",
                    scheme=parsed.scheme,
                    host=str(parsed.hostname or ""),
                    port=int(parsed.port or (443 if parsed.scheme == "https" else 80)),
                    canonical_path=parsed.path or "/",
                    query_parameter_names=sorted(
                        name for name, _value in urllib.parse.parse_qsl(
                            parsed.query, keep_blank_values=True,
                        )
                    ),
                ),
                "method": "POST",
                "auth_lane": "primary",
                "selected_shard": None,
                "request_class": "safe_authentication",
                "content_type": "application/json",
                "body_field_names": field_names,
                "selection_digest": selection_digest,
                "body_schema_digest": hashlib.sha256(
                    b'application/json:["email","password"]'
                ).hexdigest(),
            },),
        )
        manifests.append(manifest)
        references[selection_digest] = manifest.reference().canonical_dict()
    return tuple(manifests), references


def _compile_scan_request_candidate_work_manifest(
    *,
    request_manifests: Sequence[ScanWorkManifest],
    maximum: int,
) -> ScanWorkManifest | None:
    """Compile value-free mutation candidates only from exact request refs."""
    if not request_manifests:
        return None
    source_action_ids = tuple(dict.fromkeys(
        action_id
        for manifest in request_manifests
        for action_id in manifest.source_action_ids
    ))
    return build_request_candidate_manifest(
        request_manifests,
        source_action_ids=source_action_ids,
        maximum=max(1, min(2_000, int(maximum))),
    )


def _compile_allocated_scan_action_plan(
    *,
    scan_id: str,
    scan_contract: ResolvedScanContract,
    target_binding: TargetBinding,
    credential_refs: Sequence[Mapping[str, Any]] = (),
    request_collection_refs: Sequence[Mapping[str, Any]] = (),
    request_manifest_refs: Mapping[str, Mapping[str, Any]] | None = None,
    endpoint_manifest_ref: Mapping[str, Any] | None = None,
    candidate_manifest_ref: Mapping[str, Any] | None = None,
    request_candidate_manifest_ref: Mapping[str, Any] | None = None,
    template_manifest_ref: Mapping[str, Any] | None = None,
):
    raw_plan = ScanActionPlanCompiler().compile(
        scan_id=scan_id,
        execution_plan=scan_contract.execution_plan,
        target_binding=target_binding,
        credential_profile_refs=credential_profile_action_refs(credential_refs),
        request_collection_refs=request_collection_action_refs(
            request_collection_refs
        ),
        request_manifest_refs=request_manifest_refs,
        endpoint_manifest_ref=endpoint_manifest_ref,
        candidate_manifest_ref=candidate_manifest_ref,
        request_candidate_manifest_ref=request_candidate_manifest_ref,
        template_manifest_ref=template_manifest_ref,
    )
    return allocate_scan_action_plan(
        raw_plan, scan_contract.budget,
    ).plan


def _compile_scan_admission_action_authority(
    *,
    scan_id: str,
    scan_contract: ResolvedScanContract,
    target_binding: TargetBinding,
    credential_refs: Sequence[Mapping[str, Any]] = (),
    request_collection_refs: Sequence[Mapping[str, Any]] = (),
    request_manifest_refs: Mapping[str, Mapping[str, Any]] | None = None,
    endpoint_manifest_ref: Mapping[str, Any] | None = None,
    candidate_manifest_ref: Mapping[str, Any] | None = None,
    request_candidate_manifest_ref: Mapping[str, Any] | None = None,
    template_manifest_ref: Mapping[str, Any] | None = None,
) -> tuple[ScanActionPlan, ScanContinuationAllocation | None]:
    """Compile admission traffic and freeze all residual active-test authority."""
    if not scan_contract.policy.active_testing:
        return (
            _compile_allocated_scan_action_plan(
                scan_id=scan_id,
                scan_contract=scan_contract,
                target_binding=target_binding,
                credential_refs=credential_refs,
                request_collection_refs=request_collection_refs,
                request_manifest_refs=request_manifest_refs,
                endpoint_manifest_ref=endpoint_manifest_ref,
                candidate_manifest_ref=candidate_manifest_ref,
                request_candidate_manifest_ref=request_candidate_manifest_ref,
                template_manifest_ref=template_manifest_ref,
            ),
            None,
        )

    required_by_family = {
        "nuclei_active": "templates.active_batch",
        "xss": "xss.verify_batch",
        "sqli": "sqli.verify_batch",
        "bola": "authz.verify",
        "sensitive_exposure": "exposure.verify_batch",
        "nosqli": "nosqli.verify_batch",
        "authz_surface": "authz_surface.verify_batch",
    }
    allowed_by_family = dict(required_by_family)
    required_capabilities = tuple(
        required_by_family[family]
        for family in (
            "xss", "sqli", "bola", "nuclei_active", "sensitive_exposure", "nosqli",
            "authz_surface",
        )
        if family in set(scan_contract.policy.include_families)
        and family not in set(scan_contract.policy.exclude_families)
    )
    enabled_families = {
        family
        for family in allowed_by_family
        if family not in set(scan_contract.policy.exclude_families)
        and (
            not scan_contract.policy.include_families
            or family in set(scan_contract.policy.include_families)
        )
    }
    allowed_capabilities = {
        allowed_by_family[family] for family in enabled_families
    }
    if "xss" in enabled_families:
        allowed_capabilities.add("xss.request_verify_batch")
        allowed_capabilities.add("xss.browser_prove_batch")
    if "sqli" in enabled_families:
        allowed_capabilities.add("sqli.request_verify_batch")
        allowed_capabilities.add("sqli.prove_batch")
    required_holds = (*required_capabilities, "scan.finalize")
    reserved_budget: dict[str, int] = {}
    for capability_name in required_holds:
        specification = agent_tools.CAPABILITY_REGISTRY.require(capability_name)
        for name, amount in specification.budget_cost.items():
            reserved_budget[name] = reserved_budget.get(name, 0) + amount

    raw_parent = ScanActionPlanCompiler().compile(
        scan_id=scan_id,
        execution_plan=scan_contract.execution_plan,
        target_binding=target_binding,
        credential_profile_refs=credential_profile_action_refs(credential_refs),
        request_collection_refs=request_collection_action_refs(
            request_collection_refs
        ),
        request_manifest_refs=request_manifest_refs,
        endpoint_manifest_ref=endpoint_manifest_ref,
        candidate_manifest_ref=candidate_manifest_ref,
        request_candidate_manifest_ref=request_candidate_manifest_ref,
        template_manifest_ref=template_manifest_ref,
        defer_manifest_actions=True,
        include_finalizer=False,
    )
    parent_allocation = allocate_scan_action_plan(
        raw_parent,
        scan_contract.budget,
        assign_residual_to_finalizer=False,
        require_finalizer=False,
        reserved_budget=reserved_budget,
    )
    remaining = dict(parent_allocation.residual_scan_execute_budget)
    for capability_name in required_holds:
        specification = agent_tools.CAPABILITY_REGISTRY.require(capability_name)
        shortages = {
            name: amount - remaining.get(name, 0)
            for name, amount in specification.budget_cost.items()
            if amount > remaining.get(name, 0)
        }
        if shortages:
            raise ScanBudgetAllocationError(capability_name, shortages)
        for name, amount in specification.budget_cost.items():
            remaining[name] = remaining.get(name, 0) - amount

    parent_plan = parent_allocation.plan
    continuation = ScanContinuationAllocation(
        scan_id=scan_id,
        parent_plan_digest=str(parent_plan.plan_digest),
        execution_plan_digest=parent_plan.execution_plan_digest,
        target_binding_digest=parent_plan.target_binding_digest,
        parent_action_ids=tuple(
            action.action_id for action in parent_plan.actions
        ),
        budget_ceiling=parent_allocation.residual_scan_execute_budget,
        max_endpoint_entries=scan_contract.budget.max_endpoints,
        max_candidate_entries=max(
            1,
            min(
                20_000,
                scan_contract.budget.max_http_requests,
                scan_contract.budget.max_endpoints * 64,
            ),
        ),
        required_capabilities=required_capabilities,
        allowed_capabilities=tuple(sorted(allowed_capabilities)),
    )
    return parent_plan, continuation


def _compile_scan_admission_surface_work_manifests(
    *,
    scan_id: str,
    target_url: str,
    scan_contract: ResolvedScanContract,
    target_binding: TargetBinding,
    options: Mapping[str, Any],
    request_manifests: Sequence[ScanWorkManifest] = (),
) -> tuple[ScanWorkManifest, ScanWorkManifest]:
    """Freeze every route known before traffic into exact, private work.

    This is deliberately not the crawl continuation manifest.  It covers the
    canonical origin plus admitted manual/OpenAPI/HAR/request-collection seeds,
    so actions can never execute their display-redacted representations.
    """
    empty_success = {"status": "success", "observations": []}
    surface = build_scan_surface_manifest(
        target_url=target_url,
        target=target_binding,
        options=options,
        collection_replay=empty_success,
        subdomains=empty_success,
        probe=empty_success,
        crawl=empty_success,
        content=empty_success,
        max_endpoints=scan_contract.budget.max_endpoints,
    )
    request_refs_by_route: dict[str, list[str]] = {}
    auth_lane_by_route: dict[str, str] = {}
    for manifest in request_manifests:
        for entry in manifest.entries:
            route = str(entry.get("route_id") or "")
            request_ref = str(entry.get("request_ref_id") or "")
            if not route or not request_ref:
                continue
            request_refs_by_route.setdefault(route, []).append(request_ref)
            lane = str(entry.get("auth_lane") or "anonymous")
            if lane != "anonymous":
                auth_lane_by_route[route] = lane
    endpoint_manifest = build_endpoint_manifest(
        scan_id=scan_id,
        target_binding_digest=target_binding.digest,
        surface_manifest=surface,
        source_action_ids=("admission.surface",),
        auth_lane="anonymous",
        request_ref_ids_by_route={
            route: tuple(dict.fromkeys(values))
            for route, values in request_refs_by_route.items()
        },
        auth_lane_by_route=auth_lane_by_route,
    )
    candidate_manifest = build_candidate_manifest(
        endpoint_manifest,
        source_action_ids=("admission.surface",),
        maximum=max(
            1,
            min(
                20_000,
                scan_contract.budget.max_http_requests,
                scan_contract.budget.max_endpoints * 64,
            ),
        ),
    )
    return endpoint_manifest, candidate_manifest


def _compile_scan_template_work_manifest(
    *,
    scan_id: str,
    scan_contract: ResolvedScanContract,
    target_binding: TargetBinding,
) -> ScanWorkManifest | None:
    """Freeze passive templates and the active pack allowed by policy."""
    policy = scan_contract.execution_plan.policy
    include = set(policy.include_families)
    exclude = set(policy.exclude_families)
    passive_enabled = "nuclei_passive" in include and "nuclei_passive" not in exclude
    active_enabled = "nuclei_active" in include and "nuclei_active" not in exclude
    if not passive_enabled and not active_enabled:
        return None
    return build_canonical_scan_nuclei_template_manifest(
        scan_id=scan_id,
        target_binding_digest=target_binding.digest,
        include_active=policy.active_testing and active_enabled,
    )






async def _parse_public_json_model(
    request: Request,
    model: type[BaseModel],
    *,
    product: str,
) -> BaseModel:
    """Decode one already body-bounded public request without echoing input."""
    raw_body = await request.body()
    try:
        payload = json.loads(raw_body or b"{}")
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_json",
                "message": f"{product} request body must be valid JSON.",
            },
        ) from exc
    if not isinstance(payload, dict):
        raise HTTPException(
            status_code=422,
            detail={
                "error": "invalid_request_shape",
                "message": f"{product} request body must be an object.",
            },
        )
    try:
        return model.model_validate(payload)
    except ValidationError as exc:
        raise RequestValidationError(exc.errors()) from exc


@app.post(
    "/scans",
    operation_id="submit_scan_scans_post",
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "application/json": {
                    "schema": ScanRequest.model_json_schema(),
                },
            },
        },
    },
)
async def submit_scan_endpoint(request: Request):
    parsed = await _parse_public_json_model(
        request, ScanRequest, product="Scan",
    )
    return await submit_scan(parsed)


async def submit_scan(request: ScanRequest):
    """Submit one canonical secret-free Scan job."""
    return await _submit_scan(request)


def _scan_execution_options(
    options: Union[ScanOptions, ScanPublicCompatibilityOptions],
) -> ScanOptions:
    """Compile public compatibility controls into worker execution options.

    Public controls use ``None`` to distinguish an omitted parallel choice from
    an explicit boolean.  The historical worker model uses concrete boolean
    defaults, so omitted public values must be removed before validation rather
    than forwarded as ``parallel=None``.
    """
    if isinstance(options, ScanOptions):
        return options.model_copy(deep=True)
    return ScanOptions(**options.model_dump(mode="python", exclude_none=True))


def _scan_requires_durable_approval(
    scan_contract: ResolvedScanContract,
    *,
    credential_refs: Sequence[Mapping[str, Any]] = (),
    confirmed_active_collection_replay: bool = False,
) -> bool:
    """Keep admission aligned with the per-action runtime approval gate."""
    return bool(
        scan_contract.policy.active_testing
        or credential_refs
        or confirmed_active_collection_replay
    )


async def _submit_scan(
    request: _ScanRequestBase,
):
    """Canonical V2 admission; legacy identities and inline secrets are rejected."""
    execution_options = _scan_execution_options(request.options)
    scheme_inferred = "://" not in (request.target or "")
    try:
        normalized_target, target_note = normalize_target_url(request.target)
    except TargetNormalizationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if not normalized_target:
        raise HTTPException(status_code=400, detail="Invalid target URL")

    # If scheme was inferred (not provided), pass scheme-less target to scanner for auto-detect
    scan_target = normalized_target
    if scheme_inferred:
        scan_target = strip_target_scheme(normalized_target)

    r = get_redis()
    job_id = str(uuid.uuid4())
    scan_id = str(uuid.uuid4())

    approval_receipt_id = (
        request.approval_receipt_id or execution_options.approval_receipt_id
    )
    try:
        scan_contract = resolve_scan_contract(
            budget_profile=request.budget_profile or execution_options.budget_profile,
            policy=request.policy,
            advanced=(
                request.advanced.model_dump(exclude_none=True)
                if request.advanced is not None else None
            ),
            approval_receipt_id=approval_receipt_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    public_scan_type = "scan"
    execution_options.approval_receipt_id = approval_receipt_id
    execution_options.budget_profile = scan_contract.budget_profile
    execution_options.subfinder = bool(scan_contract.policy.subdomain_discovery)
    execution_options.shard_concurrency = min(20, scan_contract.budget.max_workers)

    # Validate: public mode is incompatible with active testing.
    if scan_contract.policy.active_testing and execution_options.public:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_options",
                "message": "'public' is incompatible with policy.active_testing=true.",
                "hint": "Either remove 'public: true' or set policy.active_testing=false",
            }
        )

    # Managed credentials are resolved only after the canonical target row is
    # known. Apply registry narrowing now, but defer credential preconditions
    # until the target-bound managed-profile refs have been attached below.
    options_payload = _build_canonical_scan_options_payload(
        execution_options,
        scan_contract,
        defer_family_preconditions=True,
    )
    inline_option_authentication = {
        key: options_payload.get(key)
        for key in SCAN_AUTHENTICATION_KEYS
        if _scan_authentication_value_present(options_payload.get(key))
    }
    if inline_option_authentication:
        raise HTTPException(
            status_code=422,
            detail=(
                "canonical Scan rejects inline authentication; create an "
                "encrypted credential profile and pass credential_profile_ids"
            ),
        )
    options_payload.pop("authentication", None)
    options_payload["network_discovery"] = bool(scan_contract.policy.network_discovery)
    options_payload["request_collections"] = [dict(item) for item in request.request_collections]
    options_payload["scan_policy"]["approval_receipt_id"] = approval_receipt_id

    # Record the eligible build at submit. Ordinary active scans require one
    # compatible current worker; the explicit strict flag still requires the
    # entire locally inventoried fleet to be uniform for release acceptance.
    _freshness = _worker_freshness_snapshot()
    require_uniform_current_fleet = bool(
        getattr(execution_options, "require_current_workers", False)
        and scan_contract.policy.active_testing
    )
    if require_uniform_current_fleet and (
        not _freshness.get("available") or int(_freshness.get("fleet_size") or 0) < 1
    ):
        raise HTTPException(
            status_code=503,
            detail={
                "error": "worker_inventory_unavailable",
                "message": (
                    "No local scanner worker fleet could be positively identified; refusing "
                    "active Scan with require_current_workers=true. Verify Docker socket "
                    "access and Compose project labels, then retry."
                ),
            },
        )
    if _freshness.get("available"):
        expected_worker_build = _freshness.get("expected_build_fingerprint")
        options_payload["expected_build_fingerprint_at_submit"] = expected_worker_build
        options_payload["selected_worker_build_fingerprint"] = expected_worker_build
        options_payload["stale_worker_count_at_submit"] = _freshness.get("stale_count")
        options_payload["pending_worker_count_at_submit"] = _freshness.get("pending_count")
        options_payload["worker_fleet_size_at_submit"] = _freshness.get("fleet_size")
        options_payload["current_worker_count_at_submit"] = _freshness.get("current_count")
        # This is per-job placement eligibility, not uniform-fleet admission.
        # The lease guard ensures a worker that becomes stale after submission
        # returns the job for a current worker instead of executing it.
        options_payload["require_current_worker_assignment"] = bool(
            scan_contract.policy.active_testing
        )
        if (
            scan_contract.policy.active_testing
            and int(_freshness.get("current_count") or 0) < 1
        ):
            raise HTTPException(
                status_code=503,
                detail={
                    "error": "no_compatible_current_worker",
                    "message": (
                        "No current-build scanner worker is available for active testing. "
                        "Start or rebuild one compatible worker, then retry."
                    ),
                    "stale_workers": _freshness.get("stale_names", []),
                    "pending_workers": _freshness.get("pending_names", []),
                    "expected_build_fingerprint": expected_worker_build,
                },
            )
        unsafe_worker_count = int(_freshness.get("stale_count") or 0) + int(_freshness.get("pending_count") or 0)
        if require_uniform_current_fleet and unsafe_worker_count > 0:
            raise HTTPException(
                status_code=409,
                detail={
                    "error": "workers_not_confirmed_current",
                    "message": (
                        f"{unsafe_worker_count} of {_freshness['fleet_size']} workers are not confirmed "
                        f"current ({_freshness.get('stale_count', 0)} stale, "
                        f"{_freshness.get('pending_count', 0)} pending); refusing active Scan "
                        "with require_current_workers=true. Restart workers to deploy current code and "
                        "wait for build fingerprints, then re-submit."
                    ),
                    "stale_workers": _freshness.get("stale_names", []),
                    "pending_workers": _freshness.get("pending_names", []),
                },
            )

    parallel_enabled = False
    parallel_worker_count: int | None = None

    # Create or find target
    command_result: dict[str, Any] | None = None
    async with db_pool.acquire() as conn:
        # Early missing-receipt guard before target-row creation.
        await _require_approval_receipt_if_policy_enabled(
            conn,
            approval_receipt_id,
            action_name="scan.submit",
        )
        await _require_reachable_fleet_placement(conn, options_payload.get("placement") or {})
        # Check if target exists
        target = await conn.fetchrow(
            "SELECT id FROM targets WHERE url = $1", normalized_target
        )
        if target:
            target_id = target['id']
        else:
            # Create new target
            target_id = await conn.fetchval("""
                INSERT INTO targets (url, name, root_domain, asm_enabled, asm_config)
                VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT (canonical_key) DO UPDATE SET url = targets.url
                RETURNING id
            """, normalized_target, request.name, extract_root_domain(normalized_target),
                 _default_asm_enabled_for_new_web_target("manual"),
                 json.dumps(_default_asm_config_for_new_web_target("manual")))

        (
            collection_refs,
            collection_endpoints,
            collection_manifest_requests,
        ) = await _generic_collection_refs(
            conn, target_id=target_id, target_kind=request.target_kind,
            bindings=request.request_collections,
        )
        if collection_refs:
            options_payload["request_collections"] = collection_refs
            options_payload["custom_endpoints"] = list(dict.fromkeys([
                *list(options_payload.get("custom_endpoints") or []), *collection_endpoints,
            ]))[:2000]
        executable_collection_refs = _executable_scan_collection_refs(collection_refs)
        confirmed_active_collection_replay = any(
            str(item.get("replay_policy") or "") == "confirmed_active"
            for item in executable_collection_refs
        )
        if confirmed_active_collection_replay:
            try:
                scan_replay_authorization(
                    "confirmed_active",
                    options_payload.get("scan_policy") or {},
                    approval_receipt_id=approval_receipt_id,
                )
            except ScanCollectionReplayContractError as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from exc

        credential_refs = await _admit_generic_scan_credential_profiles(
            conn,
            target_id=target_id,
            target_kind=request.target_kind,
            profile_ids=request.credential_profile_ids,
        )
        if "bola" in set(scan_contract.policy.include_families):
            by_lane = {
                str(item.get("scan_lane") or ""): item for item in credential_refs
            }
            if set(by_lane) != {"primary", "secondary"}:
                raise HTTPException(
                    status_code=422,
                    detail=(
                        "explicit BOLA coverage requires distinct primary and secondary "
                        "credential profiles"
                    ),
                )
            if any(
                not scan_credential_allows_capability(
                    item.get("allowed_capabilities") or (), "authz.verify",
                )
                for item in by_lane.values()
            ):
                raise HTTPException(
                    status_code=422,
                    detail=(
                        "explicit BOLA coverage requires both credential profiles to "
                        "allow authz.verify"
                    ),
                )
        credential_action_name = "scan.submit"
        durable_approval_required = _scan_requires_durable_approval(
            scan_contract,
            credential_refs=credential_refs,
            confirmed_active_collection_replay=(
                confirmed_active_collection_replay
            ),
        )

        approval_context = await _validate_approval_receipt_for_action(
            conn,
            approval_receipt_id,
            target_url=normalized_target,
            target_id=target_id,
            action_name=credential_action_name,
            risk_tier="credential" if credential_refs else "active",
            always_require_receipt=durable_approval_required,
            require_target_binding=durable_approval_required,
            require_expiry=durable_approval_required,
        )
        if approval_context:
            options_payload.update(approval_context)
            scan_contract = bind_scan_scope_receipt(
                scan_contract, approval_context.get("scope_receipt_id"),
            )
            options_payload.update(scan_contract.option_metadata())
        if executable_collection_refs:
            options_payload["runtime_scope_guard"] = (
                await _freeze_scan_collection_target_binding(
                    target_id=target_id,
                    target_kind=request.target_kind,
                    target_url=normalized_target,
                    refs=executable_collection_refs,
                    existing_guard=options_payload.get("runtime_scope_guard"),
                )
            )
        if (
            isinstance(options_payload.get("scan_policy"), dict)
            and options_payload["scan_policy"].get("scope_receipt_id")
            != options_payload.get("scope_receipt_id")
        ):
            raise HTTPException(
                status_code=409,
                detail="validated scope receipt is not bound to the canonical Scan plan",
            )
        if credential_refs:
            options_payload["credential_profile_refs"] = credential_refs
            options_payload["credential_target_kind"] = request.target_kind
            options_payload["credential_action_name"] = credential_action_name
            if any(
                str(item.get("auth_kind") or "") in {
                    "form_login", "oauth_client_credentials", "oauth_password",
                }
                for item in credential_refs
            ):
                options_payload[SCAN_PRIVATE_STATE_KEY_OPTION] = encrypt_secret(
                    generate_scan_private_state_key()
                )

        options_payload, _family = _apply_scan_check_family_policy(options_payload)
        parallel_enabled, parallel_worker_count = _apply_auto_sharding_policy(
            execution_options,
            options_payload,
            scan_contract.policy.active_testing,
        )
        if parallel_worker_count is not None:
            parallel_worker_count = min(
                max(0, int(parallel_worker_count)),
                scan_contract.budget.max_workers,
            )

        # Every V2 Scan persists one immutable target-bound job envelope even
        # while parallel/fleet transport is migrated in the next bounded step.
        options_payload["runtime_scope_guard"] = await _freeze_scan_target_binding(
            target_id=target_id,
            target_kind=request.target_kind,
            target_url=normalized_target,
            scope_receipt_id=scan_contract.policy.scope_receipt_id,
            scheme_inferred=scheme_inferred,
            existing_guard=options_payload.get("runtime_scope_guard"),
        )
        target_guard = options_payload["runtime_scope_guard"]
        target_binding = TargetBinding(
            target_id=str(target_id),
            target_kind=request.target_kind,
            canonical_host=target_guard.get("canonical_host"),
            allowed_origins=tuple(target_guard.get("allowed_origins") or ()),
            allowed_addresses=tuple(target_guard.get("allowed_addresses") or ()),
            allowed_root_domains=tuple(target_guard.get("allowed_root_domains") or ()),
            environment=str(target_guard.get("environment") or "unknown"),
            scope_receipt_id=scan_contract.policy.scope_receipt_id,
        )
        try:
            (
                request_work_manifests,
                request_work_manifest_refs,
            ) = _compile_scan_request_work_manifests(
                scan_id=scan_id,
                target_binding=target_binding,
                collection_refs=executable_collection_refs,
                selection_requests=collection_manifest_requests,
                options=options_payload,
            )
        except (ScanActionPlanError, ScanWorkManifestError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        if request_work_manifest_refs:
            options_payload["request_manifest_refs"] = request_work_manifest_refs
        (
            endpoint_work_manifest,
            candidate_work_manifest,
        ) = _compile_scan_admission_surface_work_manifests(
            scan_id=scan_id,
            target_url=normalized_target,
            scan_contract=scan_contract,
            target_binding=target_binding,
            options=options_payload,
            request_manifests=request_work_manifests,
        )
        endpoint_work_manifest_ref = (
            endpoint_work_manifest.reference().canonical_dict()
        )
        candidate_work_manifest_ref = (
            candidate_work_manifest.reference().canonical_dict()
        )
        request_candidate_work_manifest = (
            _compile_scan_request_candidate_work_manifest(
                request_manifests=request_work_manifests,
                maximum=scan_contract.budget.max_state_changing_requests,
            )
        )
        options_payload["endpoint_manifest_id"] = str(
            endpoint_work_manifest.manifest_id
        )
        options_payload["endpoint_manifest_ref"] = endpoint_work_manifest_ref
        options_payload["candidate_manifest_ref"] = candidate_work_manifest_ref
        if (
            request_candidate_work_manifest is not None
            and request_candidate_work_manifest.entries
        ):
            options_payload["request_candidate_manifest_ref"] = (
                request_candidate_work_manifest.reference().canonical_dict()
            )
        template_work_manifest = _compile_scan_template_work_manifest(
            scan_id=scan_id,
            scan_contract=scan_contract,
            target_binding=target_binding,
        )
        if template_work_manifest is not None:
            options_payload["template_manifest_ref"] = (
                template_work_manifest.reference().canonical_dict()
            )
        canonical_job = CanonicalScanJob.create(
            job_id=job_id,
            scan_id=scan_id,
            target=target_binding,
            execution_plan=scan_contract.execution_plan,
            request_collections=admitted_request_collection_job_refs(collection_refs),
            credential_profile_ids=admitted_credential_profile_ids(credential_refs),
            endpoint_manifest_id=str(endpoint_work_manifest.manifest_id),
        )
        try:
            (
                scan_action_plan,
                scan_continuation_allocation,
            ) = _compile_scan_admission_action_authority(
                scan_id=scan_id,
                scan_contract=scan_contract,
                target_binding=target_binding,
                credential_refs=credential_refs,
                request_collection_refs=executable_collection_refs,
                request_manifest_refs=request_work_manifest_refs,
                endpoint_manifest_ref=endpoint_work_manifest_ref,
                candidate_manifest_ref=(
                    candidate_work_manifest_ref
                    if candidate_work_manifest.entries else None
                ),
                request_candidate_manifest_ref=(
                    request_candidate_work_manifest.reference().canonical_dict()
                    if request_candidate_work_manifest is not None
                    and request_candidate_work_manifest.entries else None
                ),
                template_manifest_ref=(
                    template_work_manifest.reference().canonical_dict()
                    if template_work_manifest is not None else None
                ),
            )
            if scan_continuation_allocation is not None:
                options_payload["scan_continuation_allocation_digest"] = (
                    scan_continuation_allocation.allocation_digest
                )
        except (ScanActionPlanError, ScanBudgetAllocationError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        canonical_job_payload = canonical_job.payload()
        persisted_options = _attach_target_note(
            options_payload, request.target, target_note, scheme_inferred,
        )

        # Parallel scans become a parent row; the scan_plan job fans out shards.
        scan_role = 'parent' if parallel_enabled else 'standalone'

        # Persist the scan row, complete action index, and audit record atomically.
        async with conn.transaction():
            await conn.execute("""
                INSERT INTO scans (
                    id, target_id, target_url, job_id, status, options, scan_type, scan_role,
                    scan_generation, policy_json, budget_json, coverage_status, coverage_json,
                    scan_job_payload, scan_job_digest
                ) VALUES ($1, $2, $3, $4, 'pending', $5, $6, $7, 'v2', $8, $9, 'pending', $10,
                          $11, $12)
            """, uuid.UUID(scan_id), target_id, normalized_target, job_id,
                 json.dumps(persisted_options),
                 public_scan_type, scan_role, json.dumps(options_payload.get("scan_policy") or {}),
                 json.dumps(options_payload.get("resolved_scan_budget") or {}),
                 json.dumps({"status": "pending", "reasons": []}),
                 json.dumps(canonical_job_payload), canonical_job.payload_digest)
            action_store = PostgresScanActionStore()
            await action_store.persist_plan(
                conn, plan=scan_action_plan,
            )
            if scan_continuation_allocation is not None:
                await action_store.persist_continuation_allocation(
                    conn,
                    allocation=scan_continuation_allocation,
                    parent_plan=scan_action_plan,
                )
            for manifest in request_work_manifests:
                await PostgresScanManifestStore().persist(
                    conn, manifest=manifest,
                )
            for manifest in (
                endpoint_work_manifest, candidate_work_manifest,
                request_candidate_work_manifest,
            ):
                if manifest is not None:
                    await PostgresScanManifestStore().persist(
                        conn, manifest=manifest,
                    )
            if template_work_manifest is not None:
                await PostgresScanManifestStore().persist(
                    conn, manifest=template_work_manifest,
                )
            command_result = await _record_command_result(
                conn,
                command="scan.submit",
                status="queued",
                risk_tier=(
                    "credential"
                    if credential_refs
                    else "active" if scan_contract.policy.active_testing else "passive"
                ),
                scan_id=scan_id,
                scope_receipt_id=options_payload.get("scope_receipt_id"),
                approval_receipt_id=options_payload.get("approval_receipt_id"),
                operator_message=f"Queued Scan for {normalized_target}",
                result_json={
                    "target": normalized_target,
                    "scan_type": public_scan_type,
                    "scan_generation": "v2",
                    "policy": options_payload.get("scan_policy"),
                    "budget": options_payload.get("resolved_scan_budget"),
                    "job_id": job_id,
                    "scan_action_plan_digest": scan_action_plan.plan_digest,
                    "scan_role": scan_role,
                },
                next_action=f"/scans/{scan_id}",
            )

    # Queue the job
    canonical_queue = True
    job_data = canonical_job.queue_payload(
        placement=(
            None if parallel_enabled
            else normalize_placement(options_payload.get("placement") or {})
        ),
    )
    # Parallel scans are routed to the plan stage, which decomposes the parent
    # into shard jobs. Everything else stays on the standard scan path.
    if parallel_enabled:
        _configure_scan_plan_job(job_data, parallel_worker_count)
    try:
        enqueue_job(r, QUEUE_NAME, job_data)
    except RouteCapacityExceeded as exc:
        await _mark_scan_enqueue_failed(
            scan_id,
            "Scan was not queued because the fleet placement-route registry is at capacity.",
            command_result.get("id") if command_result else None,
        )
        raise _route_capacity_http_exception(exc) from exc
    except Exception as exc:
        logger.exception("Failed to enqueue submitted scan %s", scan_id)
        await _mark_scan_enqueue_failed(
            scan_id,
            "Scan was not queued because the queue service was unavailable.",
            command_result.get("id") if command_result else None,
        )
        raise HTTPException(
            status_code=503,
            detail={
                "error": "scan_queue_unavailable",
                "message": "The scan was recorded as failed because the queue did not accept it.",
            },
        ) from exc
    r.hset(f"job:{job_id}", mapping={'status': 'queued', 'target': scan_target})

    response = {
        'scan_id': scan_id,
        'job_id': job_id,
        'status': 'queued',
        'target': normalized_target,
        'scan_type': public_scan_type,
        'scan_generation': 'v2',
        'queue_schema': canonical_job.schema_version if canonical_queue else 'legacy-transport',
        'policy': options_payload.get('scan_policy'),
        'budget': options_payload.get('resolved_scan_budget'),
        'budget_profile': scan_contract.budget_profile,
    }
    if parallel_enabled:
        response['parallel'] = True
        if options_payload.get("auto_sharded"):
            response['auto_sharded'] = True
            response['auto_sharding_reason'] = options_payload.get("auto_sharding_reason")
    if options_payload.get("approval_receipt_id"):
        response["approval_receipt_id"] = options_payload.get("approval_receipt_id")
        response["scope_receipt_id"] = options_payload.get("scope_receipt_id")
    if command_result:
        response["operation_id"] = command_result["id"]
    # Surface warning if path/query was stripped
    if target_note:
        response['warning'] = target_note
        response['original_target'] = request.target
    return response


@app.post(
    "/scans/batch",
    operation_id="submit_batch_scans_batch_post",
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "application/json": {
                    "schema": BatchRequest.model_json_schema(),
                },
            },
        },
    },
)
async def submit_batch_endpoint(request: Request):
    parsed = await _parse_public_json_model(
        request, BatchRequest, product="Scan batch",
    )
    return await submit_batch(parsed)


async def submit_batch(request: BatchRequest):
    """Submit a bounded batch and report every accepted and rejected target."""
    return await _submit_batch(request)


async def _submit_batch(
    request: _BatchRequestBase,
):
    """Submit a bounded batch through canonical V2 admission."""
    jobs: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    targets = list(dict.fromkeys(str(target).strip() for target in request.targets if str(target).strip()))
    for target in targets:
        req = ScanRequest(
            target=target,
            target_kind=request.target_kind,
            budget_profile=request.budget_profile,
            policy=dict(request.policy or {}),
            request_collections=[dict(item) for item in request.request_collections],
            credential_profile_ids=list(request.credential_profile_ids),
            advanced=(
                request.advanced.model_dump(exclude_none=True)
                if request.advanced is not None else None
            ),
            approval_receipt_id=request.approval_receipt_id,
            options=request.options.model_copy(deep=True),
        )
        try:
            # Keep batch admission on the exact same public path as a single Scan.
            # This preserves route-level policy hooks and prevents the batch surface
            # from quietly becoming a second admission implementation.
            jobs.append(await submit_scan(req))
        except HTTPException as exc:
            errors.append({"target": target, "status_code": exc.status_code, "error": exc.detail})
        except Exception:
            logger.exception("Batch scan submission failed for %s", target)
            errors.append({
                "target": target,
                "status_code": 500,
                "error": "Internal scan submission error",
            })

    return {
        "jobs": jobs,
        "errors": errors,
        "count": len(jobs),
        "queued_count": len(jobs),
        "failed_count": len(errors),
        "requested_count": len(targets),
        "status": "queued" if not errors else ("partial" if jobs else "failed"),
    }


@app.get("/scans")
async def list_scans(
    status: Optional[str] = None,
    target: Optional[str] = None,
    root_domain: Optional[str] = None,
    created_within_days: Optional[int] = Query(None, ge=1),
    include_shards: bool = False,
    include_internal: bool = False,
    include_model_intake: bool = False,
    include_devices: bool = False,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    include_details: bool = False,
):
    """List scans with optional filtering.

    Child shard rows, Continuous ASM implementation rows, and Model Intake
    evidence scans are hidden by default so the DAST scan list stays a web
    testing surface. Model Intake remains available from its dedicated API/UI;
    use include_model_intake for administrative or evidence-selection views.
    """
    async with db_pool.acquire() as conn:
        scan_columns = "s.*" if include_details else """
                   s.id, s.target_id, s.target_url, s.status, s.progress,
                   s.current_phase, s.options, s.scan_type, s.score, s.grade,
                   s.findings_count, s.created_at, s.started_at, s.completed_at,
                   s.duration_seconds, s.error_message, s.run_kind, s.ai_target_id,
                   s.device_target_id, s.parent_scan_id, s.scan_role,
                   s.shard_index, s.shard_count
        """
        query = f"""
            SELECT {scan_columns},
                   COALESCE(t.name, ait.name) as target_name,
                   t.root_domain,
                   ait.target_type as ai_target_type
            FROM scans s
            LEFT JOIN targets t ON s.target_id = t.id
            LEFT JOIN ai_targets ait ON s.ai_target_id = ait.id
            WHERE 1=1
        """
        count_query = """
            SELECT COUNT(*)
            FROM scans s
            LEFT JOIN targets t ON s.target_id = t.id
            LEFT JOIN ai_targets ait ON s.ai_target_id = ait.id
            WHERE 1=1
        """
        hidden_roles = _hidden_scan_roles_for_list(
            include_shards=include_shards,
            include_internal=include_internal,
        )
        if hidden_roles:
            role_values = ", ".join(f"'{role}'" for role in hidden_roles)
            role_filter = f" AND (s.scan_role IS NULL OR s.scan_role NOT IN ({role_values}))"
            query += role_filter
            count_query += role_filter

        if not include_model_intake:
            product_filter = """
                AND COALESCE(s.run_kind, '') <> 'model_intake'
                AND COALESCE(s.scan_type, '') <> 'model_intake'
            """
            query += product_filter
            count_query += product_filter

        if not include_devices:
            device_filter = """
                AND COALESCE(s.run_kind, '') NOT IN ('device_posture', 'device_probe', 'device_web_dast')
                AND COALESCE(s.scan_type, '') NOT IN ('device_posture', 'device_probe')
            """
            query += device_filter
            count_query += device_filter

        params = []
        count_params = []
        param_idx = 1
        count_param_idx = 1

        if status:
            query += f" AND s.status = ${param_idx}"
            count_query += f" AND s.status = ${count_param_idx}"
            params.append(status)
            count_params.append(status)
            param_idx += 1
            count_param_idx += 1

        if target:
            query += f" AND s.target_url ILIKE ${param_idx}"
            count_query += f" AND s.target_url ILIKE ${count_param_idx}"
            params.append(f"%{target}%")
            count_params.append(f"%{target}%")
            param_idx += 1
            count_param_idx += 1

        if root_domain:
            query += f" AND t.root_domain = ${param_idx}"
            count_query += f" AND t.root_domain = ${count_param_idx}"
            params.append(root_domain)
            count_params.append(root_domain)
            param_idx += 1
            count_param_idx += 1

        if created_within_days:
            query += f" AND s.created_at >= NOW() - INTERVAL '1 day' * ${param_idx}"
            count_query += f" AND s.created_at >= NOW() - INTERVAL '1 day' * ${count_param_idx}"
            params.append(created_within_days)
            count_params.append(created_within_days)
            param_idx += 1
            count_param_idx += 1

        query += f" ORDER BY s.created_at DESC LIMIT ${param_idx} OFFSET ${param_idx + 1}"
        params.extend([limit, offset])

        rows = await conn.fetch(query, *params)
        total = await conn.fetchval(count_query, *count_params)

    scans = []
    for row in rows:
        scan = dict(row)
        if scan.get("options") is not None:
            scan["options"] = (
                _sanitize_scan_options(scan["options"])
                if include_details
                else _scan_list_options(scan["options"])
            )
        if include_details:
            scan["execution_context"] = _json_object(scan.get("execution_context"))
        # Drop the heavy full report from list rows. The Scans page only needs
        # summary columns (status/grade/score/findings_count); returning the full
        # result for every row made this response ~9 MB for 50 scans (slow load +
        # intermittent timeouts). The detail endpoint still returns the full result.
        scan.pop("result", None)
        scan.pop("result_partial", None)
        if not include_details:
            for key in _SCAN_DETAIL_ONLY_FIELDS:
                scan.pop(key, None)
        scans.append(scan)

    return {
        'scans': scans,
        'total': total,
        'limit': limit,
        'offset': offset
    }


@app.get("/scans/{scan_id}")
async def get_scan(scan_id: str, verified_only: bool = False):
    """Get scan details."""
    async with db_pool.acquire() as conn:
        scan = await conn.fetchrow("""
            SELECT s.*,
                   COALESCE(t.name, ait.name) as target_name,
                   ait.target_type as ai_target_type
            FROM scans s
            LEFT JOIN targets t ON s.target_id = t.id
            LEFT JOIN ai_targets ait ON s.ai_target_id = ait.id
            WHERE s.id = $1
        """, uuid.UUID(scan_id))

        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        # Get findings for this scan. Verified-only filtering is applied after
        # merging raw scan-time proof below, so stale persisted retest verdicts
        # cannot hide findings that this scan just proved.
        findings = await conn.fetch("""
            SELECT id, fingerprint, title, severity, cvss_score, status, tool, url,
                   last_verification_status, last_verification_verdict, last_verification_confidence
            FROM findings WHERE scan_id = $1
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    ELSE 5
                END
        """, uuid.UUID(scan_id))

        action_rows = await conn.fetch(
            _PUBLIC_SCAN_ACTIONS_SQL, uuid.UUID(scan_id),
        )

        canonical_stage_checkpoint = None
        if scan.get("job_id"):
            try:
                canonical_stage_checkpoint = await (
                    PostgresScanStageCheckpointStore().load_prefix(
                        conn,
                        scan_id=scan_id,
                        job_id=str(scan["job_id"]),
                    )
                )
            except ScanStageCheckpointError as exc:
                logger.warning(
                    "Rejected corrupt Scan stage checkpoint",
                    extra={"scan_id": scan_id, "error": str(exc)},
                )

    result = dict(scan)
    execution_explanation = _public_scan_execution_explanation(result, action_rows)
    result['execution_context'] = _json_object(result.get('execution_context'))
    if result.get('result') is not None:
        result['result'] = _normalize_scan_result_for_api(_decode_json_value(result['result']))
    verification_overrides = _scan_result_verification_overrides(result.get('result'))
    merged_findings = []
    for row in findings:
        finding = dict(row)
        override = verification_overrides.get(str(finding.get("fingerprint") or ""))
        if override:
            finding.update(override)
        if verified_only and finding.get("last_verification_verdict") != "exploited":
            continue
        merged_findings.append(finding)
    result['findings'] = merged_findings
    if canonical_stage_checkpoint:
        result["canonical_stage_checkpoint"] = dict(
            canonical_stage_checkpoint
        )
    if result.get('options') is not None:
        result['options'] = _sanitize_scan_options(result['options'])
    result['execution_explanation'] = execution_explanation
    # Raw action authority contains internal capability arguments. Public callers
    # receive the allowlisted explanation above plus content-addressed digests.
    result.pop('scan_action_plan_json', None)

    # Surface a top-level `parallel` boolean (mirrors options.parallel and the
    # submit response, which already returns parallel:true for a parent). Without
    # this, GET detail omitted `parallel`, so clients reading `parallel` saw None
    # on a genuine parent and mis-read it as standalone. scan_role is the source
    # of truth; this is the convenience mirror that keeps the two responses consistent.
    _opts = result.get('options') if isinstance(result.get('options'), dict) else {}
    result['parallel'] = result.get('scan_role') == 'parent' or bool(_opts.get('parallel'))

    # Parent of a parallel scan: attach a live rollup of its shards so the UI
    # can show per-shard progress under the single parent row.
    if result.get('scan_role') == 'parent':
        async with db_pool.acquire() as conn:
            shard_rows = await conn.fetch("""
                SELECT id, scan_role, shard_index, status, score, grade,
                       findings_count, current_phase, progress, duration_seconds,
                       executing_node_id, worker_id, execution_context,
                       result, options
                FROM scans
                WHERE parent_scan_id = $1
                ORDER BY shard_index
        """, uuid.UUID(scan_id))
        child_rows = [row_to_dict(row) for row in shard_rows]
        discovery_rows = [
            row for row in child_rows
            if row.get('scan_role') == parallel_scan.PARALLEL_DISCOVERY_ROLE
        ]
        shards = [row for row in child_rows if row.get('scan_role') == 'shard']
        for shard in shards:
            shard['execution_context'] = _json_object(shard.get('execution_context'))
        for discovery in discovery_rows:
            discovery['execution_context'] = _json_object(discovery.get('execution_context'))
        if discovery_rows:
            discovery = discovery_rows[-1]
            result['parallel_discovery'] = _public_parallel_shard(discovery)
            if not shards and result.get('status') in {'pending', 'running'}:
                discovery_progress = int(discovery.get('progress') or 0)
                result['progress'] = min(15, max(2, int(round(discovery_progress * 0.15))))
        _attach_parallel_shard_rollup(result, shards)
    return result


@app.get("/scans/{scan_id}/deployment-decision")
async def get_scan_deployment_decision(scan_id: str):
    """Return a machine-readable deployment gate decision for CI/CD."""
    async with db_pool.acquire() as conn:
        scan = await conn.fetchrow("""
            SELECT id, target_id, status, scan_type, run_kind, result, score, grade, completed_at
            FROM scans
            WHERE id = $1
        """, uuid.UUID(scan_id))
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        target_id = scan["target_id"]
        profile_rows = await conn.fetch("""
            SELECT * FROM policy_profiles
            WHERE is_active = true
              AND (active_from IS NULL OR active_from <= NOW())
              AND (active_until IS NULL OR active_until > NOW())
        """)
        exc_rows = await conn.fetch("""
            SELECT * FROM finding_exceptions
            WHERE status IN ('active','approved','accepted_risk')
              AND (expires_at IS NULL OR expires_at > NOW())
              AND (target_id IS NULL OR target_id = $1)
        """, target_id)
        # Unresolved (active) critical/high findings on the SAME canonical origin —
        # these gate deploy even if the current scan did not re-detect them and even if
        # the origin is split across scheme/slash duplicate target rows (so scanning a
        # zero-finding duplicate cannot hide a sibling's criticals). Fail-closed.
        sibling_ids: list = [target_id] if target_id else []
        if target_id:
            this_target = await conn.fetchrow(
                "SELECT url, discovery_source FROM targets WHERE id = $1", target_id
            )
            if this_target:
                canon = _canonical_target_key(
                    this_target["url"], this_target.get("discovery_source")
                )
                all_targets = await conn.fetch("SELECT id, url, discovery_source FROM targets")
                sibling_ids = [
                    r["id"] for r in all_targets
                    if _canonical_target_key(r["url"], r.get("discovery_source")) == canon
                ] or [target_id]
        taf_rows = await conn.fetch("""
            SELECT id, fingerprint, title, severity, tool, url
            FROM findings
            WHERE target_id = ANY($1::uuid[]) AND status = 'active'
              AND severity IN ('critical', 'high')
            LIMIT 200
        """, sibling_ids) if sibling_ids else []

    target_active_findings = [{
        "id": str(r["id"]),
        "fingerprint": r["fingerprint"],
        "title": r["title"],
        "severity": r["severity"],
        "tool": r["tool"],
        "url": r["url"],
        "source": "target_active",
    } for r in taf_rows]

    db_policy_profiles: dict[str, dict[str, Any]] = {}
    for r in profile_rows:
        env = str(r["environment"] or "").strip().lower()
        if not env:
            continue
        db_policy_profiles.setdefault(env, {
            "name": r["name"],
            "environment": env,
            "minimum_block_severity": r["minimum_block_severity"],
            "expires_days": r["expires_days"],
            "strict_model_intake": r["strict_model_intake"],
            "allow_active_exceptions": r["allow_active_exceptions"],
            "required_trust_anchor_ids": _str_list(_decode_json_value(r["required_trust_anchor_ids"])),
            "owner": r["owner"],
            "version": r["version"],
            "id": env,
            "profile_id": str(r["id"]),
        })
    db_exceptions = [{
        "finding_id": r["finding_id"],
        "fingerprint": r["fingerprint"],
        "policy_id": str(r["policy_id"]) if r["policy_id"] else None,
        "status": r["status"],
        "approver": r["approver"],
        "owner": r["owner"],
        "scope": r["scope"],
        "reason": r["reason"],
        "expires_at": r["expires_at"].isoformat() if r["expires_at"] else None,
    } for r in exc_rows]

    return build_deployment_decision(
        row_to_dict(scan),
        db_policy_profiles=db_policy_profiles,
        db_exceptions=db_exceptions,
        target_active_findings=target_active_findings,
    )


# ============================================================
# POLICY PROFILES + FINDING EXCEPTIONS (durable registry, R4)
# ============================================================




















# ============================================================
# DURABLE AI SURFACE INVENTORY + ATTEMPT LEDGER (R9)
# ============================================================







@app.get("/scans/{scan_id}/ai-redteam-report")
async def get_ai_redteam_report(
    scan_id: str,
    format: str = Query("json", pattern="^(json|markdown)$"),
):
    """Export an AI red-team evidence pack for AI Gate or Model Intake scans."""
    async with db_pool.acquire() as conn:
        scan = await conn.fetchrow("""
            SELECT s.*,
                   COALESCE(t.name, ait.name) as target_name,
                   ait.target_type as ai_target_type,
                   ait.metadata_json as ai_target_metadata
            FROM scans s
            LEFT JOIN targets t ON s.target_id = t.id
            LEFT JOIN ai_targets ait ON s.ai_target_id = ait.id
            WHERE s.id = $1
        """, uuid.UUID(scan_id))

        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        findings = await conn.fetch("""
            SELECT id, fingerprint, title, description, severity, cvss_score, status,
                   tool, cwe, cwe_name, owasp, url, evidence, ai_verdict,
                   ai_confidence, ai_rationale, ai_recommendations,
                   ai_classification_source, notes, last_verification_verdict,
                   last_verification_confidence, last_verified_at, source,
                   first_seen_at, last_seen_at
            FROM findings
            WHERE scan_id = $1
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    ELSE 5
                END
        """, uuid.UUID(scan_id))

    scan_payload = row_to_dict(scan)
    scan_payload["result"] = _decode_json_value(scan_payload.get("result"))
    scan_payload["options"] = _sanitize_scan_options(scan_payload.get("options"))
    scan_payload["ai_target_metadata"] = _decode_json_value(scan_payload.get("ai_target_metadata"))
    scan_payload["findings"] = [row_to_dict(item) for item in findings]

    report = build_ai_redteam_report(
        scan_payload,
        target_metadata=scan_payload.get("ai_target_metadata"),
    )
    if format == "markdown":
        return Response(
            content=render_ai_redteam_markdown(report),
            media_type="text/markdown; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="shakerscan-ai-redteam-{scan_id}.md"'},
        )
    return report


@app.get("/scans/{scan_id}/result")
async def get_scan_result(scan_id: str):
    """Get full scan result JSON."""
    async with db_pool.acquire() as conn:
        scan = await conn.fetchrow(
            """SELECT result, status, current_phase, progress, scan_type,
                      error_message, score, grade, target_url
               FROM scans WHERE id = $1""",
            uuid.UUID(scan_id),
        )
        if not scan:
            raise HTTPException(status_code=404, detail="Scan result not found")
        if scan['result']:
            return _normalize_scan_result_for_api(_decode_json_value(scan['result']))
        # A scan row with no result is only a 404 while it is still pending/running.
        # Once it reaches a terminal state, "did work but result not found" is the
        # exact trust-boundary failure we must not have (docs §1): synthesize a
        # durable degraded result from the row so callers always get an explanation.
        if scan['status'] in ('failed', 'completed', 'cancelled'):
            return _normalize_scan_result_for_api(
                synthesize_degraded_result(
                    target_url=scan['target_url'],
                    scan_type=scan['scan_type'],
                    status=scan['status'],
                    phase=scan['current_phase'],
                    progress=scan['progress'],
                    error_message=scan['error_message'],
                    score=scan['score'],
                    grade=scan['grade'],
                )
            )
        raise HTTPException(status_code=404, detail="Scan result not found")


@app.get("/scans/{scan_id}/queue-delivery")
async def get_scan_queue_delivery(scan_id: str):
    """Return content-free Stream delivery/reclaim evidence for one scan row."""
    try:
        scan_uuid = uuid.UUID(scan_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Scan not found") from exc
    async with db_pool.acquire() as conn:
        scan = await conn.fetchrow(
            "SELECT id, job_id, status, executing_node_id, worker_id FROM scans WHERE id=$1",
            scan_uuid,
        )
        broker_delivery = await conn.fetchrow(
            """
            SELECT delivery_attempts, stream_key, message_id, consumer_name
            FROM broker_job_leases
            WHERE scan_id=$1
            ORDER BY created_at DESC
            LIMIT 1
            """,
            scan_uuid,
        )
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    metadata = _redis_hash_text(get_redis().hgetall(f"job:{scan['job_id']}")) if scan.get("job_id") else {}
    return _scan_queue_delivery_payload(scan_id, scan, metadata, broker_delivery)


def _scan_queue_delivery_payload(
    scan_id: str,
    scan: Mapping[str, Any],
    metadata: Mapping[str, str],
    broker_delivery: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Merge local Stream metadata with durable broker delivery evidence."""
    try:
        attempts = int(metadata.get("queue_delivery_attempts") or 0)
    except (TypeError, ValueError):
        attempts = 0
    if broker_delivery:
        try:
            attempts = max(attempts, int(broker_delivery.get("delivery_attempts") or 0))
        except (TypeError, ValueError):
            pass
    return {
        "scan_id": scan_id,
        "status": str(scan.get("status") or ""),
        "executing_node_id": str(scan.get("executing_node_id") or "") or None,
        "worker_id": str(scan.get("worker_id") or "") or None,
        "queue_message_id": (
            (str(broker_delivery.get("message_id") or "") if broker_delivery else "")
            or metadata.get("queue_message_id")
            or None
        ),
        "delivery_attempts": attempts,
        "reclaimed": metadata.get("queue_reclaimed", "").lower() == "true" or attempts >= 2,
        "consumer": (
            (str(broker_delivery.get("consumer_name") or "") if broker_delivery else "")
            or metadata.get("queue_consumer")
            or None
        ),
        "processing_queue": (
            (str(broker_delivery.get("stream_key") or "") if broker_delivery else "")
            or metadata.get("processing_queue")
            or None
        ),
    }


@app.get("/scans/{scan_id}/artifacts")
async def list_scan_artifacts(
    scan_id: str,
    include_deleted: bool = False,
    limit: int = Query(200, ge=1, le=500),
):
    """List the durable object manifest for a scan and its child shards."""
    try:
        scan_uuid = uuid.UUID(scan_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Scan not found") from exc
    async with db_pool.acquire() as conn:
        exists = await conn.fetchval("SELECT 1 FROM scans WHERE id=$1", scan_uuid)
        if not exists:
            raise HTTPException(status_code=404, detail="Scan not found")
        rows = await conn.fetch(
            """
            SELECT id, scan_id, parent_scan_id, shard_index, executing_node_id,
                   artifact_type, artifact_key, content_type, storage_backend,
                   content_sha256, size_bytes, status, retention_class, metadata,
                   expires_at, deleted_at, created_at, updated_at
            FROM scan_artifacts
            WHERE (scan_id=$1 OR parent_scan_id=$1)
              AND ($2 OR status <> 'deleted')
            ORDER BY created_at DESC
            LIMIT $3
            """,
            scan_uuid,
            include_deleted,
            limit,
        )
    artifacts = [row_to_dict(row) for row in rows]
    for item in artifacts:
        item["download_url"] = (
            f"/scans/{item['scan_id']}/artifacts/{item['id']}"
            if item.get("status") == "available"
            else None
        )
    return {"scan_id": scan_id, "artifacts": artifacts, "count": len(artifacts)}


@app.get("/scans/{scan_id}/artifacts/{artifact_id}")
async def download_scan_artifact(scan_id: str, artifact_id: str):
    """Proxy one artifact after validating scan ownership and its content hash."""
    try:
        scan_uuid = uuid.UUID(scan_id)
        artifact_uuid = uuid.UUID(artifact_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Artifact not found") from exc
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT * FROM scan_artifacts
            WHERE id=$1 AND scan_id=$2 AND status='available' AND deleted_at IS NULL
            """,
            artifact_uuid,
            scan_uuid,
        )
    if not row:
        raise HTTPException(status_code=404, detail="Artifact not found")
    artifact = dict(row)
    try:
        payload = await asyncio.to_thread(
            read_artifact_bytes,
            results_dir=RESULTS_DIR,
            storage_uri=str(artifact["storage_uri"]),
            expected_sha256=str(artifact["content_sha256"]),
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=410, detail="Artifact object is missing") from exc
    except ArtifactStorageError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    filename = Path(str(artifact.get("artifact_key") or "artifact.bin")).name
    safe_filename = re.sub(r"[^A-Za-z0-9_.-]+", "_", filename)[:160] or "artifact.bin"
    return Response(
        content=payload,
        media_type=str(artifact.get("content_type") or "application/octet-stream"),
        headers={
            "Content-Disposition": f'attachment; filename="{safe_filename}"',
            "ETag": f'"{artifact["content_sha256"]}"',
            "Cache-Control": "private, max-age=300",
        },
    )


@app.get("/scans/{scan_id}/logs")
async def get_scan_logs(scan_id: str, limit: int = Query(200, ge=1, le=1000)):
    """Get recent scan logs (tail)."""
    r = get_redis()
    log_key = f"scan:{scan_id}:logs"
    # Return tail lines
    try:
        lines = r.lrange(log_key, max(-limit, -1000), -1) if limit else r.lrange(log_key, -200, -1)
    except Exception:
        lines = []
    # When the displayed row is a parallel parent, its children own execution
    # and therefore own the raw log keys. Aggregate their bounded feeds so the
    # parent page does not misleadingly show "No logs yet" while shards run.
    # Model Intake activity is content-free and also stored in the durable scan
    # result. Use it when Redis live logs have expired or when an older worker
    # failed before it could emit live lines, so the UI does not become blank.
    if not lines:
        try:
            scan_uuid = uuid.UUID(str(scan_id))
        except ValueError:
            scan_uuid = None
        row = None
        shard_rows = []
        if scan_uuid is not None:
            try:
                async with db_pool.acquire() as conn:
                    row = await conn.fetchrow(
                        """
                        SELECT run_kind, scan_role, status, progress,
                               current_phase, result
                        FROM scans WHERE id=$1
                        """,
                        scan_uuid,
                    )
                    if row and str(row.get("scan_role") or "") == "parent":
                        shard_rows = await conn.fetch(
                            """
                            SELECT id, shard_index, status, current_phase
                            FROM scans
                            WHERE parent_scan_id=$1 AND scan_role='shard'
                            ORDER BY shard_index ASC NULLS LAST, created_at ASC
                            """,
                            scan_uuid,
                        )
            except Exception:
                row = None
                shard_rows = []
        if row and str(row.get("scan_role") or "") == "parent" and shard_rows:
            per_shard = max(1, min(200, limit // max(1, len(shard_rows))))
            child_logs: dict[str, list[Any]] = {}
            for shard in shard_rows:
                child_id = str(shard.get("id") or "")
                try:
                    child_logs[child_id] = r.lrange(
                        f"scan:{child_id}:logs", -per_shard, -1,
                    )
                except Exception:
                    child_logs[child_id] = []
            lines = parallel_scan_activity_lines(
                shards=shard_rows,
                child_logs=child_logs,
                limit=limit,
            )
        if not lines and row and str(row.get("run_kind") or "") == "model_intake":
            result = parse_json_field(row.get("result")) or {}
            intake = result.get("model_intake") if isinstance(result.get("model_intake"), dict) else {}
            activity = intake.get("activity") if isinstance(intake.get("activity"), list) else []
            durable_lines = [
                str(item.get("line"))[:1000]
                for item in activity
                if isinstance(item, dict) and str(item.get("line") or "").startswith("[model-intake]")
            ]
            if durable_lines:
                lines = durable_lines[-limit:]
            else:
                phase = re.sub(r"[^a-z0-9_]+", "_", str(row.get("current_phase") or "unknown").lower())[:64]
                status = re.sub(r"[^a-z0-9_]+", "_", str(row.get("status") or "unknown").lower())[:32]
                try:
                    progress = max(0, min(100, int(row.get("progress") or 0)))
                except (TypeError, ValueError):
                    progress = 0
                lines = [
                    f"[model-intake] phase={phase or 'unknown'} progress={progress} status={status or 'unknown'}",
                    "[model-intake] detail=activity_not_retained_by_earlier_worker_build",
                ][-limit:]
    return {
        "scan_id": scan_id,
        "lines": lines,
        "count": len(lines),
        "limit": limit,
    }


@app.get("/scans/{scan_id}/device-activity")
async def get_scan_device_activity(scan_id: str, limit: int = Query(100, ge=1, le=250)):
    try:
        scan_uuid = uuid.UUID(str(scan_id))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid scan ID") from exc
    async with db_pool.acquire() as conn:
        scan = await conn.fetchrow(
            """SELECT id, device_target_id, run_kind, status, progress, current_phase,
                      created_at, started_at, completed_at
               FROM scans WHERE id=$1""",
            scan_uuid,
        )
    if not scan or not scan["device_target_id"] or str(scan["run_kind"] or "") not in {"device_posture", "device_probe"}:
        raise HTTPException(status_code=404, detail="Connected-device scan not found")
    try:
        raw = get_redis().lrange(f"scan:{scan_id}:device_activity", -limit, -1)
    except Exception:
        raw = []
    events = []
    for item in raw:
        try:
            text = item.decode("utf-8", "replace") if isinstance(item, bytes) else str(item)
            event = json.loads(text)
            if isinstance(event, dict):
                events.append(event)
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
    if not events:
        events.append({
            "timestamp": (scan["started_at"] or scan["created_at"]).isoformat(),
            "kind": "status",
            "phase": str(scan["current_phase"] or scan["status"]),
            "message": str(scan["current_phase"] or scan["status"]).replace("_", " ").capitalize(),
            "progress": int(scan["progress"] or 0),
            "details": {"status": str(scan["status"])},
        })
    return {
        "scan_id": str(scan["id"]),
        "status": str(scan["status"]),
        "progress": int(scan["progress"] or 0),
        "current_phase": scan["current_phase"],
        "events": events,
        "count": len(events),
    }




# ============================================================
# TARGETS
# ============================================================





























def _legacy_credential_migration_http_error(
    exc: Exception,
) -> HTTPException:
    return HTTPException(
        status_code=409,
        detail={
            "error": "legacy_credential_migration_failed",
            "message": str(exc),
            "next_action": "Manage this identity through /credentials before retrying",
        },
    )




















async def _resolve_target_credential_profiles(
    conn: Any,
    target_id: uuid.UUID,
    options_payload: dict[str, Any],
) -> dict[str, Any]:
    """Construct content-free managed-profile refs for legacy compatibility.

    Managed secret values must never be copied into scan rows or Redis jobs.
    Canonical Scan, schedules, and ASM do not call this compatibility helper;
    they require explicit profile IDs during admission.
    """
    rows = await conn.fetch(
        """
        SELECT p.auth_state, cp.id AS profile_id, cp.auth_kind
        FROM target_principals p
        JOIN target_credential_profiles cp
          ON cp.target_id = p.target_id
         AND lower(cp.name) = lower(p.credential_profile)
        WHERE p.target_id = $1
          AND p.is_active = true
          AND cp.is_active = true
          AND (cp.expires_at IS NULL OR cp.expires_at > NOW())
          AND p.auth_state IN ('user1', 'user2')
        ORDER BY CASE p.auth_state WHEN 'user1' THEN 0 ELSE 1 END, p.updated_at DESC
        """,
        target_id,
    )
    selected: dict[str, dict[str, Any]] = {}
    for row in rows:
        payload = row_to_dict(row)
        auth_state = str(payload.get("auth_state") or "").strip()
        if auth_state in selected:
            continue
        selected[auth_state] = payload

    primary = selected.get("user1")
    secondary = selected.get("user2")
    if primary and secondary and str(primary.get("profile_id")) == str(secondary.get("profile_id")):
        raise HTTPException(
            status_code=409,
            detail={
                "error": "shared_principal_credential_profile",
                "message": "user1 and user2 must reference distinct managed credential profiles",
                "blocked_by": ["principal_credentials_not_distinct"],
            },
        )

    profile_refs: list[dict[str, str]] = []
    for auth_state in ("user1", "user2"):
        payload = selected.get(auth_state)
        if not payload:
            continue
        auth_kind = str(payload.get("auth_kind") or "")
        if auth_state == "user1":
            option_key = "auth_header" if auth_kind == "authorization_header" else "auth_cookies"
        else:
            option_key = "user2_header" if auth_kind == "authorization_header" else "user2_cookies"
        if options_payload.get(option_key):
            continue
        profile_refs.append({
            "auth_state": auth_state,
            "profile_id": str(payload.get("profile_id")),
            "option_key": option_key,
        })
    if profile_refs:
        options_payload["managed_credential_profiles"] = profile_refs
    return options_payload


async def _admit_generic_scan_credential_profiles(
    conn: Any,
    *,
    target_id: uuid.UUID,
    target_kind: str,
    profile_ids: Sequence[Any],
) -> list[dict[str, Any]]:
    """Resolve opaque Scan inputs to immutable, content-free profile references."""
    normalized: list[str] = []
    for value in profile_ids:
        try:
            profile_id = str(uuid.UUID(str(value or "")))
        except (TypeError, ValueError, AttributeError) as exc:
            raise HTTPException(
                status_code=422, detail="credential_profile_ids contains an invalid UUID"
            ) from exc
        normalized.append(profile_id)
    if not normalized:
        return []
    profiles = await _generic_credential_store.list_profiles(
        conn,
        target_kind=target_kind,
        target_id=target_id,
        include_inactive=True,
    )
    try:
        return admit_scan_credential_profiles(
            normalized,
            profiles,
            target_id=target_id,
            target_kind=target_kind,
        )
    except ScanCredentialError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc




















# --- Opt-in self-registration of test principals (Deep Hunt enabler, roadmap item #1) ----
# For an authorized open-signup target, mint managed principals through the app's OWN signup flow
# (a real registration -- never forged auth) so two-principal BOLA hunts and application-graph
# residue can run without a human hand-provisioning credentials. Strictly opt-in per target; the
# secrets are stored encrypted via the normal credential-profile path and never returned to a model.








def _provision_same_origin_url(target_url: str, path: Any) -> str:
    text = str(path or "")
    if not text.startswith("/") or text.startswith("//"):
        raise HTTPException(status_code=400, detail="auto_provisioning path must be an absolute same-origin path starting with /")
    joined = urllib.parse.urljoin(target_url, text)
    if urllib.parse.urlsplit(joined)[:2] != urllib.parse.urlsplit(target_url)[:2]:
        raise HTTPException(status_code=400, detail="auto_provisioning path escapes the target origin")
    return joined






































# ============================================================
# CONTINUOUS ASM - per-target endpoint inventory + async testing (docs §16)
# ============================================================





































async def _research_campaign_budget_snapshot(conn: Any, campaign: Any) -> dict[str, Any]:
    payload = row_to_dict(campaign)
    metadata = _decode_json_value(payload.get("metadata_json")) or {}
    config = metadata.get("autonomous_research") if isinstance(metadata.get("autonomous_research"), dict) else {}
    limits = config.get("budget_limits") if isinstance(config.get("budget_limits"), dict) else {}
    if not limits:
        limits = _research_campaign_budget_limits(
            str(config.get("intensity") or "deep_hunt"),
            int(config.get("max_episodes") or 1),
        )
    used = _research_normalize_budget_used(config.get("preflight_budget_used") or {})
    rows = await conn.fetch(
        "SELECT budget_used FROM research_episodes WHERE campaign_id=$1",
        _optional_uuid(payload.get("id")),
    )
    for row in rows:
        episode_used = _research_normalize_budget_used(_decode_json_value(row.get("budget_used")) or {})
        used = {key: int(used.get(key) or 0) + int(episode_used.get(key) or 0) for key in RESEARCH_BUDGET_KEYS}
    remaining = _research_campaign_budget_remaining(limits, used)
    return {"limits": limits, "used": used, "remaining": remaining}






def _research_finding_family(finding: Any) -> str | None:
    if not finding:
        return None
    values = []
    for key in ("category", "tool", "title", "cwe"):
        try:
            values.append(str(finding.get(key) or ""))
        except AttributeError:
            values.append("")
    text = " ".join(values).lower()
    if any(token in text for token in ("sqli", "sql injection", "cwe-89")):
        return "sqli"
    if any(token in text for token in ("xss", "cross-site scripting", "cwe-79")):
        return "xss"
    if any(token in text for token in ("bola", "idor", "object access", "cwe-639")):
        return "bola"
    if any(token in text for token in ("mass assignment", "cwe-915", "forbidden field")):
        return "mass_assignment"
    if any(token in text for token in ("auth", "session", "jwt", "cwe-287")):
        return "auth_bypass"
    if any(token in text for token in ("data exposure", "information disclosure", "cwe-200", "secret exposure")):
        return "data_exposure"
    if any(token in text for token in ("business logic", "workflow", "cwe-841")):
        return "workflow"
    return None




def _bounded_research_payload(value: Any, *, depth: int = 0) -> Any:
    """Redact and bound planner-visible observations before persistence."""
    if depth > 6:
        return "[truncated]"
    redacted = _redact_agent_payload(value)
    if isinstance(redacted, dict):
        return {
            str(key)[:120]: _bounded_research_payload(nested, depth=depth + 1)
            for key, nested in list(redacted.items())[:80]
        }
    if isinstance(redacted, list):
        return [_bounded_research_payload(item, depth=depth + 1) for item in redacted[:100]]
    if isinstance(redacted, tuple):
        return [_bounded_research_payload(item, depth=depth + 1) for item in redacted[:100]]
    if isinstance(redacted, str):
        return redacted[:4000]
    if isinstance(redacted, (int, float)) or redacted is None:  # note: bool is an int subclass
        return redacted
    # Coerce non-JSON-serializable scalars (UUID, datetime, Decimal, bytes, ...) to a bounded string
    # so the observation pack + planner payloads json.dumps cleanly. A prior command result carrying
    # raw UUIDs made _build_research_observation's json.dumps(pack) raise "Object of type UUID is not
    # JSON serializable", stranding the autopilot episode in 'dispatching'.
    return str(redacted)[:4000]










def _public_campaign_action_row(row: Any) -> dict[str, Any]:
    payload = row_to_dict(row)
    for key in (
        "finding_ids",
        "hypothesis_ids",
        "evidence_object_ids",
        "tool_receipt_ids",
        "blocked_by",
        "result_json",
    ):
        payload[key] = _decode_json_value(payload.get(key)) or ([] if key != "result_json" else {})
    return payload




def _public_campaign_row(row: Any) -> dict[str, Any]:
    payload = row_to_dict(row)
    for key in ("target_scope", "planner", "deployment_impact", "metadata_json"):
        payload[key] = _decode_json_value(payload.get(key)) or {}
    payload["execution_enabled"] = False
    return payload




def _public_hypothesis_row(row: Any) -> dict[str, Any]:
    payload = row_to_dict(row)
    for key in (
        "evidence_object_ids",
        "tool_receipt_ids",
        "promoted_finding_ids",
        "next_test_action",
        "endorsements",
        "refutations",
        "metadata_json",
    ):
        payload[key] = _decode_json_value(payload.get(key)) or ([] if key not in {"next_test_action", "metadata_json"} else {})
    lease_expires_at = _parse_hypothesis_time(payload.get("claim_lease_expires_at"))
    now = datetime.now(timezone.utc)
    claim_active = bool(payload.get("claim_owner") and lease_expires_at and lease_expires_at > now)
    claim_expired = bool(payload.get("claim_owner") and lease_expires_at and lease_expires_at <= now)
    effective_status = payload.get("status")
    if effective_status in {"claimed", "testing"} and claim_expired:
        effective_status = "open"
    payload["claim_state"] = {
        "owner": payload.get("claim_owner"),
        "lease_expires_at": payload.get("claim_lease_expires_at"),
        "active": claim_active,
        "expired": claim_expired,
        "effective_status": effective_status,
    }
    payload["effective_status"] = effective_status
    payload["claimable"] = hypothesis_lifecycle.is_actionable(effective_status) and not claim_active
    payload["can_promote_finding"] = False
    payload["can_reconcile_proof"] = bool(
        payload.get("campaign_action_id")
        and hypothesis_lifecycle.is_actionable(effective_status)
    )
    payload["execution_enabled"] = False
    return payload


def _parse_hypothesis_time(value: Any) -> Optional[datetime]:
    if not value:
        return None
    if isinstance(value, datetime):
        parsed = value
    else:
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _hypothesis_claim_active(hypothesis: dict[str, Any], now: datetime) -> bool:
    lease_expires_at = _parse_hypothesis_time(hypothesis.get("claim_lease_expires_at"))
    return bool(hypothesis.get("claim_owner") and lease_expires_at and lease_expires_at > now)


def _hypothesis_report_row(hypothesis: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": str(hypothesis.get("id") or ""),
        "target_id": str(hypothesis.get("target_id")) if hypothesis.get("target_id") else None,
        "campaign_id": str(hypothesis.get("campaign_id")) if hypothesis.get("campaign_id") else None,
        "source": hypothesis.get("source"),
        "family": hypothesis.get("family"),
        "cwe": hypothesis.get("cwe"),
        "title": hypothesis.get("title"),
        "severity_guess": hypothesis.get("severity_guess"),
        "confidence": hypothesis.get("confidence") or 0,
        "dedupe_key": hypothesis.get("dedupe_key"),
        "status": hypothesis.get("effective_status") or hypothesis.get("status"),
        "stored_status": hypothesis.get("status"),
        "effective_status": hypothesis.get("effective_status") or hypothesis.get("status"),
        "version": hypothesis.get("version") or 0,
        "claim_state": hypothesis.get("claim_state") or {
            "owner": hypothesis.get("claim_owner"),
            "lease_expires_at": hypothesis.get("claim_lease_expires_at"),
        },
        "smoke_score": hypothesis.get("smoke_score"),
        "next_test_action": hypothesis.get("next_test_action") or {},
        "terminal_reason": hypothesis.get("terminal_reason"),
        "endorsement_count": len(hypothesis.get("endorsements") or []),
        "refutation_count": len(hypothesis.get("refutations") or []),
        "updated_at": hypothesis.get("updated_at"),
        "execution_enabled": False,
        "can_promote_finding": False,
    }


def _hypothesis_missing_preconditions(hypothesis: dict[str, Any]) -> list[str]:
    action = hypothesis.get("next_test_action") or {}
    if not isinstance(action, dict):
        return []
    requirements: set[str] = set()
    for key in ("requires", "preconditions", "missing_preconditions", "missing"):
        value = action.get(key)
        if isinstance(value, str):
            if value.strip():
                requirements.add(value.strip())
        elif isinstance(value, list):
            requirements.update(str(item).strip() for item in value if str(item).strip())
        elif isinstance(value, dict):
            for name, present in value.items():
                if present is False or present is None or str(present).lower() in {"missing", "required", "false"}:
                    requirements.add(str(name).strip())
    params = action.get("parameters") if isinstance(action.get("parameters"), dict) else {}
    check_family = str(params.get("check_family") or action.get("check_family") or "").lower()
    if check_family == "auth":
        requirements.add("primary_auth")
    if check_family == "bola" and bool(params.get("exploit_depth") or action.get("exploit_depth")):
        requirements.update({"primary_auth", "second_user_auth"})
    return sorted(item for item in requirements if item)








def _hypothesis_situation_report(
    rows: Sequence[Any],
    *,
    requester: Optional[str] = None,
    limit: int = 5,
    now: Optional[datetime] = None,
    graph_context: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    now = now or datetime.now(timezone.utc)
    bounded_limit = max(1, min(int(limit or 5), 25))
    requester_key = requester.strip() if requester else None
    hypotheses = [_public_hypothesis_row(row) for row in rows]
    severity_rank = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    terminal_statuses = {"refuted", "dead"}
    status_counts = Counter(str(item.get("effective_status") or item.get("status") or "unknown") for item in hypotheses)
    source_counts = Counter(str(item.get("source") or "unknown") for item in hypotheses)
    family_counts = Counter(str(item.get("family") or "unknown") for item in hypotheses)

    def hotness(item: dict[str, Any]) -> tuple[Any, ...]:
        updated = _parse_hypothesis_time(item.get("updated_at")) or datetime.fromtimestamp(0, timezone.utc)
        return (
            severity_rank.get(str(item.get("severity_guess") or "").lower(), 0),
            float(item.get("confidence") or 0),
            float(item.get("smoke_score") or 0),
            len(item.get("endorsements") or []),
            -len(item.get("refutations") or []),
            updated,
        )

    hottest_unclaimed = [
        item
        for item in hypotheses
        if (item.get("effective_status") or item.get("status")) in {"open", "supported", "claimed", "testing"}
        and not _hypothesis_claim_active(item, now)
        and item.get("status") not in terminal_statuses
    ]
    requester_claims = [
        item
        for item in hypotheses
        if requester_key
        and item.get("claim_owner") == requester_key
        and (item.get("effective_status") or item.get("status")) in {"claimed", "testing"}
        and _hypothesis_claim_active(item, now)
    ]
    avoid_resurfacing = [item for item in hypotheses if item.get("status") in terminal_statuses]
    live_blockers = [
        item
        for item in hypotheses
        if (item.get("effective_status") or item.get("status")) in {"claimed", "testing"}
        and _hypothesis_claim_active(item, now)
        and (not requester_key or item.get("claim_owner") != requester_key)
    ]

    missing_preconditions: dict[str, dict[str, Any]] = {}
    for item in hypotheses:
        if item.get("status") in terminal_statuses:
            continue
        for requirement in _hypothesis_missing_preconditions(item):
            bucket = missing_preconditions.setdefault(
                requirement,
                {"requirement": requirement, "count": 0, "sample_hypothesis_ids": []},
            )
            bucket["count"] += 1
            if len(bucket["sample_hypothesis_ids"]) < bounded_limit:
                bucket["sample_hypothesis_ids"].append(str(item.get("id")))

    return {
        "summary": {
            "generated_at": now.isoformat(),
            "considered_count": len(hypotheses),
            "status_counts": dict(status_counts),
            "source_counts": dict(source_counts),
            "family_counts": dict(family_counts),
            "requester": requester_key,
            "limit": bounded_limit,
        },
        "hottest_unclaimed": [_hypothesis_report_row(item) for item in sorted(hottest_unclaimed, key=hotness, reverse=True)[:bounded_limit]],
        "requester_claims": [_hypothesis_report_row(item) for item in sorted(requester_claims, key=hotness, reverse=True)[:bounded_limit]],
        "avoid_resurfacing": [_hypothesis_report_row(item) for item in sorted(avoid_resurfacing, key=hotness, reverse=True)[:bounded_limit]],
        "live_blockers": [_hypothesis_report_row(item) for item in sorted(live_blockers, key=hotness, reverse=True)[:bounded_limit]],
        "missing_preconditions": sorted(missing_preconditions.values(), key=lambda item: (-item["count"], item["requirement"]))[:bounded_limit],
        "execution_enabled": False,
        "findings_created": 0,
        "board_truncated": len(hypotheses) > bounded_limit,
        "graph_context": graph_context or _empty_application_graph_context(),
    }






RISK_TIER_ORDER = {
    "read_only": 0,
    "passive": 1,
    "active": 2,
    "intrusive": 3,
    "credential": 4,
    "dangerous": 5,
}






FORBIDDEN_AGENT_CONTEXT_KEYS = {
    "authorization",
    "authorization_header",
    "auth_header",
    "bearer_token",
    "cookie",
    "cookies",
    "private_key",
    "raw_private_key",
    "raw_request",
    "raw_response",
    "raw_transcript",
    "raw_transcripts",
    "secret",
    "token",
}


def _contains_forbidden_context_key(value: Any) -> bool:
    if isinstance(value, dict):
        for key, nested in value.items():
            normalized = str(key).strip().lower()
            if normalized in FORBIDDEN_AGENT_CONTEXT_KEYS:
                return True
            if _contains_forbidden_context_key(nested):
                return True
    elif isinstance(value, list):
        return any(_contains_forbidden_context_key(item) for item in value)
    return False


def _redact_agent_text(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    scrubbed = redact_text(value)
    return re.sub(r"(?i)\bsecret[-_a-z0-9]*\b", "***", scrubbed)


def _redact_agent_payload(value: Any) -> Any:
    if isinstance(value, dict):
        out: dict[Any, Any] = {}
        for key, nested in value.items():
            normalized = str(key).strip().lower()
            if normalized in FORBIDDEN_AGENT_CONTEXT_KEYS and nested not in (None, "", [], {}):
                out[key] = "***"
            else:
                out[key] = _redact_agent_payload(nested)
        return redact_sensitive(out, redact_strings=True, scrub_text=True)
    if isinstance(value, list):
        return [_redact_agent_payload(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_redact_agent_payload(item) for item in value)
    if isinstance(value, str):
        return _redact_agent_text(value)
    return value
































# =============================================================================
# Autonomous-agent tools (slice 3). Each tool enforces scope + approval BEFORE its
# handler (borrow T3MP3ST execute() placement — containment in code, not the model):
# http_request stays on the selected target host and auth comes only from a server-resolved principal;
# writes are gated. Every tool call records a durable tool_receipt.
# =============================================================================













_AGENT_RUN_TOOL_MAX_OUTPUT = 20000
























# =============================================================================
# Autonomous ReAct loop (slice 2). Port of T3MP3ST src/agent/index.ts onto our durable
# primitives: LLM-driven observe->reason->act over the four gated tools, the four
# anti-stall mechanisms, natural stop, and a single-json-block debrief through the
# provenance gate (SUSPECTED tier). Driven by call_ai_provider (configured_ai) in
# json_object mode; the same core is reusable for a keyless planner turn.
# =============================================================================

# A single planner turn may not fan out unbounded tool calls: the model's response-token limit is
# not a dependable execution cap, so bound outbound work per turn explicitly. Extras are dropped
# with a steer to request them next turn. (External-audit P1.)










# Families whose SUSPECTED lead is promotable through the DETERMINISTIC DAST retest pipeline. Each
# maps 1:1 to a retest_contract prover type: headless-DOM XSS, DBMS SQLi/NoSQLi, OOB/timing SSRF and
# command injection, file-content path traversal, Location-header open redirect, template-eval SSTI,
# Origin-reflection CORS. The deterministic prover is the SOLE arbiter — the model supplies only the
# injection point (param+payload), never a verdict. Unlike the family_proof route, a wrong/unresolved
# URL here cannot false-VERIFY: the prover confirms actual exploitation or the finding stays SUSPECTED.
# Route-based families verify against the route WITHOUT a specific injected parameter (CORS proves via
# an Origin-header reflection probe), so the auto-queue does not require a `param` for these.
















# Auto-verify is best-effort per run: high enough to close most gate-passing claims of a hunt,
# low enough that one run cannot monopolize the deterministic verifier queue.
# Bound taxonomy and operational-skip telemetry independently. Taxonomy records cost no target
# traffic and must never be starved by approval, budget, cancellation, or execution skip noise.










def _research_episode_uses_agent_loop(episode: Any) -> bool:
    """True when this episode should be driven by the LLM ReAct hunt loop instead of the menu
    planner. Opt-in at launch (planner.agent_loop); only set for configured_ai episodes."""
    payload = row_to_dict(episode) if episode is not None and not isinstance(episode, dict) else dict(episode or {})
    planner = _decode_json_value(payload.get("planner")) or {}
    return bool(planner.get("agent_loop"))


async def _run_agent_hunt_for_episode(episode_id: str) -> dict[str, Any]:
    """Run one bounded LLM ReAct hunt bound to a research episode (target / objective / budget /
    approval), then complete the episode. This is the durable deep-hunt driver for agent_loop
    episodes: it reuses the episode lifecycle (lease + heartbeat + status, managed by the
    autopilot controller) but swaps the menu planner for the autonomous tool loop. SUSPECTED
    findings persist; the family_proof VERIFIED moat is untouched."""
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM research_episodes WHERE id=$1", uuid.UUID(episode_id))
        if not row:
            return {"accepted": True, "agent_loop": True, "error": "episode_not_found"}
        target = await conn.fetchrow("SELECT url, is_active FROM targets WHERE id=$1", row["target_id"])
    target_url = str((target or {}).get("url") or "")
    if not target_url:
        async with db_pool.acquire() as conn:
            await conn.execute(
                "UPDATE research_episodes SET status='failed', stop_reason='target_missing', "
                "updated_at=NOW() WHERE id=$1 "
                "AND status NOT IN ('cancelled','failed','completed','budget_exhausted','blocked')",
                row["id"],
            )
        return {
            "accepted": True,
            "agent_loop": True,
            "error": "target_missing",
            "episode_id": episode_id,
        }
    # Respect operator deactivation: a soft-deleted (deactivated) target must not keep being hunted
    # by an in-flight campaign. Stop cleanly rather than send more requests. (External-audit P1.)
    if not (target or {}).get("is_active"):
        async with db_pool.acquire() as conn:
            await conn.execute(
                "UPDATE research_episodes SET status='blocked', stop_reason='target_deactivated', "
                "updated_at=NOW() WHERE id=$1 AND status NOT IN ('cancelled','failed','completed')",
                row["id"],
            )
        return {"accepted": True, "agent_loop": True, "error": "target_deactivated", "episode_id": episode_id}
    raw_budget_limits = _decode_json_value(row["budget_limits"]) or {}
    budget = _research_normalize_budget_limits(
        raw_budget_limits,
        max_steps=int(raw_budget_limits.get("steps") or 1),
    )
    # Episodes created before the wire ceiling existed must not become either unbounded or
    # unusable after an upgrade. Derive one conservative, finite compatibility ceiling once
    # from their already-authorized request allowance.
    if "wire_requests" not in raw_budget_limits:
        request_allowance = max(0, int(budget.get("requests") or 0))
        budget["wire_requests"] = (
            min(3600, max(450, request_allowance * 7)) if request_allowance else 0
        )
    budget_used_before = _research_normalize_budget_used(
        _decode_json_value(row["budget_used"]) or {}
    )
    execution_mode = str(row["execution_mode"] or "read_only")
    approval_receipt_id = str(row["approval_receipt_id"]) if row["approval_receipt_id"] else None
    # A gated episode with a bound approval receipt (and the server execute switch on) unlocks
    # write/active tools; otherwise the hunt stays read-only.
    allow = execution_mode == "gated" and bool(approval_receipt_id) and _ai_ops_execute_enabled()
    if allow:
        # Re-validate the approval receipt AT HUNT TIME, not only at launch: a deep_hunt campaign
        # runs for hours and a receipt bound at launch may expire or be denied mid-campaign.
        async with db_pool.acquire() as conn:
            receipt_row = await conn.fetchrow(
                "SELECT denial_reason, expires_at FROM approval_receipts WHERE id=$1",
                _optional_uuid(approval_receipt_id),
            )
        allow = bool(receipt_row) and not receipt_row.get("denial_reason")
        if allow and receipt_row.get("expires_at"):
            async with db_pool.acquire() as conn:
                allow = bool(await conn.fetchval("SELECT $1::timestamptz > NOW()", receipt_row["expires_at"]))
    remaining_steps = max(0, int(budget.get("steps") or 0) - int(budget_used_before.get("steps") or 0))
    remaining_actions = max(0, int(budget.get("actions") or 0) - int(budget_used_before.get("actions") or 0))
    remaining_active_actions = max(
        0,
        int(budget.get("active_actions") or 0) - int(budget_used_before.get("active_actions") or 0),
    )
    remaining_requests = max(
        0,
        int(budget.get("requests") or 0) - int(budget_used_before.get("requests") or 0),
    )
    remaining_wire_requests = max(
        0,
        int(budget.get("wire_requests") or 0) - int(budget_used_before.get("wire_requests") or 0),
    )
    remaining_seconds = max(
        0,
        int(budget.get("seconds") or 0) - int(budget_used_before.get("seconds") or 0),
    )
    remaining_model_tokens = max(
        0,
        int(budget.get("model_tokens") or 0) - int(budget_used_before.get("model_tokens") or 0),
    )
    max_iters = min(remaining_steps, _AGENT_HUNT_MAX_ITERATIONS)

    async def _episode_cancelled() -> bool:
        async with db_pool.acquire() as conn:
            return bool(await conn.fetchval(
                "SELECT cancel_requested FROM research_episodes WHERE id=$1", row["id"]))

    # Run-once durability guard (External-audit P1 — the configured_ai in-process loop is not
    # per-turn checkpointed, so a mid-hunt API restart re-leases this episode and would RE-RUN the
    # whole hunt, re-issuing tool calls and — for a gated episode — create-MA POSTs). Claim a durable
    # agent_hunt_runs row for this episode; if a non-terminal ('planning') claim already exists, a
    # prior run died in flight, so FAIL CLOSED (do not re-run / duplicate state-changing work) rather
    # than resume. A fresh relaunch is the operator's recourse.
    async with db_pool.acquire() as conn:
        async with conn.transaction():
            prior = await conn.fetchrow(
                "SELECT id, status FROM agent_hunt_runs WHERE episode_id=$1 "
                "ORDER BY created_at DESC LIMIT 1 FOR UPDATE", row["id"])
            if prior is not None and str(prior["status"]) == "planning":
                await conn.execute(
                    "UPDATE agent_hunt_runs SET status='failed', stop_reason='interrupted_no_resume', "
                    "updated_at=NOW() WHERE id=$1", prior["id"])
                await conn.execute(
                    "UPDATE research_episodes SET status='failed', stop_reason='hunt_interrupted_no_resume', "
                    "updated_at=NOW() WHERE id=$1 "
                    "AND status NOT IN ('cancelled','failed','completed','budget_exhausted','blocked')",
                    row["id"])
                return {"accepted": True, "agent_loop": True, "episode_id": episode_id,
                        "status": "failed", "stop_reason": "hunt_interrupted_no_resume"}
            claim = await conn.fetchrow(
                "INSERT INTO agent_hunt_runs (target_id, episode_id, objective, status, planner_mode, "
                "max_iterations, allow_write, allow_active, approval_receipt_id, token_budget, created_by) "
                "VALUES ($1,$2,$3,'planning','configured_ai',$4,$5,$5,$6,6000,$7) RETURNING id",
                row["target_id"], row["id"], str(row["objective"] or "")[:2000], max_iters, allow,
                _optional_uuid(approval_receipt_id) if approval_receipt_id else None,
                f"deep_hunt_episode:{episode_id}")
    checkpoint_run_id = claim["id"]

    result = await _run_agent_hunt(
        row["target_id"], target_url, str(row["objective"] or ""),
        max_iterations=max_iters, created_by=f"deep_hunt_episode:{episode_id}",
        allow_write=allow, allow_active=allow, approval_receipt_id=approval_receipt_id,
        persist=True, should_stop=_episode_cancelled,
        request_budget_limit=remaining_requests,
        wire_request_budget_limit=remaining_wire_requests,
        action_budget_limit=remaining_actions,
        active_action_budget_limit=remaining_active_actions,
        wall_time_budget_seconds=remaining_seconds,
        model_token_budget_limit=remaining_model_tokens,
        research_episode_id=str(row["id"]),
        agent_hunt_run_id=str(checkpoint_run_id),
    )
    suspected = sum(1 for g in result.get("findings", []) if g.get("tier") == "suspected")
    net_new = int(result.get("net_new_count") or 0)
    verified = int(result.get("verified_count") or 0)
    stop_reason = str(result.get("stop_reason") or "")
    iterations = int(result.get("iterations") or 0)
    tool_calls = int(result.get("tool_calls_made") or 0)
    request_units = int(result.get("request_units_used") or 0)
    wire_requests = int(result.get("wire_requests_reserved") or 0)
    active_actions = int(result.get("active_actions_used") or 0)
    verify_requests = int(result.get("auto_verify_requests_reserved") or 0)
    verify_actions = int(result.get("auto_verify_actions_reserved") or 0)
    verify_active_actions = int(result.get("auto_verify_active_actions_reserved") or 0)
    verify_seconds = int(result.get("auto_verify_seconds_reserved") or 0)
    elapsed_seconds = int(result.get("elapsed_seconds") or 0)
    model_tokens = int(result.get("model_tokens_used") or 0)
    # Map the loop's stop reason to the correct terminal state so the campaign's failed/blocked
    # handling and episode ceilings are not fed a false "completed". (External-audit P2.)
    if stop_reason.startswith("budget_exhausted"):
        final_status, event_type = "budget_exhausted", "episode_budget_exhausted"
    elif stop_reason.startswith("planner_error") or stop_reason == "empty_replies":
        final_status, event_type = "failed", "episode_failed"
    elif stop_reason == "model_declined":
        final_status, event_type = "blocked", "episode_blocked"
    elif stop_reason == "cancelled":
        final_status, event_type = "cancelled", "episode_cancelled"
    else:
        final_status, event_type = "completed", "episode_completed"
    # Record durable usage so campaign aggregate budgets actually see agent-loop work (was zero).
    # Conservative: one request/action per executed tool call; active only when the episode was
    # gated for writes/active tools. (External-audit P1.)
    used = budget_used_before
    used = {**used,
            "steps": int(used.get("steps") or 0) + iterations,
            "actions": int(used.get("actions") or 0) + tool_calls + verify_actions,
            "active_actions": int(used.get("active_actions") or 0) + active_actions + verify_active_actions,
            "requests": int(used.get("requests") or 0) + request_units + verify_requests,
            "wire_requests": int(used.get("wire_requests") or 0) + wire_requests,
            "seconds": int(used.get("seconds") or 0) + elapsed_seconds + verify_seconds,
            "model_tokens": int(used.get("model_tokens") or 0) + model_tokens}
    async with db_pool.acquire() as conn:
        async with conn.transaction():
            # Only emit the terminal event if THIS update actually transitioned the episode, so a
            # concurrent cancel does not get a contradictory "completed" event written after it.
            transitioned = await conn.fetchval(
                "UPDATE research_episodes SET status=$2, stop_reason=$3, step_count=step_count+$4, "
                "budget_used=$5::jsonb, updated_at=NOW() "
                "WHERE id=$1 AND status NOT IN ('cancelled','failed','completed') RETURNING id",
                row["id"], final_status,
                f"agent_hunt: {suspected} suspected ({net_new} net-new, {verified} auto-verified), "
                f"{tool_calls} tool calls, stop={stop_reason}",
                iterations, json.dumps(used),
            )
            # Release the run-once claim ATOMICALLY with the episode terminalization: if the process
            # crashes before this transaction commits, the claim stays 'planning' (fail-closed -> a
            # re-lease refuses to re-run), never 'completed' with the episode still runnable (which
            # would repeat target traffic). (External-audit P1 — claim replay window.)
            await conn.execute(
                "UPDATE agent_hunt_runs SET status='completed', stop_reason=$2, updated_at=NOW() WHERE id=$1",
                checkpoint_run_id, stop_reason[:120])
            if transitioned:
                await _record_research_event(
                    conn, row["id"], event_type=event_type, status=final_status,
                    summary=f"Autonomous agent hunt ({final_status}): {suspected} suspected findings "
                            f"({net_new} net-new, {verified} auto-verified)",
                    details={
                        "iterations": iterations, "tool_calls_made": tool_calls,
                        "http_evidence": result.get("http_evidence_count"),
                        "stop_reason": stop_reason, "allow_active": allow, "verified": verified,
                    },
                )
    return {"accepted": True, "agent_loop": True, "episode_id": episode_id, "status": final_status,
            "suspected": suspected, "net_new": net_new, "verified": verified, "stop_reason": stop_reason}




































def _resolve_hunt_allowed_capabilities(
    contract: HuntStartContract,
    *,
    credential_access: bool,
) -> tuple[str, ...]:
    return allowed_capability_names(
        contract,
        credentials_available=credential_access,
    )














async def _validate_hunt_credential_references(
    conn: Any,
    contract: HuntStartContract,
    target_id: uuid.UUID,
) -> list[dict[str, Any]]:
    if not contract.credential_refs:
        return []
    profiles = await _generic_credential_store.list_profiles(
        conn,
        target_kind=contract.target_kind,
        target_id=target_id,
        include_inactive=True,
    )
    try:
        generic, _missing = validate_generic_credential_references(
            contract.credential_refs,
            profiles,
            target_kind=contract.target_kind,
        )
    except CredentialReferenceError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return generic


async def _start_hunt_v2(contract: HuntStartContract) -> dict[str, Any]:
    """Persist one native Hunt contract without translating authority."""
    target_uuid = _uuid_or_400(contract.target_id, "target id")
    approval_validated = False
    approval_context: Mapping[str, Any] | None = None
    budget = contract.resolved_budget_object

    async with db_pool.acquire() as conn:
        web = await conn.fetchrow(
            "SELECT id, url, name, root_domain, metadata_json, is_active FROM targets WHERE id=$1",
            target_uuid,
        )
        device = await conn.fetchrow(
            "SELECT id, name, primary_locator, device_class, is_active FROM device_targets WHERE id=$1",
            target_uuid,
        )

        if contract.target_kind in {"web", "api", "network"}:
            if not web or not web["is_active"]:
                raise HTTPException(
                    status_code=404,
                    detail="Active web/API/network target not found",
                )
            target_url = str(web["url"])
            db_target_id, device_target_id = target_uuid, None
            credential_rows = await _validate_hunt_credential_references(
                conn, contract, target_uuid,
            )
            origins = await _target_web_origins(conn, target_uuid, target_url)
            (
                collection_refs,
                _collection_endpoints,
                _collection_manifest_requests,
            ) = await _generic_collection_refs(
                conn,
                target_id=target_uuid,
                target_kind=contract.target_kind,
                bindings=[{"id": value} for value in contract.request_collection_ids],
            )
            context_pack: dict[str, Any] = {
                "schema_version": "hunt-context/v2",
                "target": {
                    "id": str(target_uuid),
                    "kind": contract.target_kind,
                    "url": target_url,
                    "origins": origins,
                    "root_domain": web["root_domain"],
                    "environment": str(
                        _hunt_json(web["metadata_json"], {}).get("environment")
                        or "unknown"
                    ),
                },
                "principal_refs_available": bool(credential_rows),
                "credential_refs": credential_rows,
                "secret_values_visible_to_planner": False,
                "request_collections": collection_refs,
                "authorized_target_addresses": await _resolve_agent_target_addresses(
                    target_url
                ),
            }
        elif contract.target_kind == "device":
            if not device or not device["is_active"]:
                raise HTTPException(status_code=404, detail="Active device target not found")
            target_url = str(device["primary_locator"])
            db_target_id, device_target_id = None, target_uuid
            credential_rows = await _validate_hunt_credential_references(
                conn, contract, target_uuid,
            )
            (
                collection_refs,
                _collection_endpoints,
                _collection_manifest_requests,
            ) = await _generic_collection_refs(
                conn,
                device_target_id=target_uuid,
                target_kind="device",
                bindings=[{"id": value} for value in contract.request_collection_ids],
            )
            device_policy_state = DeviceHuntPolicyState.initial(
                safety_profile=(
                    "authenticated_active"
                    if contract.policy.active_testing
                    and contract.policy.approval_receipt_id
                    else "safe_remote"
                ),
                fragility_limit=budget.max_device_fragility_points,
                request_limit=min(40, budget.max_http_requests),
                scan_limit=3,
            )
            context_pack = {
                "schema_version": "hunt-context/v2",
                "target": {
                    "id": str(target_uuid),
                    "kind": "device",
                    "name": device["name"],
                    "locator": target_url,
                    "device_class": device["device_class"],
                },
                "principal_refs_available": bool(credential_rows),
                "credential_refs": credential_rows,
                "secret_values_visible_to_planner": False,
                "request_collections": collection_refs,
                "authorized_target_addresses": await _resolve_agent_target_addresses(
                    (
                        target_url
                        if "://" in target_url
                        else f"http://[{target_url}]"
                        if ":" in target_url
                        else f"http://{target_url}"
                    )
                ),
                "device_policy_state": device_policy_state.public_dict(),
                "device_runtime": {
                    "schema_version": "hunt-device-runtime/v2",
                    "next_evidence_ref": 1,
                    "evidence": {},
                    "shell_plans": [],
                },
            }
        else:
            raise HTTPException(status_code=422, detail="unsupported target kind")

        privileged = bool(
            contract.policy.active_testing
            or contract.policy.network_discovery
            or contract.policy.allow_state_changing_http
            or contract.policy.allow_oob_interactions
            or credential_rows
        )
        if contract.policy.approval_receipt_id:
            approval_context = await _validate_approval_receipt_for_action(
                conn,
                contract.policy.approval_receipt_id,
                target_url=target_url,
                target_id=target_uuid,
                action_name="hunt.start.v2",
                command="hunt.start.v2",
                risk_tier=(
                    "credential"
                    if credential_rows
                    else "active" if privileged else "read_only"
                ),
                always_require_receipt=privileged,
                require_target_binding=True,
                require_expiry=True,
                created_by="hunt_v2_native",
            )
            approval_validated = True
        else:
            await _require_approval_receipt_if_policy_enabled(
                conn,
                None,
                action_name="hunt.start.v2",
                risk_tier="passive",
                created_by="hunt_v2_native",
            )

        validated_approval_id, validated_scope_id = bind_validated_receipts(
            contract.policy, approval_context,
        )
        if privileged and not approval_validated:
            raise HTTPException(
                status_code=403,
                detail=(
                    "privileged Hunt policy requires a validated target-bound "
                    "approval receipt"
                ),
            )

        credential_access = bool(credential_rows and approval_validated)
        allowed_capabilities = _resolve_hunt_allowed_capabilities(
            contract,
            credential_access=credential_access,
        )
        policy = {
            "schema_version": "hunt-policy/v2",
            "target_kind": contract.target_kind,
            "active_testing": bool(
                contract.policy.active_testing and approval_validated
            ),
            "credential_access": credential_access,
            "mutation_allowed": bool(
                contract.policy.allow_state_changing_http and approval_validated
            ),
            "allow_state_changing_http": bool(
                contract.policy.allow_state_changing_http and approval_validated
            ),
            "network_discovery": bool(
                contract.policy.network_discovery and approval_validated
            ),
            "allow_oob_interactions": bool(
                contract.policy.allow_oob_interactions and approval_validated
            ),
            "authorization_confirmed": contract.policy.authorization_confirmed,
            "approval_receipt_id": validated_approval_id,
            "scope_receipt_id": validated_scope_id,
            "device_fragility_profile": (
                "authenticated_active"
                if contract.target_kind == "device" and credential_access
                else "safe_remote" if contract.target_kind == "device" else None
            ),
            "budget_profile": contract.budget_profile,
            "budget_schema_version": HUNT_BUDGET_SCHEMA,
            "budget": asdict(budget),
            "allowed_capabilities": list(allowed_capabilities),
        }
        normalized_contract = contract.public_dict()
        normalized_contract["policy"]["approval_receipt_id"] = validated_approval_id
        normalized_contract["policy"]["scope_receipt_id"] = validated_scope_id
        context_pack["hunt_start_contract"] = normalized_contract
        if approval_context:
            context_pack["runtime_scope_guard"] = dict(
                approval_context.get("runtime_scope_guard") or {}
            )
        context_pack["allowed_capabilities"] = list(allowed_capabilities)

        row = await conn.fetchrow(
            """INSERT INTO hunt_runs (
                   target_kind, target_id, device_target_id, objective, status, budget_profile,
                   policy_json, budget_json, budget_used_json, context_pack,
                   approval_receipt_id, created_by
               ) VALUES ($1,$2,$3,$4,'active',$5,$6,$7,$8,$9,$10,'hunt_v2_native')
               RETURNING *""",
            contract.target_kind,
            db_target_id,
            device_target_id,
            contract.goal,
            contract.budget_profile,
            json.dumps(policy),
            json.dumps(asdict(budget)),
            json.dumps({
                **{key: 0 for key in budget.ledger_limits()},
                "candidates": 0,
                "verifications": 0,
            }),
            json.dumps(context_pack, default=str),
            _optional_uuid(validated_approval_id) if validated_approval_id else None,
        )
    return _hunt_public(row)


_hunt_run_service = HuntRunService(lambda: db_pool)
configure_hunt_run_router(
    lambda: _hunt_run_service,
    start_handler=_start_hunt_v2,
    metrics_provider=lambda: HUNT_ACTION_SERVICE.metrics.snapshot(),
)
app.include_router(hunt_run_router)




















# =============================================================================
# Keyless, turn-based ReAct hunt (Gap A). The default planner_mode:"agent" is KEYLESS — the
# current coding-agent session (Codex/Claude/OpenCode) is the planner, so the server cannot call
# an LLM in a loop. Instead the server suspends at each planner turn: it returns the running
# transcript as an observation, the session reasons and POSTs its next reply (a text-contract
# tool_calls block or a final debrief), and the server executes the requested tools (scope- and
# approval-gated) and returns the next observation. Same loop core, same anti-stall, same
# provenance gate, same SUSPECTED persistence as the configured_ai in-process driver — only the
# planner turn is externalized. No API key required.
# =============================================================================
























# =============================================================================
# SUSPECTED -> VERIFIED bridge (Gap B). Upgrade a provenance-gated SUSPECTED autonomous-agent
# finding to VERIFIED by running it through the EXISTING family_proof two-run verification (the
# moat) — never by trusting the agent. The server re-executes and DERIVES the verdict; a finding
# that is not a real, provable vulnerability stays SUSPECTED. Currently supports BOLA.
# =============================================================================


def _materialize_bola_verification_workflow(
    collection: str, owner_ref_key: str, attacker_ref_key: str
) -> dict[str, Any]:
    """Build a BOLA family_proof workflow from the borrowed template shape. The owner/attacker object
    ids are bound as ``principal_variables`` that resolve SERVER-SIDE from each principal's captured
    references (never model literals) — that is the only form the ownership predicate accepts as a
    managed reference (`owner_established_by_captured_ref` + distinct-reference control). Reuses the
    template's assertions/predicates verbatim; the server re-derives every predicate from live
    observations, so this supplies routes/bindings, never a verdict."""
    base = str(collection).rstrip("/")
    return {
        "proof_family": "bola",
        "principal_variables": [
            {"name": "owner_object_id", "principal": "user1", "ref": owner_ref_key},
            {"name": "attacker_object_id", "principal": "user2", "ref": attacker_ref_key},
        ],
        "steps": [
            {"label": "owner_read", "kind": "http", "principal": "user1", "checkpoint": "action",
             "method": "GET", "path": f"{base}/${{owner_object_id}}"},
            {"label": "attacker_own_read", "kind": "http", "principal": "user2", "checkpoint": "before",
             "method": "GET", "path": f"{base}/${{attacker_object_id}}"},
            {"label": "attacker_read", "kind": "http", "principal": "user2", "checkpoint": "action",
             "method": "GET", "path": f"{base}/${{owner_object_id}}", "compare_to": "owner_read"},
            {"label": "anon_denied", "kind": "http", "principal": "anonymous", "checkpoint": "action",
             "method": "GET", "path": f"{base}/${{owner_object_id}}"},
        ],
        "assertions": copy.deepcopy(_EXPERIMENT_WORKFLOW_TEMPLATES["bola"]["assertions"]),
    }


def _materialize_authbypass_verification_workflow(route: str) -> dict[str, Any]:
    """Build an auth_bypass family_proof workflow: an authenticated read and an anonymous read of
    the SAME protected route. The moat's `unauthenticated_control` predicate requires the anonymous
    body to EQUAL the authenticated protected body (Tier-0 content differential), so a 200 shell or
    a deny page cannot promote. No object ids / captured refs needed."""
    base = str(route)
    return {
        "proof_family": "auth_bypass",
        "steps": [
            {"label": "authed", "kind": "http", "principal": "user1", "checkpoint": "action",
             "method": "GET", "path": base},
            {"label": "anon", "kind": "http", "principal": "anonymous", "checkpoint": "action",
             "method": "GET", "path": base, "compare_to": "authed"},
        ],
        "assertions": copy.deepcopy(_EXPERIMENT_WORKFLOW_TEMPLATES["auth_bypass"]["assertions"]),
    }


def _materialize_dataexposure_verification_workflow(route: str) -> dict[str, Any]:
    """Build a data_exposure family_proof workflow: an authenticated baseline read and an anonymous
    read of the SAME resource. The moat's `sensitive_value_present` predicate gates on a successful
    anonymous read of a server-deemed non-public route with an entropy-tightened sensitive value
    (Tier-0), so benign/example values cannot promote. No object ids / captured refs needed."""
    base = str(route)
    return {
        "proof_family": "data_exposure",
        "steps": [
            {"label": "owner", "kind": "http", "principal": "user1", "checkpoint": "before",
             "method": "GET", "path": base},
            {"label": "exposed", "kind": "http", "principal": "anonymous", "checkpoint": "action",
             "method": "GET", "path": base},
        ],
        "assertions": copy.deepcopy(_EXPERIMENT_WORKFLOW_TEMPLATES["data_exposure"]["assertions"]),
    }


def _materialize_accesscontrol_verification_workflow(route: str) -> dict[str, Any]:
    """Build an access_control family_proof workflow: the SAME protected read issued as two
    distinct-role principals (user1, user2). The approved invariant contract's ``subject_role`` is the
    ORACLE; the invariant binder (`_trusted_invariant_execution_evidence`) derives
    authorized_role_control / forbidden_role_access / distinct_identity from each principal's
    SERVER-resolved role + identity + success — the model supplies neither the roles nor the verdict.
    GET-only, so it runs from a read-only hunt with no mutation/restoration. No static assertions: the
    invariant path derives predicates from the contract, and if the ``source="invariant"`` binding is
    ever missing the moat falls through to the corroborated-predicate path with nothing to corroborate
    -> stays SUSPECTED (fail-closed)."""
    base = str(route)
    return {
        "proof_family": "access_control",
        "steps": [
            {"label": "role_a", "kind": "http", "principal": "user1", "checkpoint": "action",
             "method": "GET", "path": base},
            {"label": "role_b", "kind": "http", "principal": "user2", "checkpoint": "action",
             "method": "GET", "path": base, "compare_to": "role_a"},
        ],
        # Empty by design: the invariant binder derives access_control predicates from the approved
        # contract + observations, not from static assertions. Present so the dispatch's
        # `dispatch_params["assertions"] = workflow["assertions"]` has a value; if the invariant
        # binding is ever missing, the moat falls through to the corroborated-predicate path with
        # nothing to corroborate -> stays SUSPECTED (fail-closed).
        "assertions": [],
    }


def _field_constraint_probe_value(operator: str, expected: Any) -> Any:
    """Return a value that VIOLATES the (operator, expected) constraint, or None if one cannot be built
    deterministically. The invariant binder recomputes `violates` from the value actually submitted, so
    a wrong/None probe only fails to persist a violation -> the finding stays SUSPECTED (never
    false-verifies). Keeps the probe the same JSON type as ``expected`` so the app accepts the write."""
    op = str(operator or "").strip().lower()

    def _num(delta: float) -> Any:
        try:
            base = float(expected)
        except (TypeError, ValueError):
            return None
        value = base + delta
        if not math.isfinite(base) or not math.isfinite(value):   # a nan/inf bound yields no usable probe
            return None
        return int(value) if isinstance(expected, int) and value.is_integer() else value

    if op in {"lte", "lt"}:       # allowed <= / < expected  ->  expected+1 exceeds it
        return _num(1)
    if op in {"gte", "gt"}:       # allowed >= / > expected  ->  expected-1 falls short
        return _num(-1)
    if op == "ne":                # allowed != expected      ->  expected itself violates
        return expected
    if op == "eq":                # allowed == expected      ->  any other value violates
        if isinstance(expected, bool):
            return not expected
        if isinstance(expected, (int, float)):
            return expected + 1
        if isinstance(expected, str):
            return (expected + "_shakerscan_violation")[:200]
        return "shakerscan_violation"
    if op == "not_in":            # allowed NOT in list      ->  a member violates
        return expected[0] if isinstance(expected, list) and expected else None
    if op == "in":                # allowed in list          ->  a non-member violates
        if not isinstance(expected, list):
            return None
        for candidate in ("shakerscan_not_in_set", 0, -1, "__none__"):
            if candidate not in expected:
                return candidate
        return None
    return None


def _materialize_fieldconstraint_verification_workflow(
    route: str, method: str, field_name: str, operator: str, expected_value: Any,
    read_path: Optional[str] = None,
) -> Optional[dict[str, Any]]:
    """Build a MUTATING field_constraint proof: read the field (baseline within the constraint) ->
    write it OUT OF BOUNDS -> read back (the out-of-bounds value persisted) -> restore -> read.

    Restoration replays the FULL captured parent object (``baseline_body`` — the write-body-shaped
    subtree at the read projection's parent), not just the probed field: a PUT-replace API gets
    every sibling field back, and the baseline value keeps its original JSON type (no stringified
    scalar restore). The invariant binder derives constraint_baseline_observed /
    constraint_violation_persisted from the observed field values vs the approved contract; the
    model supplies no verdict. Restoration is mandatory (before_after_state needs it) and
    field-scoped so a write-bumped timestamp does not mask a genuine restore. Returns None (caller
    422s -> stays SUSPECTED) when no violating probe can be built.

    ``read_path`` (contract condition) is the dotted response projection to OBSERVE the field on the
    read, for APIs whose read wraps it differently than the write body (write {field: v}; read
    $.data.field). It defaults to ``field_name`` so symmetric APIs are unchanged; the WRITE body
    always keys on ``field_name``."""
    probe = _field_constraint_probe_value(operator, expected_value)
    if probe is None or _invariant_value_allowed(probe, operator, expected_value):
        return None
    base = str(route)
    field = str(field_name)                       # WRITE body key (flat)
    read = str(read_path or field_name)
    sel = f"$.{read}"                             # READ projection (may differ for wrapping APIs)
    parent = read.rsplit(".", 1)[0] if "." in read else ""
    body_sel = f"$.{parent}" if parent else "$"   # restore body = the object the write body mirrors
    return {
        "proof_family": "field_constraint",
        "steps": [
            {"label": "before", "kind": "http", "principal": "user1", "checkpoint": "before",
             "method": "GET", "path": base, "select_json": [sel],
             "extract": [{"name": "baseline_body", "source": "json_object", "path": body_sel}]},
            {"label": "mutate", "kind": "http", "principal": "user1", "checkpoint": "mutation",
             "method": method, "path": base, "json_body": {field: probe}},
            {"label": "violation", "kind": "http", "principal": "user1", "checkpoint": "action",
             "method": "GET", "path": base, "select_json": [sel]},
            {"label": "rollback", "kind": "http", "principal": "user1", "checkpoint": "rollback",
             "method": method, "path": base, "json_body": "${baseline_body}"},
            {"label": "after", "kind": "http", "principal": "user1", "checkpoint": "after",
             "method": "GET", "path": base, "select_json": [sel], "compare_to": "before"},
        ],
        "assertions": [
            {"type": "restored", "control": "before", "candidate": "after",
             "predicate": "before_after_state", "field_scoped": True},
        ],
    }


def _materialize_workflowtransition_verification_workflow(
    route: str, method: str, field_name: str, probe_state: str, read_path: Optional[str] = None
) -> Optional[dict[str, Any]]:
    """Build a MUTATING workflow_transition proof: read the state field (baseline) -> attempt a
    FORBIDDEN transition (write ``probe_state`` — a state other than the single allowed ``to_state``)
    -> read back (the forbidden state persisted) -> restore -> read. Restoration replays the FULL
    captured parent object (``baseline_body``), preserving sibling fields and JSON types. The
    invariant binder derives transition_invariant_broken ONLY when the object started in the
    approved from_state AND the forbidden probe_state persisted; the model supplies no verdict.
    Restoration is mandatory + field-scoped. Returns None (caller 422s -> stays SUSPECTED) when the
    contract carries no probe_state. proof_family is "workflow" (the FAMILY_CONTRACTS key for
    workflow_transition)."""
    probe = str(probe_state or "").strip()
    if not probe:
        return None
    base = str(route)
    field = str(field_name)                       # WRITE body key (the state field)
    read = str(read_path or field_name)
    sel = f"$.{read}"                             # READ projection (may differ for wrapping APIs)
    parent = read.rsplit(".", 1)[0] if "." in read else ""
    body_sel = f"$.{parent}" if parent else "$"   # restore body = the object the write body mirrors
    return {
        "proof_family": "workflow",
        "steps": [
            {"label": "before", "kind": "http", "principal": "user1", "checkpoint": "before",
             "method": "GET", "path": base, "select_json": [sel],
             "extract": [{"name": "baseline_body", "source": "json_object", "path": body_sel}]},
            {"label": "mutate", "kind": "http", "principal": "user1", "checkpoint": "mutation",
             "method": method, "path": base, "json_body": {field: probe}},
            {"label": "violation", "kind": "http", "principal": "user1", "checkpoint": "action",
             "method": "GET", "path": base, "select_json": [sel]},
            {"label": "rollback", "kind": "http", "principal": "user1", "checkpoint": "rollback",
             "method": method, "path": base, "json_body": "${baseline_body}"},
            {"label": "after", "kind": "http", "principal": "user1", "checkpoint": "after",
             "method": "GET", "path": base, "select_json": [sel], "compare_to": "before"},
        ],
        "assertions": [
            {"type": "restored", "control": "before", "candidate": "after",
             "predicate": "before_after_state", "field_scoped": True},
        ],
    }


async def _resolve_approved_invariant_contract(
    conn: Any, target_uuid: uuid.UUID, kind: str, route: str, method: Optional[str]
) -> Optional[dict[str, Any]]:
    """Return the APPROVED invariant contract of ``kind`` whose canonical route matches this finding
    (and method, when a ``method`` is given), or None. The contract is the operator-declared oracle;
    without it the family cannot be soundly verified and the finding stays SUSPECTED.

    ``method`` is None/"" for families whose verify OPERATION differs from the finding's observed one:
    a field_constraint lead is observed via a GET read but exploited via the contract's WRITE method,
    which a read-only hunt never evidences — so match on route and let the contract supply the method.
    Uses the same row serializer the dispatch uses, so it is robust to the contract's column layout."""
    want_route = _canonical_vulnerability_route(route) or route
    want_method = str(method or "").upper() or None
    rows = await conn.fetch(
        "SELECT * FROM target_invariant_contracts WHERE target_id=$1 AND status='approved' "
        "ORDER BY updated_at DESC LIMIT 200",
        target_uuid,
    )
    for row in rows:
        contract = _public_target_invariant_contract_row(row)
        if str(contract.get("contract_kind") or "") != kind:
            continue
        if want_method is not None and str(contract.get("method") or "").upper() != want_method:
            continue
        contract_route = _canonical_vulnerability_route(contract.get("path")) or contract.get("path")
        if contract_route == want_route:
            return contract
    return None




# Families the bridge can currently verify. bola needs distinct captured object refs; auth_bypass
# and data_exposure are anon-vs-authed reads of a fixed route (no object ids); create-based
# mass_assignment reuses the proven server materializer; access_control is a role-differential read
# gated on an operator-APPROVED invariant contract (the role oracle a bare authz finding lacks) and
# verified by the invariant binder. Every family is verified by the UNCHANGED family_proof two-run
# moat — the bridge only supplies routes/bindings, never a verdict.
_AGENT_VERIFIABLE_FAMILIES: frozenset[str] = frozenset({"bola", "auth_bypass", "data_exposure", "mass_assignment", "access_control", "field_constraint", "workflow"})
# Families whose VERIFICATION workflow mutates the target (create-MA does live create POSTs;
# field_constraint writes an out-of-bounds value then restores; workflow_transition attempts a
# forbidden state transition then restores). These may auto-verify only from a gated (allow_write)
# hunt, never a read-only one. (External-audit BUG 3.)
# Families the loop will NOT auto-promote to VERIFIED because the family_proof cannot autonomously
# prove the finding is sound. bola: the proof shows a managed/distinct reference, not OWNERSHIP, so a
# shared-behind-login collection false-VERIFIES; that is a policy question, not something an unattended
# run can settle. These stay SUSPECTED for a human to promote (manual /verify endpoint remains).


def _verification_route_from_finding_url(url: Any) -> Optional[str]:
    """The concrete same-origin PATH a route-specific family_proof must re-execute, or None when the
    finding has no resolved route — its ``url`` is only the target base, so the path is empty or "/".

    A None MUST make the verifier abstain (the finding stays SUSPECTED). A route-specific
    access-control proof (bola / auth_bypass / data_exposure) run against the public site root
    trivially "passes" — anon == authed on a public page — which false-VERIFIES. Zero-FP hole found
    by the crAPI deep-hunt smoke: a bfla lead whose evidence cited two distinct routes had an
    ambiguous locus, so its url collapsed to the base and it verified against "/"."""
    path = urllib.parse.urlsplit(str(url or "")).path
    return path if path and path != "/" else None


@asynccontextmanager
async def _agent_finding_verification_lock(finding_uuid: uuid.UUID):
    """Cross-process, finding-scoped execution lock.

    A random workflow id cannot dedupe two callers verifying the same finding. Hold a PostgreSQL
    advisory lock across the proof so manual verification, hunt finalization, stale-turn recovery,
    and multiple API replicas cannot send duplicate target traffic for one finding.
    """
    lock_name = f"agent-finding-verification:{finding_uuid}"
    async with db_pool.acquire() as conn:
        acquired = bool(await conn.fetchval(
            "SELECT pg_try_advisory_lock(hashtextextended($1, 0))",
            lock_name,
        ))
        if not acquired:
            raise HTTPException(status_code=409, detail="Finding verification is already in progress")
        try:
            yield
        finally:
            await conn.execute(
                "SELECT pg_advisory_unlock(hashtextextended($1, 0))",
                lock_name,
            )


async def _agent_verification_workflow_for(
    conn: Any, target_uuid: uuid.UUID, family: str, path: str, method: str
) -> tuple[dict[str, Any], str, str, dict[str, Any]]:
    """Return ``(workflow, canonical_object_route, proof_method, hypothesis_metadata_extra)`` for a
    suspected finding's family, or raise HTTPException(422) when the inputs cannot support a sound
    proof. ``workflow`` with ``server_materialize=True`` means dispatch WITHOUT steps and let the
    proven create-MA server materializer build them (probe runs under the authorized dispatch)."""
    if family == "bola":
        contexts = await _resolve_workflow_principal_contexts(conn, target_uuid, {"user1", "user2"})
        targets = agent_tools.derive_bola_verification_targets(
            path,
            (contexts.get("user1") or {}).get("captured_refs"),
            (contexts.get("user2") or {}).get("captured_refs"),
        )
        if not targets:
            raise HTTPException(
                status_code=422,
                detail="insufficient distinct owned object references to build a sound BOLA proof (finding stays suspected)")
        workflow = _materialize_bola_verification_workflow(
            targets["collection"], targets["owner_ref_key"], targets["attacker_ref_key"])
        return workflow, targets["collection"].rstrip("/") + "/{id}", "GET", {}
    route = _canonical_vulnerability_route(path) or path
    if family == "auth_bypass":
        return _materialize_authbypass_verification_workflow(path), route, "GET", {}
    if family == "data_exposure":
        return _materialize_dataexposure_verification_workflow(path), route, "GET", {}
    if family == "access_control":
        # Verifiable ONLY against an operator-APPROVED access_control invariant contract for this route
        # (the role oracle a bare authz finding lacks). None -> 422 -> the finding stays SUSPECTED; the
        # server never guesses the intended policy. The two-run role-differential proof + verdict come
        # entirely from the invariant binder (source="invariant" + invariant_contract_id routes it there).
        contract = await _resolve_approved_invariant_contract(conn, target_uuid, "access_control", route, method)
        if not contract:
            raise HTTPException(
                status_code=422,
                detail="access_control verification requires an operator-approved invariant contract "
                "for this route (finding stays suspected)")
        # Steps must hit the CONCRETE path — the canonical `route` carries {id} placeholders with no
        # substitution mechanism in this (no-captured-refs) workflow, so a canonical path would 404
        # every run. Canonical `route` is only for contract matching + the dedupe dimension. (Audit M1.)
        return (
            _materialize_accesscontrol_verification_workflow(path), route, "GET",
            {"invariant_contract_id": str(contract["id"])},
        )
    if family == "field_constraint":
        # Verifiable ONLY against an operator-APPROVED field_constraint invariant contract for this
        # route. None -> 422 -> stays SUSPECTED. The MUTATING proof writes an out-of-bounds value then
        # restores the captured baseline; the binder derives the verdict from observed field values vs
        # the contract, and restoration is mandatory. Resolve by ROUTE only: a read-only hunt evidences
        # a GET of the object, never the write, so the CONTRACT supplies the write method. Steps hit the
        # CONCRETE path (canonical route is for matching/dedupe only). (Audit M1.)
        contract = await _resolve_approved_invariant_contract(conn, target_uuid, "field_constraint", route, None)
        if not contract:
            raise HTTPException(
                status_code=422,
                detail="field_constraint verification requires an operator-approved invariant contract "
                "for this route (finding stays suspected)")
        write_method = str(contract.get("method") or "").upper()
        read_path = str((contract.get("conditions") or {}).get("read_path") or "") or None
        workflow = _materialize_fieldconstraint_verification_workflow(
            path, write_method, str(contract.get("field_name") or ""),
            str(contract.get("operator") or ""), contract.get("expected_value"), read_path)
        if workflow is None:
            raise HTTPException(
                status_code=422,
                detail="cannot construct a violating probe for this field_constraint contract "
                "(finding stays suspected)")
        return workflow, route, write_method, {"invariant_contract_id": str(contract["id"])}
    if family == "workflow":
        # Verifiable ONLY against an operator-APPROVED workflow_transition invariant contract for this
        # route. None -> 422 -> stays SUSPECTED. Resolve by ROUTE (the contract supplies the WRITE
        # method + the forbidden probe_state; a read-only hunt evidences only a GET). The MUTATING proof
        # attempts the forbidden transition then restores the captured baseline; the binder derives the
        # verdict from observed states vs the approved from->to. Steps hit the CONCRETE path.
        contract = await _resolve_approved_invariant_contract(conn, target_uuid, "workflow_transition", route, None)
        if not contract:
            raise HTTPException(
                status_code=422,
                detail="workflow_transition verification requires an operator-approved invariant "
                "contract for this route (finding stays suspected)")
        write_method = str(contract.get("method") or "").upper()
        conditions = contract.get("conditions") or {}
        read_path = str(conditions.get("read_path") or "") or None
        workflow = _materialize_workflowtransition_verification_workflow(
            path, write_method, str(contract.get("field_name") or ""),
            str(conditions.get("probe_state") or ""), read_path)
        if workflow is None:
            raise HTTPException(
                status_code=422,
                detail="workflow_transition contract has no probe_state (forbidden target) to test "
                "(finding stays suspected)")
        return workflow, route, write_method, {"invariant_contract_id": str(contract["id"])}
    if family == "mass_assignment":
        # Create-based only: dispatch with NO steps so _server_materialize_create_ma probes the create
        # surface and builds the role=admin overpost workflow (a wrong field is falsified by the proof).
        # Update-based (PUT/PATCH a privileged field) is not yet supported by the bridge.
        if str(method or "").upper() != "POST":
            raise HTTPException(
                status_code=422,
                detail="mass_assignment verification requires an explicitly evidenced POST create operation",
            )
        return {"proof_family": "mass_assignment", "server_materialize": True}, route, "POST", {"create_based": True}
    raise HTTPException(status_code=422, detail=f"verification bridge supports {sorted(_AGENT_VERIFIABLE_FAMILIES)}, not '{family or 'unknown'}'")


async def _verify_suspected_finding_workflow_unlocked(
    finding_uuid: uuid.UUID, approval_receipt_id: str, *, created_by: str
) -> dict[str, Any]:
    """Core of the SUSPECTED->VERIFIED bridge (Gap B): run ONE suspected autonomous-agent finding
    through the EXISTING family_proof two-run verification. The moat is unchanged — the server
    re-executes the workflow twice and derives the verdict from server-corroborated predicates; the
    agent's claim is never trusted. Raises HTTPException on guard failures (the manual endpoint
    surfaces them; the auto-verify path catches them). Supports bola / auth_bypass / data_exposure."""
    if not _ai_ops_execute_enabled():
        raise HTTPException(status_code=400, detail="execution_feature_disabled")
    async with db_pool.acquire() as conn:
        finding = await conn.fetchrow("SELECT * FROM findings WHERE id=$1", finding_uuid)
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")
        if str(finding["tool"] or "") != "autonomous_agent" or str(finding["source"] or "") != "autonomous":
            raise HTTPException(status_code=409, detail="Not a suspected autonomous-agent finding")
        if str(finding["status"] or "") != "active":
            raise HTTPException(status_code=409, detail="Only an active suspected finding can be verified")
        if str(finding["last_verification_verdict"] or "") == "exploited":
            raise HTTPException(status_code=409, detail="Finding is already verified")
        target = await conn.fetchrow("SELECT id, url, is_active FROM targets WHERE id=$1", finding["target_id"])
        if not target or not target["is_active"]:
            raise HTTPException(status_code=404, detail="Active target not found")
        target_uuid = finding["target_id"]
        target_url = str(target["url"])
        evidence = _decode_json_value(finding["evidence"]) or {}
        family = family_proof.canonical_family(evidence.get("family") or _research_finding_family(finding))
        if family not in _AGENT_VERIFIABLE_FAMILIES:
            raise HTTPException(status_code=422, detail=f"verification bridge supports {sorted(_AGENT_VERIFIABLE_FAMILIES)}, not '{family or 'unknown'}'")
        # Zero-FP: a route-specific access-control proof must re-execute against the finding's
        # CONCRETE route. An unresolved route (url == target base -> path "/") would false-VERIFY an
        # auth_bypass/data_exposure proof against the public site root, so abstain -> stays SUSPECTED.
        path = _verification_route_from_finding_url(finding["url"])
        if path is None:
            raise HTTPException(
                status_code=422,
                detail="verification_route_unresolved: finding has no concrete protected route to "
                "re-execute (ambiguous evidence locus); it stays SUSPECTED",
            )
        _, _, _, finding_method, _, _, _ = _finding_family_route_method(finding)
        # Family-dispatched workflow build (raises 422 on insufficient inputs -> stays suspected).
        workflow, object_route, method, extra_metadata = await _agent_verification_workflow_for(
            conn, target_uuid, family, path, str(finding_method or ""))
        # Gate: a valid, target-bound approval receipt for the credential-tier workflow action.
        await _validate_approval_receipt_for_action(
            conn, approval_receipt_id, target_url=target_url, target_id=str(target_uuid),
            action_name="experiment.workflow", command="experiment.workflow", risk_tier="credential",
            require_target_binding=True, created_by=created_by)
        dedupe_dimensions = {"route": object_route, "method": method}
        severity = str(finding["severity"] or "high")
        if severity not in {"critical", "high", "medium", "low", "info"}:
            severity = "high"
        # An invariant-backed verification (access_control) MUST stamp source="invariant" +
        # metadata.invariant_contract_id (threaded via extra_metadata), or _arsenal_dispatch_workflow
        # silently skips the invariant binder. That skip is fail-closed — the finding then stays
        # SUSPECTED, never false-verifies — but the feature only works when the binding is present.
        invariant_backed = bool(extra_metadata.get("invariant_contract_id"))
        hyp = await _upsert_hypothesis(conn, HypothesisRequest(
            source="invariant" if invariant_backed else "ai_planner", family=family,
            dedupe_key=f"agent_verify:{family}:{object_route}:{method}",
            dedupe_dimensions=dedupe_dimensions,
            target_id=str(target_uuid),
            title=str(finding["title"] or f"{family} (agent-suspected)")[:200],
            severity_guess=severity, confidence=0.5,
            metadata_json={"route": object_route, "method": method, "dedupe_dimensions": dedupe_dimensions,
                           "source_suspected_finding_id": str(finding_uuid), **extra_metadata},
            created_by=created_by))
        hypothesis_id = str(hyp["hypothesis"]["id"])

    # Dispatch the family_proof workflow (the moat verifies via two-run re-execution). A
    # server-materialized family (create-MA) dispatches WITHOUT steps so _server_materialize_create_ma
    # probes the create surface and builds them under the authorized dispatch.
    dispatch_params: dict[str, Any] = {
        "target_id": str(target_uuid), "workflow_id": str(uuid.uuid4()),
        "proof_family": workflow["proof_family"],
        "_research_hypothesis_id": hypothesis_id,
    }
    if not workflow.get("server_materialize"):
        dispatch_params["steps"] = workflow["steps"]
        dispatch_params["assertions"] = workflow["assertions"]
        if workflow.get("principal_variables"):
            dispatch_params["principal_variables"] = workflow["principal_variables"]
    try:
        result = await _arsenal_dispatch_workflow(dispatch_params, approval_receipt_id)
    except HTTPException as exc:
        return {"finding_id": str(finding_uuid), "verified": False, "hypothesis_id": hypothesis_id,
                "error": exc.detail}

    proof = result.get("family_proof") or {}
    promotion = result.get("promotion") or {}
    verified_finding_id = str(promotion.get("finding_id")) if isinstance(promotion, dict) and promotion.get("finding_id") else None
    # The promotion upgrades the SAME vuln-key row in place (relabeled tool='autonomous_workflow',
    # verdict='exploited'), so a suspected->verified upgrade normally lands on THIS finding's row —
    # nothing to supersede. Only if the moat wrote a DIFFERENT row do we resolve this suspected one.
    upgraded_in_place = bool(verified_finding_id) and verified_finding_id == str(finding_uuid)
    superseded = False
    if verified_finding_id and not upgraded_in_place:
        async with db_pool.acquire() as conn:
            await conn.execute(
                "UPDATE findings SET status='resolved', updated_at=NOW(), "
                "notes=(COALESCE(notes,'') || $2::text) WHERE id=$1 AND status='active'",
                finding_uuid, f" [superseded by verified finding {verified_finding_id}]")
        superseded = True
    return {
        "finding_id": str(finding_uuid),
        "verified": bool(verified_finding_id),
        "verified_finding_id": verified_finding_id,
        "upgraded_in_place": upgraded_in_place,
        "hypothesis_id": hypothesis_id,
        "proof_state": result.get("proof_state"),
        "family_proof": {"verdict": proof.get("verdict"), "promotable": proof.get("promotable"),
                         "novelty_gate": proof.get("novelty_gate")},
        "superseded_suspected": superseded,
    }


async def _verify_web_candidate_workflow_unlocked(
    candidate_uuid: uuid.UUID, approval_receipt_id: str, *, created_by: str,
) -> dict[str, Any]:
    """Verify a candidate directly; a findings row is materialized only after proof succeeds."""
    if not _ai_ops_execute_enabled():
        raise HTTPException(status_code=400, detail="execution_feature_disabled")
    async with db_pool.acquire() as conn:
        candidate = await conn.fetchrow(
            """SELECT * FROM investigation_candidates
               WHERE id=$1 AND plane='web' FOR UPDATE""",
            candidate_uuid,
        )
        if not candidate:
            raise HTTPException(status_code=404, detail="Investigation candidate not found")
        if str(candidate["status"] or "") == "verified":
            raise HTTPException(status_code=409, detail="Candidate is already verified")
        target = await conn.fetchrow(
            "SELECT id, url, is_active FROM targets WHERE id=$1",
            candidate["target_id"],
        )
        if not target or not target["is_active"]:
            raise HTTPException(status_code=404, detail="Active target not found")
        locus = _decode_json_value(candidate["canonical_locus"]) or {}
        context = _decode_json_value(candidate["verification_context"]) or {}
        family = family_proof.canonical_family(candidate["family"])
        if family not in _AGENT_VERIFIABLE_FAMILIES:
            raise HTTPException(
                status_code=422,
                detail=f"verification bridge supports {sorted(_AGENT_VERIFIABLE_FAMILIES)}, not '{family or 'unknown'}'",
            )
        route = str(locus.get("route") or locus.get("url") or context.get("route") or "").strip()
        if route.startswith("http://") or route.startswith("https://"):
            route = urllib.parse.urlsplit(route).path or "/"
        if not route or route == "/":
            raise HTTPException(status_code=422, detail="verification_route_unresolved")
        method_hint = str(locus.get("method") or context.get("method") or "GET")
        workflow, object_route, method, extra_metadata = await _agent_verification_workflow_for(
            conn, candidate["target_id"], family, route, method_hint,
        )
        await _validate_approval_receipt_for_action(
            conn,
            approval_receipt_id,
            target_url=str(target["url"]),
            target_id=str(candidate["target_id"]),
            action_name="experiment.workflow",
            command="experiment.workflow",
            risk_tier="credential",
            require_target_binding=True,
            created_by=created_by,
        )
        invariant_backed = bool(extra_metadata.get("invariant_contract_id"))
        hyp = await _upsert_hypothesis(conn, HypothesisRequest(
            source="invariant" if invariant_backed else "ai_planner",
            family=family,
            dedupe_key=f"candidate_verify:{candidate_uuid}:{family}:{object_route}:{method}",
            dedupe_dimensions={"route": object_route, "method": method},
            target_id=str(candidate["target_id"]),
            title=str(candidate["title"] or f"{family} candidate")[:200],
            severity_guess=str(candidate["claimed_severity"] or "high"),
            confidence=0.5,
            metadata_json={
                "route": object_route,
                "method": method,
                "source_candidate_id": str(candidate_uuid),
                **extra_metadata,
            },
            created_by=created_by,
        ))
        hypothesis_id = str(hyp["hypothesis"]["id"])
        await conn.execute(
            "UPDATE investigation_candidates SET status='verifying', updated_at=NOW() WHERE id=$1",
            candidate_uuid,
        )
    dispatch_params: dict[str, Any] = {
        "target_id": str(candidate["target_id"]),
        "workflow_id": str(uuid.uuid4()),
        "proof_family": workflow["proof_family"],
        "_research_hypothesis_id": hypothesis_id,
    }
    if not workflow.get("server_materialize"):
        dispatch_params["steps"] = workflow["steps"]
        dispatch_params["assertions"] = workflow["assertions"]
        if workflow.get("principal_variables"):
            dispatch_params["principal_variables"] = workflow["principal_variables"]
    try:
        result = await _arsenal_dispatch_workflow(dispatch_params, approval_receipt_id)
    except HTTPException as exc:
        async with db_pool.acquire() as conn:
            await conn.execute(
                """UPDATE investigation_candidates SET status='inconclusive',
                   verification_context=verification_context || jsonb_build_object('error',$2::text),
                   updated_at=NOW() WHERE id=$1""",
                candidate_uuid, str(exc.detail)[:500],
            )
        return {"finding_id": str(candidate_uuid), "candidate_id": str(candidate_uuid),
                "verified": False, "hypothesis_id": hypothesis_id, "error": exc.detail}
    except Exception as exc:
        async with db_pool.acquire() as conn:
            await conn.execute(
                """UPDATE investigation_candidates SET status='inconclusive',
                   verification_context=verification_context || jsonb_build_object('error',$2::text),
                   updated_at=NOW() WHERE id=$1""",
                candidate_uuid, f"workflow_verifier_error:{type(exc).__name__}"[:500],
            )
        raise
    proof = result.get("family_proof") or {}
    promotion = result.get("promotion") or {}
    verified_finding_id = (
        str(promotion.get("finding_id"))
        if isinstance(promotion, dict) and promotion.get("finding_id") else None
    )
    candidate_status = (
        "verified" if verified_finding_id
        else "refuted" if str(proof.get("verdict") or "") == "refuted"
        else "inconclusive"
    )
    proof_observation = _redact_finding_evidence(proof)
    async with db_pool.acquire() as conn:
        async with conn.transaction():
            verification_id = await conn.fetchval(
                """INSERT INTO finding_verifications (
                       finding_id, candidate_id, target_id, requested_by, status, result_status,
                       verdict, verdict_reason, finding_type, target_url, original_url, proof,
                       confidence, verification_mode, contract_id, contract_version, proof_basis,
                       started_at, completed_at, updated_at
                   ) VALUES ($1::uuid,$2,$3,$4,'completed',$5,$6,$7,$8,$9,$9,$10::jsonb,
                             $11,'deterministic',$12,'family-proof/v2',$13,NOW(),NOW(),NOW())
                   RETURNING id""",
                uuid.UUID(verified_finding_id) if verified_finding_id else None,
                candidate_uuid,
                candidate["target_id"],
                created_by[:120],
                "success" if verified_finding_id else candidate_status,
                "exploited" if verified_finding_id else str(proof.get("verdict") or candidate_status),
                "Server-owned family proof completed",
                family,
                str(target["url"]),
                json.dumps(proof_observation),
                1.0 if verified_finding_id else None,
                str(candidate["verifier_contract_id"] or f"web.{family}"),
                str(proof.get("proof_basis") or "two_run_family_proof"),
            )
            proof_hash = hashlib.sha256(
                json.dumps(proof_observation, sort_keys=True, separators=(",", ":"), default=str).encode()
            ).hexdigest()
            await conn.execute(
                """INSERT INTO evidence_instances (
                       finding_id, candidate_id, target_id, proof_observation, hash, proof_state,
                       evidence_strength, contract_id, contract_version, proof_basis, created_by
                   ) VALUES ($1::uuid,$2,$3,$4::jsonb,$5,$6,$7,$8,'family-proof/v2',$9,$10)""",
                uuid.UUID(verified_finding_id) if verified_finding_id else None,
                candidate_uuid,
                candidate["target_id"],
                json.dumps(proof_observation),
                proof_hash,
                candidate_status,
                "reproduced" if verified_finding_id else "signal",
                str(candidate["verifier_contract_id"] or f"web.{family}"),
                str(proof.get("proof_basis") or "two_run_family_proof"),
                created_by[:120],
            )
            await conn.execute(
                """UPDATE investigation_candidates
                   SET status=$2, latest_verification_id=$3,
                       verification_context=verification_context || jsonb_build_object(
                           'finding_id',$4::text,'verdict',$5::text,'proof',$6::jsonb
                       ), updated_at=NOW()
                   WHERE id=$1""",
                candidate_uuid, candidate_status, verification_id,
                verified_finding_id, str(proof.get("verdict") or candidate_status),
                json.dumps(proof_observation),
            )
    return {
        "finding_id": str(candidate_uuid),
        "candidate_id": str(candidate_uuid),
        "verified": bool(verified_finding_id),
        "verified_finding_id": verified_finding_id,
        "upgraded_in_place": False,
        "hypothesis_id": hypothesis_id,
        "proof_state": result.get("proof_state"),
        "family_proof": {
            "verdict": proof.get("verdict"),
            "promotable": proof.get("promotable"),
            "novelty_gate": proof.get("novelty_gate"),
        },
        "superseded_suspected": False,
    }


async def _verify_suspected_finding_workflow(
    finding_uuid: uuid.UUID, approval_receipt_id: str, *, created_by: str
) -> dict[str, Any]:
    async with _agent_finding_verification_lock(finding_uuid):
        async with db_pool.acquire() as conn:
            is_candidate = await conn.fetchval(
                "SELECT EXISTS(SELECT 1 FROM investigation_candidates WHERE id=$1 AND plane='web')",
                finding_uuid,
            )
        if is_candidate:
            return await _verify_web_candidate_workflow_unlocked(
                finding_uuid,
                approval_receipt_id,
                created_by=created_by,
            )
        return await _verify_suspected_finding_workflow_unlocked(
            finding_uuid,
            approval_receipt_id,
            created_by=created_by,
        )


















def _normalize_hypothesis_dedupe_value(value: Any, *, lower: bool = False) -> Optional[str]:
    if value is None:
        return None
    text = re.sub(r"\s+", " ", str(value).strip())
    if not text:
        return None
    text = text.replace("|", "%7C")
    return text.lower().replace(" ", "_") if lower else text


def _canonical_hypothesis_dedupe_dimensions(payload: dict[str, Any], metadata: dict[str, Any]) -> dict[str, str]:
    raw = payload.get("dedupe_dimensions") if isinstance(payload.get("dedupe_dimensions"), dict) else {}
    metadata_dims = metadata.get("dedupe_dimensions") if isinstance(metadata.get("dedupe_dimensions"), dict) else {}
    merged = {**metadata_dims, **raw}
    principal_pair = merged.get("principal_pair") if isinstance(merged.get("principal_pair"), dict) else {}
    route = (
        merged.get("route")
        or merged.get("endpoint")
        or merged.get("consumer_route")
        or metadata.get("route")
        or metadata.get("consumer_route")
    )
    method = merged.get("method") or metadata.get("method")
    object_key = merged.get("object_key") or merged.get("object") or metadata.get("object_key")
    actor = (
        merged.get("principal_actor")
        or merged.get("actor")
        or principal_pair.get("actor")
        or metadata.get("source_principal")
    )
    other = (
        merged.get("principal_other")
        or merged.get("other")
        or principal_pair.get("other")
        or metadata.get("excluded_principal")
    )
    tenant = merged.get("tenant") or principal_pair.get("tenant") or metadata.get("tenant")
    parameter_path = merged.get("parameter_path") or merged.get("param") or metadata.get("parameter_path")
    body_path = merged.get("body_path") or metadata.get("body_path")
    proof_surface = merged.get("proof_surface") or metadata.get("proof_surface")

    dims = {
        "method": _normalize_hypothesis_dedupe_value(method, lower=True),
        "route": _normalize_hypothesis_dedupe_value(route),
        "object_key": _normalize_hypothesis_dedupe_value(object_key),
        "principal_actor": _normalize_hypothesis_dedupe_value(actor),
        "principal_other": _normalize_hypothesis_dedupe_value(other),
        "tenant": _normalize_hypothesis_dedupe_value(tenant),
        "parameter_path": _normalize_hypothesis_dedupe_value(parameter_path),
        "body_path": _normalize_hypothesis_dedupe_value(body_path),
        "proof_surface": _normalize_hypothesis_dedupe_value(proof_surface, lower=True),
    }
    return {key: value for key, value in dims.items() if value}


def _hypothesis_dedupe_key_from_dimensions(family: str, dimensions: dict[str, str]) -> str:
    ordered_keys = (
        "method",
        "route",
        "object_key",
        "principal_actor",
        "principal_other",
        "tenant",
        "parameter_path",
        "body_path",
        "proof_surface",
    )
    parts = [f"family={family}"]
    parts.extend(f"{key}={dimensions[key]}" for key in ordered_keys if dimensions.get(key))
    return "hypothesis:v1|" + "|".join(parts)


def _canonical_hypothesis_request(req: HypothesisRequest) -> dict[str, Any]:
    payload = req.model_dump(mode="json")
    family = str(payload.get("family") or "").strip().lower().replace(" ", "_")
    source = str(payload.get("source") or "").strip()
    metadata = _redact_agent_payload(payload.get("metadata_json") or {})
    dedupe_dimensions = _canonical_hypothesis_dedupe_dimensions(payload, metadata)
    if dedupe_dimensions:
        metadata["dedupe_dimensions"] = dedupe_dimensions
        dedupe_key = _hypothesis_dedupe_key_from_dimensions(family, dedupe_dimensions)
    else:
        dedupe_key = str(payload.get("dedupe_key") or "").strip()
    endorsement = payload.get("endorsement") if isinstance(payload.get("endorsement"), dict) else {}
    if not endorsement:
        endorsement = {
            "source": source,
            "created_by": str(payload.get("created_by") or "").strip() or None,
            "confidence": payload.get("confidence"),
        }
    else:
        endorsement = _redact_agent_payload(endorsement)
    return {
        **payload,
        "source": source,
        "family": family,
        "dedupe_key": dedupe_key,
        "dedupe_dimensions": dedupe_dimensions,
        "cwe": str(payload.get("cwe") or "").strip() or None,
        "title": _redact_agent_text(str(payload.get("title") or "").strip()) or None,
        "description": _redact_agent_text(str(payload.get("description") or "").strip()) or None,
        "evidence_object_ids": _clean_string_list(payload.get("evidence_object_ids"), max_items=100),
        "tool_receipt_ids": _clean_string_list(payload.get("tool_receipt_ids"), max_items=100),
        "next_test_action": _redact_agent_payload(payload.get("next_test_action") or {}),
        "metadata_json": metadata,
        "endorsement": endorsement,
        "created_by": str(payload.get("created_by") or "").strip() or None,
    }




















































# Finding-delta integrity heuristic: a target whose latest scan reports far more findings
# than its own recent baseline is worth a refuter look. Universal (not benchmark-specific):
# a spike can be a real new exposure, a detector regression, or contaminated/benchmark-fit
# output. Thresholds are deliberately conservative to avoid noise on small, noisy targets.


def _median(values: Sequence[float]) -> float:
    ordered = sorted(float(v) for v in values)
    count = len(ordered)
    if count == 0:
        return 0.0
    mid = count // 2
    if count % 2:
        return ordered[mid]
    return (ordered[mid - 1] + ordered[mid]) / 2.0










































def _canonical_hash_payload(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()




def _canonical_tool_receipt(req: ToolReceiptRequest) -> dict[str, Any]:
    payload = req.model_dump(mode="json")
    redacted_argv = _redact_agent_payload(payload.get("redacted_argv") or [])
    target_scope = _redact_agent_payload(payload.get("target_scope") or {})
    metadata = _redact_agent_payload(payload.get("metadata_json") or {})
    command_hash = str(payload.get("command_hash") or "").strip()
    if command_hash and not re.fullmatch(r"[a-fA-F0-9]{64}", command_hash):
        raise HTTPException(status_code=400, detail="command_hash must be sha256 hex when provided")
    if not command_hash:
        command_hash = _canonical_hash_payload({
            "tool_name": payload.get("tool_name"),
            "redacted_argv": redacted_argv,
            "target_scope": target_scope,
            "metadata_json": metadata,
        })
    return {
        "tool_name": str(payload.get("tool_name") or "").strip(),
        "capability_name": str(payload.get("capability_name") or "").strip() or None,
        "adapter_name": str(payload.get("adapter_name") or "").strip() or None,
        "tool_version": str(payload.get("tool_version") or "").strip() or None,
        "adapter_version": str(payload.get("adapter_version") or "2026-07-05.v1").strip() or "2026-07-05.v1",
        "command_hash": command_hash.lower(),
        "redacted_argv": redacted_argv,
        "worker_build": str(payload.get("worker_build") or "").strip() or None,
        "container_image": str(payload.get("container_image") or "").strip() or None,
        "target_scope": target_scope,
        "scope_receipt_id": str(payload.get("scope_receipt_id") or "").strip() or None,
        "approval_receipt_id": str(payload.get("approval_receipt_id") or "").strip() or None,
        "policy_profile_id": str(payload.get("policy_profile_id") or "").strip() or None,
        "status": payload.get("status") or "recorded",
        "parser_status": payload.get("parser_status") or "not_run",
        "exit_code": payload.get("exit_code"),
        "timed_out": bool(payload.get("timed_out")),
        "started_at": _parse_hypothesis_time(payload.get("started_at")),
        "finished_at": _parse_hypothesis_time(payload.get("finished_at")),
        "stdout_evidence_object_id": str(payload.get("stdout_evidence_object_id") or "").strip() or None,
        "stderr_evidence_object_id": str(payload.get("stderr_evidence_object_id") or "").strip() or None,
        "parsed_evidence_instance_ids": _clean_string_list(payload.get("parsed_evidence_instance_ids"), max_items=500),
        "budget_json": _redact_agent_payload(payload.get("budget_json") or {}),
        "partial": bool(payload.get("partial")),
        "output_artifact_id": str(payload.get("output_artifact_id") or "").strip() or None,
        "hunt_id": str(payload.get("hunt_id") or "").strip() or None,
        "redaction_summary": _redact_agent_text(str(payload.get("redaction_summary") or "").strip()) or None,
        "metadata_json": metadata,
        "created_by": str(payload.get("created_by") or "").strip() or None,
    }


async def _record_tool_receipt(conn, req: ToolReceiptRequest) -> dict[str, Any]:
    payload = _canonical_tool_receipt(req)
    try:
        approval_uuid = _optional_uuid(payload.get("approval_receipt_id"))
        policy_uuid = _optional_uuid(payload.get("policy_profile_id"))
        stdout_uuid = _optional_uuid(payload.get("stdout_evidence_object_id"))
        stderr_uuid = _optional_uuid(payload.get("stderr_evidence_object_id"))
        output_artifact_uuid = _optional_uuid(payload.get("output_artifact_id"))
        hunt_uuid = _optional_uuid(payload.get("hunt_id"))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="receipt and evidence object ids must be UUIDs when provided") from exc
    row = await conn.fetchrow(
        """
        INSERT INTO tool_receipts (
            tool_name, tool_version, adapter_version, command_hash, redacted_argv,
            worker_build, container_image, target_scope, scope_receipt_id,
            approval_receipt_id, policy_profile_id, status, parser_status,
            exit_code, timed_out, started_at, finished_at, stdout_evidence_object_id,
            stderr_evidence_object_id, parsed_evidence_instance_ids, redaction_summary,
            metadata_json, created_by, capability_name, adapter_name, budget_json, partial,
            output_artifact_id, hunt_id
        ) VALUES (
            $1,$2,$3,$4,$5::jsonb,
            $6,$7,$8::jsonb,$9,
            $10,$11,$12,$13,
            $14,$15,$16,$17,$18,
            $19,$20::jsonb,$21,
            $22::jsonb,$23,$24,$25,$26::jsonb,$27,
            $28,$29
        )
        RETURNING *
        """,
        payload["tool_name"],
        payload.get("tool_version"),
        payload["adapter_version"],
        payload["command_hash"],
        json.dumps(payload.get("redacted_argv") or []),
        payload.get("worker_build"),
        payload.get("container_image"),
        json.dumps(payload.get("target_scope") or {}),
        payload.get("scope_receipt_id"),
        approval_uuid,
        policy_uuid,
        payload["status"],
        payload["parser_status"],
        payload.get("exit_code"),
        payload["timed_out"],
        payload.get("started_at"),
        payload.get("finished_at"),
        stdout_uuid,
        stderr_uuid,
        json.dumps(payload.get("parsed_evidence_instance_ids") or []),
        payload.get("redaction_summary"),
        json.dumps(payload.get("metadata_json") or {}),
        payload.get("created_by"),
        payload.get("capability_name"),
        payload.get("adapter_name"),
        json.dumps(payload.get("budget_json") or {}),
        payload["partial"],
        output_artifact_uuid,
        hunt_uuid,
    )
    return {
        "tool_receipt": _public_tool_receipt_row(row),
        "execution_enabled": False,
        "findings_created": 0,
        "verified_findings_created": 0,
    }






def _canonical_evidence_instance(req: EvidenceInstanceRequest) -> dict[str, Any]:
    payload = req.model_dump(mode="json")
    request_refs = _clean_string_list(payload.get("request_response_refs"), max_items=100)
    principal_pair = _redact_agent_payload(payload.get("principal_pair") or {})
    proof_observation = _redact_agent_payload(payload.get("proof_observation") or {})
    metadata = _redact_agent_payload(payload.get("metadata_json") or {})
    instance_hash = str(payload.get("hash") or "").strip()
    if instance_hash and not re.fullmatch(r"[a-fA-F0-9]{64}", instance_hash):
        raise HTTPException(status_code=400, detail="hash must be sha256 hex when provided")
    if not instance_hash:
        instance_hash = _canonical_hash_payload({
            "finding_id": payload.get("finding_id"),
            "evidence_object_id": payload.get("evidence_object_id"),
            "concrete_url": payload.get("concrete_url"),
            "object_id": payload.get("object_id"),
            "payload_variant": payload.get("payload_variant"),
            "request_response_refs": request_refs,
            "principal_pair": principal_pair,
            "proof_observation": proof_observation,
            "tool_receipt_id": payload.get("tool_receipt_id"),
        })
    return {
        "finding_id": str(payload.get("finding_id") or "").strip() or None,
        "evidence_object_id": str(payload.get("evidence_object_id") or "").strip() or None,
        "scan_id": str(payload.get("scan_id") or "").strip() or None,
        "target_id": str(payload.get("target_id") or "").strip() or None,
        "concrete_url": _redact_agent_text(str(payload.get("concrete_url") or "").strip()) if payload.get("concrete_url") else None,
        "object_id": str(payload.get("object_id") or "").strip() or None,
        "payload_variant": _redact_agent_text(str(payload.get("payload_variant") or "").strip()) if payload.get("payload_variant") else None,
        "request_response_refs": request_refs,
        "principal_pair": principal_pair,
        "proof_observation": proof_observation,
        "campaign_action_id": str(payload.get("campaign_action_id") or "").strip() or None,
        "tool_receipt_id": str(payload.get("tool_receipt_id") or "").strip() or None,
        "redaction_profile": str(payload.get("redaction_profile") or "redact_sensitive_v1").strip() or "redact_sensitive_v1",
        "hash": instance_hash.lower(),
        "retention_policy": payload.get("retention_policy") or "standard",
        "proof_state": payload.get("proof_state") or "unverified",
        "evidence_strength": str(payload.get("evidence_strength") or "").strip() or None,
        "metadata_json": metadata,
        "created_by": str(payload.get("created_by") or "").strip() or None,
    }


async def _record_evidence_instance(conn, req: EvidenceInstanceRequest) -> dict[str, Any]:
    payload = _canonical_evidence_instance(req)
    try:
        finding_uuid = _optional_uuid(payload.get("finding_id"))
        evidence_uuid = _optional_uuid(payload.get("evidence_object_id"))
        scan_uuid = _optional_uuid(payload.get("scan_id"))
        target_uuid = _optional_uuid(payload.get("target_id"))
        campaign_action_uuid = _optional_uuid(payload.get("campaign_action_id"))
        tool_receipt_uuid = _optional_uuid(payload.get("tool_receipt_id"))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="evidence instance ids must be UUIDs when provided") from exc
    row = await conn.fetchrow(
        """
        INSERT INTO evidence_instances (
            finding_id, evidence_object_id, scan_id, target_id, concrete_url,
            object_id, payload_variant, request_response_refs, principal_pair,
            proof_observation, campaign_action_id, tool_receipt_id,
            redaction_profile, hash, retention_policy, proof_state,
            evidence_strength, metadata_json, created_by
        ) VALUES (
            $1,$2,$3,$4,$5,
            $6,$7,$8::jsonb,$9::jsonb,
            $10::jsonb,$11,$12,
            $13,$14,$15,$16,
            $17,$18::jsonb,$19
        )
        RETURNING *
        """,
        finding_uuid,
        evidence_uuid,
        scan_uuid,
        target_uuid,
        payload.get("concrete_url"),
        payload.get("object_id"),
        payload.get("payload_variant"),
        json.dumps(payload.get("request_response_refs") or []),
        json.dumps(payload.get("principal_pair") or {}),
        json.dumps(payload.get("proof_observation") or {}),
        campaign_action_uuid,
        tool_receipt_uuid,
        payload["redaction_profile"],
        payload["hash"],
        payload["retention_policy"],
        payload["proof_state"],
        payload.get("evidence_strength"),
        json.dumps(payload.get("metadata_json") or {}),
        payload.get("created_by"),
    )
    return {
        "evidence_instance": _public_evidence_instance_row(row),
        "execution_enabled": False,
        "findings_updated": 0,
    }












async def _upsert_hypothesis(conn, req: HypothesisRequest) -> dict[str, Any]:
    payload = _canonical_hypothesis_request(req)
    try:
        target_uuid = _optional_uuid(payload.get("target_id"))
        campaign_uuid = _optional_uuid(payload.get("campaign_id"))
        campaign_action_uuid = _optional_uuid(payload.get("campaign_action_id"))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="target_id, campaign_id, and campaign_action_id must be UUIDs when provided") from exc
    existing = await conn.fetchrow(
        """
        SELECT *
        FROM hypotheses
        WHERE COALESCE(target_id, '00000000-0000-0000-0000-000000000000'::uuid)
              = COALESCE($1::uuid, '00000000-0000-0000-0000-000000000000'::uuid)
          AND family = $2
          AND dedupe_key = $3
        LIMIT 1
        """,
        target_uuid,
        payload["family"],
        payload["dedupe_key"],
    )
    endorsement = {
        **(payload.get("endorsement") or {}),
        "recorded_at": datetime.now(timezone.utc).isoformat(),
    }
    if existing:
        row = await conn.fetchrow(
            """
            UPDATE hypotheses
            SET confidence = GREATEST(confidence, $2),
                smoke_score = GREATEST(COALESCE(smoke_score, 0), COALESCE($3, 0)),
                evidence_object_ids = COALESCE((
                    SELECT jsonb_agg(DISTINCT value)
                    FROM jsonb_array_elements_text(evidence_object_ids || $4::jsonb) AS value
                ), '[]'::jsonb),
                tool_receipt_ids = COALESCE((
                    SELECT jsonb_agg(DISTINCT value)
                    FROM jsonb_array_elements_text(tool_receipt_ids || $5::jsonb) AS value
                ), '[]'::jsonb),
                next_test_action = COALESCE($6::jsonb, next_test_action),
                endorsements = endorsements || jsonb_build_array($7::jsonb),
                metadata_json = metadata_json || $8::jsonb,
                version = version + 1,
                updated_at = NOW()
            WHERE id = $1
            RETURNING *
            """,
            existing["id"],
            float(payload.get("confidence") or 0),
            payload.get("smoke_score"),
            json.dumps(payload.get("evidence_object_ids") or []),
            json.dumps(payload.get("tool_receipt_ids") or []),
            json.dumps(payload.get("next_test_action")) if payload.get("next_test_action") else None,
            json.dumps(endorsement),
            json.dumps(payload.get("metadata_json") or {}),
        )
        return {"hypothesis": _public_hypothesis_row(row), "created": False, "execution_enabled": False}

    row = await conn.fetchrow(
        """
        INSERT INTO hypotheses (
            target_id, campaign_id, campaign_action_id, source, family, cwe,
            title, description, severity_guess, confidence, dedupe_key,
            smoke_score, evidence_object_ids, tool_receipt_ids, next_test_action,
            endorsements, metadata_json, created_by
        ) VALUES (
            $1,$2,$3,$4,$5,$6,
            $7,$8,$9,$10,$11,
            $12,$13::jsonb,$14::jsonb,$15::jsonb,
            jsonb_build_array($16::jsonb),$17::jsonb,$18
        )
        ON CONFLICT (COALESCE(target_id, '00000000-0000-0000-0000-000000000000'::uuid), family, dedupe_key)
        DO UPDATE SET
            confidence = GREATEST(hypotheses.confidence, EXCLUDED.confidence),
            endorsements = hypotheses.endorsements || EXCLUDED.endorsements,
            version = hypotheses.version + 1,
            updated_at = NOW()
        RETURNING *
        """,
        target_uuid,
        campaign_uuid,
        campaign_action_uuid,
        payload["source"],
        payload["family"],
        payload.get("cwe"),
        payload.get("title"),
        payload.get("description"),
        payload.get("severity_guess"),
        float(payload.get("confidence") or 0),
        payload["dedupe_key"],
        payload.get("smoke_score"),
        json.dumps(payload.get("evidence_object_ids") or []),
        json.dumps(payload.get("tool_receipt_ids") or []),
        json.dumps(payload.get("next_test_action") or {}),
        json.dumps(endorsement),
        json.dumps(payload.get("metadata_json") or {}),
        payload.get("created_by"),
    )
    return {"hypothesis": _public_hypothesis_row(row), "created": True, "execution_enabled": False}


async def _record_campaign_action_from_command_result(
    conn,
    command_result: dict[str, Any],
    *,
    target_id: str | uuid.UUID | None = None,
) -> dict[str, Any] | None:
    """Best-effort campaign/action audit row paired with a CommandResult.

    Command results remain the broad audit record. Campaign actions are the
    mission-timeline execution records the roadmap calls for: action-oriented,
    claimable later, and still unable to influence findings without downstream
    proof/evidence contracts.
    """
    try:
        command_result_id = _optional_uuid(command_result.get("id"))
        row = await conn.fetchrow(
            """
            INSERT INTO campaign_actions (
                campaign_id, operation_plan_id, command_result_id, target_id,
                scope_receipt_id, approval_receipt_id, scan_id, command,
                action_name, status, dry_run, risk_tier, finding_ids,
                hypothesis_ids, evidence_object_ids, tool_receipt_ids,
                blocked_by, next_action, operator_message, result_json, created_by
            ) VALUES (
                $1,$2,$3,$4,
                $5,$6,$7,$8,
                $9,$10,$11,$12,$13::jsonb,
                $14::jsonb,$15::jsonb,$16::jsonb,
                $17::jsonb,$18,$19,$20::jsonb,$21
            )
            RETURNING *
            """,
            _optional_uuid(command_result.get("campaign_id")),
            _optional_uuid(command_result.get("operation_plan_id")),
            command_result_id,
            _optional_uuid(target_id),
            command_result.get("scope_receipt_id") or None,
            _optional_uuid(command_result.get("approval_receipt_id")),
            _optional_uuid(command_result.get("scan_id")),
            str(command_result.get("command") or "").strip(),
            str(command_result.get("command") or "").strip(),
            str(command_result.get("status") or "").strip(),
            bool(command_result.get("dry_run")),
            str(command_result.get("risk_tier") or "read_only").strip(),
            json.dumps(command_result.get("finding_ids") or []),
            json.dumps(command_result.get("hypothesis_ids") or []),
            json.dumps(command_result.get("evidence_object_ids") or []),
            json.dumps(command_result.get("tool_receipt_ids") or []),
            json.dumps(command_result.get("blocked_by") or []),
            command_result.get("next_action"),
            command_result.get("operator_message"),
            json.dumps(redact_sensitive(command_result.get("result_json") or {}, redact_strings=True, scrub_text=True)),
            command_result.get("created_by"),
        )
        return _public_campaign_action_row(row)
    except Exception:
        return None


async def _record_command_result(
    conn,
    *,
    command: str,
    status: str,
    risk_tier: str,
    operator_message: str,
    dry_run: bool = False,
    operation_plan_id: str | uuid.UUID | None = None,
    scope_receipt_id: str | None = None,
    approval_receipt_id: str | uuid.UUID | None = None,
    campaign_id: str | uuid.UUID | None = None,
    target_id: str | uuid.UUID | None = None,
    scan_id: str | uuid.UUID | None = None,
    finding_ids: list[str] | None = None,
    hypothesis_ids: list[str] | None = None,
    evidence_object_ids: list[str] | None = None,
    tool_receipt_ids: list[str] | None = None,
    blocked_by: list[str] | None = None,
    next_action: str | None = None,
    result_json: dict[str, Any] | None = None,
    created_by: str | None = None,
) -> dict[str, Any]:
    effective_created_by = _ARSENAL_CREATED_BY_CONTEXT.get() or created_by
    row = await conn.fetchrow(
        """
        INSERT INTO command_results (
            command, status, dry_run, risk_tier, operation_plan_id,
            scope_receipt_id, approval_receipt_id, campaign_id, scan_id,
            finding_ids, hypothesis_ids, evidence_object_ids, tool_receipt_ids,
            blocked_by, next_action, operator_message, result_json, created_by
        ) VALUES (
            $1,$2,$3,$4,$5,
            $6,$7,$8,$9,
            $10::jsonb,$11::jsonb,$12::jsonb,$13::jsonb,
            $14::jsonb,$15,$16,$17::jsonb,$18
        )
        RETURNING *
        """,
        str(command or "").strip(),
        status,
        bool(dry_run),
        risk_tier,
        _optional_uuid(operation_plan_id),
        str(scope_receipt_id) if scope_receipt_id else None,
        _optional_uuid(approval_receipt_id),
        _optional_uuid(campaign_id),
        _optional_uuid(scan_id),
        json.dumps(finding_ids or []),
        json.dumps(hypothesis_ids or []),
        json.dumps(evidence_object_ids or []),
        json.dumps(tool_receipt_ids or []),
        json.dumps(blocked_by or []),
        next_action,
        operator_message,
        json.dumps(redact_sensitive(result_json or {}, redact_strings=True, scrub_text=True)),
        effective_created_by,
    )
    result = _public_command_result_row(row)
    await _record_campaign_action_from_command_result(conn, result, target_id=target_id)
    return result


def _command_from_action(action_name: str) -> str:
    """Map an enforcement action_name (e.g. 'scan.submit:quick') to a command name."""
    base = str(action_name or "").split(":", 1)[0].strip()
    return base or "state_changing_action"


async def _record_blocked_command_result(
    conn,
    *,
    action_name: str,
    blocked_by: list[str],
    operator_message: str,
    status: str = "blocked",
    risk_tier: str = "active",
    command: str | None = None,
    scope_receipt_id: str | None = None,
    approval_receipt_id: str | uuid.UUID | None = None,
    created_by: str | None = None,
) -> dict[str, Any] | None:
    """Best-effort audit row for an action rejected by policy/scope before it queued.

    This is what makes "nothing ran, because X blocked it" auditable with the same
    operation id / receipt refs / blocked reasons as a successful queue. It is
    best-effort on purpose: an audit-write failure must never mask or alter the
    security rejection that is about to be raised.
    """
    try:
        return await _record_command_result(
            conn,
            command=command or _command_from_action(action_name),
            status=status,
            risk_tier=risk_tier,
            operator_message=operator_message,
            blocked_by=list(blocked_by or []),
            scope_receipt_id=scope_receipt_id,
            approval_receipt_id=approval_receipt_id,
            result_json={"action": action_name, "outcome": status},
            created_by=created_by,
        )
    except Exception:
        return None


def _context_pack_target_scope(context_pack: dict[str, Any]) -> dict[str, Any]:
    target_summary = context_pack.get("target_summary") if isinstance(context_pack.get("target_summary"), dict) else {}
    url = str(target_summary.get("url") or "").strip()
    host = ""
    if url:
        parsed = urllib.parse.urlparse(url if "://" in url else f"https://{url}")
        host = parsed.hostname or ""
    allowed_hosts = target_summary.get("allowed_hosts") if isinstance(target_summary.get("allowed_hosts"), list) else []
    if not allowed_hosts and host:
        allowed_hosts = [host]
    return {
        "target_id": target_summary.get("target_id"),
        "url": url,
        "allowed_hosts": allowed_hosts,
        "allowed_root_domains": target_summary.get("allowed_root_domains") or ([target_summary.get("root_domain")] if target_summary.get("root_domain") else []),
        "environment": target_summary.get("environment") or "unknown",
    }


def _context_pack_payload_from_row(row: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    context_row = _public_agent_context_pack_row(row)
    context_pack = context_row.get("context_pack") if isinstance(context_row.get("context_pack"), dict) else {}
    if not context_pack:
        context_pack = {
            "target_summary": context_row.get("target_summary") or {},
            "current_surface": context_row.get("current_surface") or {},
            "current_gaps": context_row.get("current_gaps") or [],
            "hypotheses_summary": context_row.get("hypotheses_summary") or [],
            "findings_summary": context_row.get("findings_summary") or [],
            "allowed_commands": context_row.get("allowed_commands") or [],
            "disallowed_commands": context_row.get("disallowed_commands") or [],
            "known_preconditions": context_row.get("known_preconditions") or {},
            "context_hash": context_row.get("context_hash"),
        }
    return context_row, context_pack










def _json_size_bytes(value: Any) -> int:
    try:
        return len(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8"))
    except TypeError:
        return len(str(value).encode("utf-8"))


def _validate_bounded_agent_parameters(
    value: Any,
    *,
    path: str,
    errors: list[str],
    max_depth: int = 6,
) -> None:
    if max_depth < 0:
        errors.append(f"{path}_too_deep")
        return
    if isinstance(value, dict):
        if len(value) > 50:
            errors.append(f"{path}_too_many_keys")
        for key, nested in value.items():
            _validate_bounded_agent_parameters(
                nested,
                path=f"{path}.{str(key).strip() or '<empty>'}",
                errors=errors,
                max_depth=max_depth - 1,
            )
    elif isinstance(value, list):
        if len(value) > 100:
            errors.append(f"{path}_too_many_items")
        for index, nested in enumerate(value[:101]):
            _validate_bounded_agent_parameters(
                nested,
                path=f"{path}[{index}]",
                errors=errors,
                max_depth=max_depth - 1,
            )
    elif isinstance(value, str) and len(value) > 2000:
        errors.append(f"{path}_string_too_long")


def _scope_hosts(scope: dict[str, Any]) -> tuple[set[str], set[str]]:
    hosts = {
        _canonical_receipt_host(item)
        for item in scope.get("allowed_hosts", [])
        if str(item or "").strip()
    }
    roots = {
        _canonical_receipt_host(item)
        for item in scope.get("allowed_root_domains", [])
        if str(item or "").strip()
    }
    url = str(scope.get("url") or "").strip()
    if url:
        parsed = urllib.parse.urlparse(url if "://" in url else f"https://{url}")
        if parsed.hostname:
            hosts.add(_canonical_receipt_host(parsed.hostname))
    return hosts, roots


def _host_allowed_by_scope(host: str, allowed_hosts: set[str], allowed_roots: set[str]) -> bool:
    candidate = _canonical_receipt_host(host)
    if candidate in allowed_hosts:
        return True
    return any(candidate == root or candidate.endswith(f".{root}") for root in allowed_roots)


def _validate_candidate_target_scope(
    candidate_scope: Any,
    context_scope: dict[str, Any],
    errors: list[str],
) -> None:
    if not isinstance(candidate_scope, dict) or not candidate_scope:
        errors.append("target_scope_required")
        return
    expected_target = str(context_scope.get("target_id") or "").strip()
    candidate_target = str(candidate_scope.get("target_id") or "").strip()
    if expected_target and candidate_target and candidate_target != expected_target:
        errors.append("target_scope_target_id_mismatch")

    allowed_hosts, allowed_roots = _scope_hosts(context_scope)
    candidate_hosts, candidate_roots = _scope_hosts(candidate_scope)
    for host in sorted(candidate_hosts):
        if not _host_allowed_by_scope(host, allowed_hosts, allowed_roots):
            errors.append(f"target_scope_host_outside_context:{host}")
    for root in sorted(candidate_roots):
        if root not in allowed_roots and root not in allowed_hosts:
            errors.append(f"target_scope_root_outside_context:{root}")


def _disallowed_commands_from_context(context_pack: dict[str, Any]) -> set[str]:
    disallowed: set[str] = set()
    for item in context_pack.get("disallowed_commands") or []:
        if isinstance(item, dict):
            command = str(item.get("command") or "").strip()
            if command:
                disallowed.add(command)
        else:
            command = str(item or "").strip()
            if command:
                disallowed.add(command)
    return disallowed








def _canonical_receipt_host(value: Any) -> str:
    host = str(value or "").strip().strip("[]").lower()
    if host.endswith("."):
        host = host[:-1]
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return host


def _host_matches_receipt_scope(host: str, scope: dict[str, Any]) -> bool:
    candidate = _canonical_receipt_host(host)
    normalized = _decode_json_value(scope.get("normalized_scope")) or {}
    allowed_hosts = _decode_json_value(scope.get("allowed_hosts")) or []
    allowed_roots = _decode_json_value(scope.get("allowed_root_domains")) or []
    normalized_host = _canonical_receipt_host(normalized.get("host") if isinstance(normalized, dict) else "")
    if normalized_host and candidate == normalized_host:
        return True
    for allowed in allowed_hosts if isinstance(allowed_hosts, list) else []:
        if candidate == _canonical_receipt_host(allowed):
            return True
    for root in allowed_roots if isinstance(allowed_roots, list) else []:
        root_host = _canonical_receipt_host(root)
        if candidate == root_host or candidate.endswith(f".{root_host}"):
            return True
    return False


async def _validate_approval_receipt_for_action(
    conn,
    approval_receipt_id: str | None,
    *,
    target_url: str | None = None,
    target_id: str | uuid.UUID | None = None,
    action_name: str = "state_changing_action",
    command: str | None = None,
    risk_tier: str = "active",
    record_blocked: bool = True,
    created_by: str | None = None,
    always_require_receipt: bool = False,
    require_target_binding: bool = False,
    required_action_name: str | None = None,
    required_action_context: dict[str, Any] | None = None,
    require_expiry: bool = False,
    created_not_before: datetime | str | None = None,
    expires_no_later_than: datetime | str | None = None,
) -> dict[str, Any] | None:
    async def _deny(
        reason: str,
        message: str,
        *,
        http_status: int = 400,
        approval_ref: str | None = None,
        scope_ref: str | None = None,
    ):
        # Persist a durable "blocked" audit row before raising so a rejected
        # request is as auditable as a queued one. FK-safe: only pass receipt
        # refs whose rows actually exist.
        if record_blocked:
            await _record_blocked_command_result(
                conn,
                action_name=action_name,
                command=command,
                risk_tier=risk_tier,
                status="blocked",
                blocked_by=[reason],
                operator_message=f"Blocked {_command_from_action(action_name)}: {message}",
                approval_receipt_id=approval_ref,
                scope_receipt_id=scope_ref,
                created_by=created_by,
            )
        raise HTTPException(status_code=http_status, detail=message)

    if not approval_receipt_id:
        if always_require_receipt:
            await _deny("approval_receipt_required", "Approval receipt is required")
        await _require_approval_receipt_if_policy_enabled(
            conn, None, action_name=action_name, command=command, risk_tier=risk_tier, created_by=created_by
        )
        return None
    try:
        approval_uuid = uuid.UUID(str(approval_receipt_id))
    except ValueError:
        await _deny("approval_receipt_id_invalid_uuid", "approval_receipt_id must be a UUID")

    approval_row = await conn.fetchrow("SELECT * FROM approval_receipts WHERE id=$1", approval_uuid)
    if not approval_row:
        await _deny("approval_receipt_not_found", "Approval receipt not found", http_status=404)
    approval_ref = str(approval_uuid)
    approval = _public_approval_receipt_row(approval_row)
    if approval.get("status") == "revoked":
        await _deny(
            "approval_receipt_revoked",
            "Approval receipt is revoked",
            approval_ref=approval_ref,
        )
    if not approval.get("approved_by") or approval.get("denial_reason"):
        await _deny("approval_receipt_is_denial", "Approval receipt is not an approval", approval_ref=approval_ref)
    approved_risk = str(approval.get("risk_tier") or "active")
    if RISK_TIER_ORDER.get(approved_risk, -1) < RISK_TIER_ORDER.get(str(risk_tier or "active"), 999):
        await _deny(
            "approval_receipt_risk_too_low",
            "Approval receipt risk tier does not cover the requested action",
            approval_ref=approval_ref,
        )
    confirmations = approval.get("confirmations") if isinstance(approval.get("confirmations"), list) else []
    if "confirm_authorized" not in confirmations:
        await _deny("approval_receipt_missing_confirm_authorized", "Approval receipt is missing confirm_authorized", approval_ref=approval_ref)
    expires_at = approval_row["expires_at"]
    if require_expiry and not expires_at:
        await _deny(
            "approval_receipt_expiry_required",
            "Approval receipt must have a bounded expiry for this action",
            approval_ref=approval_ref,
        )
    if expires_at:
        now = datetime.now(timezone.utc)
        if expires_at.tzinfo is None:
            now = utc_now()
        if expires_at <= now:
            await _deny("approval_receipt_expired", "Approval receipt is expired", approval_ref=approval_ref)
        latest_expiry = _parse_hypothesis_time(expires_no_later_than)
        normalized_expiry = _parse_hypothesis_time(expires_at)
        if latest_expiry and normalized_expiry and normalized_expiry > latest_expiry:
            await _deny(
                "approval_receipt_expiry_too_long",
                "Approval receipt outlives the bound action preview",
                approval_ref=approval_ref,
            )
    earliest_creation = _parse_hypothesis_time(created_not_before)
    if earliest_creation:
        approval_created_at = _parse_hypothesis_time(approval.get("created_at"))
        if not approval_created_at or approval_created_at < earliest_creation:
            await _deny(
                "approval_receipt_predates_preview",
                "Approval receipt predates the bound action preview",
                approval_ref=approval_ref,
            )

    receipt_action_name = str(approval.get("action_name") or "").strip()
    if receipt_action_name and receipt_action_name != str(action_name or "").strip():
        await _deny(
            "approval_receipt_action_mismatch",
            "Approval receipt is bound to a different action",
            approval_ref=approval_ref,
        )
    if required_action_name and receipt_action_name != required_action_name:
        await _deny(
            "approval_receipt_action_mismatch",
            "Approval receipt is not bound to this action",
            approval_ref=approval_ref,
        )
    expected_context = required_action_context or {}
    actual_context = approval.get("action_context") if isinstance(approval.get("action_context"), dict) else {}
    for key, expected in expected_context.items():
        if str(actual_context.get(key) or "") != str(expected or ""):
            await _deny(
                "approval_receipt_context_mismatch",
                f"Approval receipt is not bound to this {key}",
                approval_ref=approval_ref,
            )

    scope_id = approval.get("scope_receipt_id")
    if not scope_id:
        await _deny("approval_receipt_no_scope", "Approval receipt is not linked to a scope receipt", approval_ref=approval_ref)
    scope_row = await conn.fetchrow("SELECT * FROM scope_receipts WHERE id=$1", str(scope_id))
    if not scope_row:
        await _deny("scope_receipt_not_found", "Linked scope receipt not found", http_status=404, approval_ref=approval_ref)
    scope_ref = str(scope_id)
    scope = _public_scope_receipt_row(scope_row)
    if scope.get("verdict") == "blocked":
        await _deny("scope_receipt_blocked", "Linked scope receipt is blocked", approval_ref=approval_ref, scope_ref=scope_ref)
    if scope.get("verdict") == "needs_approval" and "confirm_scope_reviewed" not in confirmations:
        await _deny("scope_receipt_needs_review", "Approval receipt is missing confirm_scope_reviewed", approval_ref=approval_ref, scope_ref=scope_ref)

    requested_target_id = str(target_id) if target_id else None
    scope_target_id = str(scope.get("target_id") or "")
    if requested_target_id and require_target_binding and not scope_target_id:
        await _deny(
            "approval_scope_target_missing",
            "Approval receipt scope is not bound to the requested target",
            approval_ref=approval_ref,
            scope_ref=scope_ref,
        )
    if requested_target_id and scope_target_id and requested_target_id != scope_target_id:
        await _deny("approval_scope_target_mismatch", "Approval receipt scope target does not match requested target", approval_ref=approval_ref, scope_ref=scope_ref)

    if target_url:
        parsed = urllib.parse.urlparse(target_url if "://" in target_url else f"https://{target_url}")
        host = parsed.hostname or ""
        if host and not _host_matches_receipt_scope(host, scope):
            await _deny("approval_scope_host_mismatch", "Approval receipt scope host does not match requested target", approval_ref=approval_ref, scope_ref=scope_ref)

    return {
        "approval_receipt_id": approval["id"],
        "scope_receipt_id": scope["id"],
        "approved_by": approval.get("approved_by"),
        "risk_tier": approval.get("risk_tier"),
        "runtime_scope_guard": _runtime_scope_guard_from_scope(scope),
    }




























def _authz_observation_matches_expectation(observed_status: Any, expected: dict[str, Any]) -> bool:
    try:
        status = int(observed_status)
    except (TypeError, ValueError):
        return False
    expected_status = expected.get("expected_http_status")
    if expected_status is not None:
        try:
            return status == int(expected_status)
        except (TypeError, ValueError):
            pass
    expected_access = str(expected.get("expected_access") or "unknown").strip().lower()
    if expected_access == "allow":
        return 200 <= status < 400
    if expected_access in {"deny", "requires_role"}:
        return status in {401, 403, 404}
    return False


def _authz_status_grants_access(observed_status: Any) -> bool:
    try:
        status = int(observed_status)
    except (TypeError, ValueError):
        return False
    # Redirects often mean "go login"; only a concrete 2xx response is access.
    return 200 <= status < 300


def _authz_observation_is_violation(observation: dict[str, Any]) -> bool:
    expected_denied = str(observation.get("expected_access") or "").lower() in {"deny", "requires_role"}
    if not expected_denied:
        return False
    if not observation.get("request_success"):
        return False
    if not observation.get("authenticated_user"):
        return False
    if _authz_observation_is_soft_denial(observation):
        return False
    return _authz_status_grants_access(observation.get("observed_status"))


def _authz_observation_is_soft_denial(observation: dict[str, Any]) -> bool:
    try:
        status_int = int(observation.get("observed_status"))
    except (TypeError, ValueError):
        return False
    if status_int < 200 or status_int >= 300:
        return False
    response = observation.get("response") if isinstance(observation.get("response"), dict) else {}
    body = response.get("body_sample")
    if body is None:
        return False
    if isinstance(body, (dict, list)):
        text = json.dumps(body, sort_keys=True, default=str)
    else:
        text = str(body)
    normalized = re.sub(r"\s+", " ", text).strip().lower()
    if not normalized:
        return False
    denial_markers = (
        "forbidden",
        "unauthorized",
        "not authorized",
        "access denied",
        "permission denied",
        "requires authentication",
        "authentication required",
        "login required",
        "insufficient role",
        "insufficient privileges",
        "not allowed",
    )
    if any(marker in normalized for marker in denial_markers):
        return True
    try:
        parsed = json.loads(text) if isinstance(body, str) else body
    except Exception:
        parsed = None
    if isinstance(parsed, dict):
        for key in ("error", "message", "detail", "code"):
            value = str(parsed.get(key) or "").strip().lower()
            if value and any(marker in value for marker in denial_markers):
                return True
    return False


def _authz_redacted_request_response_ref(observation: dict[str, Any]) -> dict[str, Any]:
    request = _redact_agent_payload(observation.get("request") or {})
    response = _redact_agent_payload(observation.get("response") or {})
    return {
        "kind": "authz_replay_http_exchange",
        "method": observation.get("method"),
        "path": observation.get("path"),
        "principal_auth_state": observation.get("principal_auth_state"),
        "request": request,
        "response": response,
    }


def _authz_replay_proof_bundle(
    replay_plan: dict[str, Any],
    observations: Sequence[dict[str, Any]],
) -> dict[str, Any]:
    allowed_access = []
    violations = []
    denial_like_redirects = []
    soft_denials = []
    authenticated_principals: set[str] = set()
    for observation in observations:
        principal = str(observation.get("principal_auth_state") or observation.get("principal_label") or "").strip()
        if observation.get("authenticated_user") and principal:
            authenticated_principals.add(principal)
        expected = str(observation.get("expected_access") or "").lower()
        status = observation.get("observed_status")
        if expected == "allow" and observation.get("request_success") and observation.get("authenticated_user") and _authz_status_grants_access(status):
            allowed_access.append({
                "principal": principal or None,
                "method": observation.get("method"),
                "path": observation.get("path"),
                "status": status,
            })
        if _authz_observation_is_violation(observation):
            violations.append({
                "principal": principal or None,
                "method": observation.get("method"),
                "path": observation.get("path"),
                "status": status,
                "expected_access": observation.get("expected_access"),
            })
        if expected in {"deny", "requires_role"} and _authz_observation_is_soft_denial(observation):
            soft_denials.append({
                "principal": principal or None,
                "method": observation.get("method"),
                "path": observation.get("path"),
                "status": status,
            })
        try:
            status_int = int(status)
        except (TypeError, ValueError):
            status_int = 0
        if expected in {"deny", "requires_role"} and 300 <= status_int < 400:
            denial_like_redirects.append({
                "principal": principal or None,
                "method": observation.get("method"),
                "path": observation.get("path"),
                "status": status_int,
            })
    violation_principals = {str(item.get("principal") or "") for item in violations if item.get("principal")}
    allow_principals = {str(item.get("principal") or "") for item in allowed_access if item.get("principal")}
    principal_profile_bindings_verified = bool(observations) and all(
        observation.get("principal_profile_verified") is True
        for observation in observations
    )
    principal_identity_bindings_verified = bool(observations) and all(
        observation.get("principal_identity_verified") is True
        for observation in observations
    )
    differential_observed = bool(
        principal_profile_bindings_verified
        and principal_identity_bindings_verified
        and violations
        and allowed_access
        and (violation_principals | allow_principals)
        and len(authenticated_principals) >= 2
    )
    return _redact_agent_payload({
        "bundle_type": "authz_replay_proof_bundle",
        "plan_mode": replay_plan.get("mode"),
        "method": replay_plan.get("method"),
        "path": replay_plan.get("path"),
        "object_key": replay_plan.get("object_key"),
        "observation_count": len(observations),
        "authenticated_principal_count": len(authenticated_principals),
        "authenticated_principals": sorted(authenticated_principals)[:10],
        "principal_profile_bindings_verified": principal_profile_bindings_verified,
        "principal_identity_bindings_verified": principal_identity_bindings_verified,
        "allowed_access_observations": allowed_access[:10],
        "violation_observations": violations[:10],
        "denial_like_redirects": denial_like_redirects[:10],
        "soft_denial_observations": soft_denials[:10],
        "differential_observed": differential_observed,
        "proof_state_hint": "differential_observed" if differential_observed else "inconclusive_or_suspected",
        "promotion_requires_explicit_operator_action": True,
        "finding_created_automatically": False,
    })






def _authz_concrete_replay_path(expected: dict[str, Any], replay_plan: dict[str, Any]) -> str:
    """Resolve a concrete replay destination without inventing object identifiers."""
    for candidate in (
        expected.get("concrete_path"),
        expected.get("concrete_url"),
        replay_plan.get("concrete_path"),
        replay_plan.get("concrete_url"),
        expected.get("path"),
        replay_plan.get("path"),
    ):
        value = str(candidate or "").strip()
        if value and not _authz_replay_path_is_template(value):
            return value
    return ""


async def _authz_target_principal_profile_bindings(
    conn: Any,
    target_id: uuid.UUID,
) -> dict[str, str]:
    """Return the active managed credential profile id for each authz slot."""
    rows = await conn.fetch(
        """
        SELECT p.auth_state, cp.id AS credential_profile_id
        FROM target_principals p
        JOIN target_credential_profiles cp
          ON cp.target_id = p.target_id
         AND lower(cp.name) = lower(p.credential_profile)
        WHERE p.target_id = $1
          AND p.is_active = true
          AND cp.is_active = true
          AND (cp.expires_at IS NULL OR cp.expires_at > NOW())
          AND p.auth_state IN ('user1', 'user2')
        ORDER BY CASE p.auth_state WHEN 'user1' THEN 0 ELSE 1 END
        """,
        target_id,
    )
    bindings: dict[str, str] = {}
    for row in rows:
        payload = row_to_dict(row)
        auth_state = str(payload.get("auth_state") or "").strip()
        profile_id = str(payload.get("credential_profile_id") or "").strip()
        if auth_state in {"user1", "user2"} and profile_id and auth_state not in bindings:
            bindings[auth_state] = profile_id
    return bindings


def _authz_session_principal_identity(user: Any) -> str | None:
    """Hash a stable server-issued JWT claim without retaining principal data."""
    candidates: list[str] = []
    token = str(getattr(user, "token", None) or "").strip()
    if token:
        candidates.append(token)
    headers = getattr(user, "headers", None)
    if isinstance(headers, dict):
        for key, value in headers.items():
            if str(key).strip().lower() == "authorization":
                candidates.append(str(value or "").strip())
    cookies = getattr(user, "cookies", None)
    if isinstance(cookies, dict):
        candidates.extend(str(value or "").strip() for value in cookies.values())

    for candidate in candidates:
        raw = re.sub(r"^bearer\s+", "", candidate, flags=re.IGNORECASE).strip()
        parts = raw.split(".")
        if len(parts) != 3:
            continue
        try:
            encoded = parts[1] + "=" * (-len(parts[1]) % 4)
            claims = json.loads(base64.urlsafe_b64decode(encoded.encode("ascii")).decode("utf-8"))
        except (ValueError, TypeError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        if not isinstance(claims, dict):
            continue
        for claim in ("email", "user_id", "userId", "username", "sub", "id"):
            value = claims.get(claim)
            if isinstance(value, (str, int)) and str(value).strip():
                normalized = str(value).strip().lower() if claim in {"email", "username"} else str(value).strip()
                return hashlib.sha256(f"{claim}:{normalized}".encode("utf-8")).hexdigest()
    return None


def _authz_session_profile_binding_status(
    expected_principals: set[str],
    session_users: dict[str, Any],
    target_bindings: dict[str, str],
) -> tuple[str | None, dict[str, Any]]:
    """Validate that replay actors are the target's two distinct slotted profiles."""
    required_slots = {"user1", "user2"}
    details: dict[str, Any] = {
        "required_slots": sorted(required_slots),
        "expected_principals": sorted(expected_principals),
        "bound_slots": sorted(target_bindings),
        "mismatched_slots": [],
        "missing_session_profile_slots": [],
        "missing_session_identity_slots": [],
        "identity_verified_slots": [],
    }
    if expected_principals != required_slots:
        return "authz_replay_requires_slotted_principals", details
    if set(target_bindings) != required_slots:
        return "target_principal_profiles_missing", details
    profile_ids = [target_bindings[slot] for slot in sorted(required_slots)]
    if len(set(profile_ids)) != len(profile_ids):
        return "target_principal_profiles_not_distinct", details

    for slot in sorted(required_slots):
        user = session_users.get(slot)
        actual_profile_id = str(getattr(user, "credential_profile_id", None) or "").strip()
        actual_auth_state = str(getattr(user, "principal_auth_state", None) or "").strip()
        if not actual_profile_id or not actual_auth_state:
            details["missing_session_profile_slots"].append(slot)
            continue
        if actual_auth_state != slot or actual_profile_id != target_bindings[slot]:
            details["mismatched_slots"].append(slot)
    if details["missing_session_profile_slots"]:
        return "session_principal_profiles_unbound", details
    if details["mismatched_slots"]:
        return "session_principal_profile_mismatch", details

    identities: dict[str, str] = {}
    for slot in sorted(required_slots):
        identity = _authz_session_principal_identity(session_users.get(slot))
        if not identity:
            details["missing_session_identity_slots"].append(slot)
            continue
        identities[slot] = identity
        details["identity_verified_slots"].append(slot)
    if details["missing_session_identity_slots"]:
        return "session_principal_identity_unverified", details
    if len(set(identities.values())) != len(required_slots):
        details["identity_collision"] = True
        return "session_principals_not_distinct", details
    details["identity_collision"] = False
    return None, details


async def _execute_authz_replay_plan(
    conn,
    *,
    campaign_action_id: str,
    session_id: str,
    approval_receipt_id: str | None = None,
    created_by: str | None = None,
) -> dict[str, Any]:
    """Execute a planned authz replay through an existing interactive session."""
    action_uuid = _uuid_or_400(campaign_action_id, "campaign action id")
    session_id = str(session_id or "").strip()
    if not session_id:
        raise HTTPException(status_code=400, detail="authz.replay_plan requires a session_id parameter")
    row = await conn.fetchrow("SELECT * FROM campaign_actions WHERE id=$1", action_uuid)
    if not row:
        raise HTTPException(status_code=404, detail="Campaign action not found")
    action = _public_campaign_action_row(row)
    result_json = action.get("result_json") if isinstance(action.get("result_json"), dict) else {}
    replay_plan = result_json.get("authz_replay_plan") if isinstance(result_json.get("authz_replay_plan"), dict) else {}
    if replay_plan.get("mode") != "deterministic_authz_replay":
        raise HTTPException(status_code=400, detail="Campaign action does not contain an authz replay plan")
    expected_access = [dict(item) for item in (replay_plan.get("expected_access") or []) if isinstance(item, dict)]
    if not expected_access:
        raise HTTPException(status_code=400, detail="Authz replay plan has no expected access rows")
    for item in expected_access:
        item["_execution_path"] = _authz_concrete_replay_path(item, replay_plan)
    unresolved_templates = [
        str(item.get("path") or replay_plan.get("path") or "").strip()
        for item in expected_access
        if not item.get("_execution_path")
    ]
    target_uuid = _optional_uuid(action.get("target_id"))
    if approval_receipt_id:
        if not target_uuid:
            raise HTTPException(status_code=400, detail="authz.replay_plan campaign action is not bound to a target_id")
        target_row = await conn.fetchrow("SELECT id, url FROM targets WHERE id=$1", target_uuid)
        if not target_row:
            raise HTTPException(status_code=404, detail="Target not found")
        target_payload = row_to_dict(target_row)
        await _validate_approval_receipt_for_action(
            conn,
            approval_receipt_id,
            target_url=str(target_payload.get("url") or "").strip() or None,
            target_id=target_uuid,
            action_name="authz.replay_plan",
            command="authz.replay_plan",
            risk_tier="credential",
            created_by=created_by,
        )

    manager = await InteractiveSessionManager.get_instance()
    session = await manager.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found or expired")
    session_users = getattr(getattr(session, "state", None), "users", {}) or {}
    authenticated_users = {
        str(name)
        for name, user in session_users.items()
        if getattr(user, "is_authenticated", False)
    }
    expected_principals = {
        str(item.get("principal_auth_state") or item.get("principal_label") or "").strip()
        for item in expected_access
        if str(item.get("principal_auth_state") or item.get("principal_label") or "").strip()
    }
    missing_principals = sorted(expected_principals - authenticated_users)
    profile_binding_reason: str | None = None
    profile_binding_details: dict[str, Any] = {}
    target_profile_bindings: dict[str, str] = {}
    if not unresolved_templates and not missing_principals and len(expected_principals) >= 2:
        if not target_uuid:
            profile_binding_reason = "authz_replay_target_not_bound"
        else:
            target_profile_bindings = await _authz_target_principal_profile_bindings(conn, target_uuid)
            profile_binding_reason, profile_binding_details = _authz_session_profile_binding_status(
                expected_principals,
                session_users,
                target_profile_bindings,
            )
    precondition_reason = (
        "unresolved_route_template"
        if unresolved_templates
        else "missing_authenticated_principal"
        if missing_principals
        else "requires_two_authenticated_principals"
        if len(expected_principals) < 2
        else profile_binding_reason
    )
    if precondition_reason:
        observations = [
            {
                "method": str(item.get("method") or replay_plan.get("method") or "GET").strip().upper(),
                "path": str(item.get("_execution_path") or item.get("path") or replay_plan.get("path") or "").strip(),
                "principal_label": item.get("principal_label"),
                "principal_auth_state": str(item.get("principal_auth_state") or item.get("principal_label") or "").strip() or None,
                "expected_access": item.get("expected_access"),
                "expected_http_status": item.get("expected_http_status"),
                "observed_status": None,
                "matched": False,
                "request_success": False,
                "authenticated_user": bool(
                    str(item.get("principal_auth_state") or item.get("principal_label") or "").strip()
                    in authenticated_users
                ),
                "principal_profile_verified": False,
                "principal_identity_verified": False,
                "inconclusive_reason": precondition_reason,
            }
            for item in expected_access[:10]
        ]
        proof_bundle = _authz_replay_proof_bundle(replay_plan, observations)
        tool_receipt_result = await _record_tool_receipt(conn, ToolReceiptRequest(
            tool_name="authz.replay_plan",
            adapter_version="2026-07-10.v3",
            redacted_argv=["authz.replay_plan", str(action_uuid), "session:<redacted>"],
            target_scope={
                "campaign_action_id": str(action_uuid),
                "path": replay_plan.get("path"),
                "method": replay_plan.get("method"),
            },
            approval_receipt_id=approval_receipt_id,
            status="skipped",
            parser_status="not_applicable",
            metadata_json={
                "observation_count": len(observations),
                "mismatch_count": len(observations),
                "violation_count": 0,
                "missing_authenticated_principals": missing_principals,
                "unresolved_route_templates": sorted(set(unresolved_templates)),
                "authenticated_principal_count": len(authenticated_users),
                "required_principal_count": len(expected_principals),
                "principal_profile_binding_reason": profile_binding_reason,
                "principal_profile_binding_details": profile_binding_details,
                "proof_bundle": proof_bundle,
            },
            created_by=created_by,
        ))
        tool_receipt = tool_receipt_result.get("tool_receipt") or {}
        replay_result = {
            "authz_replay": {
                "campaign_action_id": str(action_uuid),
                "session_id": session_id,
                "plan": replay_plan,
                "observations": observations,
                "proof_bundle": proof_bundle,
                "tool_receipt_id": tool_receipt.get("id"),
                "evidence_instance_ids": [],
                "mismatch_count": len(observations),
                "violation_count": 0,
                "proof_state": f"inconclusive_{precondition_reason}",
                "finding_created": False,
            }
        }
        updated_row = await conn.fetchrow(
            """
            UPDATE campaign_actions
            SET status='partial',
                dry_run=false,
                result_json = result_json || $1::jsonb,
                updated_at=NOW()
            WHERE id=$2
            RETURNING *
            """,
            json.dumps(replay_result),
            action_uuid,
        )
        command_result = await _record_command_result(
            conn,
            command="authz.replay_plan",
            status="partial",
            risk_tier="credential",
            dry_run=False,
            approval_receipt_id=approval_receipt_id,
            blocked_by=[precondition_reason],
            tool_receipt_ids=[str(tool_receipt.get("id"))] if tool_receipt.get("id") else [],
            result_json=replay_result,
            operator_message=(
                "Authz replay was not executed because the route template has no concrete object path."
                if unresolved_templates
                else "Authz replay was inconclusive because required principal profile bindings were not verified."
                if profile_binding_reason
                else "Authz replay was inconclusive because required authenticated principals were missing."
            ),
            next_action=f"/settings/arsenal?tab=campaign-actions",
            created_by=created_by,
        )
        return {
            "campaign_action": _public_campaign_action_row(updated_row),
            "observations": observations,
            "mismatches": observations,
            "violations": [],
            "tool_receipt_id": tool_receipt.get("id"),
            "evidence_instance_ids": [],
            "command_result": command_result,
            "operation_id": command_result["id"],
            "mismatch_count": len(observations),
            "violation_count": 0,
            "status": "partial",
            "execution_enabled": True,
            "findings_created": 0,
        }

    observations: list[dict[str, Any]] = []
    mismatches: list[dict[str, Any]] = []
    violations: list[dict[str, Any]] = []
    for expected in expected_access[:10]:
        endpoint = str(expected.get("_execution_path") or "").strip()
        method = str(expected.get("method") or replay_plan.get("method") or "GET").strip().upper()
        as_user = str(expected.get("principal_auth_state") or expected.get("principal_label") or "").strip() or None
        if not endpoint:
            observation = {
                "method": method,
                "path": endpoint,
                "principal_auth_state": as_user,
                "expected_access": expected.get("expected_access"),
                "expected_http_status": expected.get("expected_http_status"),
                "observed_status": None,
                "matched": False,
                "error": "missing_endpoint",
            }
        else:
            replay = await session.test_endpoint(
                endpoint=endpoint,
                method=method,
                as_user=as_user,
                body=None,
                allow_out_of_scope=False,
            )
            observed_status = (
                replay.get("status_code")
                if isinstance(replay, dict) and replay.get("status_code") is not None
                else replay.get("status") if isinstance(replay, dict) else None
            )
            matched = _authz_observation_matches_expectation(observed_status, expected)
            observation = {
                "method": method,
                "path": endpoint,
                "principal_label": expected.get("principal_label"),
                "principal_auth_state": as_user,
                "expected_access": expected.get("expected_access"),
                "expected_http_status": expected.get("expected_http_status"),
                "observed_status": observed_status,
                "matched": matched,
                "request_success": bool(replay.get("success")) if isinstance(replay, dict) else False,
                "authenticated_user": bool(as_user and as_user in authenticated_users),
                "credential_profile_id": target_profile_bindings.get(as_user or ""),
                "principal_profile_verified": True,
                "principal_identity_verified": True,
                "request": {
                    "method": method,
                    "url": endpoint,
                    "as_user": as_user,
                },
                "response": {
                    "status": observed_status,
                    "status_text": replay.get("status_text") if isinstance(replay, dict) else None,
                    "headers": replay.get("headers") if isinstance(replay, dict) else {},
                    "body_sample": replay.get("body") if isinstance(replay, dict) else None,
                },
            }
            if isinstance(replay, dict) and replay.get("error"):
                observation["error"] = replay.get("error")
        observations.append(observation)
        if not observation.get("matched"):
            mismatches.append(observation)
            if _authz_observation_is_violation(observation):
                violations.append(observation)
        observation["violation_observed"] = _authz_observation_is_violation(observation)

    proof_bundle = _authz_replay_proof_bundle(replay_plan, observations)
    tool_receipt_result = await _record_tool_receipt(conn, ToolReceiptRequest(
        tool_name="authz.replay_plan",
        adapter_version="2026-07-10.v3",
        redacted_argv=["authz.replay_plan", str(action_uuid), "session:<redacted>"],
        target_scope={
            "campaign_action_id": str(action_uuid),
            "path": replay_plan.get("path"),
            "method": replay_plan.get("method"),
        },
        approval_receipt_id=approval_receipt_id,
        status="success" if not mismatches else "failed",
        parser_status="parsed",
        metadata_json={
            "observation_count": len(observations),
            "mismatch_count": len(mismatches),
            "violation_count": len(violations),
            "proof_bundle": proof_bundle,
        },
        created_by=created_by,
    ))
    tool_receipt = tool_receipt_result.get("tool_receipt") or {}
    tool_receipt_id = tool_receipt.get("id")
    evidence_instances: list[dict[str, Any]] = []
    principal_pair = replay_plan.get("principal_pair") if isinstance(replay_plan.get("principal_pair"), dict) else {}
    for observation in observations:
        violation_observed = _authz_observation_is_violation(observation)
        request_response_ref = _authz_redacted_request_response_ref(observation)
        instance = await _record_evidence_instance(conn, EvidenceInstanceRequest(
            target_id=str(target_uuid) if target_uuid else None,
            concrete_url=str(observation.get("path") or "").strip() or None,
            object_id=str(replay_plan.get("object_key") or "").strip() or None,
            payload_variant=str(observation.get("principal_auth_state") or observation.get("principal_label") or "").strip() or None,
            request_response_refs=[json.dumps(request_response_ref, sort_keys=True)],
            principal_pair=principal_pair,
            proof_observation={
                "type": "authz_replay_observation",
                "expected_access": observation.get("expected_access"),
                "expected_http_status": observation.get("expected_http_status"),
                "observed_status": observation.get("observed_status"),
                "matched_expectation": bool(observation.get("matched")),
                "violation_observed": violation_observed,
                "authenticated_user": bool(observation.get("authenticated_user")),
                "differential_required": True,
            },
            campaign_action_id=str(action_uuid),
            tool_receipt_id=str(tool_receipt_id) if tool_receipt_id else None,
            retention_policy="audit",
            proof_state="suspected" if violation_observed else "inconclusive",
            metadata_json={
                "source": "authz.replay_plan",
                "finding_created": False,
                "proof_bundle": proof_bundle,
            },
            created_by=created_by,
        ))
        evidence_instances.append(instance.get("evidence_instance") or {})
    evidence_instance_ids = [str(item.get("id")) for item in evidence_instances if item.get("id")]

    replay_result = {
        "authz_replay": {
            "campaign_action_id": str(action_uuid),
            "session_id": session_id,
            "plan": replay_plan,
            "observations": observations,
            "proof_bundle": proof_bundle,
            "tool_receipt_id": tool_receipt_id,
            "evidence_instance_ids": evidence_instance_ids,
            "mismatch_count": len(mismatches),
            "violation_count": len(violations),
            "proof_state": "replayed_violation_observed" if violations else "replayed_no_violation_observed",
            "finding_created": False,
        }
    }
    status = "completed" if not mismatches else "partial"
    updated_row = await conn.fetchrow(
        """
        UPDATE campaign_actions
        SET status=$1,
            dry_run=false,
            result_json = result_json || $2::jsonb,
            updated_at=NOW()
        WHERE id=$3
        RETURNING *
        """,
        status,
        json.dumps(replay_result),
        action_uuid,
    )
    hypothesis_ids = action.get("hypothesis_ids") if isinstance(action.get("hypothesis_ids"), list) else []
    command_result = await _record_command_result(
        conn,
        command="authz.replay_plan",
        status=status,
        risk_tier="credential",
        dry_run=False,
        approval_receipt_id=approval_receipt_id,
        hypothesis_ids=[str(item) for item in hypothesis_ids],
        tool_receipt_ids=[str(tool_receipt_id)] if tool_receipt_id else [],
        result_json=replay_result,
        operator_message="Executed deterministic authz replay plan; no findings were created automatically.",
        next_action=f"/settings/arsenal?tab=campaign-actions",
        created_by=created_by,
    )
    return {
        "operation_id": command_result.get("id"),
        "status": status,
        "campaign_action": _public_campaign_action_row(updated_row) if updated_row else action,
        "command_result": command_result,
        "tool_receipt": tool_receipt,
        "evidence_instances": evidence_instances,
        "observations": observations,
        "mismatch_count": len(mismatches),
        "violation_count": len(violations),
        "execution_enabled": True,
        "findings_created": 0,
    }


async def _promote_authz_replay_finding(
    conn,
    *,
    campaign_action_id: str,
    approval_receipt_id: str | None = None,
    created_by: str | None = None,
) -> dict[str, Any]:
    """Explicitly promote a replayed authz violation into a manual finding."""
    action_uuid = _uuid_or_400(campaign_action_id, "campaign action id")
    row = await conn.fetchrow("SELECT * FROM campaign_actions WHERE id=$1", action_uuid)
    if not row:
        raise HTTPException(status_code=404, detail="Campaign action not found")
    action = _public_campaign_action_row(row)
    result_json = action.get("result_json") if isinstance(action.get("result_json"), dict) else {}
    replay = result_json.get("authz_replay") if isinstance(result_json.get("authz_replay"), dict) else {}
    if not replay:
        raise HTTPException(status_code=400, detail="Campaign action has no authz replay result")
    if int(replay.get("violation_count") or 0) <= 0:
        raise HTTPException(status_code=400, detail="Authz replay did not observe a lower-role access violation")
    target_uuid = _optional_uuid(action.get("target_id"))
    if not target_uuid:
        raise HTTPException(status_code=400, detail="Campaign action is not bound to a target_id")
    target_row = await conn.fetchrow("SELECT id, url FROM targets WHERE id=$1", target_uuid)
    if not target_row:
        raise HTTPException(status_code=404, detail="Target not found")
    target_payload = row_to_dict(target_row)
    target_url = str(target_payload.get("url") or "")
    await _validate_approval_receipt_for_action(
        conn,
        approval_receipt_id,
        target_url=target_url,
        target_id=target_uuid,
        action_name="authz.promote_replay_finding",
        command="authz.promote_replay_finding",
        risk_tier="credential",
        created_by=created_by,
    )
    observations = [item for item in (replay.get("observations") or []) if isinstance(item, dict)]
    violations = []
    for item in observations:
        if item.get("violation_observed") is True or _authz_observation_is_violation(item):
            violations.append(item)
    if not violations:
        raise HTTPException(status_code=400, detail="Authz replay result has no promotable violation observation")
    proof_bundle = replay.get("proof_bundle") if isinstance(replay.get("proof_bundle"), dict) else _authz_replay_proof_bundle(replay.get("plan") if isinstance(replay.get("plan"), dict) else {}, observations)
    if proof_bundle.get("principal_profile_bindings_verified") is not True:
        raise HTTPException(
            status_code=400,
            detail="Authz replay promotion requires verified target principal profile bindings",
        )
    if proof_bundle.get("principal_identity_bindings_verified") is not True:
        raise HTTPException(
            status_code=400,
            detail="Authz replay promotion requires distinct verified session principal identities",
        )
    if proof_bundle.get("differential_observed") is not True:
        raise HTTPException(status_code=400, detail="Authz replay promotion requires a cross-principal differential observation")
    evidence_instance_ids = _clean_string_list(replay.get("evidence_instance_ids"), max_items=100)
    tool_receipt_id = str(replay.get("tool_receipt_id") or "").strip()

    # A distinct offending principal is a distinct authorization violation. The route
    # template collapse (ee7748d) already merges resource ids for one principal, so group
    # by principal and promote one finding per principal instead of dropping every
    # violation past the first.
    violations_by_actor: dict[str, list[dict[str, Any]]] = {}
    for item in violations:
        actor_key = str(item.get("principal_auth_state") or item.get("principal_label") or "lower-role principal").strip()
        violations_by_actor.setdefault(actor_key, []).append(item)

    promotions: list[dict[str, Any]] = []
    for actor, actor_violations in violations_by_actor.items():
        first = actor_violations[0]
        path = str(first.get("path") or "").strip() or target_url
        templated_path = _authz_template_replay_path(path)
        title = f"BOLA: {actor} accessed denied resource"
        fingerprint_source = f"{target_uuid}:authz.replay_plan:{templated_path or path}:{actor}:CWE-639"
        fingerprint = hashlib.sha256(fingerprint_source.encode()).hexdigest()[:32]
        request_response_ref = _authz_redacted_request_response_ref(first)
        request_payload = request_response_ref.get("request") if isinstance(request_response_ref.get("request"), dict) else {}
        response_payload = request_response_ref.get("response") if isinstance(request_response_ref.get("response"), dict) else {}
        evidence_json = _redact_finding_evidence({
            "proof": "Deterministic authz replay observed a principal receiving successful access where the role matrix expected denial.",
            "authz_replay": {
                "campaign_action_id": str(action_uuid),
                "principal": actor,
                "violation_count": len(actor_violations),
                "templated_path": templated_path or None,
                "violations": actor_violations[:10],
                "proof_bundle": proof_bundle,
                "request_response_ref": request_response_ref,
                "evidence_instance_ids": evidence_instance_ids,
                "tool_receipt_id": tool_receipt_id or None,
            },
        })
        existing = await conn.fetchrow(
            "SELECT id, status FROM findings WHERE fingerprint=$1 AND target_id=$2",
            fingerprint,
            target_uuid,
        )
        if existing:
            finding_id = existing["id"]
            status = "duplicate"
            existing_payload = row_to_dict(existing)
            if existing_payload.get("status") == "resolved":
                await conn.execute(
                    """
                    UPDATE findings
                    SET status='active', last_seen_at=NOW(),
                        resurfaced_count = resurfaced_count + 1,
                        last_verification_status='still_vulnerable',
                        last_verification_verdict='exploited',
                        last_verification_confidence=1.0,
                        last_verified_at=NOW(),
                        updated_at=NOW()
                    WHERE id=$1
                    """,
                    finding_id,
                )
                status = "resurfaced"
            else:
                await conn.execute(
                    """
                    UPDATE findings
                    SET last_seen_at=NOW(),
                        last_verification_status='still_vulnerable',
                        last_verification_verdict='exploited',
                        last_verification_confidence=1.0,
                        last_verified_at=NOW(),
                        updated_at=NOW()
                    WHERE id=$1
                    """,
                    finding_id,
                )
        else:
            finding_id = await conn.fetchval(
                """
                INSERT INTO findings (
                    target_id, fingerprint, title, description, severity,
                    cvss_score, tool, cwe, url, evidence, request, response,
                    notes, source, status, last_verification_status,
                    last_verification_verdict, last_verification_confidence, last_verified_at
                ) VALUES (
                    $1,$2,$3,$4,'high',
                    $5,'bola','CWE-639',$6,$7,$8,$9,
                    $10,'manual','active','still_vulnerable',
                    'exploited',1.0,NOW()
                )
                RETURNING id
                """,
                target_uuid,
                fingerprint,
                title,
                "Lower-role authorization replay observed successful access where the principal matrix expected denial.",
                8.1,
                path if path.startswith(("http://", "https://")) else target_url.rstrip("/") + "/" + path.lstrip("/"),
                json.dumps(evidence_json),
                json.dumps(request_payload) if request_payload else None,
                json.dumps(response_payload) if response_payload else None,
                "Promoted explicitly from authz.replay_plan evidence.",
            )
            status = "created"
        promotions.append({
            "finding_id": str(finding_id),
            "fingerprint": fingerprint,
            "status": status,
            "principal": actor,
            "finding_created": status == "created",
        })

    finding_ids = [item["finding_id"] for item in promotions]
    primary = promotions[0]
    finding_id = primary["finding_id"]
    fingerprint = primary["fingerprint"]
    status = primary["status"]
    await conn.execute(
        """
        UPDATE evidence_instances
        SET finding_id=$1
        WHERE id = ANY($2::uuid[])
        """,
        uuid.UUID(finding_id),
        [uuid.UUID(item) for item in evidence_instance_ids if _optional_uuid(item)],
    )
    await conn.execute(
        """
        UPDATE campaign_actions
        SET finding_ids = (
                SELECT COALESCE(jsonb_agg(DISTINCT value), '[]'::jsonb)
                FROM jsonb_array_elements_text(finding_ids || $1::jsonb) AS value
            ),
            status='completed',
            result_json = result_json || $2::jsonb,
            updated_at=NOW()
        WHERE id=$3
        """,
        json.dumps(finding_ids),
        json.dumps({"authz_replay_promotion": {"finding_ids": finding_ids, "promotions": promotions}}),
        action_uuid,
    )
    await conn.execute(
        """
        UPDATE targets SET
            active_findings_count = (
                SELECT COUNT(*) FROM findings WHERE target_id=$1 AND status='active'
            ),
            updated_at=NOW()
        WHERE id=$1
        """,
        target_uuid,
    )
    hypothesis_ids = action.get("hypothesis_ids") if isinstance(action.get("hypothesis_ids"), list) else []
    command_result = await _record_command_result(
        conn,
        command="authz.promote_replay_finding",
        status="completed",
        risk_tier="credential",
        dry_run=False,
        approval_receipt_id=approval_receipt_id,
        finding_ids=finding_ids,
        hypothesis_ids=[str(item) for item in hypothesis_ids],
        evidence_object_ids=[],
        tool_receipt_ids=[tool_receipt_id] if tool_receipt_id else [],
        result_json={
            "finding_id": finding_id,
            "finding_ids": finding_ids,
            "promotions": promotions,
            "fingerprint": fingerprint,
            "promotion_status": status,
            "evidence_instance_ids": evidence_instance_ids,
            "finding_created": any(item["finding_created"] for item in promotions),
        },
        operator_message="Promoted deterministic authz replay violation(s) through explicit gated command.",
        next_action=f"/findings/{finding_id}",
        created_by=created_by,
    )
    return {
        "finding_id": finding_id,
        "finding_ids": finding_ids,
        "promotions": promotions,
        "fingerprint": fingerprint,
        "status": status,
        "command_result": command_result,
        "evidence_instance_ids": evidence_instance_ids,
        "tool_receipt_id": tool_receipt_id or None,
        "execution_enabled": True,
        "findings_created": sum(1 for item in promotions if item["finding_created"]),
    }






























# --- Command Arsenal execution gateway (§2 seq #3) ---------------------------
# One schema-driven entry point that invokes a product command by NAME through
# its existing route handler. It is not a shell/arbitrary-code runner: only
# catalog commands with a wired adapter run, read-only inspection dispatches
# freely, and state-changing commands stay behind the same confirmation +
# approval-receipt + execution-flag gate as the AI Ops router.







































































































































































def _workflow_identity_fingerprint(principal_metadata: Any, profile_metadata: Any, secret: str, auth_kind: str) -> str | None:
    sources = [_decode_json_value(principal_metadata) or {}, _decode_json_value(profile_metadata) or {}]
    identity: str | None = None
    for source in sources:
        if not isinstance(source, dict):
            continue
        for key in ("principal_identity", "account_id", "subject_id", "user_id", "email"):
            value = str(source.get(key) or "").strip().lower()
            if value:
                identity = f"{key}:{value}"
                break
        if identity:
            break
    if not identity and auth_kind == "authorization_header":
        token = secret.split(None, 1)[1] if secret.lower().startswith("bearer ") and " " in secret else secret
        parts = token.split(".")
        if len(parts) == 3:
            try:
                payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
            except (ValueError, TypeError, json.JSONDecodeError):
                payload = {}
            if isinstance(payload, dict):
                for key in ("account_id", "user_id", "email", "sub"):
                    value = str(payload.get(key) or "").strip().lower()
                    if value and not (key == "sub" and value in {"user", "customer", "generic"}):
                        identity = f"{key}:{value}"
                        break
    return hashlib.sha256(identity.encode()).hexdigest() if identity else None


def _workflow_cookie_map(secret: str) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for item in secret.split(";"):
        name, separator, value = item.strip().partition("=")
        if separator and name:
            cookies[name] = value
    return cookies


async def _resolve_workflow_principal_contexts(
    conn: Any,
    target_uuid: uuid.UUID,
    used_slots: set[str],
) -> dict[str, dict[str, Any]]:
    rows = await conn.fetch(
        """
        SELECT p.id AS principal_id, p.label, p.role, p.tenant_id, p.auth_state,
               p.metadata_json AS principal_metadata, cp.id AS profile_id,
               cp.auth_kind, cp.secret_value, cp.metadata_json AS profile_metadata
        FROM target_principals p
        JOIN target_credential_profiles cp
          ON cp.target_id = p.target_id
         AND lower(cp.name) = lower(p.credential_profile)
        WHERE p.target_id = $1
          AND p.is_active = true
          AND cp.is_active = true
          AND (cp.expires_at IS NULL OR cp.expires_at > NOW())
        ORDER BY p.updated_at DESC
        """,
        target_uuid,
    )
    candidates: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        payload = row_to_dict(row)
        slots = {str(payload.get("auth_state") or "").strip().lower()}
        if str(payload.get("role") or "").strip().lower() == "admin":
            slots.add("admin")
        tenant = str(payload.get("tenant_id") or "").strip().lower()
        if tenant:
            slots.add(f"tenant:{tenant}")
        for slot in slots:
            if slot in used_slots:
                candidates.setdefault(slot, []).append(payload)
    contexts: dict[str, dict[str, Any]] = {}
    for slot in sorted(used_slots - {"anonymous"}):
        matches = candidates.get(slot) or []
        if not matches:
            raise WorkflowContractError(f"principal_context_missing:{slot}")
        if len(matches) > 1:
            raise WorkflowContractError(f"principal_context_ambiguous:{slot}")
        row = matches[0]
        secret = str(decrypt_secret(row.get("secret_value")) or "").strip()
        if not secret:
            raise WorkflowContractError(f"principal_profile_secret_unavailable:{slot}")
        auth_kind = str(row.get("auth_kind") or "").strip()
        headers = {"Authorization": secret} if auth_kind == "authorization_header" else {}
        cookies = _workflow_cookie_map(secret) if auth_kind == "cookie" else {}
        if not headers and not cookies:
            raise WorkflowContractError(f"principal_profile_auth_kind_invalid:{slot}")
        principal_metadata = _decode_json_value(row.get("principal_metadata")) or {}
        captured_refs = (
            principal_metadata.get("captured_refs")
            if isinstance(principal_metadata, dict)
            and isinstance(principal_metadata.get("captured_refs"), dict)
            else {}
        )
        contexts[slot] = {
            "principal_id": str(row.get("principal_id")),
            "profile_id": str(row.get("profile_id")),
            "identity_fingerprint": _workflow_identity_fingerprint(
                row.get("principal_metadata"), row.get("profile_metadata"), secret, auth_kind
            ),
            "role": row.get("role"),
            "tenant_id": row.get("tenant_id"),
            "captured_refs": {
                str(key): str(value)
                for key, value in captured_refs.items()
                if not is_sensitive_key(str(key)) and value not in (None, "")
            },
            "headers": headers,
            "cookies": cookies,
        }
    return contexts




async def _execute_workflow_runtime(
    target_url: str,
    workflow_payload: dict[str, Any],
    normalized: dict[str, Any],
    principal_contexts: dict[str, dict[str, Any]],
    cancel_event: asyncio.Event,
) -> dict[str, Any]:
    manager = None
    session = None
    browser_slots_applied: set[str] = set()
    try:
        if any(step["kind"] == "browser" for step in normalized["steps"]):
            manager = await InteractiveSessionManager.get_instance()
            session = await manager.create_session(target_url, RESULTS_DIR)
            started = await session.start()
            if not started.get("success"):
                raise WorkflowContractError(str(started.get("error") or "browser_session_start_failed"))

        async def browser_action(slot: str, action: str, data: dict[str, Any]) -> dict[str, Any]:
            if not session:
                return {"success": False, "error": "browser_runtime_unavailable"}
            user = "default" if slot == "anonymous" else slot
            if slot != "anonymous" and slot not in browser_slots_applied:
                context = principal_contexts[slot]
                auth_data: dict[str, Any]
                if context.get("headers"):
                    auth_data = {"auth_header": context["headers"]["Authorization"]}
                else:
                    auth_data = {"cookies": context.get("cookies") or {}}
                auth_data.update({
                    "_credential_profile_id": context["profile_id"],
                    "_principal_auth_state": slot,
                    "_replace_auth_state": True,
                })
                auth_result = await session.action({"action": "set_auth", "user": user, "data": auth_data})
                if not auth_result.get("success"):
                    return {"success": False, "error": "managed_principal_auth_failed"}
                browser_slots_applied.add(slot)
            action_data = dict(data)
            if action == "navigate":
                action_data["url"] = action_data.pop("path")
            result = await session.action({"action": action, "user": user, "data": action_data})
            if action == "extract" and result.get("success"):
                values = result.get("values")
                if isinstance(values, list) and len(values) == 1 and not isinstance(values[0], (dict, list)):
                    result["value"] = values[0]
                else:
                    return {"success": False, "error": "browser_extract_missing_or_ambiguous"}
            return result

        return await execute_workflow(
            target_url,
            workflow_payload,
            principal_contexts=principal_contexts,
            browser_action=browser_action if session else None,
            cancelled=cancel_event.is_set,
        )
    finally:
        if manager and session:
            await manager.close_session(session.session_id)


def _invariant_value_allowed(value: Any, operator: str, expected: Any) -> bool:
    """Evaluate one typed invariant value without coercing ambiguous application data."""
    if operator in {"lt", "lte", "gt", "gte"}:
        if isinstance(value, bool) or isinstance(expected, bool):
            return False
        try:
            actual_number = float(value)
            expected_number = float(expected)
        except (TypeError, ValueError):
            return False
        if not math.isfinite(actual_number) or not math.isfinite(expected_number):
            return False
        return {
            "lt": actual_number < expected_number,
            "lte": actual_number <= expected_number,
            "gt": actual_number > expected_number,
            "gte": actual_number >= expected_number,
        }[operator]
    if operator in {"in", "not_in"}:
        if not isinstance(expected, list):
            return False
        member = value in expected
        return member if operator == "in" else not member
    if operator == "eq":
        return value == expected
    if operator == "ne":
        return value != expected
    return False


def _invariant_mapping_value(value: Any, dotted_name: str) -> Any:
    current = value
    for part in str(dotted_name or "").split("."):
        if not part or not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _trusted_invariant_execution_evidence(
    contract_value: dict[str, Any],
    normalized: dict[str, Any],
    result: dict[str, Any],
) -> dict[str, Any]:
    """Bind an approved typed invariant to server-observed live workflow evidence.

    The model may choose requests, but it cannot supply any predicate below. Exact contract route,
    method, role/value/state, successful response, restoration, and selected response values are
    recomputed from the normalized workflow plus raw runtime observations.
    """
    if str(contract_value.get("status") or "") != "approved":
        return {"family": "", "predicates": set(), "bindings": {}}
    try:
        contract = invariant_contracts.canonical_contract(contract_value)
    except (TypeError, ValueError):
        return {"family": "", "predicates": set(), "bindings": {}}
    kind = contract["contract_kind"]
    family = invariant_contracts.verification_plan({**contract, "status": "approved"}).get("proof_family") or ""
    route = _canonical_vulnerability_route(contract.get("path"))
    method = str(contract.get("method") or "").upper()
    if not route or not method:
        return {"family": family, "predicates": set(), "bindings": {}}

    observations = [item for item in result.get("observations") or [] if isinstance(item, dict)]
    by_label = {str(item.get("label") or ""): item for item in observations}
    normalized_steps = [item for item in normalized.get("steps") or [] if isinstance(item, dict)]
    step_index = {str(item.get("label") or ""): index for index, item in enumerate(normalized_steps)}
    receipts = {
        str(item.get("slot") or "").lower(): item
        for item in result.get("principal_receipts") or [] if isinstance(item, dict)
    }

    def success(observation: dict[str, Any]) -> bool:
        response = observation.get("response") if isinstance(observation.get("response"), dict) else {}
        status = response.get("status")
        return not observation.get("error") and isinstance(status, int) and 200 <= status < 300

    def signature(observation: dict[str, Any]) -> tuple[str, str] | None:
        request = observation.get("request") if isinstance(observation.get("request"), dict) else {}
        observed_method = str(request.get("method") or "").upper()
        observed_route = _canonical_vulnerability_route(request.get("path"))
        return (observed_method, observed_route) if observed_method and observed_route else None

    def selected(observation: dict[str, Any]) -> dict[str, Any]:
        response = observation.get("response") if isinstance(observation.get("response"), dict) else {}
        values = response.get("selected_json")
        return values if isinstance(values, dict) else {}

    exact = [item for item in observations if signature(item) == (method, route)]
    predicates: set[str] = set()
    bindings: dict[str, tuple[str, str]] = {}

    if kind == "access_control" and contract.get("expected_access") in {"deny", "requires_role"}:
        required_role = str(contract.get("subject_role") or "").lower()

        def role(item: dict[str, Any]) -> str:
            slot = str(item.get("principal") or "anonymous").lower()
            return "anonymous" if slot == "anonymous" else str((receipts.get(slot) or {}).get("role") or "").lower()

        if contract.get("expected_access") == "requires_role":
            controls = [item for item in exact if role(item) == required_role]
            candidates = [item for item in exact if role(item) != required_role]
        else:
            controls = [item for item in exact if role(item) != required_role]
            candidates = [item for item in exact if role(item) == required_role]
        control = next((item for item in controls if success(item)), None)
        candidate = candidates[0] if candidates else None
        if control:
            predicates.add("authorized_role_control")
            bindings["authorized_role_control"] = (method, route)
        if control and candidate:
            control_slot = str(control.get("principal") or "anonymous").lower()
            candidate_slot = str(candidate.get("principal") or "anonymous").lower()
            control_identity = (
                "anonymous" if control_slot == "anonymous" else
                str((receipts.get(control_slot) or {}).get("identity_fingerprint") or "")
            )
            candidate_identity = (
                "anonymous" if candidate_slot == "anonymous" else
                str((receipts.get(candidate_slot) or {}).get("identity_fingerprint") or "")
            )
            if (
                control_slot != candidate_slot
                and control_identity
                and candidate_identity
                and control_identity != candidate_identity
            ):
                predicates.add("distinct_identity")
                bindings["distinct_identity"] = (method, route)
            if success(candidate):
                predicates.add("forbidden_role_access")
                bindings["forbidden_role_access"] = (method, route)
            else:
                predicates.add("forbidden_role_denied")
                bindings["forbidden_role_denied"] = (method, route)

    elif kind == "field_constraint":
        field_name = str(contract.get("field_name") or "")
        # The READ projection may differ from the WRITE field for response-wrapping APIs (write
        # {field: v}; read $.data.field). `read_path` redirects only where the binder OBSERVES the
        # value; the mutation body is still keyed on field_name. A wrong read_path -> the field is
        # never observed -> no predicate binds -> fails closed (stays SUSPECTED).
        read_field = str((contract.get("conditions") or {}).get("read_path") or "") or field_name
        selected_path = f"$.{read_field}"
        mutation_steps = [
            step for step in normalized_steps
            if step.get("checkpoint") == "mutation"
            and str(step.get("method") or "").upper() == method
            and _canonical_vulnerability_route(step.get("path")) == route
        ]
        mutation_step = next((step for step in mutation_steps if _invariant_mapping_value(
            step.get("json_body") if isinstance(step.get("json_body"), dict) else step.get("form_body"),
            field_name,
        ) is not None), None)
        if mutation_step:
            probe_value = _invariant_mapping_value(
                mutation_step.get("json_body") if isinstance(mutation_step.get("json_body"), dict) else mutation_step.get("form_body"),
                field_name,
            )
            violates = not _invariant_value_allowed(probe_value, str(contract.get("operator") or ""), contract.get("expected_value"))
            mutation_observation = by_label.get(str(mutation_step.get("label") or ""), {})
            mutation_position = step_index.get(str(mutation_step.get("label") or ""), -1)
            before = next((
                item for item in observations
                if item.get("checkpoint") == "before"
                and success(item)
                and selected_path in selected(item)
                and _invariant_value_allowed(selected(item)[selected_path], str(contract.get("operator") or ""), contract.get("expected_value"))
            ), None)
            after = next((
                item for item in observations
                if step_index.get(str(item.get("label") or ""), -1) > mutation_position
                and item.get("checkpoint") in {"action", "after"}
                and selected(item).get(selected_path) == probe_value
                and before is not None
                and signature(item) is not None
                and signature(item) == signature(before)
                and signature(item)[1] == route
            ), None)
            if before:
                predicates.add("constraint_baseline_observed")
                bindings["constraint_baseline_observed"] = (method, route)
            if violates and success(mutation_observation) and after and success(after):
                predicates.add("constraint_violation_persisted")
                bindings["constraint_violation_persisted"] = (method, route)
            elif violates and mutation_observation and not success(mutation_observation):
                predicates.add("constraint_enforced")
                bindings["constraint_enforced"] = (method, route)
            if result.get("restoration_verified") is True:
                predicates.add("before_after_state")
                bindings["before_after_state"] = (method, route)

    elif kind == "workflow_transition":
        from_state = str((contract.get("conditions") or {}).get("from_state") or "").lower()
        to_state = str((contract.get("conditions") or {}).get("to_state") or "").lower()
        probe_state = str((contract.get("conditions") or {}).get("probe_state") or "").lower()
        # The read projection may differ from the write field on wrapping APIs (write {city: v};
        # read $.data.city) — mirror the field_constraint branch and honor the contract's read_path
        # so the observed state value is actually found. A wrong read_path -> value never observed ->
        # transition never derived -> fails closed (stays SUSPECTED).
        read_field = str((contract.get("conditions") or {}).get("read_path") or "") or str(contract.get("field_name") or "")
        selected_path = f"$.{read_field}"
        mutation_step = next((
            step for step in normalized_steps
            if step.get("checkpoint") == "mutation"
            and str(step.get("method") or "").upper() == method
            and _canonical_vulnerability_route(step.get("path")) == route
        ), None)
        if mutation_step:
            mutation_observation = by_label.get(str(mutation_step.get("label") or ""), {})
            mutation_position = step_index.get(str(mutation_step.get("label") or ""), -1)
            before_items = [item for item in observations if item.get("checkpoint") == "before"]
            after_items = [
                item for item in observations
                if step_index.get(str(item.get("label") or ""), -1) > mutation_position
                and item.get("checkpoint") in {"action", "after"}
            ]
            transition: tuple[Any, Any] | None = None
            for before_item in before_items:
                for after_item in after_items:
                    if (
                        not success(before_item)
                        or not success(after_item)
                        or
                        signature(before_item) is None
                        or signature(after_item) != signature(before_item)
                        or signature(before_item)[1] != route
                    ):
                        continue
                    prior = str(selected(before_item).get(selected_path) or "").lower()
                    current = str(selected(after_item).get(selected_path) or "").lower()
                    if prior and current and prior != current:
                        transition = (prior, current)
                    if transition:
                        break
                if transition:
                    break
            if transition and success(mutation_observation):
                prior, current = transition
                if prior == from_state and current == to_state:
                    predicates.add("invariant_held")
                    bindings["invariant_held"] = (method, route)
                elif (
                    prior == from_state
                    and probe_state
                    and current == probe_state
                    and probe_state != to_state
                ):
                    # The ONLY sound broken derivation: the object started in the approved
                    # from-state AND the app accepted and persisted the contract-declared
                    # FORBIDDEN probe state. Without the prior guard, an object sitting in any
                    # other state makes every legitimate-but-undocumented transition "violate"
                    # the single approved pair (false VERIFIED on ordinary state machines);
                    # without the probe guard, an app that coerced the write to a third legal
                    # state was reported broken even though it never entered the forbidden
                    # state. Mirrors the field_constraint branch's allowed-baseline +
                    # exact-probe-persistence guards. (Zero-FP audit F1.)
                    predicates.add("transition_invariant_broken")
                    bindings["transition_invariant_broken"] = (method, route)
            if result.get("restoration_verified") is True:
                predicates.add("before_after_state")
                bindings["before_after_state"] = (method, route)

    return {"family": family, "predicates": predicates, "bindings": bindings}


def _is_create_based_mass_assignment(family: Any, normalized: dict[str, Any] | None) -> bool:
    """Server-derived shape check for a create + cleanup mass-assignment workflow."""
    if family_proof.canonical_family(family) != "mass_assignment":
        return False
    steps = (normalized or {}).get("steps") or []
    creates = any(
        isinstance(step, dict)
        and step.get("checkpoint") == "mutation"
        and str(step.get("method") or "").upper() == "POST"
        and step.get("extract")
        for step in steps
    )
    attempts_cleanup = any(
        isinstance(step, dict)
        and step.get("checkpoint") in {"cleanup", "rollback"}
        and str(step.get("method") or "").upper() == "DELETE"
        for step in steps
    )
    return creates and attempts_cleanup


def _trusted_workflow_family_proof(
    first: dict[str, Any],
    replay: dict[str, Any],
    *,
    invariant_contract: dict[str, Any] | None = None,
    normalized: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Derive family predicates only from matching, server-evaluated live assertions."""
    family = family_proof.canonical_family(first.get("proof_family"))
    # Ownership already has a stronger object-producer/second-principal binder below. The typed
    # binder here adds the three invariant families that previously had no promotion path.
    if (
        invariant_contract
        and normalized
        and str(invariant_contract.get("contract_kind") or "") != "ownership"
    ):
        first_evidence = _trusted_invariant_execution_evidence(invariant_contract, normalized, first)
        replay_evidence = _trusted_invariant_execution_evidence(invariant_contract, normalized, replay)
        expected_family = family_proof.canonical_family(first_evidence.get("family"))
        same_family = bool(expected_family and family == expected_family)
        allowed_contract = family_proof.FAMILY_CONTRACTS.get(expected_family) or {}
        allowed_predicates = (
            set(allowed_contract.get("requires") or [])
            | set(allowed_contract.get("refute_if") or [])
        )
        first_predicates = set(first_evidence.get("predicates") or []) & allowed_predicates
        replay_predicates = set(replay_evidence.get("predicates") or []) & allowed_predicates
        stable_predicates = first_predicates & replay_predicates
        first_bindings = first_evidence.get("bindings") if isinstance(first_evidence.get("bindings"), dict) else {}
        replay_bindings = replay_evidence.get("bindings") if isinstance(replay_evidence.get("bindings"), dict) else {}
        stable_bindings = {
            predicate: first_bindings[predicate]
            for predicate in stable_predicates
            if first_bindings.get(predicate) is not None
            and first_bindings.get(predicate) == replay_bindings.get(predicate)
        }

        def observation_shape(result: dict[str, Any]) -> list[tuple[Any, ...]]:
            shape: list[tuple[Any, ...]] = []
            for item in result.get("observations") or []:
                if not isinstance(item, dict):
                    continue
                request = item.get("request") if isinstance(item.get("request"), dict) else {}
                shape.append((
                    item.get("label"), item.get("kind"), item.get("principal"), item.get("checkpoint"),
                    str(request.get("method") or "").upper(),
                    _canonical_vulnerability_route(request.get("path")),
                    bool(item.get("error")),
                ))
            return shape

        first_shape = observation_shape(first)
        replay_shape = observation_shape(replay)
        stable = bool(first_shape) and first_shape == replay_shape
        restoration_verified = bool(
            first.get("restoration_verified") and replay.get("restoration_verified")
        )
        no_errors = not any(
            item.get("error")
            for result in (first, replay)
            for item in result.get("observations") or []
            if isinstance(item, dict)
        )
        evidence = {predicate: True for predicate in stable_predicates}
        evidence["reexecuted_at_handoff"] = bool(
            same_family and stable and restoration_verified and no_errors
        )
        proof = family_proof.evaluate_family_proof(expected_family or family, evidence)
        proof_paths = {binding[1] for binding in stable_bindings.values()}
        proof_methods = {binding[0] for binding in stable_bindings.values()}
        proof.update({
            "stable_assertions": stable,
            "stable_predicates": sorted(stable_predicates),
            "restoration_verified": restoration_verified,
            "execution_errors_absent": no_errors,
            "reproduction_count": 2,
            "proof_routes": sorted(proof_paths) if len(proof_paths) == 1 else [],
            "proof_methods": sorted(proof_methods) if len(proof_methods) == 1 else [],
            "predicate_bindings": {
                predicate: {"method": binding[0], "path": binding[1]}
                for predicate, binding in sorted(stable_bindings.items())
            },
            "invariant_contract_id": str(invariant_contract.get("id") or "") or None,
            "invariant_contract_kind": invariant_contract.get("contract_kind"),
            "invariant_family_match": same_family,
            "proof_source": "approved_invariant_live_binder",
        })
        return proof

    contract = family_proof.FAMILY_CONTRACTS.get(family) or {}
    allowed = set(contract.get("requires") or []) | set(contract.get("refute_if") or [])

    def passed_predicates(result: dict[str, Any]) -> set[str]:
        # The model's predicate LABEL is never trusted. server_corroborated_predicates confirms
        # each predicate's security meaning from the live observations (real sensitive values,
        # distinct authenticated principals, genuine access/denial differentials); we then keep
        # only those in this family's contract. Injection and any uncorroborated predicate fail
        # closed, so a generic passing assertion can no longer mint a verified finding.
        return server_corroborated_predicates(result) & allowed

    first_predicates = passed_predicates(first)
    replay_predicates = passed_predicates(replay)
    stable_predicates = first_predicates & replay_predicates
    # Canonicalize the bound route BEFORE comparing the two runs. An object-id workflow legitimately
    # touches a different concrete id each run (owner_read /objects/42 on the first run, /objects/43 on
    # the replay), so raw rendered-path bindings would never match, stable_bindings would empty, and
    # proof_routes would collapse to [] -- silently blocking every object-id BOLA/IDOR promotion even
    # though the family proof is verified. Canonicalizing to /objects/{id} keeps the resource identity
    # while ignoring the concrete id value; static-route families canonicalize to themselves.
    def _canonical_binding(binding: tuple[str, str] | None) -> tuple[str, str] | None:
        if not binding:
            return None
        method, path = binding
        route = _canonical_vulnerability_route(path)
        return (method, route) if route else None

    first_bindings = {
        predicate: _canonical_binding(binding)
        for predicate, binding in server_corroborated_predicate_bindings(first).items()
    }
    replay_bindings = {
        predicate: _canonical_binding(binding)
        for predicate, binding in server_corroborated_predicate_bindings(replay).items()
    }
    stable_bindings = {
        predicate: first_bindings[predicate]
        for predicate in stable_predicates
        if first_bindings.get(predicate) is not None
        and first_bindings.get(predicate) == replay_bindings.get(predicate)
    }
    first_shape = [
        (item.get("id"), item.get("type"), bool(item.get("passed")))
        for item in first.get("assertion_results") or [] if isinstance(item, dict)
    ]
    replay_shape = [
        (item.get("id"), item.get("type"), bool(item.get("passed")))
        for item in replay.get("assertion_results") or [] if isinstance(item, dict)
    ]
    stable = bool(first_shape) and first_shape == replay_shape
    restoration_verified = bool(first.get("restoration_verified") and replay.get("restoration_verified"))
    no_errors = not any(
        item.get("error")
        for result in (first, replay)
        for item in result.get("observations") or []
        if isinstance(item, dict)
    )
    evidence = {predicate: True for predicate in stable_predicates}
    evidence["reexecuted_at_handoff"] = bool(stable and restoration_verified and no_errors)
    proof = family_proof.evaluate_family_proof(family, evidence)
    # The vulnerable operation for a mutation family is the WRITE, not the read-back that verifies it.
    # A create-based mass_assignment writes POST /collection and reads back GET /collection/{id}, so
    # binding the proven route across BOTH would collapse proof_routes to [] (two routes) and silently
    # block promotion. Bind the proven route to the state-changing request(s) -- exactly as proof_methods
    # already does -- and fall back to all bindings for read-only families (BOLA), which stay unchanged.
    write_bindings = [
        binding for binding in stable_bindings.values()
        if binding[0] in {"POST", "PUT", "PATCH", "DELETE"}
    ]
    route_bindings = write_bindings or list(stable_bindings.values())
    proof_paths = {binding[1] for binding in route_bindings}
    proof_methods = {binding[0] for binding in write_bindings} or {
        binding[0] for binding in stable_bindings.values()
    }
    proof.update({
        "stable_assertions": stable,
        "stable_predicates": sorted(stable_predicates),
        "restoration_verified": restoration_verified,
        "execution_errors_absent": no_errors,
        "reproduction_count": 2,
        "proof_routes": sorted(proof_paths) if len(proof_paths) == 1 else [],
        "proof_methods": sorted(proof_methods),
        "predicate_bindings": {
            predicate: {"method": binding[0], "path": binding[1]}
            for predicate, binding in sorted(stable_bindings.items())
        },
    })
    return proof


def _trusted_workflow_proven_operation(
    execution: dict[str, Any], *, method: str, route: str,
) -> dict[str, Any]:
    """Return the concrete request whose operation satisfied the family proof."""
    for observation in execution.get("observations") or []:
        if not isinstance(observation, dict):
            continue
        request = observation.get("request") if isinstance(observation.get("request"), dict) else {}
        request_method = str(request.get("method") or "GET").upper()
        request_path = str(request.get("path") or request.get("url") or "").strip()
        if request_method == method and _canonical_vulnerability_route(request_path) == route:
            return request
    return {}


async def _research_promotion_provenance(conn: Any, hypothesis_id: uuid.UUID) -> dict[str, str | None]:
    row = await conn.fetchrow(
        """
        SELECT rd.id AS decision_id, rd.episode_id, re.campaign_id
        FROM research_decisions rd
        JOIN research_episodes re ON re.id=rd.episode_id
        WHERE rd.hypothesis_id=$1
          AND rd.action->>'command'='experiment.workflow'
        ORDER BY rd.created_at DESC
        LIMIT 1
        """,
        hypothesis_id,
    )
    if not row:
        return {"decision_id": None, "episode_id": None, "campaign_id": None}
    return {
        "decision_id": str(row.get("decision_id")) if row.get("decision_id") else None,
        "episode_id": str(row.get("episode_id")) if row.get("episode_id") else None,
        "campaign_id": str(row.get("campaign_id")) if row.get("campaign_id") else None,
    }


async def _promote_trusted_workflow_finding(
    conn: Any,
    *,
    target_uuid: uuid.UUID,
    target_url: str,
    hypothesis_id: str,
    workflow_id: str,
    proof: dict[str, Any],
    first: dict[str, Any],
    replay: dict[str, Any],
    evidence_instance_id: str | None,
    tool_receipt_id: str | None,
) -> dict[str, Any] | None:
    promotable, _reason = family_proof.promotion_gate(proof)
    if not promotable or not hypothesis_id:
        return None
    hypothesis_row = await conn.fetchrow(
        "SELECT * FROM hypotheses WHERE id=$1 AND target_id=$2",
        _uuid_or_400(hypothesis_id, "hypothesis id"),
        target_uuid,
    )
    if not hypothesis_row:
        return None
    hypothesis = _public_hypothesis_row(hypothesis_row)
    family = str(proof.get("family") or "workflow")
    if family_proof.canonical_family(hypothesis.get("family")) != family_proof.canonical_family(family):
        return None
    hypothesis_metadata = (
        hypothesis.get("metadata_json") if isinstance(hypothesis.get("metadata_json"), dict) else {}
    )
    dedupe_dimensions = (
        hypothesis_metadata.get("dedupe_dimensions")
        if isinstance(hypothesis_metadata.get("dedupe_dimensions"), dict)
        else {}
    )
    # Bind promotion to routes that the stable family predicates themselves proved. Merely touching
    # a hypothesis route elsewhere in the workflow is not causal evidence for that route.
    proven_routes = {
        _canonical_vulnerability_route(route) for route in (proof.get("proof_routes") or [])
    }
    proven_routes.discard(None)
    if len(proven_routes) != 1:
        return None
    hypothesis_route = _canonical_vulnerability_route(
        dedupe_dimensions.get("route") or hypothesis_metadata.get("route")
    )
    if hypothesis_route and hypothesis_route not in proven_routes:
        return None
    hypothesis_method = str(dedupe_dimensions.get("method") or hypothesis_metadata.get("method") or "").upper()
    proof_methods = {str(method).upper() for method in (proof.get("proof_methods") or []) if str(method).strip()}
    if hypothesis_method and hypothesis_method not in proof_methods:
        return None
    proven_method = hypothesis_method or (next(iter(proof_methods)) if len(proof_methods) == 1 else "")
    finding_route = hypothesis_route or (sorted(proven_routes)[0] if proven_routes else None)
    vulnerability_dimensions = _research_vulnerability_dimensions(
        hypothesis.get("family") or family,
        dedupe_dimensions,
        hypothesis_metadata,
        {"predicates": proof.get("stable_predicates") or []},
    )
    canonical_vulnerability_key = _canonical_vulnerability_key(
        family=family,
        route=finding_route,
        method=proven_method or None,
        dimensions=vulnerability_dimensions,
    )
    if not canonical_vulnerability_key:
        return None
    # Suppress only the same operation. Include earlier autonomous promotions so the same
    # vulnerability is refreshed, rather than cloned once per planner hypothesis.
    candidate_vulnerability_keys = {canonical_vulnerability_key}
    known_rows = await conn.fetch(
        """
        SELECT id, status, tool, cwe, title, url, evidence, request
        FROM findings
        WHERE target_id=$1
          AND status IN ('active','resolved','accepted_risk')
        ORDER BY last_seen_at DESC
        LIMIT 2000
        """,
        target_uuid,
    )
    known_match = next(
        (
            row for row in known_rows
            if _finding_vulnerability_key(row) in candidate_vulnerability_keys
        ),
        None,
    )
    # A prior SUSPECTED autonomous-agent finding for this same vuln is exactly the thing being
    # UPGRADED to verified — it must not suppress its own promotion. This is DEDUP logic only; the
    # proof gate above (promotion_gate) is unchanged, so recognizing the upgrade cannot promote
    # anything unproven. A DAST/other-tool finding still suppresses (we don't re-clone what another
    # detector already owns). The superseded suspected row is resolved by the caller after promotion.
    _upgradeable_prior_tools = {"autonomous_workflow", "autonomous_agent"}
    if known_match and str(known_match.get("tool") or "") not in _upgradeable_prior_tools:
        proof["novelty_gate"] = "known_vulnerability_already_covered"
        proof["known_finding_id"] = str(known_match["id"])
        await conn.execute(
            """
            UPDATE hypotheses SET status='dead',
                terminal_reason='known_vulnerability_already_covered',
                version=version+1, updated_at=NOW()
            WHERE id=$1
            """,
            uuid.UUID(hypothesis_id),
        )
        return None
    fingerprint = hashlib.sha256(
        f"{target_uuid}:autonomous_workflow:{canonical_vulnerability_key}".encode()
    ).hexdigest()[:32]
    title = str(hypothesis.get("title") or f"Verified {family.replace('_', ' ')} invariant violation")[:500]
    severity = str(hypothesis.get("severity_guess") or "high").lower()
    if severity not in {"critical", "high", "medium", "low", "info"}:
        severity = "high"
    proven_operation = _trusted_workflow_proven_operation(
        first, method=proven_method, route=str(finding_route),
    )
    concrete_path = str(proven_operation.get("path") or finding_route or "/")
    finding_url = urllib.parse.urljoin(target_url.rstrip("/") + "/", concrete_path.lstrip("/"))
    raw_request_body = proven_operation.get("json_body") or proven_operation.get("form_body")
    request_body = (
        json.dumps(raw_request_body, sort_keys=True, separators=(",", ":"))
        if isinstance(raw_request_body, (dict, list))
        else str(raw_request_body or "")
    )
    retest_type = "bola" if family_proof.canonical_family(family) == "bola" else "generic_http"
    provenance = await _research_promotion_provenance(conn, uuid.UUID(hypothesis_id))
    prior_evidence = _decode_json_value(known_match.get("evidence")) if known_match else {}
    prior_evidence = prior_evidence if isinstance(prior_evidence, dict) else {}
    provenance_history = [
        item for item in (prior_evidence.get("research_provenance_history") or [])
        if isinstance(item, dict)
    ]
    prior_provenance = prior_evidence.get("research_provenance")
    if isinstance(prior_provenance, dict):
        provenance_history.append(prior_provenance)
    provenance_history.append(provenance)
    unique_provenance: dict[tuple[str, str, str], dict[str, Any]] = {}
    for item in provenance_history:
        key = (
            str(item.get("campaign_id") or ""),
            str(item.get("episode_id") or ""),
            str(item.get("decision_id") or ""),
        )
        if any(key):
            unique_provenance[key] = item
    evidence = _redact_finding_evidence({
        "proof": "Independent live workflow replay satisfied the deterministic family-proof contract.",
        "type": retest_type,
        "retest_type": retest_type,
        "route": finding_route,
        "method": proven_method,
        "url": finding_url,
        "canonical_vulnerability_key": canonical_vulnerability_key,
        "canonical_vulnerability_key_version": "v3",
        "canonical_vulnerability_dimensions": vulnerability_dimensions,
        "dedupe_dimensions": dedupe_dimensions,
        "family_proof": proof,
        "autonomous_workflow": {
            "family": family,
            "route": finding_route,
            "method": proven_method,
            "url": finding_url,
            "request_body": request_body or None,
            "workflow_id": workflow_id,
            "hypothesis_id": hypothesis_id,
            "reproduction_count": 2,
            "first_assertions": first.get("assertion_results") or [],
            "replay_assertions": replay.get("assertion_results") or [],
            "restoration_verified": proof.get("restoration_verified"),
            "evidence_instance_id": evidence_instance_id,
            "tool_receipt_id": tool_receipt_id,
        },
        "research_provenance": provenance,
        "research_provenance_history": list(unique_provenance.values()),
    })
    existing = known_match if known_match else await conn.fetchrow(
        "SELECT id, status FROM findings WHERE target_id=$1 AND fingerprint=$2",
        target_uuid,
        fingerprint,
    )
    if existing:
        finding_id = existing["id"]
        status = "resurfaced" if str(existing.get("status") or "") == "resolved" else "duplicate"
        await conn.execute(
            """
            UPDATE findings SET status='active', last_seen_at=NOW(),
                last_verification_status='still_vulnerable',
                last_verification_verdict='exploited',
                last_verification_confidence=1.0, last_verified_at=NOW(),
                fingerprint=$2, url=$3, source='autonomous', tool='autonomous_workflow',
                evidence=$4::jsonb, updated_at=NOW()
            WHERE id=$1
            """,
            finding_id,
            fingerprint,
            finding_url,
            json.dumps(evidence),
        )
    else:
        finding_id = await conn.fetchval(
            """
            INSERT INTO findings (
                target_id, fingerprint, title, description, severity, cvss_score,
                tool, cwe, url, evidence, notes, source, status,
                last_verification_status, last_verification_verdict,
                last_verification_confidence, last_verified_at
            ) VALUES (
                $1,$2,$3,$4,$5,$6,'autonomous_workflow',$7,$8,$9::jsonb,
                $10,'autonomous','active','still_vulnerable','exploited',1.0,NOW()
            ) RETURNING id
            """,
            target_uuid,
            fingerprint,
            title,
            str(hypothesis.get("description") or "Verified by two independent live workflow executions with deterministic assertions and restoration checks."),
            severity,
            {"critical": 9.1, "high": 8.1, "medium": 5.3, "low": 3.1, "info": 0.0}[severity],
            proof.get("cwe"),
            finding_url,
            json.dumps(evidence),
            "Created only after trusted live replay passed family proof and promotion gates.",
        )
        status = "created"
    if evidence_instance_id and _optional_uuid(evidence_instance_id):
        await conn.execute(
            "UPDATE evidence_instances SET finding_id=$1, proof_state='verified' WHERE id=$2",
            finding_id,
            uuid.UUID(evidence_instance_id),
        )
    await conn.execute(
        """
        UPDATE hypotheses SET status='promoted',
            promoted_finding_ids=(SELECT COALESCE(jsonb_agg(DISTINCT value), '[]'::jsonb)
                FROM jsonb_array_elements_text(promoted_finding_ids || $2::jsonb) AS value),
            terminal_reason='trusted_workflow_family_proof', version=version+1, updated_at=NOW()
        WHERE id=$1
        """,
        uuid.UUID(hypothesis_id),
        json.dumps([str(finding_id)]),
    )
    return {"finding_id": str(finding_id), "fingerprint": fingerprint, "status": status}








async def _link_command_result_to_campaign(conn, campaign_id, command_result_id) -> None:
    """Best-effort: stamp mission_campaign_id onto the campaign_action created for
    a command result. Never fails the surrounding operation."""
    if not campaign_id or not command_result_id:
        return
    try:
        await conn.execute(
            "UPDATE campaign_actions SET mission_campaign_id=$1, updated_at=NOW() WHERE command_result_id=$2",
            uuid.UUID(str(campaign_id)),
            uuid.UUID(str(command_result_id)),
        )
    except Exception:
        return


_CAMPAIGN_ACTION_STATUS_FROM_COMMAND_RESULT = {
    "planned": "planned",
    "completed": "completed",
    "queued": "queued",
    "running": "running",
    "blocked": "blocked",
    "approval_required": "approval_required",
    "approved": "approved",
    "partial": "partial",
    "degraded": "degraded",
    "failed": "failed",
    "cancelled": "cancelled",
    "evidence_bound": "evidence_bound",
    "retest_scheduled": "retest_scheduled",
    "refuter_requested": "refuter_requested",
}




async def _link_command_result_to_campaign_action(
    conn,
    campaign_action_id: str | uuid.UUID | None,
    command_result: dict[str, Any] | None,
) -> dict[str, Any] | None:
    """Bind an executed command result back to the planned campaign action row."""
    if not campaign_action_id or not isinstance(command_result, dict) or not command_result.get("id"):
        return None
    try:
        action_uuid = uuid.UUID(str(campaign_action_id))
        command_result_uuid = uuid.UUID(str(command_result.get("id")))
    except (TypeError, ValueError):
        return None
    status = _CAMPAIGN_ACTION_STATUS_FROM_COMMAND_RESULT.get(str(command_result.get("status") or ""), "completed")
    try:
        row = await conn.fetchrow(
            """
            UPDATE campaign_actions
            SET command_result_id=$1,
                status=$2,
                dry_run=$3,
                risk_tier=$4,
                scan_id=COALESCE($5, scan_id),
                scope_receipt_id=COALESCE($6, scope_receipt_id),
                approval_receipt_id=COALESCE($7, approval_receipt_id),
                finding_ids=$8::jsonb,
                hypothesis_ids=$9::jsonb,
                evidence_object_ids=$10::jsonb,
                tool_receipt_ids=$11::jsonb,
                blocked_by=$12::jsonb,
                next_action=COALESCE($13, next_action),
                operator_message=COALESCE($14, operator_message),
                result_json=COALESCE(result_json, '{}'::jsonb) || $15::jsonb,
                updated_at=NOW()
            WHERE id=$16
            RETURNING *
            """,
            command_result_uuid,
            status,
            bool(command_result.get("dry_run")),
            str(command_result.get("risk_tier") or "read_only"),
            _optional_uuid(command_result.get("scan_id")),
            command_result.get("scope_receipt_id") or None,
            _optional_uuid(command_result.get("approval_receipt_id")),
            json.dumps(command_result.get("finding_ids") or []),
            json.dumps(command_result.get("hypothesis_ids") or []),
            json.dumps(command_result.get("evidence_object_ids") or []),
            json.dumps(command_result.get("tool_receipt_ids") or []),
            json.dumps(command_result.get("blocked_by") or []),
            command_result.get("next_action"),
            command_result.get("operator_message"),
            json.dumps({
                "executed_command_result_id": str(command_result_uuid),
                "execution_linked_at": datetime.now(timezone.utc).isoformat(),
            }),
            action_uuid,
        )
        if row:
            # _record_command_result already auto-created a paired campaign_action for this
            # command result. Now that the PLANNED action is bound to it, delete that
            # auto-created duplicate so one execution maps to exactly one action row.
            await conn.execute(
                "DELETE FROM campaign_actions WHERE command_result_id=$1 AND id<>$2",
                command_result_uuid,
                action_uuid,
            )
        return _public_campaign_action_row(row) if row else None
    except Exception:
        return None






def _arsenal_action_state(
    req: ArsenalExecuteRequest,
    command_spec: dict[str, Any],
    *,
    catalog_status: str,
    risk_tier: str,
    phase: str,
    dispatched: bool,
    dry_run: bool,
    execution_enabled: bool,
    operation_id: str | None = None,
    command_result: dict[str, Any] | None = None,
    blocked_reason: str | None = None,
    gate_enabled: bool | None = None,
    missing_confirmations: list[str] | None = None,
    adapter_status: str | None = None,
) -> dict[str, Any]:
    required = list(command_spec.get("required_confirmations") or [])
    supplied = [str(item) for item in (req.confirmations or [])]
    missing = missing_confirmations if missing_confirmations is not None else [
        item for item in required if item not in supplied
    ]
    command_result_id = command_result.get("id") if isinstance(command_result, dict) else None
    return {
        "command": req.command,
        "catalog_status": catalog_status,
        "risk_tier": risk_tier,
        "phase": phase,
        "transition": {
            "from": "requested",
            "to": phase,
            "reason": blocked_reason,
        },
        "gate": {
            "execute_requested": bool(req.execute),
            "execute_feature_enabled": gate_enabled,
            "required_confirmations": required,
            "supplied_confirmations": supplied,
            "missing_confirmations": missing,
            "approval_receipt_id": req.approval_receipt_id,
        },
        "adapter_status": adapter_status,
        "dispatched": dispatched,
        "dry_run": dry_run,
        "execution_enabled": execution_enabled,
        "operation_id": operation_id,
        "command_result_id": command_result_id,
        "blocked_reason": blocked_reason,
    }




async def _arsenal_execute(conn, req: ArsenalExecuteRequest) -> dict[str, Any]:
    command, status, risk_tier = await _validate_arsenal_execute_request(conn, req)
    await _validate_campaign_action_for_execution(conn, req)

    readonly = _arsenal_readonly_adapters()
    gated = _arsenal_gated_adapters()

    # This command has two mutually exclusive contracts. Its target-scoped
    # dry-run is read-only even though execution of a consumed preview is
    # dangerous. Dispatch previews before the state-changing gateway so callers
    # do not need an execution flag, global active-work gate, or approval just to
    # inspect the immutable cohort.
    if req.command == "evidence.retention_sweep" and req.parameters.get("dry_run", True) is not False:
        result = await gated[req.command](req.parameters, None)
        cr = await _record_command_result(
            conn,
            command=req.command,
            status="completed",
            risk_tier="read_only",
            dry_run=True,
            target_id=req.parameters.get("target_id"),
            operator_message="Created a target-scoped immutable evidence-retention preview",
            result_json={
                "dispatched": True,
                "via": "arsenal.execute",
                "preview_id": result.get("preview_id"),
                "candidate_count": result.get("candidate_count", 0),
            },
            created_by=req.created_by,
        )
        await _link_command_result_to_campaign(conn, req.campaign_id, cr["id"])
        linked_action = await _link_command_result_to_campaign_action(conn, req.campaign_action_id, cr)
        return {
            "command": req.command,
            "dispatched": True,
            "dry_run": True,
            "result": result,
            "operation_id": cr["id"],
            "command_result": cr,
            "action_state": _arsenal_action_state(
                req,
                command,
                catalog_status=status,
                risk_tier="read_only",
                phase="completed",
                dispatched=True,
                dry_run=True,
                execution_enabled=False,
                operation_id=cr["id"],
                command_result=cr,
                missing_confirmations=[],
                adapter_status="dispatched",
            ),
            "campaign_action": linked_action,
            "execution_enabled": False,
        }

    # Read-only / dry-run inspection: safe, no state change -> dispatch directly.
    if req.command in readonly and status in {"read_only", "dry_run"}:
        result = await readonly[req.command](req.parameters)
        cr = await _record_command_result(
            conn,
            command=req.command,
            status="completed",
            risk_tier=risk_tier,
            operator_message=f"Executed {req.command} via arsenal execution gateway",
            result_json={"dispatched": True, "via": "arsenal.execute"},
            created_by=req.created_by,
        )
        await _link_command_result_to_campaign(conn, req.campaign_id, cr["id"])
        linked_action = await _link_command_result_to_campaign_action(conn, req.campaign_action_id, cr)
        return {
            "command": req.command,
            "dispatched": True,
            "dry_run": False,
            "result": result,
            "operation_id": cr["id"],
            "command_result": cr,
            "action_state": _arsenal_action_state(
                req,
                command,
                catalog_status=status,
                risk_tier=risk_tier,
                phase="completed",
                dispatched=True,
                dry_run=False,
                execution_enabled=True,
                operation_id=cr["id"],
                command_result=cr,
                adapter_status="dispatched",
            ),
            "campaign_action": linked_action,
            "execution_enabled": True,
        }

    if status in {"read_only", "dry_run"}:
        return await _arsenal_adapter_pending_response(
            conn,
            req,
            command,
            catalog_status=status,
            risk_tier=risk_tier,
        )

    # State-changing command: apply the same execution gate as the AI Ops router.
    required_confs = list(command.get("required_confirmations") or ())
    missing_confs = [c for c in required_confs if c not in (req.confirmations or [])]
    gate_on = _ai_ops_execute_enabled()
    blocked_reason = None
    if not req.execute:
        blocked_reason = "execute_not_requested"
    elif missing_confs:
        blocked_reason = f"missing_confirmation:{missing_confs[0]}"
    elif not gate_on:
        blocked_reason = "AI_OPS_ROUTER_EXECUTE_ENABLED_disabled"
    if blocked_reason:
        result_status = "approval_required" if blocked_reason in {"execute_not_requested"} or blocked_reason.startswith("missing_confirmation") else "blocked"
        cr = await _record_blocked_command_result(
            conn,
            action_name=req.command,
            command=req.command,
            risk_tier=risk_tier,
            status=result_status,
            blocked_by=[blocked_reason],
            operator_message=f"Did not execute {req.command}: {blocked_reason}",
            created_by=req.created_by,
        )
        await _link_command_result_to_campaign(conn, req.campaign_id, cr["id"] if cr else None)
        linked_action = await _link_command_result_to_campaign_action(conn, req.campaign_action_id, cr)
        return {
            "command": req.command,
            "dispatched": False,
            "dry_run": True,
            "execution_blocked_reason": blocked_reason,
            "operation_id": cr["id"] if cr else None,
            "command_result": cr,
            "action_state": _arsenal_action_state(
                req,
                command,
                catalog_status=status,
                risk_tier=risk_tier,
                phase=result_status,
                dispatched=False,
                dry_run=True,
                execution_enabled=False,
                operation_id=cr["id"] if cr else None,
                command_result=cr,
                blocked_reason=blocked_reason,
                gate_enabled=gate_on,
                missing_confirmations=missing_confs,
                adapter_status="not_dispatched",
            ),
            "campaign_action": linked_action,
            "execution_enabled": False,
        }

    # Gate satisfied: validate the approval receipt (records a blocked row on failure).
    await _validate_approval_receipt_for_action(
        conn,
        req.approval_receipt_id,
        target_url=str(req.parameters.get("target") or "").strip() or None,
        target_id=req.parameters.get("target_id"),
        action_name=req.command,
        command=req.command,
        risk_tier=risk_tier,
        created_by=req.created_by,
    )

    adapter = gated.get(req.command)
    if not adapter:
        cr = await _record_blocked_command_result(
            conn,
            action_name=req.command,
            command=req.command,
            risk_tier=risk_tier,
            status="blocked",
            blocked_by=["dispatch_adapter_pending"],
            operator_message=f"{req.command} passed the execution gate but has no gateway dispatch adapter yet; use its dedicated route",
            created_by=req.created_by,
        )
        await _link_command_result_to_campaign(conn, req.campaign_id, cr["id"] if cr else None)
        linked_action = await _link_command_result_to_campaign_action(conn, req.campaign_action_id, cr)
        return {
            "command": req.command,
            "dispatched": False,
            "dry_run": False,
            "execution_blocked_reason": "dispatch_adapter_pending",
            "operation_id": cr["id"] if cr else None,
            "command_result": cr,
            "action_state": _arsenal_action_state(
                req,
                command,
                catalog_status=status,
                risk_tier=risk_tier,
                phase="blocked",
                dispatched=False,
                dry_run=False,
                execution_enabled=False,
                operation_id=cr["id"] if cr else None,
                command_result=cr,
                blocked_reason="dispatch_adapter_pending",
                gate_enabled=gate_on,
                missing_confirmations=[],
                adapter_status="pending",
            ),
            "campaign_action": linked_action,
            "execution_enabled": False,
        }

    # The dispatched handler records its own command_result audit row.
    context_token = _ARSENAL_CREATED_BY_CONTEXT.set(req.created_by)
    try:
        adapter_parameters = dict(req.parameters)
        if req.research_hypothesis_id:
            adapter_parameters["_research_hypothesis_id"] = req.research_hypothesis_id
        result = await adapter(adapter_parameters, req.approval_receipt_id)
    finally:
        _ARSENAL_CREATED_BY_CONTEXT.reset(context_token)
    operation_id = result.get("operation_id") if isinstance(result, dict) else None
    command_result = None
    await _link_command_result_to_campaign(conn, req.campaign_id, operation_id)
    command_result = await _command_result_response_row(conn, operation_id)
    linked_action = await _link_command_result_to_campaign_action(conn, req.campaign_action_id, command_result)
    dispatched = bool(operation_id)
    blocked_reason = None if dispatched else "adapter_returned_no_operation_receipt"
    return {
        "command": req.command,
        "dispatched": dispatched,
        "dry_run": False,
        "execution_blocked_reason": blocked_reason,
        "result": result,
        "operation_id": operation_id,
        "command_result": command_result,
        "action_state": _arsenal_action_state(
            req,
            command,
            catalog_status=status,
            risk_tier=risk_tier,
            phase=str(result.get("status") or "dispatched") if isinstance(result, dict) else "dispatched",
            dispatched=dispatched,
            dry_run=False,
            execution_enabled=dispatched,
            operation_id=operation_id,
            command_result=command_result,
            gate_enabled=gate_on,
            missing_confirmations=[],
            blocked_reason=blocked_reason,
            adapter_status="dispatched" if dispatched else "no_operation_receipt",
        ),
        "campaign_action": linked_action,
        "execution_enabled": dispatched,
    }


























































# --- Cross-product mission timeline (§1) -------------------------------------
# Explicit, API-backed statuses so operators never infer state from scan JSON.











































async def _record_research_event(
    conn,
    episode_id: uuid.UUID,
    *,
    event_type: str,
    status: str,
    summary: str,
    observation_id: str | uuid.UUID | None = None,
    decision_id: str | uuid.UUID | None = None,
    command_result_id: str | uuid.UUID | None = None,
    details: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    row = await conn.fetchrow(
        """
        INSERT INTO research_events (
            episode_id, event_type, status, summary, observation_id,
            decision_id, command_result_id, details
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb)
        RETURNING *
        """,
        episode_id,
        event_type,
        status,
        str(summary or "")[:1000],
        _optional_uuid(observation_id),
        _optional_uuid(decision_id),
        _optional_uuid(command_result_id),
        json.dumps(_bounded_research_payload(details or {})),
    )
    return _public_research_event_row(row)




















# Keep a planner turn near 8k tokens before provider framing.  The old 48 KiB
# ceiling regularly left too little of a 250k campaign budget for 20+ useful
# decisions, especially when experiment schemas were also attached.


















def _research_rejection_is_policy_steering(errors: Any) -> bool:
    """Distinguish safe no-progress steering from planner/runtime failure.

    These errors prove the deterministic policy worked. They should create a new
    observation and exclude the rejected action, but must not consume the same
    three-strike breaker reserved for malformed output and controller failures.
    Model-token budgets still bound a planner that ignores repeated steering.
    """
    normalized = {str(error).strip() for error in errors or [] if str(error).strip()}
    if not normalized:
        return False
    fixed = {
        "known_vulnerability_already_covered",
        "repeated_action_without_state_change",
        "campaign_recon_cap_reached",
        "finding_retest_campaign_cap_reached",
    }
    return all(
        error in fixed
        or error.startswith(("semantic_dimension_exhausted:", "experiment_actuator_exhausted:"))
        for error in normalized
    )










































# Experiments the planner re-stamps with fresh identifiers / re-worded prose on every
# attempt. Only these get collapsed to a mechanical identity for dedupe.














def _canonical_vulnerability_route(value: Any) -> str | None:
    text = str(value or "").strip()
    if not text:
        return None
    parsed = urllib.parse.urlsplit(text if "://" in text else f"https://placeholder.invalid{text if text.startswith('/') else '/' + text}")
    path = parsed.path or "/"
    path = re.sub(r"(?i)/[0-9a-f]{8}-[0-9a-f-]{27,36}(?=/|$)", "/{id}", path)
    path = re.sub(r"/[0-9]+(?=/|$)", "/{id}", path)
    path = re.sub(r"(?i)/[0-9a-f]{16,}(?=/|$)", "/{id}", path)
    path = re.sub(r"\$?\{[^/{}]+\}|:[A-Za-z_][A-Za-z0-9_]*", "{id}", path)
    path = re.sub(r"/+", "/", path)
    # An object identifier addressed via a query parameter (e.g. crAPI's /orders/all?id=<uuid>) is
    # the SAME object operation as a path-segment id. Collapse such a query id into a trailing /{id}
    # so a query-string object access matches a path-style one and does not degrade to the bare
    # collection route -- otherwise the autobind can never match a query-string BOLA lead.
    if parsed.query and "{id}" not in path and re.search(
        r"(?:^|&)(?:id|[a-z0-9_]+_id)=[^&]+", parsed.query, re.IGNORECASE
    ):
        path = path.rstrip("/") + "/{id}"
    # Normalize a trailing slash: /api/Users/ and /api/Users are the same resource. Without this the
    # inventory's slash/no-slash variants split into different routes, so a create lead, its workflow,
    # and the promotion route-binding never line up.
    path = path.rstrip("/") or "/"
    return path[:1000]


def _research_vulnerability_dimensions(family: Any, *sources: Any) -> dict[str, Any]:
    """Extract stable identity dimensions that distinguish bugs on one operation."""
    raw_family = str(family or "").strip().lower().replace("-", "_").replace(" ", "_")
    canonical_family = family_proof.canonical_family(raw_family)
    parameters: set[str] = set()
    fields: set[str] = set()
    invariants: set[str] = set()
    predicates: set[str] = set()
    roles: set[str] = set()
    tenants: set[str] = set()
    locations: set[str] = set()
    variants: set[str] = set()

    def _add(target: set[str], value: Any) -> None:
        values: list[Any]
        if isinstance(value, dict):
            values = list(value.keys())
        elif isinstance(value, (list, tuple, set)):
            values = list(value)
        else:
            values = [value]
        for item in values:
            text = str(item or "").strip().lower()
            if text:
                target.add(text[:160])

    for source in sources:
        if not isinstance(source, dict):
            continue
        nested_sources = [source]
        for key in (
            "dedupe_dimensions", "canonical_vulnerability_dimensions",
            "metadata_json", "endpoint_hint",
        ):
            if isinstance(source.get(key), dict):
                nested_sources.append(source[key])
        for item in nested_sources:
            for key in ("parameter", "param", "parameter_name", "object_key", "object_id_key"):
                _add(parameters, item.get(key))
            for key in ("object_parameters", "query_keys"):
                _add(parameters, item.get(key))
            if not isinstance(item.get("parameters"), dict):
                _add(parameters, item.get("parameters"))
            for key in ("field", "field_name", "fields", "submitted_fields", "request_fields"):
                _add(fields, item.get(key))
            for key in ("json_body", "form_body"):
                _add(fields, item.get(key))
            if isinstance(item.get("query"), dict):
                _add(parameters, item["query"])
            for key in ("invariant_contract_id", "invariant_id", "invariants", "contract_kind", "operator"):
                _add(invariants, item.get(key))
            for key in ("predicate", "predicates", "assertion_predicates"):
                _add(predicates, item.get(key))
            for key in ("role", "roles", "subject_role", "required_role"):
                _add(roles, item.get(key))
            for key in ("tenant", "tenants", "tenant_id"):
                _add(tenants, item.get(key))
            for key in ("location", "locations", "injection_point", "parameter_location"):
                _add(locations, item.get(key))
            _add(variants, item.get("variant"))

    dimensions: dict[str, Any] = {}
    if canonical_family == "injection":
        if raw_family and raw_family != "injection":
            dimensions["variant"] = raw_family
        elif variants:
            dimensions["variant"] = sorted(variants)[0]
        if parameters:
            dimensions["parameters"] = sorted(parameters)
        if locations:
            dimensions["locations"] = sorted(locations)
    elif canonical_family == "bola":
        if parameters:
            dimensions["object_parameters"] = sorted(parameters)
        if tenants:
            dimensions["tenants"] = sorted(tenants)
    elif canonical_family == "mass_assignment":
        if fields:
            dimensions["fields"] = sorted(fields)
    elif canonical_family in {"field_constraint", "workflow"}:
        if fields:
            dimensions["fields"] = sorted(fields)
        if invariants:
            dimensions["invariants"] = sorted(invariants)
        if predicates:
            dimensions["predicates"] = sorted(predicates)
    elif canonical_family == "access_control":
        if invariants:
            dimensions["invariants"] = sorted(invariants)
        if predicates:
            dimensions["predicates"] = sorted(predicates)
        if roles:
            dimensions["roles"] = sorted(roles)
        if tenants:
            dimensions["tenants"] = sorted(tenants)
    return dimensions


def _canonical_vulnerability_key(
    *, family: Any, route: Any, method: Any = None, dimensions: Any = None,
) -> str | None:
    canonical_family = family_proof.canonical_family(family)
    canonical_route = _canonical_vulnerability_route(route)
    if not canonical_family or not canonical_route:
        return None
    # Method is part of the vulnerability identity: GET vs DELETE on the same object route are
    # distinct operations and must not collapse to one novelty key. '*' when the caller has no
    # method, and '*' only matches '*' (conservative -- an unknown method never suppresses a known one).
    canonical_method = str(method or "").strip().upper() or "*"
    canonical_dimensions = _research_vulnerability_dimensions(
        family,
        dimensions if isinstance(dimensions, dict) else {},
    )
    return hashlib.sha256(
        (
            f"vulnerability:v3|{canonical_family}|{canonical_method}|{canonical_route}|"
            + json.dumps(canonical_dimensions, sort_keys=True, separators=(",", ":"))
        ).encode()
    ).hexdigest()










































































_CAMPAIGN_MAX_CONSECUTIVE_BLOCKED = 3


async def _record_campaign_blocker(
    conn,
    campaign_id: Any,
    *,
    kind: str,
    episode_id: str | None = None,
    detail: str | None = None,
) -> None:
    """Append a durable, bounded blocker to a campaign (escalate-don't-block).

    Blockers are advisory context surfaced in the campaign report so an operator can see why the loop
    had to skip or terminate work -- without the campaign having to stop and wait for an answer.
    """
    row = await conn.fetchrow("SELECT metadata_json FROM campaigns WHERE id=$1", campaign_id)
    if not row:
        return
    metadata = _decode_json_value(row["metadata_json"]) or {}
    config = metadata.get("autonomous_research") if isinstance(metadata.get("autonomous_research"), dict) else {}
    existing = config.get("blockers") if isinstance(config.get("blockers"), list) else []
    blocker = {
        "kind": str(kind)[:80],
        "episode_id": str(episode_id) if episode_id else None,
        "detail": str(detail)[:300] if detail else None,
        "at": datetime.now(timezone.utc).isoformat(),
    }
    blockers = [*existing, blocker][-20:]
    await conn.execute(
        """
        UPDATE campaigns
        SET metadata_json=jsonb_set(metadata_json, '{autonomous_research,blockers}', $2::jsonb, true),
            updated_at=NOW()
        WHERE id=$1
        """,
        campaign_id, json.dumps(blockers),
    )


def _research_campaign_terminal_needs_review(
    config: dict[str, Any], latest_episode_id: Any, latest_status: Any,
) -> bool:
    """Return true once per failed/blocked/cancelled terminal episode until operator resume."""
    episode_id = str(latest_episode_id or "")
    return bool(
        episode_id
        and str(latest_status or "") in {"blocked", "failed"}
        and str(config.get("last_paused_episode_id") or "") != episode_id
    )


async def _continue_autonomous_research_campaigns() -> int:
    """Start the next episode for active campaigns with no non-terminal episode."""
    # D2: reap stuck non-terminal episodes so their campaign becomes visible to the chaining/completion
    # logic below. An episode waiting on operator input, or left in a planning state after the autopilot
    # breaker disabled it (3 consecutive failures) with an expired lease, would otherwise count as
    # "active" forever -- freezing the whole campaign (it never even reaches the deadline/ceiling check).
    # Force it terminal ('blocked'); the terminal-review branch then records a blocker and chains a fresh
    # episode (escalate-don't-block). The lease/autopilot guards avoid racing an actively-planning runner.
    async with db_pool.acquire() as conn:
        await conn.execute(
            """
            UPDATE research_episodes e SET
                status='blocked',
                stop_reason=COALESCE(e.stop_reason, CASE WHEN e.status='awaiting_input'
                    THEN 'operator_input_requested' ELSE 'autopilot_disabled_after_failures' END),
                autopilot_error=COALESCE(e.autopilot_error, 'reaped_by_campaign_supervisor'),
                updated_at=NOW()
            FROM campaigns c
            WHERE e.campaign_id=c.id
              AND c.campaign_type='autonomous_research' AND c.status='active'
              AND e.status NOT IN ('completed','cancelled','failed','budget_exhausted','blocked')
              AND (
                  e.status='awaiting_input'
                  OR (e.status IN ('awaiting_planner','awaiting_observation')
                      AND e.autopilot_enabled=false
                      AND COALESCE(c.metadata_json->'autonomous_research'->>'planner_mode',
                                   e.planner->>'mode', 'configured_ai') = 'configured_ai'
                      AND (e.lease_expires_at IS NULL OR e.lease_expires_at < NOW()))
              )
            """
        )
    async with db_pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT c.*, COUNT(re.id)::int AS episode_count,
                   (ARRAY_AGG(re.id ORDER BY re.created_at DESC)
                       FILTER (WHERE re.id IS NOT NULL))[1] AS latest_episode_id,
                   (ARRAY_AGG(re.status ORDER BY re.created_at DESC)
                       FILTER (WHERE re.id IS NOT NULL))[1] AS latest_episode_status
            FROM campaigns c
            LEFT JOIN research_episodes re ON re.campaign_id=c.id
            WHERE c.campaign_type='autonomous_research' AND c.status='active'
              AND NOT EXISTS (
                  SELECT 1 FROM research_episodes active
                  WHERE active.campaign_id=c.id
                    AND active.status NOT IN ('completed','cancelled','failed','budget_exhausted','blocked')
              )
            GROUP BY c.id ORDER BY c.updated_at ASC LIMIT 5
            """
        )
    started = 0
    for row in rows:
        payload = row_to_dict(row)
        metadata = _decode_json_value(payload.get("metadata_json")) or {}
        config = metadata.get("autonomous_research") if isinstance(metadata.get("autonomous_research"), dict) else {}
        try:
            deadline = datetime.fromisoformat(str(config.get("deadline_at") or "").replace("Z", "+00:00"))
            if deadline.tzinfo is None:
                deadline = deadline.replace(tzinfo=timezone.utc)
        except (TypeError, ValueError):
            deadline = datetime.now(timezone.utc)
        count = int(payload.get("episode_count") or 0)
        try:
            maximum = max(1, min(100, int(config.get("max_episodes") or 1)))
        except (TypeError, ValueError):
            maximum = 1
        if deadline <= datetime.now(timezone.utc) or count >= maximum:
            async with db_pool.acquire() as conn:
                await conn.execute("UPDATE campaigns SET status='completed', updated_at=NOW() WHERE id=$1", row["id"])
            continue
        async with db_pool.acquire() as conn:
            current_campaign = await conn.fetchrow("SELECT * FROM campaigns WHERE id=$1", row["id"])
            readiness = await _research_campaign_readiness(conn, current_campaign)
        if not readiness.get("ready"):
            await _research_campaign_self_repair(row["id"])
            continue
        async with db_pool.acquire() as conn:
            invariant_hypotheses = await _materialize_research_invariant_hypotheses(
                conn,
                row["target_id"],
            )
            budget = await _research_campaign_budget_snapshot(conn, current_campaign)
            episode_budget_limits = _research_campaign_episode_budget_limits(
                str(config.get("intensity") or "deep_hunt"),
                budget["remaining"],
            )
            latest_metadata = _decode_json_value(current_campaign.get("metadata_json")) or {}
            latest_config = (
                latest_metadata.get("autonomous_research")
                if isinstance(latest_metadata.get("autonomous_research"), dict)
                else {}
            )
            latest_config.update({
                "preflight_state": "completed",
                "preflight_scan_id": str((readiness.get("preflight_scan") or {}).get("id") or latest_config.get("preflight_scan_id") or "") or None,
                "readiness": readiness,
                "surface_after_preflight": readiness.get("surface") or {},
                "invariant_hypotheses_materialized": invariant_hypotheses,
                "budget_limits": budget["limits"],
                "budget_used": budget["used"],
                "remaining_budget": budget["remaining"],
                "effective_families": list(
                    (readiness.get("surface") or {}).get("executable_families") or []
                ),
            })
            latest_metadata["autonomous_research"] = latest_config
            if not _research_campaign_episode_budget_available(episode_budget_limits):
                latest_config["last_error"] = "campaign_budget_exhausted"
                latest_metadata["autonomous_research"] = latest_config
                await conn.execute(
                    "UPDATE campaigns SET status='completed', metadata_json=$2::jsonb, updated_at=NOW() WHERE id=$1",
                    row["id"],
                    json.dumps(latest_metadata, default=str),
                )
                continue
            await conn.execute(
                "UPDATE campaigns SET metadata_json=$2::jsonb, updated_at=NOW() WHERE id=$1",
                row["id"],
                json.dumps(latest_metadata, default=str),
            )
            refreshed_campaign = await conn.fetchrow("SELECT * FROM campaigns WHERE id=$1", row["id"])
            yield_metrics = await _research_campaign_yield_metrics(conn, refreshed_campaign)
            if yield_metrics.get("stop_recommended"):
                latest_config["yield"] = yield_metrics
                latest_config["last_error"] = yield_metrics.get("stop_reason")
                latest_metadata["autonomous_research"] = latest_config
                await conn.execute(
                    "UPDATE campaigns SET status='paused', metadata_json=$2::jsonb, updated_at=NOW() WHERE id=$1",
                    row["id"],
                    json.dumps(latest_metadata, default=str),
                )
                continue
        latest_episode_id = str(payload.get("latest_episode_id") or "")
        latest_status = str(payload.get("latest_episode_status") or "")
        # An operator cancelling THIS episode is an explicit stop, not a recoverable planner failure --
        # do NOT relaunch active testing ~30s later. Pause the campaign; an explicit resume restarts it.
        if latest_status == "cancelled" and str(config.get("last_paused_episode_id") or "") != latest_episode_id:
            async with db_pool.acquire() as conn:
                await conn.execute(
                    """
                    UPDATE campaigns SET status='paused',
                        metadata_json=jsonb_set(
                            jsonb_set(metadata_json, '{autonomous_research,last_paused_episode_id}', to_jsonb($2::text), true),
                            '{autonomous_research,last_error}', to_jsonb($3::text), true),
                        updated_at=NOW() WHERE id=$1
                    """,
                    row["id"], latest_episode_id,
                    "Latest research episode was cancelled by an operator; campaign paused (resume to continue)",
                )
            continue
        # Escalate-don't-block: a blocked/failed episode is recorded as a durable blocker and the campaign
        # keeps moving (a fresh episode is chained) so it stays autonomous. Only after several consecutive
        # unrecovered episodes do we pause for real operator review -- a systemic failure, not a dead end.
        from_review = False
        if _research_campaign_terminal_needs_review(config, latest_episode_id, latest_status):
            consecutive_blocked = int(config.get("consecutive_blocked") or 0) + 1
            async with db_pool.acquire() as conn:
                await _record_campaign_blocker(
                    conn, row["id"], kind=f"episode_{latest_status}", episode_id=latest_episode_id,
                )
                if consecutive_blocked >= _CAMPAIGN_MAX_CONSECUTIVE_BLOCKED:
                    await conn.execute(
                        """
                        UPDATE campaigns SET status='paused',
                            metadata_json=jsonb_set(jsonb_set(jsonb_set(metadata_json,
                                '{autonomous_research,last_paused_episode_id}', to_jsonb($2::text), true),
                                '{autonomous_research,consecutive_blocked}', to_jsonb($3::int), true),
                                '{autonomous_research,last_error}', to_jsonb($4::text), true),
                            updated_at=NOW() WHERE id=$1
                        """,
                        row["id"], latest_episode_id, consecutive_blocked,
                        f"Paused after {consecutive_blocked} consecutive unrecovered episodes (last ended {latest_status})",
                    )
                    continue
                await conn.execute(
                    """
                    UPDATE campaigns SET
                        metadata_json=jsonb_set(jsonb_set(metadata_json,
                            '{autonomous_research,last_paused_episode_id}', to_jsonb($2::text), true),
                            '{autonomous_research,consecutive_blocked}', to_jsonb($3::int), true),
                        updated_at=NOW() WHERE id=$1
                    """,
                    row["id"], latest_episode_id, consecutive_blocked,
                )
            from_review = True
        try:
            effective_families = list(
                (readiness.get("surface") or {}).get("executable_families") or []
            )
            planner_mode = str(config.get("planner_mode") or "configured_ai")
            await launch_research_episode(ResearchLaunchRequest(
                subject_type="target", subject_id=str(row["target_id"]), mission_profile="target_hunt",
                intensity=str(config.get("intensity") or "deep_hunt"),
                approval_receipt_id=config.get("approval_receipt_id"),
                planner_mode=planner_mode,
                autopilot=planner_mode == "configured_ai",
                force_new=True,
                created_by="research_campaign_supervisor", campaign_id=str(row["id"]),
                objective_override=config.get("objective"),
                allowed_families_override=effective_families,
                budget_limits_override=episode_budget_limits,
                agent_loop=bool(config.get("agent_loop")),
            ))
        except asyncpg.UniqueViolationError:
            continue
        except Exception as exc:
            async with db_pool.acquire() as conn:
                await conn.execute(
                    """
                    UPDATE campaigns SET status='paused',
                        metadata_json=jsonb_set(metadata_json, '{autonomous_research,last_error}', to_jsonb($2::text), true),
                        updated_at=NOW() WHERE id=$1
                    """,
                    row["id"], str(exc)[:500],
                )
            continue
        async with db_pool.acquire() as conn:
            # Reset the consecutive-blocked counter when chaining after a clean (non-review) episode;
            # keep the just-incremented value when retrying after a recorded blocker.
            await conn.execute(
                """
                UPDATE campaigns SET
                    metadata_json=jsonb_set(
                        jsonb_set(
                            CASE WHEN $3 THEN metadata_json
                                 ELSE jsonb_set(metadata_json, '{autonomous_research,consecutive_blocked}', '0'::jsonb, true) END,
                            '{autonomous_research,episodes_started}', to_jsonb($2::int), true),
                        '{autonomous_research,last_error}', 'null'::jsonb, true),
                    updated_at=NOW() WHERE id=$1
                """,
                row["id"], count + 1, from_review,
            )
        started += 1
    return started








# Hard cap on observations per episode. POST /observe consumes no budget, so bound
# unbounded row growth (each observation row is itself size-bounded). 500 is generous
# relative to the <=25-step episode budget.






















# Concrete, contract-valid workflow proof templates per promotable family. The planner copies the
# matching template and fills in real routes/objects/principals from the observation; keeping the
# checkpoints, assertion types, and predicates verbatim is what makes the proof both structurally
# valid (normalize_workflow) and server-corroborable. Every template is asserted valid in tests.


# Create-based mass-assignment: POST /collection overposts a privilege field; the created object is read
# back at /collection/${created_id} and the created objects are DELETE-cleaned. Restoration is the
# collection list (exists before creation and after cleanup). The proof binds the read-back to the
# created object via the extracted id (see workflow_experiment._create_object_readback).


_CREATE_MA_LOGIN_TOKENS = ("email", "mail", "login", "username", "user")
_CREATE_MA_SECRET_TOKENS = ("password", "passwd", "passphrase", "pwd", "secret", "pass")
_CREATE_MA_ID_ENVELOPES = ("data", "result", "item", "user", "record", "payload")


def _classify_create_field(name: str) -> str:
    """Universal field-name heuristic: is a create-body field a login, a secret, or something else.

    Uses only conventional field naming (email/password/...), never a target-specific fact.
    """
    low = re.sub(r"[^a-z0-9]+", "", str(name or "").lower())
    if any(token in low for token in _CREATE_MA_SECRET_TOKENS):
        return "secret"
    if any(token in low for token in _CREATE_MA_LOGIN_TOKENS):
        return "login"
    return "other"


def _discover_create_object_shape(response_json: Any) -> tuple[str | None, str] | None:
    """Locate a created object's envelope + id field in a real create response, universally.

    Returns (envelope_key_or_None, id_field) or None. Checks the root object then one level of common
    REST envelopes for an id-like scalar key -- so the created-id extract path is discovered, not guessed.
    """
    def _id_field(obj: dict[str, Any]) -> str | None:
        for key in obj:
            if str(key).lower() == "id" and not isinstance(obj[key], (dict, list)):
                return str(key)
        for key in obj:
            low = str(key).lower()
            if low.endswith("id") and not isinstance(obj[key], (dict, list)):
                return str(key)
        return None

    if not isinstance(response_json, dict):
        return None
    root_id = _id_field(response_json)
    if root_id:
        return (None, root_id)
    for env in _CREATE_MA_ID_ENVELOPES:
        nested = response_json.get(env)
        if isinstance(nested, dict):
            nested_id = _id_field(nested)
            if nested_id:
                return (env, nested_id)
    return None


def _create_mass_assignment_credentials() -> dict[str, str]:
    """Server-generated, unique-per-run throwaway credentials for a create-MA experiment.

    Never model-supplied (only their sha256 is persisted as principal_variable receipts). Two distinct
    logins so a unique-identifier constraint cannot collide across the control and mutate creates.
    """
    nonce = uuid.uuid4().hex
    return {
        "ctrl_login": f"shakerscan-ma-c-{nonce[:14]}@shakerscan-probe.test",
        "adm_login": f"shakerscan-ma-m-{nonce[14:28]}@shakerscan-probe.test",
        "reg_cred": "ShakerScan9!" + uuid.uuid4().hex[:12],
    }


def _inject_create_mass_assignment_credentials(
    principal_contexts: dict[str, dict[str, Any]], normalized: dict[str, Any],
) -> None:
    """Refresh server-generated create-MA credentials before EACH run of the two-run.

    A create with a unique-identifier constraint (e.g. a registration email) would collide on the
    replay if both runs reused one login, breaking the two-run. Fresh unique credentials per run keep
    it sound; the predicates, assertion shapes, and proof routes are identical across runs regardless
    of the concrete login. No-op for every non-create-based-mass_assignment workflow. Values are
    server-generated (never model-supplied); only their sha256 receipts persist.
    """
    if not _is_create_based_mass_assignment(normalized.get("proof_family"), normalized):
        return
    fresh = _create_mass_assignment_credentials()
    for binding in normalized.get("principal_variables") or []:
        ref = str(binding.get("ref") or "")
        if ref not in fresh:
            continue
        context = principal_contexts.setdefault(str(binding.get("principal") or "user1"), {})
        refs = context.get("captured_refs")
        if not isinstance(refs, dict):
            refs = {}
            context["captured_refs"] = refs
        refs[ref] = fresh[ref]


def _materialize_create_mass_assignment_workflow(
    *,
    collection_route: str,
    request_fields: str | None,
    forbidden_field: str,
    forbidden_value: str,
    envelope: str | None,
    id_field: str,
) -> dict[str, Any] | None:
    """Build a complete create-based mass_assignment workflow from a lead + discovered response shape.

    Universal: field roles come from name heuristics; extract/read-back paths from the discovered
    envelope. Requires a login-like field (a unique identifier, so the two independent creates do not
    collide) and a forbidden field; returns None otherwise rather than fabricate an unprovable workflow.
    """
    collection = "/" + str(collection_route or "").strip().strip("/")
    forbidden = str(forbidden_field or "").strip()
    fields = [f.strip() for f in str(request_fields or "").split(",") if f.strip()]
    roles = {f: _classify_create_field(f) for f in fields}
    if not forbidden or not any(role == "login" for role in roles.values()):
        return None
    id_path = f"$.{envelope}.{id_field}" if envelope else f"$.{id_field}"
    forbidden_path = f"$.{envelope}.{forbidden}" if envelope else f"$.{forbidden}"

    def _body(login_var: str, include_forbidden: bool) -> dict[str, Any]:
        body: dict[str, Any] = {}
        for field in fields:
            if field == forbidden:
                continue
            role = roles[field]
            body[field] = (
                "${%s}" % login_var if role == "login"
                else "${reg_cred}" if role == "secret"
                else "shakerscan-benign"
            )
        if include_forbidden:
            body[forbidden] = forbidden_value
        return body

    return {
        "proof_family": "mass_assignment",
        "objective": f"{forbidden}={forbidden_value} overposted on POST {collection} persists in the created object",
        "expected_signal": "the create succeeds and the created-object read-back shows the forbidden field, while a benign create does not",
        "falsifier": "the create fails, the forbidden field is rejected, or the read-back does not show it",
        "principal_variables": [
            {"name": "ctrl_login", "principal": "user1", "ref": "ctrl_login"},
            {"name": "adm_login", "principal": "user1", "ref": "adm_login"},
            {"name": "reg_cred", "principal": "user1", "ref": "reg_cred"},
        ],
        "steps": [
            {"label": "list_before", "kind": "http", "principal": "user1", "checkpoint": "before", "method": "GET", "path": collection},
            {"label": "control", "kind": "http", "principal": "user1", "checkpoint": "mutation", "method": "POST", "path": collection, "json_body": _body("ctrl_login", False), "extract": [{"name": "control_id", "source": "json", "path": id_path}]},
            {"label": "mutate", "kind": "http", "principal": "user1", "checkpoint": "mutation", "method": "POST", "path": collection, "json_body": _body("adm_login", True), "extract": [{"name": "created_id", "source": "json", "path": id_path}]},
            {"label": "control_verify", "kind": "http", "principal": "user1", "checkpoint": "action", "method": "GET", "path": collection + "/${control_id}", "select_json": [forbidden_path]},
            {"label": "verify", "kind": "http", "principal": "user1", "checkpoint": "action", "method": "GET", "path": collection + "/${created_id}", "select_json": [forbidden_path], "compare_to": "control_verify"},
            {"label": "cleanup_created", "kind": "http", "principal": "user1", "checkpoint": "cleanup", "method": "DELETE", "path": collection + "/${created_id}"},
            {"label": "cleanup_control", "kind": "http", "principal": "user1", "checkpoint": "cleanup", "method": "DELETE", "path": collection + "/${control_id}"},
            {"label": "list_after", "kind": "http", "principal": "user1", "checkpoint": "after", "method": "GET", "path": collection, "compare_to": "list_before"},
        ],
        "assertions": [
            {"type": "status_in", "step": "control", "values": [200, 201, 202, 204], "predicate": "benign_control_accepted"},
            {"type": "status_in", "step": "mutate", "values": [200, 201, 202, 204], "predicate": "forbidden_field_accepted"},
            {"type": "comparison_changed", "control": "control_verify", "candidate": "verify", "predicate": "observable_state_change"},
            {"type": "restored", "control": "list_before", "candidate": "list_after", "predicate": "before_after_state"},
        ],
    }


async def _probe_create_surface(
    target_url: str,
    collection_route: str,
    headers: dict[str, str],
    cookies: dict[str, str] | None = None,
    transport: Any = None,
) -> dict[str, Any]:
    """Discover a create body/response shape and immediately clean up the probe object.

    The first accepted create must expose a scalar identifier and its same-principal DELETE must
    succeed. Otherwise probing stops and the workflow is not materialized. This retains autonomous
    schema discovery without silently accumulating registration artifacts.
    """
    import httpx
    from urllib.parse import quote

    try:
        path = agent_tools.validate_same_origin_path(collection_route)
    except agent_tools.AgentToolError:
        return {
            "usable": False,
            "reason": "probe_collection_outside_same_origin_scope",
            "request_count": 0,
            "cleanup_request_count": 0,
            "artifacts": [],
        }
    parsed_path = urllib.parse.urlsplit(path)
    if parsed_path.query or parsed_path.fragment:
        return {
            "usable": False,
            "reason": "probe_collection_must_not_include_query_or_fragment",
            "request_count": 0,
            "cleanup_request_count": 0,
            "artifacts": [],
        }
    path = parsed_path.path
    url = _provision_same_origin_url(target_url, path)
    creds = _create_mass_assignment_credentials()
    candidate_bodies = [
        {"email": creds["ctrl_login"], "password": creds["reg_cred"], "passwordRepeat": creds["reg_cred"]},
        {"email": creds["ctrl_login"], "password": creds["reg_cred"]},
        {"username": creds["ctrl_login"], "email": creds["ctrl_login"], "password": creds["reg_cred"]},
    ]
    safe_headers = {k: v for k, v in (headers or {}).items() if k.lower() == "authorization"}
    request_count = 0
    cleanup_request_count = 0
    artifacts: list[dict[str, Any]] = []
    try:
        async with httpx.AsyncClient(
            timeout=12,
            trust_env=False,
            follow_redirects=False,
            transport=transport,
            cookies=cookies or {},
        ) as client:
            for body in candidate_bodies:
                try:
                    request_count += 1
                    resp = await client.post(
                        url,
                        json=body,
                        headers=safe_headers,
                    )
                except httpx.HTTPError:
                    continue
                if resp.status_code not in (200, 201, 202, 204):
                    continue
                try:
                    response_json = resp.json()
                    shape = _discover_create_object_shape(response_json)
                except (ValueError, TypeError):
                    response_json = None
                    shape = None
                if not shape:
                    # A 2xx create with no id-bearing body (an empty 204, or a registration that echoes
                    # no identifier) still created a real object -- we must not silently walk away and
                    # leave it behind. Best-effort cleanup: RFC-7231 says a 201's Location header points
                    # at the created resource, so DELETE that when it is same-origin. Whatever the
                    # outcome, record the residual (login hash + status) as an artifact so an uncleaned
                    # object is visible in telemetry rather than silent.
                    residual = {
                        "login_sha256": hashlib.sha256(str(creds["ctrl_login"]).encode()).hexdigest(),
                        "create_status": resp.status_code,
                        "cleanup_attempted": False,
                        "cleanup_succeeded": False,
                    }
                    location = resp.headers.get("location")
                    if location:
                        joined = urllib.parse.urljoin(url, location)
                        if (
                            urllib.parse.urlsplit(joined)[:2]
                            == urllib.parse.urlsplit(target_url)[:2]
                            and urllib.parse.urlsplit(joined).path.startswith("/")
                        ):
                            residual["cleanup_attempted"] = True
                            try:
                                cleanup_request_count += 1
                                cleanup = await client.delete(joined, headers=safe_headers)
                                residual["cleanup_status"] = cleanup.status_code
                                residual["cleanup_succeeded"] = cleanup.status_code in (200, 202, 204)
                            except httpx.HTTPError:
                                residual["cleanup_status"] = None
                    artifacts.append(residual)
                    return {
                        "usable": False,
                        "reason": (
                            "accepted_probe_missing_trackable_id_residual_cleaned"
                            if residual["cleanup_succeeded"]
                            else "accepted_probe_missing_trackable_id_residual_uncleaned"
                        ),
                        "request_count": request_count,
                        "cleanup_request_count": cleanup_request_count,
                        "artifacts": artifacts,
                    }
                envelope, id_field = shape
                created_object = (
                    response_json.get(envelope)
                    if envelope and isinstance(response_json, dict)
                    else response_json
                )
                created_id = (
                    created_object.get(id_field)
                    if isinstance(created_object, dict)
                    else None
                )
                if created_id in (None, "") or isinstance(created_id, (dict, list)):
                    return {
                        "usable": False,
                        "reason": "accepted_probe_identifier_invalid",
                        "request_count": request_count,
                        "cleanup_request_count": cleanup_request_count,
                        "artifacts": artifacts,
                    }
                artifact = {
                    "id_sha256": hashlib.sha256(str(created_id).encode()).hexdigest(),
                    "cleanup_attempted": True,
                    "cleanup_succeeded": False,
                }
                artifacts.append(artifact)
                cleanup_url = _provision_same_origin_url(
                    target_url,
                    path.rstrip("/") + "/" + quote(str(created_id), safe=""),
                )
                try:
                    cleanup_request_count += 1
                    cleanup = await client.delete(
                        cleanup_url,
                        headers=safe_headers,
                    )
                    artifact["cleanup_status"] = cleanup.status_code
                    artifact["cleanup_succeeded"] = cleanup.status_code in (200, 202, 204)
                except httpx.HTTPError:
                    artifact["cleanup_status"] = None
                if not artifact["cleanup_succeeded"]:
                    return {
                        "usable": False,
                        "reason": "probe_cleanup_unconfirmed",
                        "request_count": request_count,
                        "cleanup_request_count": cleanup_request_count,
                        "artifacts": artifacts,
                    }
                return {
                    "usable": True,
                    "request_fields": ",".join(body.keys()),
                    "envelope": envelope,
                    "id_field": id_field,
                    "request_count": request_count,
                    "cleanup_request_count": cleanup_request_count,
                    "artifacts": artifacts,
                }
    except Exception:
        logger.warning("create-surface probe failed for %s", path, exc_info=True)
        return {
            "usable": False,
            "reason": "probe_runtime_error",
            "request_count": request_count,
            "cleanup_request_count": cleanup_request_count,
            "artifacts": artifacts,
        }
    return {
        "usable": False,
        "reason": "no_create_candidate_accepted",
        "request_count": request_count,
        "cleanup_request_count": cleanup_request_count,
        "artifacts": artifacts,
    }


async def _server_materialize_create_ma(
    conn: Any,
    target_url: str,
    target_uuid: uuid.UUID,
    params: dict[str, Any],
    hypothesis_id: str | None,
    approval_receipt_id: str | None = None,
) -> bool:
    """When a create-based mass_assignment lead is dispatched WITHOUT a planner-supplied workflow, the
    server discovers the real create body (active probe) and materializes the workflow itself, so the
    planner only has to SELECT the lead. Respects a planner-supplied workflow (does nothing if steps are
    present). Returns True if it materialized. Backstopped end-to-end by the family proof."""
    if params.get("steps") or not hypothesis_id:
        return False
    hypothesis_uuid = _optional_uuid(hypothesis_id)
    if not hypothesis_uuid:
        return False
    row = await conn.fetchrow(
        "SELECT family, metadata_json FROM hypotheses WHERE id=$1 AND target_id=$2",
        hypothesis_uuid, target_uuid,
    )
    if not row or family_proof.canonical_family(row.get("family")) != "mass_assignment":
        return False
    metadata = _decode_json_value(row.get("metadata_json")) or {}
    collection = str(metadata.get("route") or "").strip()
    if not metadata.get("create_based") or not collection:
        return False
    cleanup_rows = await conn.fetch(
        """
        SELECT path FROM target_endpoints
        WHERE target_id=$1 AND upper(method)='DELETE' AND COALESCE(test_status, '') <> 'gone'
        """,
        target_uuid,
    )
    expected_cleanup_route = (
        (_canonical_vulnerability_route(collection) or "").rstrip("/") + "/{id}"
    )
    if not any(
        _canonical_vulnerability_route(row.get("path")) == expected_cleanup_route
        for row in cleanup_rows
    ):
        params["_server_materialization"] = {
            "usable": False,
            "reason": "cleanup_route_not_on_discovered_surface",
            "request_count": 0,
            "cleanup_request_count": 0,
            "artifacts": [],
        }
        return False
    try:
        contexts = await _resolve_workflow_principal_contexts(conn, target_uuid, {"user1"})
    except WorkflowContractError:
        # Do not mutate anonymously and only then discover the credential-bound workflow is invalid.
        return False
    context = contexts.get("user1") if isinstance(contexts.get("user1"), dict) else {}
    started_at = datetime.now(timezone.utc)
    probe = await _probe_create_surface(
        target_url,
        collection,
        context.get("headers") or {},
        context.get("cookies") or {},
    )
    materialization = {
        "usable": bool(probe.get("usable")),
        "reason": probe.get("reason"),
        "request_count": int(probe.get("request_count") or 0),
        "cleanup_request_count": int(probe.get("cleanup_request_count") or 0),
        "artifacts": probe.get("artifacts") or [],
    }
    if materialization["request_count"]:
        receipt_result = await _record_tool_receipt(conn, ToolReceiptRequest(
            tool_name="experiment.create_surface_probe",
            adapter_version="2026-07-18.v1",
            redacted_argv=[
                "experiment.create_surface_probe",
                str(target_uuid),
                _canonical_vulnerability_route(collection) or "/",
            ],
            target_scope={
                "target_id": str(target_uuid),
                "target_url": target_url,
                "same_origin_only": True,
            },
            approval_receipt_id=approval_receipt_id,
            status="success" if materialization["usable"] else "failed",
            parser_status="parsed",
            started_at=started_at.isoformat(),
            finished_at=datetime.now(timezone.utc).isoformat(),
            redaction_summary="Managed credentials stayed in memory; artifact identifiers are hashed.",
            metadata_json=materialization,
            created_by="research_create_surface_probe",
        ))
        materialization["tool_receipt_id"] = (
            receipt_result.get("tool_receipt") or {}
        ).get("id")
    params["_server_materialization"] = materialization
    if not probe.get("usable"):
        return False
    # role=admin is the dominant privilege-escalation overpost; a wrong field is falsified by the proof.
    workflow = _materialize_create_mass_assignment_workflow(
        collection_route=collection, request_fields=probe["request_fields"],
        forbidden_field="role", forbidden_value="admin",
        envelope=probe["envelope"], id_field=probe["id_field"],
    )
    if not workflow:
        materialization["usable"] = False
        materialization["reason"] = "discovered_shape_not_materializable"
        return False
    for key in ("proof_family", "objective", "expected_signal", "falsifier",
                "principal_variables", "assertions", "steps"):
        params[key] = workflow[key]
    return True






















async def _release_research_autopilot_lease(
    pool,
    episode_id: str,
    owner: str,
    *,
    error: str | None = None,
) -> None:
    async with pool.acquire() as conn:
        if error:
            row = await conn.fetchrow(
                """
                UPDATE research_episodes
                SET autopilot_error=$3,
                    autopilot_consecutive_failures=autopilot_consecutive_failures+1,
                    autopilot_enabled=CASE WHEN autopilot_consecutive_failures+1 < 3 THEN autopilot_enabled ELSE false END,
                    lease_owner=NULL,
                    lease_expires_at=CASE
                        WHEN autopilot_consecutive_failures+1 < 3 THEN NOW() + make_interval(secs => LEAST(60, 5 * (autopilot_consecutive_failures+1)))
                        ELSE NULL
                    END,
                    updated_at=NOW()
                WHERE id=$1 AND lease_owner=$2
                RETURNING id, autopilot_enabled, autopilot_consecutive_failures
                """,
                uuid.UUID(episode_id), owner, error[:1000],
            )
            if row:
                await _record_research_event(
                    conn,
                    row["id"],
                    event_type="autopilot_error",
                    status="retrying" if row["autopilot_enabled"] else "paused",
                    summary=("Autopilot planner failed; retry scheduled" if row["autopilot_enabled"] else "Autopilot paused after repeated planner failures"),
                    details={"error": error[:500], "consecutive_failures": row["autopilot_consecutive_failures"]},
                )
            return
        await conn.execute(
            """
            UPDATE research_episodes
            SET lease_owner=NULL, lease_expires_at=NULL, autopilot_error=NULL,
                autopilot_consecutive_failures=0,
                autopilot_enabled=CASE
                    WHEN status IN ('awaiting_planner','awaiting_observation') THEN autopilot_enabled
                    ELSE false
                END,
                updated_at=NOW()
            WHERE id=$1 AND lease_owner=$2
            """,
            uuid.UUID(episode_id), owner,
        )




def _research_autopilot_expected_control_race(exc: Exception) -> bool:
    """Operator pause/cancel racing a model call is control flow, not a planner failure."""
    if not isinstance(exc, HTTPException) or int(exc.status_code or 0) != 409:
        return False
    detail = str(exc.detail or "")
    return detail in {
        "Research autopilot was paused before dispatch",
        "Research episode is terminal or cancelled",
    }


RESEARCH_EPISODE_ABANDON_TTL_HOURS = int(os.getenv("RESEARCH_EPISODE_ABANDON_TTL_HOURS", "6") or 6)


async def _reap_abandoned_research_episodes(conn) -> int:
    """Expire episodes stranded in a waiting state with no activity for the abandon TTL — chiefly
    agent-mode (session-driven) episodes whose driving coding-agent session never returned. The
    autopilot runner only advances `autopilot_enabled` episodes, so these never get touched and
    accumulate indefinitely (16 observed, oldest a week old). Conservative TTL (default 6h) so a
    legitimately-slow session is safe. Also GCs old terminal keyless `agent_hunt_runs`.
    (External-audit P2 — stuck episodes / no GC.)"""
    ttl = max(1, RESEARCH_EPISODE_ABANDON_TTL_HOURS)
    # Reap ONLY genuinely-stranded work: agent-mode (autopilot_enabled=false) episodes stuck waiting
    # for a PLANNER/OPERATOR that never returned, whose campaign is not operator-paused. Deliberately
    # EXCLUDE awaiting_observation (that state is blocked on real linked scan/retest work — the
    # stale-dispatch reconciler owns it; cancelling it would orphan a live scan) and autopilot
    # episodes (the runner advances/re-leases them). No hard delete of hunt transcripts — those are
    # run records under the evidence-retention discipline, not reaper-deletable. (External-audit P1/P2.)
    reaped = await conn.fetch(
        """UPDATE research_episodes re
           SET status='cancelled', stop_reason='abandoned_reaper_timeout',
               lease_expires_at=NULL, updated_at=NOW()
           WHERE re.status IN ('awaiting_planner','awaiting_input')
             AND re.autopilot_enabled=false
             AND re.cancel_requested=false
             AND re.updated_at < NOW() - make_interval(hours => $1::int)
             AND NOT EXISTS (
                 SELECT 1 FROM campaigns c WHERE c.id=re.campaign_id AND c.status='paused')
             -- Do NOT reap an OPERATOR-PAUSED episode: autopilot pause sets autopilot_enabled=false
             -- (the same signal as agent-mode), so distinguish a pause via its event trail — skip any
             -- episode whose latest autopilot event is a pause (no later resume). (External-audit P1.)
             AND NOT EXISTS (
                 SELECT 1 FROM research_events ev
                 WHERE ev.episode_id=re.id AND ev.event_type='autopilot_paused'
                   AND ev.created_at > COALESCE(
                       (SELECT max(ev2.created_at) FROM research_events ev2
                        WHERE ev2.episode_id=re.id AND ev2.event_type='autopilot_resumed'),
                       '-infinity'::timestamptz))
           RETURNING id""",
        ttl,
    )
    return len(reaped)


async def _reconcile_stale_research_dispatches(conn) -> int:
    """Fail closed on expired dispatch windows; never replay an uncertain active action."""
    rows = await conn.fetch(
        """
        SELECT re.*, rd.id AS decision_id, rd.command_result_id AS linked_command_result_id,
               rd.policy_result, rd.action,
               recovered.id AS recovered_command_result_id,
               recovered.status AS recovered_command_status,
               recovered.dry_run AS recovered_command_dry_run,
               recovered_scan.id AS recovered_scan_id,
               recovered_scan.status AS recovered_scan_status,
               recovered_scan.job_id AS recovered_scan_job_id,
               recovered_scan.campaign_id AS recovered_scan_campaign_id,
               fv.id AS recovered_retest_id, fv.finding_id AS recovered_finding_id,
               fv.status AS recovered_retest_status
        FROM research_episodes re
        LEFT JOIN research_decisions rd ON rd.id=re.current_decision_id
        LEFT JOIN LATERAL (
            SELECT cr.id, cr.status, cr.dry_run
            FROM command_results cr
            WHERE rd.command_result_id IS NULL
              AND cr.created_by=(
                  'research_episode:' || re.id::text || ':decision:' || rd.id::text
              )
            ORDER BY cr.created_at DESC
            LIMIT 1
        ) recovered ON true
        LEFT JOIN LATERAL (
            SELECT s.id, s.status, s.job_id, s.campaign_id
            FROM scans s
            WHERE rd.command_result_id IS NULL
              AND recovered.id IS NULL
              AND s.options->>'research_dispatch_correlation'=(
                  'research_episode:' || re.id::text || ':decision:' || rd.id::text
              )
            ORDER BY s.created_at DESC
            LIMIT 1
        ) recovered_scan ON true
        LEFT JOIN LATERAL (
            SELECT verification.id, verification.finding_id, verification.status
            FROM finding_verifications verification
            WHERE rd.command_result_id IS NULL
              AND recovered.id IS NULL
              AND recovered_scan.id IS NULL
              AND verification.requested_by=(
                  'research_episode:' || re.id::text || ':decision:' || rd.id::text
              )
            ORDER BY verification.created_at DESC
            LIMIT 1
        ) fv ON true
        WHERE re.status='dispatching'
          AND re.updated_at < NOW() - INTERVAL '5 minutes'
        ORDER BY re.updated_at ASC
        FOR UPDATE OF re SKIP LOCKED
        LIMIT 10
    """
    )
    repaired = 0
    for row in rows:
        receipt_id = row["linked_command_result_id"] or row["recovered_command_result_id"]
        recovered_status = str(row["recovered_command_status"] or "")
        recovered_dry_run = bool(row["recovered_command_dry_run"])
        correlation = f"research_episode:{row['id']}:decision:{row['decision_id']}"
        if not receipt_id and row.get("recovered_scan_id"):
            action = _decode_json_value(row.get("action")) or {}
            command_name = str(action.get("command") or "asm.improve").strip()
            command = _research_command_catalog().get(command_name) or {}
            scan_status = str(row.get("recovered_scan_status") or "unknown")
            receipt_status = (
                "queued" if scan_status in {"pending", "queued"}
                else "running" if scan_status == "running"
                else scan_status
            )
            synthesized = await _record_command_result(
                conn,
                command=command_name,
                status=receipt_status,
                risk_tier=str(command.get("risk_tier") or "active"),
                campaign_id=row.get("recovered_scan_campaign_id"),
                scan_id=row["recovered_scan_id"],
                operator_message="Recovered ASM scan queued by an interrupted research dispatch",
                result_json={
                    "scan_id": str(row["recovered_scan_id"]),
                    "job_id": str(row.get("recovered_scan_job_id") or ""),
                    "status": scan_status,
                    "recovered_from_scan_correlation": True,
                },
                next_action=f"/scans/{row['recovered_scan_id']}",
                created_by=correlation,
            )
            receipt_id = synthesized["id"]
            recovered_status = str(synthesized.get("status") or "")
            recovered_dry_run = bool(synthesized.get("dry_run"))
        if not receipt_id and row["recovered_retest_id"]:
            synthesized = await _record_command_result(
                conn,
                command="finding.retest",
                status=(
                    "retest_scheduled"
                    if str(row["recovered_retest_status"] or "") in {"queued", "running"}
                    else str(row["recovered_retest_status"] or "completed")
                ),
                risk_tier="active",
                finding_ids=[str(row["recovered_finding_id"])],
                operator_message="Recovered finding retest queued by an interrupted research dispatch",
                result_json={
                    "finding_id": str(row["recovered_finding_id"]),
                    "retest_id": str(row["recovered_retest_id"]),
                    "status": str(row["recovered_retest_status"] or "unknown"),
                },
                next_action=f"/findings/{row['recovered_finding_id']}",
                created_by=correlation,
            )
            receipt_id = synthesized["id"]
            recovered_status = str(synthesized.get("status") or "")
            recovered_dry_run = bool(synthesized.get("dry_run"))
        if receipt_id:
            if not row["linked_command_result_id"]:
                policy_result = _decode_json_value(row["policy_result"]) or {}
                settled_cost = dict(policy_result.get("cost_reserved") or {})
                if recovered_dry_run or recovered_status in {
                    "blocked", "approval_required", "failed", "cancelled",
                }:
                    settled_cost["active_actions"] = 0
                    settled_cost["requests"] = 0
                    settled_cost["seconds"] = 0
                recovered_decision_status = (
                    "blocked"
                    if recovered_dry_run or recovered_status in {
                        "blocked", "approval_required", "failed", "cancelled",
                    }
                    else "dispatching"
                )
                used = _research_apply_cost(
                    _decode_json_value(row["budget_used"]) or {},
                    settled_cost,
                )
                next_step = int(row["step_count"] or 0) + 1
                max_steps = int((_decode_json_value(row["budget_limits"]) or {}).get("steps") or 1)
                await conn.execute(
                    """
                    UPDATE research_decisions
                    SET command_result_id=$2, status=$4,
                        policy_result=$3::jsonb, updated_at=NOW()
                    WHERE id=$1 AND command_result_id IS NULL
                    """,
                    row["decision_id"],
                    _optional_uuid(receipt_id),
                    json.dumps({
                        **policy_result,
                        "recovered_dispatch": True,
                        "cost_settled": settled_cost,
                    }),
                    recovered_decision_status,
                )
                await conn.execute(
                    """
                    UPDATE research_episodes
                    SET status='awaiting_observation', step_count=$2,
                        budget_used=$3::jsonb,
                        stop_reason=CASE WHEN $2 >= $4 THEN 'max_steps_reached_without_conclusion' ELSE stop_reason END,
                        lease_owner=NULL, lease_expires_at=NULL,
                        autopilot_error='recovered_expired_dispatch_with_receipt',
                        version=version+1, updated_at=NOW()
                    WHERE id=$1
                    """,
                    row["id"], next_step, json.dumps(used), max_steps,
                )
            else:
                await conn.execute(
                    """
                    UPDATE research_episodes
                    SET status='awaiting_observation', lease_owner=NULL, lease_expires_at=NULL,
                        autopilot_error='recovered_expired_dispatch_with_receipt', updated_at=NOW()
                    WHERE id=$1
                    """,
                    row["id"],
                )
            summary = "Recovered expired dispatch from its durable command receipt"
            status = "awaiting_observation"
        else:
            await conn.execute(
                """
                UPDATE research_episodes
                SET status='blocked', autopilot_enabled=false, lease_owner=NULL,
                    lease_expires_at=NULL, stop_reason='dispatch_outcome_unknown',
                    autopilot_error='dispatch_outcome_unknown_no_replay', updated_at=NOW()
                WHERE id=$1
                """,
                row["id"],
            )
            await conn.execute(
                """
                UPDATE research_decisions
                SET status='blocked', validation_errors=(validation_errors || '["dispatch_outcome_unknown"]'::jsonb),
                    updated_at=NOW()
                WHERE id=$1 AND status='dispatching'
                """,
                row["decision_id"],
            )
            summary = "Blocked expired dispatch with no durable receipt; action was not replayed"
            status = "blocked"
        await _record_research_event(
            conn,
            row["id"],
            event_type="dispatch_reconciled",
            status=status,
            summary=summary,
            decision_id=row["decision_id"],
            command_result_id=receipt_id,
        )
        repaired += 1
    return repaired


def _research_queued_job_ids(redis_client, queue_name: str) -> set[str]:
    queued: set[str] = set()
    for raw in queue_payloads(redis_client, queue_name):
        try:
            payload = json.loads(raw)
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
        if isinstance(payload, dict) and payload.get("job_id"):
            queued.add(str(payload["job_id"]))
    return queued


RESEARCH_PROCESSING_LEASE_MAX_AGE_SECONDS = 120


def _redis_hash_text(payload: Any) -> dict[str, str]:
    if not isinstance(payload, dict):
        return {}
    result: dict[str, str] = {}
    for raw_key, raw_value in payload.items():
        key = raw_key.decode("utf-8", "replace") if isinstance(raw_key, bytes) else str(raw_key)
        value = raw_value.decode("utf-8", "replace") if isinstance(raw_value, bytes) else str(raw_value)
        result[key] = value
    return result


def _research_fresh_processing_lease(
    metadata: Any,
    *,
    now: datetime | None = None,
    max_age_seconds: int = RESEARCH_PROCESSING_LEASE_MAX_AGE_SECONDS,
) -> bool:
    """Accept only a worker-authored, recent pop/heartbeat marker.

    The API's ordinary ``status=queued`` cache hash is not queue durability: it
    survives a Stream lease, worker crashes, and queue clearing. Workers stamp
    ``processing_lease_at`` immediately after leasing; running jobs also maintain
    ``heartbeat``. Either timestamp is useful only while fresh.
    """
    values = _redis_hash_text(metadata)
    raw_timestamp = values.get("processing_lease_at") or values.get("heartbeat")
    if not raw_timestamp:
        return False
    try:
        parsed = datetime.fromisoformat(raw_timestamp.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return False
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    current = now or datetime.now(timezone.utc)
    age_seconds = (current - parsed.astimezone(timezone.utc)).total_seconds()
    return -5 <= age_seconds <= max(1, int(max_age_seconds))


def _research_queue_presence(
    redis_client,
    *,
    queue_ids: set[str],
    job_id: str,
    metadata_key: str,
    now: datetime | None = None,
) -> bool | None:
    """Return True for durable/fresh work, False for proven orphan, None if unknown."""
    if not job_id:
        return False
    if job_id in queue_ids:
        return True
    try:
        metadata = redis_client.hgetall(metadata_key)
    except Exception:
        # A partial Redis read cannot prove absence; retry on the next sweep.
        return None
    return _research_fresh_processing_lease(metadata, now=now)


async def _reconcile_unconfirmed_queue_handoffs(conn) -> int:
    """Fail stale two-phase handoffs that died before queue confirmation."""
    rows = await conn.fetch(
        """
        SELECT id, campaign_id
        FROM scans
        WHERE status='pending'
          AND options->>'queue_handoff_confirmed'='false'
          AND created_at < NOW() - INTERVAL '5 minutes'
        ORDER BY created_at ASC
        FOR UPDATE SKIP LOCKED
        LIMIT 25
        """
    )
    repaired = 0
    for row in rows:
        changed = await conn.fetchval(
            """
            UPDATE scans
            SET status='failed', progress=100, current_phase='queue_failed',
                error_message='Queue handoff confirmation remained absent after the recovery deadline; active work was not started.',
                completed_at=NOW()
            WHERE id=$1 AND status='pending'
              AND options->>'queue_handoff_confirmed'='false'
            RETURNING id
            """,
            row["id"],
        )
        if not changed:
            continue
        campaign_id = row.get("campaign_id")
        if campaign_id:
            await conn.execute(
                """
                UPDATE scan_campaigns campaign
                SET status='failed', completed_at=COALESCE(completed_at, NOW()), updated_at=NOW()
                WHERE campaign.id=$1 AND campaign.status='active'
                  AND EXISTS (
                      SELECT 1 FROM scans owner
                      WHERE owner.id=$2 AND owner.campaign_id=campaign.id
                        AND owner.status='failed'
                  )
                  AND NOT EXISTS (
                      SELECT 1 FROM scans other
                      WHERE other.campaign_id=campaign.id AND other.id<>$2
                  )
                """,
                campaign_id,
                row["id"],
            )
        repaired += 1
    return repaired


async def _reconcile_research_orphaned_queue_work(conn) -> int:
    """Fail closed work committed to Postgres but lost before its Redis enqueue."""
    try:
        redis_client = get_redis()
        redis_client.ping()
        scan_queue_ids = _research_queued_job_ids(redis_client, QUEUE_NAME)
        retest_queue_ids = _research_queued_job_ids(redis_client, RETEST_QUEUE_NAME)
    except Exception:
        # Queue visibility is required to prove a job is orphaned.
        return 0

    scan_rows = await conn.fetch(
        """
        SELECT re.id AS episode_id, s.id, s.job_id
        FROM research_episodes re
        JOIN research_decisions rd ON rd.episode_id=re.id
        JOIN command_results cr ON cr.id=rd.command_result_id
        JOIN scans s ON s.id=cr.scan_id
        WHERE re.status='awaiting_observation' AND re.cancel_requested=false
          AND s.status IN ('pending','queued')
          AND s.created_at < NOW() - INTERVAL '5 minutes'
        FOR UPDATE OF s SKIP LOCKED
        LIMIT 25
        """
    )
    retest_rows = await conn.fetch(
        """
        SELECT re.id AS episode_id, fv.id, fv.job_id, fv.finding_id
        FROM research_episodes re
        JOIN research_decisions rd ON rd.episode_id=re.id
        JOIN command_results cr ON cr.id=rd.command_result_id
        JOIN finding_verifications fv ON fv.id::text=cr.result_json->>'retest_id'
        WHERE re.status='awaiting_observation' AND re.cancel_requested=false
          AND fv.status='queued'
          AND fv.created_at < NOW() - INTERVAL '5 minutes'
        FOR UPDATE OF fv SKIP LOCKED
        LIMIT 25
        """
    )
    repaired = 0
    for row in scan_rows:
        job_id = str(row["job_id"] or "")
        presence = _research_queue_presence(
            redis_client,
            queue_ids=scan_queue_ids,
            job_id=job_id,
            metadata_key=f"job:{job_id}",
        )
        if presence is not False:
            continue
        changed = await conn.fetchval(
            """
            UPDATE scans
            SET status='failed', progress=100, current_phase='terminated', completed_at=NOW(),
                error_message='Research dispatch queue handoff was not durable; job was never enqueued.'
            WHERE id=$1 AND status IN ('pending','queued')
            RETURNING id
            """,
            row["id"],
        )
        if changed:
            await _record_research_event(
                conn,
                row["episode_id"],
                event_type="orphaned_queue_work_failed",
                status="failed",
                summary="Marked a scan failed because its durable queue handoff was missing",
                details={"kind": "scan", "scan_id": str(row["id"]), "job_id": job_id},
            )
            repaired += 1
    for row in retest_rows:
        job_id = str(row["job_id"] or "")
        presence = _research_queue_presence(
            redis_client,
            queue_ids=retest_queue_ids,
            job_id=job_id,
            metadata_key=f"retest_job:{job_id}",
        )
        if presence is not False:
            continue
        changed = await conn.fetchval(
            """
            UPDATE finding_verifications
            SET status='failed', result_status='error', verdict='error',
                verdict_reason='Research dispatch queue handoff was not durable; job was never enqueued.',
                error_message='Research dispatch queue handoff missing', completed_at=NOW(), updated_at=NOW()
            WHERE id=$1 AND status='queued'
            RETURNING id
            """,
            row["id"],
        )
        if changed:
            await conn.execute(
                """
                UPDATE findings f
                SET last_verification_status='error', last_verification_verdict='error',
                    last_verified_at=NOW(), updated_at=NOW()
                WHERE f.id=$1
                  AND NOT EXISTS (
                      SELECT 1 FROM finding_verifications active
                      WHERE active.finding_id=f.id AND active.status IN ('queued','running')
                  )
                  AND (
                      SELECT latest.id FROM finding_verifications latest
                      WHERE latest.finding_id=f.id ORDER BY latest.created_at DESC LIMIT 1
                  )=$2
                """,
                row["finding_id"], row["id"],
            )
            await _record_research_event(
                conn,
                row["episode_id"],
                event_type="orphaned_queue_work_failed",
                status="failed",
                summary="Marked a finding retest failed because its durable queue handoff was missing",
                details={"kind": "finding_retest", "retest_id": str(row["id"]), "job_id": job_id},
            )
            repaired += 1
    return repaired


async def research_autopilot_runner(pool) -> None:
    """Durably advance opted-in episodes independent of any browser session.

    A Postgres lease makes the controller safe across API replicas. Episodes with a linked active
    scan or finding retest are left alone until that work settles, then receive exactly one fresh
    result-bearing observation before planning.
    """
    owner = f"api-autopilot:{os.getpid()}:{uuid.uuid4()}"
    last_queue_reconcile_monotonic = 0.0
    last_campaign_reconcile_monotonic = 0.0
    last_episode_reap_monotonic = 0.0
    while True:
        episode_id: str | None = None
        try:
            now_monotonic = time.monotonic()
            if now_monotonic - last_campaign_reconcile_monotonic >= 30.0:
                await _continue_autonomous_research_campaigns()
                last_campaign_reconcile_monotonic = now_monotonic
            async with pool.acquire() as conn:
                async with conn.transaction():
                    await _reconcile_stale_research_dispatches(conn)
                    now_monotonic = time.monotonic()
                    if now_monotonic - last_queue_reconcile_monotonic >= 30.0:
                        await _reconcile_unconfirmed_queue_handoffs(conn)
                        await _reconcile_research_orphaned_queue_work(conn)
                        last_queue_reconcile_monotonic = now_monotonic
                    if now_monotonic - last_episode_reap_monotonic >= 300.0:
                        await _reap_abandoned_research_episodes(conn)
                        last_episode_reap_monotonic = now_monotonic
                row = await conn.fetchrow(
                    """
                    WITH candidate AS (
                        SELECT re.id
                        FROM research_episodes re
                        WHERE re.autopilot_enabled=true
                          AND re.status IN ('awaiting_planner','awaiting_observation')
                          AND re.cancel_requested=false
                          AND (re.lease_expires_at IS NULL OR re.lease_expires_at < NOW())
                          AND NOT EXISTS (
                              SELECT 1
                              FROM research_decisions rd
                              JOIN command_results cr ON cr.id=rd.command_result_id
                              JOIN scans s ON s.id=cr.scan_id
                              WHERE rd.episode_id=re.id AND s.status IN ('pending','queued','running')
                          )
                          AND NOT EXISTS (
                              SELECT 1
                              FROM research_decisions rd
                              JOIN command_results cr ON cr.id=rd.command_result_id
                              JOIN finding_verifications fv ON fv.id::text=cr.result_json->>'retest_id'
                              WHERE rd.episode_id=re.id AND fv.status IN ('queued','running')
                          )
                        ORDER BY re.updated_at ASC
                        FOR UPDATE SKIP LOCKED
                        LIMIT 1
                    )
                    UPDATE research_episodes re
                    SET lease_owner=$1,
                        lease_expires_at=NOW()+make_interval(secs => $2),
                        updated_at=NOW()
                    FROM candidate
                    WHERE re.id=candidate.id
                    RETURNING re.*
                    """,
                    owner,
                    RESEARCH_AUTOPILOT_LEASE_SECONDS,
                )
                if row:
                    episode_id = str(row["id"])
                    should_plan = str(row["status"]) == "awaiting_planner"
                    if str(row["status"]) == "awaiting_observation":
                        async with conn.transaction():
                            locked = await conn.fetchrow(
                                "SELECT * FROM research_episodes WHERE id=$1 FOR UPDATE",
                                row["id"],
                            )
                            if (
                                not locked
                                or str(locked["status"]) != "awaiting_observation"
                                or bool(locked["cancel_requested"])
                                or str(locked["lease_owner"] or "") != owner
                            ):
                                should_plan = False
                            elif await _research_async_work(conn, row["id"], active_only=True):
                                # Work became active after the candidate query; keep waiting.
                                should_plan = False
                            else:
                                settlement = await _settle_research_awaiting_observation(conn, locked)
                                should_plan = settlement.get("next_status") == "awaiting_planner"
            if not episode_id:
                await asyncio.sleep(1.0)
                continue
            if not should_plan:
                await _release_research_autopilot_lease(pool, episode_id, owner)
                continue
            heartbeat_stop = asyncio.Event()
            heartbeat_task = asyncio.create_task(
                _research_lease_heartbeat(pool, episode_id, owner, heartbeat_stop)
            )
            try:
                if _research_episode_uses_agent_loop(row):
                    # Opt-in: drive this episode with the LLM ReAct hunt loop instead of the
                    # menu planner. The existing create-MA/menu path is untouched (this branch
                    # only fires when planner.agent_loop was set at launch).
                    result = await _run_agent_hunt_for_episode(episode_id)
                else:
                    result = await _plan_research_episode_step(
                        episode_id,
                        ResearchPlannerStepRequest(
                            execute=True,
                            # 240s (of a 300s ceiling) so a large reasoning planner finishes the first big
                            # pack with room for one retry after a transient provider connection error; the
                            # full 8000 max_tokens so a filled mass_assignment/BOLA workflow isn't truncated
                            # into a harness-repair/misinferred stop.
                            timeout_seconds=240,
                            max_tokens=8000,
                            created_by="server_autopilot",
                        ),
                    )
            except asyncio.CancelledError:
                heartbeat_stop.set()
                # Graceful shutdown cancels this task and awaits it BEFORE closing the pool (see
                # lifespan), so release the lease we hold here. Otherwise a restarted controller must
                # wait out the ~4-minute lease TTL before it can resume this episode -- the observed
                # multi-minute dead window after an API restart. Shield so the cleanup completes
                # despite the cancellation propagating.
                try:
                    await asyncio.shield(heartbeat_task)
                except Exception:
                    pass
                try:
                    await asyncio.shield(_release_research_autopilot_lease(pool, episode_id, owner))
                except Exception:
                    pass
                raise
            except Exception as exc:
                heartbeat_stop.set()
                await heartbeat_task
                if _research_autopilot_expected_control_race(exc):
                    await _release_research_autopilot_lease(pool, episode_id, owner)
                else:
                    detail = exc.detail if isinstance(exc, HTTPException) else str(exc)
                    error = json.dumps(detail, default=str) if isinstance(detail, (dict, list)) else str(detail)
                    await _release_research_autopilot_lease(pool, episode_id, owner, error=error or type(exc).__name__)
            else:
                heartbeat_stop.set()
                await heartbeat_task
                result_episode = result.get("episode") if isinstance(result, dict) else {}
                if isinstance(result, dict) and result.get("accepted") is False and not (result_episode or {}).get("terminal"):
                    errors = []
                    decisions = result.get("decisions") if isinstance(result.get("decisions"), list) else []
                    if decisions and isinstance(decisions[0], dict):
                        errors = decisions[0].get("validation_errors") or []
                    policy_steering = _research_rejection_is_policy_steering(errors)
                    async with pool.acquire() as conn:
                        episode_row = await conn.fetchrow(
                            "SELECT * FROM research_episodes WHERE id=$1 AND lease_owner=$2",
                            uuid.UUID(episode_id), owner,
                        )
                        if episode_row and str(episode_row["status"]) == "awaiting_planner":
                            await _build_research_observation(
                                conn,
                                episode_row,
                                previous_result={
                                    "planner_rejection": {
                                        "validation_errors": [str(item)[:300] for item in errors[:20]],
                                        "instruction": (
                                            "The deterministic policy excluded this exact action/hypothesis. "
                                            "Choose a different planner-visible hypothesis or semantic dimension."
                                            if policy_steering else
                                            "Choose a named proposable command or provide a valid stop/input decision."
                                        ),
                                    }
                                },
                                next_status="awaiting_planner",
                            )
                            if policy_steering:
                                await _record_research_event(
                                    conn,
                                    episode_row["id"],
                                    event_type="planner_steered",
                                    status="retrying",
                                    summary="Deterministic policy steered the planner to different work",
                                    details={"validation_errors": [str(item)[:300] for item in errors[:20]]},
                                )
                    if policy_steering:
                        await _release_research_autopilot_lease(pool, episode_id, owner)
                    else:
                        await _release_research_autopilot_lease(
                            pool,
                            episode_id,
                            owner,
                            error=f"planner_decision_rejected:{','.join(str(item) for item in errors)[:800]}",
                        )
                else:
                    await _release_research_autopilot_lease(pool, episode_id, owner)
        except asyncio.CancelledError:
            raise
        except Exception:
            if episode_id:
                try:
                    await _release_research_autopilot_lease(pool, episode_id, owner, error="autopilot_controller_error")
                except Exception:
                    pass
            await asyncio.sleep(2.0)
















def _ai_ops_execute_enabled() -> bool:
    # First-run installs should be able to launch Deep Hunt without a hidden
    # environment prerequisite. Execution is still bounded by per-operation
    # confirmations, target-scoped approval receipts, and the server-side
    # scope/budget/proof gates. Operators can set the flag to false to disable
    # every gated AI Operations execution path globally.
    return str(os.environ.get("AI_OPS_ROUTER_EXECUTE_ENABLED", "true")).strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }














async def _asm_active_scan_count(conn, target_id: str) -> int:
    return int(await conn.fetchval(
        """
        SELECT COUNT(*) FROM scans
        WHERE target_id = $1 AND status IN ('pending', 'queued', 'running')
        """,
        uuid.UUID(target_id),
    ) or 0)






async def _persist_asm_decision(
    conn,
    target_id: str | uuid.UUID,
    decision: dict[str, Any],
    *,
    source: str,
    active_scan_ids: list[str] | None = None,
) -> None:
    public = _public_asm_decision(decision) or {}
    public["source"] = source
    public["recorded_at"] = utc_now_iso()
    if active_scan_ids:
        public["active_scan_id"] = active_scan_ids[0]
        public["active_scan_ids"] = active_scan_ids
    await conn.execute(
        """
        UPDATE targets
        SET metadata_json = jsonb_set(
                COALESCE(metadata_json, '{}'::jsonb),
                '{asm_last_decision}',
                $1::jsonb,
                true
            ),
            updated_at = NOW()
        WHERE id = $2
        """,
        json.dumps(public),
        uuid.UUID(str(target_id)),
    )









































# Generic field/path signals that a READ route may return sensitive VALUES -> data-exposure leads.
# Universal nouns only (no app-specific paths); the server proof still has to observe a live
# high-precision sensitive value on a protected/denied read before anything is promoted.
# Generic path signals of a privileged/admin function -> function-level-authz (BFLA/auth_bypass) leads.




































# ============================================================
# FINDINGS
# ============================================================

















def _public_evidence_object_row(row: Any) -> dict[str, Any]:
    return hydrate_evidence_content(row_to_dict(row), results_dir=RESULTS_DIR)



# Compliance-sensitive classes whose retention floor an operator-supplied
# older_than_days may raise but never shorten. legal_hold (None above) is always
# excluded from sweeps entirely.












































async def _record_export_event(
    conn,
    *,
    export_kind: str,
    command: str,
    bundle: dict[str, Any],
    filters: Optional[dict[str, Any]] = None,
    target_id: str | uuid.UUID | None = None,
    created_by: str | None = "api",
) -> dict[str, Any] | None:
    """Best-effort durable audit row for content-free exports.

    Export events are read-side audit artifacts. They intentionally carry only
    hashes, IDs, filters, and replay/read paths; evidence bodies and transcripts
    stay out of the timeline.
    """
    try:
        evidence_reads = (bundle.get("replay_plan") or {}).get("evidence_object_reads") or []
        evidence_ids = [
            str(item.get("evidence_object_id"))
            for item in evidence_reads
            if isinstance(item, dict) and item.get("evidence_object_id")
        ]
        finding_ids = [str(item) for item in (bundle.get("finding_ids") or []) if item]
        scan_ids = [str(item) for item in (bundle.get("scan_ids") or []) if item]
        row = await conn.fetchrow(
            """
            INSERT INTO export_events (
                export_kind, command, status, risk_tier, target_id, scan_id,
                finding_id, bundle_hash, manifest_hash, object_count, filters,
                evidence_object_ids, finding_ids, scan_ids, replay_plan,
                operator_message, created_by
            ) VALUES (
                $1,$2,'completed','read_only',$3,$4,
                $5,$6,$7,$8,$9::jsonb,
                $10::jsonb,$11::jsonb,$12::jsonb,$13::jsonb,
                $14,$15
            )
            RETURNING *
            """,
            export_kind,
            command,
            _optional_uuid(target_id),
            _optional_uuid(scan_ids[0]) if scan_ids else None,
            _optional_uuid(finding_ids[0]) if finding_ids else None,
            bundle.get("bundle_hash") or bundle.get("export_hash"),
            bundle.get("manifest_hash"),
            int(bundle.get("object_count") or 0),
            json.dumps(filters or bundle.get("filters") or {}),
            json.dumps(evidence_ids),
            json.dumps(finding_ids),
            json.dumps(scan_ids),
            json.dumps(redact_sensitive(bundle.get("replay_plan") or {}, redact_strings=True, scrub_text=True)),
            f"Recorded content-free {export_kind} export",
            created_by,
        )
        return _public_export_event_row(row)
    except Exception:
        return None










































































# ============================================================
# DISCOVERY (Subdomain Enumeration)
# ============================================================







# ============================================================
# WORKER MANAGEMENT
# ============================================================

# Fleet container ceiling the /workers scaler allows. The default mirrors
# scanner.sh startup sizing: reserve RAM for Docker/the OS and the supporting
# PostgreSQL, Redis, API, and UI containers, then budget ~1GB for each worker.
# An explicit SHAKERSCAN_MAX_WORKERS always overrides. Hard sanity bound: 200.
def _compute_max_allowed_workers() -> int:
    env_override = os.environ.get("SHAKERSCAN_MAX_WORKERS")
    if env_override:
        try:
            return max(1, min(200, int(env_override)))
        except (TypeError, ValueError):
            pass
    try:
        status, info = docker_socket_request("GET", "/info")
        mem_gb = (info.get("MemTotal") or 0) / 1024 ** 3 if (status == 200 and isinstance(info, dict)) else 0
    except Exception:
        mem_gb = 0
    try:
        per_worker_gb = float(os.environ.get("SHAKERSCAN_PER_WORKER_MEM_GB") or 1)
    except (TypeError, ValueError):
        per_worker_gb = 1
    try:
        platform_reserve_gb = float(os.environ.get("SHAKERSCAN_PLATFORM_MEMORY_RESERVE_GB") or 7)
    except (TypeError, ValueError):
        platform_reserve_gb = 7
    if mem_gb <= 0 or per_worker_gb <= 0:
        return 5
    if mem_gb < 8:
        return max(1, min(4, int(mem_gb) - 3))
    if mem_gb < 16:
        return 5
    return max(5, min(200, int((mem_gb - max(0, platform_reserve_gb)) / per_worker_gb)))

# Hard per-worker memory cap applied to scaler-created worker containers. Without
# it, a runaway/large scan can exhaust the whole Docker VM and OOM-thrash every
# container; with it, a single worker is OOM-killed in isolation and its job is
# requeued by the stale-scan checker. 0 disables the cap. (compose `deploy.resources`
# is ignored outside Swarm, so we set HostConfig.Memory explicitly here.)
try:
    WORKER_MEM_LIMIT_BYTES = int(float(os.environ.get("SHAKERSCAN_WORKER_MEM_LIMIT_GB") or 4) * (1024 ** 3))
except (TypeError, ValueError):
    WORKER_MEM_LIMIT_BYTES = 4 * (1024 ** 3)


def _worker_hostconfig(network: str, binds: list) -> dict:
    """HostConfig for a scaler-created worker, incl. the hard memory cap."""
    hc = {
        "NetworkMode": network,
        "RestartPolicy": {"Name": "unless-stopped"},
        "Binds": binds,
    }
    if WORKER_MEM_LIMIT_BYTES > 0:
        hc["Memory"] = WORKER_MEM_LIMIT_BYTES
        # MemorySwap == Memory disables swap for the container (no swap thrash);
        # the worker is OOM-killed cleanly at the limit instead.
        hc["MemorySwap"] = WORKER_MEM_LIMIT_BYTES
    return hc


def _compute_max_active_scans(max_allowed: int | None = None) -> int:
    """Max concurrent ACTIVE scans across the fleet (workers enforce it via a Redis
    semaphore). Memory safety primarily comes from the RAM-derived fleet cap
    (_compute_max_allowed_workers, ~1GB/worker after the platform reserve) plus
    the per-worker hard memory cap (each worker is OOM-isolated and its job
    requeued). With no explicit
    override this defaults to the full RAM-derived fleet capacity so a busy fleet —
    and single large Full Coverage parents — can actually use every worker instead
    of leaving most idle behind a flat cap. Set SHAKERSCAN_MAX_ACTIVE_SCANS to pin
    a lower burst ceiling; it is always clamped to the RAM-derived fleet cap."""
    if max_allowed is None:
        max_allowed = _compute_max_allowed_workers()
    env_override = os.environ.get("SHAKERSCAN_MAX_ACTIVE_SCANS")
    if env_override:
        try:
            n = max(1, int(env_override))
        except (TypeError, ValueError):
            n = max_allowed
    else:
        n = max_allowed
    return max(1, min(n, max_allowed))


def _publish_max_active_scans(max_allowed: int | None = None) -> int:
    """Compute + publish the active-scan concurrency cap to Redis for workers."""
    n = _compute_max_active_scans(max_allowed)
    try:
        get_redis().set("shakerscan:max_active_scans", n, ex=120)
    except Exception:
        pass
    return n


class WorkerScaleRequest(BaseModel):
    # Hard ceiling here is just a sanity bound; the effective cap is
    # _compute_max_allowed_workers() (RAM-derived, or SHAKERSCAN_MAX_WORKERS),
    # enforced in scale_workers.
    count: int = Field(..., ge=1, le=200, description="Number of worker containers")


def docker_socket_request(method: str, path: str, body: dict = None) -> tuple[int, dict | list]:
    """Send HTTP request to Docker socket API.

    Args:
        method: HTTP method (GET, POST, DELETE)
        path: API path (e.g., /containers/json)
        body: Optional JSON body for POST requests

    Returns:
        Tuple of (status_code, response_data)
    """
    import socket as sock_module
    import json as json_module

    docker_socket = "/var/run/docker.sock"
    s = sock_module.socket(sock_module.AF_UNIX, sock_module.SOCK_STREAM)
    s.settimeout(30)
    s.connect(docker_socket)

    if body:
        body_str = json_module.dumps(body)
        request = (
            f"{method} {path} HTTP/1.1\r\n"
            f"Host: localhost\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body_str)}\r\n"
            f"Connection: close\r\n"
            f"\r\n{body_str}"
        )
    else:
        request = f"{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"

    s.sendall(request.encode())

    # Read response
    response = b""
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        response += chunk
    s.close()

    # Parse HTTP response (bytes-safe for chunked payloads).
    status_code = 0
    response_body = {}

    header_bytes, sep, body_bytes = response.partition(b"\r\n\r\n")
    header_text = header_bytes.decode("iso-8859-1", errors="ignore")

    if header_text:
        status_line = header_text.split("\r\n", 1)[0]
        parts = status_line.split(" ")
        if len(parts) >= 2 and parts[1].isdigit():
            status_code = int(parts[1])

    if sep:
        header_lines = header_text.lower().split("\r\n")
        is_chunked = any(
            line.startswith("transfer-encoding:") and "chunked" in line
            for line in header_lines
        )

        if is_chunked:
            # Parse chunked encoding from raw bytes:
            # size\r\ndata\r\nsize\r\ndata\r\n...0\r\n\r\n
            assembled = bytearray()
            remaining = body_bytes
            while remaining:
                line_end = remaining.find(b"\r\n")
                if line_end == -1:
                    break
                size_line = remaining[:line_end].decode("ascii", errors="ignore")
                remaining = remaining[line_end + 2:]
                size_str = size_line.split(";", 1)[0].strip()
                if not size_str:
                    break
                try:
                    chunk_size = int(size_str, 16)
                except ValueError:
                    break
                if chunk_size == 0:
                    break
                if len(remaining) < chunk_size:
                    break
                assembled.extend(remaining[:chunk_size])
                remaining = remaining[chunk_size:]
                if remaining.startswith(b"\r\n"):
                    remaining = remaining[2:]
            body_bytes = bytes(assembled)

        if body_bytes.strip():
            try:
                response_body = json_module.loads(body_bytes.decode("utf-8", errors="ignore"))
            except json_module.JSONDecodeError:
                response_body = {}

    return status_code, response_body




def _is_scan_worker_container_name(name: str) -> bool:
    normalized = str(name or "").lstrip("/").lower()
    return "shakerscan" in normalized and "worker" in normalized and "gungnir" not in normalized


def _local_compose_project_best_effort() -> str | None:
    """Resolve the Compose project that owns this API container.

    A host may run a standalone ShakerScan stack and one or more Fleet node
    stacks at the same time. Container-name matching alone crosses that trust
    boundary and makes standalone worker freshness/scale operations include
    Fleet workers. Prefer an explicit project when one is passed through, then
    inspect this API container's immutable Compose label through the mounted
    Docker socket.
    """
    configured = str(
        os.environ.get("COMPOSE_PROJECT_NAME")
        or os.environ.get("SHAKERSCAN_COMPOSE_PROJECT")
        or ""
    ).strip()
    if configured:
        return configured
    hostname = str(os.environ.get("HOSTNAME") or "").strip()
    if not hostname:
        return None
    try:
        status_code, container = docker_socket_request("GET", f"/containers/{hostname}/json")
        if status_code != 200 or not isinstance(container, dict):
            return None
        labels = ((container.get("Config") or {}).get("Labels") or {})
        project = str(labels.get("com.docker.compose.project") or "").strip()
        return project or None
    except Exception:
        return None


def _is_local_scan_worker_container(container: dict, *, compose_project: str | None) -> bool:
    if not compose_project:
        # Unknown project authority must not cross the standalone/Fleet trust
        # boundary. Callers treat this as unavailable inventory.
        return False
    labels = container.get("Labels", {}) or {}
    return (
        labels.get("com.docker.compose.project") == compose_project
        and labels.get("com.docker.compose.service") == "worker"
    )






def _stale_scan_worker_count_best_effort() -> int:
    """Count running workers CONFIRMED to be on a stale build (0 when unknown).

    Cross-references the same per-worker build registry /workers uses. Returns 0
    whenever build identity is unavailable, so it can only ever subtract a worker
    we are certain is stale.
    """
    try:
        filters = urllib.parse.quote('{"name":["worker"]}')
        status_code, containers = docker_socket_request(
            "GET",
            f"/containers/json?all=true&filters={filters}",
        )
        if status_code != 200 or not isinstance(containers, list):
            return 0
        compose_project = _local_compose_project_best_effort()
        running = [
            c for c in containers
            if _is_local_scan_worker_container(c, compose_project=compose_project)
            and c.get("State") == "running"
        ]
        if not running:
            return 0
        worker_build_redis = None
        try:
            worker_build_redis = get_redis()
            worker_build_raw = worker_build_redis.hgetall("shakerscan:worker_build") or {}
        except Exception:
            worker_build_raw = {}
        if not worker_build_raw:
            return 0
        worker_build: dict = {}
        for host, raw in worker_build_raw.items():
            host_s = (host.decode() if isinstance(host, bytes) else str(host)).lower()
            raw_s = raw.decode() if isinstance(raw, bytes) else raw
            try:
                worker_build[host_s] = json.loads(raw_s)
            except Exception:
                continue
        expected_fp = expected_build_fingerprint()
        expected_version = current_scanner_version()
        stale = 0
        for c in running:
            cid = (c.get("Id", "") or "").lower()
            info = next((v for h, v in worker_build.items() if h and cid.startswith(h)), None)
            if info is not None and worker_build_current(
                reported_fingerprint=info.get("build_fingerprint"),
                reported_version=info.get("scanner_version"),
                expected_fingerprint=expected_fp,
                expected_version=expected_version,
            ) is False:
                stale += 1
        return stale
    except Exception:
        return 0


def _current_scan_worker_count_best_effort() -> int | None:
    """Running worker count EXCLUDING workers confirmed to run stale code.

    Auto-sharding sizes fan-out from fleet capacity; counting workers left behind
    on an old build (unmanaged scale-out after a rebuild) inflates shard count and
    spawns shards running stale code — the "skew masquerades as coverage" failure
    (docs proposed-next-steps §3: stale workers must not silently contribute to
    capacity math). Delegates to the all-running count, then subtracts only
    workers we are CERTAIN are stale, so a uniform/fresh fleet is never penalized.
    """
    base = _running_scan_worker_count_best_effort()
    if not base:  # None or 0
        return base
    return max(0, base - _stale_scan_worker_count_best_effort())




def compute_fleet_summary(worker_list: list[dict]) -> dict[str, Any]:
    """Pure fleet-truth summary over a /workers ``worker_list``.

    The single source of truth for "is the fleet safe to trust" shared by the
    /workers response, ``scanner.sh status``, and the benchmark fleet gate
    (docs proposed-next-steps §3). ``current`` = running this build, ``stale`` =
    running old code (unmanaged scale-out left behind by a rebuild), ``pending`` =
    started but not yet registered a fingerprint. ``fleet_uniform`` is True only
    when every running worker is confirmed on the expected build, so a mixed
    fleet can never silently produce benchmark numbers.
    """
    running_workers = [w for w in worker_list if w.get("status") == "running"]
    running = len(running_workers)
    current_count = sum(1 for w in running_workers if w.get("build_current") is True)
    stale_count = sum(1 for w in running_workers if w.get("build_current") is False)
    pending_count = sum(1 for w in running_workers if w.get("build_current") is None)
    stale_workers = [w.get("name") for w in worker_list if w.get("build_current") is False]
    distinct_fingerprints = sorted({
        w.get("build_fingerprint") for w in running_workers if w.get("build_fingerprint")
    })
    return {
        "count": running,
        "current_count": current_count,
        "stale_count": stale_count,
        "pending_count": pending_count,
        "fleet_uniform": running > 0 and stale_count == 0 and pending_count == 0,
        "distinct_fingerprints": distinct_fingerprints,
        "stale_workers": stale_workers,
    }


def compute_execution_capacity(
    local_summary: Mapping[str, Any],
    fleet_nodes: list[Mapping[str, Any]],
    *,
    remote_inventory_available: bool = True,
) -> dict[str, Any]:
    """Combine control-plane-local and schedulable remote worker capacity.

    ``count`` remains the local Docker worker count for backwards-compatible
    local scaling. This companion summary makes the actual execution pool
    explicit without pretending that a stale, draining, or unexplained-drift
    remote node is available to accept a scan. An explicitly reported local
    source build remains schedulable for development while retaining image-drift
    telemetry so benchmark and production operators can see it.
    """
    active_nodes = [node for node in fleet_nodes if node.get("status") != "disabled"]
    available_nodes = [
        node for node in active_nodes
        if _fleet_node_is_schedulable(node)
        and int(node.get("active_worker_count") or 0) > 0
    ]
    local_running = max(0, int(local_summary.get("count") or 0))
    local_available = max(0, int(local_summary.get("current_count") or 0))
    remote_running = sum(max(0, int(node.get("active_worker_count") or 0)) for node in active_nodes)
    remote_available = sum(
        max(0, int(node.get("active_worker_count") or 0)) for node in available_nodes
    )
    return {
        "local_running": local_running,
        "local_available": local_available,
        "remote_running": remote_running,
        "remote_available": remote_available,
        "total_running": local_running + remote_running,
        "total_available": local_available + remote_available,
        "remote_nodes": len(active_nodes),
        "remote_nodes_available": len(available_nodes),
        "remote_inventory_available": remote_inventory_available,
    }


def fleet_feature_state() -> dict[str, Any]:
    """Return the host-aware UI contract for the optional fleet feature.

    The API runs inside a Linux container even on Docker Desktop, so the host
    platform must be recorded by ``scanner.sh``. Unknown remains eligible for
    backwards compatibility with direct Compose deployments, while an explicit
    non-Linux host fails closed for managed fleet operations.
    """
    raw_platform = os.environ.get("SHAKERSCAN_HOST_PLATFORM", "").strip().lower()
    if raw_platform in {"darwin", "mac", "macos", "osx"}:
        host_platform = "macos"
    elif raw_platform.startswith("linux"):
        host_platform = "linux"
    elif raw_platform in {"windows", "win32", "wsl"}:
        host_platform = raw_platform
    else:
        host_platform = "unknown"

    supported = host_platform in {"linux", "unknown"}
    configured = bool(
        len(os.environ.get("FLEET_OPERATOR_TOKEN", "").strip()) >= 32
        and os.environ.get("FLEET_WORKER_IMAGE_DIGEST", "").strip()
    )
    enabled = supported and configured
    if not supported:
        status = "unsupported"
        reason = "Managed multi-node fleets require a Linux host."
    elif not configured:
        status = "disabled"
        reason = "Fleet mode has not been initialized on this control plane."
    else:
        status = "enabled"
        reason = None
    return {
        "enabled": enabled,
        "configured": configured,
        "supported": supported,
        "status": status,
        "host_platform": host_platform,
        "reason": reason,
    }


async def _execution_capacity_snapshot(local_summary: Mapping[str, Any]) -> dict[str, Any]:
    stale_after = max(60, _int_env("FLEET_HEARTBEAT_TIMEOUT_SECONDS", HEARTBEAT_TIMEOUT_MINUTES * 60))
    try:
        async with db_pool.acquire() as conn:
            rows = await conn.fetch("SELECT * FROM nodes ORDER BY created_at ASC")
        nodes = [
            _public_fleet_node(row, stale_after_seconds=stale_after)
            for row in rows
        ]
        return compute_execution_capacity(local_summary, nodes)
    except Exception:
        return compute_execution_capacity(
            local_summary,
            [],
            remote_inventory_available=False,
        )


@app.get("/workers")
async def get_workers():
    """Get current worker count and status via Docker socket API."""
    import socket
    import time
    import json as json_module

    docker_socket = "/var/run/docker.sock"

    try:
        # Connect to Docker socket directly
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect(docker_socket)

        # Request container list filtered by name
        request = (
            "GET /containers/json?all=true&filters=%7B%22name%22%3A%5B%22worker%22%5D%7D HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Connection: close\r\n\r\n"
        )
        sock.sendall(request.encode())

        # Read response
        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
        sock.close()

        # Parse HTTP response
        response_str = response.decode('utf-8')
        if '\r\n\r\n' in response_str:
            headers, body = response_str.split('\r\n\r\n', 1)
            # Handle chunked transfer encoding
            if 'Transfer-Encoding: chunked' in headers:
                # Simple chunked parsing - get content after first chunk size
                lines = body.split('\r\n')
                body = '\r\n'.join(lines[1:]) if len(lines) > 1 else ''
                # Find JSON array
                if '[' in body:
                    body = body[body.find('['):]
                    if ']' in body:
                        body = body[:body.rfind(']')+1]
        else:
            body = response_str

        containers = json_module.loads(body) if body.strip().startswith('[') else []

        # Per-worker build identity: workers self-register their source fingerprint
        # in Redis (keyed by container hostname == short container id) on startup.
        # Match it here so the UI can show current/stale per worker WITHOUT shelling
        # into containers.
        expected_fp = expected_build_fingerprint()
        expected_version = current_scanner_version()
        worker_build_redis = None
        try:
            worker_build_redis = get_redis()
            worker_build_raw = worker_build_redis.hgetall("shakerscan:worker_build") or {}
        except Exception:
            worker_build_raw = {}
        worker_build: dict = {}
        for host, raw in worker_build_raw.items():
            host_s = host.decode() if isinstance(host, bytes) else str(host)
            raw_s = raw.decode() if isinstance(raw, bytes) else raw
            try:
                worker_build[host_s.lower()] = json.loads(raw_s)
            except Exception:
                continue

        def _build_for_container(container_id: str):
            cid = (container_id or "").lower()
            for host_s, info in worker_build.items():
                if host_s and cid.startswith(host_s):
                    return info
            return None

        # Filter and format workers owned by this exact Compose stack. A host can
        # simultaneously run standalone and Fleet stacks.
        compose_project = _local_compose_project_best_effort()
        worker_list = []
        running_worker_ids: list[str] = []
        for c in containers:
            names = c.get('Names', [])
            name = names[0].lstrip('/') if names else 'unknown'
            if _is_local_scan_worker_container(c, compose_project=compose_project):
                state = c.get('State', 'unknown')
                if state == "running" and c.get("Id"):
                    running_worker_ids.append(str(c["Id"]))
                wb = _build_for_container(c.get('Id', '')) or {}
                reported_fp = wb.get('build_fingerprint')
                reported_version = wb.get('scanner_version')
                # Container age — a benchmark needs to know "all workers were
                # (re)started after the last rebuild", not just that they report a
                # fingerprint (docs proposed-next-steps §3 — record container age).
                created_epoch = c.get('Created')
                age_seconds = None
                if isinstance(created_epoch, (int, float)) and created_epoch > 0:
                    age_seconds = max(0, int(time.time() - created_epoch))
                worker_list.append({
                    "name": name,
                    "status": state,
                    "health": c.get('Status', ''),
                    "build_fingerprint": reported_fp,
                    "scanner_version": reported_version,
                    "created": created_epoch,
                    "age_seconds": age_seconds,
                    # True/False when the worker reported a fingerprint; null until it
                    # has registered (e.g. just started, or not yet picked up a job).
                    "build_current": worker_build_current(
                        reported_fingerprint=reported_fp,
                        reported_version=reported_version,
                        expected_fingerprint=expected_fp,
                        expected_version=expected_version,
                    ),
                })

        # The Docker-backed operational endpoint knows which containers are actually live. Prune
        # hash fields left by crashed/removed workers so the lightweight /health summary converges
        # immediately whenever an operator or dashboard asks for authoritative fleet state.
        orphaned_hosts = _orphaned_worker_build_report_hosts(worker_build, running_worker_ids)
        if orphaned_hosts and worker_build_redis is not None:
            try:
                worker_build_redis.hdel("shakerscan:worker_build", *orphaned_hosts)
            except Exception:
                pass

        summary = compute_fleet_summary(worker_list)
        execution_capacity = await _execution_capacity_snapshot(summary)
        max_allowed_workers = _compute_max_allowed_workers()
        # Refresh the per-scan active-scan concurrency cap for workers.
        max_active_scans = _publish_max_active_scans(max_allowed=max_allowed_workers)
        # Refresh the real build label so workers stamp/report the deployed commit.
        _publish_scanner_version()

        return {
            **summary,
            "workers": worker_list,
            "max_allowed": max_allowed_workers,
            "max_active_scans": max_active_scans,
            "expected_build_fingerprint": expected_fp,
            "expected_scanner_version": expected_version,
            "execution_capacity": execution_capacity,
            "fleet": fleet_feature_state(),
        }
    except FileNotFoundError:
        return {
            "count": -1,
            "error": "Docker socket not available",
            "workers": [],
            "max_allowed": _compute_max_allowed_workers(),
            "max_active_scans": _compute_max_active_scans(),
            "execution_capacity": compute_execution_capacity(
                {"count": 0, "current_count": 0}, [], remote_inventory_available=False
            ),
            "fleet": fleet_feature_state(),
        }
    except Exception:
        logger.exception("Failed to query Docker worker fleet")
        return {
            "count": -1,
            "error": "Failed to query Docker",
            "workers": [],
            "max_allowed": _compute_max_allowed_workers(),
            "max_active_scans": _compute_max_active_scans(),
            "execution_capacity": compute_execution_capacity(
                {"count": 0, "current_count": 0}, [], remote_inventory_available=False
            ),
            "fleet": fleet_feature_state(),
        }


@app.post("/workers")
async def scale_workers(request: WorkerScaleRequest):
    """Scale the number of worker containers using Docker socket API."""
    import urllib.parse

    try:
        count = request.count
        _max_allowed = _compute_max_allowed_workers()
        if count < 1:
            raise HTTPException(400, f"Workers must be between 1 and {_max_allowed}")

        # Get current workers via socket API
        filters = urllib.parse.quote('{"name":["worker"]}')
        status_code, containers = docker_socket_request(
            "GET",
            f"/containers/json?all=true&filters={filters}"
        )

        if status_code != 200:
            raise HTTPException(500, f"Failed to query containers: status {status_code}")

        # Filter to workers owned by this exact Compose stack. Never scale a
        # co-located Fleet node from the standalone worker control.
        compose_project = _local_compose_project_best_effort()
        workers = []
        for c in containers if isinstance(containers, list) else []:
            if _is_local_scan_worker_container(c, compose_project=compose_project):
                workers.append(c)

        running = [c for c in workers if c.get('State') == 'running']
        stopped = [c for c in workers if c.get('State') != 'running']
        current_count = len(running)

        if count == current_count:
            return {
                "status": "success",
                "target_count": current_count,
                "message": f"Already at {count} worker(s)"
            }

        # An older configuration may have launched more workers than the current
        # memory-derived ceiling. Always permit a request that moves that fleet
        # downward; applying the ceiling before discovering the current count made
        # the dashboard's one-step decrease control impossible to use. The ceiling
        # still rejects every request that would grow an at/over-limit fleet.
        if count > _max_allowed and count > current_count:
            raise HTTPException(400, f"Workers must be between 1 and {_max_allowed}")

        if count > current_count:
            # Remove non-running worker containers (stopped, crash-looping, or left
            # over from a prior scale-down) instead of restarting them. Restarting a
            # stopped container brings back its OUTDATED baked image, which then
            # crashes against the bind-mounted current code (the version-skew bug).
            # We always (re)create the shortfall from the running fleet's current
            # image so the whole fleet stays on one code version.
            for container in stopped:
                cid = container.get('Id')
                if cid:
                    docker_socket_request("DELETE", f"/containers/{cid}?force=true")

            started = 0  # stale stopped containers are recreated, never restarted
            new_count = current_count

            needed = count - new_count
            if needed > 0:
                # Infer image/project/network from a RUNNING worker (freshest image),
                # never a stopped/stale one. If nothing is running we have no trusted
                # current-image reference to clone from -- cloning a stopped/stale
                # worker would reintroduce the version-skew bug -- so refuse and let
                # the compose stack (which always uses the current image) start them.
                ref_pool = running
                if not ref_pool:
                    raise HTTPException(
                        status_code=409,
                        detail=(
                            "No running worker to clone the current image from. "
                            "Start the stack first (./scanner.sh start, or "
                            "docker compose up -d --scale worker=N) so new workers "
                            "use the current code instead of a stale baked image."
                        ),
                    )
                project, network, image = get_compose_context(ref_pool)
                if project and network and image:
                    # Find the highest worker number (among the surviving running fleet)
                    existing_numbers = []
                    for w in ref_pool:
                        names = w.get('Names', [])
                        name = names[0].lstrip('/') if names else ''
                        # Extract number from name like "shakerscan-oss-worker-3"
                        if '-worker-' in name:
                            try:
                                num = int(name.split('-worker-')[-1])
                                existing_numbers.append(num)
                            except ValueError:
                                pass

                    next_num = max(existing_numbers) + 1 if existing_numbers else 1
                    created = 0

                    # Get env vars and bind mounts from an existing worker (via inspect)
                    existing_env = [f"REDIS_URL={REDIS_URL}", f"DATABASE_URL={DATABASE_URL}"]
                    existing_binds = [f"{os.environ.get('HOST_RESULTS_PATH', '/tmp/scanner-results')}:/results:rw"]

                    if ref_pool:
                        # Inspect a running worker to copy its env + bind mounts.
                        ref_worker = ref_pool[0]
                        ref_id = ref_worker.get("Id", "")
                        if ref_id:
                            inspect_status, inspect_data = docker_socket_request("GET", f"/containers/{ref_id}/json")
                            if inspect_status == 200 and isinstance(inspect_data, dict):
                                # Copy env vars from existing worker
                                config_env = inspect_data.get("Config", {}).get("Env", [])
                                if config_env:
                                    existing_env = config_env

                                # Copy bind mounts from existing worker
                                mounts = inspect_data.get("Mounts", [])
                                binds = []
                                for mount in mounts:
                                    if mount.get("Type") == "bind":
                                        src = mount.get("Source", "")
                                        dst = mount.get("Destination", "")
                                        mode = "ro" if not mount.get("RW", True) else "rw"
                                        if src and dst:
                                            binds.append(f"{src}:{dst}:{mode}")
                                if binds:
                                    existing_binds = binds

                    for i in range(needed):
                        worker_num = next_num + i
                        name = f"{project}-worker-{worker_num}"

                        labels = {
                            "com.docker.compose.project": project,
                            "com.docker.compose.service": "worker",
                            "com.docker.compose.oneoff": "False",
                            "com.docker.compose.container-number": str(worker_num)
                        }

                        create_body = {
                            "Image": image,
                            "Cmd": ["python3", "/app/worker.py"],
                            "Env": existing_env,
                            "Labels": labels,
                            "HostConfig": _worker_hostconfig(network, existing_binds),
                        }

                        create_path = f"/containers/create?name={urllib.parse.quote(name)}"
                        create_status, create_data = docker_socket_request("POST", create_path, create_body)

                        if create_status == 201:
                            container_id = create_data.get("Id")
                            # Start the new container
                            start_status, _ = docker_socket_request("POST", f"/containers/{container_id}/start")
                            if start_status in [204, 304]:
                                created += 1
                                new_count += 1

                    if created > 0:
                        # Return success only if we reached the target, otherwise partial
                        status = "success" if new_count >= count else "partial"
                        return {
                            "status": status,
                            "target_count": new_count,
                            "message": f"Scaled to {new_count} worker(s) (started {started}, created {created})"
                        }

            if new_count < count:
                return {
                    "status": "partial",
                    "target_count": new_count,
                    "message": f"Could only scale to {new_count} workers"
                }

            return {
                "status": "success",
                "target_count": new_count,
                "message": f"Scaled to {new_count} worker(s)"
            }

        else:
            # Scale down - REMOVE excess workers (not just stop them). A merely
            # stopped worker lingers and gets restarted on the next scale-up running
            # a stale baked image; removing forces a fresh create from the current
            # image next time, keeping the fleet on one code version.
            to_remove = running[count:]
            removed_count = 0
            for container in to_remove:
                container_id = container.get('Id')
                rm_status, _ = docker_socket_request("DELETE", f"/containers/{container_id}?force=true")
                if rm_status in [204, 200]:
                    removed_count += 1

            return {
                "status": "success",
                "target_count": count,
                "message": f"Scaled down to {count} worker(s) (removed {removed_count})"
            }

    except FileNotFoundError:
        raise HTTPException(
            status_code=503,
            detail="Docker socket not accessible. Use CLI: ./scanner.sh scale <N>"
        )
    except HTTPException:
        raise
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Failed to scale workers: {str(e)}")


# ============================================================
# GUNGNIR CT MONITOR
# ============================================================







# ============================================================
# INTERACTIVE SESSIONS (AI Security Testing)
# ============================================================

# Import session manager
from session_manager import InteractiveSessionManager, InteractiveSession


























# ============================================================
# QUEUE MANAGEMENT
# ============================================================





# ============================================================
# RESULTS (File-based)
# ============================================================





# ============================================================
# SCHEDULES (Recurring Scans)
# ============================================================











# ============================================================
# UTILITIES
# ============================================================









def strip_target_scheme(target: str) -> str:
    """Strip scheme from a normalized URL (used to trigger auto-detect)."""
    from urllib.parse import urlparse
    parsed = urlparse(target)
    host = parsed.hostname or ""
    if not host:
        return target
    host_display = f"[{host}]" if ":" in host and not host.startswith("[") else host
    return f"{host_display}{f':{parsed.port}' if parsed.port else ''}"




# ============================================================
# MAIN
# ============================================================

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host='0.0.0.0', port=8080)
