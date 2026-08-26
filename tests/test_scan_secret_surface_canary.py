from __future__ import annotations

import hashlib
import json

import pytest

from api.runtime.scan_credentials import resolve_scan_http_principal
from api.scan.action_plan import ScanActionPlanCompiler
from api.scan.capability_result import CapabilityResultStatus
from api.scan.finalizer import finalize_scan_report
from api.scan.placement_transport import write_private_placement_bundle
from tests.test_scan_action_compiler import SCAN_ID, _execution, _target
from tests.test_scan_job_contract import _job
from tests.test_scan_orchestrator import _plan, _result
from tests.test_scan_work_manifests import _endpoint_manifest


CANARY = "v2-secret-canary-7d39f6cf-2295-48a3-9b56-never-persist"


def _assert_absent(surfaces):
    for name, value in surfaces.items():
        encoded = (
            value if isinstance(value, str)
            else json.dumps(value, sort_keys=True, default=str)
        )
        assert CANARY not in encoded, name


def test_canary_never_crosses_public_scan_storage_or_transport_surfaces(tmp_path):
    profile_ref = {
        "profile_id": "primary-profile",
        "version": 4,
        "digest": "d" * 64,
        "lane": "primary",
        "auth_kind": "bearer_token",
    }
    action_plan = ScanActionPlanCompiler().compile(
        scan_id=SCAN_ID,
        execution_plan=_execution(active=False, exclude=("nuclei_passive",)),
        target_binding=_target(),
        credential_profile_refs=(profile_ref,),
    )
    queue_payload = _job().queue_payload(placement={"node_scope": "local"})

    stored_ciphertext = "enc:fernet:opaque:" + hashlib.sha256(
        CANARY.encode(),
    ).hexdigest()

    principal = resolve_scan_http_principal({
        "auth_header": f"Bearer {CANARY}",
        "resolved_credential_profiles": [{
            "profile_id": "primary-profile",
            "profile_version": 4,
            "auth_kind": "bearer_token",
            "principal_slot": "primary",
            "scan_lane": "primary",
        }],
    })
    simple_plan = _plan()
    action_results = {
        action.action_id: _result(
            action, status=CapabilityResultStatus.SUCCESS,
        )
        for action in simple_plan.actions
        if action.action_id != "finalize.report"
    }
    report = finalize_scan_report(
        plan=simple_plan,
        target_url="https://app.example.test",
        action_results=action_results,
        observations={action_id: () for action_id in action_results},
    )
    endpoint_manifest = _endpoint_manifest().canonical_dict()
    placement = write_private_placement_bundle(
        {
            "schema_version": "canonical-scan-placements/v1",
            "execution_plan_digest": action_plan.execution_plan_digest,
            "target_binding_digest": action_plan.target_binding_digest,
            "capabilities": {
                "auth.session.establish": principal.public_dict(),
            },
        },
        parent_directory=tmp_path,
    )
    try:
        surfaces = {
            "postgres_credential_ciphertext": stored_ciphertext,
            "postgres_scan_json": queue_payload,
            "redis_queue": queue_payload,
            "action_plan": action_plan.canonical_dict(),
            "process_environment": placement.environment(),
            "private_placement_bundle": placement.path.read_text(encoding="utf-8"),
            "receipt": {
                "principal_profile_ref": "primary-profile",
                "principal_profile_version": 4,
                "principal_binding_digest": principal.binding_digest,
                "secret_values_visible": False,
            },
            "observation_manifest": endpoint_manifest,
            "report_artifact": report,
            "worker_log_projection": repr(principal),
        }
        _assert_absent(surfaces)
    finally:
        placement.cleanup()

    assert principal.headers() == {"Authorization": f"Bearer {CANARY}"}


def test_broker_private_input_canary_is_visible_only_after_lease_bound_open():
    pytest.importorskip("cryptography")
    from api.runtime.sealed_inputs import (
        generate_sealed_input_keypair,
        open_private_input,
        seal_private_input,
    )

    authority = {
        "scan_id": SCAN_ID,
        "action_id": "inputs.auth_primary",
        "lease_id": "lease-primary",
    }
    private_key, public_key = generate_sealed_input_keypair()
    sealed = seal_private_input(
        {"auth_header": f"Bearer {CANARY}"},
        recipient_public_key=public_key,
        authority=authority,
    )

    _assert_absent({"broker_sealed_envelope": sealed})
    assert open_private_input(
        sealed,
        recipient_private_key=private_key,
        authority=authority,
    ) == {"auth_header": f"Bearer {CANARY}"}
