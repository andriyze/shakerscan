from __future__ import annotations

import uuid

import pytest

from api.runtime.observation_manifests import ObservationManifest
from api.scan.action_plan import ScanAction
from api.scan.capability_result import (
    CapabilityReceiptReference,
    CapabilityResultError,
    CapabilityResultReason,
    CapabilityResultReference,
    CapabilityResultStatus,
    placement_from_stored_result,
)


def _action() -> ScanAction:
    return ScanAction(
        action_id="discover.web_crawl",
        stage="discover_surface",
        ordinal=0,
        capability_name="web.crawl",
        capability_args={"endpoint_manifest_ref": "manifest-1"},
        target_binding_digest="a" * 64,
        input_binding_digest="b" * 64,
        requested_budget={"http_requests": 10, "tool_wall_seconds": 5},
        placement={"backend": "any"},
        dependencies=(),
        required=True,
        supporting=False,
        output_schema="katana-lines/v1",
    )


def _manifest_ref():
    return ObservationManifest(
        manifest_id=str(uuid.UUID("00000000-0000-0000-0000-000000000301")),
        owner_id=str(uuid.UUID("00000000-0000-0000-0000-000000000302")),
        action_id="discover.web_crawl",
        capability_name="web.crawl",
        output_schema="katana-lines/v1",
        observation_count=2,
        content_sha256="c" * 64,
        size_bytes=120,
        object_key="scans/00000000-0000-0000-0000-000000000302/crawl.jsonl",
    ).reference()


def _receipt_ref():
    return CapabilityReceiptReference(
        receipt_id=str(uuid.UUID("00000000-0000-0000-0000-000000000303")),
        receipt_hash="d" * 64,
    )


def test_generic_capability_result_round_trips_and_validates_action_authority():
    action = _action()
    result = CapabilityResultReference(
        action_id=action.action_id,
        action_digest=action.action_digest,
        capability_name=action.capability_name,
        adapter_name="katana",
        adapter_version="1",
        output_schema=action.output_schema,
        status=CapabilityResultStatus.SUCCESS,
        partial=False,
        timed_out=False,
        reason_code=None,
        receipt_ref=_receipt_ref(),
        observation_manifest_ref=_manifest_ref(),
        budget_reserved={"http_requests": 10, "tool_wall_seconds": 5},
        budget_consumed={"http_requests": 2, "tool_wall_seconds": 1},
    )

    assert len(result.result_digest) == 64
    assert CapabilityResultReference.from_dict(result.canonical_dict()) == result
    assert placement_from_stored_result(
        action=action, stored=result.canonical_dict(),
    ) == result.canonical_dict()

    detached = result.canonical_dict()
    detached["action_digest"] = "e" * 64
    detached["result_digest"] = None
    detached_result = CapabilityResultReference(**{
        **detached,
        "receipt_ref": _receipt_ref(),
        "observation_manifest_ref": _manifest_ref(),
    })
    with pytest.raises(CapabilityResultError, match="detached"):
        placement_from_stored_result(action=action, stored=detached_result)


def test_result_rejects_success_without_manifest_and_budget_overspend():
    action = _action()
    common = dict(
        action_id=action.action_id,
        action_digest=action.action_digest,
        capability_name=action.capability_name,
        adapter_name="katana",
        adapter_version="1",
        output_schema=action.output_schema,
        status="success",
        partial=False,
        timed_out=False,
        reason_code=None,
        receipt_ref=_receipt_ref(),
        observation_manifest_ref=None,
        budget_reserved={"http_requests": 1},
        budget_consumed={"http_requests": 1},
    )
    with pytest.raises(CapabilityResultError, match="requires an observation manifest"):
        CapabilityResultReference(**common)

    with pytest.raises(CapabilityResultError, match="exceeds reservation"):
        CapabilityResultReference(**{
            **common,
            "status": "failed",
            "reason_code": "adapter_failed",
            "budget_consumed": {"http_requests": 2},
        })


def test_timed_out_result_is_partial_and_uses_stable_reason_vocabulary():
    action = _action()
    result = CapabilityResultReference(
        action_id=action.action_id,
        action_digest=action.action_digest,
        capability_name=action.capability_name,
        adapter_name="katana",
        adapter_version="1",
        output_schema=action.output_schema,
        status="timed_out",
        partial=True,
        timed_out=True,
        reason_code=CapabilityResultReason.TIMED_OUT,
        receipt_ref=_receipt_ref(),
        observation_manifest_ref=_manifest_ref(),
        budget_reserved={"http_requests": 10},
        budget_consumed={"http_requests": 10},
    )
    assert result.status is CapabilityResultStatus.TIMED_OUT
    assert result.reason_code is CapabilityResultReason.TIMED_OUT

    with pytest.raises(ValueError):
        CapabilityResultReference(**{
            **result.digest_material(),
            "receipt_ref": _receipt_ref(),
            "observation_manifest_ref": _manifest_ref(),
            "reason_code": "free_form_reason",
        })
