"""A broker lease never carries a capture request whose recorded path holds a credential.

A capture indexed before path credentials were withheld lists such a request as supported, so a
Scan's request manifest can name it. The broker materializes the private replay plan without it;
when it was the action's only request, the lease carries no plan for that action and the node
skips it. The database row, the manifest store and decryption are labelled test doubles (unit
fixtures); nothing touches a database or the network.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sys
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

import pytest

from capture.flows import CaptureFlow, empty_capture_document, har_entry
from fleet_routes import router as fleet
from runtime.models import TargetBinding
from runtime.request_collection_store import RequestCollectionSelection, request_collection_selection_digest
from scan.action_plan import ScanAction
from scan.work_manifests import build_request_manifest
from scanner_tools.device_request_formats import resolve_imported_requests

TARGET = TargetBinding(
    target_id=str(uuid.uuid4()), target_kind="web", canonical_host="app.example.test",
    allowed_origins=("https://app.example.test",), allowed_addresses=("192.0.2.10",),
    allowed_root_domains=("example.test",),
)
SECRET = "Zx9Qp2Lm7Rt4Wv8Yb3NcKd5Hj6"


def _payload():
    payload = empty_capture_document()
    payload["document"]["log"]["entries"] = [
        har_entry(CaptureFlow.model_validate({"method": "GET", "url": f"https://app.example.test{path}"}))[0]
        for path in ("/api/items", f"/s/{SECRET}/dashboard")
    ]
    return payload


def _materialize(monkeypatch, manifest_ids):
    payload = _payload()
    payload_sha256 = hashlib.sha256(json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode()).hexdigest()
    scan_id = str(uuid.uuid4())
    collection_id, binding_id, selection_id = (str(uuid.uuid4()) for _ in range(3))
    selection = RequestCollectionSelection(max_requests=10)
    origins = list(TARGET.allowed_origins)
    selection_digest = request_collection_selection_digest(
        collection_id=collection_id, payload_sha256=payload_sha256, binding_id=binding_id,
        allowed_origins=origins, selector=selection, replay_policy="safe_reads",
        environment_sha256=None,
    )
    manifest = build_request_manifest(
        scan_id=scan_id, target_binding_digest=TARGET.digest,
        source_action_ids=("inputs.collection_00",),
        requests=tuple({
            "request_ref_id": request_id, "route_id": f"{index + 1:064x}", "method": "GET",
            "auth_lane": "anonymous", "selected_shard": None, "safe_method": True,
            "body_schema_digest": None,
        } for index, request_id in enumerate(manifest_ids)),
    )
    action = ScanAction(
        action_id="inputs.collection_00", stage="resolve_inputs", ordinal=0,
        capability_name="collections.replay_safe",
        capability_args={
            "request_collection_ref": {"selection_id": selection_id, "selection_digest": selection_digest},
            "request_manifest_ref": manifest.reference().canonical_dict(),
        },
        target_binding_digest=TARGET.digest, input_binding_digest="1" * 64,
        requested_budget={"http_requests": 10, "tool_wall_seconds": 30},
        placement={"schema_version": "scan-action-placement/v1", "eligible_backends": ["broker"],
                   "requirements": {}, "adapter_name": "pinned_http_replay", "adapter_version": "1"},
        dependencies=(), required=True, supporting=False, output_schema="request-replay-observation/v1",
    )
    options = {"request_collections": [{
        "collection_id": collection_id, "binding_id": binding_id, "selection_id": selection_id,
        "selection_digest": selection_digest, "replay_policy": "safe_reads", "payload_sha256": payload_sha256,
        "target_id": TARGET.target_id, "target_kind": TARGET.target_kind, "allowed_origins": origins,
    }], "scan_policy": {}}

    class ManifestStore:
        async def load(self, _conn, **_kwargs):
            return manifest

    class Conn:
        async def fetchrow(self, _sql, *_args):
            return {
                "encrypted_payload": "enc:fernet:fixture", "payload_sha256": payload_sha256,
                "allowed_origins": origins, "environment_id": None,
                "encrypted_environment": None, "environment_sha256": None,
                "replay_policy": "safe_reads", "selector_json": selection.public_dict(),
                "selection_digest": selection_digest,
            }

    monkeypatch.setattr(fleet, "PostgresScanManifestStore", ManifestStore)
    monkeypatch.setattr(fleet, "decrypt_secret", lambda _value: json.dumps(payload))
    # Fixture: the row's JSON array column, decoded as the database driver returns it.
    monkeypatch.setattr(fleet, "_broker_json_array", lambda value, *, subject: list(value))
    return asyncio.run(fleet._broker_private_replay_plan(
        Conn(), action=action, options=options, target=TARGET, scan_id=scan_id,
    ))


def _ids():
    return [request["id"] for request in resolve_imported_requests(_payload())]


def test_a_broker_lease_leaves_out_a_withheld_capture_request(monkeypatch):
    items, withheld = _ids()
    plan = _materialize(monkeypatch, [withheld, items])
    assert [request["request_id"] for request in plan["requests"]] == [items]
    assert SECRET not in json.dumps(plan)


def test_a_broker_lease_carries_no_plan_when_every_request_is_withheld(monkeypatch):
    _items, withheld = _ids()
    assert _materialize(monkeypatch, [withheld]) is None


def test_a_broker_lease_still_refuses_an_unknown_request(monkeypatch):
    items, _withheld = _ids()
    with pytest.raises(fleet.HTTPException, match="missing child request authority"):
        _materialize(monkeypatch, [items, "f" * 24])
