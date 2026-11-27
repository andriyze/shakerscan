from __future__ import annotations

import json

import pytest

from api.scan.parallel_inputs import (
    ParallelScanInputError,
    partition_request_manifests,
)
from api.scan.work_manifests import build_request_manifest


def _manifest(scan_id: str, selection: str, *request_ids: str):
    return build_request_manifest(
        scan_id=scan_id,
        target_binding_digest="a" * 64,
        source_action_ids=("inputs.collection_00",),
        requests=tuple({
            "request_ref_id": request_id,
            "route_id": (selection[0] * 64),
            "method": "GET" if index % 2 == 0 else "POST",
            "auth_lane": "anonymous" if index % 2 == 0 else "primary",
            "selected_shard": None,
            "safe_method": index % 2 == 0,
            "body_schema_digest": None,
        } for index, request_id in enumerate(request_ids)),
    )


def _ownership(partitions):
    return {
        str(entry["request_ref_id"]): partition.shard_index
        for partition in partitions
        for manifest in partition.manifests_by_selection.values()
        for entry in manifest.entries
    }


def test_parallel_request_partition_is_complete_unique_and_deterministic():
    parent_scan_id = "40000000-0000-4000-8000-000000000001"
    children = (
        ("40000000-0000-4000-8000-000000000011", 0),
        ("40000000-0000-4000-8000-000000000012", 1),
        ("40000000-0000-4000-8000-000000000013", 2),
    )
    manifests = {
        "b" * 64: _manifest(parent_scan_id, "b", "get-a", "post-a", "get-b"),
        "c" * 64: _manifest(parent_scan_id, "c", "get-c", "post-c"),
    }

    first = partition_request_manifests(manifests, children=children)
    second = partition_request_manifests(
        dict(reversed(tuple(manifests.items()))),
        children=tuple(reversed(children)),
    )

    assert _ownership(first) == _ownership(second)
    assert set(_ownership(first)) == {"get-a", "post-a", "get-b", "get-c", "post-c"}
    assert sum(partition.request_count for partition in first) == 5
    assert all(
        manifest.scan_id == partition.child_scan_id
        for partition in first
        for manifest in partition.manifests_by_selection.values()
    )
    serialized = json.dumps([
        manifest.canonical_dict()
        for partition in first
        for manifest in partition.manifests_by_selection.values()
    ])
    assert "private-body-canary" not in serialized
    assert "authorization-canary" not in serialized
    assert "https://" not in serialized


def test_parallel_request_partition_respects_auth_lane_eligibility():
    parent_scan_id = "40000000-0000-4000-8000-000000000001"
    partitions = partition_request_manifests(
        {"d" * 64: _manifest(parent_scan_id, "d", "get-public", "post-private")},
        children=(
            ("40000000-0000-4000-8000-000000000011", 0),
            ("40000000-0000-4000-8000-000000000012", 1),
        ),
        eligible_shards_by_lane={"primary": (1,)},
    )

    assert _ownership(partitions)["post-private"] == 1


def test_parallel_request_partition_rejects_ambiguous_cross_selection_reference():
    parent_scan_id = "40000000-0000-4000-8000-000000000001"
    with pytest.raises(ParallelScanInputError, match="ambiguous across selections"):
        partition_request_manifests(
            {
                "b" * 64: _manifest(parent_scan_id, "b", "same-request"),
                "c" * 64: _manifest(parent_scan_id, "c", "same-request"),
            },
            children=(
                ("40000000-0000-4000-8000-000000000011", 0),
                ("40000000-0000-4000-8000-000000000012", 1),
            ),
        )
