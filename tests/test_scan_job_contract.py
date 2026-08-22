from __future__ import annotations

import copy
import os
import sys

import pytest


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

from runtime.models import TargetBinding
from scan.contracts import bind_scan_scope_receipt, resolve_scan_contract
from scan.jobs import (
    CanonicalScanJob,
    CanonicalScanJobError,
    RequestCollectionJobRef,
    ScanShardAuthority,
    admitted_credential_profile_ids,
    admitted_request_collection_job_refs,
    derive_scan_shard_budget,
    scan_job_options_digest,
)
from scan.job_runtime import (
    CanonicalScanJobMaterializationError,
    materialize_canonical_scan_job,
)


def _target():
    return TargetBinding(
        target_id="target-1",
        target_kind="web",
        canonical_host="api.example.test",
        allowed_origins=("https://api.example.test",),
        allowed_addresses=("192.0.2.10",),
        allowed_root_domains=("example.test",),
        environment="test",
        scope_receipt_id="scope-1",
    )


def _job(*, active=False, confirmed=False):
    contract = bind_scan_scope_receipt(resolve_scan_contract(
        budget_profile="balanced",
        policy={
            "active_testing": active,
            "allow_state_changing_http": confirmed,
        },
        approval_receipt_id="approval-1" if confirmed else None,
    ), "scope-1")
    mode = "confirmed_active" if confirmed else "safe_reads"
    return CanonicalScanJob.create(
        job_id="job-1",
        scan_id="scan-1",
        target=_target(),
        execution_plan=contract.execution_plan,
        request_collections=(RequestCollectionJobRef(
            collection_id="collection-1",
            binding_id="binding-1",
            selection_id="selection-1",
            replay_mode=mode,
            max_requests=500,
        ),),
        credential_profile_ids=("credential-primary",),
        endpoint_manifest_id="manifest-1",
        created_at="2026-08-20T12:00:00Z",
    )


def _keys(value):
    result = set()
    if isinstance(value, dict):
        for key, item in value.items():
            result.add(key)
            result |= _keys(item)
    elif isinstance(value, list):
        for item in value:
            result |= _keys(item)
    return result


def test_canonical_scan_job_is_mode_free_and_round_trips():
    job = _job()
    payload = job.payload()
    restored = CanonicalScanJob.from_payload(payload)

    assert restored == job
    assert restored.payload_digest == job.payload_digest
    assert payload["execution_plan"]["engine"] == "scan"
    assert payload["execution_plan"]["generation"] == "v2"
    assert not _keys(payload) & {
        "scan_type", "execution_scan_type", "legacy_scan_type", "legacy_executor_alias",
        "quick", "standard", "deep", "full", "aggressive", "smart", "active",
    }


def test_canonical_scan_job_rejects_non_registry_family_authority():
    payload = _job().payload()
    payload["execution_plan"]["policy"]["exclude_families"] = ["legacy_magic"]
    with pytest.raises(CanonicalScanJobError, match="unknown family"):
        CanonicalScanJob.from_payload(payload)


def test_canonical_scan_job_queue_transport_allows_only_normalized_routing_metadata():
    job = _job()
    queued = job.queue_payload(placement={
        "node_scope": "remote",
        "region": "us-central",
        "requires": ["nuclei", "playwright"],
    })
    queued["_base_queue_name"] = "scan_jobs"

    assert CanonicalScanJob.from_queue_payload(queued) == job
    assert queued["placement"] == {
        "node_scope": "remote",
        "region": "us-central",
        "requires": ["nuclei", "playwright"],
    }
    assert job.payload_digest == CanonicalScanJob.from_queue_payload(queued).payload_digest

    changed = copy.deepcopy(queued)
    changed["placement"]["region"] = "US-CENTRAL"
    with pytest.raises(CanonicalScanJobError, match="not canonical"):
        CanonicalScanJob.from_queue_payload(changed)

    changed = copy.deepcopy(queued)
    changed["broker_secret"] = "forbidden"
    with pytest.raises(CanonicalScanJobError, match="forbidden|unknown"):
        CanonicalScanJob.from_queue_payload(changed)


def test_parallel_parent_transport_is_local_bounded_and_mode_free():
    job = _job()
    queued = job.queue_payload()
    queued.update({
        "type": "scan_plan",
        "placement": {"node_scope": "local"},
        "attempt": 1,
        "plan_version": 1,
        "parallel_worker_count": 4,
    })

    assert CanonicalScanJob.from_queue_payload(queued) == job
    assert "options" not in queued
    assert "target" in queued and isinstance(queued["target"], dict)

    remote = copy.deepcopy(queued)
    remote["placement"] = {"node_scope": "remote"}
    with pytest.raises(CanonicalScanJobError, match="must remain local"):
        CanonicalScanJob.from_queue_payload(remote)

    oversized = copy.deepcopy(queued)
    oversized["parallel_worker_count"] = 5
    with pytest.raises(CanonicalScanJobError, match="worker budget"):
        CanonicalScanJob.from_queue_payload(oversized)


def _shard_job_and_row(*, discovery=False):
    parent = _job()
    row = _persisted_row(parent)
    options = copy.deepcopy(row["options"])
    authority = ScanShardAuthority(
        parent_scan_id=parent.scan_id,
        parent_execution_plan_digest=parent.execution_plan.digest,
        options_digest=scan_job_options_digest(options),
        shard_index=-1 if discovery else 1,
        shard_count=0 if discovery else 3,
        shard_label="discovery" if discovery else "coverage[1]",
        parallel_discovery=discovery,
        sub_budget=derive_scan_shard_budget(options, parent.execution_plan.budget),
    )
    options["canonical_shard_authority"] = authority.payload()
    child = CanonicalScanJob.create(
        job_id="job-child",
        scan_id="scan-child",
        target=parent.target,
        execution_plan=parent.execution_plan,
        request_collections=parent.request_collections,
        credential_profile_ids=parent.credential_profile_ids,
        endpoint_manifest_id=parent.endpoint_manifest_id,
        shard=authority,
        created_at="2026-08-20T12:01:00Z",
    )
    row.update({
        "job_id": child.job_id,
        "options": options,
        "scan_job_payload": child.payload(),
        "scan_job_digest": child.payload_digest,
        "parent_scan_id": parent.scan_id,
        "scan_role": "parallel_discovery" if discovery else "shard",
        "shard_index": authority.shard_index,
        "shard_count": None if discovery else authority.shard_count,
    })
    queued = child.payload()
    queued.update({"type": "scan_shard", "attempt": 1, "plan_version": 1})
    return child, row, queued


def test_canonical_child_shard_round_trips_with_bounded_tamper_evident_authority():
    child, _row, queued = _shard_job_and_row()
    restored = CanonicalScanJob.from_queue_payload(queued)

    assert restored == child
    assert restored.shard.sub_budget.max_workers == 1
    assert restored.shard.sub_budget.max_http_requests <= child.execution_plan.budget.max_http_requests
    assert "options" not in queued

    changed = copy.deepcopy(queued)
    changed["shard"]["sub_budget"]["max_http_requests"] += 1
    with pytest.raises(CanonicalScanJobError, match="canonical|digest|parent Scan budget"):
        CanonicalScanJob.from_queue_payload(changed)

    changed = copy.deepcopy(queued)
    changed.pop("type")
    with pytest.raises(CanonicalScanJobError, match="scan_shard|typed queue job"):
        CanonicalScanJob.from_queue_payload(changed)


def test_canonical_parallel_discovery_has_distinct_bounded_authority():
    child, row, queued = _shard_job_and_row(discovery=True)
    materialized = materialize_canonical_scan_job(
        queued, row, resolved_addresses=("192.0.2.10",),
    )
    assert child.shard.parallel_discovery is True
    assert materialized["parallel_discovery"] is True
    assert materialized["shard_index"] == -1
    assert materialized["parent_scan_id"] == "scan-1"


def test_placed_discovery_preserves_only_policy_owned_network_tool_budget():
    contract = resolve_scan_contract(
        budget_profile="balanced",
        policy={
            "active_testing": True,
            "network_discovery": True,
            "subdomain_discovery": True,
        },
        approval_receipt_id="approval-1",
    )
    options = contract.option_metadata()
    options.update({
        "parallel_discovery": True,
        "skip_global_checks": True,
        "network_discovery": True,
        "subfinder": True,
        "custom_budget": {
            "browser_max_pages": 0,
            "phase4_max_seconds": 0,
        },
    })
    budget = derive_scan_shard_budget(options, contract.execution_plan.budget)

    assert budget.max_browser_actions == 0
    assert budget.max_tcp_ports == contract.execution_plan.budget.max_tcp_ports
    assert (
        budget.max_tool_wall_seconds
        == contract.execution_plan.budget.max_tool_wall_seconds
    )


def test_endpoint_only_shard_preserves_zero_browser_network_and_tool_authority():
    parent = _job()
    options = {
        "skip_global_checks": True,
        "custom_endpoints": ["GET /v1/items"],
        "custom_budget": {
            "request_max": 50,
            "max_urls": 20,
            "browser_max_pages": 0,
            "phase4_max_seconds": 0,
        },
    }
    budget = derive_scan_shard_budget(options, parent.execution_plan.budget)
    assert budget.max_browser_actions == 0
    assert budget.max_tcp_ports == 0
    assert budget.max_tool_wall_seconds == 0
    assert budget.max_http_requests == 50


def test_shard_materialization_rejects_durable_option_or_parent_drift():
    _child, row, queued = _shard_job_and_row()
    changed = copy.deepcopy(row)
    changed["options"]["custom_endpoints"] = ["/not-authorized"]
    with pytest.raises(CanonicalScanJobMaterializationError, match="shard options"):
        materialize_canonical_scan_job(
            queued, changed, resolved_addresses=("192.0.2.10",),
        )

    changed = copy.deepcopy(row)
    changed["parent_scan_id"] = "scan-other"
    with pytest.raises(CanonicalScanJobMaterializationError, match="parent or role"):
        materialize_canonical_scan_job(
            queued, changed, resolved_addresses=("192.0.2.10",),
        )


@pytest.mark.parametrize("legacy", ["quick", "standard", "deep", "full", "aggressive", "smart"])
def test_legacy_alias_is_translated_before_queue_boundary(legacy):
    contract = bind_scan_scope_receipt(
        resolve_scan_contract(legacy_scan_type=legacy), "scope-1",
    )
    job = CanonicalScanJob.create(
        job_id=f"job-{legacy}",
        scan_id=f"scan-{legacy}",
        target=_target(),
        execution_plan=contract.execution_plan,
        created_at="2026-08-20T12:00:00+00:00",
    )
    payload = job.payload()

    assert payload["execution_plan"]["engine"] == "scan"
    assert "scan_type" not in payload
    assert "legacy_scan_type" not in payload
    assert "scan_compatibility" not in payload


def test_tampered_execution_plan_or_digest_is_rejected():
    payload = _job().payload()
    changed = copy.deepcopy(payload)
    changed["execution_plan"]["budget"]["max_http_requests"] += 1
    with pytest.raises(CanonicalScanJobError, match="digest"):
        CanonicalScanJob.from_payload(changed)

    changed = copy.deepcopy(payload)
    changed["execution_plan_digest"] = "0" * 64
    with pytest.raises(CanonicalScanJobError, match="digest"):
        CanonicalScanJob.from_payload(changed)


def test_secret_or_legacy_execution_material_is_rejected_recursively():
    payload = _job().payload()
    for key, value in (
        ("scan_type", "smart"),
        ("authorization", "Bearer secret"),
        ("argv", ["curl", "https://example.test"]),
    ):
        changed = copy.deepcopy(payload)
        changed["target"][key] = value
        with pytest.raises(CanonicalScanJobError, match="forbidden"):
            CanonicalScanJob.from_payload(changed)


def test_collection_refs_are_opaque_bounded_and_require_authority_for_mutation():
    with pytest.raises(CanonicalScanJobError, match="active state-changing authority"):
        CanonicalScanJob.create(
            job_id="job-1",
            scan_id="scan-1",
            target=_target(),
            execution_plan=resolve_scan_contract().execution_plan,
            request_collections=(RequestCollectionJobRef(
                collection_id="collection-1",
                binding_id="binding-1",
                selection_id="selection-1",
                replay_mode="confirmed_active",
            ),),
        )

    active = _job(active=True, confirmed=True)
    assert active.payload()["request_collections"][0]["replay_mode"] == "confirmed_active"
    with pytest.raises(CanonicalScanJobError, match="between 1 and 2000"):
        RequestCollectionJobRef(
            collection_id="collection-1",
            binding_id="binding-1",
            selection_id="selection-1",
            max_requests=2_001,
        )


def test_scope_receipt_mismatch_fails_closed():
    contract = resolve_scan_contract()
    policy = contract.execution_plan.policy
    from runtime.models import ScanPolicy
    from scan.execution import ScanExecutionPlan

    mismatched = ScanExecutionPlan(
        policy=ScanPolicy(
            active_testing=policy.active_testing,
            allow_state_changing_http=policy.allow_state_changing_http,
            network_discovery=policy.network_discovery,
            subdomain_discovery=policy.subdomain_discovery,
            include_families=policy.include_families,
            exclude_families=policy.exclude_families,
            scope_receipt_id="scope-2",
            approval_receipt_id=policy.approval_receipt_id,
        ),
        budget_profile=contract.execution_plan.budget_profile,
        budget=contract.execution_plan.budget,
    )
    with pytest.raises(CanonicalScanJobError, match="scope receipts"):
        CanonicalScanJob.create(
            job_id="job-1", scan_id="scan-1", target=_target(), execution_plan=mismatched
        )


def _persisted_row(job, *, scheme_inferred=False):
    options = job.execution_plan.option_metadata()
    options.update({
        "target_scheme_inferred": scheme_inferred,
        "runtime_scope_guard": {
            **job.payload()["target"],
            "requires_runtime_destination_check": True,
            "requires_runtime_dns_check": True,
            "address_binding_source": "submission_dns_snapshot",
        },
        "request_collections": [{
            "collection_id": "collection-1",
            "binding_id": "binding-1",
            "selection_id": "selection-1",
            "replay_policy": "safe_reads",
            "selector": {"max_requests": 500},
        }],
        "credential_profile_refs": [{"profile_id": "credential-primary"}],
    })
    return {
        "target_id": job.target.target_id,
        "target_url": "https://api.example.test",
        "job_id": job.job_id,
        "options": options,
        "scan_generation": "v2",
        "policy_json": job.execution_plan.canonical_dict()["policy"],
        "budget_json": job.execution_plan.canonical_dict()["budget"],
        "scan_job_payload": job.payload(),
        "scan_job_digest": job.payload_digest,
    }


def test_admitted_inputs_reduce_to_opaque_queue_references():
    refs = admitted_request_collection_job_refs([{
        "collection_id": "collection-1",
        "binding_id": "binding-1",
        "selection_id": "selection-1",
        "replay_policy": "safe_reads",
        "selector": {"max_requests": 321},
        "payload_sha256": "secret-free-but-not-a-queue-field",
    }])
    assert refs == (RequestCollectionJobRef(
        collection_id="collection-1",
        binding_id="binding-1",
        selection_id="selection-1",
        replay_mode="safe_reads",
        max_requests=321,
    ),)
    assert admitted_credential_profile_ids([
        {"profile_id": "credential-primary", "profile_version": 7},
    ]) == ("credential-primary",)


def test_worker_materializes_only_after_persisted_authority_and_dns_match():
    job = _job()
    materialized = materialize_canonical_scan_job(
        job.payload(), _persisted_row(job), resolved_addresses=("192.0.2.10",),
    )

    assert materialized["target"] == "https://api.example.test"
    assert "options" not in job.payload()
    assert materialized["_canonical_queue_payload"] == job.payload()
    assert materialized["_canonical_scan_job_digest"] == job.payload_digest
    assert materialized["options"]["_canonical_target_binding"] == job.target.canonical_dict()


def test_worker_preserves_only_validated_queue_placement_after_materialization():
    job = _job()
    queued = job.queue_payload(placement={"node_scope": "remote", "region": "us-central"})
    queued["_base_queue_name"] = "scan_jobs"
    materialized = materialize_canonical_scan_job(
        queued, _persisted_row(job), resolved_addresses=("192.0.2.10",),
    )
    assert materialized["placement"] == {
        "node_scope": "remote", "region": "us-central",
    }
    assert materialized["_base_queue_name"] == "scan_jobs"
    assert materialized["_canonical_queue_payload"] == queued


def test_worker_reconstructs_scheme_inferred_target_without_expanding_dns():
    job = _job()
    row = _persisted_row(job, scheme_inferred=True)
    materialized = materialize_canonical_scan_job(
        job.payload(), row, resolved_addresses=("192.0.2.10",),
    )
    assert materialized["target"] == "api.example.test"

    with pytest.raises(CanonicalScanJobMaterializationError, match="DNS"):
        materialize_canonical_scan_job(
            job.payload(), row, resolved_addresses=("192.0.2.99",),
        )


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda row: row.__setitem__("scan_job_digest", "0" * 64), "digest"),
        (
            lambda row: row["options"].__setitem__("scan_execution_plan_digest", "0" * 64),
            "execution-plan digest",
        ),
        (
            lambda row: row["options"]["credential_profile_refs"][0].__setitem__(
                "profile_id", "credential-other"
            ),
            "credential profile references",
        ),
        (
            lambda row: row["options"]["runtime_scope_guard"].__setitem__(
                "canonical_host", "other.example.test"
            ),
            "target binding",
        ),
    ],
)
def test_worker_materialization_rejects_durable_state_drift(mutation, message):
    job = _job()
    row = _persisted_row(job)
    mutation(row)
    with pytest.raises(CanonicalScanJobMaterializationError, match=message):
        materialize_canonical_scan_job(
            job.payload(), row, resolved_addresses=("192.0.2.10",),
        )
