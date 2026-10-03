"""Execution-time DNS revalidation of a frozen scan-job/v2 target binding.

Live defect (engine 2.5.4): a Scan of a CloudFront-hosted name failed with "runtime DNS
resolution exceeds the frozen scan-job/v2 target binding" because every lookup returns a
different subset of the CDN's edge addresses, and materialization demanded that the worker's
answer be a subset of the admission answer. The protection is that execution never reaches a
destination the policy refuses, not that a CDN answers identically twice. These tests pin both
halves: rotating public answers (IPv4 and IPv6, including fully disjoint ones) run, pinned to the
frozen set, with the fresh answer recorded as evidence; answers rebound to loopback, a private
range under a refusing deployment, or cloud metadata still fail closed with a clear reason.
All DNS here is supplied by the test; nothing touches the network.
"""
from __future__ import annotations

import asyncio
import ipaddress
import os
import socket
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

from runtime.models import TargetBinding  # noqa: E402
from scan.contracts import bind_scan_scope_receipt, resolve_scan_contract  # noqa: E402
from scan.jobs import CanonicalScanJob  # noqa: E402
from scan.job_runtime import (  # noqa: E402
    CanonicalScanJobMaterializationError,
    materialize_canonical_scan_job,
)
from scan.runtime_dns import (  # noqa: E402
    RUNTIME_DNS_REVALIDATION_OPTION,
    record_runtime_dns_revalidation,
)

HOST = "strength.cdn-customer.example"
FROZEN_V4 = ("99.84.152.10", "99.84.152.24")
FROZEN_V6 = ("2600:9000:2000:1a00:1:2:3:4",)


@pytest.fixture
def refusing_deployment(monkeypatch):
    monkeypatch.setenv("SHAKERSCAN_PRIVATE_NETWORK_TARGETS", "refuse")


def _binding(host=HOST, addresses=FROZEN_V4 + FROZEN_V6, environment="production"):
    scheme_host = f"[{host}]" if ":" in host else host
    return TargetBinding(
        target_id="target-cdn",
        target_kind="web",
        canonical_host=host,
        allowed_origins=(f"https://{scheme_host}",),
        allowed_addresses=tuple(addresses),
        allowed_root_domains=(),
        environment=environment,
        scope_receipt_id="scope-cdn",
    )


def _job(binding, scan_id="scan-cdn"):
    contract = bind_scan_scope_receipt(resolve_scan_contract(
        budget_profile="fast", policy={"active_testing": True},
        approval_receipt_id="approval-cdn",
    ), "scope-cdn")
    return CanonicalScanJob.create(
        job_id="job-cdn",
        scan_id=scan_id,
        target=binding,
        execution_plan=contract.execution_plan,
        request_collections=(),
        credential_profile_ids=(),
        endpoint_manifest_id=None,
        created_at="2026-09-26T12:00:00Z",
    )


def _row(job):
    options = job.execution_plan.option_metadata()
    options.update({
        "runtime_scope_guard": {
            **job.payload()["target"],
            "requires_runtime_destination_check": True,
            "requires_runtime_dns_check": True,
            "address_binding_source": "submission_dns_snapshot",
        },
    })
    host = job.target.canonical_host
    return {
        "target_id": job.target.target_id,
        "target_url": f"https://[{host}]" if ":" in host else f"https://{host}",
        "job_id": job.job_id,
        "options": options,
        "scan_generation": "v2",
        "policy_json": job.execution_plan.canonical_dict()["policy"],
        "budget_json": job.execution_plan.canonical_dict()["budget"],
        "scan_job_payload": job.payload(),
        "scan_job_digest": job.payload_digest,
    }


def _materialize(observed, binding=None):
    job = _job(binding or _binding())
    return job, materialize_canonical_scan_job(
        job.payload(), _row(job), resolved_addresses=observed,
    )


@pytest.mark.parametrize("observed", [
    # A different subset of the same edge range, disjoint from the admission answer.
    ("99.84.152.51", "99.84.152.77", "99.84.152.90", "99.84.152.113"),
    # IPv6 rotation, disjoint from the frozen IPv6 edge.
    ("2600:9000:2000:3c00:5:6:7:8", "2600:9000:2000:4e00:9:a:b:c"),
    # Partial overlap plus new edges of both families.
    ("99.84.152.10", "99.84.152.200", "2600:9000:2000:9900::1"),
])
def test_a_rotating_cdn_answer_runs_pinned_to_the_frozen_binding(refusing_deployment, observed):
    job, materialized = _materialize(observed)

    options = materialized["options"]
    # The binding every connection is pinned to (scanner resolver, socket factory, proxy) is the
    # frozen, digested one -- never the fresh answer.
    assert options["_canonical_target_binding"] == job.target.canonical_dict()
    evidence = options[RUNTIME_DNS_REVALIDATION_OPTION]
    assert evidence["effective_addresses"] == list(job.target.allowed_addresses)
    assert evidence["pinning"] == "frozen_target_binding"
    assert evidence["observed_addresses"] == list(observed)
    assert evidence["observed_admitted_addresses"] == list(observed)
    assert evidence["observed_refused_addresses"] == []
    assert evidence["answer_drifted"] is True
    assert evidence["environment"] == "production"


def test_an_identical_answer_is_recorded_without_drift(refusing_deployment):
    _, materialized = _materialize(FROZEN_V4 + FROZEN_V6)
    evidence = materialized["options"][RUNTIME_DNS_REVALIDATION_OPTION]
    assert evidence["answer_drifted"] is False
    assert evidence["overlap_addresses"] == list(_binding().allowed_addresses)


@pytest.mark.parametrize(("observed", "refused"), [
    (("127.0.0.1",), "127.0.0.1"),
    (("10.0.0.5",), "10.0.0.5"),
    (("::1",), "::1"),
    (("::ffff:10.1.2.3",), "::ffff:10.1.2.3"),
    (("169.254.169.254",), "169.254.169.254"),
    (("10.0.0.5", "169.254.169.254"), "169.254.169.254"),
])
def test_a_rebinding_answer_fails_closed_under_a_refusing_deployment(
    refusing_deployment, observed, refused,
):
    with pytest.raises(CanonicalScanJobMaterializationError) as excinfo:
        _materialize(observed)
    message = str(excinfo.value)
    assert "runtime DNS" in message
    assert "rebinding" in message
    assert str(ipaddress.ip_address(refused)) in message
    assert "loopback_or_private_range" in message


def test_cloud_metadata_is_refused_even_where_private_targets_are_allowed(monkeypatch):
    monkeypatch.setenv("SHAKERSCAN_PRIVATE_NETWORK_TARGETS", "allow")
    with pytest.raises(CanonicalScanJobMaterializationError, match="169.254.169.254"):
        _materialize(("169.254.169.254",))


def test_a_mixed_answer_drops_refused_addresses_as_admission_does(refusing_deployment):
    job, materialized = _materialize(("99.84.152.140", "127.0.0.1", "169.254.169.254"))
    evidence = materialized["options"][RUNTIME_DNS_REVALIDATION_OPTION]
    assert evidence["observed_admitted_addresses"] == ["99.84.152.140"]
    assert evidence["observed_refused_addresses"] == [
        {"address": "127.0.0.1", "reason": "loopback_or_private_range"},
        {"address": "169.254.169.254", "reason": "loopback_or_private_range"},
    ]
    assert evidence["effective_addresses"] == list(job.target.allowed_addresses)


def test_an_address_literal_target_stays_exact(refusing_deployment):
    binding = _binding(host="93.184.216.34", addresses=("93.184.216.34",))
    _, materialized = _materialize(("93.184.216.34",), binding)
    assert materialized["options"][RUNTIME_DNS_REVALIDATION_OPTION]["answer_drifted"] is False
    with pytest.raises(CanonicalScanJobMaterializationError, match="address-literal"):
        _materialize(("93.184.216.35",), binding)


def test_a_frozen_address_the_deployment_now_refuses_does_not_run(monkeypatch):
    """Admitted under the permissive default, executed after the operator turned refusal on."""
    monkeypatch.setenv("SHAKERSCAN_PRIVATE_NETWORK_TARGETS", "allow")
    binding = _binding(host="intranet.corp.example", addresses=("10.0.0.7",))
    _materialize(("10.0.0.8",), binding)  # same classification as admission: admitted

    monkeypatch.setenv("SHAKERSCAN_PRIVATE_NETWORK_TARGETS", "refuse")
    with pytest.raises(CanonicalScanJobMaterializationError, match="no longer an allowed"):
        _materialize(("10.0.0.7",), binding)


def test_the_lab_environment_admits_what_its_admission_admitted(refusing_deployment):
    binding = _binding(host="app.lab.example", addresses=("127.0.0.1",), environment="lab")
    _, materialized = _materialize(("127.0.0.2",), binding)
    assert materialized["options"][RUNTIME_DNS_REVALIDATION_OPTION]["environment"] == "lab"


def test_no_lookup_records_no_dns_evidence(refusing_deployment):
    job = _job(_binding())
    row = _row(job)
    row["options"][RUNTIME_DNS_REVALIDATION_OPTION] = {"stale": True}
    materialized = materialize_canonical_scan_job(job.payload(), row, resolved_addresses=None)
    assert RUNTIME_DNS_REVALIDATION_OPTION not in materialized["options"]


def test_the_evidence_reaches_the_scan_result_metadata(refusing_deployment):
    _, materialized = _materialize(("99.84.152.51",))
    metadata: dict = {}
    record_runtime_dns_revalidation(metadata, materialized["options"])
    assert metadata["runtime_dns_revalidation"]["observed_addresses"] == ["99.84.152.51"]
    assert metadata["runtime_dns_revalidation"]["effective_addresses"] == list(
        _binding().allowed_addresses
    )


def test_the_worker_result_carries_the_dns_evidence(refusing_deployment):
    import worker

    _, materialized = _materialize(("99.84.152.51",))
    options = {
        **materialized["options"],
        "runtime_scope_guard": {
            "scope_receipt_id": "scope-cdn",
            "environment": "production",
            "allowed_hosts": [HOST],
            "allowed_root_domains": [],
            "normalized_scope": {"host": HOST},
            "requires_runtime_destination_check": True,
        },
    }
    checked = worker._apply_runtime_scope_guard_to_result(
        {"http": {"final_url": f"https://{HOST}/"}, "findings": [], "result": {}}, options,
    )
    assert checked.get("error") is None
    evidence = checked["scan_metadata"]["runtime_dns_revalidation"]
    assert evidence["observed_addresses"] == ["99.84.152.51"]
    assert evidence["effective_addresses"] == list(_binding().allowed_addresses)


def _fake_getaddrinfo(answers):
    async def getaddrinfo(host, port, *args, **kwargs):
        assert host == HOST
        return [
            (socket.AF_INET6 if ":" in address else socket.AF_INET, socket.SOCK_STREAM,
             socket.IPPROTO_TCP, "", (address, port))
            for address in answers
        ]
    return getaddrinfo


def test_the_worker_materializes_a_rotating_answer_and_refuses_a_rebound_one(
    refusing_deployment, monkeypatch,
):
    import worker

    job = _job(_binding(), scan_id="00000000-0000-0000-0000-00000000c0de")
    row = _row(job)

    class _Conn:
        async def fetchrow(self, *_args):
            return {**row, "parent_scan_id": None, "scan_role": None, "shard_index": None,
                    "shard_count": None, "campaign_id": None}

    class _Acquire:
        async def __aenter__(self):
            return _Conn()

        async def __aexit__(self, *_exc):
            return False

    monkeypatch.setattr(worker, "db_pool", type("Pool", (), {"acquire": lambda self: _Acquire()})())
    queued = job.payload()

    async def run(answers):
        asyncio.get_running_loop().getaddrinfo = _fake_getaddrinfo(answers)
        return await worker._materialize_scan_job_v2(queued)

    materialized = asyncio.run(run(("99.84.152.51", "2600:9000:2000:3c00::8")))
    assert materialized["options"]["_canonical_target_binding"] == job.target.canonical_dict()
    assert materialized["options"][RUNTIME_DNS_REVALIDATION_OPTION]["observed_addresses"] == [
        "99.84.152.51", "2600:9000:2000:3c00::8",
    ]
    with pytest.raises(CanonicalScanJobMaterializationError, match="rebinding"):
        asyncio.run(run(("127.0.0.1",)))


def test_broker_dispatch_revalidation_behaves_the_same(refusing_deployment, monkeypatch):
    from fleet_routes import router as fleet_router

    job = _job(_binding(), scan_id="00000000-0000-0000-0000-00000000b0b0")
    row = _row(job)

    class _Conn:
        async def fetchrow(self, *_args):
            return {**row, "parent_scan_id": None, "scan_role": None, "shard_index": None,
                    "shard_count": None}

    class _Acquire:
        async def __aenter__(self):
            return _Conn()

        async def __aexit__(self, *_exc):
            return False

    monkeypatch.setattr(fleet_router, "_pool", lambda: type("Pool", (), {"acquire": lambda self: _Acquire()})())

    async def run(answers, revalidate=True):
        asyncio.get_running_loop().getaddrinfo = _fake_getaddrinfo(answers)
        return await fleet_router._materialize_control_plane_scan_job_v2(
            job.payload(), revalidate_dns=revalidate,
        )

    materialized = asyncio.run(run(("99.84.152.51", "10.0.0.9", "2600:9000:2000:3c00::8")))
    options = materialized["options"]
    assert options["_canonical_target_binding"] == job.target.canonical_dict()
    evidence = options[RUNTIME_DNS_REVALIDATION_OPTION]
    # The dispatch resolver already drops what admission would drop.
    assert evidence["observed_admitted_addresses"] == ["99.84.152.51", "2600:9000:2000:3c00::8"]
    assert evidence["effective_addresses"] == list(job.target.allowed_addresses)
    assert "_runtime_dns_revalidation" in fleet_router._broker_execution_projection(materialized)["options"]

    for rebound in (("127.0.0.1",), ("10.0.0.9",), ("169.254.169.254",)):
        with pytest.raises(fleet_router.HTTPException) as excinfo:
            asyncio.run(run(rebound))
        assert excinfo.value.status_code == 422
        assert "does not allow" in str(excinfo.value.detail)

    # Re-projecting a finished lease for ingest makes no lookup and records no DNS evidence.
    ingest = asyncio.run(run(("127.0.0.1",), revalidate=False))
    assert RUNTIME_DNS_REVALIDATION_OPTION not in ingest["options"]
