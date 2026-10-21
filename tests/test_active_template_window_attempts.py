"""The batch adapter runs planned active-template positions past a host's endpoints.

A thorough or deep slice declares ``endpoint_entries`` (E) beside ``manifest_entries`` (the
positions planned, up to the allowlist's 39 windows): position o runs window o on endpoint o % E.
Positions below E keep the attempt identities, checkpoints and resume of every earlier release;
later positions are their own attempts; a position past a smaller (GET-only) allowlist's windows
runs nothing. These tests drive the real adapter with a synthetic template bundle shaped like the
pinned one (1,146 templates, 1,000 of them GET-only) and a fake execution that returns success; no
scanner process runs. The last test checks the planned window count against the pinned bundle
and runs only in the scanner image.
"""

from __future__ import annotations

import asyncio
import hashlib
import math
import os
import uuid
from dataclasses import replace
from pathlib import Path

import pytest
import scan.action_adapter as action_adapter_module
from hunt.capability_executor import CapabilityAdapterResult
from runtime.capability_registry import CAPABILITY_REGISTRY
from runtime.models import ScanPolicy, TargetBinding
from scan.action_adapter import DatabaseNeutralScanActionDispatcher, _batch_candidate_id
from scan.action_plan import ScanAction, ScanActionPlan
from scan.execution_backend import ActionLease
from scan.external_process import ACTIVE_TEMPLATE_PLANNED_GET_ONLY_WINDOWS
from scan.nuclei_execution import (
    ACTIVE_TEMPLATE_PLANNED_WINDOWS,
    ACTIVE_TEMPLATE_WINDOW_SIZE,
    active_template_window,
    resolve_active_scan_nuclei_options,
)
from scan.nuclei_template_index import nuclei_templates_directory
from scan.work_manifests import (
    build_canonical_nuclei_template_manifest,
    build_endpoint_manifest,
)

TARGET = TargetBinding(
    target_id="target-1", target_kind="web", canonical_host="app.example.test",
    allowed_origins=("https://app.example.test",), allowed_addresses=("192.0.2.10",),
    allowed_root_domains=("example.test",),
)
AUTHORIZED = ScanPolicy(active_testing=True, allow_state_changing_http=True, approval_receipt_id="approval-1")
GET_ONLY = ScanPolicy(active_testing=True, approval_receipt_id="approval-1")
POSITION = {"http_requests": 120, "state_changing_requests": 120, "tool_wall_seconds": 45}


# --- adapter -------------------------------------------------------------------------------


def _template(index: int, method: str) -> str:
    return (
        f"id: synthetic-{method.lower()}-{index:04d}\n\ninfo:\n  name: Synthetic {index}\n"
        "  author: test\n  severity: high\n  tags: exposure\n\nhttp:\n"
        f"  - method: {method}\n    path:\n      - \"{{{{BaseURL}}}}/probe-{index}\"\n"
        f"    matchers:\n      - type: word\n        words:\n          - \"synthetic-{index}\"\n"
    )


@pytest.fixture(scope="module")
def bundle(tmp_path_factory):
    """A synthetic bundle shaped like the pinned one: 1,146 permitted, 1,000 of them GET."""
    root = tmp_path_factory.mktemp("nuclei-bundle")
    folder = root / "http" / "exposures"
    folder.mkdir(parents=True)
    for index in range(1_000):
        (folder / f"get-{index:04d}.yaml").write_text(_template(index, "GET"))
    for index in range(146):
        (folder / f"post-{index:04d}.yaml").write_text(_template(index, "POST"))
    return str(root)


class _Backend:
    def __init__(self, manifests):
        self.manifests = dict(manifests)
        self.attempts: dict = {}

    async def load_work_manifest(self, _action_id, reference):
        return self.manifests[reference.manifest_id]

    async def load_batch_attempts(self, action_id):
        return tuple(self.attempts.get(action_id, {}).values())

    async def checkpoint_batch_attempt(self, action_id, attempt):
        self.attempts.setdefault(action_id, {})[attempt["attempt_id"]] = dict(attempt)


class _Host:
    """One endpoint manifest and template manifest; slices of it run through the adapter."""

    def __init__(self, paths, sources=None):
        self.scan_id = str(uuid.uuid4())
        self.endpoints = build_endpoint_manifest(
            scan_id=self.scan_id, target_binding_digest=TARGET.digest,
            surface_manifest={
                "schema_version": "endpoint-manifest/v2", "status": "complete", "reason": None,
                "endpoints": [{
                    "method": "GET", "scheme": "https", "host": "app.example.test", "port": 443,
                    "normalized_path": path, "concrete_path": path, "query_keys": [],
                    "source": (sources or {}).get(path, "web.crawl"),
                } for path in paths],
            },
            source_action_ids=("discover.web_crawl",),
        )
        self.templates = build_canonical_nuclei_template_manifest(
            scan_id=self.scan_id, target_binding_digest=TARGET.digest,
        )
        self.backend = _Backend({
            self.endpoints.manifest_id: self.endpoints, self.templates.manifest_id: self.templates,
        })
        self.calls: list[dict] = []

    def action(self, action_id, *, start, count, windows=True, policy=AUTHORIZED):
        spec = CAPABILITY_REGISTRY.require("templates.active_batch")
        endpoints = len(self.endpoints.entries)
        hold = {
            name: amount * count for name, amount in POSITION.items()
            if name != "state_changing_requests" or policy.allow_state_changing_http
        }
        return ScanAction(
            action_id=action_id, stage="deterministic_active", ordinal=0,
            capability_name="templates.active_batch",
            capability_args={
                "target_manifest_ref": self.endpoints.reference().canonical_dict(),
                "template_manifest_ref": self.templates.reference().canonical_dict(),
                "slice": {"start": start, "count": count},
                "manifest_entries": ACTIVE_TEMPLATE_PLANNED_WINDOWS if windows else endpoints,
                **({"endpoint_entries": endpoints} if windows else {}),
                "profile": "thorough_batch_v1",
                "proof_policy": "deterministic_proof_contract_required",
            },
            target_binding_digest=TARGET.digest, input_binding_digest="1" * 64,
            requested_budget=hold,
            placement={
                "schema_version": "scan-action-placement/v1",
                "eligible_backends": ["local", "broker"],
                "requirements": dict(spec.placement_requirements),
                "adapter_name": spec.adapter, "adapter_version": spec.adapter_version,
            },
            dependencies=(), required=False, supporting=False, output_schema=spec.output_schema,
        )

    def run(self, monkeypatch, bundle_dir, action, *, policy=AUTHORIZED, statuses=None):
        plan = ScanActionPlan(
            scan_id=self.scan_id, execution_plan_digest="a" * 64,
            target_binding_digest=TARGET.digest, actions=(action,),
        )
        calls = self.calls

        async def execute(_self, context, adapter, **_kwargs):
            payload = adapter._process_payload
            calls.append({
                "action_id": action.action_id,
                "url": payload["execution_target"],
                "template_ids": payload["scanner_options"]["template_ids"],
            })
            return CapabilityAdapterResult(
                status=(statuses or {}).get(len(calls) - 1, "success"),
                actual_budget={name: 1 for name in context.requested_budget},
                observations=(), execution_started=True, parser_version="nuclei-jsonl/v1",
            )

        monkeypatch.setattr(action_adapter_module.CapabilityExecutor, "execute", execute)
        monkeypatch.setattr(action_adapter_module, "nuclei_templates_directory", lambda: bundle_dir)

        async def process_runner(*_a, **_k):
            raise AssertionError("process runner must not be used")

        async def heartbeat():
            return None

        dispatcher = DatabaseNeutralScanActionDispatcher(
            target_url="https://app.example.test/", options={}, target=TARGET, policy=policy,
            scan_id=plan.scan_id, job_id="job-1", worker_id="broker:worker-1", plan=plan,
            backend=self.backend, process_runner=process_runner, cancelled=lambda: False,
        )
        lease = ActionLease(
            lease_id=str(uuid.uuid4()), lease_token="x" * 32, scan_id=plan.scan_id,
            plan_digest=plan.plan_digest, execution_plan_digest=plan.execution_plan_digest,
            target_binding_digest=plan.target_binding_digest, action=action,
            backend="broker", worker_id="broker:worker-1", lease_seconds=60, attempt=1,
        )
        return asyncio.run(dispatcher(action, lease, heartbeat))

    def attempt_id(self, position):
        endpoints = len(self.endpoints.entries)
        entry = self.endpoints.entries[position % endpoints]
        candidate = _batch_candidate_id(entry, position % endpoints)
        if position >= endpoints:
            candidate = f"{candidate}:window:{position}"
        digest = self.endpoints.reference().manifest_digest
        return hashlib.sha256(f"{digest}:nuclei_active:{candidate}".encode()).hexdigest()


def _allowlist(bundle_dir, *, state_changing):
    resolved = resolve_active_scan_nuclei_options(
        {"severity": "high,critical"}, templates_dir=bundle_dir,
        allow_state_changing_http=state_changing, allow_exploit_classes=state_changing,
    )
    return str(resolved.worker_options["template_ids"])


def _windows_record(receipt):
    return next(item for item in receipt.observations if item.get("kind") == "active_template_windows")


def test_each_position_runs_its_window_on_endpoint_o_mod_e(monkeypatch, bundle):
    host = _Host(("/", "/a"))
    receipts = [
        host.run(monkeypatch, bundle, host.action("active.templates.r01", start=0, count=2)),
        host.run(monkeypatch, bundle, host.action("active.templates.r02", start=2, count=33)),
        host.run(monkeypatch, bundle, host.action("active.templates.r03", start=35, count=4)),
    ]
    assert [receipt.status for receipt in receipts] == ["success"] * 3
    allowlist = _allowlist(bundle, state_changing=True)
    assert math.ceil(len(allowlist.split(",")) / ACTIVE_TEMPLATE_WINDOW_SIZE) == 39
    assert len(host.calls) == 39
    # Every window runs at the host's base URL (no seed here: the origin's root).
    assert {call["url"] for call in host.calls} == {"https://app.example.test/"}
    assert [call["template_ids"] for call in host.calls] == [
        active_template_window(allowlist, position).template_ids for position in range(39)
    ]
    # Every permitted template ran exactly once on the host.
    ran = [item for call in host.calls for item in call["template_ids"].split(",")]
    assert sorted(ran) == sorted(allowlist.split(","))
    windows = [_windows_record(receipt) for receipt in receipts]
    assert [record["windows_run"] for record in windows] == [
        [0, 1], list(range(2, 35)), list(range(35, 39)),
    ]
    assert {record["window_count"] for record in windows} == {39}


def test_every_window_runs_at_the_scans_seed_url_not_a_discovered_endpoints_path(monkeypatch, bundle):
    """A window's templates address the host from nuclei's base URL ({{BaseURL}}/images/json; a
    raw ``GET /version`` is joined to the base path too). Zoo docker (0d8c38011): its endpoints
    were /version, /info and /, so window 3 ran misconfigured-docker at /version/images/json and
    window 37 ran docker-daemon-exposed under /info: both got 404, both windows counted as run,
    and the host's two critical findings were lost. Every window now runs at the scan's seed."""
    host = _Host(("/version", "/info", "/"), sources={"/": "seed"})
    for number, (start, count) in enumerate(((0, 3), (3, 33), (36, 3)), start=1):
        host.run(monkeypatch, bundle, host.action(f"active.templates.r{number:02d}", start=start, count=count))
    assert len(host.calls) == 39
    assert {call["url"] for call in host.calls} == {"https://app.example.test/"}
    # Each window still ran exactly once, under its own planned position's attempt.
    allowlist = _allowlist(bundle, state_changing=True)
    assert [call["template_ids"] for call in host.calls] == [
        active_template_window(allowlist, position).template_ids for position in range(39)
    ]


def test_a_seed_with_a_base_path_is_where_the_windows_run(monkeypatch, bundle):
    host = _Host(("/app/", "/app/login", "/app/api"), sources={"/app/": "seed"})
    host.run(monkeypatch, bundle, host.action("active.templates.r01", start=0, count=3))
    host.run(monkeypatch, bundle, host.action("active.templates.r02", start=3, count=4))
    assert {call["url"] for call in host.calls} == {"https://app.example.test/app/"}


def test_a_slice_without_planned_windows_runs_its_windows_at_the_seed_too(monkeypatch, bundle):
    """Fast, balanced, a host with as many endpoints as windows and a parallel shard plan and hold
    one position per endpoint exactly as before, with the same attempts and the same window per
    position; only the URL each attempt targets is the seed (or, in a shard's slice of the
    endpoints with no seed, the origin's root) instead of the endpoint's path."""
    host = _Host(("/version", "/info", "/"), sources={"/": "seed"})
    action = host.action("active.templates.r01", start=0, count=3, windows=False)
    host.run(monkeypatch, bundle, action)
    assert "endpoint_entries" not in action.capability_args
    assert [call["url"] for call in host.calls] == ["https://app.example.test/"] * 3
    allowlist = _allowlist(bundle, state_changing=True)
    assert [call["template_ids"] for call in host.calls] == [
        active_template_window(allowlist, position).template_ids for position in range(3)
    ]
    assert set(host.backend.attempts["active.templates.r01"]) == {
        host.attempt_id(position) for position in range(3)
    }
    shard = _Host(("/version", "/info"))
    shard.run(monkeypatch, bundle, shard.action("active.templates.r01", start=0, count=2, windows=False))
    assert [call["url"] for call in shard.calls] == ["https://app.example.test/"] * 2


def test_an_endpoints_own_position_keeps_its_identity_and_later_ones_are_their_own(monkeypatch, bundle):
    windowed = _Host(("/", "/a"))
    windowed.run(monkeypatch, bundle, windowed.action("active.templates.r01", start=0, count=2))
    windowed.run(monkeypatch, bundle, windowed.action("active.templates.r02", start=2, count=4))
    # The same endpoints planned as 2.11.0 did, without positions past them.
    legacy = _Host(("/", "/a"))
    legacy.endpoints, legacy.templates, legacy.backend = (
        windowed.endpoints, windowed.templates, _Backend(windowed.backend.manifests),
    )
    legacy.run(monkeypatch, bundle, legacy.action("active.templates.r01", start=0, count=2, windows=False))
    first = set(windowed.backend.attempts["active.templates.r01"])
    assert first == set(legacy.backend.attempts["active.templates.r01"])
    assert first == {windowed.attempt_id(0), windowed.attempt_id(1)}
    later = windowed.backend.attempts["active.templates.r02"]
    assert set(later) == {windowed.attempt_id(position) for position in range(2, 6)}
    assert all(
        str(item["candidate_id"]).endswith(f":window:{item['template_window']['index']}")
        for item in later.values()
    )
    # Resumed, the slice re-sends nothing and keeps the same attempts and windows.
    calls = len(windowed.calls)
    resumed = windowed.run(monkeypatch, bundle, windowed.action("active.templates.r02", start=2, count=4))
    assert len(windowed.calls) == calls
    assert set(windowed.backend.attempts["active.templates.r02"]) == set(later)
    assert resumed.redacted_execution["resumed_count"] == 4
    assert _windows_record(resumed)["windows_run"] == [2, 3, 4, 5]


def test_a_position_past_a_get_only_allowlist_runs_nothing(monkeypatch, bundle):
    host = _Host(("/",))
    allowlist = _allowlist(bundle, state_changing=False)
    get_windows = math.ceil(len(allowlist.split(",")) / ACTIVE_TEMPLATE_WINDOW_SIZE)
    assert get_windows == 34 < ACTIVE_TEMPLATE_PLANNED_WINDOWS
    receipts = [
        host.run(monkeypatch, bundle, host.action("active.templates.r01", start=0, count=1, policy=GET_ONLY), policy=GET_ONLY),
        host.run(monkeypatch, bundle, host.action("active.templates.r02", start=1, count=33, policy=GET_ONLY), policy=GET_ONLY),
        host.run(monkeypatch, bundle, host.action("active.templates.r03", start=34, count=5, policy=GET_ONLY), policy=GET_ONLY),
    ]
    assert len(host.calls) == get_windows
    pairs = [(call["url"], call["template_ids"]) for call in host.calls]
    assert len(set(pairs)) == len(pairs), "no endpoint runs the same window twice"
    beyond = [
        item for receipt in receipts for item in receipt.observations
        if item.get("kind") == "candidate_inapplicable"
    ]
    assert len(beyond) == ACTIVE_TEMPLATE_PLANNED_WINDOWS - get_windows
    assert {item["reason"] for item in beyond} == {"template_window_beyond_allowlist"}
    # The last slice ran nothing at all: settled without traffic and without unattempted work.
    last = receipts[-1]
    assert last.status == "success"
    assert last.redacted_execution["unattempted_count"] == 0
    assert last.redacted_execution["inapplicable_count"] == 5
    assert sum(int(amount) for amount in last.budget_consumed.values()) == 0
    assert _windows_record(receipts[1])["window_count"] == get_windows


def test_only_windows_whose_attempt_finished_are_reported_run(monkeypatch, bundle):
    """A window whose attempt timed out or failed did not run its templates; the slice's record
    (and so ``nuclei_active.template_windows``) leaves it out."""
    host = _Host(("/", "/a"))
    receipt = host.run(
        monkeypatch, bundle, host.action("active.templates.r02", start=2, count=4),
        statuses={1: "timed_out", 2: "failed"},
    )
    assert [call["template_ids"] for call in host.calls[:4]] == [
        active_template_window(_allowlist(bundle, state_changing=True), position).template_ids
        for position in range(2, 6)
    ]
    assert _windows_record(receipt)["windows_run"] == [2, 5]


def test_a_slice_whose_declared_endpoints_disagree_with_its_manifest_fails_closed(monkeypatch, bundle):
    host = _Host(("/", "/a"))
    action = host.action("active.templates.r02", start=2, count=4)
    args = dict(action.capability_args)
    args["endpoint_entries"] = 3
    with pytest.raises(action_adapter_module.ScanActionAdapterError):
        host.run(monkeypatch, bundle, replace(action, capability_args=args, action_digest=None))


# --- the pinned bundle ------------------------------------------------------------------------


def _pinned_bundle() -> str | None:
    directory = nuclei_templates_directory()
    return directory if (Path(directory) / "http").is_dir() and os.access(directory, os.R_OK) else None


@pytest.mark.skipif(_pinned_bundle() is None, reason="runs in the scanner image (pinned template bundle)")
def test_the_planned_windows_match_the_pinned_bundle():
    directory = _pinned_bundle()
    state_changing = _allowlist(directory, state_changing=True).split(",")
    get_only = _allowlist(directory, state_changing=False).split(",")
    assert ACTIVE_TEMPLATE_PLANNED_WINDOWS == math.ceil(len(state_changing) / ACTIVE_TEMPLATE_WINDOW_SIZE)
    assert ACTIVE_TEMPLATE_PLANNED_GET_ONLY_WINDOWS == math.ceil(len(get_only) / ACTIVE_TEMPLATE_WINDOW_SIZE)
    assert ACTIVE_TEMPLATE_PLANNED_GET_ONLY_WINDOWS <= ACTIVE_TEMPLATE_PLANNED_WINDOWS


# The template bundle both planned window counts were measured on (1,146 permitted templates
# with state-changing HTTP, 761 GET-only), in the scanner image built from it.
MEASURED_BUNDLE_COMMIT = "2935d63aebd1f5f4a3c8e87c6e7f5c47f689b115"
MEASURED_BUNDLE_SHA256 = "20aff7085b5c1771a8f7a28624009359a1cedab924c9ad7836078ca07e28de39"


def test_the_planned_windows_were_measured_on_the_bundle_the_image_pins():
    """The test above re-measures the windows, but only where the bundle is installed. A bundle
    bump whose allowlist splits into more windows would leave the extra ones unplanned while the
    family read complete, so the bump fails here, on any host, until they are re-measured."""
    dockerfile = (Path(__file__).parents[1] / "scanner" / "Dockerfile").read_text()
    assert f"ARG NUCLEI_TEMPLATES_COMMIT={MEASURED_BUNDLE_COMMIT}" in dockerfile
    assert f"ARG NUCLEI_TEMPLATES_SHA256={MEASURED_BUNDLE_SHA256}" in dockerfile
    assert (ACTIVE_TEMPLATE_PLANNED_WINDOWS, ACTIVE_TEMPLATE_PLANNED_GET_ONLY_WINDOWS) == (39, 26)
