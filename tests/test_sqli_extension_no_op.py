"""A chained SQLi extension is never admitted at a wall its own stage guard must refuse (audit S002).

`_floor_scale` gave a chained SQLi link exactly its predecessor's wall, assuming the interrupted
stage had started part-way through that hold. When the earlier stages were carried, the stage
had the whole hold. Then `run_staged_sqli_attempt` refused an equal-wall retry
(`would_repeat_timeout`), the link settled `partial` rather than `timed_out`, and the planner,
which extends only `timed_out`, ended the chain. With two such links and a 900 s lane,
`_fair_walls` granted {450, 450}: two guaranteed no-ops, where one 900 s link would finish a
stage that needs 600 s.

This replays that shape for real across rounds: the batch adapter runs every round (sqlmap is
the scripted unit fixture), each receipt is settled by the execution backend's own outcome
rule, and the extension planner plans the next round from those results and receipts.

Since soak N55 the floor is the interrupted stage's wall predicted at its own measured rate, so
the {450, 450} round is not planned at all: the lane funds one link that can finish.
"""

from __future__ import annotations

import asyncio
import dataclasses
import math
from types import SimpleNamespace
import uuid

import scan.action_adapter as action_adapter_module
from hunt.capability_executor import CapabilityAdapterResult
from runtime.models import ScanPolicy
from scan.action_plan import ScanActionPlan
from scan.execution_backend import PostgresScanExecutionBackend
from scan.sqli_stages import MINIMUM_STAGE_WALL_SECONDS
from scan.verification_extension import (
    EXTENDS_ARG,
    plan_verification_extensions,
    resume_observation_action_ids,
    stage_resume_walls,
)
from scan.work_manifests import build_candidate_manifest, build_endpoint_manifest
from tests.test_scan_action_adapter import TARGET, Backend, _action, _dispatcher, _lease, _noop

PROFILE = {"http_requests": 20_000, "tool_wall_seconds": 3_600}
SLICE = {"http_requests": 800, "tool_wall_seconds": 420}
# Time-based blind needs 600 s on this target -- its 189 requests at about 3.17 s each --
# and every other technique settles in 5 s.
TIME_STAGE_SECONDS = 600
TIME_STAGE_RATE = TIME_STAGE_SECONDS / 189


def _manifests():
    scan_id = str(uuid.uuid4())
    endpoints = build_endpoint_manifest(
        scan_id=scan_id, target_binding_digest=TARGET.digest,
        surface_manifest={
            "schema_version": "endpoint-manifest/v2", "status": "complete", "reason": None,
            "endpoints": [
                {
                    "method": "GET", "scheme": "https", "host": "app.example.test", "port": 443,
                    "normalized_path": path, "concrete_path": path, "query_keys": ["q"],
                    "source": "web.crawl",
                }
                for path in ("/one", "/two")
            ],
        },
        source_action_ids=("discover.web_crawl",),
    )
    candidates = build_candidate_manifest(
        endpoints, source_action_ids=("discover.web_crawl",), maximum=10,
    )
    return scan_id, endpoints, candidates


class _Scan:
    """Every action so far, run round by round against one durable checkpoint store."""

    def __init__(self, monkeypatch):
        self.scan_id, self.endpoints, self.candidates = _manifests()
        self.backend = Backend(manifests={
            self.endpoints.manifest_id: self.endpoints,
            self.candidates.manifest_id: self.candidates,
        })
        self.actions: list = []
        self.receipts: dict = {}
        self.results: dict = {}
        self.calls: list[tuple[str, str, int]] = []
        scan = self

        async def execute(_executor, context, adapter, **_kwargs):
            return await scan._execute(context, adapter)

        monkeypatch.setattr(action_adapter_module.CapabilityExecutor, "execute", execute)

    async def _execute(self, context, adapter):
        path = adapter._process_payload["execution_target"].split("app.example.test", 1)[1]
        technique = adapter._process_payload["scanner_options"]["technique"]
        wall = int(context.requested_budget["tool_wall_seconds"])
        self.calls.append((path.split("?")[0], technique, wall))
        if technique != "T":
            return CapabilityAdapterResult(
                status="success", actual_budget={"http_requests": 10, "tool_wall_seconds": 5},
                execution_started=True, parser_version="sqlmap-output/v1",
            )
        if wall >= TIME_STAGE_SECONDS:
            return CapabilityAdapterResult(
                status="success",
                actual_budget={"http_requests": 100, "tool_wall_seconds": TIME_STAGE_SECONDS - 10},
                execution_started=True, parser_version="sqlmap-output/v1",
            )
        # Killed by the wall it was given, having used all of it at the target's rate.
        return CapabilityAdapterResult(
            status="partial", partial=True, timed_out=True, errors=("timeout",),
            actual_budget={"http_requests": int(wall / TIME_STAGE_RATE), "tool_wall_seconds": wall},
            execution_started=True, parser_version="sqlmap-output/v1",
        )

    def add(self, action_id, *, start=0, budget=SLICE, extends=None):
        args = {
            "candidate_manifest_ref": self.candidates.reference().canonical_dict(),
            "endpoint_manifest_ref": self.endpoints.reference().canonical_dict(),
            "slice": {"start": start, "count": 1},
            "profile": "balanced_batch_v1", "proof_policy": "deterministic_differential_required",
            **({EXTENDS_ARG: extends} if extends else {}),
        }
        self.actions.append(dataclasses.replace(
            _action(action_id, "sqli.verify_batch", len(self.actions), capability_args=args),
            requested_budget=dict(budget), action_digest=None,
        ))

    def plan(self):
        return ScanActionPlan(
            scan_id=self.scan_id, execution_plan_digest="a" * 64,
            target_binding_digest=TARGET.digest, actions=tuple(self.actions),
        )

    def run(self, action_ids):
        plan = self.plan()
        dispatcher = _dispatcher(
            plan, self.backend,
            policy=ScanPolicy(active_testing=True, approval_receipt_id="approval-1"),
        )
        for action in plan.actions:
            if action.action_id not in action_ids:
                continue
            receipt = asyncio.run(dispatcher(action, _lease(plan, action), _noop))
            self.receipts[action.action_id] = receipt
            # Settled exactly as the execution backend settles a receipt.
            status, reason = PostgresScanExecutionBackend._receipt_outcome(
                SimpleNamespace(_receipt_reason=PostgresScanExecutionBackend._receipt_reason),
                receipt,
            )
            self.results[action.action_id] = SimpleNamespace(
                status=status, reason_code=reason,
                budget_reserved=dict(receipt.budget_reserved),
                budget_consumed=dict(receipt.budget_consumed),
            )

    def next_round(self, round_number):
        """Plan the next round from the settled results and their receipts; add its actions."""
        plan = self.plan()
        used = {
            name: sum(int(result.budget_consumed.get(name, 0)) for result in self.results.values())
            for name in PROFILE
        }
        observations = {
            action_id: tuple(self.receipts[action_id].observations)
            for action_id in resume_observation_action_ids(plan, self.results)
        }
        planned = plan_verification_extensions(
            parent_plan=plan, parent_results=self.results, profile_limits=PROFILE,
            residual={name: PROFILE[name] - used[name] for name in PROFILE},
            stage_resume_walls=stage_resume_walls(observations),
        )
        added = []
        for spec in planned:
            action_id = f"{spec['action_id']}.r{round_number:02d}"
            original = next(
                item for item in self.actions
                if item.action_id == spec["capability_args"][EXTENDS_ARG]
            )
            self.add(
                action_id, start=original.capability_args["slice"]["start"],
                budget=spec["budget"], extends=spec["capability_args"][EXTENDS_ARG],
            )
            added.append((action_id, int(spec["budget"]["tool_wall_seconds"])))
        return added

    def status(self, action_id):
        return self.results[action_id].status.value

    def techniques(self, path, since=0):
        return [technique for seen, technique, _ in self.calls[since:] if seen == path]


def _predicted_time_stage_wall(killed_wall):
    """What the killed time stage's own measurement predicts it needs (sqli_stages)."""
    sent = int(killed_wall / TIME_STAGE_RATE)
    return math.ceil(max(189, math.ceil(sent * 1.5)) * killed_wall / sent) + MINIMUM_STAGE_WALL_SECONDS


def test_two_links_that_cannot_both_finish_are_funded_one_at_a_time(monkeypatch):
    scan = _Scan(monkeypatch)
    scan.add("verify.sqli.r01", start=0)
    scan.add("verify.sqli.001.r01", start=1)
    scan.run({"verify.sqli.r01", "verify.sqli.001.r01"})
    # Each slice settles three techniques and its time-based stage is wall-killed.
    assert scan.status("verify.sqli.r01") == scan.status("verify.sqli.001.r01") == "timed_out"
    resume = [
        item["resume_wall_seconds"]
        for item in scan.receipts["verify.sqli.r01"].observations
        if item.get("kind") == "candidate_attempt"
    ]
    # The floor is the time stage predicted at its own measured rate, not the killed wall
    # plus a few seconds: {450, 450} would buy two links the wall kills again (N55).
    killed_at = max(wall for _, technique, wall in scan.calls if technique == "T")
    assert resume == [_predicted_time_stage_wall(killed_at)]
    assert resume[0] > killed_at + MINIMUM_STAGE_WALL_SECONDS

    # The 900 s lane cannot fund two such floors: one link is funded to the share, the other
    # keeps its place for the next round.
    second = scan.next_round(2)
    assert len(second) == 1
    assert second[0][0] == "verify.sqli.r01.ext.r02"
    assert resume[0] <= second[0][1] <= 900
    before = len(scan.calls)
    scan.run({second[0][0]})
    # Control: finished work is carried, not re-sent. Only the time stage runs, and finishes.
    assert scan.techniques("/one", before) == ["T"]
    assert scan.status(second[0][0]) == "success", "the stage that needs 600 s finished"

    third = scan.next_round(3)
    assert [action_id for action_id, _ in third] == ["verify.sqli.001.r01.ext.r03"]
    before = len(scan.calls)
    scan.run({third[0][0]})
    assert scan.techniques("/two", before) == ["T"]
    assert scan.status(third[0][0]) == "success"
    # Nothing is left to extend.
    assert scan.next_round(4) == []


def test_an_extension_held_below_its_predicted_stage_wall_is_refused_before_any_traffic(
    monkeypatch,
):
    scan = _Scan(monkeypatch)
    scan.add("verify.sqli.r01", start=0)
    scan.run({"verify.sqli.r01"})
    killed_at = max(wall for _, technique, wall in scan.calls if technique == "T")
    need = _predicted_time_stage_wall(killed_at)

    # Control: a link held at the wall its stage was killed at plus the old 30 s margin -- as
    # the old floor granted -- is refused before any traffic, not dispatched to be killed again.
    scan.add(
        "verify.sqli.r01.ext.r02", start=0, extends="verify.sqli.r01",
        budget={"http_requests": 800, "tool_wall_seconds": killed_at + 30},
    )
    before = len(scan.calls)
    scan.run({"verify.sqli.r01.ext.r02"})

    assert scan.calls[before:] == []
    receipt = scan.receipts["verify.sqli.r01.ext.r02"]
    deferred = [item for item in receipt.observations if item.get("kind") == "candidate_deferred"]
    assert [(item["reason"], item["resume_wall_seconds"], item["available_wall_seconds"])
            for item in deferred] == [("stage_wall_unfunded", need, killed_at + 30)]
    assert receipt.budget_consumed.get("http_requests", 0) == 0
    # It settles as the wall stopping it -- the limit it hit -- not as a partial verdict.
    assert scan.status("verify.sqli.r01.ext.r02") == "timed_out"
    assert stage_resume_walls({"x": receipt.observations}) == {"x": need}
    # The refused link measured nothing, yet the chain goes on: the next round is sized from
    # the chain's last measured link and funds the predicted stage wall.
    following = scan.next_round(3)
    assert [action_id for action_id, _ in following] == ["verify.sqli.r01.ext.r02.ext.r03"]
    assert following[0][1] >= need
    before = len(scan.calls)
    scan.run({following[0][0]})
    assert [technique for _, technique, _ in scan.calls[before:]] == ["T"]
    assert scan.status(following[0][0]) == "success"
