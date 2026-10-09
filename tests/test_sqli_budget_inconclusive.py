"""SQLi continuations need evidence they can make progress (soak N55, 2026-10-09).

Balanced scan 9de6a910 of honey (2.8.0, seeds ``GET /hub/``, ``GET /hub/login`` and
``POST /hub/login form:username=,password=``) ran into its 3,600 s limit. SQLi held 2,833 s
of it across six timed-out actions and concluded nothing. Its receipts show why:

* two JSON chat candidates (8 and 4 body fields, 13.1 and 5.3 s per request) each ran a
  420 s slice that was killed inside union-based, the first technique, after 32 and 80
  requests; union-based alone needs 53 requests per field there (424 and 212);
* the next round extended both at 450 s against a 440 s floor -- the killed wall plus 20 s --
  and both were killed in the same stage again, after 122 and 72 requests: 900 s on work
  that could not finish in any round, while the login form's XSS extension was crowded out;
* the login form's guard sized error-based at 144 requests although sqlmap ran it over both
  fields (286), so it started with 159 s left and the wall killed it at 90.

Every sqlmap call here is a scripted unit fixture (no process runs); the request counts and
rates are the ones those receipts recorded.
"""

from __future__ import annotations

import asyncio
import dataclasses
import uuid
from types import SimpleNamespace

import scan.action_adapter as action_adapter_module
from hunt.capability_executor import CapabilityAdapterResult
from runtime.models import ScanPolicy
from scan.action_plan import ScanActionPlan
from scan.execution_backend import PostgresScanExecutionBackend
from scan.finalizer import _SLOW_ENDPOINT_RECORD_KINDS
from scan.sqli_stages import (
    INCONCLUSIVE_RECORD_KIND,
    MINIMUM_STAGE_WALL_SECONDS,
    predicted_stage_wall_seconds,
    prior_resume_wall_seconds,
    prior_stages,
    resume_wall_seconds,
    run_staged_sqli_attempt,
    stage_attempt_id,
    stage_requests,
)
from scan.verification_extension import (
    EXTENDS_ARG,
    lane_round_wall_ceiling,
    plan_verification_extensions,
    resume_observation_action_ids,
    stage_resume_walls,
)
from scan.work_manifests import build_candidate_manifest, build_endpoint_manifest

from tests.test_scan_action_adapter import (
    TARGET,
    Backend,
    _action,
    _dispatcher,
    _lease,
    _noop,
)

BALANCED = {"http_requests": 20_000, "state_changing_requests": 2_000, "tool_wall_seconds": 3_600}
EXECUTION_PLAN = {"budget": {"max_tool_wall_seconds": 3_600}}
# The body slice 9de6a910 planned for each chat candidate.
SLICE = {"http_requests": 800, "state_changing_requests": 480, "tool_wall_seconds": 420}
# The login slice keeps the 420 s wall; its request hold is large enough that, like the soak's
# (364 of 800), it spends under half of it -- a latency-starved slice, eligible to extend.
LOGIN_SLICE = {"http_requests": 1_200, "state_changing_requests": 1_200, "tool_wall_seconds": 420}
# Fixture: single-field requests per technique for a negative verdict (sqli_stages).
NEGATIVE = {"U": 53, "B": 87, "E": 144, "T": 189}


def test_a_stage_costs_its_single_field_requests_once_per_tested_field():
    # 9de6a910's login form, two fields: U 103, B 171, E 286 requests were measured.
    assert [stage_requests(item, 2) for item in "UBE"] == [106, 174, 288]
    assert stage_requests("U", 8) == 424
    assert stage_requests("T", None) == 189
    # No measurement of the candidate's own rate: no prediction.
    assert predicted_stage_wall_seconds("U", field_count=8, seconds_per_request=None) is None


def test_the_next_stage_is_predicted_at_the_candidates_own_rate():
    # Fixture: verify.sqli.r01's chat candidate, U killed at 420 s after 32 requests.
    rate = 420 / 32
    need = resume_wall_seconds(
        (), {"U": 420}, field_count=8, seconds_per_request=rate, killed_sent={"U": 32},
    )
    assert need == predicted_stage_wall_seconds(
        "U", field_count=8, seconds_per_request=rate, sent_before_kill=32,
    )
    assert need > 5_000
    # Without a rate the old floor (killed wall plus one stage minimum) still applies.
    assert resume_wall_seconds((), {"U": 420}) == 420 + MINIMUM_STAGE_WALL_SECONDS
    # A stage killed after sending more than its nominal cost needs half again what it sent.
    assert predicted_stage_wall_seconds(
        "U", field_count=1, seconds_per_request=1.0, sent_before_kill=200,
    ) == 300 + MINIMUM_STAGE_WALL_SECONDS


def test_the_guard_counts_every_field_before_starting_a_stage():
    # Fixture: the login form's slice. U and B settle; error-based over two fields does not fit
    # the wall left at the measured rate, so it is not started to be killed part-way.
    calls = []

    async def run_stage(technique, budget, _latency):
        calls.append(technique)
        need = stage_requests(technique, 2)
        took = int(need * 1.0)
        return SimpleNamespace(
            status="success", timed_out=False, errors=(), observations=(),
            actual_budget={"http_requests": need, "tool_wall_seconds": took},
        )

    async def checkpoint(_item):
        return None

    outcome = asyncio.run(run_staged_sqli_attempt(
        candidate_attempt_id="c" * 64, candidate_id="login", budget={
            "http_requests": 800, "state_changing_requests": 800, "tool_wall_seconds": 420,
        },
        prior=prior_stages((), "c" * 64), own_action_id="verify.sqli.r02",
        run_stage=run_stage, checkpoint=checkpoint, cancelled=lambda: False, field_count=2,
    ))
    # U 106 s and B 174 s leave 140 s; E needs 288 requests at about 1 s each.
    assert calls == ["U", "B"]
    assert outcome.stages[-1] == {"technique": "E", "outcome": "wall_exhausted"}
    assert outcome.actual_budget["tool_wall_seconds"] == 280
    assert outcome.resume_technique == "E" and outcome.field_count == 2
    assert outcome.resume_wall_seconds >= 288 + MINIMUM_STAGE_WALL_SECONDS
    # Each stage record names the fields it tested, so a later round predicts from it.
    prior = prior_stages(
        (("verify.sqli.r02", ({
            "attempt_id": stage_attempt_id("c" * 64, "U"), "status": "success",
            "budget_consumed": {"http_requests": 106, "tool_wall_seconds": 106},
            "observations": (dict(outcome.observations[0]),),
        },)),), "c" * 64,
    )
    assert prior.field_count == 2 and prior.seconds_per_request == 1.0
    assert prior_resume_wall_seconds(prior) == 174 + MINIMUM_STAGE_WALL_SECONDS


def test_the_lane_round_ceiling_is_read_from_the_execution_plan():
    assert lane_round_wall_ceiling(EXECUTION_PLAN) == 900
    assert lane_round_wall_ceiling({"budget": {"max_tool_wall_seconds": 10_800}}) == 2_700
    assert lane_round_wall_ceiling({}) is None
    assert lane_round_wall_ceiling(None) is None
    assert INCONCLUSIVE_RECORD_KIND in _SLOW_ENDPOINT_RECORD_KINDS


# Fixture endpoints: seconds per request and tested fields, from 9de6a910's receipts.
ENDPOINTS = {
    "/chat": (13.1, 8),
    "/copilot": (5.3, 4),
    "/login": (0.6, 2),
}


class _Scan:
    """A Balanced Scan's SQLi slices run round by round against one checkpoint store."""

    def __init__(self, monkeypatch, paths):
        self.scan_id = str(uuid.uuid4())
        self.paths = paths
        self.endpoints = build_endpoint_manifest(
            scan_id=self.scan_id, target_binding_digest=TARGET.digest,
            surface_manifest={
                "schema_version": "endpoint-manifest/v2", "status": "complete", "reason": None,
                "endpoints": [
                    {
                        "method": "POST", "scheme": "https", "host": "app.example.test",
                        "port": 443, "normalized_path": path, "concrete_path": path,
                        "query_keys": [], "content_type": "application/json",
                        "body_field_names": [
                            f"field{index}" for index in range(ENDPOINTS[path][1])
                        ],
                        "source": "inputs.custom_endpoints",
                    }
                    for path in paths
                ],
            },
            source_action_ids=("discover.web_crawl",),
        )
        self.candidates = build_candidate_manifest(
            self.endpoints, source_action_ids=("discover.web_crawl",), maximum=20,
            allow_state_changing_http=True,
        )
        # sqlmap is handed every declared body field (``-p``); each slice here holds the
        # endpoint's first candidate.
        self.order = [str(entry["canonical_path"]) for entry in self.candidates.entries]
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
            return scan._execute(context, adapter)

        monkeypatch.setattr(action_adapter_module.CapabilityExecutor, "execute", execute)

    def _execute(self, context, adapter):
        target = adapter._process_payload["execution_target"]
        path = target.split("app.example.test", 1)[1].split("?")[0]
        technique = adapter._process_payload["scanner_options"]["technique"]
        wall = int(context.requested_budget["tool_wall_seconds"])
        self.calls.append((path, technique, wall))
        rate, fields = ENDPOINTS[path]
        need = NEGATIVE[technique] * fields
        if need * rate <= wall:
            return CapabilityAdapterResult(
                status="success",
                actual_budget={"http_requests": need, "tool_wall_seconds": int(need * rate)},
                execution_started=True, parser_version="sqlmap-output/v1",
            )
        return CapabilityAdapterResult(
            status="partial", partial=True, timed_out=True, errors=("timeout",),
            actual_budget={"http_requests": int(wall / rate), "tool_wall_seconds": wall},
            execution_started=True, parser_version="sqlmap-output/v1",
        )

    def add(self, action_id, *, path, budget=SLICE, extends=None):
        args = {
            "candidate_manifest_ref": self.candidates.reference().canonical_dict(),
            "endpoint_manifest_ref": self.endpoints.reference().canonical_dict(),
            "slice": {"start": self.order.index(path), "count": 1},
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
            policy=ScanPolicy(
                active_testing=True, allow_state_changing_http=True,
                approval_receipt_id="approval-1",
            ),
            options={"scan_execution_plan": EXECUTION_PLAN},
        )
        for action in plan.actions:
            if action.action_id not in action_ids:
                continue
            receipt = asyncio.run(dispatcher(action, _lease(plan, action), _noop))
            self.receipts[action.action_id] = receipt
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
        plan = self.plan()
        used = {
            name: sum(int(result.budget_consumed.get(name, 0)) for result in self.results.values())
            for name in BALANCED
        }
        observations = {
            action_id: tuple(self.receipts[action_id].observations)
            for action_id in resume_observation_action_ids(plan, self.results)
        }
        planned = plan_verification_extensions(
            parent_plan=plan, parent_results=self.results, profile_limits=BALANCED,
            residual={name: BALANCED[name] - used[name] for name in BALANCED},
            stage_resume_walls=stage_resume_walls(observations),
        )
        added = []
        for spec in planned:
            action_id = f"{spec['action_id']}.r{round_number:02d}"
            original = next(
                item for item in self.actions
                if item.action_id == spec["capability_args"][EXTENDS_ARG]
            )
            path = self.order[original.capability_args["slice"]["start"]]
            self.add(
                action_id, path=path, budget=spec["budget"],
                extends=spec["capability_args"][EXTENDS_ARG],
            )
            added.append((action_id, int(spec["budget"]["tool_wall_seconds"])))
        return added

    def records(self, action_id, kind):
        return [
            item for item in self.receipts[action_id].observations if item.get("kind") == kind
        ]


def test_no_continuation_is_granted_to_a_slice_that_settled_nothing_and_cannot_fit(monkeypatch):
    """Regression for N55: verify.sqli.r01 settled no stage and was extended at 450 s anyway."""
    scan = _Scan(monkeypatch, ("/chat", "/copilot"))
    scan.add("verify.sqli.r01", path="/chat")
    scan.add("verify.sqli.001.r01", path="/copilot")
    scan.run({"verify.sqli.r01", "verify.sqli.001.r01"})
    # As on the soak: both slices are killed inside union-based with no stage settled.
    assert [(path, technique) for path, technique, _ in scan.calls] == [
        ("/chat", "U"), ("/copilot", "U"),
    ]
    assert scan.results["verify.sqli.r01"].status.value == "timed_out"
    assert scan.results["verify.sqli.001.r01"].status.value == "timed_out"
    chat = scan.records("verify.sqli.r01", "candidate_attempt")[0]
    assert chat["resume_technique"] == "U" and chat["field_count"] == 8
    assert chat["resume_wall_seconds"] > 900

    # Control: the floor the 2.8.0 planner read from the same receipt -- the killed wall
    # plus one stage minimum -- fits the lane and would have granted the 450 s extension.
    old_walls = {"verify.sqli.r01": 420 + MINIMUM_STAGE_WALL_SECONDS,
                 "verify.sqli.001.r01": 420 + MINIMUM_STAGE_WALL_SECONDS}
    used = {
        name: sum(int(item.budget_consumed.get(name, 0)) for item in scan.results.values())
        for name in BALANCED
    }
    old = plan_verification_extensions(
        parent_plan=scan.plan(), parent_results=scan.results, profile_limits=BALANCED,
        residual={name: BALANCED[name] - used[name] for name in BALANCED},
        stage_resume_walls=old_walls,
    )
    assert [item["budget"]["tool_wall_seconds"] for item in old] == [450, 450]

    # With the prediction no continuation is granted: there is no signal it can progress.
    assert scan.next_round(2) == []
    # Each candidate carries an explicit inconclusive-for-budget verdict with its numbers.
    for action_id, fields in (("verify.sqli.r01", 8), ("verify.sqli.001.r01", 4)):
        attempt = scan.records(action_id, "candidate_attempt")[0]
        assert attempt["verdict"] == "inconclusive"
        assert attempt["inconclusive_reason"] == "budget"
        [verdict] = scan.records(action_id, INCONCLUSIVE_RECORD_KIND)
        assert verdict["reason"] == "verdict_exceeds_round_budget"
        assert verdict["technique"] == "U" and verdict["field_count"] == fields
        assert verdict["refuted_techniques"] == []
        assert verdict["unsettled_techniques"] == ["U", "B", "E", "T"]
        assert verdict["predicted_wall_seconds"] > verdict["round_wall_ceiling_seconds"] == 900
        assert verdict["url"].startswith("https://app.example.test/")


def test_the_login_form_concludes_once_hopeless_work_yields_its_time(monkeypatch):
    scan = _Scan(monkeypatch, ("/chat", "/login"))
    scan.add("verify.sqli.r01", path="/chat")
    scan.add("verify.sqli.r02", path="/login", budget=LOGIN_SLICE)
    scan.run({"verify.sqli.r01", "verify.sqli.r02"})
    login = [technique for path, technique, _ in scan.calls if path == "/login"]
    # U, B and E settle in the slice; time-based over two fields does not fit what is left,
    # so the slice yields that wall instead of starting a stage the wall would kill.
    assert login == ["U", "B", "E"]
    [attempt] = scan.records("verify.sqli.r02", "candidate_attempt")
    assert attempt["resume_technique"] == "T"
    assert "verdict" not in attempt
    assert scan.receipts["verify.sqli.r02"].budget_consumed["tool_wall_seconds"] < 420

    # Only the login form is continued; its time-based stage fits and settles.
    second = scan.next_round(2)
    assert [action_id for action_id, _ in second] == ["verify.sqli.r02.ext.r02"]
    assert second[0][1] >= attempt["resume_wall_seconds"]
    before = len(scan.calls)
    scan.run({second[0][0]})
    assert [(path, technique) for path, technique, _ in scan.calls[before:]] == [("/login", "T")]
    assert scan.results[second[0][0]].status.value == "success"
    assert scan.next_round(3) == []
