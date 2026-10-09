"""SQLi continuations need evidence they can make progress (soak N55, 2026-10-09).

Balanced scan 9de6a910 of honey (2.8.0, seeds ``GET /hub/``, ``GET /hub/login`` and
``POST /hub/login form:username=,password=``) ran into its 3,600 s limit. SQLi held 2,833 s
of it across six timed-out actions and concluded nothing. Its receipts show why:

* two JSON chat candidates (8 and 4 body fields, 13.1 and 5.3 s per request) each ran a
  420 s slice that was killed inside union-based, the first technique, after 32 and 80
  requests -- sqlmap ran it over every field, 424 and 212 requests for a negative verdict;
* the next round extended both at 450 s against a 440 s floor -- the killed wall plus 20 s --
  and both were killed in the same stage again, after 122 and 72 requests: 900 s on work
  that could not finish, while the login form's XSS extension was crowded out;
* the login form's guard sized error-based at 144 requests although sqlmap ran it over both
  fields (286), so it started with 159 s left and the wall killed it at 90.

A body with several fields is now verified one field per run, so partial progress is
checkpointed; each unit is predicted at the candidate's own robust rate, and a unit that no
round can fund is given one probe round before it is recorded as inconclusive for budget.

Every sqlmap call here is a scripted unit fixture (no process runs); the request counts and
rates are the ones those receipts recorded unless a test says otherwise.
"""

from __future__ import annotations

import asyncio
import dataclasses
import sys
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
    MINIMUM_RATE_SAMPLE_REQUESTS,
    MINIMUM_STAGE_WALL_SECONDS,
    predicted_stage_wall_seconds,
    prior_stages,
    rate_sample,
    resume_plan,
    run_staged_sqli_attempt,
    sqli_budget_outcomes,
    stage_attempt_id,
    stage_requests,
    stage_units,
)
from scan.verification_extension import (
    EXTENDS_ARG,
    LAST_CHANCE_ARG,
    SCAN_WALL_SHARE_ARG,
    budget_concluded_slices,
    lane_round_wall_ceiling,
    plan_verification_extensions,
    resume_observation_action_ids,
    stage_last_chance_walls,
    stage_remaining_walls,
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

# Fixture: tool-wall ceilings of the budget profiles (scan/contracts.py) and one round's
# SQLi lane share of each.
FAST, BALANCED_WALL, THOROUGH = 1_500, 3_600, 10_800
BALANCED = {"http_requests": 20_000, "state_changing_requests": 2_000, "tool_wall_seconds": 3_600}
# Fixture: single-field requests per technique for a negative verdict (sqli_stages).
NEGATIVE = {"U": 53, "B": 87, "E": 144, "T": 189}


def _plan(wall):
    return {"budget": {"max_tool_wall_seconds": wall}}


def test_the_round_ceiling_is_one_lane_share_of_the_profile_wall():
    assert lane_round_wall_ceiling(_plan(FAST)) == 375
    assert lane_round_wall_ceiling(_plan(BALANCED_WALL)) == 900
    assert lane_round_wall_ceiling(_plan(THOROUGH)) == 2_700
    assert lane_round_wall_ceiling({}) is None
    assert lane_round_wall_ceiling(None) is None
    assert INCONCLUSIVE_RECORD_KIND in _SLOW_ENDPOINT_RECORD_KINDS


def test_a_body_with_several_fields_is_verified_one_field_per_run():
    assert stage_units(("username", "password")) == (
        ("U", "username"), ("U", "password"), ("B", "username"), ("B", "password"),
        ("E", "username"), ("E", "password"), ("T", "username"), ("T", "password"),
    )
    # One tested field (or a query candidate) keeps one unit per technique.
    assert stage_units(("message",)) == (("U", None), ("B", None), ("E", None), ("T", None))
    assert stage_units(None) == stage_units(())
    # A whole run over several fields costs one field's run per field (9de6a910's login form
    # measured U 103, B 171 and E 286 requests over two fields).
    assert [stage_requests(item, 2) for item in "UBE"] == [106, 174, 288]
    assert predicted_stage_wall_seconds("U", field_count=8, seconds_per_request=None) is None


def test_a_rate_sample_needs_enough_requests_from_a_settled_or_wall_killed_run():
    # U killed after 2 requests in 20 s measured start-up, not a 10 s per request target.
    assert rate_sample(status="partial", timed_out=True, sent=2, wall=20) is None
    assert MINIMUM_RATE_SAMPLE_REQUESTS == 10
    # An errored run (not settled, not wall-killed) measures nothing either.
    assert rate_sample(status="failed", timed_out=False, sent=50, wall=400) is None
    assert rate_sample(status="partial", timed_out=False, sent=50, wall=400) is None
    assert rate_sample(status="success", timed_out=False, sent=50, wall=75) == 1.5
    assert rate_sample(status="partial", timed_out=True, sent=32, wall=420) == 420 / 32


def test_balanced_five_field_body_continues_error_based_field_by_field():
    """Review blocker: E over five fields (about 1,100 s) does not fit 900 s; E on one does."""
    fields = ("a", "b", "c", "d", "e")
    settled = [f"{technique}:{name}" for technique in "UB" for name in fields]
    resume = resume_plan(
        settled, {}, fields=fields, field_count=5, rate_samples=[("U:a", 1.5), ("B:a", 1.5)],
        round_wall_ceiling=900,
    )
    assert (resume.technique, resume.field_name) == ("E", "a")
    assert resume.wall_seconds == 236  # 144 requests at 1.5 s, plus one stage minimum
    assert not resume.budget_inconclusive and not resume.probe


def test_fast_two_field_login_runs_error_based_and_judges_time_based_by_itself():
    """Review blockers: Fast's 375 s share; the login form at 2 s per request."""
    fields = ("username", "password")
    settled = [f"{technique}:{name}" for technique in "UB" for name in fields]
    # One sample: E on one field (308 s) fits and runs as normal work. Time-based (398 s on
    # one field) is above the share on that single sample: not a verdict, and not a probe of
    # E either -- it is judged when it is next.
    error = resume_plan(
        settled, {}, fields=fields, rate_samples=[("U:username", 2.0)], round_wall_ceiling=375,
    )
    assert (error.technique, error.field_name, error.wall_seconds) == ("E", "username", 308)
    assert not error.probe and not error.budget_inconclusive and error.unfundable == ()
    assert error.unconfirmed
    # Two samples, judged by their minimum, confirm time-based above the share: only time-based
    # is inconclusive for budget; error-based still runs and concludes normally.
    samples = [("U:username", 2.0), ("B:username", 2.0)]
    confirmed = resume_plan(settled, {}, fields=fields, rate_samples=samples, round_wall_ceiling=375)
    assert confirmed.unfundable == ("T",) and not confirmed.budget_inconclusive
    assert (confirmed.technique, confirmed.wall_seconds) == ("E", 308)
    # With E settled too, nothing fundable is left: the candidate is closed.
    closed = resume_plan(
        settled + [f"E:{name}" for name in fields], {}, fields=fields, rate_samples=samples,
        round_wall_ceiling=375,
    )
    assert closed.budget_inconclusive and closed.wall_seconds is None
    assert closed.unfundable == ("T",)
    # The same candidate is fully fundable on Balanced and Thorough.
    for ceiling in (900, 2_700):
        fits = resume_plan(settled, {}, fields=fields, rate_samples=samples, round_wall_ceiling=ceiling)
        assert fits.wall_seconds == 308 and fits.unfundable == () and not fits.probe


def test_a_technique_above_the_scan_share_is_inconclusive_while_the_others_run():
    """Review blocker 2: a technique whose remaining units need more than the candidate's fair
    part of the Scan's residual is not funded, even though each unit fits a round."""
    fields = ("a", "b", "c", "d")
    samples = [("U:a", 5.3), ("U:b", 5.3)]
    settled = ["U:a", "U:b", "U:c", "U:d"]
    # B costs 481 s per field at 5.3 s: one unit fits Balanced's 900 s share. Its four fields
    # (1,924 s) do not fit a 1,500 s part of the residual, so B is inconclusive; E and T are too.
    shared = resume_plan(
        settled, {}, fields=fields, rate_samples=samples, round_wall_ceiling=900,
        scan_wall_share=1_500,
    )
    assert shared.unfundable == ("B", "E", "T") and shared.budget_inconclusive
    # With the residual to itself (no share named) B is funded unit by unit: a late-field
    # boolean injection is still reached.
    alone = resume_plan(settled, {}, fields=fields, rate_samples=samples, round_wall_ceiling=900)
    assert (alone.technique, alone.field_name, alone.wall_seconds) == ("B", "a", 482)
    assert alone.unfundable == ("T",)  # 189 requests at 5.3 s exceed the 900 s share


def test_thorough_funds_what_balanced_cannot_for_the_slow_chat_candidate():
    # Fixture: the 8-field chat candidate at 13.1 s per request, union-based settled.
    fields = tuple(f"field{index}" for index in range(8))
    settled = [f"U:{name}" for name in fields]
    samples = [("U:field0", 13.1), ("U:field1", 13.1)]
    balanced = resume_plan(
        settled, {}, fields=fields, rate_samples=samples, round_wall_ceiling=900,
    )
    # Boolean (1,160 s per field), error- and time-based all exceed Balanced's share: closed.
    assert balanced.budget_inconclusive and balanced.unfundable == ("B", "E", "T")
    thorough = resume_plan(
        settled, {}, fields=fields, rate_samples=samples, round_wall_ceiling=2_700,
    )
    assert (thorough.technique, thorough.field_name, thorough.wall_seconds) == ("B", "field0", 1_160)
    assert thorough.unfundable == ()


def test_one_slow_run_is_re_measured_before_any_verdict():
    """Review blocker: a single run at sqlmap's 8 s timeout must not decide the candidate."""
    fields = ("a", "b", "c")
    first = resume_plan(
        ["U:a", "U:b", "U:c", "B:a", "B:b", "B:c"], {}, fields=fields,
        rate_samples=[("B:a", 8.0)], round_wall_ceiling=900,
    )
    # E on one field at 8 s is 1,172 s: one probe, not a verdict. The probe holds just enough
    # for a second rate sample (10 requests, half again, at 8 s, plus one stage minimum).
    assert first.probe and first.wall_seconds == 140 and first.unfundable == ()
    # The probe measured the true 1 s per request: E on one field fits at 164 s.
    second = resume_plan(
        ["U:a", "U:b", "U:c", "B:a", "B:b", "B:c"], {}, fields=fields,
        rate_samples=[("B:a", 8.0), ("B:b", 1.0)], round_wall_ceiling=900,
    )
    assert second.wall_seconds == 164 and not second.probe and second.unfundable == ()
    # A unit already killed at the share needs no probe: its own kill is the second
    # measurement, so union-based is inconclusive -- and the next technique is judged on its own.
    killed = resume_plan(
        [], {"U": 900}, rate_samples=[("U", 20.0)], killed_sent={"U": 45},
        round_wall_ceiling=900,
    )
    assert killed.unfundable == ("U",)
    assert (killed.technique, killed.probe) == ("B", True)
    # Too few requests to measure anything: only the killed-wall floor applies.
    unmeasured = resume_plan([], {"U": 20}, rate_samples=[], round_wall_ceiling=900)
    assert unmeasured.wall_seconds == 20 + MINIMUM_STAGE_WALL_SECONDS
    assert unmeasured.unfundable == ()


def test_the_guard_counts_one_field_per_run_before_starting_it():
    # Fixture: the login form at 1 s per request in a 420 s hold. U and B settle on both fields;
    # error-based on one field (144 requests) does not fit the 140 s left, so it is not started
    # to be killed part-way, and the wall returns to the slice.
    calls = []

    async def run_stage(technique, budget, _latency, field_name=None):
        calls.append((technique, field_name))
        need = NEGATIVE[technique]
        return SimpleNamespace(
            status="success", timed_out=False, errors=(), observations=(),
            actual_budget={"http_requests": need, "tool_wall_seconds": need},
        )

    async def checkpoint(_item):
        return None

    fields = ("username", "password")
    outcome = asyncio.run(run_staged_sqli_attempt(
        candidate_attempt_id="c" * 64, candidate_id="login", budget={
            "http_requests": 800, "state_changing_requests": 800, "tool_wall_seconds": 420,
        },
        prior=prior_stages((), "c" * 64, fields=fields), own_action_id="verify.sqli.r02",
        run_stage=run_stage, checkpoint=checkpoint, cancelled=lambda: False,
        fields=fields, round_wall_ceiling=900,
    ))
    assert calls == [
        ("U", "username"), ("U", "password"), ("B", "username"), ("B", "password"),
    ]
    assert outcome.stages[-1] == {"technique": "E", "field": "username", "outcome": "wall_exhausted"}
    assert outcome.actual_budget["tool_wall_seconds"] == 280
    assert (outcome.resume_technique, outcome.resume_field) == ("E", "username")
    assert outcome.resume_wall_seconds == 164
    # Each unit's checkpoint is its own, so a later round carries exactly what settled.
    prior = prior_stages(
        (("verify.sqli.r02", tuple(
            {"attempt_id": stage_attempt_id("c" * 64, f"{technique}:{name}"),
             "status": "success",
             "budget_consumed": {"http_requests": NEGATIVE[technique],
                                 "tool_wall_seconds": NEGATIVE[technique]},
             "observations": ({"kind": "sqli_technique_stage", "technique": technique,
                               "field": name, "delay_ms": 0},)}
            for technique in "UB" for name in fields
        )),), "c" * 64, fields=fields,
    )
    assert set(prior.finished) == {"U:username", "U:password", "B:username", "B:password"}
    assert prior.seconds_per_request == 1.0


def test_a_cancelled_attempt_is_never_inconclusive_for_budget():
    verdict = action_adapter_module._budget_verdict(
        SimpleNamespace(
            status="cancelled", budget_inconclusive=True, resume_technique="U",
            resume_field=None, resume_wall_seconds=5_000, settled_units=(), field_count=1,
            seconds_per_request=20.0,
        ),
        candidate_id="c", ceiling=900, fields=None,
    )
    assert verdict is None


def test_the_field_count_is_what_sqlmap_is_handed_after_leaf_deduplication():
    # A nested JSON body offers each field under its leaf name; duplicates are one -p entry.
    fields, count = action_adapter_module._sqli_fields(
        "https://app.example.test/api", {
            "method": "POST", "content_type": "application/json",
            "body_field_names": ["user.name", "admin.name", "message"],
            "injection_field": "message",
        },
    )
    assert fields == ("name", "message") and count == 2
    # A query candidate is the URL with its own parameter.
    assert action_adapter_module._sqli_fields("https://app.example.test/s?q=1", {}) == (None, 1)


# Fixture endpoints: seconds per request and tested body fields.
# Fixture: per-run slowdown factors of endpoints whose rate drifts upward.
DRIFT: dict[str, float] = {}

ENDPOINTS = {
    "/s0": (13.1, 8), "/s1": (5.3, 4), "/s2": (8.0, 2), "/s3": (6.0, 3),
    "/s4": (4.0, 1), "/s5": (10.0, 5), "/s6": (3.5, 2), "/s7": (7.0, 1),
    "/vuln": (5.3, 4),
    "/fast5": (0.08, 5),
    "/slow8": (8.0, 2),
    "/mid": (2.0, 3),
    "/slow10": (10.0, 5),
    "/stall": (150.0, 1),
    "/chat": (13.1, 8),
    "/copilot": (5.3, 4),
    "/slow": (20.0, 1),
    "/login": (0.6, 2),
    "/fastlogin": (2.0, 2),
}


class _Scan:
    """A Scan's SQLi slices run round by round against one checkpoint store."""

    def __init__(self, monkeypatch, paths, *, profile_wall=BALANCED_WALL, vuln=(), earlier=0):
        self.vuln = set(vuln)  # (path, technique, field) a fixture injection answers on
        self.found: set[tuple[str, str, str]] = set()
        # Tool wall the Scan spent outside these lanes (discovery, templates, exposure).
        self.earlier = earlier
        # Fixture: tool wall the round's compile will need for first slices of new candidates.
        self.pending_new_work: list[tuple[str, int]] = []
        self.scan_id = str(uuid.uuid4())
        self.profile = {**BALANCED, "tool_wall_seconds": profile_wall}
        self.execution_plan = _plan(profile_wall)
        self.endpoints = build_endpoint_manifest(
            scan_id=self.scan_id, target_binding_digest=TARGET.digest,
            surface_manifest={
                "schema_version": "endpoint-manifest/v2", "status": "complete", "reason": None,
                "endpoints": [
                    {
                        "method": "POST", "scheme": "https", "host": "app.example.test",
                        "port": 443, "normalized_path": path, "concrete_path": path,
                        "query_keys": [], "content_type": "application/x-www-form-urlencoded",
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
        # Each slice here holds the endpoint's first candidate.
        self.order = [str(entry["canonical_path"]) for entry in self.candidates.entries]
        self.backend = Backend(manifests={
            self.endpoints.manifest_id: self.endpoints,
            self.candidates.manifest_id: self.candidates,
        })
        self.actions: list = []
        self.receipts: dict = {}
        self.results: dict = {}
        self.calls: list[tuple[str, str, tuple[str, ...], int]] = []
        scan = self

        async def execute(_executor, context, adapter, **_kwargs):
            return scan._execute(context, adapter)

        monkeypatch.setattr(action_adapter_module.CapabilityExecutor, "execute", execute)

    def _execute(self, context, adapter):
        payload = adapter._process_payload
        path = payload["execution_target"].split("app.example.test", 1)[1].split("?")[0]
        options = payload["scanner_options"]
        technique = options["technique"]
        tested = tuple(options.get("injection_fields") or options["body_field_names"])
        wall = int(context.requested_budget["tool_wall_seconds"])
        self.calls.append((path, technique, tested, wall))
        rate, _fields = ENDPOINTS[path]
        # Fixture drift: some endpoints answer slower with every run (a loaded target).
        runs = sum(1 for call in self.calls if call[0] == path) - 1
        rate *= DRIFT.get(path, 1.0) ** runs
        hit = [item for item in tested if (path, technique, item) in self.vuln]
        if hit:
            # sqlmap tests the fields in order and stops at the vulnerable one: the fields
            # before it cost a full negative, the injection about 30 requests.
            requests = NEGATIVE[technique] * tested.index(hit[0]) + 30
            if requests * rate <= wall:
                self.found.add((path, technique, hit[0]))
                return CapabilityAdapterResult(
                    status="success",
                    actual_budget={"http_requests": requests, "tool_wall_seconds": int(requests * rate)},
                    observations=({"kind": "sqli_finding", "param": hit[0],
                                   "proof_state": "candidate"},),
                    execution_started=True, parser_version="sqlmap-output/v1",
                )
        need = NEGATIVE[technique] * len(tested)
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

    def add(self, action_id, *, path, budget, extends=None, share=None, last_chance=None):
        args = {
            "candidate_manifest_ref": self.candidates.reference().canonical_dict(),
            "endpoint_manifest_ref": self.endpoints.reference().canonical_dict(),
            "slice": {"start": self.order.index(path), "count": 1},
            "profile": "balanced_batch_v1", "proof_policy": "deterministic_differential_required",
            **({EXTENDS_ARG: extends} if extends else {}),
            **({SCAN_WALL_SHARE_ARG: share} if share else {}),
            **({LAST_CHANCE_ARG: True} if last_chance else {}),
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
            options={"scan_execution_plan": self.execution_plan},
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

    def residual(self):
        left = {
            name: self.profile[name] - sum(
                int(result.budget_consumed.get(name, 0)) for result in self.results.values()
            )
            for name in self.profile
        }
        left["tool_wall_seconds"] -= self.earlier
        return left

    def drive(self, rounds=8):
        """Continue round by round until the planner funds nothing; return the rounds run."""
        ran = []
        for round_number in range(2, 2 + rounds):
            added = self.next_round(round_number)
            if not added:
                break
            self.run({action_id for action_id, _ in added})
            ran.append(added)
        return ran

    def sqli_wall(self):
        return sum(
            int(result.budget_consumed.get("tool_wall_seconds", 0))
            for action_id, result in self.results.items() if action_id.startswith("verify.sqli")
        )

    def outcomes(self):
        """The finalizer's budget outcome for every SQLi candidate (sqli_budget_outcomes)."""
        rows = [
            item for action in self.actions if action.action_id in self.receipts
            for item in self.receipts[action.action_id].observations
        ]
        return {item["candidate_id"]: item for item in sqli_budget_outcomes(rows)}

    def candidate(self, path):
        return self.candidates.entries[self.order.index(path)]["candidate_id"]

    def settled(self, path):
        candidate = self.candidate(path)
        return {
            (item["technique"], item.get("field"))
            for receipt in self.receipts.values() for item in receipt.observations
            if item.get("kind") == "sqli_technique_stage" and item.get("candidate_id") == candidate
            and item.get("status") == "success" and not item.get("carried_from")
        }

    def plan_extensions(self):
        """Plan the next round exactly as ``compile_continuation_round`` does."""
        plan = self.plan()
        observations = {
            action_id: tuple(self.receipts[action_id].observations)
            for action_id in resume_observation_action_ids(plan, self.results)
            if action_id in self.receipts
        }
        return plan_verification_extensions(
            parent_plan=plan, parent_results=self.results, profile_limits=self.profile,
            residual=self.residual(), stage_resume_walls=stage_resume_walls(observations),
            budget_concluded=budget_concluded_slices(observations),
            stage_remaining_walls=stage_remaining_walls(observations),
            stage_remaining_requests=stage_remaining_walls(observations, key="remaining_requests"),
            stage_last_chance_walls=stage_last_chance_walls(observations),
            reserved_for_new_work=self.pending_new_work,
        )

    def next_round(self, round_number):
        planned = self.plan_extensions()
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
                share=spec["capability_args"].get(SCAN_WALL_SHARE_ARG),
                last_chance=spec["capability_args"].get(LAST_CHANCE_ARG),
            )
            added.append((action_id, int(spec["budget"]["tool_wall_seconds"])))
        return added

    def records(self, action_id, kind):
        return [
            item for item in self.receipts[action_id].observations if item.get("kind") == kind
        ]


# The body slice 9de6a910 planned for each chat candidate.
SLICE = {"http_requests": 800, "state_changing_requests": 480, "tool_wall_seconds": 420}
# A slice whose request hold is large enough that the slice spends under half of it, as the
# soak's login slice did (364 of 800): latency-starved, eligible to extend.
WIDE_SLICE = {"http_requests": 1_200, "state_changing_requests": 600, "tool_wall_seconds": 420}


def test_a_slice_that_settled_nothing_is_continued_once_then_given_a_verdict(monkeypatch):
    """Regression for N55: verify.sqli.r01 settled nothing and was extended again and again."""
    scan = _Scan(monkeypatch, ("/chat", "/copilot"))
    scan.add("verify.sqli.r01", path="/chat", budget=SLICE)
    scan.add("verify.sqli.001.r01", path="/copilot", budget=SLICE)
    scan.run({"verify.sqli.r01", "verify.sqli.001.r01"})
    # Union-based on the chat's first field needs 53 requests at 13.1 s: the slice is killed.
    # The copilot settles union-based on its first field (281 s) -- progress a whole-body run
    # never checkpointed -- and yields the rest of its slice.
    assert [
        (path, technique, tested) for path, technique, tested, _ in scan.calls
    ] == [("/chat", "U", ("field0",)), ("/copilot", "U", ("field0",))]
    [chat] = scan.records("verify.sqli.r01", "candidate_attempt")
    assert (chat["resume_technique"], chat["resume_field"]) == ("U", "field0")
    assert chat["field_count"] == 8 and chat["resume_wall_seconds"] == 716
    # One rate sample: boolean-based (1,160 s per field) over the share is not yet judged.
    assert chat["resume_unconfirmed"] is True and "verdict" not in chat

    # Control: the floor the 2.8.0 planner read -- the killed wall plus one stage minimum --
    # granted two 450 s extensions the wall killed again, settling nothing.
    old = plan_verification_extensions(
        parent_plan=scan.plan(), parent_results=scan.results, profile_limits=scan.profile,
        residual=scan.residual(),
        stage_resume_walls={
            "verify.sqli.r01": 420 + MINIMUM_STAGE_WALL_SECONDS,
            "verify.sqli.001.r01": 420 + MINIMUM_STAGE_WALL_SECONDS,
        },
    )
    assert [item["budget"]["tool_wall_seconds"] for item in old] == [450, 450]

    # Now the chat's next unit is funded once, at what it needs; its second measurement shows
    # union-based over eight fields (5,700 s) cannot fit its part of the residual, and the
    # other techniques cannot fit a round: closed, inconclusive for budget, never funded again.
    second = scan.next_round(2)
    assert second == [("verify.sqli.r01.ext.r02", 716)]
    scan.run({second[0][0]})
    [chat_verdict] = scan.records("verify.sqli.r01.ext.r02", INCONCLUSIVE_RECORD_KIND)
    assert chat_verdict["unfundable_techniques"] == ["U", "B", "E", "T"]
    assert chat_verdict["closed"] is True
    assert chat_verdict["settled_units"] == ["U:field0"]
    assert scan.results["verify.sqli.r01.ext.r02"].reason_code.value == "insufficient_plan_budget"
    rounds = scan.drive()
    assert all(
        not action_id.startswith("verify.sqli.r01.") for added in rounds for action_id, _ in added
    )


def test_a_unit_no_round_can_fund_is_probed_once_then_inconclusive(monkeypatch):
    # Fixture: one tested field at 20 s per request; union-based needs 1,080 s, above 900 s.
    scan = _Scan(monkeypatch, ("/slow",))
    scan.add("verify.sqli.r01", path="/slow", budget=SLICE)
    scan.run({"verify.sqli.r01"})
    [first] = scan.records("verify.sqli.r01", "candidate_attempt")
    # One measurement: no verdict yet, but one probe with the least hold above the 420 s the
    # unit was killed at.
    assert first.get("resume_probe") is True and "verdict" not in first
    assert first["resume_wall_seconds"] == 440
    assert scan.records("verify.sqli.r01", INCONCLUSIVE_RECORD_KIND) == []
    probe = scan.next_round(2)
    assert probe == [("verify.sqli.r01.ext.r02", 440)]
    scan.run({probe[0][0]})
    # The probe was killed again: two measurements agree, so every technique is inconclusive
    # for budget and no further continuation is granted.
    [attempt] = scan.records(probe[0][0], "candidate_attempt")
    assert attempt["verdict"] == "inconclusive" and attempt["inconclusive_reason"] == "budget"
    [verdict] = scan.records(probe[0][0], INCONCLUSIVE_RECORD_KIND)
    assert verdict["reason"] == "verdict_exceeds_budget"
    assert verdict["unfundable_techniques"] == ["U", "B", "E", "T"]
    assert verdict["refuted_techniques"] == [] and verdict["closed"] is True
    assert verdict["round_wall_ceiling_seconds"] == 900
    assert verdict["url"].startswith("https://app.example.test/")
    assert scan.next_round(3) == []


def test_the_balanced_login_form_concludes_in_the_next_round(monkeypatch):
    scan = _Scan(monkeypatch, ("/login",))
    scan.add("verify.sqli.r02", path="/login", budget=WIDE_SLICE)
    scan.run({"verify.sqli.r02"})
    ran = [(technique, tested[0]) for _, technique, tested, _ in scan.calls]
    # U, B and E settle field by field; time-based on one field (113 s) does not fit what is
    # left, so the slice yields that wall instead of starting a run the wall would kill.
    assert ran == [(t, f) for t in "UBE" for f in ("field0", "field1")]
    [attempt] = scan.records("verify.sqli.r02", "candidate_attempt")
    assert (attempt["resume_technique"], attempt["resume_field"]) == ("T", "field0")
    assert "verdict" not in attempt
    assert scan.receipts["verify.sqli.r02"].budget_consumed["tool_wall_seconds"] < 420

    second = scan.next_round(2)
    assert [action_id for action_id, _ in second] == ["verify.sqli.r02.ext.r02"]
    before = len(scan.calls)
    scan.run({second[0][0]})
    assert [(technique, tested[0]) for _, technique, tested, _ in scan.calls[before:]] == [
        ("T", "field0"), ("T", "field1"),
    ]
    assert scan.results[second[0][0]].status.value == "success"
    assert scan.next_round(3) == []


def test_the_fast_login_form_refutes_three_techniques_and_judges_time_based_alone(monkeypatch):
    """Review blockers, Fast (375 s share): the login form at 2 s per request.

    A whole-body run never got past boolean-based. Field by field, one unit at a time, every
    unit that fits Fast's share runs: union-, boolean- and error-based are refuted on both
    fields, and only time-based (398 s on one field) is inconclusive for budget.
    """
    scan = _Scan(monkeypatch, ("/fastlogin",), profile_wall=FAST)
    scan.add("verify.sqli.r01", path="/fastlogin", budget=WIDE_SLICE)
    scan.run({"verify.sqli.r01"})
    assert [(technique, tested[0]) for _, technique, tested, _ in scan.calls] == [
        ("U", "field0"), ("U", "field1"), ("B", "field0"),
    ]
    rounds = scan.drive()
    # The last extension is E on field 1's 308 s with the cap's 20% of slack.
    assert [wall for added in rounds for _, wall in added] == [375, 375, 370]
    assert scan.settled("/fastlogin") == {(t, f) for t in "UBE" for f in ("field0", "field1")}
    [verdict] = scan.records(rounds[-1][0][0], INCONCLUSIVE_RECORD_KIND)
    assert verdict["unfundable_techniques"] == ["T"] and verdict["closed"] is True
    assert verdict["refuted_techniques"] == ["U", "B", "E"]
    assert verdict["round_wall_ceiling_seconds"] == 375


def test_a_late_field_boolean_injection_at_5_3_s_is_found_on_balanced(monkeypatch):
    """Review blocker 1: boolean-based on a 4-field body at 5.3 s per request (481 s per field)
    fits Balanced's share; it used to be skipped once time-based was over the share."""
    scan = _Scan(monkeypatch, ("/vuln",), vuln={("/vuln", "B", "field3")}, earlier=540)
    scan.add("verify.sqli.r01", path="/vuln", budget=SLICE)
    scan.run({"verify.sqli.r01"})
    scan.drive()
    assert scan.found == {("/vuln", "B", "field3")}
    assert scan.settled("/vuln") >= {("U", f) for f in ("field0", "field1", "field2", "field3")}


def test_error_based_on_a_middle_field_is_found_or_the_residual_is_used(monkeypatch):
    """Review blocker 1, single candidate: error-based on field 2 at 5.3 s per request."""
    for rate, expect_found in ((2.5, True), (5.3, False)):
        ENDPOINTS["/vuln"] = (rate, 4)
        scan = _Scan(monkeypatch, ("/vuln",), vuln={("/vuln", "E", "field2")}, earlier=540)
        scan.add("verify.sqli.r01", path="/vuln", budget=SLICE)
        scan.run({"verify.sqli.r01"})
        scan.drive()
        if expect_found:
            assert scan.found == {("/vuln", "E", "field2")}
            continue
        # At 5.3 s the injection lies beyond what Balanced can fund (U and B over four fields
        # alone need 3,048 s): the candidate uses the residual unit by unit until the next one
        # no longer fits, rather than stopping early.
        [record] = [
            item for item in scan.receipts[scan.actions[-1].action_id].observations
            if item.get("kind") == "candidate_attempt"
        ]
        assert scan.residual()["tool_wall_seconds"] < record["resume_wall_seconds"]
        assert len(scan.settled("/vuln")) >= 7
    ENDPOINTS["/vuln"] = (5.3, 4)


def test_a_thorough_scan_stops_sqli_with_verdicts_before_the_residual_runs_out(monkeypatch):
    """Review blocker 2: Thorough's 2,700 s share fits a unit of almost anything, so only the
    residual check stops an endpoint that would need ~50,000 s."""
    paths = ("/chat", "/copilot", "/slow8", "/mid", "/login", "/slow10")
    scan = _Scan(
        monkeypatch, paths, profile_wall=THOROUGH, vuln={("/mid", "B", "field2")}, earlier=540,
    )
    for index, path in enumerate(paths):
        scan.add(f"verify.sqli.{index:03d}.r01", path=path, budget=WIDE_SLICE)
    scan.run({action.action_id for action in scan.actions})
    scan.drive(rounds=12)
    assert scan.found == {("/mid", "B", "field2")}
    assert scan.settled("/login") == {(t, f) for t in "UBET" for f in ("field0", "field1")}
    outcomes = scan.outcomes()
    for path in ("/chat", "/copilot", "/slow10"):
        assert scan.candidate(path) in outcomes, f"{path} ends with no budget outcome"
    # Every candidate ends proven, refuted, or inconclusive with a reason -- and SQLi stopped
    # with wall left that it could have spent.
    assert scan.residual()["tool_wall_seconds"] > 0
    assert scan.sqli_wall() < THOROUGH - 540


def test_a_fast_body_stopped_by_its_mutation_hold_is_extended_and_concludes(monkeypatch):
    """Review should-fix: a fast 5-field body whose next unit needs more mutations than its
    hold has left stops on the request ceiling -- not as wall-exhausted -- and is extended."""
    for mutations in (600, 1_200):
        ENDPOINTS["/fast5"] = (0.08, 5)
        scan = _Scan(monkeypatch, ("/fast5",), earlier=540)
        scan.add(
            "verify.sqli.r01", path="/fast5",
            budget={"http_requests": 1_200, "state_changing_requests": mutations, "tool_wall_seconds": 420},
        )
        scan.run({"verify.sqli.r01"})
        if mutations == 600:
            assert scan.results["verify.sqli.r01"].reason_code.value == "http_request_budget_exhausted"
        scan.drive()
        assert scan.settled("/fast5") == {(t, f"field{i}") for t in "UBET" for i in range(5)}


class _HoneyScan(_Scan):
    """The 9de6a910 shape, round by round: SQLi slices run; XSS slices are settled fixtures."""

    # Fixture: what discovery, baseline, templates and the exposure batch consumed outside
    # the verifier lanes (9de6a910 started its first SQLi slice 679 s in, 218 s of that in its
    # two XSS slices, and its exposure batch took 76 s).
    EARLIER_TOOL_WALL = 540

    def __init__(self, monkeypatch):
        super().__init__(monkeypatch, ("/chat", "/copilot", "/login"))
        self.xss_funded: list[tuple[str, int]] = []

    def residual(self):
        left = super().residual()
        left["tool_wall_seconds"] -= self.EARLIER_TOOL_WALL
        return left

    def add_xss(self, action_id, *, extends=None, budget, consumed, status):
        args = {
            "candidate_manifest_ref": self.candidates.reference().canonical_dict(),
            "endpoint_manifest_ref": self.endpoints.reference().canonical_dict(),
            "slice": {"start": self.order.index("/login"), "count": 1},
            "profile": "balanced_batch_v1",
            "proof_policy": "deterministic_proof_contract_required",
            **({EXTENDS_ARG: extends} if extends else {}),
        }
        self.actions.append(dataclasses.replace(
            _action(action_id, "xss.verify_batch", len(self.actions), capability_args=args),
            requested_budget=dict(budget), action_digest=None,
        ))
        self.results[action_id] = SimpleNamespace(
            status=SimpleNamespace(value=status), reason_code=None,
            budget_reserved=dict(budget), budget_consumed=dict(consumed),
        )

    def next_round(self, round_number):
        planned = self.plan_extensions()
        sqli = []
        for spec in planned:
            action_id = f"{spec['action_id']}.r{round_number:02d}"
            budget = dict(spec["budget"])
            if spec["capability_name"] == "xss.verify_batch":
                # Fixture: the extension finishes Dalfox on the form inside its hold.
                self.add_xss(
                    action_id, extends=spec["capability_args"][EXTENDS_ARG], budget=budget,
                    consumed={**budget, "tool_wall_seconds": budget["tool_wall_seconds"] // 2},
                    status="success",
                )
                self.xss_funded.append((action_id, int(budget["tool_wall_seconds"])))
                continue
            original = next(
                item for item in self.actions
                if item.action_id == spec["capability_args"][EXTENDS_ARG]
            )
            self.add(
                action_id, path=self.order[original.capability_args["slice"]["start"]],
                budget=budget, extends=spec["capability_args"][EXTENDS_ARG],
                share=spec["capability_args"].get(SCAN_WALL_SHARE_ARG),
                last_chance=spec["capability_args"].get(LAST_CHANCE_ARG),
            )
            sqli.append(action_id)
        return sqli

    def sqli_wall(self):
        return sum(
            int(self.results[action.action_id].budget_consumed.get("tool_wall_seconds", 0))
            for action in self.actions
            if action.capability_name == "sqli.verify_batch" and action.action_id in self.results
        )

    def verdicts(self, path):
        candidate = self.candidates.entries[self.order.index(path)]["candidate_id"]
        return [
            item for action_id in self.receipts
            for item in self.records(action_id, INCONCLUSIVE_RECORD_KIND)
            if item["candidate_id"] == _batch_candidate(self, candidate)
        ]


def _batch_candidate(scan, manifest_candidate_id):
    # The batch names a candidate by the manifest's candidate id.
    return manifest_candidate_id


def test_the_honey_scan_concludes_and_sqli_does_not_starve_xss(monkeypatch):
    """N55 end to end on 9de6a910's shapes (scripted fixtures, Balanced 3,600 s).

    2.8.0 spent 2,833 s of SQLi on these candidates and concluded nothing. a774b411 still spent
    2,928 s -- the 8-field chat drew a 900 s share in three rounds -- without a budget verdict,
    and SQLi extensions were planned before the form's XSS extension.
    """
    scan = _HoneyScan(monkeypatch)
    # Round 1: one slice per chat candidate, and the login form's XSS slice, wall-killed with
    # its requests mostly unspent (9de6a910: 240 of 700 in 200 s).
    scan.add("verify.sqli.r01", path="/chat", budget=SLICE)
    scan.add("verify.sqli.001.r01", path="/copilot", budget=SLICE)
    scan.add_xss(
        "verify.xss.001.r01",
        budget={"http_requests": 700, "state_changing_requests": 240, "tool_wall_seconds": 200},
        consumed={"http_requests": 240, "state_changing_requests": 240, "tool_wall_seconds": 200},
        status="timed_out",
    )
    scan.run({"verify.sqli.r01", "verify.sqli.001.r01"})
    login = scan.candidates.entries[scan.order.index("/login")]["candidate_id"]

    def login_settled():
        return {
            (item["technique"], item.get("field"))
            for action_id in scan.receipts
            for item in scan.records(action_id, "sqli_technique_stage")
            if item.get("candidate_id") == login and item.get("status") == "success"
        }

    def concluded():
        return (
            login_settled() == {(t, f) for t in "UBET" for f in ("field0", "field1")}
            and all(scan.verdicts(path) for path in ("/chat", "/copilot"))
        )

    concluded_at = None
    for round_number in range(2, 9):
        added = scan.next_round(round_number)
        if round_number == 2:
            # The form's SQLi slice is new work in round 2, as it was on the soak.
            scan.add("verify.sqli.r02", path="/login", budget=WIDE_SLICE)
            added.append("verify.sqli.r02")
        if not added:
            break
        scan.run(set(added))
        if concluded_at is None and concluded():
            concluded_at = (round_number, scan.sqli_wall())

    # XSS on the form is funded in the first continuation round, beside the SQLi work.
    assert scan.xss_funded == [("verify.xss.001.r01.ext.r02", 583)]
    # Both chat candidates end closed with an explicit budget verdict: their union-based units
    # each fit a round, but not their part of the residual beside the form's work, and their
    # other techniques fit no round at 13.1 and 5.3 s per request.
    chat, copilot = scan.verdicts("/chat")[-1], scan.verdicts("/copilot")[-1]
    assert chat["unfundable_techniques"] == ["U", "B", "E", "T"] and chat["closed"] is True
    assert copilot["unfundable_techniques"] == ["U", "B", "E", "T"] and copilot["closed"] is True
    assert scan.settled("/copilot") == {("U", "field0"), ("U", "field1")}
    # The login form's SQLi concludes, and the whole SQLi lane has concluded by round 3, with
    # 331 s of the Scan's wall unspent; the lane spent 2,238 s against 2.8.0's 2,833 s.
    assert concluded_at == (3, 2_238)
    assert scan.sqli_wall() == 2_238
    assert scan.residual()["tool_wall_seconds"] == 331


def test_lane_order_does_not_decide_who_gets_the_residual():
    """SQLi used to be planned first because ``sqli.verify_batch`` sorts before ``xss``."""
    from tests.test_scan_action_adapter import TARGET as target

    def slice_action(action_id, capability, ordinal):
        return dataclasses.replace(
            _action(action_id, capability, ordinal, capability_args={
                "slice": {"start": 0, "count": 1}, "profile": "balanced_batch_v1",
            }),
            action_digest=None,
        )

    def results(sqli_floor_fits_alone):
        return {
            "verify.sqli.r01": SimpleNamespace(
                status=SimpleNamespace(value="timed_out"), reason_code=None,
                budget_reserved={"http_requests": 800, "tool_wall_seconds": 420},
                budget_consumed={"http_requests": 32, "tool_wall_seconds": 420},
            ),
            "verify.xss.r01": SimpleNamespace(
                status=SimpleNamespace(value="timed_out"), reason_code=None,
                budget_reserved={"http_requests": 700, "tool_wall_seconds": 200},
                budget_consumed={"http_requests": 240, "tool_wall_seconds": 200},
            ),
        }

    for order in (("verify.sqli.r01", "verify.xss.r01"), ("verify.xss.r01", "verify.sqli.r01")):
        actions = tuple(
            slice_action(action_id, "sqli.verify_batch" if "sqli" in action_id else "xss.verify_batch", index)
            for index, action_id in enumerate(order)
        )
        plan = ScanActionPlan(
            scan_id=str(uuid.UUID(int=1)), execution_plan_digest="a" * 64,
            target_binding_digest=target.digest, actions=actions,
        )
        planned = plan_verification_extensions(
            parent_plan=plan, parent_results=results(True), profile_limits=BALANCED,
            # 1,000 s left: the SQLi slice alone could take 900 s of it.
            residual={**BALANCED, "tool_wall_seconds": 1_000},
            stage_resume_walls={"verify.sqli.r01": 716},
        )
        walls = {item["capability_name"]: item["budget"]["tool_wall_seconds"] for item in planned}
        # Each lane first holds half of what is left: SQLi's 716 s floor does not fit its half,
        # XSS is funded and then topped up to its latency-sized need from what the first pass
        # left. SQLi no longer drains the residual first, whatever the lanes' order or names.
        assert walls == {"xss.verify_batch": 583}, order


def test_time_based_is_not_predicted_from_union_based_rate():
    samples = [("U:a", 1.0), ("U:b", 1.0), ("B:a", 1.0), ("T:a", 5.0)]
    settled = ["U:a", "U:b", "B:a", "B:b", "E:a", "E:b", "T:a"]
    # T:b has no run of its own: it is predicted from time-based's own rate, not union's.
    plan = resume_plan(settled, {}, fields=("a", "b"), rate_samples=samples, round_wall_ceiling=2_700)
    assert (plan.technique, plan.field_name) == ("T", "b")
    assert plan.seconds_per_request == 5.0 and plan.wall_seconds == 965
    # Without any time-based run, all of the candidate's runs are the fallback.
    early = resume_plan(["U:a", "U:b"], {}, fields=("a", "b"), rate_samples=samples[:2])
    assert early.seconds_per_request == 1.0


def test_a_candidate_with_no_rate_is_deferred_before_any_traffic(monkeypatch):
    # Fixture: a stalled endpoint, 150 s per request -- U is killed after 2 requests, too few to
    # measure a rate, so only the killed-wall floor applies and no verdict is given.
    scan = _Scan(monkeypatch, ("/stall",))
    scan.add("verify.sqli.r01", path="/stall", budget=SLICE)
    scan.run({"verify.sqli.r01"})
    [first] = scan.records("verify.sqli.r01", "candidate_attempt")
    assert "seconds_per_request_ms" not in first and "verdict" not in first
    assert first["resume_wall_seconds"] == 440
    # An extension held at exactly the killed wall is refused before any traffic.
    scan.add(
        "verify.sqli.r01.ext.r02", path="/stall", extends="verify.sqli.r01",
        budget={**SLICE, "tool_wall_seconds": 420},
    )
    before = len(scan.calls)
    scan.run({"verify.sqli.r01.ext.r02"})
    assert scan.calls[before:] == []
    [deferred] = scan.records("verify.sqli.r01.ext.r02", "candidate_deferred")
    assert (deferred["reason"], deferred["resume_wall_seconds"]) == ("stage_wall_unfunded", 440)
    assert "verdict" not in deferred
    assert scan.receipts["verify.sqli.r01.ext.r02"].budget_consumed.get("http_requests", 0) == 0
    assert scan.records("verify.sqli.r01.ext.r02", INCONCLUSIVE_RECORD_KIND) == []


def test_a_field_name_with_a_comma_is_never_a_unit_of_its_own():
    # sqlmap splits -p on commas, so such a name cannot be addressed alone; the other fields
    # are still verified one per run.
    fields, count = action_adapter_module._sqli_fields(
        "https://app.example.test/login", {
            "method": "POST", "content_type": "application/x-www-form-urlencoded",
            "body_field_names": ["user", "a,b", "pass"], "injection_field": "user",
        },
    )
    assert fields == ("user", "pass") and count == 2


def test_extension_caps_have_slack_for_a_mispredicted_rate(monkeypatch):
    """Follow-up 2: an extension capped at exactly the predicted wall of the units left is cut
    short by a target that answers slightly slower each run, and the remainder costs another of
    the Scan's eight continuation rounds."""
    import scan.verification_extension as extension_module

    def rounds_needed(slack):
        if not slack:
            monkeypatch.setattr(extension_module, "_with_slack", lambda wall: int(wall))
        ENDPOINTS["/drift"] = (1.0, 2)
        DRIFT["/drift"] = 1.04  # fixture: 4% slower each run
        try:
            scan = _Scan(monkeypatch, ("/drift",), earlier=540)
            scan.add("verify.sqli.r01", path="/drift", budget=SLICE)
            scan.run({"verify.sqli.r01"})
            rounds = scan.drive()
            assert scan.settled("/drift") == {(t, f) for t in "UBET" for f in ("field0", "field1")}
            return [[wall for _, wall in added] for added in rounds]
        finally:
            DRIFT.clear()
            monkeypatch.undo()

    # Control: without slack the 746 s cap leaves the last time-based unit for a 2nd round.
    assert rounds_needed(False) == [[746], [260]]
    assert rounds_needed(True) == [[854]]


def test_a_slice_sized_for_its_units_is_extended_although_it_spent_most_requests(monkeypatch):
    """Follow-up 2 (found while measuring the slack): an extension's request holds are sized
    for its remaining units, so spending most of them is no sign it was not starved of wall.
    Refusing it abandoned the candidate one unit short with most of the residual left."""
    ENDPOINTS["/drift"] = (1.0, 2)
    DRIFT["/drift"] = 1.05
    try:
        scan = _Scan(monkeypatch, ("/drift",), earlier=540)
        scan.add("verify.sqli.r01", path="/drift", budget=SLICE)
        scan.run({"verify.sqli.r01"})
        scan.drive()
        assert scan.settled("/drift") == {(t, f) for t in "UBET" for f in ("field0", "field1")}
        assert scan.outcomes() == {}
    finally:
        DRIFT.clear()


def test_the_scans_last_wall_runs_a_unit_that_can_still_prove_an_injection(monkeypatch):
    """Follow-up 1: the 4.0 s late-field boolean injection. With 257 s left, boolean-based on
    field 3 cannot reach its negative verdict (368 s), but its positive needs about 120 s."""
    import scan.verification_extension as extension_module

    def run(last_chance):
        ENDPOINTS["/vuln"] = (4.0, 4)
        try:
            # Fixture: the residual 9de6a910's other families left (earlier work, both XSS
            # slices), with the 13.1 s chat candidate beside the form.
            scan = _Scan(
                monkeypatch, ("/vuln", "/chat"), vuln={("/vuln", "B", "field3")}, earlier=1_031,
            )
            if not last_chance:
                monkeypatch.setattr(
                    sys.modules[__name__], "stage_last_chance_walls", lambda _observations: {},
                )
            scan.add("verify.sqli.r01", path="/vuln", budget=SLICE)
            scan.add("verify.sqli.001.r01", path="/chat", budget=SLICE)
            scan.run({"verify.sqli.r01", "verify.sqli.001.r01"})
            rounds = scan.drive()
            return scan, rounds
        finally:
            ENDPOINTS["/vuln"] = (5.3, 4)

    control, _control_rounds = run(False)
    assert control.found == set() and control.residual()["tool_wall_seconds"] == 257
    monkeypatch.undo()
    scan, rounds = run(True)
    assert [[wall for _, wall in added] for added in rounds] == [[900], [900], [604], [256]]
    last = scan.actions[-1]
    assert last.capability_args[extension_module.LAST_CHANCE_ARG] is True
    assert scan.found == {("/vuln", "B", "field3")}
    assert scan.residual()["tool_wall_seconds"] == 137
    # Not a last chance while the residual can still fund the unit's negative verdict.
    assert all(
        not action.capability_args.get(extension_module.LAST_CHANCE_ARG)
        for action in scan.actions[:-1]
    )


def test_a_candidate_still_waiting_at_scan_end_says_what_it_did_not_reach(monkeypatch):
    """Follow-up 3: a candidate with techniques judged unfundable but others still fundable when
    the Scan's budget ran out is not "inconclusive for E and T" alone -- that reads as if U and
    B were refuted. It reports the exhausted budget, the unit it would have run next, and which
    techniques were refuted, judged unfundable, or simply not reached."""
    ENDPOINTS["/vuln"] = (8.0, 4)
    try:
        scan = _Scan(
            monkeypatch, ("/vuln", "/chat"), vuln={("/vuln", "B", "field3")}, earlier=1_031,
        )
        scan.add("verify.sqli.r01", path="/vuln", budget=SLICE)
        scan.add("verify.sqli.001.r01", path="/chat", budget=SLICE)
        scan.run({"verify.sqli.r01", "verify.sqli.001.r01"})
        scan.drive()
    finally:
        ENDPOINTS["/vuln"] = (5.3, 4)
    outcome = scan.outcomes()[scan.candidate("/vuln")]
    assert {key: outcome[key] for key in (
        "reason", "refuted_techniques", "inconclusive_techniques", "unfinished_techniques",
        "closed", "next_technique", "next_field",
    )} == {
        "reason": "scan_budget_exhausted",
        "refuted_techniques": ["U"],
        "inconclusive_techniques": ["E", "T"],
        "unfinished_techniques": ["B"],
        "closed": False,
        "next_technique": "B",
        "next_field": "field0",
    }
    chat = scan.outcomes()[scan.candidate("/chat")]
    assert chat["reason"] == "scan_budget_exhausted"
    assert chat["refuted_techniques"] == [] and chat["unfinished_techniques"] == ["U", "B", "E", "T"]


def test_unsliced_candidates_get_a_first_slice_before_probes_and_lost_causes(monkeypatch):
    """Follow-up 4: eight slow candidates on Balanced. Extensions are planned before the
    round's compile adds first slices, so probes of candidates that will most likely be
    inconclusive took the residual and the later candidates were never tested at all."""
    paths = tuple(f"/s{index}" for index in range(8))

    def run(reserve):
        scan = _Scan(monkeypatch, paths, earlier=540)
        queue = list(paths)
        hold = {"http_requests": 1_200, "state_changing_requests": 600, "tool_wall_seconds": 420}
        sliced = []

        def first_slices():
            # Fixture: the round's compile, which adds up to two first slices from what the
            # extensions left (``compile_continuation_round``).
            added = []
            while queue and len(added) < 2 and (
                scan.residual()["tool_wall_seconds"] - 420 * (len(added) + 1) > 0
            ):
                path = queue.pop(0)
                action_id = f"verify.sqli.{len(sliced):03d}.r01"
                scan.add(action_id, path=path, budget=hold)
                sliced.append(path)
                added.append(action_id)
            return added

        scan.run(set(first_slices()))
        for round_number in range(2, 10):
            scan.pending_new_work = [("verify.sqli", 420)] * len(queue) if reserve else []
            extensions = [action_id for action_id, _ in scan.next_round(round_number)]
            fresh = first_slices()
            if not extensions and not fresh:
                break
            scan.run(set(extensions) | set(fresh))
        return sliced

    # Control: without the reserve /s6 (3.5 s per request) and /s7 never got a first slice.
    assert run(False) == ["/s0", "/s1", "/s2", "/s3", "/s4", "/s5"]
    assert run(True) == ["/s0", "/s1", "/s2", "/s3", "/s4", "/s5", "/s6", "/s7"]


def test_the_new_work_reserve_counts_candidates_beyond_the_verifier_offsets():
    from scan.continuation_rounds import new_work_reserve

    actions = tuple(
        dataclasses.replace(
            _action(f"{lane}.r02", capability, ordinal, capability_args={
                "slice": {"start": 0, "count": 2}, "continuation_work_key": lane,
            }),
            action_digest=None,
        )
        for ordinal, (lane, capability) in enumerate((
            ("verify.sqli", "sqli.verify_batch"), ("verify.xss", "xss.verify_batch"),
        ))
    )
    plan = ScanActionPlan(
        scan_id=str(uuid.UUID(int=2)), execution_plan_digest="a" * 64,
        target_binding_digest=TARGET.digest, actions=actions,
    )
    body = {"body_field_names": ["a"], "family_hints": ["xss", "sqli"]}
    query = {"family_hints": ["sqli"]}
    # Five candidates, two of them sliced in each lane. The SQLi lane's three pending ones hold
    # their own floors (a body's 420 s, a query's 30 s); the XSS lane counts only the bodies
    # hinted for XSS (120 s each).
    entries = [body, body, body, query, body]
    assert new_work_reserve(plan, SimpleNamespace(entries=entries)) == [
        ("verify.sqli", 420), ("verify.sqli", 30), ("verify.sqli", 420),
        ("verify.xss", 120), ("verify.xss", 120),
    ]
    assert new_work_reserve(plan, SimpleNamespace(entries=entries[:2])) == []
    # A family the Scan did not select reserves nothing.
    sqli_only = ScanActionPlan(
        scan_id=str(uuid.UUID(int=3)), execution_plan_digest="a" * 64,
        target_binding_digest=TARGET.digest, actions=actions[:1],
    )
    assert all(lane == "verify.sqli" for lane, _ in new_work_reserve(
        sqli_only, SimpleNamespace(entries=entries),
    ))


def test_only_first_slices_the_compile_can_admit_are_reserved():
    from scan.verification_extension import _admissible_reserve

    # One pending body slice (540 s) with 257 s left cannot be admitted: nothing is held back.
    assert _admissible_reserve([("verify.sqli", 540)], 257, 900) == 0
    assert _admissible_reserve(540, 257, 900) == 0
    # Smallest first, while they fit what is left; slices beyond one round's lane share are
    # admitted in later rounds and stay reserved.
    assert _admissible_reserve(
        [("verify.sqli", 420)] * 3 + [("verify.xss", 120)], 1_000, 900,
    ) == 420 + 420 + 120
    assert _admissible_reserve([("verify.sqli", 420)] * 3, 5_000, 900) == 1_260
    # A slice larger than its lane's round share is never admitted.
    assert _admissible_reserve([("verify.sqli", 1_000)], 5_000, 900) == 0


def test_an_unsliceable_pending_candidate_does_not_cost_the_last_chance(monkeypatch):
    """Follow-up review: one pending first slice that cannot fit the 257 s left held that wall
    back from the last chance, and the 4.0 s late-field injection was missed again."""
    ENDPOINTS["/vuln"] = (4.0, 4)
    try:
        scan = _Scan(
            monkeypatch, ("/vuln", "/chat"), vuln={("/vuln", "B", "field3")}, earlier=1_031,
        )
        scan.pending_new_work = [("verify.sqli", 540)]
        scan.add("verify.sqli.r01", path="/vuln", budget=SLICE)
        scan.add("verify.sqli.001.r01", path="/chat", budget=SLICE)
        scan.run({"verify.sqli.r01", "verify.sqli.001.r01"})
        scan.drive()
    finally:
        ENDPOINTS["/vuln"] = (5.3, 4)
    assert scan.found == {("/vuln", "B", "field3")}
    assert scan.residual()["tool_wall_seconds"] == 137

