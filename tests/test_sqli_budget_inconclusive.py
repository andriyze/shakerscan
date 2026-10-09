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
    stage_attempt_id,
    stage_requests,
    stage_units,
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


def test_fast_two_field_login_still_attempts_error_and_time_based():
    """Review blocker: Fast's 375 s share; the login form at 2 s per request."""
    fields = ("username", "password")
    samples = [("U:username", 2.0), ("B:username", 2.0)]
    settled = [f"{technique}:{name}" for technique in "UB" for name in fields]
    error = resume_plan(
        settled, {}, fields=fields, rate_samples=samples, round_wall_ceiling=375,
    )
    assert (error.technique, error.field_name, error.wall_seconds) == ("E", "username", 308)
    assert not error.budget_inconclusive
    # Time-based on one field needs 398 s at that rate, above the share: one probe round at the
    # share measures again rather than declaring the candidate inconclusive on one rate.
    time_based = resume_plan(
        settled + [f"E:{name}" for name in fields], {}, fields=fields,
        rate_samples=[("U:username", 2.0)], round_wall_ceiling=375,
    )
    assert (time_based.technique, time_based.field_name) == ("T", "username")
    assert time_based.probe and time_based.wall_seconds == 375
    assert not time_based.budget_inconclusive
    # Two measurements that agree make it inconclusive for budget on Fast ...
    confirmed = resume_plan(
        settled + [f"E:{name}" for name in fields], {}, fields=fields,
        rate_samples=samples, round_wall_ceiling=375,
    )
    assert confirmed.budget_inconclusive and confirmed.wall_seconds == 398
    # ... and the same unit fits Balanced and Thorough.
    for ceiling in (900, 2_700):
        fits = resume_plan(
            settled + [f"E:{name}" for name in fields], {}, fields=fields,
            rate_samples=samples, round_wall_ceiling=ceiling,
        )
        assert fits.wall_seconds == 398 and not fits.budget_inconclusive and not fits.probe


def test_thorough_funds_what_balanced_cannot_for_the_slow_chat_candidate():
    # Fixture: the 8-field chat candidate at 13.1 s per request, union-based settled.
    fields = tuple(f"field{index}" for index in range(8))
    settled = [f"U:{name}" for name in fields]
    samples = [("U:field0", 13.1), ("U:field1", 13.1)]
    balanced = resume_plan(
        settled, {}, fields=fields, rate_samples=samples, round_wall_ceiling=900,
    )
    assert (balanced.technique, balanced.field_name) == ("B", "field0")
    assert balanced.wall_seconds == 1_160 and balanced.budget_inconclusive
    thorough = resume_plan(
        settled, {}, fields=fields, rate_samples=samples, round_wall_ceiling=2_700,
    )
    assert thorough.wall_seconds == 1_160 and not thorough.budget_inconclusive


def test_one_slow_run_is_re_measured_before_any_verdict():
    """Review blocker: a single run at sqlmap's 8 s timeout must not decide the candidate."""
    fields = ("a", "b", "c")
    first = resume_plan(
        ["U:a", "U:b", "U:c", "B:a", "B:b", "B:c"], {}, fields=fields,
        rate_samples=[("B:a", 8.0)], round_wall_ceiling=900,
    )
    # E on one field at 8 s is 1,172 s: one probe round at the share, not a verdict.
    assert first.probe and first.wall_seconds == 900 and not first.budget_inconclusive
    # The probe measured the true 1 s per request: E on one field fits at 164 s.
    second = resume_plan(
        ["U:a", "U:b", "U:c", "B:a", "B:b", "B:c"], {}, fields=fields,
        rate_samples=[("B:a", 8.0), ("B:b", 1.0)], round_wall_ceiling=900,
    )
    assert second.wall_seconds == 164 and not second.probe and not second.budget_inconclusive
    # A unit killed at the share already needs no probe: its own kill is the second measurement.
    killed = resume_plan(
        [], {"U": 900}, rate_samples=[("U", 20.0)], killed_sent={"U": 45},
        round_wall_ceiling=900,
    )
    assert killed.budget_inconclusive and killed.wall_seconds == 1_380  # 68 requests (1.5 x 45)
    # Too few requests to measure anything: only the killed-wall floor applies.
    unmeasured = resume_plan([], {"U": 20}, rate_samples=[], round_wall_ceiling=900)
    assert unmeasured.wall_seconds == 20 + MINIMUM_STAGE_WALL_SECONDS
    assert not unmeasured.budget_inconclusive


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
ENDPOINTS = {
    "/chat": (13.1, 8),
    "/copilot": (5.3, 4),
    "/slow": (20.0, 1),
    "/login": (0.6, 2),
    "/fastlogin": (2.0, 2),
}


class _Scan:
    """A Scan's SQLi slices run round by round against one checkpoint store."""

    def __init__(self, monkeypatch, paths, *, profile_wall=BALANCED_WALL):
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

    def add(self, action_id, *, path, budget, extends=None):
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
        return {
            name: self.profile[name] - sum(
                int(result.budget_consumed.get(name, 0)) for result in self.results.values()
            )
            for name in self.profile
        }

    def next_round(self, round_number):
        plan = self.plan()
        observations = {
            action_id: tuple(self.receipts[action_id].observations)
            for action_id in resume_observation_action_ids(plan, self.results)
        }
        planned = plan_verification_extensions(
            parent_plan=plan, parent_results=self.results, profile_limits=self.profile,
            residual=self.residual(), stage_resume_walls=stage_resume_walls(observations),
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


# The body slice 9de6a910 planned for each chat candidate.
SLICE = {"http_requests": 800, "state_changing_requests": 480, "tool_wall_seconds": 420}
# A slice whose request hold is large enough that the slice spends under half of it, as the
# soak's login slice did (364 of 800): latency-starved, eligible to extend.
WIDE_SLICE = {"http_requests": 1_200, "state_changing_requests": 1_200, "tool_wall_seconds": 420}


def test_no_continuation_is_granted_below_what_the_unit_is_predicted_to_need(monkeypatch):
    """Regression for N55: verify.sqli.r01 settled nothing and was extended at 450 s anyway."""
    scan = _Scan(monkeypatch, ("/chat", "/copilot"))
    scan.add("verify.sqli.r01", path="/chat", budget=SLICE)
    scan.add("verify.sqli.001.r01", path="/copilot", budget=SLICE)
    scan.run({"verify.sqli.r01", "verify.sqli.001.r01"})
    # Union-based on the chat's first field needs 53 requests at 13.1 s: the slice is killed.
    # The copilot settles union-based on its first field (281 s) -- progress the whole-body run
    # never checkpointed -- and yields the rest of its slice.
    assert [
        (path, technique, tested) for path, technique, tested, _ in scan.calls
    ] == [("/chat", "U", ("field0",)), ("/copilot", "U", ("field0",))]
    assert scan.results["verify.sqli.r01"].status.value == "timed_out"
    [chat] = scan.records("verify.sqli.r01", "candidate_attempt")
    assert (chat["resume_technique"], chat["resume_field"]) == ("U", "field0")
    assert chat["field_count"] == 8
    assert chat["resume_wall_seconds"] == 716  # 53 requests at 13.125 s, plus 20 s

    # Control: the floor the 2.8.0 planner read -- the killed wall plus one stage minimum --
    # granted the 450 s extension the wall killed again, settling nothing.
    old = plan_verification_extensions(
        parent_plan=scan.plan(), parent_results=scan.results, profile_limits=scan.profile,
        residual=scan.residual(),
        stage_resume_walls={
            "verify.sqli.r01": 420 + MINIMUM_STAGE_WALL_SECONDS,
            "verify.sqli.001.r01": 420 + MINIMUM_STAGE_WALL_SECONDS,
        },
    )
    assert [item["budget"]["tool_wall_seconds"] for item in old] == [450, 450]

    # With the prediction the continuation is only granted at a wall that settles the unit:
    # the lane cannot hold the chat's 716 s and the copilot's 301 s together, so the copilot
    # waits for the next round instead of both being funded below what they need.
    [copilot] = scan.records("verify.sqli.001.r01", "candidate_attempt")
    assert (copilot["resume_technique"], copilot["resume_field"]) == ("U", "field1")
    assert copilot["resume_wall_seconds"] == 420  # 301 s predicted, the body attempt floor
    second = scan.next_round(2)
    assert [action_id for action_id, _ in second] == ["verify.sqli.r01.ext.r02"]
    assert second[0][1] >= 716
    before = len(scan.calls)
    scan.run({second[0][0]})
    ran = scan.calls[before:]
    assert ran[0][:3] == ("/chat", "U", ("field0",))
    attempts = scan.records(second[0][0], "sqli_technique_stage")
    assert any(
        item.get("field") == "field0" and item.get("status") == "success" for item in attempts
    ), "the extension made progress: union-based is settled on the first field"


def test_a_unit_no_round_can_fund_is_probed_once_then_inconclusive(monkeypatch):
    # Fixture: one tested field at 20 s per request; union-based needs 1,080 s, above 900 s.
    scan = _Scan(monkeypatch, ("/slow",))
    scan.add("verify.sqli.r01", path="/slow", budget=SLICE)
    scan.run({"verify.sqli.r01"})
    [first] = scan.records("verify.sqli.r01", "candidate_attempt")
    # One measurement: no verdict yet, but one probe round at the lane's share.
    assert first.get("resume_probe") is True and "verdict" not in first
    assert first["resume_wall_seconds"] == 900
    assert scan.records("verify.sqli.r01", INCONCLUSIVE_RECORD_KIND) == []
    probe = scan.next_round(2)
    assert probe == [("verify.sqli.r01.ext.r02", 900)]
    scan.run({probe[0][0]})
    # The probe was killed at the share: two measurements agree, so the candidate is
    # inconclusive for budget and no further continuation is granted.
    [attempt] = scan.records(probe[0][0], "candidate_attempt")
    assert attempt["verdict"] == "inconclusive" and attempt["inconclusive_reason"] == "budget"
    [verdict] = scan.records(probe[0][0], INCONCLUSIVE_RECORD_KIND)
    assert verdict["reason"] == "verdict_exceeds_round_budget"
    assert verdict["technique"] == "U" and verdict["field_count"] == 1
    assert verdict["refuted_techniques"] == []
    assert verdict["unsettled_techniques"] == ["U", "B", "E", "T"]
    assert verdict["predicted_wall_seconds"] > verdict["round_wall_ceiling_seconds"] == 900
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


def test_the_fast_login_form_keeps_its_per_field_progress_and_is_told_why_it_stops(
    monkeypatch,
):
    """Review blocker, Fast (375 s share): the login form at 2 s per request.

    Fast's body slice holds 420 s and the planner never sizes an extension below the 420 s body
    attempt floor, so no Fast body candidate is ever extended. Run over both fields at once,
    union-based (212 s) settled and boolean (348 s) was cut off; field by field, boolean on the
    first field settles too, and the candidate says why it stops.
    """
    scan = _Scan(monkeypatch, ("/fastlogin",), profile_wall=FAST)
    scan.add("verify.sqli.r01", path="/fastlogin", budget=WIDE_SLICE)
    scan.run({"verify.sqli.r01"})
    ran = [(technique, tested[0]) for _, technique, tested, _ in scan.calls]
    assert ran == [("U", "field0"), ("U", "field1"), ("B", "field0")]
    [attempt] = scan.records("verify.sqli.r01", "candidate_attempt")
    assert (attempt["resume_technique"], attempt["resume_field"]) == ("B", "field1")
    assert attempt["verdict"] == "inconclusive"
    [verdict] = scan.records("verify.sqli.r01", INCONCLUSIVE_RECORD_KIND)
    assert verdict["refuted_techniques"] == ["U"]
    assert verdict["unsettled_techniques"] == ["B", "E", "T"]
    assert (verdict["technique"], verdict["field"]) == ("B", "field1")
    assert verdict["round_wall_ceiling_seconds"] == 375
    assert verdict["predicted_wall_seconds"] == 420  # the body attempt floor
    assert scan.next_round(2) == []
