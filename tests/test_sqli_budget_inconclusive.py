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
    budget_concluded_slices,
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


def test_fast_two_field_login_reaches_error_based_until_time_based_is_confirmed_unfundable():
    """Review blocker: Fast's 375 s share; the login form at 2 s per request."""
    fields = ("username", "password")
    settled = [f"{technique}:{name}" for technique in "UB" for name in fields]
    # One sample: time-based (398 s on one field) would not fit, but one sample is not a
    # verdict. The next unit, E, is run as a probe that measures the rate again: 50 s holds
    # 15 requests at 2 s, plus one stage minimum.
    error = resume_plan(
        settled, {}, fields=fields, rate_samples=[("U:username", 2.0)], round_wall_ceiling=375,
    )
    assert (error.technique, error.field_name, error.wall_seconds) == ("E", "username", 50)
    assert error.probe and not error.budget_inconclusive
    # Time-based next on a single sample: one probe measures again.
    time_based = resume_plan(
        settled + [f"E:{name}" for name in fields], {}, fields=fields,
        rate_samples=[("U:username", 2.0)], round_wall_ceiling=375,
    )
    assert (time_based.technique, time_based.field_name) == ("T", "username")
    assert time_based.probe and time_based.wall_seconds == 50
    assert not time_based.budget_inconclusive
    # Two samples judged by their minimum confirm time-based above the share: the candidate
    # cannot reach a full negative, so it is inconclusive now, before E is spent on.
    samples = [("U:username", 2.0), ("B:username", 2.0)]
    confirmed = resume_plan(settled, {}, fields=fields, rate_samples=samples, round_wall_ceiling=375)
    assert confirmed.budget_inconclusive and confirmed.unfundable == ("T",)
    assert confirmed.wall_seconds is None and not confirmed.positive_only
    # The same candidate is fully fundable on Balanced and Thorough.
    for ceiling in (900, 2_700):
        fits = resume_plan(settled, {}, fields=fields, rate_samples=samples, round_wall_ceiling=ceiling)
        assert fits.wall_seconds == 308 and not fits.budget_inconclusive and not fits.probe


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
    # E on one field at 8 s is 1,172 s: one probe, not a verdict. The probe holds just enough
    # for a second rate sample (10 requests, half again, at 8 s, plus one stage minimum).
    assert first.probe and first.wall_seconds == 140 and not first.budget_inconclusive
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
    "/stall": (150.0, 1),
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
            budget_concluded=budget_concluded_slices(observations),
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
WIDE_SLICE = {"http_requests": 1_200, "state_changing_requests": 600, "tool_wall_seconds": 420}


def test_a_slice_that_settled_nothing_gets_one_probe_then_a_verdict(monkeypatch):
    """Regression for N55: verify.sqli.r01 settled nothing and was extended again and again."""
    scan = _Scan(monkeypatch, ("/chat", "/copilot"))
    scan.add("verify.sqli.r01", path="/chat", budget=SLICE)
    scan.add("verify.sqli.001.r01", path="/copilot", budget=SLICE)
    scan.run({"verify.sqli.r01", "verify.sqli.001.r01"})
    # Union-based on the chat's first field needs 53 requests at 13.1 s: the slice is killed.
    # The copilot settles union-based on its first field (281 s) -- progress a whole-body run
    # never checkpointed -- and spends the 139 s it cannot finish the next field in measuring
    # its rate a second time instead of returning it.
    assert [
        (path, technique, tested) for path, technique, tested, _ in scan.calls
    ] == [
        ("/chat", "U", ("field0",)), ("/copilot", "U", ("field0",)),
        ("/copilot", "U", ("field1",)),
    ]
    [chat] = scan.records("verify.sqli.r01", "candidate_attempt")
    assert (chat["resume_technique"], chat["resume_field"]) == ("U", "field0")
    assert chat["field_count"] == 8
    # One rate sample (13.1 s) puts boolean-based above the 900 s share: not yet a verdict,
    # but only a probe -- the least hold above the 420 s the unit was killed at.
    assert chat["resume_probe"] is True and chat["resume_wall_seconds"] == 440
    assert "verdict" not in chat
    # Two samples put time-based on any copilot field (1,019 s) above the share: the copilot
    # cannot reach a full negative, so it is inconclusive now; its next union-based unit is
    # cheap enough to fund for a positive while no other lane is waiting.
    [copilot] = scan.records("verify.sqli.001.r01", "candidate_attempt")
    assert copilot["verdict"] == "inconclusive" and copilot["positive_only"] is True
    [copilot_verdict] = scan.records("verify.sqli.001.r01", INCONCLUSIVE_RECORD_KIND)
    assert copilot_verdict["unfundable_techniques"] == ["T"]
    assert copilot_verdict["settled_units"] == ["U:field0"]

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

    # Now: the chat's probe is funded at its floor, and the copilot's cheap positive-only unit
    # at its own, since no other lane is waiting.
    second = scan.next_round(2)
    assert second == [("verify.sqli.r01.ext.r02", 440), ("verify.sqli.001.r01.ext.r02", 420)]
    scan.run({action_id for action_id, _ in second})
    # The probe measured the chat again: boolean-, error- and time-based can never fit a
    # round, so the chat is inconclusive for budget and is not funded again.
    [chat_verdict] = scan.records("verify.sqli.r01.ext.r02", INCONCLUSIVE_RECORD_KIND)
    assert chat_verdict["unfundable_techniques"] == ["B", "E", "T"]
    assert chat_verdict["positive_only"] is False
    third = scan.next_round(3)
    assert all(not action_id.startswith("verify.sqli.r01.") for action_id, _ in third)


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
    # The probe was killed again: two measurements agree, so the candidate is inconclusive
    # for budget and no further continuation is granted.
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
    # Time-based on one field (398 s at 2 s per request) can never fit Fast's share, so the
    # candidate cannot reach a full negative: inconclusive now, and not funded again.
    assert verdict["unfundable_techniques"] == ["T"]
    assert verdict["positive_only"] is False and "predicted_wall_seconds" not in verdict
    assert verdict["settled_units"] == ["B:field0", "U:field0", "U:field1"]
    assert scan.next_round(2) == []


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
        plan = self.plan()
        observations = {
            action_id: tuple(self.receipts[action_id].observations)
            for action_id in resume_observation_action_ids(plan, self.results)
            if action_id in self.receipts
        }
        planned = plan_verification_extensions(
            parent_plan=plan, parent_results=self.results, profile_limits=self.profile,
            residual=self.residual(), stage_resume_walls=stage_resume_walls(observations),
            budget_concluded=budget_concluded_slices(observations),
        )
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

    2.8.0 spent 2,833 s of SQLi on these candidates and concluded nothing. The first version
    of this fix (a774b411) still spent 2,928 s -- the 8-field chat drew a 900 s share in three
    rounds -- without a budget verdict, and SQLi extensions were planned before the form's XSS
    extension.
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
    # Both chat candidates end with an explicit budget verdict naming what no round can fund.
    chat, copilot = scan.verdicts("/chat")[0], scan.verdicts("/copilot")[0]
    assert chat["unfundable_techniques"] == ["B", "E", "T"]
    assert chat["positive_only"] is False
    assert copilot["unfundable_techniques"] == ["T"]
    # The login form's SQLi concludes, and the whole SQLi lane has concluded by round 3.
    assert concluded_at == (3, 1_844)
    # Afterwards only the copilot's cheap union-based units are funded, for a positive, from
    # what no other lane is waiting for; the lane stays below 2.8.0's 2,833 s.
    assert scan.sqli_wall() == 2_404


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
        # Each lane first holds half of what is left: XSS is funded, and SQLi's 716 s floor
        # does not fit its half, so it waits rather than draining the residual first.
        assert "xss.verify_batch" in walls, order
        assert walls["xss.verify_batch"] <= 500


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
