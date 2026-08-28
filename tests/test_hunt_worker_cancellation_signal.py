"""Cancelling a Hunt must reach the capability jobs it queued to workers.

Not every Hunt capability runs inline. A worker-placed one polls `agent_tool_cancel:{job_id}` for
a job id minted fresh at queue time, so a Hunt cancellation could not reconstruct it -- and
`HuntRunService.cancel` cancelled the Hunt row and its scans while that traffic kept running. An
external audit found this after the inline watch and scan cascade were added, which is exactly the
gap those two did not cover.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))

from hunt.cancellation import (  # noqa: E402
    JOB_CANCEL_PREFIX,
    JOB_SET_PREFIX,
    record_cancellable_job,
    signal_cancelled_jobs,
)


class _Redis:
    def __init__(self, *, fail_on=()):
        self.sets: dict[str, set[str]] = {}
        self.keys: dict[str, str] = {}
        self.expiries: dict[str, int] = {}
        self._fail_on = set(fail_on)

    def sadd(self, key, value):
        if "sadd" in self._fail_on:
            raise RuntimeError("redis down")
        self.sets.setdefault(key, set()).add(value)

    def expire(self, key, ttl):
        self.expiries[key] = ttl

    def smembers(self, key):
        if "smembers" in self._fail_on:
            raise RuntimeError("redis down")
        return set(self.sets.get(key) or ())

    def set(self, key, value, ex=None):
        if "set" in self._fail_on:
            raise RuntimeError("redis down")
        self.keys[key] = value


def test_a_queued_job_is_signalled_when_its_hunt_is_cancelled():
    redis = _Redis()
    record_cancellable_job(redis, "hunt-1", "job-a")
    record_cancellable_job(redis, "hunt-1", "job-b")

    signalled = signal_cancelled_jobs(redis, "hunt-1")
    assert signalled == ["job-a", "job-b"]
    # The exact key a worker-placed capability polls.
    assert redis.keys[f"{JOB_CANCEL_PREFIX}job-a"] == "1"
    assert redis.keys[f"{JOB_CANCEL_PREFIX}job-b"] == "1"


def test_another_hunts_jobs_are_untouched():
    redis = _Redis()
    record_cancellable_job(redis, "hunt-1", "mine")
    record_cancellable_job(redis, "hunt-2", "theirs")

    signal_cancelled_jobs(redis, "hunt-1")
    assert f"{JOB_CANCEL_PREFIX}mine" in redis.keys
    assert f"{JOB_CANCEL_PREFIX}theirs" not in redis.keys


def test_signalling_is_idempotent():
    redis = _Redis()
    record_cancellable_job(redis, "hunt-1", "job-a")
    assert signal_cancelled_jobs(redis, "hunt-1") == ["job-a"]
    assert signal_cancelled_jobs(redis, "hunt-1") == ["job-a"]


def test_the_job_set_expires_so_it_cannot_grow_without_bound():
    redis = _Redis()
    record_cancellable_job(redis, "hunt-1", "job-a")
    assert redis.expiries[f"{JOB_SET_PREFIX}hunt-1"] > 0


def test_bookkeeping_never_breaks_the_queue_path():
    # Failing to remember a job must not stop it being queued: losing the ability to cancel it is
    # bad, refusing to run authorized work because Redis hiccuped is worse.
    record_cancellable_job(_Redis(fail_on=("sadd",)), "hunt-1", "job-a")


def test_an_unreadable_set_does_not_block_the_cancellation():
    # The Hunt is cancelled either way; signalling is best-effort on top of that.
    assert signal_cancelled_jobs(_Redis(fail_on=("smembers",)), "hunt-1") == []


def test_missing_identifiers_are_refused_rather_than_guessed():
    redis = _Redis()
    record_cancellable_job(redis, "", "job-a")
    record_cancellable_job(redis, "hunt-1", "")
    record_cancellable_job(None, "hunt-1", "job-a")
    assert redis.sets == {}
    assert signal_cancelled_jobs(redis, "") == []


def test_every_queue_site_records_its_job():
    """Enumerated from the source, not listed by hand.

    The first version of this test named the two sites the fix had touched, so it passed while
    browser, scanner and replay work stayed uncancellable -- an external audit found exactly that.
    Discovering the sites means a new one cannot be added without either registering its job or
    failing here.
    """
    import ast

    router = Path("api/hunt/interaction_router.py").read_text(encoding="utf-8")
    tree = ast.parse(router)
    missing = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)):
            continue
        if not node.name.startswith("_enqueue_"):
            continue
        body = ast.get_source_segment(router, node) or ""
        # A site that mints a job id is placing work on a worker, so a Hunt cancellation has to be
        # able to reach it.
        if "job_id = str(uuid.uuid4())" not in body:
            continue
        if "record_cancellable_job(" not in body:
            missing.append(node.name)
    assert not missing, (
        "these queue work to a worker but never register it for Hunt cancellation: "
        + ", ".join(sorted(missing))
    )


def test_the_enumeration_finds_every_known_site():
    # Guard the guard: if the discovery predicate stops matching, the test above would pass
    # vacuously.
    import ast

    router = Path("api/hunt/interaction_router.py").read_text(encoding="utf-8")
    tree = ast.parse(router)
    found = {
        node.name for node in ast.walk(tree)
        if isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef))
        and node.name.startswith("_enqueue_")
        and "job_id = str(uuid.uuid4())" in (ast.get_source_segment(router, node) or "")
    }
    assert found >= {
        "_enqueue_canonical_network_capability",
        "_enqueue_canonical_http_capability",
        "_enqueue_canonical_browser_capability",
        "_enqueue_canonical_scanner_capability",
        "_enqueue_hunt_replay_capability",
    }, found


def test_cancel_signals_and_reports_what_it_reached():
    from tests.api_sources import definition_source

    source = definition_source("cancel")
    assert "signal_cancelled_jobs(" in source
    assert 'payload["cancelled_job_ids"] = signalled' in source
