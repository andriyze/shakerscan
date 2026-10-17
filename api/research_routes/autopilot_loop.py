"""The research autopilot: every process advances opted-in episodes, one leader maintains (2.11).

Every API process ran this loop on its own: once a second each one reconciled stale dispatches
and (every 30 s / 5 min) queue handoffs, orphaned queue work, campaign chaining and the abandoned
episode reaper, and polled for an episode to claim with a query that examined every eligible
episode's linked Scans and retests. Now:

* Maintenance (``loop_leader``): only the process that leads ``research_autopilot_maintenance``
  runs the maintenance passes, on a task of their own (``run_led_loop``, every
  ``MAINTENANCE_INTERVAL``, each tick bounded by ``MAINTENANCE_TICK_TIMEOUT``), so a planner step
  never delays them. A follower costs one try-lock query per interval.
* Claims: every process claims its own episodes. The Postgres lease on each episode and
  ``FOR UPDATE SKIP LOCKED`` keep two processes off the same episode, and a process that dies
  mid-step is taken over when its lease expires, exactly as before.
* Steps: a claimed episode's planner step (up to ~240 s) runs as a task; at most
  ``STEP_CONCURRENCY`` per process at once, and a process at that bound claims nothing more.
* Bounded claims: each poll examines at most ``CLAIM_BATCH`` eligible episodes (oldest change
  first, from a cursor that wraps), so episodes blocked on running work cannot make the poll scan
  them all, nor starve the ones behind them.
* An idle process backs off from 1 s to ``IDLE_MAX_SECONDS`` between polls.

The collaborators (planner step, lease release, observation settlement...) still live in the API
composition root and are read from it at call time (``hub``), so their test patches apply.
"""
from __future__ import annotations

import asyncio
import json
import os
import time
import uuid
from typing import Any

try:
    import loop_leader
except ModuleNotFoundError:  # package import layout
    from .. import loop_leader

MAINTENANCE_LOOP = "research_autopilot_maintenance"
MAINTENANCE_INTERVAL = 1.0
CLAIM_BATCH = 50
#: Planner steps one process runs at once.
STEP_CONCURRENCY = 2
IDLE_MAX_SECONDS = 5.0
#: How often a process with every step slot busy looks again.
BUSY_POLL_SECONDS = 1.0
MAINTENANCE_TICK_TIMEOUT = 120.0
CAMPAIGN_INTERVAL = 30.0
QUEUE_INTERVAL = 30.0
REAP_INTERVAL = 300.0

#: Eligible episodes, oldest change first, after the cursor: the batch one poll examines.
ELIGIBLE_BATCH_SQL = """
SELECT re.id, re.updated_at
FROM research_episodes re
WHERE re.autopilot_enabled=true
  AND re.status IN ('awaiting_planner','awaiting_observation')
  AND re.cancel_requested=false
  AND (re.lease_expires_at IS NULL OR re.lease_expires_at < NOW())
  AND ($1::timestamptz IS NULL OR (re.updated_at, re.id) > ($1::timestamptz, $2::uuid))
ORDER BY re.updated_at, re.id
LIMIT $3
"""

#: Claim the first episode of the batch that has no queued or running linked Scan or retest.
CLAIM_SQL = """
WITH candidate AS (
    SELECT re.id
    FROM research_episodes re
    WHERE re.id = ANY($3::uuid[])
      AND re.autopilot_enabled=true
      AND re.status IN ('awaiting_planner','awaiting_observation')
      AND re.cancel_requested=false
      AND (re.lease_expires_at IS NULL OR re.lease_expires_at < NOW())
      AND NOT EXISTS (
          SELECT 1
          FROM research_decisions rd
          JOIN command_results cr ON cr.id=rd.command_result_id
          JOIN scans s ON s.id=cr.scan_id
          WHERE rd.episode_id=re.id AND s.status IN ('pending','queued','running')
      )
      AND NOT EXISTS (
          SELECT 1
          FROM research_decisions rd
          JOIN command_results cr ON cr.id=rd.command_result_id
          JOIN finding_verifications fv ON fv.id=(CASE WHEN cr.result_json->>'retest_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN (cr.result_json->>'retest_id')::uuid END)
          WHERE rd.episode_id=re.id AND fv.status IN ('queued','running')
      )
    ORDER BY re.updated_at ASC, re.id ASC
    FOR UPDATE SKIP LOCKED
    LIMIT 1
)
UPDATE research_episodes re
SET lease_owner=$1,
    lease_expires_at=NOW()+make_interval(secs => $2),
    updated_at=NOW()
FROM candidate
WHERE re.id=candidate.id
RETURNING re.*
"""


class MaintenanceClock:
    """When each periodic maintenance pass last ran (monotonic seconds)."""

    def __init__(self) -> None:
        self.campaigns = 0.0
        self.queue = 0.0
        self.reap = 0.0


async def maintenance_tick(pool: Any, hub: Any, clock: MaintenanceClock) -> None:
    """One maintenance pass (the leader's): every pass reconciles stale dispatches (10 at most);
    queue handoffs and orphaned queue work every 30 s; campaigns every 30 s; the reaper every
    5 min. Each step is bounded by its own LIMIT."""
    now = time.monotonic()
    if now - clock.campaigns >= CAMPAIGN_INTERVAL:
        await hub._continue_autonomous_research_campaigns()
        clock.campaigns = now
    async with pool.acquire() as conn, conn.transaction():
        await hub._reconcile_stale_research_dispatches(conn)
        now = time.monotonic()
        if now - clock.queue >= QUEUE_INTERVAL:
            await hub._reconcile_unconfirmed_queue_handoffs(conn)
            await hub._reconcile_research_orphaned_queue_work(conn)
            clock.queue = now
        if now - clock.reap >= REAP_INTERVAL:
            await hub._reap_abandoned_research_episodes(conn)
            clock.reap = now


class ClaimCursor:
    """Where the next claim poll starts: after the last episode the previous one examined."""

    def __init__(self) -> None:
        self.position: tuple[Any, Any] | None = None


async def claim_episode(conn: Any, hub: Any, owner: str, cursor: ClaimCursor,
                        *, batch: int = CLAIM_BATCH) -> Any:
    """Lease one claimable episode from the next batch (``RETURNING re.*``), or None.

    A full batch with nothing claimable moves the cursor past it; a short batch wraps it."""
    after, after_id = cursor.position or (None, None)
    eligible = await conn.fetch(ELIGIBLE_BATCH_SQL, after, after_id, batch)
    if not eligible:
        cursor.position = None
        return None
    row = await conn.fetchrow(CLAIM_SQL, owner, hub.RESEARCH_AUTOPILOT_LEASE_SECONDS,
                              [item["id"] for item in eligible])
    if row is None:
        cursor.position = (
            (eligible[-1]["updated_at"], eligible[-1]["id"]) if len(eligible) >= batch else None
        )
    return row


async def _settle_observation(conn: Any, hub: Any, row: Any, owner: str) -> bool:
    """For a claimed ``awaiting_observation`` episode: True when it is ready to plan."""
    async with conn.transaction():
        locked = await conn.fetchrow("SELECT * FROM research_episodes WHERE id=$1 FOR UPDATE", row["id"])
        if (
            not locked
            or str(locked["status"]) != "awaiting_observation"
            or bool(locked["cancel_requested"])
            or str(locked["lease_owner"] or "") != owner
        ):
            return False
        if await hub._research_async_work(conn, row["id"], active_only=True):
            # Work became active after the candidate query; keep waiting.
            return False
        settlement = await hub._settle_research_awaiting_observation(conn, locked)
        return settlement.get("next_status") == "awaiting_planner"


async def run_research_autopilot(pool: Any, hub: Any, *, concurrency: int = STEP_CONCURRENCY) -> None:
    """Durably advance opted-in episodes independent of any browser session."""
    clock = MaintenanceClock()
    maintenance = asyncio.create_task(loop_leader.run_led_loop(
        pool, MAINTENANCE_LOOP, lambda: maintenance_tick(pool, hub, clock),
        interval=MAINTENANCE_INTERVAL, timeout=MAINTENANCE_TICK_TIMEOUT,
    ))
    steps: set[asyncio.Task] = set()
    try:
        await _claim_loop(pool, hub, steps, max(1, int(concurrency)))
    finally:
        # Shutdown: each step releases its lease when cancelled (see _advance).
        maintenance.cancel()
        for step in steps:
            step.cancel()
        await asyncio.gather(maintenance, *steps, return_exceptions=True)


async def _claim_loop(pool: Any, hub: Any, steps: set[asyncio.Task], concurrency: int) -> None:
    owner = f"api-autopilot:{os.getpid()}:{uuid.uuid4()}"
    cursor = ClaimCursor()
    idle = 1.0
    while True:
        episode_id: str | None = None
        try:
            if len(steps) >= concurrency:
                await asyncio.sleep(BUSY_POLL_SECONDS)
                continue
            should_plan = False
            async with pool.acquire() as conn:
                row = await claim_episode(conn, hub, owner, cursor)
                if row:
                    episode_id = str(row["id"])
                    should_plan = str(row["status"]) == "awaiting_planner"
                    if str(row["status"]) == "awaiting_observation":
                        should_plan = await _settle_observation(conn, hub, row, owner)
            if not episode_id:
                await asyncio.sleep(idle)
                idle = min(IDLE_MAX_SECONDS, idle * 2)
                continue
            idle = 1.0
            if not should_plan:
                await hub._release_research_autopilot_lease(pool, episode_id, owner)
                continue
            step = asyncio.create_task(_run_step(pool, hub, row, episode_id, owner))
            steps.add(step)
            step.add_done_callback(steps.discard)
        except asyncio.CancelledError:
            raise
        except Exception:
            if episode_id:
                await _release_after_error(pool, hub, episode_id, owner)
            await asyncio.sleep(2.0)


async def _release_after_error(pool: Any, hub: Any, episode_id: str, owner: str) -> None:
    try:
        await hub._release_research_autopilot_lease(pool, episode_id, owner, error="autopilot_controller_error")
    except Exception:
        pass


async def _run_step(pool: Any, hub: Any, row: Any, episode_id: str, owner: str) -> None:
    """One step as a task: an unexpected failure releases the lease instead of being lost."""
    try:
        await _advance(pool, hub, row, episode_id, owner)
    except asyncio.CancelledError:
        raise
    except Exception:
        await _release_after_error(pool, hub, episode_id, owner)


async def _advance(pool: Any, hub: Any, row: Any, episode_id: str, owner: str) -> None:
    """Run one planner step for a leased episode and release its lease (the 2.10 logic)."""
    heartbeat_stop = asyncio.Event()
    heartbeat_task = asyncio.create_task(
        hub._research_lease_heartbeat(pool, episode_id, owner, heartbeat_stop)
    )
    try:
        if hub._research_episode_uses_agent_loop(row):
            # Opt-in: drive this episode with the LLM ReAct hunt loop instead of the
            # menu planner. The existing create-MA/menu path is untouched (this branch
            # only fires when planner.agent_loop was set at launch).
            result = await hub._run_agent_hunt_for_episode(episode_id)
        else:
            result = await hub._plan_research_episode_step(
                episode_id,
                hub.ResearchPlannerStepRequest(
                    execute=True,
                    # 240s (of a 300s ceiling) so a large reasoning planner finishes the first big
                    # pack with room for one retry after a transient provider connection error; the
                    # full 8000 max_tokens so a filled mass_assignment/BOLA workflow isn't truncated
                    # into a harness-repair/misinferred stop.
                    timeout_seconds=240,
                    max_tokens=8000,
                    created_by="server_autopilot",
                ),
            )
    except asyncio.CancelledError:
        heartbeat_stop.set()
        # Graceful shutdown cancels this task and awaits it BEFORE closing the pool (see
        # lifespan), so release the lease we hold here. Otherwise a restarted controller must
        # wait out the ~4-minute lease TTL before it can resume this episode -- the observed
        # multi-minute dead window after an API restart. Shield so the cleanup completes
        # despite the cancellation propagating.
        try:
            await asyncio.shield(heartbeat_task)
        except Exception:
            pass
        try:
            await asyncio.shield(hub._release_research_autopilot_lease(pool, episode_id, owner))
        except Exception:
            pass
        raise
    except Exception as exc:
        heartbeat_stop.set()
        await heartbeat_task
        if hub._research_autopilot_expected_control_race(exc):
            await hub._release_research_autopilot_lease(pool, episode_id, owner)
        else:
            detail = exc.detail if isinstance(exc, hub.HTTPException) else str(exc)
            error = json.dumps(detail, default=str) if isinstance(detail, (dict, list)) else str(detail)
            await hub._release_research_autopilot_lease(pool, episode_id, owner, error=error or type(exc).__name__)
    else:
        heartbeat_stop.set()
        await heartbeat_task
        result_episode = result.get("episode") if isinstance(result, dict) else {}
        if isinstance(result, dict) and result.get("accepted") is False and not (result_episode or {}).get("terminal"):
            errors = []
            decisions = result.get("decisions") if isinstance(result.get("decisions"), list) else []
            if decisions and isinstance(decisions[0], dict):
                errors = decisions[0].get("validation_errors") or []
            policy_steering = hub._research_rejection_is_policy_steering(errors)
            async with pool.acquire() as conn:
                episode_row = await conn.fetchrow(
                    "SELECT * FROM research_episodes WHERE id=$1 AND lease_owner=$2",
                    uuid.UUID(episode_id), owner,
                )
                if episode_row and str(episode_row["status"]) == "awaiting_planner":
                    await hub._build_research_observation(
                        conn,
                        episode_row,
                        previous_result={
                            "planner_rejection": {
                                "validation_errors": [str(item)[:300] for item in errors[:20]],
                                "instruction": (
                                    "The deterministic policy excluded this exact action/hypothesis. "
                                    "Choose a different planner-visible hypothesis or semantic dimension."
                                    if policy_steering else
                                    "Choose a named proposable command or provide a valid stop/input decision."
                                ),
                            }
                        },
                        next_status="awaiting_planner",
                    )
                    if policy_steering:
                        await hub._record_research_event(
                            conn,
                            episode_row["id"],
                            event_type="planner_steered",
                            status="retrying",
                            summary="Deterministic policy steered the planner to different work",
                            details={"validation_errors": [str(item)[:300] for item in errors[:20]]},
                        )
            if policy_steering:
                await hub._release_research_autopilot_lease(pool, episode_id, owner)
            else:
                await hub._release_research_autopilot_lease(
                    pool,
                    episode_id,
                    owner,
                    error=f"planner_decision_rejected:{','.join(str(item) for item in errors)[:800]}",
                )
        else:
            await hub._release_research_autopilot_lease(pool, episode_id, owner)

__all__ = [
    "CLAIM_BATCH",
    "MAINTENANCE_LOOP",
    "STEP_CONCURRENCY",
    "ClaimCursor",
    "MaintenanceClock",
    "claim_episode",
    "maintenance_tick",
    "run_research_autopilot",
]
