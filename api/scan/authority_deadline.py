"""Time-bounded target-authorization checks around running Scan work.

``ScanAuthorityGuard`` (``action_authority_guard``) answers whether a Scan is still authorized;
this module decides *when* an answer is too late. Both callers use it: the action executor
(``ReceiptScanActionExecutor``) around each action, and ``running_scan_authority`` around a
Scan that runs as one piece of work.

* Before work starts, ``check_before_start`` runs the full check, retrying a failure after each
  of ``check_retry_delays``. Every attempt and retry together take at most
  ``unverified_after_seconds``; a check that does not answer by then is cancelled and the work
  is refused as ``authorization_unverified``, never as a revoke.
* While work runs, ``watch_authorization`` polls about every ``poll_seconds``, sooner when the
  last check was slow. The safety deadline is ``unverified_after_seconds`` after the start of
  the last check that confirmed the authorization, not after the first failure. Each poll (pool acquisition, queries and any full
  re-check, as one operation) is bounded by that deadline and runs as its own task, so a
  database that never answers cannot hold the interruption back: the signal is set on time and
  the stalled poll is cancelled, releasing its connection.
"""

from __future__ import annotations

import asyncio
from typing import Any, Awaitable, Callable

from .action_interruption import ActionInterruption
from .capability_result import CapabilityResultReason


# A check that cannot reach the database is unverified, never a revoke. While work runs, it may
# go this long without a successful confirmation (a database blip must not kill healthy work);
# a longer outage, or a check that does not answer, interrupts it as authorization_unverified.
# Before work starts the check is retried after each delay below, all within the same bound,
# and then fails closed, unverified.
AUTHORITY_UNVERIFIED_AFTER_SECONDS = 10.0
AUTHORITY_CHECK_RETRY_DELAYS = (0.5, 1.0, 2.0)
# How long a timed-out check may take to unwind after it is cancelled (an asyncpg acquire or
# query releases its connection on cancellation) before it is abandoned.
AUTHORITY_CHECK_CANCEL_GRACE_SECONDS = 1.0

UNVERIFIED = CapabilityResultReason.AUTHORIZATION_UNVERIFIED.value
# How long work stopped on its authorization may take to wind down through its own stop checks
# before it is cancelled outright.
HARD_STOP_GRACE_SECONDS = 5.0


class AuthorityCheckTimeout(Exception):
    """An authority check did not answer before its deadline; the outcome is unknown."""


def tolerance_seconds(authority: Any) -> float:
    return float(getattr(authority, "unverified_after_seconds", AUTHORITY_UNVERIFIED_AFTER_SECONDS))


async def bounded_check(check: Awaitable[str | None], timeout: float,
                        on_timeout: Callable[[], None] | None = None) -> str | None:
    """Run one whole check under one deadline that does not depend on the check returning.

    A check still pending at the deadline calls ``on_timeout`` at once (so an interruption is
    recorded on time), is then cancelled and given a short grace to release its connection, so
    no task is left behind, and raises ``AuthorityCheckTimeout``.
    """
    task = asyncio.ensure_future(check)
    try:
        done, _pending = await asyncio.wait({task}, timeout=max(0.0, timeout))
    except BaseException:
        task.cancel()
        await asyncio.wait({task}, timeout=AUTHORITY_CHECK_CANCEL_GRACE_SECONDS)
        raise
    if task in done:
        return task.result()
    if on_timeout is not None:
        on_timeout()
    task.cancel()
    await asyncio.wait({task}, timeout=AUTHORITY_CHECK_CANCEL_GRACE_SECONDS)
    if task.done() and not task.cancelled():
        task.exception()  # retrieved: a late failure of an abandoned check is not reported
    raise AuthorityCheckTimeout()


async def check_before_start(authority: Any, action: Any) -> tuple[str | None, float]:
    """``(denial, confirmed_at)``: the fail-closed check before work starts.

    ``denial`` is ``None`` when authorized, else a ``CapabilityResultReason`` value;
    ``confirmed_at`` is the loop time the confirming check started.
    """
    delays = tuple(getattr(authority, "check_retry_delays", AUTHORITY_CHECK_RETRY_DELAYS))
    loop = asyncio.get_running_loop()
    give_up_at = loop.time() + tolerance_seconds(authority)
    denial: str | None = UNVERIFIED
    confirmed_at = 0.0
    for attempt in range(len(delays) + 1):
        try:
            confirmed_at = loop.time()
            denial = await bounded_check(authority.check(action), give_up_at - confirmed_at)
            return (CapabilityResultReason(denial).value if denial is not None else None), confirmed_at
        except Exception:
            # Fail closed before any traffic, but say what is known: the authorization could
            # not be read (or the answer was not a known reason), which is not a revoke.
            denial = UNVERIFIED
            if attempt < len(delays) and loop.time() + delays[attempt] < give_up_at:
                await asyncio.sleep(delays[attempt])
            else:
                break
    return denial, confirmed_at


def poll_floor_seconds(tolerance: float) -> float:
    """The least time a poll is given before the deadline (1 s at the production 10 s)."""
    return min(1.0, tolerance * 0.1)


async def watch_authorization(
    authority: Any,
    action: Any,
    *,
    confirmed_at: float,
    stopped: asyncio.Event,
    signal: ActionInterruption,
    on_interrupt: Callable[[str], None],
) -> None:
    """Poll while work runs; on a withdrawal or a missed deadline record it on ``signal``.

    Polls are scheduled so the next one is expected to answer before the deadline: the wait
    shrinks by how long the last confirming check took and always leaves at least
    ``poll_floor_seconds``. A slow but healthy database therefore keeps confirming (up to
    checks of about half the tolerance), and the run is never declared unverified without a
    poll attempted since the last confirmation. A poll still pending at the deadline is
    abandoned; one started in the last floor window is given that floor, so the interruption
    comes at most ``poll_floor_seconds`` after the deadline.
    """
    tolerance = tolerance_seconds(authority)
    floor = poll_floor_seconds(tolerance)
    loop = asyncio.get_running_loop()
    # The check that confirmed just before this watch started ran until now.
    expected = max(0.0, loop.time() - confirmed_at)
    attempted = False  # a poll has started since the last confirmation
    while not stopped.is_set() and signal.reason is None:
        remaining = confirmed_at + tolerance - loop.time()
        reason = UNVERIFIED if remaining <= 0 and attempted else None
        if reason is None:
            if remaining > floor + expected:
                wait = min(authority.poll_seconds, remaining - floor - expected)
            elif attempted:
                wait = max(0.0, remaining)  # the last attempt was made: wait out the deadline
            else:
                wait = 0.0
            if wait > 0:
                try:
                    await asyncio.wait_for(stopped.wait(), timeout=wait)
                    return
                except asyncio.TimeoutError:
                    pass
                if attempted and wait >= remaining:
                    continue
            started = loop.time()
            attempted = True

            def unverified_now() -> None:
                # Recorded at the deadline, before the stalled poll is unwound.
                if signal.reason is None:
                    signal.record(UNVERIFIED)
                    on_interrupt(UNVERIFIED)
            try:
                reason = await bounded_check(authority.poll(action),
                                             max(confirmed_at + tolerance - started, floor),
                                             on_timeout=unverified_now)
                confirmed_at, attempted = started, False
                expected = loop.time() - started
            except AuthorityCheckTimeout:
                reason = UNVERIFIED
            except Exception:
                continue  # unknown, not revoked: the deadline above decides
        if reason is not None and signal.reason is None:
            try:
                reason = CapabilityResultReason(reason).value
            except ValueError:
                reason = UNVERIFIED
            signal.record(reason)
            on_interrupt(reason)


async def stop_task(task: "asyncio.Task[Any] | None") -> None:
    if task is None:
        return
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
