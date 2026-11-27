"""Bounded concurrency across the SQLi candidates of one verification slice.

On a slow target the SQLi lane is latency-bound, not rate-bound. sqlmap runs one thread and
waits for every response, so on soak target honey (about 3.4 s per response) one candidate
sends about 0.29 requests a second while its slice's pacing contract allows about 1 a second:
soak scan 44e393ba spent 2,580 tool-wall seconds on 731 SQLi requests, one candidate at a time,
and the Scan's 3,600-second limit stopped it with no verdict. Running several candidates of a
slice at once sends the same requests at no higher aggregate rate than the slice's contract;
it only stops the lane idling while one response is in flight.

What bounds it:

* **Slots.** At most ``candidate_concurrency`` candidates run at once. The planner sets it from
  the Scan budget's ``max_workers`` (the profile's worker ceiling, lowered by an advanced limit
  or ``force_single_worker``) and :data:`MAX_CONCURRENT_CANDIDATES`; a plan compiled before this
  argument existed runs one at a time. Within that, the slots are sized from the pacing
  contract (:func:`concurrent_slot_count`): only as many candidates as the slice's rate ceiling
  covers at the measured response time. Before anything on the target was measured, one runs.
* **Rate.** One :class:`RequestRateGate` per slice spaces the start of every request of every
  concurrent candidate at least ``1 / rate`` apart. The pinned transport awaits it before it
  opens each connection to the target, and sqlmap opens one connection per request, so the
  aggregate rate of the slice stays at or below its ceiling whatever the target's latency does.
  The ceiling (:func:`slice_rate_ceiling`) is the rate one attempt of this slice was already
  paced to when candidates ran one at a time: the attempt's hold spread across its wall, less
  the same headroom. Concurrency adds no rate; it fills the time one candidate spends waiting.
* **Budget.** Every candidate's hold is carved from what the slice has neither consumed nor
  already lent to a running candidate, before it sends anything (:class:`SliceHolds`), so the
  holds of concurrent candidates never add up to more than the slice's reservation. Each is
  settled once, from the attempt's own traffic accounting, and its unspent part returns to the
  slice.
* **Tool wall is elapsed time.** Requests and mutations are volumes, so concurrent holds are
  summed. Tool wall is the time the slice holds the lane: the budget contract keeps every
  profile's ``max_tool_wall_seconds`` at or below its ``max_duration_seconds`` ("tool wall never
  exceeds total wall"; Balanced and Thorough set them equal) for a Scan whose orchestrator runs
  one action at a time, so a tool second is a second of the Scan. Charging
  each concurrent process its own seconds (soak N40, 43b9a549) billed two candidates running
  side by side at twice real time: the Thorough plan's 10,800 s ran out at 43% of the Scan,
  with 3 of 4 candidates unfinished and 25,295 requests unused. The slice is charged the
  union of the intervals in which any of its candidates ran (:meth:`ConcurrentCandidates.
  busy_seconds`), a running candidate's wall hold is not lent away from the others (they
  overlap in time; each still ends inside the slice's wall), and every sqlmap process remains
  bounded by its own hold. The request gate, not the wall, is what keeps concurrency from
  adding load.

A candidate that cannot be funded while others hold budget waits for one to settle; it is
reported unfunded only when nothing is running. Cancellation reaches every running candidate
through the same cancel callback the process runner polls.
"""

from __future__ import annotations

import asyncio
import math
import time
from collections.abc import Awaitable, Callable, Iterable, Mapping

from .external_process import BATCH_ATTEMPT_REQUEST_HEADROOM

# The most candidates of one slice that run at once, whatever the profile's worker ceiling.
# Each is a sqlmap process; four keeps the worker inside its memory ceiling.
MAX_CONCURRENT_CANDIDATES = 4
# The capability argument that carries the planner's concurrency bound for a slice.
CANDIDATE_CONCURRENCY_ARG = "candidate_concurrency"
# The smallest delay a paced attempt keeps between requests (the batch attempt's floor).
_MINIMUM_DELAY_SECONDS = 0.05
# Budget dimensions charged as the slice's elapsed time, not summed over concurrent candidates.
ELAPSED_DIMENSIONS = frozenset({"tool_wall_seconds"})


def elapsed_clock() -> float:
    """The clock a slice's elapsed tool time is measured on (tests substitute a virtual one)."""
    return time.monotonic()


def planned_candidate_concurrency(max_workers: int) -> int:
    """The concurrency bound the planner records on a SQLi slice for this Scan budget."""
    return max(1, min(MAX_CONCURRENT_CANDIDATES, int(max_workers or 1)))


def slice_rate_ceiling(
    budget: Mapping[str, int],
    *,
    candidates: int,
    floors: Iterable[Mapping[str, int]],
) -> float:
    """Requests per second the slice may send in aggregate: one sequential attempt's paced rate.

    Run one at a time, the slice's first attempt holds the larger of its class floor and an even
    share of each hold (a body attempt's requests bounded by its mutation hold), and is paced to
    send that many across that wall less the headroom. ``floors`` holds the floor of every
    candidate class in the slice; the ceiling is the fastest of those attempts. Concurrent
    candidates together never send faster than one of them alone was already allowed to, and a
    candidate that runs alone is never slowed by the gate.
    """
    count = max(1, int(candidates or 1))
    ceiling = 0.0
    for floor in floors:
        def share(name: str) -> int:
            hold = int(budget.get(name) or 0)
            return min(hold, max(int(floor.get(name) or 0), hold // count))

        wall = share("tool_wall_seconds")
        requests = share("http_requests")
        if int(floor.get("state_changing_requests") or 0) > 0:
            # Every request of a body attempt is a mutation; the mutation hold bounds them.
            requests = min(requests, share("state_changing_requests"))
        if wall > 0 and requests > 0:
            ceiling = max(ceiling, BATCH_ATTEMPT_REQUEST_HEADROOM * requests / wall)
    return ceiling


def concurrent_slot_count(
    *, bound: int, rate_ceiling: float, latency_seconds: float | None,
) -> int:
    """How many candidates may run at once within ``bound`` and the slice's rate ceiling.

    One sqlmap candidate sends at most one request per (response time + its minimum delay).
    The slots are as many such candidates as the ceiling covers, so on a fast target -- where
    one candidate already reaches the ceiling -- nothing changes, and on a slow one the slots
    fill the time spent waiting for responses. With no measurement yet, one candidate runs.
    """
    bound = max(1, int(bound or 1))
    if bound == 1 or not latency_seconds or latency_seconds <= 0 or rate_ceiling <= 0:
        return 1
    covered = math.floor(rate_ceiling * (float(latency_seconds) + _MINIMUM_DELAY_SECONDS))
    return max(1, min(bound, covered))


class RequestRateGate:
    """Space request starts across every concurrent candidate of one slice.

    Awaited by the pinned transport before each connection to the target. Each caller takes
    the next start time and waits for it, so ``n`` starts span at least ``(n - 1) / rate``
    seconds. Taking a start time involves no await, so concurrent callers cannot share one.
    """

    def __init__(
        self,
        rate_per_second: float,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        if not rate_per_second or rate_per_second <= 0 or not math.isfinite(rate_per_second):
            raise ValueError("request rate gate needs a positive finite rate")
        self.rate_per_second = float(rate_per_second)
        self.interval = 1.0 / self.rate_per_second
        self._clock = clock
        self._sleep = sleep
        self._next: float | None = None
        self.admitted = 0

    async def __call__(self) -> None:
        now = self._clock()
        start = now if self._next is None else max(now, self._next)
        self._next = start + self.interval
        self.admitted += 1
        if start > now:
            await self._sleep(start - now)


class SliceHolds:
    """The parts of one slice's reservation lent to candidates that are still running."""

    def __init__(self, reserved: Mapping[str, int]) -> None:
        self._reserved = {str(name): int(amount) for name, amount in reserved.items()}
        self._held: dict[str, dict[str, int]] = {}
        self.peak = 0

    def __len__(self) -> int:
        return len(self._held)

    def available(self, consumed: Mapping[str, int]) -> dict[str, int]:
        """What the slice has neither consumed nor lent to a running candidate.

        An elapsed dimension (tool wall) is never lent away: candidates that run at once spend
        the same seconds, so what is left of it is the reservation less the elapsed time
        already charged.
        """
        lent: dict[str, int] = {}
        for hold in self._held.values():
            for name, amount in hold.items():
                if name in ELAPSED_DIMENSIONS:
                    continue
                lent[name] = lent.get(name, 0) + amount
        return {
            name: max(0, limit - int(consumed.get(name, 0)) - lent.get(name, 0))
            for name, limit in self._reserved.items()
        }

    def lend(self, key: str, hold: Mapping[str, int], consumed: Mapping[str, int]) -> None:
        if key in self._held:
            raise ValueError("a candidate already holds part of this slice")
        available = self.available(consumed)
        if any(int(amount) > available.get(name, 0) for name, amount in hold.items()):
            raise ValueError("a candidate hold exceeds what the slice has left")
        self._held[key] = {str(name): int(amount) for name, amount in hold.items()}
        self.peak = max(self.peak, len(self._held))

    def settle(self, key: str) -> None:
        """Return a finished candidate's hold; its consumption is already counted."""
        self._held.pop(key, None)


class ConcurrentCandidates:
    """Run a slice's candidates in bounded slots; every slot's hold is lent before it starts."""

    def __init__(
        self,
        reserved: Mapping[str, int],
        *,
        bound: int,
        rate_ceiling: float,
        latency_seconds: float | None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.bound = max(1, int(bound or 1))
        self.rate_ceiling = float(rate_ceiling or 0.0)
        self.latency_seconds = latency_seconds
        self.holds = SliceHolds(reserved)
        self._running: dict[asyncio.Task[None], str] = {}
        self._capacity = asyncio.Event()
        self._clock = clock or elapsed_clock
        self._active = 0
        self._busy_since: float | None = None
        self._busy_total = 0.0

    def busy_seconds(self) -> float:
        """Elapsed seconds in which at least one candidate of the slice was running."""
        running = (
            self._clock() - self._busy_since
            if self._active and self._busy_since is not None else 0.0
        )
        return self._busy_total + max(0.0, running)

    def wall_shares(self, remaining_candidates: int) -> int:
        """How many successive turns ``remaining_candidates`` take in the current slots: the
        number of ways the slice's remaining wall is split, since candidates in one turn run
        in the same seconds."""
        return max(1, math.ceil(max(1, int(remaining_candidates)) / self.slots()))

    @property
    def running(self) -> int:
        return len(self._running)

    def slots(self) -> int:
        return concurrent_slot_count(
            bound=self.bound, rate_ceiling=self.rate_ceiling,
            latency_seconds=self.latency_seconds,
        )

    def measured(self, latency_seconds: float) -> None:
        """A finished stage measured the target's response time: the slots may grow."""
        if latency_seconds > 0:
            self.latency_seconds = float(latency_seconds)
            self._capacity.set()

    def launch(
        self,
        key: str,
        hold: Mapping[str, int],
        consumed: Mapping[str, int],
        work: Callable[[], Awaitable[None]],
    ) -> None:
        """Lend ``hold`` to a candidate, then start it. Its hold returns when it settles."""
        self.holds.lend(key, hold, consumed)

        async def run() -> None:
            if not self._active:
                self._busy_since = self._clock()
            self._active += 1
            try:
                await work()
            finally:
                self._active -= 1
                if not self._active and self._busy_since is not None:
                    self._busy_total += max(0.0, self._clock() - self._busy_since)
                    self._busy_since = None
                # ``work`` counts the candidate's consumption as its last step, with no await
                # after it, so the hold is never returned before or counted twice with it.
                self.holds.settle(key)

        self._running[asyncio.ensure_future(run())] = key

    async def wait(self) -> None:
        """Until a running candidate finishes or the target's latency changes the slots."""
        if not self._running:
            return
        waiter = asyncio.ensure_future(self._capacity.wait())
        try:
            done, _pending = await asyncio.wait(
                {*self._running, waiter}, return_when=asyncio.FIRST_COMPLETED,
            )
        finally:
            waiter.cancel()
        self._capacity.clear()
        for task in done:
            if task is not waiter:
                self._running.pop(task, None)
                task.result()

    async def finish(self) -> None:
        while self._running:
            await self.wait()

    async def abandon(self) -> None:
        """Stop every running candidate: the action itself is being cancelled or failed."""
        tasks = list(self._running)
        self._running.clear()
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
