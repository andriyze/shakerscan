"""Unit-test fixture: a Python mirror of ``api/domain_rate.py``'s three ledger Lua scripts.

It is a *fixture*, not evidence that the Lua is right: ``tests/test_domain_rate.py`` runs the same
scenarios against this mirror and, when ``SHAKERSCAN_TEST_REDIS_URL`` points at a disposable Redis,
against the real scripts, so the two cannot silently drift. The clock is explicit (``now_ms``)
where the real scripts read the Redis server clock.
"""

from __future__ import annotations

from typing import Any


class DomainRateLedgerFake:
    def __init__(self, now_ms: int = 1_800_000_000_000) -> None:
        self.now_ms = int(now_ms)
        self.expiry: dict[str, dict[str, float]] = {}
        self.units: dict[str, dict[str, int]] = {}

    def advance(self, seconds: float) -> None:
        self.now_ms += int(seconds * 1000)

    @staticmethod
    def handles(script: Any) -> bool:
        return "shakerscan:domain_rate:" in str(script)

    def entries(self, root_domain: str) -> dict[str, int]:
        from domain_rate import ledger_keys

        return {key: value for key, value in self.units.get(ledger_keys(root_domain)[1], {}).items()
                if value > 0}

    def eval(self, script: str, _numkeys: int, *args: Any) -> Any:
        zkey, hkey, *argv = args
        expiry = self.expiry.setdefault(zkey, {})
        units = self.units.setdefault(hkey, {})
        now = self.now_ms
        for member, score in list(expiry.items()):
            if score <= now:
                del expiry[member]
                units.pop(member, None)
        used = sum(units.values())
        if "shakerscan:domain_rate:reserve" in script:
            entry, requested, headroom, ttl_ms, all_or_nothing, enforce = argv
            hold = f"h:{entry}"
            requested, headroom = int(requested), int(headroom)
            existing = units.get(hold, 0)
            total = existing
            if requested > existing:
                need = requested - existing
                grant = need
                if str(enforce) != "0":
                    free = max(0, headroom - used)
                    grant = min(grant, free)
                    if str(all_or_nothing) == "1" and grant < need:
                        grant = 0
                total = existing + grant
            if total > 0:
                units[hold] = total
                expiry[hold] = now + int(ttl_ms)
            return [total, used - existing + total]
        if "shakerscan:domain_rate:settle" in script:
            entry, consumed, window_ms, settled_ms, finalized = argv
            hold = f"h:{entry}"
            done = f"d:{entry}"
            used_entry = f"c:{entry}"
            if done in units:
                return [0, units.get(used_entry, 0)]
            held = units.pop(hold, 0)
            expiry.pop(hold, None)
            consumed = int(consumed)
            if consumed < 0:
                consumed = held
            if consumed > 0:
                units[used_entry] = consumed
                expiry[used_entry] = now + int(window_ms)
            if str(finalized) == "1":
                units[done] = 0
                expiry[done] = now + int(settled_ms)
            return [held, consumed]
        if "shakerscan:domain_rate:usage" in script:
            schedule: list[int] = []
            for member, score in sorted(expiry.items(), key=lambda item: item[1]):
                schedule.extend([int(score), units.get(member, 0)])
            return [now, used, schedule]
        raise AssertionError("unknown domain-rate script")
