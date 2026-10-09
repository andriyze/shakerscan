"""The CT monitor adds targets only on label boundaries, never for a public suffix, deduplicated
and at most a daily cap per apex (unit tests with fixture callables; no gungnir, DB or Redis)."""

from __future__ import annotations

import asyncio
from datetime import date
import importlib.util
from pathlib import Path
import sys
import types

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def gungnir(monkeypatch):
    monkeypatch.setitem(sys.modules, "redis", types.SimpleNamespace(Redis=object, from_url=lambda *_a, **_k: None))
    monkeypatch.setitem(sys.modules, "asyncpg", types.SimpleNamespace(create_pool=None))
    monkeypatch.syspath_prepend(str(ROOT / "api"))
    spec = importlib.util.spec_from_file_location("gungnir_bounds_under_test", ROOT / "api" / "gungnir_worker.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FixtureRedis:
    def __init__(self):
        self.counts: dict[str, int] = {}

    def hincrby(self, key, field, amount):
        assert key == "gungnir:suppressed"
        self.counts[field] = self.counts.get(field, 0) + amount


class Day:
    def __init__(self, value: date):
        self.value = value

    def __call__(self):
        return self.value


def run(gungnir, lines, roots, *, cap=3, already_today=0, existing=(), day=None):
    stored: list[tuple[str, str]] = []
    redis_client = FixtureRedis()
    clock = day or Day(date(2026, 10, 9))

    async def store(subdomain, root):
        if subdomain in existing:
            return False
        stored.append((subdomain, root))
        return True

    async def count_today(_apex, _day):
        return already_today

    limiter = gungnir.ApexDailyCap(cap, today=clock)
    seen: set[str] = set()

    async def go():
        return [await gungnir.handle_ct_name(line, roots, seen, limiter, store=store,
                                             count_today=count_today, redis_client=redis_client)
                for line in lines]

    return asyncio.run(go()), stored, redis_client, limiter


@pytest.mark.parametrize(("line", "name"), [
    ("A.Example.com\n", "a.example.com"), ("*.dev.example.com", "dev.example.com"),
    ("x.example.com.", "x.example.com"), ("a.*.example.com", None), ("*.*.example.com", None),
    ("*", None), ("", None), ("1.2.3.4", None), ("bad_label.example.com", None),
    ("-x.example.com", None), ("a" * 64 + ".example.com", None), ("com", None),
])
def test_ct_names_are_valid_hosts_and_a_leading_wildcard_names_its_parent(gungnir, line, name):
    assert gungnir.ct_name(line) == name


def test_public_suffix_roots_are_never_monitored(gungnir):
    assert gungnir.monitored_roots(["co.uk", "example.co.uk", "github.io", "Example.co.uk.", "com", ""]) == [
        "example.co.uk",
    ]


def test_names_are_matched_on_dot_boundaries_and_deduplicated(gungnir):
    outcomes, stored, _redis, _cap = run(gungnir, [
        "a.example.com", "evilexample.com", "a.example.com", "*.a.example.com", "x.other.test",
        "b.example.com", "*.example.com",
    ], ["example.com"], cap=10, existing={"b.example.com"})
    assert outcomes == ["added", "out_of_scope", "duplicate", "duplicate", "out_of_scope", "existing",
                        "out_of_scope"]
    assert stored == [("a.example.com", "example.com")]


def test_new_targets_stop_at_the_daily_cap_per_apex_and_suppressed_names_are_counted(gungnir):
    lines = [f"h{index}.example.com" for index in range(5)] + ["a.eu.example.com", "a.other.test"]
    outcomes, stored, redis_client, limiter = run(
        gungnir, lines, ["example.com", "eu.example.com", "other.test"], cap=3,
    )
    # eu.example.com shares the example.com apex and its cap; other.test has its own.
    assert outcomes == ["added", "added", "added", "suppressed", "suppressed", "suppressed", "added"]
    assert [name for name, _root in stored] == ["h0.example.com", "h1.example.com", "h2.example.com", "a.other.test"]
    assert redis_client.counts == {"2026-10-09:example.com": 3}
    assert limiter.suppressed == {"example.com": 3}
    assert gungnir.stats["suppressed_count"] == 3


def test_the_cap_counts_targets_already_added_today_and_resets_the_next_day(gungnir):
    clock = Day(date(2026, 10, 9))
    outcomes, stored, _redis, limiter = run(gungnir, ["a.example.com"], ["example.com"], cap=100,
                                           already_today=100, day=clock)
    assert outcomes == ["suppressed"] and stored == []
    clock.value = date(2026, 10, 10)

    async def count_today(_apex, day):
        assert day == date(2026, 10, 10)
        return 0

    async def store(_subdomain, _root):
        return True

    outcome = asyncio.run(gungnir.handle_ct_name("b.example.com", ["example.com"], set(), limiter,
                                                 store=store, count_today=count_today,
                                                 redis_client=FixtureRedis()))
    assert outcome == "added" and limiter.suppressed == {}


@pytest.mark.parametrize(("raw", "cap"), [("", 100), ("25", 25), ("0", 0), ("junk", 100), ("999999", 10_000)])
def test_daily_cap_is_configurable(gungnir, monkeypatch, raw, cap):
    monkeypatch.setenv("SHAKERSCAN_CT_MONITOR_DAILY_CAP", raw)
    assert gungnir.daily_cap() == cap


def test_a_legacy_public_suffix_root_keeps_monitoring_under_the_customers_domain(gungnir):
    # targets.root_domain still holds the pre-2.8.1 two-label root (the startup migration has not
    # run yet): monitoring continues for example.co.uk and never covers co.uk.
    class Conn:
        async def fetch(self, query, *args):
            if "DISTINCT root_domain" in query:
                return [{"root_domain": "co.uk"}, {"root_domain": "example.com"}, {"root_domain": "github.io"}]
            assert sorted(args[0]) == ["co.uk", "github.io"]
            return [{"root_domain": "co.uk", "url": "https://shop.example.co.uk"},
                    {"root_domain": "co.uk", "url": "https://example.co.uk"},
                    {"root_domain": "github.io", "url": "https://victim.github.io"},
                    {"root_domain": "co.uk", "url": "https://co.uk"}]

    class Pool:
        def acquire(self):
            class Acquire:
                async def __aenter__(self):
                    return Conn()

                async def __aexit__(self, *exc):
                    return False

            return Acquire()

    gungnir.db_pool = Pool()
    roots = gungnir.monitored_roots(asyncio.run(gungnir.get_monitored_domains()))
    assert roots == ["example.com", "example.co.uk", "victim.github.io"]
    assert gungnir.match_root_domain("new.example.co.uk", roots) == "example.co.uk"
    assert gungnir.match_root_domain("shop.other.co.uk", roots) is None


@pytest.mark.parametrize("root", ["amazonaws.com", "kawasaki.jp", "crm.dev"])
def test_roots_with_public_suffixes_below_are_not_monitored(gungnir, root):
    assert gungnir.monitored_roots([root, "example.com"]) == ["example.com"]
