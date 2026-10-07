"""Names without an address record are explained, skipped by discovery, and traded for their twin.

Observed on a 2.5.4 deployment: ``example.net`` resolves, subdomain discovery then added
``www.example.net`` -- a name certificate transparency knows but DNS has no A/AAAA record for.
It showed as an ordinary target with a Scan button; Scan admission refused it with
"Scan target DNS resolution failed" and the targets page said only "Failed to start scan".

* Scan admission says which name does not resolve and names the www/apex twin that does,
  without relaxing the destination policy for either.
* Discovery does not insert names the resolver says have no address; it records them.
* Adding ``example.com`` whose only address is on ``www.example.com`` (or the reverse) registers
  the name that resolves and says so.

Every lookup here is a fixture; nothing touches the network.
"""
from __future__ import annotations

import asyncio
import json
import socket
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))
sys.path.insert(1, str(ROOT / "scanner"))

import target_resolution

# The real resolver entry point, captured before the suite's hermetic fixture replaces it; the
# admission tests below drive it through a fixture event-loop getaddrinfo.
REAL_SYSTEM_LOOKUP = target_resolution.system_lookup
NXDOMAIN = socket.gaierror(socket.EAI_NONAME, "nodename nor servname provided, or not known")
RESOLVER_DOWN = socket.gaierror(socket.EAI_AGAIN, "Temporary failure in name resolution")


def _lookup(table):
    """A fixture resolver: ``table[name]`` is a list of addresses or an exception to raise."""
    seen: list[str] = []

    async def lookup(hostname):
        seen.append(hostname)
        answer = table.get(hostname, NXDOMAIN)
        if isinstance(answer, BaseException):
            raise answer
        return list(answer)

    lookup.seen = seen
    return lookup


# ------------------------------------------------------------------------------ the classifier


def test_lookup_distinguishes_no_record_from_resolver_fault():
    lookup = _lookup({"ok.example.com": ["203.0.113.10"], "down.example.com": RESOLVER_DOWN})

    assert asyncio.run(target_resolution.lookup_host("ok.example.com", lookup=lookup)) == (
        target_resolution.RESOLVES, ["203.0.113.10"],
    )
    assert asyncio.run(target_resolution.lookup_host("gone.example.com", lookup=lookup))[0] == (
        target_resolution.NO_ADDRESS
    )
    assert asyncio.run(target_resolution.lookup_host("down.example.com", lookup=lookup))[0] == (
        target_resolution.UNKNOWN
    ), "a resolver fault says nothing about the name and must not be read as 'no record'"


def test_an_empty_answer_is_no_record_and_a_slow_resolver_is_unknown():
    async def empty(_hostname):
        return []

    async def slow(_hostname):
        await asyncio.sleep(5)
        return ["203.0.113.10"]

    assert asyncio.run(target_resolution.lookup_host("x.example.com", lookup=empty))[0] == (
        target_resolution.NO_ADDRESS
    )
    assert asyncio.run(
        target_resolution.lookup_host("x.example.com", lookup=slow, timeout=0.01)
    )[0] == target_resolution.UNKNOWN


def test_address_literals_never_reach_the_resolver():
    lookup = _lookup({})
    assert asyncio.run(target_resolution.lookup_host("192.0.2.7", lookup=lookup)) == (
        target_resolution.RESOLVES, ["192.0.2.7"],
    )
    assert lookup.seen == []


@pytest.mark.parametrize(
    ("host", "twin"),
    [
        ("example.com", "www.example.com"),
        ("www.example.com", "example.com"),
        ("WWW.Example.com.", "example.com"),
        ("www.example.co.uk", "example.co.uk"),
        ("example.co.uk", "www.example.co.uk"),
        ("api.example.com", "www.api.example.com"),
        ("juice-shop", None),
        ("www.com", None),
        ("203.0.113.9", None),
        ("", None),
    ],
)
def test_www_twin(host, twin):
    assert target_resolution.www_twin(host) == twin


def test_dns_alias_lookup_uses_the_targets_table_host_and_port_identity():
    assert target_resolution.canonical_web_key("https://example.com") == "web:example.com"
    assert target_resolution.canonical_web_key("http://example.com:80") == "web:example.com"
    assert target_resolution.canonical_web_key("https://example.com:8443") == "web:example.com:8443"


def test_the_message_names_the_host_and_the_twin_that_works():
    assert target_resolution.unresolvable_message("www.example.net") == (
        "www.example.net does not resolve in DNS (no A/AAAA record), so it cannot be scanned."
    )
    message = target_resolution.unresolvable_message("www.example.net", twin="example.net")
    assert message.endswith("example.net does resolve; use example.net instead.")


# ------------------------------------------------------------------------- www/apex on creation


@pytest.mark.parametrize(
    ("url", "table", "expected_url"),
    [
        ("https://example.com", {"www.example.com": ["203.0.113.10"]}, "https://www.example.com"),
        ("http://www.example.com:8080/app", {"example.com": ["203.0.113.10"]}, "http://example.com:8080/app"),
    ],
)
def test_the_resolving_twin_is_preferred(url, table, expected_url):
    fallback = asyncio.run(target_resolution.prefer_resolving_twin(url, lookup=_lookup(table)))
    assert fallback is not None
    assert fallback["resolved_url"] == expected_url
    assert fallback["reason"] == "no_address_record"
    assert fallback["message"] == (
        f"{fallback['requested_host']} has no address record; using {fallback['resolved_host']}."
    )


@pytest.mark.parametrize(
    "table",
    [
        # The name resolves: nothing to do, and the twin is not even asked.
        {"example.com": ["203.0.113.10"], "www.example.com": ["203.0.113.11"]},
        # The resolver failed: never rewrite what the operator typed on a fault.
        {"example.com": RESOLVER_DOWN, "www.example.com": ["203.0.113.11"]},
        # Neither resolves: keep the name; admission will explain it.
        {},
    ],
)
def test_no_twin_is_chosen_unless_the_name_has_no_record_and_the_twin_resolves(table):
    lookup = _lookup(table)
    assert asyncio.run(
        target_resolution.prefer_resolving_twin("https://example.com", lookup=lookup)
    ) is None
    if table.get("example.com") and not isinstance(table["example.com"], BaseException):
        assert lookup.seen == ["example.com"]


def test_replace_host_keeps_scheme_lessness_port_and_path():
    assert target_resolution.replace_host("example.com", "www.example.com") == "www.example.com"
    assert target_resolution.replace_host("example.com:8443/x", "www.example.com") == "www.example.com:8443/x"
    assert target_resolution.replace_host("https://example.com/a?b=1", "www.example.com") == (
        "https://www.example.com/a?b=1"
    )


# --------------------------------------------------------------------------------- discovery


class _DiscoveryConn:
    def __init__(self, existing=()):
        self.inserted: list[tuple] = []
        self.existing = set(existing)

    async def execute(self, query, *args):
        assert "INSERT INTO targets" in query
        self.inserted.append(args)
        return "INSERT 0 0" if args[0] in self.existing else "INSERT 0 1"


def test_discovery_skips_names_without_an_address_record():
    lookup = _lookup({
        "example.net": ["203.0.113.10"],
        "api.example.net": ["203.0.113.12"],
        "old.example.net": ["203.0.113.13"],
        "flaky.example.net": RESOLVER_DOWN,
        # www.example.net and mail.example.net: no record.
    })
    names = [
        "www.example.net", "api.example.net", "mail.example.net",
        "flaky.example.net", "old.example.net", "API.example.net",
    ]
    plan = asyncio.run(target_resolution.plan_discovered_targets(names, lookup=lookup))
    conn = _DiscoveryConn(existing={"https://old.example.net"})
    outcome = asyncio.run(target_resolution.store_discovered_targets(conn, plan, "example.net"))

    inserted = [args[0] for args in conn.inserted]
    assert "https://www.example.net" not in inserted
    assert "https://mail.example.net" not in inserted
    # A resolver fault keeps the name, as before: a broken resolver must not empty the inventory.
    assert inserted == [
        "https://api.example.net", "https://flaky.example.net", "https://old.example.net",
    ]
    assert all(args[1:] == ("example.net", "subfinder") for args in conn.inserted)
    assert outcome == {
        "checked": 5,
        "scannable": 3,
        "added": 2,
        "unresolved_count": 2,
        "unresolved": ["www.example.net", "mail.example.net"],
        "unknown_count": 1,
        "insert_failed": 0,
    }


def test_discovery_resolution_is_bounded():
    active = 0
    peak = 0

    async def lookup(_hostname):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0.001)
        active -= 1
        return ["203.0.113.10"]

    names = [f"h{index}.example.com" for index in range(400)]
    plan = asyncio.run(target_resolution.plan_discovered_targets(names, lookup=lookup))
    assert len(plan["scannable"]) == target_resolution.DISCOVERY_RESOLVE_LIMIT
    assert peak <= target_resolution.DISCOVERY_CONCURRENCY

    conn = _DiscoveryConn()
    outcome = asyncio.run(target_resolution.store_discovered_targets(conn, plan, "example.com"))
    assert len(conn.inserted) == target_resolution.DISCOVERY_TARGET_LIMIT
    assert outcome["added"] == target_resolution.DISCOVERY_TARGET_LIMIT


def test_the_discovery_route_lifts_the_outcome_out_of_sources_used():
    outcome = {"added": 1, "unresolved_count": 2, "unresolved": ["www.a.example"]}
    row = {"id": "d1", "sources_used": json.dumps({"subfinder": 3, "dns_resolution": outcome})}
    public = target_resolution.public_discovery_run(row)
    assert public["resolution"] == outcome
    assert public["sources_used"] == {"subfinder": 3}

    legacy = target_resolution.public_discovery_run({"id": "d0", "sources_used": {"subfinder": 3}})
    assert legacy["resolution"] is None
    assert legacy["sources_used"] == {"subfinder": 3}


# ---------------------------------------------------------------------------- Scan admission


def _patch_system_resolver(monkeypatch, table):
    """Answer the event loop's getaddrinfo from ``table`` (addresses or an exception)."""

    async def getaddrinfo(self, host, port, *args, **kwargs):
        answer = table.get(host, NXDOMAIN)
        if isinstance(answer, BaseException):
            raise answer
        return [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, port or 0))
            for address in answer
        ]

    monkeypatch.setattr(asyncio.base_events.BaseEventLoop, "getaddrinfo", getaddrinfo)
    monkeypatch.setattr(target_resolution, "system_lookup", REAL_SYSTEM_LOOKUP)


def _admission_detail(url, *, subject="Scan target", environment="production"):
    import fleet_routes.router as fleet_router
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as refused:
        asyncio.run(fleet_router._resolve_runtime_target_addresses(
            url, subject=subject, environment=environment,
        ))
    assert refused.value.status_code == 422
    return refused.value.detail


def test_admission_names_the_host_and_the_twin_that_resolves(monkeypatch):
    _patch_system_resolver(monkeypatch, {"example.net": ["203.0.113.10"]})
    assert _admission_detail("https://www.example.net") == (
        "www.example.net does not resolve in DNS (no A/AAAA record), so it cannot be scanned. "
        "example.net does resolve; use example.net instead."
    )


def test_admission_without_a_twin_still_says_why(monkeypatch):
    _patch_system_resolver(monkeypatch, {})
    assert _admission_detail("https://www.example.net") == (
        "www.example.net does not resolve in DNS (no A/AAAA record), so it cannot be scanned."
    )
    assert _admission_detail("https://www.example.net", subject="Hunt target").endswith(
        "so it cannot be tested."
    )


def test_admission_never_suggests_a_twin_the_destination_policy_refuses(monkeypatch):
    """A twin that resolves only to the metadata address is not offered as the way forward."""
    _patch_system_resolver(monkeypatch, {"example.net": ["169.254.169.254"]})
    detail = _admission_detail("https://www.example.net")
    assert "use example.net" not in detail
    assert detail.startswith("www.example.net does not resolve in DNS")


def test_a_resolver_fault_keeps_the_old_refusal(monkeypatch):
    _patch_system_resolver(monkeypatch, {"www.example.net": RESOLVER_DOWN})
    assert _admission_detail("https://www.example.net") == "Scan target DNS resolution failed"


def test_the_destination_policy_is_unchanged(monkeypatch):
    """A name resolving only to the metadata address is refused exactly as before."""
    _patch_system_resolver(monkeypatch, {"meta.example.com": ["169.254.169.254"]})
    assert _admission_detail("https://meta.example.com") == (
        "Scan target resolves only to addresses this deployment does not allow: "
        "169.254.169.254 is a cloud metadata or platform-service address, which is never "
        "scanned in any environment."
    )


# ------------------------------------------------------------------- the discovery worker job


def test_the_discovery_job_inserts_only_resolving_names_and_records_the_rest(monkeypatch):
    import uuid

    import worker

    executed: list[tuple[str, tuple]] = []

    class Conn:
        async def execute(self, query, *args):
            executed.append((" ".join(query.split()), args))
            return "INSERT 0 1" if "INSERT INTO targets" in query else "UPDATE 1"

    class Pool:
        def acquire(self):
            class _Acquire:
                async def __aenter__(self_inner):
                    return Conn()

                async def __aexit__(self_inner, *exc):
                    return False

            return _Acquire()

    class Redis:
        def hset(self, *args, **kwargs):
            return None

        def expire(self, *args):
            return None

    async def run_discovery(root_domain):
        assert root_domain == "example.net"
        return {
            "subdomains": ["www.example.net", "shop.example.net"],
            "by_source": {"subfinder": 2},
            "total": 2,
        }

    monkeypatch.setattr(worker, "db_pool", Pool())
    monkeypatch.setattr(worker, "get_redis", lambda: Redis())
    monkeypatch.setattr(worker, "run_discovery", run_discovery)
    monkeypatch.setattr(
        target_resolution, "system_lookup", _lookup({"shop.example.net": ["203.0.113.20"]}),
    )

    discovery_id = str(uuid.uuid4())
    asyncio.run(worker.process_discovery_job({
        "job_id": "job-discovery-1", "discovery_id": discovery_id, "root_domain": "example.net",
    }))

    inserts = [args for query, args in executed if query.startswith("INSERT INTO targets")]
    assert inserts == [("https://shop.example.net", "example.net", "subfinder")]
    completed = [args for query, args in executed if "status = 'completed'" in query]
    assert len(completed) == 1
    found, added, result_json, sources_json = completed[0][:4]
    assert (found, added) == (2, 1)
    assert json.loads(result_json) == ["www.example.net", "shop.example.net"]
    sources = json.loads(sources_json)
    assert sources["subfinder"] == 2
    assert sources["dns_resolution"]["unresolved"] == ["www.example.net"]
    assert sources["dns_resolution"]["added"] == 1


# ------------------------------------------------------------------ the twin must be admitted


def test_a_twin_the_policy_refuses_is_not_chosen():
    lookup = _lookup({"www.example.com": ["169.254.169.254"]})

    async def production():
        return "production"

    assert asyncio.run(target_resolution.prefer_resolving_twin(
        "https://example.com", environment_of=production, lookup=lookup,
    )) is None


def test_the_environment_is_consulted_only_when_a_swap_is_in_question():
    asked: list[bool] = []

    async def environment_of():
        asked.append(True)
        return "production"

    lookup = _lookup({"example.com": ["93.184.215.14"], "www.example.com": ["93.184.215.14"]})
    assert asyncio.run(target_resolution.prefer_resolving_twin(
        "https://example.com", environment_of=environment_of, lookup=lookup,
    )) is None
    assert asked == [], "a name that resolves costs one lookup and no database read"


def test_scan_fallback_without_a_database_judges_under_production(monkeypatch):
    monkeypatch.setenv("SHAKERSCAN_PRIVATE_NETWORK_TARGETS", "refuse")
    monkeypatch.setattr(target_resolution, "system_lookup", _lookup({"www.example.com": ["10.0.0.5"]}))
    assert asyncio.run(target_resolution.scan_target_dns_fallback("https://example.com", None)) == (
        "https://example.com", None,
    )
    monkeypatch.setattr(target_resolution, "system_lookup", _lookup({"www.example.com": ["93.184.215.14"]}))
    url, fallback = asyncio.run(target_resolution.scan_target_dns_fallback("https://example.com", None))
    assert url == "https://www.example.com"
    assert fallback["message"] == "example.com has no address record; using www.example.com."


def test_one_deadline_bounds_the_whole_discovery_check():
    """A dead resolver cost every name its full lookup timeout. With a deadline the names it
    leaves unjudged are listed as not checked and, like any resolver fault, stay scannable."""
    async def hangs(_hostname):
        await asyncio.sleep(30)
        return []

    names = [f"h{index}.example.com" for index in range(40)]
    started = time.monotonic()
    plan = asyncio.run(target_resolution.plan_discovered_targets(
        names, lookup=hangs, deadline_seconds=0.2,
    ))
    assert time.monotonic() - started < 2.0
    assert len(plan["not_checked"]) == 40
    assert len(plan["scannable"]) == 40 and plan["unresolved"] == []
    assert plan["submitted_count"] == 40
    assert plan["resolve_limit"] == target_resolution.DISCOVERY_RESOLVE_LIMIT
