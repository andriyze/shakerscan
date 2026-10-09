"""Wildcard DNS among discovered names is detected, recorded, and its echoes are not inserted.

A wildcard zone answers every name, so passive sources filled the 100 inserted-target slots with
names that were only the wildcard's echo. The planner now resolves random labels under the apex
and the parents the names sit under, and drops names whose answer is only the wildcard's unless a
certificate names them. Every resolver here is a labelled fixture; no test touches live DNS.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import re
import socket
import types

import pytest

from api import discovery_wildcards, target_resolution
from api.scan import subdomain_targets
from api.scan.action_plan import ScanActionPlan
from api.scan.finalizer import finalize_scan_report
from tests.test_scan_finalizer import _result_with_observation_count
from tests.test_scan_orchestrator import SCAN_ID, _action

APEX = "example.com"
NXDOMAIN = socket.gaierror(socket.EAI_NONAME, "no such name")
RESOLVER_DOWN = socket.gaierror(socket.EAI_AGAIN, "temporary failure")
PROBE = re.compile(r"^[0-9a-f]{16}\.")
WILDCARD_ADDRESS = "198.51.100.7"
# Captured at import, before the suite's hermetic fixture replaces it for each test.
_REAL_SYSTEM_ANSWER = target_resolution.system_answer


class FixtureResolver:
    """Answers from labelled fixtures.

    ``names``: name -> (addresses, cname) or an exception. ``wildcards``: parent -> the answer
    every random probe label below that parent (and below its unlisted descendants) receives,
    or an exception (``NXDOMAIN`` models a parent that exists without a wildcard).
    """

    def __init__(self, names=None, wildcards=None):
        self.names = dict(names or {})
        self.wildcards = dict(wildcards or {})
        self.asked: list[str] = []
        self.active = 0
        self.peak = 0

    async def __call__(self, hostname):
        self.asked.append(hostname)
        self.active += 1
        self.peak = max(self.peak, self.active)
        try:
            await asyncio.sleep(0)
            if PROBE.match(hostname):
                # As in DNS, the closest enclosing wildcard (or explicit absence) answers.
                parent = hostname.split(".", 1)[1]
                while parent not in self.wildcards and "." in parent:
                    parent = parent.split(".", 1)[1]
                answer = self.wildcards.get(parent, NXDOMAIN)
            else:
                answer = self.names.get(hostname, NXDOMAIN)
            if isinstance(answer, BaseException):
                raise answer
            addresses, cname = answer
            return list(addresses), cname
        finally:
            self.active -= 1

    @property
    def probes(self):
        return [name for name in self.asked if PROBE.match(name)]


def _plan(names, resolver, **kwargs):
    return asyncio.run(target_resolution.plan_discovered_targets(
        names, root_domain=APEX, answer=resolver, **kwargs,
    ))


def test_names_that_only_echo_a_wildcard_are_suppressed_and_the_wildcard_recorded():
    resolver = FixtureResolver(
        names={
            "a.dev.example.com": ([WILDCARD_ADDRESS], None),
            "b.dev.example.com": ([WILDCARD_ADDRESS], None),
            "real.dev.example.com": (["203.0.113.40"], None),
            "api.example.com": (["203.0.113.10"], None),
        },
        wildcards={"dev.example.com": ([WILDCARD_ADDRESS], None)},
    )
    plan = _plan(
        ["a.dev.example.com", "b.dev.example.com", "real.dev.example.com", "api.example.com"],
        resolver,
    )
    assert plan["wildcard_suppressed"] == ["a.dev.example.com", "b.dev.example.com"]
    assert plan["scannable"] == ["real.dev.example.com", "api.example.com"]
    assert plan["wildcards"] == [{
        "parent": "dev.example.com", "pattern": "*.dev.example.com",
        "addresses": [WILDCARD_ADDRESS], "cnames": [], "suppressed": 2,
    }]
    assert plan["wildcard_notes"] == ["wildcard DNS at *.dev.example.com; 2 names suppressed"]
    # The apex and the one distinct parent, PROBES_PER_PARENT random labels each.
    assert len(resolver.probes) == 2 * discovery_wildcards.PROBES_PER_PARENT
    assert {probe.split(".", 1)[1] for probe in resolver.probes} == {APEX, "dev.example.com"}


def test_a_certificate_keeps_a_name_the_wildcard_would_explain_away():
    resolver = FixtureResolver(
        names={
            "ct.dev.example.com": ([WILDCARD_ADDRESS], None),
            "sub.dev.example.com": ([WILDCARD_ADDRESS], None),
            "dns.dev.example.com": ([WILDCARD_ADDRESS], None),
        },
        wildcards={"dev.example.com": ([WILDCARD_ADDRESS], None)},
    )
    plan = _plan(
        ["ct.dev.example.com", "sub.dev.example.com", "dns.dev.example.com"], resolver,
        evidence={
            "ct.dev.example.com": ["gungnir"],
            "sub.dev.example.com": ["subfinder:crtsh"],
            # A DNS dataset is not a certificate: it may well have recorded the wildcard's echo.
            "dns.dev.example.com": ["subfinder:hackertarget"],
        },
    )
    assert plan["scannable"] == ["ct.dev.example.com", "sub.dev.example.com"]
    assert plan["wildcard_suppressed"] == ["dns.dev.example.com"]


def test_a_cname_wildcard_is_matched_by_its_target_even_when_addresses_rotate():
    resolver = FixtureResolver(
        names={
            "x.example.com": (["192.0.2.2"], "lb.wildhost.net"),
            "y.example.com": (["192.0.2.9"], "app.elsewhere.net"),
        },
        wildcards={APEX: (["192.0.2.1"], "lb.wildhost.net")},
    )
    plan = _plan(["x.example.com", "y.example.com"], resolver)
    assert plan["wildcard_suppressed"] == ["x.example.com"]
    assert plan["scannable"] == ["y.example.com"]
    assert plan["wildcards"][0]["cnames"] == ["lb.wildhost.net"]
    assert plan["wildcards"][0]["pattern"] == "*.example.com"


def test_a_parent_beyond_the_probe_limit_suppresses_nothing():
    """Only a judged immediate parent counts: names under parents that were never probed are
    kept, even though an ancestor (the apex) publishes a wildcard."""
    names = [f"h{index}.p{index:02d}.example.com" for index in range(12)]
    resolver = FixtureResolver(
        names={name: ([WILDCARD_ADDRESS], None) for name in names},
        wildcards={APEX: ([WILDCARD_ADDRESS], None)},
    )
    plan = _plan(names, resolver)
    # The parent set is bounded: the apex plus the most common parents, PARENT_LIMIT in all.
    assert len(resolver.probes) == (
        discovery_wildcards.PARENT_LIMIT * discovery_wildcards.PROBES_PER_PARENT
    )
    probed = {probe.split(".", 1)[1] for probe in resolver.probes}
    suppressed = set(plan["wildcard_suppressed"])
    assert suppressed == {name for name in names if name.split(".", 1)[1] in probed}
    assert len(suppressed) == discovery_wildcards.PARENT_LIMIT - 1
    assert set(plan["scannable"]) == set(names) - suppressed


def test_an_unjudged_closer_parent_suppresses_nothing():
    """A resolver fault on dev.example.com's probes never falls back to the apex wildcard."""
    resolver = FixtureResolver(
        names={"a.dev.example.com": ([WILDCARD_ADDRESS], None)},
        wildcards={APEX: ([WILDCARD_ADDRESS], None), "dev.example.com": RESOLVER_DOWN},
    )
    plan = _plan(["a.dev.example.com"], resolver)
    assert plan["wildcard_suppressed"] == []
    assert plan["scannable"] == ["a.dev.example.com"]


def test_a_real_host_sharing_one_address_of_a_rotating_wildcard_is_kept():
    """Review repro: wildcard rotating {.1, .2}; app's single A record is .1. Subset is not
    equality, so app stays."""
    answers = iter(["203.0.113.1", "203.0.113.2"] * 4)

    class Rotating(FixtureResolver):
        async def __call__(self, hostname):
            if PROBE.match(hostname) and hostname.endswith("." + APEX) and hostname.count(".") == 2:
                self.asked.append(hostname)
                return [next(answers)], None
            return await super().__call__(hostname)

    resolver = Rotating(names={
        "app.example.com": (["203.0.113.1"], None),
        "junk.example.com": (["203.0.113.1", "203.0.113.2"], None),
    })
    plan = _plan(["app.example.com", "junk.example.com"], resolver)
    assert plan["wildcards"][0]["addresses"] == ["203.0.113.1", "203.0.113.2"]
    assert "app.example.com" in plan["scannable"]
    assert plan["wildcard_suppressed"] == ["junk.example.com"]


def test_a_host_with_its_own_cname_ending_at_the_same_cdn_edge_is_kept():
    """Review repro: www aliases its own record, which ends at the same CDN edge as the
    wildcard's alias. The first hop differs, so www is not the wildcard's answer."""
    resolver = FixtureResolver(
        names={
            "www.example.com": (["198.51.100.20"], "www-example.cdn.net"),
            "junk.example.com": (["198.51.100.20"], "wildcard-example.cdn.net"),
        },
        wildcards={APEX: (["198.51.100.20"], "wildcard-example.cdn.net")},
    )
    plan = _plan(["www.example.com", "junk.example.com"], resolver)
    assert plan["scannable"] == ["www.example.com"]
    assert plan["wildcard_suppressed"] == ["junk.example.com"]


def test_an_unread_first_hop_is_never_an_echo():
    resolver = FixtureResolver(
        names={"a.example.com": ([WILDCARD_ADDRESS], target_resolution.UNKNOWN_HOP)},
        wildcards={APEX: ([WILDCARD_ADDRESS], None)},
    )
    assert _plan(["a.example.com"], resolver)["scannable"] == ["a.example.com"]


def test_no_wildcard_and_a_resolver_fault_suppress_nothing():
    names = {"a.example.com": ([WILDCARD_ADDRESS], None), "b.example.com": ([WILDCARD_ADDRESS], None)}
    clean = _plan(list(names), FixtureResolver(names=names))
    assert clean["wildcard_suppressed"] == [] and clean["wildcards"] == []
    assert clean["scannable"] == ["a.example.com", "b.example.com"]

    faulty = _plan(list(names), FixtureResolver(names=names, wildcards={APEX: RESOLVER_DOWN}))
    assert faulty["wildcard_suppressed"] == [] and faulty["wildcards"] == []


def test_a_closer_parent_without_a_wildcard_shields_its_names_from_the_apex_wildcard():
    resolver = FixtureResolver(
        names={"a.prod.example.com": ([WILDCARD_ADDRESS], None)},
        wildcards={APEX: ([WILDCARD_ADDRESS], None), "prod.example.com": NXDOMAIN},
    )
    plan = _plan(["a.prod.example.com"], resolver)
    assert plan["wildcard_suppressed"] == []
    assert plan["scannable"] == ["a.prod.example.com"]


def test_probes_share_the_lookup_bounds_and_the_deadline():
    names = [f"n{index}.example.com" for index in range(60)]

    async def hangs(hostname):
        await asyncio.sleep(30)
        return [], None

    plan = asyncio.run(target_resolution.plan_discovered_targets(
        names, root_domain=APEX, answer=hangs, deadline_seconds=0.2,
    ))
    assert plan["wildcards"] == [] and plan["wildcard_suppressed"] == []
    assert len(plan["not_checked"]) == 60

    resolver = FixtureResolver(names={name: (["203.0.113.5"], None) for name in names})
    _plan(names, resolver)
    assert resolver.peak <= target_resolution.DISCOVERY_CONCURRENCY


def test_without_a_root_domain_no_probe_is_sent():
    resolver = FixtureResolver(names={"a.example.com": (["203.0.113.5"], None)})
    asyncio.run(target_resolution.plan_discovered_targets(["a.example.com"], answer=resolver))
    assert resolver.probes == []


def test_storing_records_the_wildcard_and_inserts_no_echo():
    resolver = FixtureResolver(
        names={"a.dev.example.com": ([WILDCARD_ADDRESS], None), "api.example.com": (["203.0.113.10"], None)},
        wildcards={"dev.example.com": ([WILDCARD_ADDRESS], None)},
    )
    plan = _plan(["a.dev.example.com", "api.example.com"], resolver)
    inserted: list[str] = []

    class Conn:
        async def execute(self, query, *args):
            inserted.append(args[0])
            return "INSERT 0 1"

    outcome = asyncio.run(target_resolution.store_discovered_targets(Conn(), plan, APEX))
    assert inserted == ["https://api.example.com"]
    assert outcome["wildcard_suppressed_count"] == 1
    assert outcome["wildcard_suppressed"] == ["a.dev.example.com"]
    assert outcome["notes"] == ["wildcard DNS at *.dev.example.com; 1 names suppressed"]
    assert outcome["checked"] == 2


# --------------------------------------------------------------------------- the Scan path


def _report(hosts, sources=None):
    discover = _action("discover.subdomains", 0, capability_name="subdomains.discover")
    final = _action("finalize.report", 1, dependencies=(discover.action_id,))
    plan = ScanActionPlan(
        scan_id=SCAN_ID, execution_plan_digest="b" * 64, target_binding_digest="a" * 64,
        actions=(discover, final),
    )
    observations = {discover.action_id: tuple(
        {"kind": "subdomain", "host": host, "root_domain": APEX,
         **({"source": sources[host]} if sources and host in sources else {})}
        for host in hosts
    )}
    return finalize_scan_report(
        plan=plan, target_url=f"https://{APEX}",
        action_results={discover.action_id: _result_with_observation_count(discover, len(hosts))},
        observations=observations,
    )


def test_the_report_lists_which_source_named_each_host():
    section = _report(["a.example.com", "b.example.com"], {"a.example.com": "crtsh"})
    assert section["discovery"]["subdomains"]["sources"] == {"a.example.com": ["crtsh"]}


def test_the_scan_records_the_wildcard_in_its_partial_reasons_and_notes(monkeypatch):
    hosts = ["a.dev.example.com", "b.dev.example.com", "c.dev.example.com", "api.example.com"]
    resolver = FixtureResolver(
        names={
            **{name: ([WILDCARD_ADDRESS], None) for name in hosts[:3]},
            "api.example.com": (["203.0.113.10"], None),
        },
        wildcards={"dev.example.com": ([WILDCARD_ADDRESS], None)},
    )
    monkeypatch.setattr(target_resolution, "system_answer", resolver)
    report = _report(hosts, {"c.dev.example.com": "certspotter"})
    inserted: list[str] = []

    class Conn:
        async def fetchrow(self, query, *args):
            return None

        async def execute(self, query, *args):
            if "INSERT INTO targets" in query:
                inserted.append(args[0])
            return "INSERT 0 1"

    @asynccontextmanager
    async def acquire():
        yield Conn()

    outcome = asyncio.run(subdomain_targets.record_scan_subdomain_discovery(
        types.SimpleNamespace(acquire=acquire), report, scan_id=str(SCAN_ID),
        allowed_root_domains=(APEX,),
    ))
    assert sorted(inserted) == ["https://api.example.com", "https://c.dev.example.com"]
    assert outcome["wildcard_suppressed"] == 2
    assert "wildcard_dns" in outcome["partial_reasons"]
    assert outcome["notes"] == ["wildcard DNS at *.dev.example.com; 2 names suppressed"]
    # Suppressed names stay listed in the report.
    assert outcome["wildcard_suppressed_names"] == ["a.dev.example.com", "b.dev.example.com"]
    assert outcome["wildcards"][0]["addresses"] == [WILDCARD_ADDRESS]
    assert outcome["checked"] == 4 and outcome["not_checked"] == 0


@pytest.mark.parametrize(("sources", "expected"), [
    (["gungnir"], True), (["crtsh"], True), (["subfinder:certspotter"], True),
    (["subfinder:hackertarget"], False), (["subfinder"], False), ([], False), (None, False),
])
def test_only_certificate_sources_count_as_evidence(sources, expected):
    assert discovery_wildcards.has_certificate_evidence(sources) is expected


def test_the_system_answer_reports_the_first_hop_not_the_terminal(monkeypatch):
    async def getaddrinfo(self, host, port, *args, **kwargs):
        canonical = "edge.cdn.net" if host == "www.example.com" else ""
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, canonical, ("198.51.100.20", 0))]

    async def first_hop(host):
        return "www-example.cdn.net"

    monkeypatch.setattr(asyncio.base_events.BaseEventLoop, "getaddrinfo", getaddrinfo)
    monkeypatch.setattr(target_resolution, "first_cname_hop", first_hop)
    answer = _REAL_SYSTEM_ANSWER
    assert asyncio.run(answer("www.example.com")) == (["198.51.100.20"], "www-example.cdn.net")
    assert asyncio.run(answer("plain.example.com")) == (["198.51.100.20"], None)
