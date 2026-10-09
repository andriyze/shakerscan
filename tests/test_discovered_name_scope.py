"""Discovered names belong to an apex only on a DNS label boundary, on every insert path.

Targets-page discovery filtered with ``name.endswith(apex)`` and no leading dot, so
``notexample.com`` and ``evil-example.com`` were stored as subdomains of ``example.com`` and became
targets with a Scan button under the operator's root. Every source filter and every path that
inserts discovered names now asks ``scanner_tools.discovered_names``. All fixtures; no live DNS.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import importlib.util
import socket
from pathlib import Path
import sys
import types

import pytest

from api import action_scope, target_resolution
from api.capabilities.network import SubdomainsDiscoverAdapter
from api.scan import subdomain_targets
from scanner.scanner_tools import (
    ct_monitor, discovered_names, gungnir, subdomain_discovery, subfinder,
)

ROOT = Path(__file__).resolve().parents[1]
APEX = "example.com"
# Lookalikes: the apex is a string suffix, but not on a label boundary, or not a suffix at all.
LOOKALIKES = (
    "notexample.com", "evil-example.com", "xexample.com", "example.com.evil.net",
    "a.example.co", "example.comm",
)


# ---------------------------------------------------------------------------- the helper


@pytest.mark.parametrize("name", LOOKALIKES)
def test_a_lookalike_is_never_a_subdomain(name):
    assert discovered_names.name_under_apex(name, APEX) is None
    assert discovered_names.subdomain_of(name, APEX) is None


@pytest.mark.parametrize(("raw", "expected"), [
    ("API.Example.COM", "api.example.com"),
    ("api.example.com.", "api.example.com"),
    ("  Api.Example.Com.  ", "api.example.com"),
    ("*.dev.example.com", "dev.example.com"),
    ("bücher.example.com", "xn--bcher-kva.example.com"),
])
def test_case_trailing_dot_wildcard_and_idna_are_canonicalised(raw, expected):
    assert discovered_names.subdomain_of(raw, "Example.COM.") == expected


@pytest.mark.parametrize("raw", ["", None, "a..example.com", ".example.com", "a b.example.com",
                                 "203.0.113.10", "-a.example.com"])
def test_a_name_that_is_not_a_dns_name_is_refused(raw):
    assert discovered_names.subdomain_of(raw, APEX) is None


def test_the_apex_is_under_itself_but_not_its_own_subdomain():
    assert discovered_names.name_under_apex("EXAMPLE.com.", APEX) == APEX
    assert discovered_names.subdomain_of(APEX, APEX) is None


def test_filtering_dedupes_canonical_names_and_counts_refusals():
    kept, refused = discovered_names.filter_subdomains(
        ["a.example.com", "A.EXAMPLE.COM.", "notexample.com", "example.com", "b.example.com"],
        APEX,
    )
    assert kept == ["a.example.com", "b.example.com"]
    assert refused == 1


@pytest.mark.parametrize("host", [
    "API.Example.com.", "bücher.example.com", "straße.example.com", "plain.example.com",
])
def test_canonicalisation_matches_the_scope_guard(host):
    """The name stored is the host the scope guard (and the HTTP client) would use."""
    assert discovered_names.canonical_name(host) == action_scope._canonical_host(host)


# ------------------------------------------------------------------ source filters (scanner)


def test_targets_page_discovery_refuses_lookalikes_from_every_source(monkeypatch):
    returned = ["api.example.com", "API.Example.com.", *LOOKALIKES]

    async def available():
        return True

    async def gungnir_scan(domain, timeout=30):
        return {"subdomains": list(returned)}

    async def subfinder_scan(domain):
        return {"subdomains": list(returned)}

    async def crtsh(domain, **_kwargs):
        return {"subdomain_discovery": {"subdomains": list(returned)}}

    monkeypatch.setattr(subdomain_discovery, "check_gungnir_available", available)
    monkeypatch.setattr(subdomain_discovery, "gungnir_scan", gungnir_scan)
    monkeypatch.setattr(subdomain_discovery, "subfinder_scan", subfinder_scan)
    monkeypatch.setattr(subdomain_discovery, "check_certificate_transparency", crtsh)

    result = asyncio.run(subdomain_discovery.discover_subdomains(APEX))
    assert result["subdomains"] == ["api.example.com"]
    for source in ("gungnir", "subfinder", "crtsh"):
        assert result["by_source"][source]["subdomains"] == ["api.example.com"]


def test_ct_parsing_refuses_lookalikes():
    certs = [
        {"common_name": "notexample.com", "name_value": "evil-example.com\n*.Dev.Example.com"},
        {"common_name": "*.example.com", "name_value": "www.example.com.,example.com"},
    ]
    found = ct_monitor._discover_subdomains_from_ct(certs, APEX)
    assert found["subdomains"] == ["dev.example.com", "www.example.com"]


def test_gungnir_and_subfinder_output_is_filtered(monkeypatch):
    output = "\n".join(["api.example.com", "*.WWW.example.com.", *LOOKALIKES, "example.com"])

    async def run(cmd, timeout=60, **_kwargs):
        return output, "", 0

    monkeypatch.setattr(gungnir.os.path, "isfile", lambda _path: True)
    monkeypatch.setattr(gungnir, "run", run)
    monkeypatch.setattr(subfinder, "run", run)
    assert asyncio.run(gungnir.gungnir_scan(APEX))["subdomains"] == [
        "api.example.com", "www.example.com",
    ]
    assert asyncio.run(subfinder.subfinder_scan(APEX))["subdomains"] == [
        "api.example.com", "www.example.com",
    ]


def test_the_scan_subfinder_parser_refuses_lookalikes_and_canonicalises():
    lines = [
        '{"host": "API.Example.com.", "source": "crtsh"}',
        *[f'{{"host": "{name}", "source": "crtsh"}}' for name in LOOKALIKES],
    ]
    parsed = SubdomainsDiscoverAdapter().parse("\n".join(lines), root_domain=APEX)
    assert [row["host"] for row in parsed.observations] == ["api.example.com"]
    assert len(parsed.errors) == len(LOOKALIKES)


# --------------------------------------------------------------------------- insert paths


class _Conn:
    def __init__(self):
        self.inserted: list[str] = []
        self.runs: list[tuple] = []

    async def fetchrow(self, query, *args):
        return None

    async def execute(self, query, *args):
        if "INSERT INTO targets" in query:
            self.inserted.append(args[0])
            return "INSERT 0 1"
        if "INSERT INTO discovery_runs" in query:
            self.runs.append(args)
            return "INSERT 0 1"
        raise AssertionError(query)


def _pool(conn):
    @asynccontextmanager
    async def acquire():
        yield conn

    return types.SimpleNamespace(acquire=acquire)


async def _resolves(name):
    # Real names resolve; the planner's random wildcard probes (16 hex labels) do not.
    if len(name.split(".", 1)[0]) == 16:
        raise socket.gaierror(socket.EAI_NONAME, "no such name")
    return ["203.0.113.10"]


def test_targets_page_planning_and_storing_refuse_lookalikes():
    plan = asyncio.run(target_resolution.plan_discovered_targets(
        ["api.example.com", "API.example.com.", *LOOKALIKES], root_domain=APEX, lookup=_resolves,
    ))
    assert plan["scannable"] == ["api.example.com"]
    assert plan["outside_root_count"] == len(LOOKALIKES)
    conn = _Conn()
    outcome = asyncio.run(target_resolution.store_discovered_targets(conn, plan, APEX))
    assert conn.inserted == ["https://api.example.com"]
    assert outcome["outside_root_count"] == len(LOOKALIKES)


def test_storing_refuses_a_lookalike_whichever_planner_produced_the_plan():
    conn = _Conn()
    outcome = asyncio.run(target_resolution.store_discovered_targets(
        conn, {"scannable": ["notexample.com", "a.example.com"]}, APEX,
    ))
    assert conn.inserted == ["https://a.example.com"]
    assert outcome["outside_root_count"] == 1


def test_the_scan_path_records_only_canonical_names_under_the_bound_root():
    report = {"discovery": {"subdomains": {
        "root_domain": "Example.com.",
        "hosts": ["A.Example.com.", *LOOKALIKES],
        "total": 1 + len(LOOKALIKES),
    }}}
    seen: list[list[str]] = []

    async def plan(names):
        seen.append(list(names))
        return {"scannable": list(names), "unresolved": [], "unknown": []}

    conn = _Conn()
    outcome = asyncio.run(subdomain_targets.record_scan_subdomain_discovery(
        _pool(conn), report, scan_id="scan-1", allowed_root_domains=("EXAMPLE.COM",),
        plan_targets=plan,
    ))
    assert seen == [["a.example.com"]]
    assert conn.inserted == ["https://a.example.com"]
    assert outcome["rejected"] == len(LOOKALIKES)
    assert "names_outside_root_domain" in outcome["partial_reasons"]


def test_the_scan_path_refuses_a_report_whose_names_are_all_lookalikes():
    report = {"discovery": {"subdomains": {"root_domain": APEX, "hosts": list(LOOKALIKES)}}}
    outcome = asyncio.run(subdomain_targets.record_scan_subdomain_discovery(
        _pool(_Conn()), report, scan_id="scan-1", allowed_root_domains=(APEX,),
    ))
    assert outcome == {"status": "not_recorded", "reason": "no_names_under_root_domain"}


@pytest.fixture(params=["api/gungnir_worker.py", "scanner/gungnir_worker.py"])
def gungnir_worker(request, monkeypatch):
    monkeypatch.setitem(sys.modules, "redis", types.SimpleNamespace(Redis=object, from_url=lambda *_a, **_k: None))
    monkeypatch.setitem(sys.modules, "asyncpg", types.SimpleNamespace(create_pool=None))
    spec = importlib.util.spec_from_file_location(
        f"gungnir_scope_{request.param.split('/')[0]}", ROOT / request.param,
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("name", LOOKALIKES)
def test_the_ct_monitor_worker_never_attributes_a_lookalike(gungnir_worker, name):
    assert gungnir_worker.match_root_domain(name, [APEX]) is None


def test_the_ct_monitor_worker_stores_canonical_names(gungnir_worker, monkeypatch):
    stored: list[tuple[str, str]] = []

    async def store(subdomain, root):
        stored.append((subdomain, root))
        return True

    lines = [b"*.API.Example.com.\n", b"notexample.com\n", b"evil-example.com\n", b""]

    class _Stream:
        async def readline(self):
            return lines.pop(0) if lines else b""

    class _Proc:
        returncode = None
        stdout = _Stream()
        stderr = _Stream()

        def terminate(self):
            self.returncode = 0

        async def wait(self):
            return 0

    async def spawn(*_args, **_kwargs):
        return _Proc()

    monkeypatch.setattr(gungnir_worker, "store_subdomain", store)
    monkeypatch.setattr(gungnir_worker.asyncio, "create_subprocess_exec", spawn)

    async def run():
        task = asyncio.create_task(gungnir_worker.run_gungnir([APEX]))
        await asyncio.sleep(0.05)
        gungnir_worker.shutdown_event.set()
        await asyncio.wait_for(task, timeout=5)

    asyncio.run(run())
    assert stored == [("api.example.com", APEX)]


def test_storing_inserts_the_canonical_name_and_root_it_validated():
    inserted: list[tuple] = []

    class Conn:
        async def execute(self, query, *args):
            inserted.append(args)
            return "INSERT 0 1"

    asyncio.run(target_resolution.store_discovered_targets(
        Conn(), {"scannable": ["API.Example.com.", "api.example.com"]}, "Example.COM.",
    ))
    assert inserted == [("https://api.example.com", "example.com", "subfinder")]
