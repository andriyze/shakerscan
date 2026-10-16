"""Opt-in recon_active family: admission, plan, controls and report (unit fixtures).

These are fixture tests with fake resolvers and fake HTTP answers, not lab efficacy acceptance.
"""

from __future__ import annotations

import asyncio
import hashlib
import itertools
import uuid

import pytest

from api.capabilities import recon_active as ra
from api.capabilities.http import bound_virtual_host, execute_bound_http_request
from api.runtime.capability_registry import CAPABILITY_REGISTRY
from api.runtime.models import ScanBudget, ScanPolicy, TargetBinding
from api.scan.action_plan import ScanActionPlanCompiler
from api.scan.contracts import BUDGET_PROFILES, SCAN_FAMILY_PRESETS, resolve_scan_contract
from api.scan.execution import ScanExecutionPlan
from api.scan.finalizer import _posture_sections
from api.scan.surface_manifest import build_scan_surface_manifest

SCAN_ID = str(uuid.UUID("20000000-0000-0000-0000-000000000001"))
RECEIPT = str(uuid.UUID("20000000-0000-0000-0000-000000000004"))


def _target(**overrides) -> TargetBinding:
    values = dict(
        target_id=str(uuid.UUID("20000000-0000-0000-0000-000000000002")),
        target_kind="web", canonical_host="www.example.test",
        allowed_origins=("https://www.example.test",), allowed_addresses=("192.0.2.10",),
        allowed_root_domains=("example.test",),
    )
    values.update(overrides)
    return TargetBinding(**values)


def _plan(*, families=("recon", "recon_active"), subdomains=True, active=True,
          budget: ScanBudget | None = None):
    policy = ScanPolicy(
        active_testing=active, subdomain_discovery=subdomains,
        include_families=tuple(families), approval_receipt_id=RECEIPT if active else None,
    )
    execution = ScanExecutionPlan(policy=policy, budget_profile="balanced",
                                  budget=budget or BUDGET_PROFILES["balanced"],
                                  requested_families=tuple(families),
                                  resolved_families=tuple(families))
    return ScanActionPlanCompiler().compile(
        scan_id=SCAN_ID, execution_plan=execution, target_binding=_target())


def _counter():
    counter = itertools.count()
    return lambda size: f"{next(counter):0{size * 2}x}"


# --- admission -----------------------------------------------------------------------------


def test_recon_active_is_in_no_preset_and_needs_active_authority_and_a_receipt():
    assert all("recon_active" not in families for families in SCAN_FAMILY_PRESETS.values())
    for preset in ("passive", "standard_active"):
        contract = resolve_scan_contract(
            policy={"active_testing": preset == "standard_active", "preset": preset},
            approval_receipt_id=RECEIPT)
        assert "recon_active" not in contract.execution_plan.resolved_families
    with pytest.raises(ValueError, match="active_testing is required"):
        resolve_scan_contract(policy={"include_families": ["recon_active"]})
    with pytest.raises(ValueError, match="approval receipt"):
        resolve_scan_contract(policy={"active_testing": True, "include_families": ["recon_active"]})
    contract = resolve_scan_contract(
        policy={"active_testing": True, "include_families": ["recon_active"]},
        approval_receipt_id=RECEIPT)
    assert "recon_active" in contract.execution_plan.resolved_families


def test_capabilities_are_active_scan_only_with_declared_risk():
    for name in ("dns.enumerate", "vhost.discover", "web.param_discover"):
        spec = CAPABILITY_REGISTRY.require(name)
        assert spec.risk_tier == "active" and spec.required_approval == "active_testing"
        assert spec.requires_active_approval and not spec.planner_visible
        assert spec.credential_transport == "not_used"


# --- plan ----------------------------------------------------------------------------------


def test_plan_adds_recon_actions_only_when_explicitly_selected():
    by_id = {action.action_id: action for action in _plan().actions}
    assert by_id["discover.parameters"].capability_name == "web.param_discover"
    assert "discover.web_crawl" in by_id["discover.parameters"].dependencies
    assert by_id["discover.virtual_hosts"].capability_name == "vhost.discover"
    assert list(by_id["discover.dns_names"].capability_args["root_domains"]) == ["example.test"]
    assert by_id["discover.dns_names"].requested_budget["hosts_attempted"] == 100  # max_hosts/2
    without = {action.action_id for action in _plan(families=("recon",)).actions}
    assert not without & {"discover.parameters", "discover.virtual_hosts", "discover.dns_names"}


def test_dns_enumeration_needs_subdomain_discovery_authority():
    ids = {action.action_id for action in _plan(subdomains=False).actions}
    assert "discover.dns_names" not in ids
    assert {"discover.parameters", "discover.virtual_hosts"} <= ids


def test_corporate_content_list_is_pinned_only_with_active_authority():
    active = {a.action_id: a for a in _plan(families=("recon",)).actions}
    passive = {a.action_id: a for a in _plan(families=("recon",), active=False).actions}
    assert active["discover.web_content"].capability_args["wordlist"] == "corporate"
    assert passive["discover.web_content"].capability_args["wordlist"] == "common"


# --- bundled lists -------------------------------------------------------------------------


@pytest.mark.parametrize("name", [ra.DNS_WORDLIST, ra.VHOST_WORDLIST, ra.PARAMETER_WORDLIST])
def test_bundled_lists_are_authored_versioned_and_unique(name):
    loaded = ra.load_bundled_list(name)
    assert loaded.version.endswith("/v1") and len(loaded.entries) >= 40
    assert loaded.receipt()["provenance"] == "authored_by_shakerscan"
    assert loaded.sha256 == hashlib.sha256("\n".join(loaded.entries).encode()).hexdigest()
    with pytest.raises(ValueError):
        ra.load_bundled_list("../etc/passwd")


# --- DNS enumeration -----------------------------------------------------------------------


def _resolver(table, *, wildcard=None, fail=()):
    async def answer(name):
        if name in fail:
            raise OSError("resolver fault")
        if name in table:
            return table[name]
        if wildcard and name.endswith("." + wildcard[0]):
            return wildcard[1]
        return [], None
    return answer


def test_dns_enumeration_reports_resolving_names_and_counts_the_rest():
    result = asyncio.run(ra.enumerate_dns_names(
        roots=["example.test"], labels=["www", "vpn", "mail", "jira"],
        answer=_resolver({"www.example.test": (["192.0.2.1"], None),
                          "vpn.example.test": (["192.0.2.2"], None)}, fail={"jira.example.test"}),
        name_limit=50, deadline_seconds=10, cancelled=lambda: False, token=_counter(),
    ))
    hosts = sorted(o["host"] for o in result["observations"] if o["kind"] == "subdomain")
    assert hosts == ["vpn.example.test", "www.example.test"]
    summary = [o for o in result["observations"] if o["kind"] == "dns_enumeration"][0]
    root = summary["roots"][0]
    assert (root["found"], root["no_address"], root["unjudged"]) == (2, 1, 1)
    assert root["wildcard_judged"] is True and root["wildcards"] == []
    assert result["budget_consumed"]["hosts_attempted"] == 6  # 2 probes + 4 names


def test_dns_enumeration_suppresses_wildcard_echoes_but_keeps_distinct_aliases():
    table = {"vpn.wild.test": (["192.0.2.9"], "edge.wild.test")}
    result = asyncio.run(ra.enumerate_dns_names(
        roots=["wild.test"], labels=["www", "vpn", "mail"],
        answer=_resolver(table, wildcard=("wild.test", (["192.0.2.50"], None))),
        name_limit=50, deadline_seconds=10, cancelled=lambda: False, token=_counter(),
    ))
    hosts = [o["host"] for o in result["observations"] if o["kind"] == "subdomain"]
    assert hosts == ["vpn.wild.test"]
    root = [o for o in result["observations"] if o["kind"] == "dns_enumeration"][0]["roots"][0]
    assert root["wildcard_suppressed"] == 2 and root["wildcards"][0]["pattern"] == "*.wild.test"


def test_dns_enumeration_respects_the_reserved_name_budget():
    asked = []

    async def answer(name):
        asked.append(name)
        return [], None

    result = asyncio.run(ra.enumerate_dns_names(
        roots=["example.test"], labels=[f"n{i}" for i in range(100)], answer=answer,
        name_limit=10, deadline_seconds=10, cancelled=lambda: False, token=_counter()))
    assert len(asked) == 10 and result["budget_consumed"]["hosts_attempted"] == 10
    assert result["status"] == "partial"
    summary = [o for o in result["observations"] if o["kind"] == "dns_enumeration"][0]
    assert summary["roots"][0]["beyond_budget"] == 92


def test_dns_enumeration_stops_between_batches_when_cancelled():
    asked = []
    calls = {"n": 0}

    async def answer(name):
        asked.append(name)
        return ["192.0.2.1"] if name.startswith("n") else [], None

    def cancelled():
        calls["n"] += 1
        return calls["n"] > 1

    result = asyncio.run(ra.enumerate_dns_names(
        roots=["example.test"], labels=[f"n{i}" for i in range(200)], answer=answer,
        name_limit=500, deadline_seconds=10, cancelled=cancelled, token=_counter()))
    assert result["status"] == "cancelled"
    assert len(asked) == ra.DNS_BATCH
    assert result["budget_consumed"]["hosts_attempted"] == ra.DNS_BATCH
    found = [o for o in result["observations"] if o["kind"] == "subdomain"]
    assert len(found) == ra.DNS_BATCH - 2  # what was measured before the stop is kept


def test_dns_enumeration_never_leaves_the_bound_root():
    asked = []

    async def answer(name):
        asked.append(name)
        return [], None

    asyncio.run(ra.enumerate_dns_names(
        roots=["example.test", "co.uk"], labels=["www", "a.b", "..", "x" * 70], answer=answer,
        name_limit=50, deadline_seconds=10, cancelled=lambda: False, token=_counter()))
    assert all(name.endswith(".example.test") for name in asked)


# --- virtual hosts -------------------------------------------------------------------------


def _sig(status=200, body=b"default page", location=None):
    return ra.ResponseSignature(status, len(body), hashlib.sha256(body).hexdigest(), location)


def _vhost_server(pages, default=_sig()):
    asked = []

    async def request(host):
        asked.append(host)
        return pages.get(host, default)
    return request, asked


def test_vhost_lead_must_differ_from_baseline_and_every_random_control():
    request, asked = _vhost_server({
        "intranet.example.test": _sig(body=b"<h1>Intranet</h1>" * 20),
        "admin.example.test": _sig(403, b"forbidden"),
    })
    result = asyncio.run(ra.discover_virtual_hosts(
        canonical_host="www.example.test", roots=["example.test"],
        labels=["intranet", "admin", "staging", "www"], request=request, request_limit=40,
        deadline_seconds=10, cancelled=lambda: False, token=_counter()))
    leads = sorted(o["host"] for o in result["observations"] if o["kind"] == "virtual_host")
    assert leads == ["admin.example.test", "intranet.example.test"]
    assert "www.example.test" not in asked[3:]  # the bound name is the baseline, not a guess
    summary = [o for o in result["observations"] if o["kind"] == "virtual_host_discovery"][0]
    assert summary["controls"]["catch_all"] is True and summary["leads"] == 2


def test_catch_all_and_self_redirecting_servers_produce_no_leads():
    async def request(host):  # every name redirects to its own https origin
        name = host or "www.example.test"
        return _sig(301, b"", ra.normalized_location(f"https://{name}/", name))

    result = asyncio.run(ra.discover_virtual_hosts(
        canonical_host="www.example.test", roots=["example.test"],
        labels=["intranet", "admin"], request=request, request_limit=40,
        deadline_seconds=10, cancelled=lambda: False, token=_counter()))
    assert [o for o in result["observations"] if o["kind"] == "virtual_host"] == []


def test_vhost_lead_needs_a_reproducing_second_answer():
    flips = itertools.cycle([_sig(body=b"A" * 900), _sig(body=b"B" * 100)])

    async def request(host):
        return next(flips) if host == "staging.example.test" else _sig()

    result = asyncio.run(ra.discover_virtual_hosts(
        canonical_host="www.example.test", roots=["example.test"], labels=["staging"],
        request=request, request_limit=40, deadline_seconds=10, cancelled=lambda: False,
        token=_counter()))
    assert [o for o in result["observations"] if o["kind"] == "virtual_host"] == []


def test_vhost_discovery_respects_budget_and_cancellation():
    request, asked = _vhost_server({})
    result = asyncio.run(ra.discover_virtual_hosts(
        canonical_host="www.example.test", roots=["example.test"],
        labels=[f"h{i}" for i in range(100)], request=request, request_limit=20,
        deadline_seconds=10, cancelled=lambda: False, token=_counter()))
    assert len(asked) <= 20 and result["status"] == "partial"
    state = {"n": 0}

    def cancelled():
        state["n"] += 1
        return state["n"] > 2

    request, asked = _vhost_server({})
    result = asyncio.run(ra.discover_virtual_hosts(
        canonical_host="www.example.test", roots=["example.test"],
        labels=[f"h{i}" for i in range(100)], request=request, request_limit=200,
        deadline_seconds=10, cancelled=cancelled, token=_counter()))
    assert result["status"] == "cancelled" and len(asked) == 3 + 2


def test_bound_request_admits_only_virtual_hosts_under_the_bound_root():
    target = _target()
    assert bound_virtual_host("Intranet.Example.Test.", target) == "intranet.example.test"
    assert bound_virtual_host("example.test", target) is None
    assert bound_virtual_host("intranet.evil.test", target) is None
    assert bound_virtual_host("notexample.test", target) is None
    result = asyncio.run(execute_bound_http_request(
        "https://www.example.test", {"method": "GET", "path": "/"}, target=target,
        virtual_host="intranet.evil.test"))
    assert result["ok"] is False and result["error"].startswith("scope:")
    result = asyncio.run(execute_bound_http_request(
        "https://www.example.test", {"method": "POST", "path": "/"}, target=target,
        allow_write=True, virtual_host="intranet.example.test"))
    assert result["ok"] is False and result["error"].startswith("scope:")


# --- parameters ----------------------------------------------------------------------------


def _parameter_server(reads, *, echo_all=False, dynamic=False):
    """reads: {path: {name: kind}} with kind 'reflect' or 'change'."""
    counter = itertools.count()
    asked = []

    async def request(origin, path, query, marker):
        asked.append((path, dict(query or {})))
        body = b"<html>page " + path.encode() + b"</html>" + (
            str(next(counter)).encode() * 50 if dynamic else b"")
        reflected = False
        for name, value in (query or {}).items():
            kind = reads.get(path, {}).get(name)
            if kind == "reflect" or echo_all:
                body += value.encode()
                reflected = True
            elif kind == "change":
                body += b"<pre>debug details</pre>" * 20
        return ra.ParameterResponse(_sig(body=body), reflected)
    return request, asked


def test_parameter_discovery_confirms_reflected_and_response_changing_names():
    request, asked = _parameter_server({"/search": {"q": "reflect"}, "/report": {"debug": "change"}})
    result = asyncio.run(ra.discover_parameters(
        origin="https://www.example.test", routes=["/search", "/report", "/static-page"],
        names=["q", "debug", "id"], request=request, request_limit=100, deadline_seconds=10,
        cancelled=lambda: False, token=_counter()))
    found = {(o["path"], o["parameter"]): o["signals"]
             for o in result["observations"] if o["kind"] == "discovered_parameter"}
    assert found == {("/search", "q"): ["reflected"], ("/report", "debug"): ["response_change"]}
    routes = [o["url"] for o in result["observations"] if o["kind"] == "discovered_route"]
    assert routes == ["https://www.example.test/search?q=1", "https://www.example.test/report?debug=1"]


def test_a_route_that_echoes_any_parameter_is_attributed_nothing():
    request, _ = _parameter_server({}, echo_all=True)
    result = asyncio.run(ra.discover_parameters(
        origin="https://www.example.test", routes=["/echo"], names=["q", "id"], request=request,
        request_limit=100, deadline_seconds=10, cancelled=lambda: False, token=_counter()))
    assert [o for o in result["observations"] if o["kind"] == "discovered_parameter"] == []
    summary = [o for o in result["observations"] if o["kind"] == "parameter_discovery"][0]
    assert summary["routes"][0]["echoes_any_parameter"] is True


def test_parameter_routes_are_observed_same_origin_gets_only():
    observations = [
        {"kind": "discovered_route", "method": "GET", "url": "https://www.example.test/search"},
        {"kind": "discovered_route", "method": "POST", "url": "https://www.example.test/login"},
        {"kind": "discovered_route", "method": "GET", "url": "https://other.example.test/x"},
        {"kind": "discovered_route", "method": "GET", "url": "https://www.example.test/app.js"},
        {"kind": "discovered_route", "method": "GET", "url": "https://www.example.test/logout"},
        {"kind": "content_discovery", "url": "https://www.example.test/report", "status": 200},
        {"kind": "content_discovery", "url": "https://www.example.test/gone", "status": 404},
        {"kind": "content_discovery", "url": "https://www.example.test/.shakerscan-absent-0",
         "status": 200, "negative_control": True},
    ]
    assert ra.parameter_routes(observations, origin="https://www.example.test") == [
        "/", "/search", "/report"]


def test_discovered_parameters_reach_the_candidate_surface_as_observed_routes():
    request, _ = _parameter_server({"/search": {"q": "reflect"}})
    result = asyncio.run(ra.discover_parameters(
        origin="https://www.example.test", routes=["/search"], names=["q"], request=request,
        request_limit=50, deadline_seconds=10, cancelled=lambda: False, token=_counter()))
    skipped = {"status": "skipped", "observations": []}
    surface = build_scan_surface_manifest(
        target_url="https://www.example.test", target=_target(), options={},
        collection_replay=skipped, subdomains=skipped, probe=skipped, crawl=skipped,
        content=skipped, max_endpoints=100,
        parameters={"status": "success", "observations": result["observations"]},
    )
    endpoints = surface["endpoints"]
    assert any("q" in (item.get("query_parameter_names") or item.get("query_keys") or ())
               for item in endpoints)
    assert surface["producers"]["web.param_discover"]["status"] == "complete"


# --- report --------------------------------------------------------------------------------


def test_report_lists_recon_leads_and_enumerated_names_with_their_source():
    sections = _posture_sections({
        "discover.dns_names": [
            {"kind": "subdomain", "host": "vpn.example.test", "root_domain": "example.test",
             "source": "dns_enumeration"},
            {"kind": "dns_enumeration", "roots": [{"root_domain": "example.test", "found": 1}],
             "partial": False},
        ],
        "discover.virtual_hosts": [
            {"kind": "virtual_host", "host": "intranet.example.test", "status": 200},
            {"kind": "virtual_host_discovery", "tested": 80, "leads": 1},
        ],
        "discover.parameters": [
            {"kind": "discovered_parameter", "path": "/search", "parameter": "q"},
            {"kind": "parameter_discovery", "routes_tested": 3, "found": 1},
        ],
    })
    discovery = sections["discovery"]
    assert discovery["subdomains"]["hosts"] == ["vpn.example.test"]
    assert discovery["subdomains"]["sources"] == {"vpn.example.test": ["dns_enumeration"]}
    assert discovery["dns_enumeration"]["runs"][0]["roots"][0]["found"] == 1
    assert discovery["virtual_hosts"]["items"][0]["host"] == "intranet.example.test"
    assert discovery["virtual_hosts"]["scope"].startswith("leads")
    assert discovery["parameters"]["items"] == [{"path": "/search", "parameter": "q"}]
