"""Passive subdomain-takeover checks of discovered names, under the Scan's authorization.

``check_subdomain_takeover`` existed only in the legacy scanner path, and canonical Scans skipped
it as ``canonical_capability_not_registered``. ``subdomains.takeover_check`` is now planned after
subdomain discovery. Discovered names are not destinations of the Scan, so they get DNS evidence
only; the bound host alone may get one same-origin GET fingerprint. Fixture DNS and HTTP only.
"""

from __future__ import annotations

import asyncio

import pytest

from api.capabilities import takeover
from api.runtime.capability_registry import CAPABILITY_REGISTRY
from api.scan.action_plan import ScanActionPlan, ScanActionPlanCompiler
from api.scan.finalizer import _takeover_finding, finalize_scan_report
from tests.test_scan_action_compiler import SCAN_ID as COMPILER_SCAN_ID, _execution, _target
from tests.test_scan_finalizer import _result_with_observation_count
from tests.test_scan_orchestrator import SCAN_ID, _action

ROOT = "example.com"
BOUND_ORIGIN = "https://app.example.com"


class FixtureDns:
    """``records[(name, type)]`` is (status, values); anything absent is NXDOMAIN."""

    def __init__(self, records):
        self.records = dict(records)
        self.asked: list[tuple[str, str]] = []

    async def __call__(self, name, rdtype):
        self.asked.append((name, rdtype))
        answer = self.records.get((name, rdtype))
        if callable(answer):
            return answer()
        if answer is not None:
            return answer
        exists = any(key[0] == name for key in self.records)
        return (takeover.NODATA, []) if exists else (takeover.NXDOMAIN, [])

    def names(self):
        return {name for name, _type in self.asked}


def cname(target):
    return (takeover.ANSWER, [target])


def address(value="203.0.113.10"):
    return (takeover.ANSWER, [value])


class FixtureHttp:
    def __init__(self, body):
        self.body = body
        self.requested: list[str] = []

    async def __call__(self, origin):
        self.requested.append(origin)
        return {"ok": True, "response": {"status": 404, "body_sample": self.body, "body_sha256": "f" * 64}}


class FixtureConfirm:
    """The independent resolver: ``verdict`` for every name it is asked about."""

    def __init__(self, verdict=True):
        self.verdict = verdict
        self.asked: list[str] = []

    async def __call__(self, name):
        self.asked.append(name)
        return self.verdict


def _check(dns, hosts, *, http_get=None, confirm=None, **kwargs):
    return asyncio.run(takeover.check_takeovers(
        hosts=hosts, root_domains=(ROOT,), authorized_origins=(BOUND_ORIGIN,),
        query=dns, http_get=http_get, confirm=confirm or FixtureConfirm(True),
        independent_confirmation=kwargs.pop("independent_confirmation", True), **kwargs,
    ))


def _by_host(result):
    return {row["host"]: row for row in result["observations"] if row["kind"] == "takeover_check"}


# ------------------------------------------------------------------------------- DNS evidence


def test_a_dangling_cname_to_an_nxdomain_signature_service_is_verified_by_dns_alone():
    dns = FixtureDns({
        ("old.example.com", "CNAME"): cname("old-app.azurewebsites.net"),
        # old-app.azurewebsites.net: no record at all (NXDOMAIN), asked twice.
    })
    http = FixtureHttp("irrelevant")
    confirm = FixtureConfirm(True)
    row = _by_host(_check(dns, ["old.example.com"], http_get=http, confirm=confirm))["old.example.com"]
    assert row["outcome"] == "verified"
    assert row["service"] == "Microsoft Azure"
    assert row["cname_chain"] == ["old-app.azurewebsites.net"]
    assert row["terminal_status"] == takeover.NXDOMAIN
    assert row["terminal_nxdomain_confirmed"] is True
    assert row["confirmation"] == "independent_doh_resolver"
    assert row["evidence_basis"] == "dns_cname_to_nxdomain_service"
    # Confirmed by the independent resolver, not by asking the system resolver again.
    assert confirm.asked == ["old-app.azurewebsites.net"]
    assert dns.asked.count(("old-app.azurewebsites.net", "A")) == 1
    # A discovered name never receives a request.
    assert http.requested == []


@pytest.mark.parametrize(("verdict", "outcome"), [(None, "suspected"), (False, "inconclusive")])
def test_without_an_independent_confirmation_nothing_is_verified(verdict, outcome):
    """The system resolver's negative cache repeating itself is not a second observation."""
    dns = FixtureDns({("old.example.com", "CNAME"): cname("old-app.azurewebsites.net")})
    row = _by_host(_check(dns, ["old.example.com"], confirm=FixtureConfirm(verdict)))["old.example.com"]
    assert row["outcome"] == outcome
    assert row["terminal_nxdomain_confirmed"] is False


def test_a_service_in_the_middle_of_the_chain_is_not_the_dangling_name():
    """shop -> legacy.trafficmanager.net -> old-vendor-shop.com (NXDOMAIN) is a dangling CNAME
    at a third-party name, not an Azure takeover."""
    dns = FixtureDns({
        ("shop.example.com", "CNAME"): cname("legacy.cloudapp.net"),
        ("legacy.cloudapp.net", "CNAME"): cname("old-vendor-shop.com"),
    })
    row = _by_host(_check(dns, ["shop.example.com"]))["shop.example.com"]
    assert row["cname_chain"] == ["legacy.cloudapp.net", "old-vendor-shop.com"]
    assert row["service"] is None
    assert row["outcome"] == "suspected"
    finding = _takeover_finding(row, capability_name="subdomains.takeover_check", receipt={})
    assert finding["verified"] is False and finding["severity"] == "medium"


def test_a_cname_whose_target_exists_is_not_vulnerable():
    dns = FixtureDns({
        ("live.example.com", "CNAME"): cname("live-app.azurewebsites.net"),
        ("live-app.azurewebsites.net", "A"): address(),
    })
    row = _by_host(_check(dns, ["live.example.com"]))["live.example.com"]
    assert row["outcome"] == "not_vulnerable"
    finding = _takeover_finding(row, capability_name="subdomains.takeover_check", receipt={})
    assert finding is None


def test_a_dangling_cname_outside_the_known_services_is_only_suspected():
    dns = FixtureDns({
        ("legacy.example.com", "CNAME"): cname("gone.unregistered-vendor.net"),
    })
    row = _by_host(_check(dns, ["legacy.example.com"]))["legacy.example.com"]
    assert row["outcome"] == "suspected"
    assert row["service"] is None
    assert row["evidence_basis"] == "dns_dangling_cname"


def test_a_negative_answer_the_independent_resolver_contradicts_is_never_verified():
    dns = FixtureDns({("flaky.example.com", "CNAME"): cname("flaky.cloudapp.net")})
    row = _by_host(_check(dns, ["flaky.example.com"], confirm=FixtureConfirm(False)))["flaky.example.com"]
    assert row["terminal_nxdomain_confirmed"] is False
    assert row["outcome"] != "verified"


def test_a_name_without_a_cname_produces_no_observation():
    dns = FixtureDns({("www.example.com", "A"): address()})
    result = _check(dns, ["www.example.com"])
    assert _by_host(result) == {}
    summary = result["observations"][-1]
    assert summary["kind"] == "takeover_summary"
    assert summary["hosts_checked"] == 1 and summary["hosts_with_cname"] == 0


# -------------------------------------------------------------------------- authorization


def test_an_unauthorized_discovered_host_gets_dns_only_treatment():
    """A CNAME to an HTTP-signature service needs a request this Scan may not send there."""
    dns = FixtureDns({
        ("docs.example.com", "CNAME"): cname("example-org.github.io"),
        ("example-org.github.io", "A"): address("185.199.108.153"),
    })
    http = FixtureHttp("There isn't a GitHub Pages site here")
    row = _by_host(_check(dns, ["docs.example.com"], http_get=http))["docs.example.com"]
    assert row["outcome"] == "inconclusive_dns_only"
    assert row["authorized_destination"] is False
    assert http.requested == []
    assert "http" not in row
    assert _takeover_finding(row, capability_name="subdomains.takeover_check", receipt={}) is None


def test_the_bound_host_gets_one_same_origin_fingerprint_request():
    dns = FixtureDns({
        ("app.example.com", "CNAME"): cname("bucket.s3.amazonaws.com"),
        ("bucket.s3.amazonaws.com", "A"): address("52.216.1.1"),
    })
    http = FixtureHttp("<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>")
    result = _check(dns, ["app.example.com"], http_get=http)
    row = _by_host(result)["app.example.com"]
    assert http.requested == [BOUND_ORIGIN]
    assert row["authorized_destination"] is True
    assert row["outcome"] == "verified"
    assert row["http"]["fingerprint_matched"] is True
    assert result["budget_consumed"] == {"hosts_attempted": 1, "http_requests": 1}

    claimed = FixtureHttp("<h1>Welcome to our docs</h1>")
    row = _by_host(_check(dns, ["app.example.com"], http_get=claimed))["app.example.com"]
    assert row["outcome"] == "not_vulnerable"
    assert row["http"]["fingerprint_matched"] is False


def test_an_edge_case_service_fingerprint_is_only_suspected():
    """can-i-take-over-xyz rates GitHub Pages an edge case: no verified HIGH from its page."""
    dns = FixtureDns({
        ("app.example.com", "CNAME"): cname("example-org.github.io"),
        ("example-org.github.io", "A"): address("185.199.108.153"),
    })
    http = FixtureHttp("<p>There isn't a GitHub Pages site here.</p>")
    row = _by_host(_check(dns, ["app.example.com"], http_get=http))["app.example.com"]
    assert row["service_status"] == "edge_case"
    assert row["outcome"] == "suspected"


def test_the_fingerprint_is_matched_in_the_bounded_body_not_the_display_sample():
    dns = FixtureDns({
        ("app.example.com", "CNAME"): cname("bucket.s3.amazonaws.com"),
        ("bucket.s3.amazonaws.com", "A"): address("52.216.1.1"),
    })
    page = "<style>" + "a{color:red}" * 400 + "</style><p>The specified bucket does not exist</p>"
    assert len(page) > 2_000

    async def get(origin):
        return {"ok": True, "response": {"status": 404, "body_sample": page[:2_000]},
                "body": page.encode()}

    row = _by_host(_check(dns, ["app.example.com"], http_get=get))["app.example.com"]
    assert row["http"]["fingerprint_matched"] is True
    assert row["outcome"] == "verified"


def test_requests_never_exceed_the_reserved_budget():
    dns = FixtureDns({
        ("app.example.com", "CNAME"): cname("bucket.s3.amazonaws.com"),
        ("bucket.s3.amazonaws.com", "A"): address("52.216.1.1"),
    })
    http = FixtureHttp("The specified bucket does not exist")
    result = _check(dns, ["app.example.com"], http_get=http, request_limit=0)
    assert http.requested == []
    assert _by_host(result)["app.example.com"]["outcome"] == "inconclusive"
    assert result["budget_consumed"]["http_requests"] == 0


def test_the_host_cap_counts_the_bound_host_and_caps_discovered_names():
    hosts = ["app.example.com", *[f"h{index:03d}.example.com" for index in range(80)]]
    dns = FixtureDns({})
    result = _check(dns, hosts, host_limit=takeover.HOST_LIMIT + 1)
    summary = result["observations"][-1]
    assert summary["hosts_checked"] == takeover.HOST_LIMIT + 1
    assert "app.example.com" in dns.names()
    small = _check(FixtureDns({}), hosts, host_limit=5)["observations"][-1]
    assert small["hosts_checked"] == 5


def test_names_outside_the_bound_root_are_never_queried():
    dns = FixtureDns({})
    result = _check(dns, ["notexample.com", "evil-example.com", "a.example.org"])
    assert dns.asked == []
    assert result["observations"][-1]["hosts_outside_root"] == 3


def test_the_number_of_names_and_the_time_are_bounded():
    hosts = [f"h{index:03d}.example.com" for index in range(80)]
    dns = FixtureDns({})
    result = _check(dns, hosts, host_limit=10)
    summary = result["observations"][-1]
    assert summary["hosts_checked"] == 10 and summary["hosts_beyond_limit"] == 70
    assert result["partial"] is True
    assert len(dns.names()) == 10

    async def hangs(name, rdtype):
        await asyncio.sleep(30)

    result = asyncio.run(takeover.check_takeovers(
        hosts=hosts[:5], root_domains=(ROOT,), authorized_origins=(),
        query=hangs, confirm=FixtureConfirm(True), independent_confirmation=True,
        deadline_seconds=0.1,
    ))
    assert result["observations"][-1]["hosts_deadline_skipped"] == 5
    assert result["errors"] == ["takeover_deadline"]


@pytest.mark.parametrize(("name", "service"), [
    ("x.blob.core.windows.net", "Microsoft Azure"),
    # Not in the catalogue's Azure list.
    ("legacy.trafficmanager.net", None),
    # Rated "not vulnerable" by can-i-take-over-xyz.
    ("shop.fastly.net", None),
    ("env.eu-west-1.elasticbeanstalk.com", "AWS Elastic Beanstalk"),
    ("bucket.s3.amazonaws.com", "AWS S3"),
    ("notgithub.io", None),
    ("evilazurewebsites.net", None),
])
def test_services_match_on_label_boundaries(name, service):
    matched = takeover.match_service(name)
    assert (matched.name if matched else None) == service


# --------------------------------------------------------------- findings and the Scan plan


def _report(observations):
    discover = _action("discover.subdomains", 0, capability_name="subdomains.discover")
    check = _action(
        "discover.takeover", 1, capability_name="subdomains.takeover_check",
        dependencies=(discover.action_id,),
    )
    final = _action("finalize.report", 2, dependencies=(discover.action_id, check.action_id))
    plan = ScanActionPlan(
        scan_id=SCAN_ID, execution_plan_digest="b" * 64, target_binding_digest="a" * 64,
        actions=(discover, check, final),
    )
    subdomains = tuple(
        {"kind": "subdomain", "host": row["host"], "root_domain": ROOT}
        for row in observations if row.get("kind") == "takeover_check"
    )
    return finalize_scan_report(
        plan=plan, target_url=BOUND_ORIGIN,
        action_results={
            discover.action_id: _result_with_observation_count(discover, len(subdomains)),
            check.action_id: _result_with_observation_count(check, len(observations)),
        },
        observations={discover.action_id: subdomains, check.action_id: tuple(observations)},
    )


def test_verified_and_suspected_takeovers_become_findings_with_their_evidence():
    dns = FixtureDns({
        ("old.example.com", "CNAME"): cname("old-app.azurewebsites.net"),
        ("legacy.example.com", "CNAME"): cname("gone.unregistered-vendor.net"),
        ("docs.example.com", "CNAME"): cname("example-org.github.io"),
        ("example-org.github.io", "A"): address(),
    })
    result = _check(dns, ["old.example.com", "legacy.example.com", "docs.example.com"])
    report = _report(result["observations"])
    findings = {
        finding["evidence"]["host"]: finding for finding in report["findings"]
        if finding.get("tool") == "subdomain_takeover"
    }
    assert set(findings) == {"old.example.com", "legacy.example.com"}
    verified = findings["old.example.com"]
    assert verified["verified"] is True and verified["severity"] == "high"
    assert verified["proof_state"] == "verified"
    assert verified["proof_contract_v2"]["verdict"] == "verified"
    assert verified["evidence"]["cname_chain"] == ["old-app.azurewebsites.net"]
    assert verified["evidence"]["passive"] is True
    suspected = findings["legacy.example.com"]
    assert suspected["verified"] is False and suspected["suspected"] is True
    assert suspected["needs_verification"] is True and suspected["severity"] == "medium"
    section = report["discovery"]["subdomains"]["takeover"]
    assert section["outcomes"]["inconclusive_dns_only"] == ["docs.example.com"]
    assert "DNS evidence only" in section["authorization"]


def test_the_takeover_check_is_planned_after_subdomain_discovery_only():
    plan = ScanActionPlanCompiler().compile(
        scan_id=COMPILER_SCAN_ID,
        execution_plan=_execution(include=("recon",), network=False, subdomains=True),
        target_binding=_target(),
    )
    by_id = {action.action_id: action for action in plan.actions}
    check = by_id["discover.takeover"]
    assert check.capability_name == "subdomains.takeover_check"
    assert check.dependencies == ("discover.subdomains",)
    assert check.required is False
    # Endpoint work never waits for it.
    assert not any(
        "discover.takeover" in action.dependencies
        for action in plan.actions if action.action_id != "finalize.report"
    )

    without = ScanActionPlanCompiler().compile(
        scan_id=COMPILER_SCAN_ID,
        execution_plan=_execution(include=("recon",), network=False, subdomains=False),
        target_binding=_target(),
    )
    assert "discover.takeover" not in {action.action_id for action in without.actions}


def test_the_capability_is_passive_and_bounded_in_the_registry():
    spec = CAPABILITY_REGISTRY.require("subdomains.takeover_check")
    assert spec.risk_tier == "passive" and not spec.requires_active_approval
    assert spec.budget_cost["hosts_attempted"] == takeover.HOST_LIMIT + 1
    assert spec.placement_requirements["http_destinations"] == "bound_origins_only"


def test_the_independent_confirmation_uses_the_configured_doh_resolvers(monkeypatch):
    import dns.message
    import dns.rcode

    from api.capabilities import dns as dns_capability

    monkeypatch.setattr(dns_capability, "_DOH_RESOLVERS", ())
    assert asyncio.run(takeover.doh_nxdomain("gone.azurewebsites.net")) is None

    asked = []

    async def doh(name, rdtype):
        asked.append((name, rdtype))
        message = dns.message.make_response(dns.message.make_query(name, rdtype))
        message.set_rcode(dns.rcode.NXDOMAIN if name.startswith("gone") else dns.rcode.NOERROR)
        return message

    monkeypatch.setattr(dns_capability, "_DOH_RESOLVERS", ("https://doh.example/dns-query",))
    monkeypatch.setattr(dns_capability, "_doh_query", doh)
    assert asyncio.run(takeover.doh_nxdomain("gone.azurewebsites.net")) is True
    assert asyncio.run(takeover.doh_nxdomain("live.azurewebsites.net")) is False
    assert asked == [("gone.azurewebsites.net", "A"), ("live.azurewebsites.net", "A")]



def test_a_dangling_name_outside_the_catalogue_is_never_sent_to_doh():
    dns = FixtureDns({
        ("legacy.example.com", "CNAME"): cname("gone.unregistered-vendor.net"),
        ("db.example.com", "CNAME"): cname("db01.corp.internal"),
    })
    confirm = FixtureConfirm(True)
    rows = _by_host(_check(dns, ["legacy.example.com", "db.example.com"], confirm=confirm))
    assert confirm.asked == []
    assert rows["legacy.example.com"]["outcome"] == "suspected"
    assert rows["db.example.com"]["outcome"] == "suspected"


def test_an_internal_binding_never_confirms_through_doh():
    """dns.doh_permitted refused the binding: even a catalogue name is not sent anywhere."""
    dns = FixtureDns({("old.example.com", "CNAME"): cname("old-app.azurewebsites.net")})
    confirm = FixtureConfirm(True)
    row = _by_host(_check(
        dns, ["old.example.com"], confirm=confirm, independent_confirmation=False,
    ))["old.example.com"]
    assert confirm.asked == []
    assert row["outcome"] == "suspected"


@pytest.mark.parametrize("name", [
    "db01.corp.internal", "printer.local", "nas.home.arpa", "intranet", "x.lan",
])
def test_doh_is_never_asked_about_an_internal_name(monkeypatch, name):
    from api.capabilities import dns as dns_capability

    async def doh(name, rdtype):
        raise AssertionError(f"{name} was sent to a third-party resolver")

    monkeypatch.setattr(dns_capability, "_DOH_RESOLVERS", ("https://doh.example/dns-query",))
    monkeypatch.setattr(dns_capability, "_doh_query", doh)
    assert asyncio.run(takeover.doh_nxdomain(name)) is None
