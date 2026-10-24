"""Header values, CORS, open redirect and DNS/email posture: judged from recorded observations."""

from __future__ import annotations

import asyncio

from api.capabilities.open_redirect import probe_candidate, probe_url, redirect_candidates
from api.finding_detail import build_finding_detail
from api.finding_detail.common import q
from api.scan.action_plan import ScanActionPlan
from api.scan.finalizer import finalize_scan_report
from api.scan.posture_findings import (
    CORS_PROBE_ORIGIN, REDIRECT_CANARY_URL, header_value_issues, redirects_to_canary,
)
from tests.test_scan_finalizer import _result_with_observation_count
from tests.test_scan_orchestrator import SCAN_ID, _action


def _report(observations_by_action: dict, *, target: str = "https://app.example.test", capabilities=None):
    capabilities = capabilities or {}
    actions = [
        _action(action_id, index, capability_name=capabilities.get(action_id, "http.request"))
        for index, action_id in enumerate(observations_by_action)
    ]
    final = _action("finalize.report", len(actions), dependencies=tuple(a.action_id for a in actions))
    plan = ScanActionPlan(scan_id=SCAN_ID, execution_plan_digest="b" * 64, target_binding_digest="a" * 64,
                          actions=(*actions, final))
    return finalize_scan_report(
        plan=plan, target_url=target,
        action_results={a.action_id: _result_with_observation_count(a, len(observations_by_action[a.action_id])) for a in actions},
        observations={key: tuple(value) for key, value in observations_by_action.items()},
    )


def _baseline(origin: str, headers: dict, status: int = 200):
    return {
        "kind": "http_observation",
        "request": {"method": "GET", "origin": origin, "path": "/"},
        "response": {"status": status, "security_headers": headers, "set_cookie_metadata": []},
    }


WEAK = {
    "content-security-policy": "default-src * 'unsafe-inline' 'unsafe-eval' data: blob:",
    "referrer-policy": "unsafe-url",
    "permissions-policy": "camera=*, microphone=*, geolocation=*",
    "x-frame-options": "ALLOWALL",
    "x-content-type-options": "none",
    "strict-transport-security": "max-age=60",
}
GOOD = {
    "content-security-policy": "default-src 'self'; script-src 'self' 'nonce-abc'; frame-ancestors 'none'",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=(), microphone=(), geolocation=()",
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "strict-transport-security": "max-age=63072000; includeSubDomains",
}


def test_weak_header_values_are_findings_with_the_observed_and_expected_value():
    report = _report({"baseline.http": [_baseline("https://app.example.test", WEAK)]})
    weak = {f["evidence"]["header"]: f for f in report["findings"] if f["evidence"].get("check", "").startswith("weak_header_")}
    assert set(weak) == set(WEAK)
    csp = weak["content-security-policy"]
    assert csp["title"] == "Weak Content-Security-Policy header value" and csp["severity"] == "low"
    codes = {item["code"] for item in csp["evidence"]["issues"]}
    assert {"csp_script_any_origin", "csp_unsafe_eval", "csp_unsafe_inline"} <= codes
    assert csp["proof_state"] == "verified"
    assert weak["strict-transport-security"]["evidence"]["issues"][0]["code"] == "hsts_short_max_age"
    assert weak["x-frame-options"]["severity"] == "low"
    assert weak["referrer-policy"]["severity"] == "low"
    assert weak["x-content-type-options"]["severity"] == "info"
    assert weak["permissions-policy"]["severity"] == "info"
    # The severity reason is recorded with the finding and shown by the brief.
    brief = build_finding_detail(csp)
    assert brief["class"] == "header.weak_value"
    assert "default-src *" in brief["observed"][0]["value"]
    assert brief["severity"]["reason"].startswith("The header is present but its value")
    assert brief["verify"]["command"].startswith("curl ")


def test_strong_header_values_produce_no_value_finding_and_hsts_is_not_judged_over_http():
    report = _report({"baseline.http": [_baseline("https://app.example.test", GOOD)]})
    assert not [f for f in report["findings"] if f["evidence"].get("check", "").startswith("weak_header_")]
    assert "strict-transport-security" not in header_value_issues({"strict-transport-security": "max-age=1"}, origin="http://a.example")
    # A nonce neutralises 'unsafe-inline' (CSP3), and frame-ancestors excuses an invalid XFO.
    assert header_value_issues({"content-security-policy": "script-src 'self' 'unsafe-inline' 'nonce-x'"}, origin="https://a.example") == {}
    assert header_value_issues({"x-frame-options": "ALLOWALL", "content-security-policy": "frame-ancestors 'self'; script-src 'self'"}, origin="https://a.example") == {}
    # includeSubDomains is expected only on the registrable domain itself.
    apex = header_value_issues({"strict-transport-security": "max-age=63072000"}, origin="https://example.com")
    assert apex["strict-transport-security"][0][1] == "hsts_no_include_subdomains"
    assert header_value_issues({"strict-transport-security": "max-age=63072000"}, origin="https://www.example.com") == {}


def test_opt_in_isolation_headers_reported_by_the_template_are_not_findings():
    templates = [{
        "kind": "template_match", "template_id": "http-missing-security-headers", "severity": "info",
        "matched_at": "https://app.example.test/", "matcher_name": name, "name": "HTTP Missing Security Headers",
    } for name in ("cross-origin-embedder-policy", "cross-origin-opener-policy", "cross-origin-resource-policy",
                   "x-permitted-cross-domain-policies", "x-content-type-options")]
    report = _report({"passive.templates": templates}, capabilities={"passive.templates": "templates.passive_batch"})
    assert [f["evidence"]["header_name"] for f in report["findings"]] == ["x-content-type-options"]


def _cors(action_id: str, headers: dict, status: int = 200):
    return {action_id: [{
        "kind": "http_observation",
        "request": {"method": "GET", "origin": "https://app.example.test", "path": "/"},
        "response": {"status": status, "security_headers": headers},
    }]}


def test_cors_reflection_and_null_origin_with_credentials_are_high():
    reflected = _report(_cors("baseline.cors", {
        "access-control-allow-origin": CORS_PROBE_ORIGIN, "access-control-allow-credentials": "true"}))["findings"]
    assert [(f["title"], f["severity"], f["cwe"]) for f in reflected] == [("CORS policy reflects any origin", "high", "CWE-942")]
    assert reflected[0]["evidence"]["request_origin_header"] == CORS_PROBE_ORIGIN
    brief = build_finding_detail(reflected[0])
    assert brief["class"] == "cors.reflected_origin"
    assert "Origin: " + CORS_PROBE_ORIGIN in brief["reproduce"]["command"]
    null = _report(_cors("baseline.cors_null", {
        "access-control-allow-origin": "null", "access-control-allow-credentials": "true"}))["findings"]
    assert [(f["title"], f["severity"]) for f in null] == [("CORS policy trusts the null origin", "high")]


def test_cors_reflection_is_judged_on_the_observation_as_the_receipt_stores_it():
    """Unit fixture: an origin-reflecting target's answer, stored through the runtime receipt
    redactor exactly as a worker's receipt stores every observation."""
    import api.runtime  # noqa: F401 -- importing the runtime installs its receipt redactor
    from api.runtime import receipts
    [observation] = _cors("baseline.cors", {
        "access-control-allow-origin": CORS_PROBE_ORIGIN, "access-control-allow-credentials": "true"})["baseline.cors"]
    stored = receipts.redact_receipt_value(dict(observation))
    # The redactor renders a bare URL origin with a "/" path, so the stored header no longer
    # spells the Origin that was sent.
    assert stored["response"]["security_headers"]["access-control-allow-origin"] == CORS_PROBE_ORIGIN + "/"
    findings = _report({"baseline.cors": [stored]})["findings"]
    assert [(f["title"], f["severity"]) for f in findings] == [("CORS policy reflects any origin", "high")]
    assert findings[0]["evidence"]["access_control_allow_origin"] == CORS_PROBE_ORIGIN
    brief = build_finding_detail(findings[0])
    assert brief["reproduce"]["expect"] == "access-control-allow-origin: " + CORS_PROBE_ORIGIN


def test_cors_answers_that_grant_nothing_are_not_findings():
    assert _report(_cors("baseline.cors", {}))["findings"] == []
    assert _report(_cors("baseline.cors", {"access-control-allow-origin": "https://app.example.test"}))["findings"] == []
    assert [f["severity"] for f in _report(_cors("baseline.cors", {"access-control-allow-origin": CORS_PROBE_ORIGIN}))["findings"]] == ["low"]
    star = _report(_cors("baseline.cors", {"access-control-allow-origin": "*", "access-control-allow-credentials": "true"}))["findings"]
    assert [(f["title"], f["severity"]) for f in star] == [("CORS wildcard combined with credentials", "low")]
    # The same headers on the ordinary baseline request prove nothing about origin handling.
    assert not [f for f in _report({"baseline.http": [_baseline("https://app.example.test", {**GOOD, "access-control-allow-origin": "*"})]})["findings"]
                if f["evidence"].get("check", "").startswith("cors_")]


def _dns(records: dict, host: str = "example.com", errors=(), answered=None):
    base = {key: [] for key in ("host_txt", "dmarc", "host_caa", "host_mx")}
    records = {**base, **records}
    failed = {item.split(":", 1)[0] for item in errors}
    # The capability records metadata for every answered query, an empty answer included.
    answered = [label for label in records if label not in failed] if answered is None else answered
    return {"baseline.dns": [{
        "kind": "dns_posture", "canonical_host": host, "records": records,
        "record_metadata": {label: {"answer_count": len(records[label])} for label in answered},
        "query_names": {"host_txt": host, "dmarc": f"_dmarc.{host}", "host_caa": host}, "errors": list(errors),
    }]}


def _dns_findings(records, **kwargs):
    report = _report(_dns(records, **kwargs), capabilities={"baseline.dns": "dns.inspect"})
    return {f["evidence"]["check"]: f for f in report["findings"]}


def test_spf_plus_all_missing_dmarc_and_missing_caa_on_the_apex():
    found = _dns_findings({"host_txt": ["v=spf1 +all"], "host_mx": [{"host": "mail.example.com", "priority": 10}]})
    assert set(found) == {"spf_pass_all", "dmarc_missing", "caa_missing"}
    assert found["spf_pass_all"]["severity"] == "medium"
    assert found["dmarc_missing"]["severity"] == "low"
    assert found["caa_missing"]["severity"] == "info"
    brief = build_finding_detail(found["spf_pass_all"])
    assert brief["class"] == "dns.spf_pass_all"
    assert brief["reproduce"]["command"] == "dig +short TXT example.com"
    assert "v=spf1 +all" in brief["observed"][0]["value"]


def test_dmarc_none_too_many_lookups_and_a_healthy_domain():
    record = "v=spf1 " + " ".join(f"include:s{i}.example.net" for i in range(11)) + " -all"
    found = _dns_findings({"host_txt": [record], "dmarc": ["v=DMARC1; p=none; rua=mailto:d@example.com"],
                           "host_caa": [{"flags": 0, "tag": "issue", "value": "letsencrypt.org"}]})
    assert set(found) == {"spf_too_many_lookups", "dmarc_policy_none"}
    assert found["spf_too_many_lookups"]["evidence"]["lookup_count"] == 11
    healthy = _dns_findings({"host_txt": ["v=spf1 include:_spf.example.net -all"],
                             "dmarc": ["v=DMARC1; p=reject"], "host_caa": [{"flags": 0, "tag": "issue", "value": "x"}]})
    assert healthy == {}


def test_dns_posture_is_not_judged_for_subdomains_addresses_or_failed_queries():
    # A web subdomain without mail: DMARC/CAA live at the registrable domain, SPF is not expected.
    assert _dns_findings({}, host="www.example.com") == {}
    assert _dns_findings({}, host="192.0.2.10") == {}
    # A query that failed is not an absent record.
    assert _dns_findings({}, errors=["host_txt:LifetimeTimeout", "dmarc:LifetimeTimeout", "host_caa:LifetimeTimeout"]) == {}


def test_open_redirect_candidates_probe_only_redirect_named_parameters():
    entries = [
        {"route_id": "r1", "scheme": "https", "host": "app.example.test", "port": 443, "canonical_path": "/go",
         "query_parameter_names": ["next", "page"]},
        {"route_id": "r2", "scheme": "https", "host": "app.example.test", "port": 443, "canonical_path": "/search",
         "query_parameter_names": ["q"]},
        {"route_id": "r3", "scheme": "https", "host": "app.example.test", "port": 443, "canonical_path": "/login",
         "query_parameter_names": ["returnUrl"]},
    ]
    candidates = redirect_candidates(entries)
    assert [(c["route_id"], c["parameter"]) for c in candidates] == [("r1", "next"), ("r3", "returnUrl")]
    assert candidates[0]["url"] == probe_url("https://app.example.test/go", "next")
    assert "next=https%3A%2F%2Fshakerscan-redirect-probe.invalid%2F" in candidates[0]["url"]


def _probe(status, location):
    async def send(_url):
        return status, {"Location": location} if location is not None else {}
    candidate = {"url": "https://app.example.test/go?next=x", "parameter": "next", "route_id": "r1"}
    return asyncio.run(probe_candidate(candidate, send))


def test_only_a_location_naming_the_canary_is_an_open_redirect():
    proven = _probe(302, REDIRECT_CANARY_URL)
    assert proven["proof_state"] == "verified" and proven["location"] == REDIRECT_CANARY_URL
    assert _probe(302, "//shakerscan-redirect-probe.invalid/x")["proof_state"] == "verified"
    for status, location in ((302, "/home"), (302, "https://app.example.test/"), (200, REDIRECT_CANARY_URL),
                             (302, "https://shakerscan-redirect-probe.invalid.evil.example/"), (302, None)):
        result = _probe(status, location)
        assert result["proof_state"] == "not_proven" and result["location"] == ""
    assert redirects_to_canary("https:\\\\shakerscan-redirect-probe.invalid") is True


def test_a_proven_redirect_becomes_a_medium_finding_with_a_brief():
    proof = {**_probe(302, REDIRECT_CANARY_URL), "kind": "open_redirect_proof"}
    report = _report({"verify.redirect": [proof]}, capabilities={"verify.redirect": "redirect.verify_batch"})
    [finding] = report["findings"]
    assert (finding["title"], finding["severity"], finding["cwe"]) == ("Open redirect", "medium", "CWE-601")
    brief = build_finding_detail(finding)
    assert brief["class"] == "redirect.open" and "next" in brief["summary"]
    assert brief["severity"]["reason"].startswith("A link on this trusted origin")
    not_proven = _probe(302, "/home")
    assert _report({"verify.redirect": [not_proven]}, capabilities={"verify.redirect": "redirect.verify_batch"})["findings"] == []


def test_redirect_commands_send_the_canary_although_the_stored_url_is_masked():
    """Unit fixture: a proven redirect, stored through the runtime receipt redactor, which masks
    every query value of a URL, the probe's own canary included."""
    import api.runtime  # noqa: F401 -- importing the runtime installs its receipt redactor
    from api.runtime import receipts
    sent = probe_url("https://app.example.test/go", "next")

    async def send(_url):
        return 302, {"Location": REDIRECT_CANARY_URL}
    proof = asyncio.run(probe_candidate({"url": sent, "parameter": "next", "route_id": "r1"}, send))
    stored = receipts.redact_receipt_value({**proof, "kind": "open_redirect_proof"})
    assert stored["url"] == "https://app.example.test/go?next=%3Credacted%3E"
    [finding] = _report({"verify.redirect": [stored]}, capabilities={"verify.redirect": "redirect.verify_batch"})["findings"]
    brief = build_finding_detail(finding)
    for step in ("reproduce", "verify"):
        assert q(sent) in brief[step]["command"] and "redacted" not in brief[step]["command"]
    assert brief["reproduce"]["expect"] == "location: " + REDIRECT_CANARY_URL


def test_queries_the_deadline_cut_off_are_not_absent_records():
    # The capability's overall deadline left these labels empty; only host_mx answered.
    cut_off = ["dns_inspection:Timeout:3", "host_txt:Timeout", "dmarc:Timeout", "host_caa:Timeout"]
    assert _dns_findings({}, errors=cut_off) == {}
    # Before the per-label timeouts were recorded, only the summary error existed: the labels
    # without metadata are still unanswered, not answered-empty.
    assert _dns_findings({}, errors=["dns_inspection:Timeout:3"], answered=["host_mx"]) == {}
    # An authoritative negative answer (NXDOMAIN for _dmarc) is an answer.
    assert set(_dns_findings({}, answered=["dmarc", "host_mx"])) == {"dmarc_missing"}


def test_strict_dynamic_ignores_the_host_and_scheme_fallbacks():
    policy = "script-src 'nonce-r4nd' 'strict-dynamic' https: http: 'unsafe-inline'; object-src 'none'"
    assert header_value_issues({"content-security-policy": policy}, origin="https://a.example") == {}
    # Without 'strict-dynamic' the same fallbacks are real.
    plain = header_value_issues({"content-security-policy": policy.replace(" 'strict-dynamic'", "")},
                                origin="https://a.example")
    assert [code for _l, code, _t in plain["content-security-policy"]] == ["csp_script_any_origin"]
    # 'unsafe-eval' is not neutralised by 'strict-dynamic'.
    eval_issues = header_value_issues({"content-security-policy": "script-src 'nonce-a' 'strict-dynamic' 'unsafe-eval'"},
                                      origin="https://a.example")
    assert [code for _l, code, _t in eval_issues["content-security-policy"]] == ["csp_unsafe_eval"]


def test_a_header_sent_twice_with_the_same_valid_value_is_valid():
    assert header_value_issues({"x-frame-options": "SAMEORIGIN, SAMEORIGIN",
                                "x-content-type-options": "nosniff, nosniff"}, origin="https://a.example") == {}
    assert header_value_issues({"x-frame-options": "deny,DENY"}, origin="https://a.example") == {}
    conflicting = header_value_issues({"x-frame-options": "DENY, SAMEORIGIN", "x-content-type-options": "nosniff, none"},
                                      origin="https://a.example")
    assert set(conflicting) == {"x-frame-options", "x-content-type-options"}


def test_a_csp_that_only_sets_frame_ancestors_is_reported_as_no_script_policy():
    report = _report({"baseline.http": [_baseline("https://app.example.test", {**GOOD,
                      "content-security-policy": "frame-ancestors 'self'"})]})
    (csp,) = [f for f in report["findings"] if f["evidence"].get("check") == "weak_header_content-security-policy"]
    assert [item["code"] for item in csp["evidence"]["issues"]] == ["csp_no_script_policy"]
    assert "only frame-ancestors" in csp["evidence"]["issues"][0]["text"]


def test_report_endpoint_tokens_in_a_recorded_policy_are_redacted():
    policy = ("default-src * 'unsafe-inline'; report-uri https://o1.ingest.sentry.io/api/7/security/"
              "?sentry_key=abc123def456&sentry_env=prodenv9")
    report = _report({"baseline.http": [_baseline("https://app.example.test", {**GOOD, "content-security-policy": policy})]})
    (csp,) = [f for f in report["findings"] if f["evidence"].get("check") == "weak_header_content-security-policy"]
    stored = repr(csp["evidence"]) + repr(report["http"])
    assert "abc123def456" not in stored and "prodenv9" not in stored
    assert "?sentry_key=<redacted>&sentry_env=<redacted>" in csp["evidence"]["observed_value"]
    assert "sentry_key=<redacted>" in csp["evidence"]["observed_response"]["observed_headers"]["content-security-policy"]
