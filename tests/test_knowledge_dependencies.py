"""Unit tests: dependency significance rules, experiment binding, reuse, briefing bounds, CLI and MCP.

Unit fixtures only: dependency items and observations are literal dictionaries, the CLI talks to a
loopback stub, and the MCP path is in tests/test_knowledge_changes_mcp_route.py. The
PostgreSQL paths are in tests/test_knowledge_changes_postgres.py.
"""
from __future__ import annotations

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import uuid


from hunt import briefing as hunt_briefing
from hunt.interpretations import reuse_decision
from hunt.knowledge_dependencies import (
    INCOMPARABLE, MINOR, SIGNIFICANCE_RULES, SIGNIFICANT, bind_experiment, canonical_origin, compare_auth_surface,
    compare_deployment, compare_endpoint, compare_finding, compare_response, compare_service, compare_subject, decide, digest_format,
    operation_route, public_dependencies, service_key,
)

ROOT = Path(__file__).resolve().parents[1]
SESSION = "00000000-0000-4000-8000-000000005e55"


def _item(kind, observed, **extra):
    return {"type": kind, "key": f"{kind}-key", "observed": observed, **extra}


def _significance(changes):
    return {change["field"]: change["significance"] for change in changes}


def test_every_dependency_type_has_a_published_rule_and_age_is_never_one():
    assert set(SIGNIFICANCE_RULES) == {"endpoint", "response", "deployment", "auth_surface", "service", "finding",
                                       "subject", "age"}
    assert SIGNIFICANCE_RULES["age"].startswith("never")


def test_endpoint_rules_removal_is_significant_inventory_growth_is_minor():
    present = {"present": True, "auth_states": ["anonymous"], "param_shapes_sha256": "a"}
    item = _item("endpoint", present)
    assert _significance(compare_endpoint(item, {"present": False})) == {"present": SIGNIFICANT}
    assert compare_endpoint({**item, "is_subject": True}, {"present": False})[0]["historical"] is True
    assert _significance(compare_endpoint(_item("endpoint", {"present": False}), present)) == {"present": MINOR}
    grown = {"present": True, "auth_states": ["anonymous", "authenticated"], "param_shapes_sha256": "b"}
    assert _significance(compare_endpoint(item, grown)) == {"auth_states": MINOR, "param_shapes": MINOR}
    assert compare_endpoint(item, present) == []


def test_response_rules_status_media_type_and_keys_are_significant_body_alone_is_minor():
    before = {"action_id": "a", "status": 403, "media_type": "application/json", "json_keys_sha256": "k1"}
    item = _item("response", before)
    assert compare_response(item, None) == []  # nothing newer observed: no change, as of that observation
    same = dict(before)
    assert compare_response(item, same, recorded_body="1" * 64, newer_body="1" * 64) == []
    assert _significance(compare_response(item, same, recorded_body="1" * 64, newer_body="2" * 64)) == \
        {"body_digest": MINOR}
    changed = {**before, "status": 200, "media_type": "text/html", "json_keys_sha256": "k2"}
    assert _significance(compare_response(item, changed)) == {
        "status": SIGNIFICANT, "media_type": SIGNIFICANT, "json_keys_sha256": SIGNIFICANT}


def test_a_body_change_is_significant_for_a_negative_result():
    item = _item("response", {"action_id": "a", "status": 200, "media_type": "application/json",
                              "json_keys_sha256": "k"})
    same = {"status": 200, "media_type": "application/json", "json_keys_sha256": "k"}
    changes = compare_response(item, same, recorded_body="1" * 64, newer_body="2" * 64, body_significant=True)
    assert _significance(changes) == {"body_digest": SIGNIFICANT}
    assert compare_response(item, same, recorded_body="1" * 64, newer_body="1" * 64, body_significant=True) == []
    missing = compare_response(item, same, recorded_body="1" * 64, newer_body=None, body_significant=True)
    assert _significance(missing) == {"body_digest": INCOMPARABLE}


def test_body_digests_of_different_formats_are_never_compared():
    assert digest_format("1" * 64) == "sha256"
    assert digest_format("scrypt-v1:" + "ab" * 16) == "scrypt-v1"
    assert digest_format("hmac-installation:" + "cd" * 32) == "hmac-installation"
    assert digest_format("") is None and digest_format("other") == "unrecognized"
    item = _item("response", {"action_id": "a", "status": 200, "media_type": None, "json_keys_sha256": None})
    newer = {"status": 200, "media_type": None, "json_keys_sha256": None}
    changes = compare_response(item, newer, recorded_body="1" * 64, newer_body="scrypt-v1:" + "ab" * 16)
    assert _significance(changes) == {"body_digest": INCOMPARABLE}
    assert decide({"items": [item]}, changes, changes) == "unknown"  # incomparable is not unchanged


def test_deployment_rules_versions_and_banners_are_significant_certificates_are_not_dependencies():
    before = {"scan_id": "s1", "technologies": {"Express": "4.18", "jQuery": None, "Redis": "7"},
              "server_banners": ["nginx/1.24"], "server_banners_sha256": "b1", "certificate_sha256": "c1"}
    item = _item("deployment", before)
    assert compare_deployment(item, None) == []
    renewed = {**before, "scan_id": "s2", "certificate_sha256": "c2"}
    assert compare_deployment(item, renewed) == []
    changed = {**before, "scan_id": "s3", "technologies": {"Express": "5.0", "Bootstrap": None, "Redis": "7"},
               "server_banners_sha256": "b2"}
    assert _significance(compare_deployment(item, changed)) == {
        "technology:Express": SIGNIFICANT, "technology:jQuery": MINOR, "technology:Bootstrap": MINOR,
        "server_banners": SIGNIFICANT}
    dropped = {**before, "technologies": {"Express": "4.18", "jQuery": None}}
    assert _significance(compare_deployment(item, dropped)) == {"technology:Redis": SIGNIFICANT}
    # A Scan that recorded no technologies or no banners compares nothing (absence of data is no change).
    assert compare_deployment(item, {**before, "scan_id": "s4", "technologies": {}, "server_banners": [],
                                     "server_banners_sha256": "empty"}) == []


def test_auth_service_finding_and_subject_rules():
    auth = _item("auth_surface", {"routes_sha256": "r1", "count": 2})
    assert compare_auth_surface(auth, {"routes_sha256": "r1", "count": 2}) == []
    assert _significance(compare_auth_surface(auth, {"routes_sha256": "r2", "count": 3})) == {"routes": SIGNIFICANT}
    service = _item("service", {"present": True, "state": "open", "product": "OpenSSH", "version": "9.6"})
    assert _significance(compare_service(service, {"present": True, "state": "open", "product": "OpenSSH",
                                                   "version": "9.8"})) == {"version": SIGNIFICANT}
    assert _significance(compare_service(service, {"present": True, "state": "not_observed", "product": "OpenSSH",
                                                   "version": "9.6"})) == {"state": SIGNIFICANT}
    finding = _item("finding", {"severity": "medium", "url": "https://a/s", "tool": "nuclei",
                                "last_verification_verdict": None, "resurfaced_count": 0},
                    dismissal_reason="false_positive")
    assert compare_finding(finding, dict(finding["observed"])) == []
    assert _significance(compare_finding(finding, {**finding["observed"], "tool": "zap"})) == {"tool": MINOR}
    assert _significance(compare_finding(finding, {**finding["observed"], "severity": "high",
                                                   "last_verification_verdict": "exploited"})) == {
        "severity": SIGNIFICANT, "last_verification_verdict": SIGNIFICANT}
    # Noise never reopens: a verdict agreeing with the dismissal, an error or inconclusive verdict, a
    # lower severity, a cleared verdict.
    for verdict in ("false_positive", "error", "inconclusive", "likely_fixed", "blocked_by_security"):
        changes = compare_finding(finding, {**finding["observed"], "last_verification_verdict": verdict})
        assert SIGNIFICANT not in _significance(changes).values(), verdict
    assert SIGNIFICANT not in _significance(compare_finding(finding, {**finding["observed"],
                                                                      "severity": "low"})).values()
    verified = _item("finding", {**finding["observed"], "last_verification_verdict": "false_positive"})
    assert compare_finding(verified, {**finding["observed"], "last_verification_verdict": None}) == []  # cleared
    # An accepted risk proven exploitable was already accepted as real: not a change of the decision.
    accepted = {**finding, "dismissal_reason": "accepted_risk"}
    assert SIGNIFICANT not in _significance(compare_finding(accepted, {**finding["observed"],
                                            "last_verification_verdict": "exploited"})).values()
    # Resolved and detected again: a regression.
    assert _significance(compare_finding(finding, {**finding["observed"], "resurfaced_count": 1})) == \
        {"resurfaced": SIGNIFICANT}
    assert compare_finding(finding, None)[0]["historical"] is True
    assert compare_subject(_item("subject", {"exists": True}), False)[0]["historical"] is True


def test_decide_never_applicable_without_observed_dependencies():
    item = _item("endpoint", {"present": True})
    assert decide({"items": []}, [], []) == "unknown"
    assert decide({"items": [item], "unobserved": [{"type": "deployment"}]}, [], []) == "unknown"
    assert decide({"items": [item]}, [], []) == "applicable"
    significant = compare_endpoint(item, {"present": False})
    assert decide({"items": [item], "unobserved": [{"type": "deployment"}]}, significant, []) == "needs_revalidation"
    assert decide({"items": [item]}, compare_endpoint({**item, "is_subject": True}, {"present": False}), []) == \
        "historical"


def _redaction():
    """The real input redaction of the loaded app (the Hunt action ledger writes input summaries
    through it), so binding is tested on what is actually recorded."""
    from api import api as api_module
    routes = (nested for route in api_module.app.routes
              for nested in getattr(getattr(route, "original_router", None), "routes", (route,)))
    endpoint = next(route.endpoint for route in routes if getattr(route, "path", None) == "/hunts/{hunt_id}/query")
    return endpoint.__globals__["_hunt_redacted_capability_input"]


ORIGIN = "https://app.example"


def _cited(method="GET", path="/api/invoices/17", session=SESSION, **extra):
    raw = {"method": method, "path": path, **({"session_ref": session} if session else {}), **extra}
    return {"id": uuid.UUID(int=1), "default_origin": ORIGIN,
            "input_summary": {"input": _redaction()("http.request", raw)}}


def test_experiment_conditions_are_bound_only_to_what_the_cited_request_was():
    exact = {"origin": ORIGIN, "method": "GET", "route": "/api/invoices/{id}", "principals": [SESSION],
             "objects": ["invoice:17"], "technique": "http.request cross-tenant read"}
    assert bind_experiment(exact, [_cited()])["bound"] is True
    assert bind_experiment({**exact, "route": None, "operation": "GET /api/invoices/{id}"}, [_cited()])["bound"]
    for mismatch, cited in (({"method": "POST"}, _cited()), ({"route": "/api/orders/{id}"}, _cited()),
                            ({"principals": ["admin"]}, _cited()), ({"principals": [SESSION, "other"]}, _cited()),
                            ({"technique": "sqlmap"}, _cited()), ({}, _cited(path="/api/invoices/17/lines")),
                            ({}, _cited(session="")), ({"principals": None, "roles": ["viewer"]}, _cited())):
        conditions = {key: value for key, value in {**exact, **mismatch}.items() if value is not None}
        assert bind_experiment(conditions, [cited])["bound"] is False, mismatch
    for mismatch in ({"objects": ["invoice:99"]}, {"inputs": {"q": "x"}}, {"route": "/{a}/{b}/{c}"},
                     {"route": "/api/{collection}/{id}"}, {"route": "/api/invoices/{id}/{more}"},
                     {"objects": None}, {"technique": "not-http.request"}, {"principals": None},
                     {"service": "tcp/443"}, {"environment": "staging"}, {"application_state": {"cart": "empty"}},
                     {"origin": None}, {"origin": "https://app.example:8443"}, {"origin": "http://app.example"},
                     # A named id standing in a literal segment, or a concrete route naming objects.
                     {"route": "/api/invoices/17"}, {"objects": ["invoice:17", "invoice:18"]}):
        conditions = {key: value for key, value in {**exact, **mismatch}.items() if value is not None}
        assert bind_experiment(conditions, [_cited()])["bound"] is False, mismatch
    concrete = {**exact, "route": "/api/invoices/17"}
    assert bind_experiment({k: v for k, v in concrete.items() if k != "objects"}, [_cited()])["bound"] is True
    # Two placeholders need two named objects, each in exactly its own segment.
    nested = _cited(path="/api/users/5/invoices/17")
    two = {**exact, "route": "/api/users/{uid}/invoices/{id}"}
    assert bind_experiment(two, [nested])["bound"] is False  # user 5 was part of the request, not named
    assert bind_experiment({**two, "objects": ["user:5", "invoice:17"]}, [nested])["bound"] is True
    assert bind_experiment({**two, "objects": ["user:17", "invoice:5"]}, [_cited(path="/api/users/5/invoices/5")]
                           )["bound"] is False  # duplicate ids are ambiguous
    # The request's origin: explicit, or the Hunt target's when none was given; a different port is
    # a different origin.
    port = _cited(origin="https://app.example:8443")
    assert bind_experiment(exact, [port])["bound"] is False
    assert bind_experiment({**exact, "origin": "https://app.example:8443"}, [port])["bound"] is True
    assert bind_experiment({**exact, "origin": "https://APP.example:443/"}, [_cited()])["bound"] is True
    recorded = _cited(method="POST", json_body={"owner": "victim"})["input_summary"]["input"]
    assert recorded["body_kind"] == "json" and "json_body" not in recorded  # the real redaction ran
    # Anything recorded beyond method, path, origin and session is not a plain request: bodies (which
    # the ledger keeps only as body_kind), a principal binding without a session, a pinned address,
    # redirects, query, headers, captures and request bindings.
    for extra in ({"json_body": {"owner": "victim"}}, {"form_body": {"user": "x"}},
                  {"as_principal": "primary"}, {"via_address": "203.0.113.9"}, {"follow_redirects": True},
                  {"follow_redirects": False}, {"query": {"debug": "1"}}, {"headers": {"X-Tenant": "2"}},
                  {"capture": [{"name": "a", "json_pointer": "/a"}]}, {"path": "/api/invoices/17?debug=1"}):
        cited = _cited(**{k: v for k, v in extra.items() if k != "path"},
                       **({"path": extra["path"]} if "path" in extra else {}))
        assert bind_experiment(exact, [cited])["bound"] is False, extra
    principal = _cited(session="", as_principal="primary")
    assert bind_experiment({**exact, "principals": ["anonymous"]}, [principal])["bound"] is False
    anonymous = {**exact, "principals": ["anonymous"]}
    assert bind_experiment(anonymous, [_cited(session="")])["bound"] is True
    assert bind_experiment(exact, [])["bound"] is False
    assert bind_experiment(exact, [{"id": uuid.UUID(int=2), "input_summary": {}}])["bound"] is False
    assert operation_route({"operation": "delete /a/42"}) == ("DELETE", "/a/{id}")
    assert service_key("tcp/443") == ("tcp", 443) and service_key("8443/UDP") == ("udp", 8443)
    assert service_key("443") is None and service_key("tcp/70000") is None
    assert canonical_origin("https://user@app.example") is None and canonical_origin("ftp://a") is None
    assert canonical_origin("http://App.Example:80") == "http://app.example"


def _negative(**extra):
    dependencies = {"schema": "knowledge-dependencies/v1", "binding": {"bound": True},
                    "items": [{"type": t} for t in ("deployment", "endpoint", "response")], "unobserved": []}
    return {"negative_state": "experiment_completed_negative", "status": "active", "experiment_key": "a" * 64,
            "applicability": "applicable", "dependencies": dependencies, **extra}


FRESH = {"observed": True, "by": "the same request after this Hunt started"}


def test_reuse_needs_every_guard_and_the_skip_is_only_advice():
    assert reuse_decision(_negative(), "a" * 64, evaluated=True, reobservation=FRESH)["skip"] is True
    assert "Advice" in reuse_decision(_negative(), "a" * 64, evaluated=True, reobservation=FRESH)["override"]
    # Applicable is not enough: an evaluation during this check and a fresh observation are required.
    assert reuse_decision(_negative(), "a" * 64)["skip"] is False
    assert reuse_decision(_negative(), "a" * 64, reobservation=FRESH)["skip"] is False
    assert reuse_decision(_negative(), "a" * 64, evaluated=True)["skip"] is False
    assert reuse_decision(_negative(), "a" * 64, evaluated=True,
                          reobservation={"observed": False, "reason": "x"})["skip"] is False
    dependencies = _negative()["dependencies"]
    for variant in (
            {"applicability": "unknown"}, {"applicability": "needs_revalidation"}, {"applicability": "historical"},
            {"status": "superseded"}, {"status": "retracted"}, {"negative_state": "experiment_inconclusive"},
            {"dependencies": {**dependencies, "binding": {"bound": False}}},
            {"dependencies": {k: v for k, v in dependencies.items() if k != "binding"}},
            {"dependencies": {**dependencies, "unobserved": [{"type": "deployment"}]}},
            {"dependencies": {**dependencies, "items": [{"type": "endpoint"}, {"type": "response"}]}},
            {"dependencies": {}}):
        assert reuse_decision(_negative(**variant), "a" * 64, evaluated=True,
                              reobservation=FRESH)["skip"] is False, variant
    assert reuse_decision(_negative(), "b" * 64, evaluated=True, reobservation=FRESH)["skip"] is False


def test_public_dependencies_carry_no_digests():
    recorded = {"schema": "knowledge-dependencies/v1", "captured_at": "t", "binding": {"bound": True},
                "items": [{"type": "response", "key": "GET /a session:none",
                           "observed": {"completed_at": "t", "body_digest_format": "sha256", "status": 200}}]}
    public = public_dependencies(recorded)
    assert public["items"] == [{"type": "response", "key": "GET /a session:none", "observed_at": "t"}]
    assert "sha256" not in json.dumps(public["items"]) and public_dependencies({}) == {"tracked": False}


def test_changed_since_last_hunt_lists_give_way_and_the_cut_is_stated():
    affected = [{"id": str(uuid.uuid4()), "kind": "observation", "negative_state": None,
                 "applicability": "needs_revalidation", "reopened_for_review": False,
                 "caused_by": [{"type": "deployment", "key": "scan", "field": "technology:" + "x" * 200}]}] * 5
    briefing = {"schema_version": "hunt-briefing/v1", "instructions": {"mode": "full", "text": "short"},
                "objective": {"text": "goal"}, "trimmed": [],
                "changed_since_last_hunt": {"knowledge": {"affected": affected},
                                            "deployment": {"changes": [{"field": "technology:Express"}] * 3}}}
    room = len(json.dumps({**briefing, "changed_since_last_hunt": {"knowledge": {"affected": []},
                                                                   "deployment": {"changes": []}}})) + 400
    bounded = hunt_briefing.bound_briefing(briefing, limit=room)
    assert bounded["changed_since_last_hunt"]["knowledge"]["affected"] == []
    assert any(item.startswith("changed_since_last_hunt.knowledge.affected removed") for item in bounded["trimmed"])
    assert bounded["instructions"]["mode"] == "full"


# --- CLI ------------------------------------------------------------------------------------------

REPORT = {
    "since": {"kind": "last_hunt", "at": "2026-10-10T00:00:00+00:00", "resolved": True},
    "sections": {
        "endpoints": {"added": {"count": 1, "items": [{"method": "GET", "path": "/x\x1b[2J‮evil",
                                                       "auth_state": "anonymous"}]},
                      "removed": {"count": 0, "items": []}, "auth_surface": {"significant": True}},
        "deployment": {"compared": True, "changes": [{"field": "technology:Express", "before": "4.18",
                                                      "after": "5.0\x07", "significance": "significant"}]},
        "responses": {"changed": []}, "findings": {"new": {"count": 2}},
        "subdomains": {"new_targets": [{"host": "new.example.test", "source": "gungnir-monitor"}]}},
    "knowledge": {"active_by_applicability": {"applicable": 3, "needs_revalidation": 1},
                  "affected": [{"id": "e-1", "kind": "negative_result", "negative_state": "finding_dismissed",
                                "applicability": "needs_revalidation", "reopened_for_review": True,
                                "caused_by": [{"type": "finding", "key": "f", "field": "severity"}]}]},
}


class _Stub:
    def __init__(self, status=200, body=REPORT):
        self.paths: list[str] = []
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                return

            def do_GET(self):  # noqa: N802
                stub.paths.append(self.path)
                data = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server.server_address[1]}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def _cli():
    sys.path.insert(0, str(ROOT / "scripts"))
    import v2_cli
    return v2_cli


def test_cli_knowledge_changes_is_read_only_and_renders_target_text_inert(capsys):
    v2_cli = _cli()
    stub = _Stub()
    try:
        assert v2_cli.main(["--api-url", stub.url, "knowledge", "changes", "t-1", "--since", "release"]) == 0
    finally:
        stub.close()
    out = capsys.readouterr().out
    assert stub.paths == ["/targets/t-1/knowledge/changes?since=release"]
    assert "\x1b" not in out and "\x07" not in out and "‮" not in out
    assert "deployment technology:Express: 4.18" in out and "reopened for review" in out
    assert "authentication surface changed" in out and "nothing was sent to the target" in out


def test_cli_knowledge_changes_reports_a_refusal(capsys):
    v2_cli = _cli()
    stub = _Stub(status=422, body={"detail": {"error": "invalid_since", "message": "since needs a time zone"}})
    try:
        assert v2_cli.main(["--api-url", stub.url, "knowledge", "changes", "t-1", "--since", "2026-01-01"]) == 2
    finally:
        stub.close()
    assert "shakerscan knowledge changes" in capsys.readouterr().err
