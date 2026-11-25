"""A recognised product's own template checks: selection, holds, the worker plan and the sweep."""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

import pytest

from api import agent_tools
from api.hunt.scanner_identity import body_authority_refusal
from api.hunt.server_sweep import Sweep, product_candidate, template_matches
from api.runtime import product_templates
from api.runtime.capability_registry import CAPABILITY_REGISTRY, CapabilityInputContractError
from api.runtime.product_templates import (
    PRODUCT_KEYS, PRODUCT_WINDOW_COUNTS, READ_ONLY_WINDOW_REQUESTS, STATE_CHANGING_WINDOW_REQUESTS,
    product_hold, product_request, product_windows, resolve_product_window,
)
from api.scan import nuclei_template_index


def _template(root: Path, name: str, body: str) -> None:
    path = root / "http" / f"{name}.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")


@pytest.fixture
def bundle(tmp_path):
    """A small bundle: one template of every kind the selection tells apart."""
    root = tmp_path / "bundle"
    (root / "http").mkdir(parents=True)
    (root / ".nuclei-ignore").write_text("tags:\n  - dos\n", encoding="utf-8")
    (root / "helpers").mkdir()
    (root / "helpers" / "paths.txt").write_text("a\nb\nc\n", encoding="utf-8")
    _template(root, "jenkins-read", """id: jenkins-read
info: {name: Jenkins read, severity: high, tags: "jenkins,unauth"}
http:
  - method: GET
    path: ["{{BaseURL}}/api/json", "{{BaseURL}}/whoAmI/api/json"]
""")
    _template(root, "jenkins-files", """id: jenkins-files
info: {name: Jenkins files, severity: medium, tags: "jenkins,exposure"}
http:
  - method: GET
    path: ["{{BaseURL}}/{{p}}"]
    payloads:
      p: helpers/paths.txt
      q: [x, y]
""")
    _template(root, "jenkins-script", """id: jenkins-script
info: {name: Jenkins script, severity: critical, tags: "jenkins,rce"}
http:
  - raw:
      - |
        POST /script HTTP/1.1
        Host: {{Hostname}}

        script=println(1)
""")
    _template(root, "jenkins-weak-password", """id: jenkins-weak-password
info: {name: Jenkins weak password, severity: high, tags: "jenkins,default-login"}
http:
  - method: POST
    path: ["{{BaseURL}}/j_acegi_security_check"]
    body: "j_username={{user}}&j_password={{pass}}"
    payloads:
      user: [admin]
      pass: [admin, password]
""")
    _template(root, "jenkins-delete", """id: jenkins-delete
info: {name: Jenkins delete, severity: high, tags: "jenkins,intrusive"}
http:
  - method: DELETE
    path: ["{{BaseURL}}/job/x"]
""")
    _template(root, "jenkins-oob", """id: jenkins-oob
info: {name: Jenkins oob, severity: high, tags: "jenkins,ssrf"}
http:
  - method: GET
    path: ["{{BaseURL}}/x?u={{interactsh-url}}"]
""")
    _template(root, "jenkins-flow", """id: jenkins-flow
info: {name: Jenkins flow, severity: high, tags: "jenkins"}
flow: http(1) && http(2)
http:
  - method: GET
    path: ["{{BaseURL}}/a"]
  - method: GET
    path: ["{{BaseURL}}/b"]
""")
    _template(root, "jenkins-race", """id: jenkins-race
info: {name: Jenkins race, severity: low, tags: "jenkins"}
http:
  - method: GET
    path: ["{{BaseURL}}/r"]
    race: true
    race_count: 4
""")
    _template(root, "grafana-read", """id: grafana-read
info: {name: Grafana read, severity: high, tags: "grafana"}
http:
  - method: GET
    path: ["{{BaseURL}}/api/health"]
""")
    nuclei_template_index.clear_index_cache()
    yield root
    nuclei_template_index.clear_index_cache()


def _index(root: Path):
    return nuclei_template_index._cached_index(str(root))


def test_request_upper_bound_counts_paths_payload_combinations_and_races(bundle):
    bounds = {record.template_id: record.max_requests for record in _index(bundle).templates}
    assert bounds["jenkins-read"] == 2
    # one path x (3 file lines x 2 inline values): the default attack is counted as clusterbomb
    assert bounds["jenkins-files"] == 6
    assert bounds["jenkins-race"] == 4
    assert bounds["jenkins-script"] == 1
    # a flow step can repeat requests: no static bound
    assert bounds["jenkins-flow"] is None


def test_read_only_selection_has_only_get_templates_without_attack_input(bundle):
    windows, counts, bounds = product_windows(_index(bundle), "jenkins", "read_only")
    assert windows == [("jenkins-files", "jenkins-race", "jenkins-read")]
    assert bounds == [12]
    # the out-of-band and flow templates are exploit-class: they belong to the state-changing checks
    assert counts == {}


def test_state_changing_selection_never_runs_logins_or_intrusive_templates(bundle):
    windows, counts, _bounds = product_windows(_index(bundle), "jenkins", "state_changing")
    assert windows == [("jenkins-script",)]
    assert counts == {"excluded_intrusive": 1, "excluded_login_attempts": 1, "excluded_oob": 1,
                      "excluded_unbounded": 1}


def test_a_selection_larger_than_one_hold_is_cut_into_windows(bundle, monkeypatch):
    monkeypatch.setattr(product_templates, "READ_ONLY_WINDOW_REQUESTS", 6)
    windows, _counts, bounds = product_windows(_index(bundle), "jenkins", "read_only")
    assert windows == [("jenkins-files",), ("jenkins-race", "jenkins-read")]
    assert bounds == [6, 6]
    monkeypatch.setattr(product_templates, "READ_ONLY_WINDOW_REQUESTS", 5)
    windows, counts, _bounds = product_windows(_index(bundle), "jenkins", "read_only")
    assert ("jenkins-files",) not in windows and counts["excluded_exceeds_window"] == 1


def test_resolution_fails_closed(bundle, tmp_path):
    ok = resolve_product_window(str(bundle), "jenkins", "read_only", 0, allow_state_changing_http=False)
    assert ok.skip_reason is None and ok.request_upper_bound == 12 and ok.windows == 1
    refused = resolve_product_window(str(bundle), "jenkins", "state_changing", 0, allow_state_changing_http=False)
    assert refused.skip_reason == "needs_state_changing_http" and refused.template_ids == ()
    past = resolve_product_window(str(bundle), "jenkins", "read_only", 1, allow_state_changing_http=False)
    assert past.skip_reason == "window_past_selection" and past.template_ids == ()
    none = resolve_product_window(str(bundle), "ray", "read_only", 0, allow_state_changing_http=False)
    assert none.skip_reason == "no_eligible_templates"
    missing = resolve_product_window(str(tmp_path / "absent"), "jenkins", "read_only", 0,
                                     allow_state_changing_http=False)
    assert missing.skip_reason == "nuclei_template_index_unavailable"


def test_product_input_is_validated_by_the_hunt_schema():
    accepted = CAPABILITY_REGISTRY.validate_hunt_input(
        "templates.scan", {"product": "jenkins", "product_checks": "state_changing", "product_window": 2,
                           "path": "/jenkins/"})
    assert product_request(accepted) == ("jenkins", "state_changing", 2)
    for bad in ({"product": "not-a-product"}, {"product": "jenkins", "product_checks": "all"},
                {"product": "jenkins", "product_window": -1}):
        with pytest.raises(CapabilityInputContractError):
            CAPABILITY_REGISTRY.validate_hunt_input("templates.scan", bad)
    assert product_request({"path": "/"}) is None


def test_admission_holds_one_window_and_writes_as_verifier_writes():
    read = agent_tools.hunt_scanner_dispatch_budgets(
        "templates.scan", **agent_tools.hunt_scanner_budget_context({}, {"product": "ray"}))
    assert read == (product_hold("read_only"),)
    assert read[0]["http_requests"] == READ_ONLY_WINDOW_REQUESTS and "verifier_write_requests" not in read[0]
    writes = agent_tools.hunt_scanner_dispatch_budgets(
        "templates.scan",
        **agent_tools.hunt_scanner_budget_context({}, {"product": "ray", "product_checks": "state_changing"}))
    assert writes[0]["verifier_write_requests"] == writes[0]["http_requests"] == STATE_CHANGING_WINDOW_REQUESTS
    passive = agent_tools.hunt_scanner_dispatch_budgets(
        "templates.scan", **agent_tools.hunt_scanner_budget_context({}, {}))
    assert passive[0]["http_requests"] == agent_tools.canonical_passive_nuclei_request_upper_bound()


def _options(bundle, monkeypatch, values, *, writes=False, hold=None):
    monkeypatch.setenv("NUCLEI_TEMPLATES", str(bundle))
    policy = {"active_testing": True, "allow_state_changing_http": writes}
    checks = values.get("product_checks", "read_only")
    return agent_tools.canonical_hunt_scanner_options(
        "templates.scan", values, policy, hold if hold is not None else product_hold(checks))


def test_the_worker_runs_exactly_the_resolved_window(bundle, monkeypatch):
    options = _options(bundle, monkeypatch, {"product": "jenkins", "path": "/jenkins/"})
    assert options["template_ids"] == "jenkins-files,jenkins-race,jenkins-read"
    assert options["product_request_upper_bound"] == 12 and options["path"] == "/jenkins/"
    assert options["nuclei_active_state_changing"] is False
    argv = agent_tools._tmpl_nuclei("http://t.example/jenkins/", options)
    assert argv[argv.index("-id") + 1] == options["template_ids"]
    assert "-tags" not in argv and "-severity" not in argv and "-no-interactsh" in argv
    plan = agent_tools.build_enforced_scanner_plan(
        "nuclei", "http://t.example/jenkins/", options, reserved_budget=product_hold("read_only"),
        pinned_address="192.0.2.10")
    assert plan.budget_proof["upper_bound"]["http_requests"] == 12
    assert plan.budget_proof["method"] == "reviewed_template_allowlist"
    assert plan.budget_proof["inputs"]["profile"] == "product_templates"


def test_the_worker_refuses_writes_without_permission_and_windows_over_the_hold(bundle, monkeypatch):
    with pytest.raises(agent_tools.AgentToolError, match="needs_state_changing_http"):
        _options(bundle, monkeypatch, {"product": "jenkins", "product_checks": "state_changing"})
    sc = _options(bundle, monkeypatch, {"product": "jenkins", "product_checks": "state_changing"}, writes=True)
    assert sc["template_ids"] == "jenkins-script" and sc["nuclei_active_state_changing"] is True
    with pytest.raises(agent_tools.AgentToolError, match="the call holds 7"):
        _options(bundle, monkeypatch, {"product": "jenkins"}, hold={"http_requests": 7, "tool_wall_seconds": 30})
    with pytest.raises(agent_tools.AgentToolError, match="window_past_selection"):
        _options(bundle, monkeypatch, {"product": "jenkins", "product_window": 3})
    with pytest.raises(agent_tools.AgentToolError, match="exceeds the reservation"):
        agent_tools.build_enforced_scanner_plan(
            "nuclei", "http://t.example/", {**sc, "product_request_upper_bound": 999},
            reserved_budget=product_hold("state_changing"), pinned_address="192.0.2.10")


def test_state_changing_product_checks_need_the_hunts_write_permission():
    values = {"product": "ray", "product_checks": "state_changing"}
    refusal = body_authority_refusal("templates.scan", values, {"active_testing": True})
    assert refusal is not None and refusal.reason_code == "state_changing_http_not_allowed"
    assert body_authority_refusal("templates.scan", values,
                                  {"active_testing": True, "allow_state_changing_http": True}) is None
    assert body_authority_refusal("templates.scan", {"product": "ray"}, {"active_testing": True}) is None


def _match(template_id, url, *, tags, severity="high", name=None):
    return {"kind": "template_match", "template_id": template_id, "matched_at": url, "tags": tags,
            "severity": severity, "name": name or template_id}


def test_a_match_becomes_a_candidate_of_the_class_its_template_names():
    exposure = product_candidate("kubelet", "read_only", _match(
        "kubernetes-pods-api", "http://t/pods", tags=["kubernetes", "exposure"]), "a1")
    assert exposure["family"] == "data_exposure" and exposure["locus"] == {"path": "/pods", "method": "GET"}
    assert exposure["evidence_refs"] == ["action:a1"]
    rce = product_candidate("ray", "state_changing", _match(
        "cve-2023-48022", "http://t/api/jobs/x/logs", tags=["ray", "rce"], severity="critical"), "a2")
    assert rce["family"] == "command_injection" and "method" not in rce["locus"]
    query = product_candidate("joomla", "read_only", _match(
        "cve-2023-23752", "http://t/api/index.php/v1/config/application?public=true",
        tags=["joomla", "disclosure"], severity="medium"), "a3")
    assert query["locus"]["path"] == "/api/index.php/v1/config/application?public=true"
    redacted = product_candidate("joomla", "read_only", _match(
        "cve-2023-23752", "http://t/api/index.php/v1/config/application?public=%3Credacted%3E",
        tags=["joomla", "disclosure"]), "a7")
    assert redacted["locus"]["path"] == "/api/index.php/v1/config/application"
    doubled = product_candidate("wordpress", "read_only", _match(
        "wordpress-accessible-wpconfig", "http://t//wp-config.php", tags=["wordpress", "backup"]), "a8")
    assert doubled["locus"]["path"] == "/wp-config.php"
    # tagged only by product and year, named for what it reads
    named = product_candidate("joomla", "read_only", _match(
        "cve-2023-23752", "http://t/api/index.php/v1/config/application?public=true",
        tags=["cve", "joomla"], severity="medium", name="Joomla! Webservice - Password Disclosure"), "a6")
    assert named["family"] == "data_exposure"
    misconfig = product_candidate("docker_api", "read_only", _match(
        "misconfigured-docker", "http://t/images/json", tags=["docker", "misconfig"], severity="critical",
        name="Docker Container - Misconfiguration Exposure"), "a4")
    assert misconfig["family"] == "security_misconfiguration"
    # A bare detection is not a weakness; a match without its action cannot be cited.
    assert product_candidate("jenkins", "read_only", _match(
        "jenkins-detect", "http://t/", tags=["jenkins", "tech", "detect"], severity="info"), "a5") is None
    assert product_candidate("jenkins", "read_only", _match(
        "unauthenticated-jenkins", "http://t/jenkins/", tags=["jenkins"]), None) is None


def test_matches_are_read_from_the_action_result():
    result = {"action_id": "a", "action_result": {"observations": [
        _match("x", "http://t/x", tags=[]), {"kind": "request_response"}, {"kind": "template_match"}]}}
    assert [item["template_id"] for item in template_matches(result)] == ["x"]
    assert template_matches(None) == []


class _Engine:
    def __init__(self):
        self.calls = []
        self.candidates = []

    async def call(self, capability, values, key):
        self.calls.append((capability, dict(values), key))
        if capability == "templates.scan":
            base = "http://t" + str(values.get("path") or "/")
            matches = []
            if values["product"] == "jenkins" and values["product_checks"] == "read_only":
                matches = [_match("unauthenticated-jenkins", "http://t/jenkins/", tags=["jenkins"]),
                           _match("jenkins-users", base + "asynchPeople/api/json",
                                  tags=["jenkins", "exposure"], severity="info")]
            if values["product"] == "jenkins" and values["product_checks"] == "state_changing":
                matches = [_match("jenkins-script", "http://t/jenkins/script", tags=["jenkins", "rce"])]
            return {"action_id": f"x{len(self.calls)}", "action_result": {"status": "success",
                                                                       "observations": matches}}
        return {"action_id": f"x{len(self.calls)}", "action_result": {"status": "success", "observations": []}}

    async def create(self, values):
        self.candidates.append(dict(values))
        return {"candidate": {"id": f"c{len(self.candidates)}"}}


def _sweep_run(*, writes):
    return {"id": "h1", "target_id": "t1", "target_kind": "web", "status": "active", "completed_at": None,
            "policy_json": json.dumps({"allowed_capabilities": ["templates.scan", "candidate.verify"],
                                       "allow_state_changing_http": writes, "approval_receipt_id": "r1",
                                       "active_testing": True}),
            "context_pack": json.dumps({})}


def _sweep(engine, state):
    async def live():
        return True
    return Sweep(call=engine.call, create_candidate=engine.create, state=state, live=live)


@pytest.mark.parametrize("writes", [False, True])
def test_the_sweep_runs_each_products_templates_at_the_root_and_where_it_answered(writes):
    engine = _Engine()
    state = {"products": ["jenkins", "wordpress", "openai_api"],
             "product_paths": {"jenkins": ["/jenkins/api/json", "/api/json"]}}
    asyncio.run(_sweep(engine, state).run(_sweep_run(writes=writes), {"open": []}))
    scans = [values for capability, values, _key in engine.calls if capability == "templates.scan"]
    read = [values for values in scans if values["product_checks"] == "read_only"]
    assert {(values["product"], values.get("path", "/")) for values in read} == {
        ("jenkins", "/"), ("jenkins", "/jenkins/"), ("wordpress", "/")}
    assert sorted(values["product_window"] for values in read if values["product"] == "wordpress") == list(
        range(PRODUCT_WINDOW_COUNTS[("wordpress", "read_only")]))
    written = [values for values in scans if values["product_checks"] == "state_changing"]
    assert bool(written) is writes
    titles = [candidate["title"] for candidate in engine.candidates]
    # one candidate per template and path, however many bases matched it
    assert titles.count("unauthenticated-jenkins (unauthenticated-jenkins)") == 1
    assert ("jenkins-script (jenkins-script)" in titles) is writes
    verified = [values for capability, values, _key in engine.calls if capability == "candidate.verify"]
    # only the exposure is handed to candidate.verify
    assert len(verified) == sum(1 for candidate in engine.candidates if candidate["family"] == "data_exposure")


def test_the_sweep_runs_no_product_templates_without_active_approval():
    engine = _Engine()
    run = _sweep_run(writes=True)
    policy = json.loads(run["policy_json"])
    policy["approval_receipt_id"] = None
    run["policy_json"] = json.dumps(policy)
    asyncio.run(_sweep(engine, {"products": ["jenkins"]}).run(run, {"open": []}))
    assert not [call for call in engine.calls if call[0] == "templates.scan"]


def test_every_product_key_has_templates_and_is_one_discovery_recognises():
    from api.hunt.auto_discovery import PRODUCTS
    assert set(PRODUCT_KEYS) <= {product.key for product in PRODUCTS}


def test_pinned_bundle_window_plan():
    """Image test: the pinned bundle the scanner image installs (``NUCLEI_TEMPLATES``).

    Every product's selection fits the holds as recorded: the window counts the sweep runs
    (PRODUCT_WINDOW_COUNTS) are the bundle's, and no window can send more than its hold."""
    if "NUCLEI_TEMPLATES" not in os.environ:
        pytest.skip("requires the pinned Nuclei template bundle of the scanner image")
    index = nuclei_template_index._cached_index(nuclei_template_index.nuclei_templates_directory())
    for product in PRODUCT_KEYS:
        for checks, hold in (("read_only", READ_ONLY_WINDOW_REQUESTS),
                             ("state_changing", STATE_CHANGING_WINDOW_REQUESTS)):
            windows, counts, bounds = product_windows(index, product, checks)
            assert len(windows) <= product_templates.product_window_count(product, checks), (product, checks)
            assert (len(windows) > 1) == ((product, checks) in PRODUCT_WINDOW_COUNTS), (product, checks)
            assert all(bound <= hold for bound in bounds)
            assert "excluded_exceeds_window" not in counts, (product, checks)
