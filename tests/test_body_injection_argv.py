"""The injection tools must be able to reach a request body.

`_tmpl_dalfox` and `_tmpl_sqlmap` were deliberately GET-only -- "no data body" -- so even once a
body field became a candidate there was no way to test it. Both binaries support the flags needed
(`dalfox -d/--data -X/--method -p/--param`, `sqlmap --data -p`), verified against the images in the
worker.

The body carries benign placeholder values only. The tools inject their own payloads into the one
field named by `-p`, so a candidate stays one field's worth of work and its budget stays
proportional.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))

import agent_tools  # noqa: E402

URL = "https://target.test/rest/user/login"


def test_dalfox_is_unchanged_without_a_body():
    args = agent_tools._tmpl_dalfox(URL, {"severity": "high"})
    assert args[:2] == ["url", URL]
    for flag in ("-d", "--data", "-X", "--method", "-p", "--param"):
        assert flag not in args


def test_dalfox_sends_the_body_and_targets_one_field():
    args = agent_tools._tmpl_dalfox(URL, {
        "severity": "high", "method": "POST",
        "body_field_names": ["email", "password"], "content_type": "application/json",
        "injection_field": "password",
    })
    assert "-X" in args and args[args.index("-X") + 1] == "POST"
    # Every declared field is offered, not just the anchor: the tool tests them in one run.
    assert [args[i + 1] for i, item in enumerate(args) if item == "-p"] == ["email", "password"]
    body = args[args.index("-d") + 1]
    decoded = json.loads(body)
    assert sorted(decoded) == ["email", "password"], "every declared field must be present"
    assert all(isinstance(value, str) and value for value in decoded.values())


def test_sqlmap_is_unchanged_without_a_body():
    args = agent_tools._tmpl_sqlmap(URL, {})
    assert args[:2] == ["-u", URL]
    assert not any(item.startswith("--data") for item in args)
    assert "-p" not in args


def test_sqlmap_sends_the_body_and_targets_one_field():
    args = agent_tools._tmpl_sqlmap(URL, {
        "method": "POST", "body_field_names": ["email", "password"],
        "content_type": "application/json", "injection_field": "email",
    })
    assert "--data" in args
    decoded = json.loads(args[args.index("--data") + 1])
    assert sorted(decoded) == ["email", "password"]
    assert args[args.index("-p") + 1] == "email,password"


def test_a_form_content_type_produces_a_form_body():
    args = agent_tools._tmpl_sqlmap(URL, {
        "method": "POST", "body_field_names": ["user", "pass"],
        "content_type": "application/x-www-form-urlencoded", "injection_field": "user",
    })
    body = args[args.index("--data") + 1]
    assert "=" in body and "&" in body and not body.startswith("{")


def test_an_injection_field_outside_the_declared_body_is_refused():
    # The field comes from a manifest that already validated it against its endpoint; a mismatch
    # here means something upstream is inconsistent, and guessing would test the wrong input.
    import pytest

    for template in (agent_tools._tmpl_dalfox, agent_tools._tmpl_sqlmap):
        with pytest.raises(ValueError):
            template(URL, {"method": "POST", "body_field_names": ["a", "b"],
                           "content_type": "application/json", "injection_field": "c"})


def test_body_values_are_placeholders_not_payloads():
    # The engine supplies inert values; the tool supplies the attack. A payload here would send
    # attack traffic outside the tool's own accounting.
    args = agent_tools._tmpl_sqlmap(URL, {
        "method": "POST", "body_field_names": ["q"],
        "content_type": "application/json", "injection_field": "q"})
    body = args[args.index("--data") + 1]
    for suspicious in ("'", '"or"', "<script", "UNION", "--", ";"):
        assert suspicious not in json.loads(body)["q"], suspicious


def test_sqlmap_does_not_abandon_an_endpoint_that_rejects_credentials():
    """An authentication endpoint answers wrong credentials with 401/403.

    sqlmap treats that on its connection test as "not authorized ... skipping to the next target",
    so it refuses to test the endpoint class where body injection most often lives. Verified
    against the worker's own sqlmap: without this Juice Shop's login SQLi is unreachable, and with
    it sqlmap reports the JSON email parameter vulnerable with a boolean-based blind payload.
    """
    args = agent_tools._tmpl_sqlmap(URL, {
        "method": "POST", "body_field_names": ["email", "password"],
        "content_type": "application/json", "injection_field": "email"})
    ignored = [args[i + 1] for i, item in enumerate(args) if item == "--ignore-code"]
    assert sorted(ignored) == ["401", "403"]


def test_a_query_scan_still_treats_an_auth_failure_as_before():
    # Scoped to the body path: an existing query-parameter scan must not silently change what it
    # accepts as a testable response.
    args = agent_tools._tmpl_sqlmap(URL, {})
    assert "--ignore-code" not in args


# --- A body attempt is a different cost class -------------------------------------------------

def test_a_body_attempt_gets_a_floor_matched_to_what_the_tool_needs():
    """Measured, not guessed.

    Against the worker's own sqlmap on a live JSON login endpoint, reaching and confirming the
    injection took 410 HTTP requests and about 420 seconds. The query floor grants 30 seconds,
    which is why every body attempt in a real scan returned unproven after ~25 while the execution
    chain itself worked. The floor is set to what the work costs, so a body candidate is reported
    as unattempted rather than run in a way that cannot reach a verdict.
    """
    from scan.external_process import batch_attempt_floor

    query = batch_attempt_floor("sqli.verify_batch")
    body = batch_attempt_floor("sqli.verify_batch", body_candidate=True)
    assert query["tool_wall_seconds"] == 30
    assert body["tool_wall_seconds"] >= 420, "a body attempt must be able to reach a verdict"
    assert body["http_requests"] >= 410, "measured: 410 requests to confirm the injection"
    assert body["http_requests"] > query["http_requests"]

    # XSS body attempts cost more than query ones too, without inheriting SQLi's ceiling.
    xss_body = batch_attempt_floor("xss.verify_batch", body_candidate=True)
    assert xss_body["tool_wall_seconds"] > batch_attempt_floor("xss.verify_batch")["tool_wall_seconds"]


def test_an_unknown_capability_has_no_floor_either_way():
    from scan.external_process import batch_attempt_floor

    assert batch_attempt_floor("templates.passive_batch") == {}
    assert batch_attempt_floor("templates.passive_batch", body_candidate=True) == {}


def test_the_adapter_selects_the_floor_by_candidate_class():
    from tests.api_sources import definition_source

    source = definition_source("_external_batch")
    assert "batch_attempt_floor(" in source
    assert "body_candidate=bool(body_request)" in source



def test_a_tool_finding_carries_the_endpoint_the_adapter_resolved():
    """The tool names the parameter; only the adapter knows the endpoint.

    sqlmap's output line is `(custom) POST parameter 'JSON email' is vulnerable` -- no URL. A
    finding built from that alone has no route, so it cannot be matched to a benchmark
    expectation, routed to a verifier (an unresolved route abstains by design), or acted on. The
    adapter resolved the request, so it supplies the locus, and never overwrites one the parser
    did establish.
    """
    from tests.api_sources import definition_source

    source = definition_source("_external_batch")
    block = source[source.index("attempt_observations = tuple("):]
    stamp = block.index('"url": execution_target')
    spread = block.index("**dict(item)")
    assert stamp < spread, "a parser-supplied locus must win over the adapter's default"
    assert '"method": body_request.get("method", "GET")' in block
