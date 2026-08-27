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
    assert "-p" in args and args[args.index("-p") + 1] == "password"
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
    assert "-p" in args and args[args.index("-p") + 1] == "email"


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
