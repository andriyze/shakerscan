"""Unit tests for the agent primitives that outlived the legacy engine.

Covers the honest context packer and the fixed tool guards and argv builders in ``agent_tools``.
"""
import os
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

import agent_context_pack as cp
import agent_tools as at
from runtime.capability_registry import CapabilityInputContractError
from tests.api_sources import (
    api_tree_source, definition_source, route_is_declared, route_source,
)



# ---------------------------------------------------------------- context packer -------

def test_map_header_always_present():
    pack = cp.pack_context([{"key": "endpoints", "body": "GET /a\nGET /b"}], token_budget=2000)
    assert "=== CONTEXT MAP (1 sections) ===" in pack["text"]
    assert pack["included"] == ["endpoints"]
    assert pack["dropped"] == []


def test_return_shape():
    pack = cp.pack_context([], token_budget=100)
    assert set(pack) == {"text", "included", "dropped", "tokens_used", "token_budget"}
    assert pack["token_budget"] == 100


def test_over_budget_drops_and_notes():
    items = [{"key": f"sec_{i}", "body": "Z" * 2000} for i in range(6)]
    pack = cp.pack_context(items, token_budget=400)
    assert len(pack["included"]) >= 1
    assert len(pack["dropped"]) >= 1  # honest drop, not silent


def test_map_capped_note():
    items = [{"key": f"sec_{i:03d}", "body": "y"} for i in range(100)]
    pack = cp.pack_context(items, token_budget=300)
    assert "more sections (not listed — map capped for budget)" in pack["text"]


def test_oversized_body_elided_not_truncated():
    pack = cp.pack_context([{"key": "big", "body": "Q" * 8000}], token_budget=500)
    assert "…[middle elided for context budget]…" in pack["text"]
    assert "big" in pack["included"]


def test_relevance_ranks_objective_keyword_first():
    items = [
        {"key": "misc", "body": "some unrelated content about weather"},
        {"key": "login_flow", "body": "POST /rest/user/login handles password auth token"},
    ]
    pack = cp.pack_context(items, token_budget=4000, objective="find broken authentication and login token flaws")
    ti = pack["text"].index
    # the login section body should appear before the misc section body
    assert ti("=== SECTION: login_flow ===") < ti("=== SECTION: misc ===")


# ---------------------------------------------------------------- agent tools ---------


def test_method_classification():
    assert at.coerce_method("get") == "GET"
    assert at.is_write_method("POST") is True
    assert at.is_write_method("GET") is False
    try:
        at.coerce_method("TRACE")
        assert False, "expected AgentToolError"
    except at.AgentToolError:
        pass


def test_same_origin_path_guard():
    assert at.validate_same_origin_path("/rest/basket/1") == "/rest/basket/1"
    for bad in ["//evil.com/x", "http://evil.com", "rest/x", "/x\x00y"]:
        try:
            at.validate_same_origin_path(bad)
            assert False, f"expected rejection for {bad!r}"
        except at.AgentToolError:
            pass



def test_header_filter_explains_decisions_without_echoing_values():
    accepted, rejected = at.classify_request_headers({
        "Authorization": "Bearer should-never-be-echoed",
        "Origin": "https://comparison.example",
        "X-Forwarded-For": "127.0.0.1",
        "Transfer-Encoding": "chunked",
    })
    assert accepted == {"Origin": "https://comparison.example"}
    assert rejected == {
        "authorization": "managed_principal_required",
        "transfer-encoding": "executor_owned_header",
        "x-forwarded-for": "identity_header_approval_required",
    }
    assert "should-never-be-echoed" not in repr(rejected)


def test_principal_slot_normalize():
    assert at.normalize_principal_slot("") == "anonymous"
    assert at.normalize_principal_slot("User1") == "user1"
    assert at.normalize_principal_slot(None) == "anonymous"



def test_run_tool_argv_templates_hardcode_flags():
    b, argv, timeout = at.build_scanner_argv("httpx", "http://t/x", {})
    assert b == "httpx" and "-json" in argv and "-silent" in argv and argv[argv.index("-u") + 1] == "http://t/x"
    b, argv, timeout = at.build_scanner_argv("nuclei", "http://t/x", {"severity": "high,critical", "tags": "cve,exposure"})
    assert b == "nuclei" and "-jsonl" in argv
    assert timeout == 300_000
    assert "-no-interactsh" in argv
    assert "-stats-json" in argv and argv[argv.index("-stats-interval") + 1] == "5"
    assert argv[argv.index("-rate-limit") + 1] == "10"
    assert argv[argv.index("-retries") + 1] == "0"
    assert argv[argv.index("-type") + 1] == "http"
    assert argv[argv.index("-severity") + 1] == "high,critical"
    assert argv[argv.index("-tags") + 1] == "cve,exposure"


def test_httpx_release_does_not_require_runtime_classifier_download():
    dockerfile = (
        Path(__file__).resolve().parents[1] / "scanner" / "Dockerfile"
    ).read_text(encoding="utf-8")
    # v1.9+ initializes a roughly 92 MB Hugging Face DIT model download merely
    # for JSON output.  Scanner processes must remain offline except for their
    # frozen target destination.
    assert (
        "build_tool httpx github.com/projectdiscovery/httpx/cmd/httpx v1.8.1"
        in dockerfile
    )


def test_sqlmap_runtime_path_is_worker_bound_per_job():
    _, argv, _ = at.build_scanner_argv("sqlmap", "http://t/item?id=1", {})
    bound = at.bind_scanner_runtime_paths(
        "sqlmap", argv, scratch_dir="/tmp/shakerscan-sqlmap-job-123",
    )

    assert bound[bound.index("--output-dir") + 1] == "/tmp/shakerscan-sqlmap-job-123"
    assert argv[argv.index("--output-dir") + 1] == "/tmp/shakerscan-sqlmap"
    with pytest.raises(at.AgentToolError):
        at.bind_scanner_runtime_paths("sqlmap", argv, scratch_dir="relative")


def test_run_tool_rejects_flag_injection():
    # a severity/tags value trying to inject flags is rejected -> safe defaults, no extra flags
    _, argv, _ = at.build_scanner_argv("nuclei", "http://t/x", {"severity": "-o /etc/passwd", "tags": "; rm -rf /"})
    assert argv[argv.index("-severity") + 1] == "high,critical"  # bad severity -> default
    assert argv[argv.index("-tags") + 1] == "exposure,misconfig,auth-bypass,default-login"
    assert "-o" not in argv and "/etc/passwd" not in argv


@pytest.mark.parametrize(
    ("tool_name", "header_flag"),
    [
        ("nuclei", "-H"),
        ("katana", "-H"),
        ("ffuf", "-H"),
        ("dalfox", "--header"),
    ],
)
def test_worker_private_credentials_bind_to_fixed_http_scanner_argv(
    tool_name, header_flag,
):
    _, argv, _ = at.build_scanner_argv(
        tool_name,
        "https://app.example.test/account?id=1",
        {},
        trusted_headers={
            "Cookie": "session=worker-private",
            "Authorization": "Bearer worker-private",
        },
    )

    header_values = [
        argv[index + 1]
        for index, value in enumerate(argv[:-1])
        if value == header_flag
    ]
    assert "Authorization: Bearer worker-private" in header_values
    assert "Cookie: session=worker-private" in header_values


def test_sqlmap_worker_private_credentials_use_one_bounded_header_argument():
    _, argv, _ = at.build_scanner_argv(
        "sqlmap",
        "https://app.example.test/account?id=1",
        {},
        trusted_headers={
            "Cookie": "session=worker-private",
            "Authorization": "Bearer worker-private",
        },
    )

    value = argv[argv.index("--headers") + 1]
    assert value == (
        "Authorization: Bearer worker-private\n"
        "Cookie: session=worker-private"
    )


def test_httpx_credentials_require_a_private_descriptor_and_never_enter_argv():
    headers = {"Authorization": "Bearer worker-private", "Cookie": "session=cookie-private"}
    with pytest.raises(at.AgentToolError, match="sealed worker configuration"):
        at.build_scanner_argv("httpx", "https://app.example.test/", {}, trusted_headers=headers)
    for descriptor in (None, True, 0, 2, "/tmp/config"):
        with pytest.raises(at.AgentToolError, match="sealed worker configuration"):
            at.build_enforced_scanner_plan("httpx", "https://app.example.test/", {},
                reserved_budget={"http_requests": 1, "tool_wall_seconds": 10}, trusted_headers=headers,
                runtime_paths={"httpx_config_fd": descriptor})
    plan = at.build_enforced_scanner_plan("httpx", "https://app.example.test/", {},
        reserved_budget={"http_requests": 1, "tool_wall_seconds": 10}, trusted_headers=headers,
        runtime_paths={"httpx_config_fd": 7})
    assert "worker-private" not in str(plan.argv) and "cookie-private" not in str(plan.argv)
    assert plan.argv[-2:] == ("-config", "/proc/self/fd/7")
    assert json.loads(at.httpx_credential_config_bytes(headers)) == {"header": [
        "Authorization: Bearer worker-private", "Cookie: session=cookie-private"]}


@pytest.mark.parametrize(
    "headers",
    [
        {"Host": "evil.example"},
        {"Authorization": "Bearer good\r\nX-Evil: injected"},
        {"Authorization": "Bearer one", "authorization": "Bearer two"},
    ],
)
def test_worker_private_scanner_headers_fail_closed(headers):
    with pytest.raises(at.AgentToolError, match="headers are invalid"):
        at.build_scanner_argv(
            "httpx", "https://app.example.test/", {},
            trusted_headers=headers,
        )

    with pytest.raises(at.AgentToolError, match="does not accept HTTP"):
        at.build_scanner_argv(
            "nmap", "https://app.example.test/", {},
            trusted_headers={"Authorization": "Bearer worker-private"},
        )


def test_planner_scanner_options_cannot_inject_credentials():
    _, argv, _ = at.build_scanner_argv(
        "httpx",
        "https://app.example.test/",
        {"headers": {"Authorization": "Bearer planner-controlled"}},
    )

    assert not any("planner-controlled" in value for value in argv)


def test_run_tool_unknown_rejected():
    try:
        at.coerce_run_tool({"name": "metasploit", "target": "/x"})
        assert False
    except at.AgentToolError:
        pass


def test_discovery_scanners_present_as_fixed_read_only_capabilities():
    # Katana disables form fill and FFUF uses only a bundled exact GET wordlist,
    # so both canonical adapters are safe in a passive Scan.
    assert {"katana", "ffuf"}.issubset(at.RUN_TOOL_NAMES)
    for name in ("katana", "ffuf"):
        assert at.SCANNER_ARG_TEMPLATES[name]["risk"] == "read_only"



def test_katana_preserves_distinct_body_encodings_for_the_same_fields():
    output = at.parse_scanner_output("katana", "\n".join((
        json.dumps({"request": {
            "endpoint": "https://app.test/api/search",
            "method": "POST",
            "body": '{"q":"json-value"}',
        }}),
        json.dumps({"request": {
            "endpoint": "https://app.test/api/search",
            "method": "POST",
            "body": "q=form-value",
        }}),
    )))

    assert output["record_count"] == 2
    assert {record["content_type"] for record in output["records"]} == {
        "application/json", "application/x-www-form-urlencoded",
    }


def test_katana_preserves_only_spa_fragment_route_shape_and_field_names():
    output = at.parse_scanner_output(
        "katana_headless",
        "https://app.test/#/search?q=private-browser-value&sort=recent",
        allowed_host="app.test",
    )

    assert output["records"] == [{
        "kind": "discovered_route",
        "url": "https://app.test/#/search?q=&sort=",
        "method": "GET",
        "source": None,
    }]
    assert "private-browser-value" not in json.dumps(output)


def test_headless_katana_uses_only_a_worker_owned_private_profile(tmp_path):
    profile = tmp_path / "profile"
    profile.mkdir(mode=0o700)
    profile.chmod(0o700)

    plan = at.build_enforced_scanner_plan(
        "katana_headless",
        "https://app.test/",
        {},
        reserved_budget={"http_requests": 601, "tool_wall_seconds": 30},
        pinned_address="192.0.2.10",
        pinned_proxy_url="socks5://127.0.0.1:1080",
        runtime_paths={"chrome_data_dir": str(profile)},
    )

    assert plan.argv[plan.argv.index("-chrome-data-dir") + 1] == str(profile)
    assert "-no-incognito" in plan.argv
    assert plan.budget_proof["inputs"]["browser_profile_seeded"] is True


def test_headless_katana_rejects_a_shared_private_profile(tmp_path):
    profile = tmp_path / "profile"
    profile.mkdir(mode=0o755)
    profile.chmod(0o755)

    with pytest.raises(at.AgentToolError, match="worker-owned"):
        at.build_enforced_scanner_plan(
            "katana_headless",
            "https://app.test/",
            {},
            reserved_budget={"http_requests": 601, "tool_wall_seconds": 30},
            pinned_address="192.0.2.10",
            pinned_proxy_url="socks5://127.0.0.1:1080",
            runtime_paths={"chrome_data_dir": str(profile)},
        )


def test_external_scanner_output_is_typed_and_query_values_are_redacted():
    secret = "AbCdEf0123456789AbCdEf0123456789"
    output = at.parse_scanner_output("nuclei", json.dumps({
        "template-id": "cve-test",
        "matched-at": f"https://app.test/reset/{secret}?q=secret-value",
        "matcher-name": "body",
        "info": {"name": "Test match", "severity": "high"},
    }))

    assert output["parser_status"] == "parsed"
    record = output["records"][0]
    assert record["kind"] == "template_match"
    assert record["proof_state"] == "candidate"
    assert secret not in record["matched_at"]
    assert "/reset/<redacted>" in record["matched_at"]
    assert "secret-value" not in record["matched_at"]
    assert "q=%3Credacted%3E" in record["matched_at"]



def test_worker_scanner_target_revalidation_is_same_host_and_http_only():
    assert at.validate_scanner_execution_target(
        "https://Example.test", "http://example.test:8080/admin?q=1"
    ) == "http://example.test:8080/admin?q=1"
    with pytest.raises(at.AgentToolError, match="selected target host"):
        at.validate_scanner_execution_target("https://example.test", "https://evil.test/")
    with pytest.raises(at.AgentToolError, match=r"HTTP\(S\)"):
        at.validate_scanner_execution_target("https://example.test", "file:///etc/passwd")
    # A fragment is client-side only: it cannot move the destination, and a browser
    # DOM check needs it, so it must survive revalidation.
    assert at.validate_scanner_execution_target(
        "http://example.test:3000", "http://example.test:3000/#/search?q=1"
    ) == "http://example.test:3000/#/search?q=1"
    with pytest.raises(at.AgentToolError, match="selected target host"):
        at.validate_scanner_execution_target(
            "http://example.test:3000", "http://evil.test:3000/#/search?q=1"
        )


def test_scanner_execution_is_address_pinned_with_original_host_and_sni():
    _binary, argv, _timeout = at.build_scanner_argv(
        "nuclei", "https://example.test:8443/admin", {}, pinned_address="203.0.113.7",
    )
    assert argv[argv.index("-target") + 1] == "https://203.0.113.7:8443/admin"
    assert "Host: example.test:8443" in argv
    assert argv[argv.index("-sni") + 1] == "example.test"
    assert "-disable-redirects" in argv
    assert at.validate_pinned_scanner_address(
        "203.0.113.7", ["203.0.113.7", "2001:db8::7"],
    ) == "203.0.113.7"
    assert at.validate_pinned_scanner_address(
        None, ["2001:db8::7", "203.0.113.8", "203.0.113.7"],
    ) == "203.0.113.7"
    with pytest.raises(at.AgentToolError, match="outside the authorized"):
        at.validate_pinned_scanner_address("127.0.0.1", ["203.0.113.7"])


def test_all_scanners_preserve_hostname_through_the_pinned_socks_broker():
    proxy = "socks5://127.0.0.1:45678"
    expected_flags = {
        "httpx": "-http-proxy",
        "nuclei": "-proxy",
        "katana": "-proxy",
        "ffuf": "-x",
        "dalfox": "--proxy",
    }
    for name, flag in expected_flags.items():
        _binary, argv, _timeout = at.build_scanner_argv(
            name, "https://example.test:8443/admin", {},
            pinned_address="203.0.113.7", pinned_proxy_url=proxy,
        )
        assert any(str(value).startswith("https://example.test:8443/admin") for value in argv)
        assert argv[argv.index(flag) + 1] == proxy
        assert "https://203.0.113.7:8443/admin" not in argv
    _binary, sqlmap_argv, _timeout = at.build_scanner_argv(
        "sqlmap", "https://example.test:8443/item?id=1", {},
        pinned_address="203.0.113.7", pinned_proxy_url=proxy,
    )
    assert "https://example.test:8443/item?id=1" in sqlmap_argv
    assert f"--proxy={proxy}" in sqlmap_argv
    with pytest.raises(at.AgentToolError, match="loopback SOCKS5"):
        at.build_scanner_argv(
            "katana", "https://example.test/", {},
            pinned_address="203.0.113.7", pinned_proxy_url="socks5://evil.test:1080",
        )



def test_scanner_request_settlement_distinguishes_exact_from_observed():
    # nuclei's own counters are progress, not wire evidence (see
    # test_nuclei_progress_counter_is_not_wire_evidence); a generic tool's explicit counter is exact.
    assert at.scanner_request_settlement(
        "nuclei", json.dumps({"stats": {"total-requests": 17}})
    )["mode"] == "unavailable"
    assert at.scanner_request_settlement(
        "generic-tool", json.dumps({"stats": {"total-requests": 17}})
    ) == {
        "mode": "exact", "actual": 17, "observed_minimum": 17,
        "source": "scanner_counter",
    }
    httpx = at.scanner_request_settlement(
        "httpx", json.dumps({"url": "https://example.test", "status_code": 200})
    )
    assert httpx["mode"] == "exact" and httpx["actual"] == 1
    katana = at.scanner_request_settlement(
        "katana", "\n".join([
            json.dumps({"request": {"endpoint": "https://example.test/a"}}),
            json.dumps({"request": {"endpoint": "https://example.test/b"}}),
        ])
    )
    assert katana == {
        "mode": "unavailable",
        "actual": None,
        "observed_minimum": 0,
        "source": "discovery_records_are_not_wire_evidence",
    }


def test_katana_javascript_routes_are_not_miscounted_as_wire_requests():
    routes = "\n".join(
        f"https://example.test/static-route-{index}" for index in range(51)
    )

    settlement = at.scanner_request_settlement("katana", routes)

    assert settlement["mode"] == "unavailable"
    assert settlement["observed_minimum"] == 0
    assert at.parse_scanner_output("katana", routes)["record_count"] == 51


def test_katana_compact_output_is_typed_deduplicated_and_host_scoped():
    output = at.parse_scanner_output(
        "katana",
        "\n".join([
            "http://juice-shop:3000/rest/products?token=secret",
            "http://juice-shop:3000/rest/products?token=secret",
            "https://external.example/reference",
            "not a URL",
        ]),
        allowed_host="juice-shop",
    )
    assert output["parser_status"] == "parsed"
    assert output["record_count"] == 1
    assert output["records"] == [{
        "kind": "discovered_route",
        "url": "http://juice-shop:3000/rest/products?token=%3Credacted%3E",
        "method": "GET",
        "source": None,
    }]


def test_katana_jsonl_retains_only_value_free_request_body_shape():
    secret = "worker-private-password"
    output = at.parse_scanner_output("katana", "\n".join([
        json.dumps({"request": {
            "method": "GET",
            "endpoint": "https://app.test/api/session",
        }}),
        json.dumps({"request": {
            "method": "POST",
            "endpoint": "https://app.test/api/session",
            "body": json.dumps({"email": "operator@example.test", "password": secret}),
        }}),
    ]), allowed_host="app.test")

    assert output["records"] == [
        {
            "kind": "discovered_route",
            "url": "https://app.test/api/session",
            "method": "GET",
            "source": None,
        },
        {
            "kind": "discovered_route",
            "url": "https://app.test/api/session",
            "method": "POST",
            "source": None,
            "content_type": "application/json",
            "body_field_names": ["email", "password"],
        },
    ]
    assert secret not in repr(output)



def test_ffuf_wordlist_tunable_is_injection_proof():
    # a valid selector maps to a BUNDLED list and FUZZ is appended to the same-origin base
    _, argv, _ = at.build_scanner_argv("ffuf", "http://t/base", {"wordlist": "api"})
    assert argv[argv.index("-u") + 1] == "http://t/base/FUZZ"
    assert argv[argv.index("-w") + 1] == at._AGENT_FFUF_WORDLISTS["api"]
    assert "-maxtime" in argv and "-ac" not in argv              # hard wall, no hidden calibration requests
    # unknown / path-injection selectors fall back to the bundled common list — never an arbitrary path
    for bad in ("/etc/passwd", "; rm -rf /", "nope"):
        _, argv2, _ = at.build_scanner_argv("ffuf", "http://t/x", {"wordlist": bad})
        assert argv2[argv2.index("-w") + 1] == at._AGENT_FFUF_WORDLISTS["common"]
        assert "/etc/passwd" not in argv2



# ---------------------------------------------------- shared turn-driver classification --


# ------------------------------------------------ SUSPECTED->VERIFIED bridge (Gap B) ----

def test_bola_targets_juice_shop_basket():
    t = at.derive_bola_verification_targets("/rest/basket/1", {"basket_id": "15"}, {"basket_id": "16"})
    assert t == {"collection": "/rest/basket", "owner_object_id": "15", "attacker_object_id": "16",
                 "owner_ref_key": "basket_id", "attacker_ref_key": "basket_id", "ref_segment": "basket"}


def test_bola_targets_require_distinct_refs():
    # equal owned refs cannot prove an ownership differential -> None (stays suspected)
    assert at.derive_bola_verification_targets("/rest/basket/1", {"basket_id": "9"}, {"basket_id": "9"}) is None


def test_bola_targets_missing_ref_is_none():
    assert at.derive_bola_verification_targets("/rest/basket/1", {"basket_id": "15"}, {}) is None
    assert at.derive_bola_verification_targets("/rest/basket/1", {}, {"basket_id": "16"}) is None


def test_bola_targets_plural_collection_matches_singular_ref_key():
    # plural collection segment 'products' must match the singular captured key 'product_id'
    t = at.derive_bola_verification_targets("/api/Products/1", {"product_id": "5"}, {"product_id": "6"})
    assert t["collection"] == "/api/Products" and t["owner_ref_key"] == "product_id"
    # templated /api/Orders/{id} + order_id refs also binds
    t2 = at.derive_bola_verification_targets("/api/Orders/{id}", {"order_id": "1"}, {"order_id": "2"})
    assert t2 and t2["owner_object_id"] == "1" and t2["attacker_object_id"] == "2"


def test_bola_targets_unrelated_ref_key_is_none_zero_fp():
    # BUG 1 fix: an UNRELATED captured ref (basket_id) must NOT bind to a /api/Products route,
    # even though both values are distinct — that fabricated a false-VERIFIED BOLA. Fail closed.
    assert at.derive_bola_verification_targets("/api/Products/1", {"basket_id": "15"}, {"basket_id": "16"}) is None
    # a generic 'id'/'object_id' or a lone unrelated single ref no longer binds either
    assert at.derive_bola_verification_targets("/api/Products/1", {"id": "15"}, {"id": "16"}) is None
    assert at.derive_bola_verification_targets("/api/Users/{id}", {"uid": "1"}, {"uid": "2"}) is None


def test_bola_targets_bare_collection_route():
    # no trailing id segment -> the route itself is the collection
    t = at.derive_bola_verification_targets("/rest/basket", {"basket_id": "15"}, {"basket_id": "16"})
    assert t["collection"] == "/rest/basket"



def test_attack_scanner_pinning_preserves_host_and_sni():
    _, argv, _ = at.build_scanner_argv("dalfox", "https://t.test:8443/x?a=1", {}, pinned_address="10.0.0.5")
    assert argv[argv.index("url") + 1].startswith("https://10.0.0.5:8443/")
    assert argv[argv.index("--header") + 1] == "Host: t.test:8443"

    _, argv, _ = at.build_scanner_argv("sqlmap", "https://t.test:8443/x?a=1", {}, pinned_address="10.0.0.5")
    assert argv[argv.index("-u") + 1].startswith("https://10.0.0.5:8443/")
    assert argv[argv.index("--host") + 1] == "t.test:8443"



def test_posture_scanner_pinning_replaces_host_with_pinned_ip():
    # nmap/naabu support neither SOCKS proxies nor Host/SNI overrides: the pinned IP becomes
    # the scan target itself (hostname dropped — no SNI needed for port/service posture).
    _, argv, _ = at.build_scanner_argv(
        "nmap", "https://example.test:8443/admin", {}, pinned_address="203.0.113.7",
    )
    assert argv[-1] == "203.0.113.7"
    assert argv[argv.index("-p") + 1] == "8443"
    assert "example.test" not in argv
    assert not any("Host" in str(flag) for flag in argv)

    _, argv, _ = at.build_scanner_argv(
        "naabu", "https://example.test:8443/", {}, pinned_address="203.0.113.7",
    )
    assert argv[argv.index("-host") + 1] == "203.0.113.7"
    assert "example.test" not in argv

    # with BOTH a proxy broker and a pinned address, posture tools pin by address (they cannot
    # ride SOCKS) — no proxy flags, no hostname in argv
    _, argv, _ = at.build_scanner_argv(
        "naabu", "https://example.test/", {},
        pinned_address="203.0.113.7", pinned_proxy_url="socks5://127.0.0.1:45678",
    )
    assert argv[argv.index("-host") + 1] == "203.0.113.7"
    assert "socks5://127.0.0.1:45678" not in argv
    # fail-closed: a SOCKS broker with NO pinned address cannot host a posture tool
    with pytest.raises(at.AgentToolError, match="SOCKS"):
        at.build_scanner_argv(
            "nmap", "https://example.test/", {},
            pinned_proxy_url="socks5://127.0.0.1:45678",
        )


def test_posture_scanner_output_is_typed():
    nmap_out = at.parse_scanner_output("nmap", "\n".join([
        "Starting Nmap 7.94 ( https://nmap.org )",
        "Nmap scan report for example.test (203.0.113.7)",
        "PORT     STATE SERVICE VERSION",
        "8443/tcp open  https  nginx 1.25.3",
        "22/tcp   filtered ssh",
        "Service detection performed. Please report any incorrect results.",
    ]))
    assert nmap_out["parser_status"] == "parsed"
    assert nmap_out["record_count"] == 2
    rec = nmap_out["records"][0]
    assert rec["kind"] == "port_service"
    assert rec["port"] == "8443/tcp" and rec["state"] == "open" and rec["service"] == "https"
    assert rec["version"] == "nginx 1.25.3"
    assert rec["proof_state"] == "candidate"
    assert nmap_out["records"][1]["version"] is None  # filtered row has no version

    naabu_out = at.parse_scanner_output("naabu", "\n".join([
        json.dumps({"host": "203.0.113.7", "port": "8443", "protocol": "tcp"}),
        json.dumps({"host": "203.0.113.7", "port": 22}),
        json.dumps({"stats": {"count": 10}}),          # stats line is not an observation
        "[INF] naabu scan started",                    # banner is not JSON
    ]))
    assert naabu_out["parser_status"] == "parsed"
    assert naabu_out["record_count"] == 2
    rec = naabu_out["records"][0]
    assert rec["kind"] == "open_port"
    assert rec["port"] == 8443 and rec["protocol"] == "tcp"
    assert rec["host"] == "203.0.113.7"
    assert rec["proof_state"] == "candidate"


def test_dalfox_sqlmap_output_is_typed_and_payloads_not_exposed():
    out = at.parse_scanner_output("dalfox", json.dumps({
        "type": "alert",
        "data": {"type": "V", "address": "http://t/?q=abc", "param": "q",
                 "payload": "<script>alert(1)</script>"},
    }))
    assert out["parser_status"] == "parsed"
    record = out["records"][0]
    assert record["kind"] == "xss_alert" and record["proof_state"] == "verified"
    assert "alert(1)" not in json.dumps(record) and record["payload_sha256"]

    headless_url = "http://t/#/search?q=%3Csvg%20onload%3Dalert(1)%3E"
    out = at.parse_scanner_output("dalfox", json.dumps({
        "type": "V", "inject_type": "headless", "data": headless_url,
        "param": "", "payload": "", "message_str": "Triggered XSS Payload",
    }))
    record = out["records"][0]
    assert record["proof_state"] == "verified"
    assert record["url"] == "http://t/"
    assert record["client_route"] == "/search?q="
    assert record["payload_sha256"]
    assert "svg" not in json.dumps(record).lower()

    out = at.parse_scanner_output("sqlmap", "Parameter 'q' is vulnerable. Do you want to keep testing? [Ny/N]\n[INFO] back-end DBMS: MySQL")
    kinds = {r["kind"] for r in out["records"]}
    assert kinds == {"sqli_finding", "sqli_dbms_fingerprint"}
    assert not any("Do you want" in r["message"] for r in out["records"])
    sqli = next(r for r in out["records"] if r["kind"] == "sqli_finding")
    assert sqli["param"] == "q"
    assert sqli["method"] is None
    assert sqli["proof_state"] == "candidate"
    # no trailing id segment -> the route itself is the collection
    t = at.derive_bola_verification_targets("/rest/basket", {"basket_id": "15"}, {"basket_id": "16"})
    assert t["collection"] == "/rest/basket"


def test_sqlmap_dbms_fingerprint_is_only_the_summary_line():
    # Unit fixture in the shape of a recorded sqlmap --batch run: the DBMS prompt, a fingerprint
    # warning and an info line all mention "back-end DBMS"; only the summary line names it.
    output = "\n".join((
        "[03:35:11] [INFO] heuristic (basic) test shows that GET parameter 'id' might be injectable (possible DBMS: 'SQLite')",
        "it looks like the back-end DBMS is 'SQLite'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y",
        "GET parameter 'id' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N",
        "[03:35:12] [WARNING] the back-end DBMS is not MySQL",
        "[03:35:12] [INFO] the back-end DBMS is SQLite",
        "back-end DBMS: SQLite",
        "back-end DBMS operating system: Linux Ubuntu",
    ))
    records = at.parse_scanner_output("sqlmap", output)["records"]
    fingerprints = [r["message"] for r in records if r["kind"] == "sqli_dbms_fingerprint"]
    assert fingerprints == ["back-end DBMS: SQLite"]
    assert [r["param"] for r in records if r["kind"] == "sqli_finding"] == ["id"]


# ------------------------------------------------------------------------ runner --------

def test_interactsh_validator_rejects_public_and_malformed_servers():
    for bad in (None, "", "oast.fun", "https://oast.fun", "https://x.interact.sh",
                "ftp://oob.example", "oob example", "http://:80"):
        assert at.validate_private_interactsh_server(bad) is None
    assert at.validate_private_interactsh_server("oob.corp.example") == "https://oob.corp.example"
    assert at.validate_private_interactsh_server("http://oob.corp:8443/p?q") == "http://oob.corp:8443"


def test_nuclei_interactsh_disabled_by_default_and_off_without_gate(monkeypatch):
    monkeypatch.delenv("SHAKERSCAN_HUNT_INTERACTSH_SERVER", raising=False)
    _, argv, _ = at.build_scanner_argv("nuclei", "https://t/", {}, pinned_address="10.0.0.1")
    assert "-no-interactsh" in argv and "-interactsh-server" not in argv
    assert at.resolve_hunt_interactsh_config(
        allow_active=True, allow_oob=False, reserved_oob_interactions=1,
    ) == (None, None)
    assert at.resolve_hunt_interactsh_config(
        allow_active=True, allow_oob=True, reserved_oob_interactions=0,
    ) == (None, None)
    assert at.resolve_hunt_interactsh_config(
        allow_active=False, allow_oob=True, reserved_oob_interactions=1,
    ) == (None, None)


def test_nuclei_interactsh_requires_gate_and_private_server(monkeypatch):
    monkeypatch.setenv("SHAKERSCAN_HUNT_INTERACTSH_SERVER", "https://oast.fun")
    assert at.resolve_hunt_interactsh_config(
        allow_active=True, allow_oob=True, reserved_oob_interactions=1,
    ) == (None, None)  # public rejected
    monkeypatch.setenv("SHAKERSCAN_HUNT_INTERACTSH_SERVER", "oob.corp.example")
    assert at.resolve_hunt_interactsh_config(
        allow_active=True, allow_oob=False, reserved_oob_interactions=1,
    ) == (None, None)
    assert at.resolve_hunt_interactsh_config(
        allow_active=True, allow_oob=True, reserved_oob_interactions=0,
    ) == (None, None)
    assert at.resolve_hunt_interactsh_config(
        allow_active=True, allow_oob=True, reserved_oob_interactions=1,
    ) == ("https://oob.corp.example", None)


def test_hunt_scanner_projection_takes_a_bounded_body_input_and_preserves_scan_input():
    body = {
        "path": "/rest/user/login",
        "method": "DELETE",
        "content_type": "application/json",
        "body_field_names": ["email", "password"],
        "injection_field": "email",
    }
    for capability in ("xss.verify", "sqli.verify"):
        # Deterministic Scan may still execute an immutable body candidate.
        assert at.CAPABILITY_REGISTRY.validate_input(capability, body) == body
        # A Hunt body test is POST, PUT or PATCH only; other methods are refused.
        with pytest.raises(CapabilityInputContractError, match="not an allowed value"):
            at.CAPABILITY_REGISTRY.validate_hunt_input(capability, body)
        with pytest.raises(CapabilityInputContractError, match="not an allowed value"):
            at.canonical_hunt_scanner_options(capability, body)
        posted = {**body, "method": "POST"}
        assert at.canonical_hunt_scanner_options(capability, posted)["injection_field"] == "email"
        # Scan-private staging fields stay out of the Hunt projection.
        with pytest.raises(CapabilityInputContractError, match="unsupported fields"):
            at.canonical_hunt_scanner_options(capability, {**posted, "probe_profile": "x"})


def test_hunt_nuclei_uses_server_owned_get_only_pack():
    options = at.canonical_hunt_scanner_options(
        "templates.scan", {"path": "/api/products?limit=10"},
    )
    assert options["template_ids"] == at._CANONICAL_PASSIVE_NUCLEI_IDS
    assert options["template_pack_digest"]
    assert options["template_request_cost_upper_bound"] == 7
    _, argv, _ = at.build_scanner_argv("nuclei", "https://t/", options)
    assert argv[argv.index("-id") + 1] == at._CANONICAL_PASSIVE_NUCLEI_IDS
    assert "-no-interactsh" in argv
    assert "-tags" not in argv
    assert at.CAPABILITY_REGISTRY.validate_hunt_input(
        "templates.scan", {"tags":"exposure,config", "severity":"medium,info"},
    ) == {"tags":"exposure,config", "severity":"medium,info"}
    for forbidden in ("template_ids", "template_pack_digest"):
        with pytest.raises(CapabilityInputContractError, match="unsupported fields"):
            at.CAPABILITY_REGISTRY.validate_hunt_input(
                "templates.scan", {forbidden: "cve"},
            )


def test_nuclei_interactsh_enable_drops_proxy_internal_keeps_scan_pin():
    base = at.SCANNER_ARG_TEMPLATES["nuclei"]["build"]("https://t/", {})
    argv = base + ["-proxy", "socks5://127.0.0.1:9", "-proxy-internal"]
    out = at._apply_nuclei_interactsh(list(argv), "oob.corp.example", "tok")
    assert "-no-interactsh" not in out and "-proxy-internal" not in out
    assert "-proxy" in out  # scan traffic stays pinned via the SOCKS broker
    assert out[out.index("-interactsh-server") + 1] == "https://oob.corp.example"
    assert out[out.index("-interactsh-token") + 1] == "tok"
    # Disabled / public -> argv is unchanged.
    assert at._apply_nuclei_interactsh(list(argv), None, None) == argv
    assert at._apply_nuclei_interactsh(list(argv), "https://oast.fun", None) == argv


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"  ok  {fn.__name__}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"FAIL  {fn.__name__}: {type(e).__name__}: {e}")
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)


def test_katana_javascript_derived_api_routes_survive_the_record_cap():
    """Static assets are emitted first; API routes arrive after them.

    Katana fetches the bundle before it can parse it, so the parameterized
    routes candidate generation depends on land at the end of the stream. A
    200-record cap spent the whole budget on .js chunks and dropped them: a
    single-page application reached the endpoint manifest with almost no query
    parameters, so every active family ran out of work.
    """
    assets = [f"https://example.test/chunk-{index}.js" for index in range(400)]
    api_routes = [
        "https://example.test/rest/products/search?q=",
        "https://example.test/rest/user/change-password?current=",
        "https://example.test/api/Challenges/?key=nftMintChallenge",
    ]
    parsed = at.parse_scanner_output("katana", "\n".join(assets + api_routes))

    # Query values are redacted; the parameter names candidate generation
    # selects on must survive.
    observed = {record["url"] for record in parsed["records"]}
    for path, parameter in (
        ("/rest/products/search", "q="),
        ("/rest/user/change-password", "current="),
        ("/api/Challenges/", "key="),
    ):
        assert any(
            path in url and parameter in url for url in observed
        ), f"{path}?{parameter} was dropped"
    assert parsed["record_count"] == len(assets) + len(api_routes)


def test_tool_output_records_stay_bounded():
    """The cap is raised, not removed: output stays bounded for evidence."""
    flood = "\n".join(
        f"https://example.test/route-{index}" for index in range(at.MAX_TOOL_RECORDS + 500)
    )
    parsed = at.parse_scanner_output("katana", flood)
    assert parsed["record_count"] <= at.MAX_TOOL_RECORDS


def test_nuclei_progress_counter_is_not_wire_evidence():
    """Measured on the deployed 2.3.6 candidate through the real pinned proxy at a counting
    target: one 120-request/45-second attempt at `-rate-limit 2` sent 33 HTTP requests over 5
    connections while nuclei's stats reported `requests: 277` (`total: 2729`, `percent: 10`).
    The counter is progress through the request plan, about eight times the wire. Taken as
    exact it made every batch attempt fail the hard-ceiling contract regardless of pacing --
    thirteen of thirteen on the rerun -- and charged each its full hold.
    """
    settlement = at.scanner_request_settlement(
        "nuclei",
        json.dumps({"duration": "0:00:40", "errors": "2", "hosts": "1", "matched": "0",
                    "percent": "10", "requests": "277", "rps": "6", "templates": "1183",
                    "total": "2729"}),
    )
    assert settlement["mode"] != "exact"
    assert settlement["actual"] is None
    # The progress counter must not masquerade as a lower bound either; nothing about the
    # wire is known from it.
    assert settlement["observed_minimum"] == 0
    assert settlement["source"] == "progress_counter_is_not_wire_evidence"


def _feed(counter, *chunks):
    return sum(counter.feed(c) for c in chunks)


def _post(body: bytes, extra: bytes = b"") -> bytes:
    return b"POST /submit HTTP/1.1\r\nHost: t\r\n" + extra + b"Content-Length: %d\r\n\r\n" % len(body) + body


def test_request_lookalikes_inside_a_body_or_header_are_not_requests():
    """Audit counterexample (2026-09-18): the first counter matched a request-shaped string
    anywhere in the stream, so one POST whose body carried 120 such strings counted as 121
    requests, the settlement called that a lower bound, and the hard-ceiling contract failed a
    120-request hold on one real message -- the original failure class for a new reason. nuclei's
    smuggling templates send exactly such payloads. A counter that can exceed the real message
    count is not a lower bound; requests are counted at HTTP/1 message boundaries only."""
    from pinned_socks_proxy import RequestCounter
    assert _feed(RequestCounter(), _post(b"GET /embedded-not-a-request HTTP/1.1\r\n")) == 1
    assert _feed(RequestCounter(), _post(b"".join(b"GET /embedded-%d HTTP/1.1\r\n" % i for i in range(120)))) == 1
    assert _feed(RequestCounter(), b"GET /x HTTP/1.1\r\nHost: t\r\nX-Debug: GET /inner HTTP/1.1\r\n\r\n") == 1


def test_keep_alive_requests_are_counted_across_bodies_and_chunk_boundaries():
    """Under keep-alive the next request follows the previous body with no newline between them,
    and chunks split anywhere; each real message counts exactly once."""
    from pinned_socks_proxy import RequestCounter
    stream = (b"GET /a HTTP/1.1\r\nHost: t\r\n\r\n"
              + _post(b"ok")
              + b"GET /c HTTP/1.1\r\nHost: t\r\n\r\n")
    for cut in (1, 7, 29, 40, len(stream) - 3):
        c = RequestCounter()
        assert _feed(c, stream[:cut], stream[cut:]) == 3, cut
    # chunked transfer encoding: the body is framed by chunk sizes, then a zero chunk
    chunked = (b"POST /u HTTP/1.1\r\nHost: t\r\nTransfer-Encoding: chunked\r\n\r\n"
               b"5\r\nGET /\r\n" b"c\r\n HTTP/1.1\r\nx\r\n" b"0\r\n\r\n"
               b"GET /after HTTP/1.1\r\n\r\n")
    assert _feed(RequestCounter(), chunked) == 2


def test_opaque_or_malformed_traffic_stops_counting_instead_of_guessing():
    """TLS and anything that is not well-formed HTTP/1 are unmeasurable: the counter keeps what it
    has already counted (still a true lower bound) and never adds to it."""
    from pinned_socks_proxy import RequestCounter
    c = RequestCounter()
    assert c.feed(b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03") == 0 and c.measurable is False
    c = RequestCounter()
    assert c.feed(b"GET /a HTTP/1.1\r\nHost: t\r\n\r\n") == 1
    assert c.feed(b"NOT AN HTTP MESSAGE\r\n\r\nGET /b HTTP/1.1\r\n\r\n") == 0 and c.measurable is False



def test_worker_prefers_proxy_wire_evidence_over_an_unavailable_settlement():
    """What the pinned proxy relayed is wire evidence; a tool's progress counter is not. When the
    scanner settlement is not exact, the proxy's request-line count becomes the lower bound the
    hard-ceiling contract checks -- so 33 real requests pass a 120 hold and 312 fail it, instead
    of every attempt failing on a counter that was eight times the wire."""
    w = at

    class Proxy:
        http_requests_observed = 33
    unavailable = {"mode": "unavailable", "actual": None, "observed_minimum": 0, "source": "progress_counter_is_not_wire_evidence"}
    settled = w.wire_evidence_settlement(unavailable, Proxy())
    assert settled == {"mode": "observed_lower_bound", "actual": None, "observed_minimum": 33, "source": "proxy_request_lines"}
    # An exact settlement from a tool's own complete wire log is kept as is.
    exact = {"mode": "exact", "actual": 17, "observed_minimum": 17, "source": "tool_wire_log"}
    assert w.wire_evidence_settlement(exact, Proxy()) == exact
    # Without a proxy, or with nothing relayed, the settlement is unchanged.
    assert w.wire_evidence_settlement(unavailable, None) == unavailable
    class Quiet:
        http_requests_observed = 0
    assert w.wire_evidence_settlement(unavailable, Quiet()) == unavailable


def test_method_override_aliases_are_executor_owned_even_with_identity_authority():
    headers = {
        "X-HTTP-Method-Override": "DELETE",
        "X-HTTP-Method": "DELETE",
        "X-Method-Override": "DELETE",
    }
    accepted, rejected = at.classify_request_headers(headers, allow_identity_headers=True)
    assert accepted == {}
    assert rejected == {
        "x-http-method-override": "executor_owned_header",
        "x-http-method": "executor_owned_header",
        "x-method-override": "executor_owned_header",
    }


def test_katana_argv_is_bounded_and_same_host():
    b, argv, timeout = at.build_scanner_argv("katana", "http://t/app", {})
    assert b == "katana"
    assert argv[argv.index("-u") + 1] == "http://t/app"
    assert "-js-crawl" in argv                                   # JS endpoint extraction on
    assert argv[argv.index("-field-scope") + 1] == "fqdn"        # same host ONLY, never cross-origin
    assert argv[argv.index("-depth") + 1] == "2"                 # bounded depth
    assert argv[argv.index("-crawl-duration") + 1] == "30s"      # hard wall cap
    assert argv[argv.index("-rate-limit") + 1] == "5"
    assert "-jsonl" in argv                                  # typed method/body shape
    assert "-omit-raw" in argv and "-omit-body" in argv
    excluded = argv[argv.index("-exclude-output-fields") + 1].split(",")
    assert {"headers", "response", "raw"} <= set(excluded)
    assert timeout > 0
    # no form-submission / cross-scope flags leaked in
    for unsafe in ("-form-extraction", "-automatic-form-fill", "-aff", "-display-out-scope", "-do"):
        assert unsafe not in argv


def test_nuclei_focused_default_and_progress_counter_contract():
    _, argv, timeout_ms = at.build_scanner_argv("nuclei", "https://example.test/", {})
    assert argv[argv.index("-tags") + 1] == "exposure,misconfig,auth-bypass,default-login"
    assert timeout_ms == 300_000
    settlement = at.scanner_request_settlement(
        "nuclei",
        "\n".join([
            json.dumps({"duration": "0:00:05", "requests": 73}),
            json.dumps({"duration": "0:00:10", "requests": 149}),
        ]),
    )
    # The progress counter is parsed (both int and v3.11 string forms) but is not wire evidence.
    assert settlement["mode"] == "unavailable" and settlement["actual"] is None
    assert settlement["source"] == "progress_counter_is_not_wire_evidence"
    string_counter = at.scanner_request_settlement(
        "nuclei",
        json.dumps({"duration": "0:00:10", "requests": "149", "templates": "1183"}),
    )
    assert string_counter == settlement
    assert at.parse_scanner_output(
        "nuclei", json.dumps({"duration": "0:00:10", "requests": "149"})
    )["record_count"] == 0


def test_attack_scanners_dalfox_sqlmap_present_and_bounded():
    # dalfox + sqlmap join the fixed-argv arsenal: active (approval-gated), bounded reservations,
    # GET-based XSS (no headless/blind/mining), widened SQLi (BEUT incl. time-based inside a
    # 300s wall, level/risk 2, no crawl).
    assert {"dalfox", "sqlmap"}.issubset(at.RUN_TOOL_NAMES)
    for name in ("dalfox", "sqlmap"):
        assert at.SCANNER_ARG_TEMPLATES[name]["risk"] == "active"

    b, argv, _ = at.build_scanner_argv("dalfox", "http://t/search?q=1", {"severity": "high"})
    assert b == "dalfox"
    assert argv[0] == "url" and argv[argv.index("url") + 1] == "http://t/search?q=1"
    assert "--skip-headless" in argv and "--skip-bav" in argv and "--skip-mining-all" in argv
    assert argv[argv.index("--worker") + 1] == "3" and argv[argv.index("--delay") + 1] == "1000"
    assert argv[argv.index("--only-poc") + 1] == "r,v"  # no browser: preserve reflected candidates
    assert argv[argv.index("--format") + 1] == "jsonl"
    assert "--skip-discovery" in argv
    assert argv[argv.index("-p") + 1] == "q"
    assert "--only-custom-payload" in argv
    assert argv[argv.index("--custom-payload") + 1] == "/app/payloads/xss/hunt-verify.txt"

    _, dom_argv, _ = at.build_scanner_argv(
        "dalfox", "http://t/#/search?q=1",
        {"severity": "high", "deep_domxss": True},
    )
    assert "--skip-headless" not in dom_argv
    assert "--force-headless-verification" in dom_argv
    assert dom_argv[dom_argv.index("--only-poc") + 1] == "v"
    # --deep-domxss never converges inside the capability wall ceiling.
    assert "--deep-domxss" not in dom_argv
    assert dom_argv[dom_argv.index("--delay") + 1] == "0"
    assert dom_argv[dom_argv.index("--worker") + 1] == "10"
    assert argv[argv.index("--delay") + 1] == "1000"
    assert argv[argv.index("--worker") + 1] == "3"

    plan = at.build_enforced_scanner_plan(
        "dalfox", "http://t/#/search?q=1", {"deep_domxss": True},
        reserved_budget={"http_requests": 400, "tool_wall_seconds": 120},
        pinned_address="127.0.0.1",
        pinned_proxy_url="socks5://127.0.0.1:1080",
    )
    proof_inputs = plan.budget_proof["inputs"]
    assert proof_inputs["headless"] is True
    assert proof_inputs["delay_ms"] == 0
    assert proof_inputs["workers"] == 10
    assert plan.argv[plan.argv.index("--delay") + 1] == "0"
    assert plan.argv[plan.argv.index("--worker") + 1] == "10"

    b, argv, timeout = at.build_scanner_argv("sqlmap", "http://t/item?id=1", {})
    assert b == "sqlmap"
    assert argv[argv.index("-u") + 1] == "http://t/item?id=1"
    assert argv[argv.index("--batch") + 1] == "--technique"  # non-interactive
    assert argv[argv.index("--technique") + 1] == "BEUT"     # boolean/error/union/time-based
    assert argv[argv.index("--level") + 1] == "2" and argv[argv.index("--risk") + 1] == "2"
    assert argv[argv.index("--threads") + 1] == "1" and argv[argv.index("--delay") + 1] == "1"
    assert argv[argv.index("--retries") + 1] == "0"
    assert timeout == 300_000                                # wider window for time-based payloads
    assert "--crawl" not in " ".join(argv) and "--os-shell" not in " ".join(argv)


def test_posture_scanners_nmap_naabu_present_and_bounded():
    # nmap + naabu join the fixed-argv arsenal: ACTIVE (they send probe traffic), bounded wall
    # clocks and wire reservations, connect scans only (never raw SYN), no NSE scripts.
    assert {"nmap", "naabu"}.issubset(at.RUN_TOOL_NAMES)
    for name in ("nmap", "naabu"):
        assert at.SCANNER_ARG_TEMPLATES[name]["risk"] == "active"

    b, argv, timeout = at.build_scanner_argv("nmap", "https://example.test:8443/admin", {})
    assert b == "nmap"
    assert argv[argv.index("-p") + 1] == "8443"                 # single port from the URL
    assert argv[argv.index("-sV") + 1] == "-sT"                 # service detect + connect scan
    assert "-sS" not in argv                                    # never raw SYN
    assert not any(str(flag).startswith("--script") for flag in argv)  # no NSE scripts
    assert argv[argv.index("--host-timeout") + 1] == "60s"      # hard host wall
    assert argv[argv.index("--max-retries") + 1] == "0"
    assert argv[argv.index("-oN") + 1] == "-"                   # output on stdout only, no files
    assert argv[-1] == "example.test"                           # positional host
    assert timeout == 90_000
    # scheme-default port when the URL carries none
    _, argv, _ = at.build_scanner_argv("nmap", "http://example.test/", {})
    assert argv[argv.index("-p") + 1] == "80"

    b, argv, timeout = at.build_scanner_argv("naabu", "https://example.test:8443/", {})
    assert b == "naabu"
    assert argv[argv.index("-host") + 1] == "example.test"
    assert argv[argv.index("-top-ports") + 1] == "100"          # bounded top-100 sweep
    assert "-p-" not in argv and "-p" not in argv               # never a full-range sweep
    assert argv[argv.index("-scan-type") + 1] == "c"            # connect scan
    assert argv[argv.index("-rate") + 1] == "10"
    assert argv[argv.index("-c") + 1] == "10"
    assert timeout == 120_000
    # rate 10 x the 120s wall must fit inside the wire reservation
