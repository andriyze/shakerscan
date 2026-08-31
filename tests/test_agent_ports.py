"""Unit tests for the T3MP3ST-ported autonomous-agent primitives.

Pure-stdlib modules, so this runs on the host with no scanner deps:
    python3 tests/test_agent_ports.py
(also importable by pytest). Covers the provenance gate, the text tool-contract shim,
and the honest context packer.
"""
import os
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

import agent_provenance as prov
import agent_text_toolcalls as tc
import agent_context_pack as cp
import agent_tools as at
from runtime.capability_registry import CapabilityInputContractError
from tests.api_sources import (
    api_tree_source, definition_source, route_is_declared, route_source,
)

import agent_budget
import agent_loop as al


# ------------------------------------------------------------------ provenance gate ----

def test_tool_evidence_passes():
    f = {"severity": "high", "evidence": [{"type": "response", "content": "HTTP/1.1 200 ... token=abc"}]}
    g = prov.gate_live_finding(f)
    assert g["passed"] is True
    assert g["provenance"] == "tool"
    assert g["reasons"] == []


def test_prose_only_fails():
    f = {"severity": "critical", "evidence": []}
    g = prov.gate_live_finding(f)
    assert g["passed"] is False
    assert g["provenance"] == "none"
    # both RULE 1 (no tool evidence) and RULE 2 (crit + zero evidence) trip
    assert len(g["reasons"]) == 2


def test_context_only_is_not_tool():
    # a non-tool evidence kind (e.g. a model 'note') counts as context, not tool output
    f = {"severity": "medium", "evidence": [{"type": "note", "content": "looks suspicious"}]}
    g = prov.gate_live_finding(f)
    assert g["passed"] is False
    assert g["provenance"] == "context"
    assert len(g["reasons"]) == 1  # only RULE 1; medium severity does not trip overclaim


def test_empty_tool_content_does_not_count():
    f = {"severity": "low", "evidence": [{"type": "output", "content": "   "}]}
    g = prov.gate_live_finding(f)
    assert g["passed"] is False
    assert g["provenance"] == "context"  # evidence present but empty content -> not tool


def test_strip_self_verification():
    payload = {"title": "x", "verified_at": 123, "last_verification_verdict": "exploited", "promotable": True, "evidence": []}
    out = prov.strip_self_verification(payload)
    assert "verified_at" not in out
    assert "last_verification_verdict" not in out
    assert "promotable" not in out
    assert out["title"] == "x"  # non-owned fields preserved


# ---------------------------------------------------------------- text tool-calls ------

def test_render_tool_contract_marks_required():
    tools = [{
        "name": "http_request",
        "description": "issue an HTTP request",
        "parameters": {"type": "object", "properties": {"method": {"type": "string"}, "path": {"type": "string"}}, "required": ["path"]},
    }]
    out = tc.render_tool_contract(tools)
    assert "## ARSENAL" in out
    assert "## ACTION CONTRACT" in out
    assert "path*: string" in out       # required marked
    assert "method: string" in out      # optional unmarked
    assert '{"tool_calls":[' in out


def test_parse_fenced_json():
    text = 'Let me try that.\n```json\n{"tool_calls":[{"name":"http_request","arguments":{"method":"GET","path":"/rest/products/search?q=1"}}]}\n```'
    calls = tc.parse_text_tool_calls(text)
    assert calls and len(calls) == 1
    assert calls[0]["name"] == "http_request"
    assert calls[0]["arguments"]["path"].startswith("/rest/products/search")


def test_parse_balanced_no_fence():
    text = '{"tool_calls":[{"name":"note","arguments":{"kind":"idea"}}]}'
    calls = tc.parse_text_tool_calls(text)
    assert calls and calls[0]["name"] == "note"
    assert calls[0]["arguments"] == {"kind": "idea"}


def test_parse_single_unwrapped():
    text = '{"name":"query_kb","arguments":{"kind":"endpoints"}}'
    calls = tc.parse_text_tool_calls(text)
    assert calls and calls[0]["name"] == "query_kb"


def test_parse_trailing_commas_tolerated():
    text = '```json\n{"tool_calls":[{"name":"note","arguments":{"a":1,},},],}\n```'
    calls = tc.parse_text_tool_calls(text)
    assert calls and calls[0]["name"] == "note"


def test_parse_multiple_calls():
    text = '```json\n{"tool_calls":[{"name":"http_request","arguments":{"path":"/a"}},{"name":"http_request","arguments":{"path":"/b"}}]}\n```'
    calls = tc.parse_text_tool_calls(text)
    assert calls and len(calls) == 2
    assert [c["arguments"]["path"] for c in calls] == ["/a", "/b"]


def test_unclosed_large_fence_is_bounded_and_not_a_tool_call():
    text = "```json" + (" " * 200_000) + '{"tool_calls":['
    assert tc.parse_text_tool_calls(text) is None
    assert tc.parse_final_findings(text) == []
    assert tc.has_terminal_json(text) is False


def test_prose_is_final_answer():
    assert tc.parse_text_tool_calls("The surface is exhausted; no exploitable issue found.") is None


def test_balanced_spans_ignore_braces_in_strings():
    text = '{"name":"note","arguments":{"payload":"a { nested } brace and \\" quote"}}'
    calls = tc.parse_text_tool_calls(text)
    assert calls and calls[0]["arguments"]["payload"] == 'a { nested } brace and " quote'


def test_refusal_detection():
    assert tc.is_likely_refusal("I can't help with that request.") is True
    assert tc.is_likely_refusal("I'm not able to assist with this.") is True
    assert tc.is_likely_refusal("This is against my guidelines.") is True
    assert tc.is_likely_refusal("I can't find the flag on this endpoint yet.") is False
    assert tc.is_likely_refusal("x" * 1400) is False   # long substantive output
    assert tc.is_likely_refusal("", "content_filter") is True


def test_history_replay_summarizes():
    assert tc.render_history_tool_request(["http_request", "note"]) == "[requested tools: http_request, note]"


def test_parse_final_findings():
    text = ('Here is my debrief.\n```json\n{"done":true,"findings":[{"title":"BOLA on basket",'
            '"severity":"high","family":"BOLA","predicate":"cross_principal_equivalent",'
            '"route":"/api/baskets/7","method":"GET",'
            '"details":"user2 read user1 basket","evidence_refs":["resp_2","resp_3"],'
            '"cwe":"CWE-639"}],"abstained":false}\n```')
    fs = tc.parse_final_findings(text)
    assert len(fs) == 1
    assert fs[0]["title"] == "BOLA on basket" and fs[0]["severity"] == "high"
    assert fs[0]["predicate"] == "cross_principal_equivalent"
    assert fs[0]["route"] == "/api/baskets/7" and fs[0]["method"] == "GET"
    assert fs[0]["evidence_refs"] == ["resp_2", "resp_3"]
    assert fs[0]["provenance"] == "model"


def test_parse_final_findings_preserves_injection_point():
    # An injection debrief must carry param + payload through so the deterministic DAST prover can
    # re-execute it; a non-injection finding simply omits them.
    text = ('```json\n{"done":true,"findings":[{"title":"Reflected XSS in q","severity":"high",'
            '"family":"xss","route":"/search","method":"GET","details":"payload reflected unescaped",'
            '"evidence_refs":["resp_1"],"param":"q","payload":"<script>alert(1)</script>"}],'
            '"abstained":false}\n```')
    fs = tc.parse_final_findings(text)
    assert len(fs) == 1
    assert fs[0]["family"] == "xss"
    assert fs[0]["param"] == "q"
    assert fs[0]["payload"] == "<script>alert(1)</script>"


def test_interpret_assistant_dict_toolcalls():
    d = tc.interpret_assistant({"tool_calls": [{"name": "http_request", "arguments": {"path": "/x"}}]})
    assert d["done"] is False and len(d["tool_calls"]) == 1


def test_interpret_assistant_dict_done():
    d = tc.interpret_assistant({"done": True, "findings": [{"title": "x", "severity": "low"}], "abstained": False})
    assert d["done"] is True and d["tool_calls"] == [] and len(d["findings"]) == 1


def test_interpret_assistant_dict_abstain():
    d = tc.interpret_assistant({"done": True, "findings": [], "abstained": True})
    assert d["done"] is True and d["abstained"] is True and d["findings"] == []


def test_interpret_assistant_text_toolcalls():
    d = tc.interpret_assistant('```json\n{"tool_calls":[{"name":"query_kb","arguments":{"kind":"findings"}}]}\n```')
    assert d["done"] is False and d["tool_calls"][0]["name"] == "query_kb"


def test_loop_prompt_builders():
    contract = tc.render_tool_contract(at.tool_schemas())
    sysp = al.build_system_prompt(contract, max_iterations=12)
    assert "RECON" in sysp and "SELF-CRITIQUE" in sysp and "12 tool-using iterations" in sysp
    assert "## ACTION CONTRACT" in sysp
    user = al.build_user_message("find BOLA", "endpoints: GET /x")
    assert "find BOLA" in user and "TARGET CONTEXT" in user


def test_loop_format_tool_result_caps():
    big = {"blob": "Z" * 9000}
    out = al.format_tool_result(big, max_chars=1000)
    assert len(out) < 1200 and "truncated" in out


def test_loop_dup_and_steer():
    sig1 = al.dup_signature("http_request", {"path": "/a", "method": "GET"})
    sig2 = al.dup_signature("http_request", {"method": "GET", "path": "/a"})
    assert sig1 == sig2  # order-independent
    assert "Duplicate call" in al.dup_steer_message("http_request", "200 OK")
    assert "different vector" in al.no_progress_message(4)
    assert "do not invent" in al.hallucinated_tool_message("frobnicate", ["http_request"]).lower()


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

def test_tool_schemas_render():
    assert {s["name"] for s in at.tool_schemas(include_run_tool=False)} == {"http_request", "query_kb", "diff", "note"}
    schemas = at.tool_schemas()
    assert {s["name"] for s in schemas} == {"http_request", "query_kb", "diff", "note"}
    # the schemas must render through the text-contract shim
    contract = tc.render_tool_contract(schemas)
    assert "http_request(" in contract
    assert "path*: string" in contract  # required marked


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


def test_header_filter_drops_auth():
    filtered = at.filter_request_headers({
        "Authorization": "Bearer x", "Cookie": "s=1", "X-Api-Key": "k",
        "Observed-Access-Key": "ak", "X-Private_Key": "pk",
        "X-Signing-Key": "sk",
        "X-Forwarded-For": "1.2.3.4", "Accept": "application/json", "X-Custom": "ok",
    })
    assert "Authorization" not in filtered and "Cookie" not in filtered
    assert "X-Api-Key" not in filtered and "X-Forwarded-For" not in filtered
    assert "Observed-Access-Key" not in filtered
    assert "X-Private_Key" not in filtered and "X-Signing-Key" not in filtered
    assert filtered.get("Accept") == "application/json"
    assert filtered.get("X-Custom") == "ok"


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


def test_query_kb_and_note_coercion():
    assert at.coerce_query_kb({"kind": "findings"})[0] == "findings"
    try:
        at.coerce_query_kb({"kind": "passwords"})
        assert False
    except at.AgentToolError:
        pass
    note = at.coerce_note({"kind": "hypothesis", "title": "BOLA on basket", "detail": "x", "family": "BOLA"})
    assert note["kind"] == "hypothesis" and note["family"] == "bola"
    try:
        at.coerce_note({"kind": "observation", "title": ""})
        assert False
    except at.AgentToolError:
        pass


def test_run_tool_schema_is_compatibility_only_and_never_callable():
    schemas = at.tool_schemas(include_run_tool=True)
    assert any(s["name"] == "run_tool" for s in schemas)
    assert "run_tool" not in at.CALLABLE_TOOL_NAMES
    assert "run_tool" not in {item["name"] for item in at.tool_schemas()}
    assert at.tool_schemas(include_run_tool=False) == [s for s in schemas if s["name"] != "run_tool"]
    run_tool = next(schema for schema in schemas if schema["name"] == "run_tool")
    name_schema = run_tool["parameters"]["properties"]["name"]
    assert set(name_schema["enum"]) == {
        "httpx", "nuclei", "katana", "katana_headless", "ffuf", "dalfox",
        "sqlmap", "nmap", "naabu",
    }
    assert "dalfox" in name_schema["description"] and "sqlmap" in name_schema["description"]
    assert "nmap" in name_schema["description"] and "naabu" in name_schema["description"]


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
        ("httpx", "-H"),
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


def test_katana_argv_is_bounded_and_same_host():
    b, argv, timeout = at.build_scanner_argv("katana", "http://t/app", {})
    assert b == "katana"
    assert argv[argv.index("-u") + 1] == "http://t/app"
    assert "-js-crawl" in argv                                   # JS endpoint extraction on
    assert argv[argv.index("-field-scope") + 1] == "fqdn"        # same host ONLY, never cross-origin
    assert argv[argv.index("-depth") + 1] == "2"                 # bounded depth
    assert argv[argv.index("-crawl-duration") + 1] == "30s"      # hard wall cap
    assert argv[argv.index("-rate-limit") + 1] == "5"
    assert "-jsonl" not in argv                                # URL-only; no raw bodies
    assert at.scanner_request_reservation("katana") == 150
    assert timeout > 0
    # no form-submission / cross-scope flags leaked in
    for unsafe in ("-form-extraction", "-automatic-form-fill", "-aff", "-display-out-scope", "-do"):
        assert unsafe not in argv


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


def test_scanner_request_reservations_are_conservative_and_explicit():
    assert at.scanner_request_reservation("httpx") == 1
    assert at.scanner_request_reservation("nuclei") == 4000
    assert at.scanner_request_reservation("ffuf") == 220


def test_exact_scanner_wire_settlement_refunds_and_never_clamps_overruns():
    refund = at.settle_scanner_wire_reservation(
        charged_total=450, reservation=450, accounting="exact", actual=17,
        budget_limit=500,
    )
    assert refund["charged_total"] == 17
    assert refund["reservation_refund"] == 433
    assert refund["budget_overrun"] == 0

    overrun = at.settle_scanner_wire_reservation(
        charged_total=400, reservation=400, accounting="exact", actual=525,
        budget_limit=500,
    )
    assert overrun["actual"] == 525
    assert overrun["charged_total"] == 525
    assert overrun["reservation_overrun"] == 125
    assert overrun["budget_overrun"] == 25

    unknown = at.settle_scanner_wire_reservation(
        charged_total=220, reservation=220, accounting="unavailable", actual=None,
        budget_limit=500,
    )
    assert unknown["charged_total"] == 220 and unknown["settled"] is False


def test_scanner_rate_and_wall_bounds_fit_their_wire_reservations():
    _, nuclei, nuclei_ms = at.build_scanner_argv("nuclei", "http://t/", {})
    assert int(nuclei[nuclei.index("-rate-limit") + 1]) * (nuclei_ms // 1000) <= at.scanner_request_reservation("nuclei")
    _, ffuf, _ = at.build_scanner_argv("ffuf", "http://t/", {})
    assert int(ffuf[ffuf.index("-rate") + 1]) * int(ffuf[ffuf.index("-maxtime") + 1]) <= at.scanner_request_reservation("ffuf")
    _, dalfox, dalfox_ms = at.build_scanner_argv("dalfox", "http://t/?q=x", {})
    dalfox_ceiling = int(dalfox[dalfox.index("--worker") + 1]) * (dalfox_ms // int(dalfox[dalfox.index("--delay") + 1]))
    assert dalfox_ceiling <= at.scanner_request_reservation("dalfox")
    _, sqlmap, sqlmap_ms = at.build_scanner_argv("sqlmap", "http://t/?id=1", {})
    sqlmap_ceiling = int(sqlmap[sqlmap.index("--threads") + 1]) * (sqlmap_ms // (1000 * int(sqlmap[sqlmap.index("--delay") + 1])))
    assert sqlmap_ceiling <= at.scanner_request_reservation("sqlmap")


def test_episode_request_budget_counts_scanner_invocations_not_internal_wire_ceiling():
    assert at.request_budget_units("http_request") == 1
    assert at.request_budget_units("run_tool") == 1
    assert at.request_budget_units("query_kb") == 0
    assert at.request_budget_units("note") == 0
    assert at.request_budget_units("diff") == 0
    assert at.request_budget_units("nuclei") == 0


def test_worker_scanner_target_revalidation_is_same_host_and_http_only():
    assert at.validate_scanner_execution_target(
        "https://Example.test", "http://example.test:8080/admin?q=1"
    ) == "http://example.test:8080/admin?q=1"
    with pytest.raises(at.AgentToolError, match="selected target host"):
        at.validate_scanner_execution_target("https://example.test", "https://evil.test/")
    with pytest.raises(at.AgentToolError, match=r"HTTP\(S\)"):
        at.validate_scanner_execution_target("https://example.test", "file:///etc/passwd")


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


def test_short_deep_hunts_can_compose_recon_with_one_attack_scanner():
    assert agent_budget.keyless_hunt_wire_budget(1) == 4200
    assert agent_budget.keyless_hunt_wire_budget(4) == 4200
    assert agent_budget.keyless_hunt_wire_budget(20) == 4200
    assert agent_budget.keyless_hunt_wire_budget(40) == 8400
    assert (
        at.scanner_request_reservation("httpx")
        + at.scanner_request_reservation("katana")
        + at.scanner_request_reservation("nuclei")
    ) <= agent_budget.keyless_hunt_wire_budget(20)
    with pytest.raises(at.AgentToolError, match="user information"):
        at.validate_scanner_execution_target("https://example.test", "https://user@example.test/")


def test_hunt_dns_authorization_is_frozen_in_session_state():
    seed = definition_source("_agent_seed_state")
    http_request = definition_source("_agent_tool_http_request")
    assert (
        'state["authorized_target_addresses"] = await '
        '_resolve_agent_target_addresses(target_url)'
    ) in seed
    assert "await _resolve_agent_target_addresses" not in http_request
    assert (
        'authorized_addresses=state.get("authorized_target_addresses") or []'
        in api_tree_source()
    )


def test_scanner_request_settlement_distinguishes_exact_from_observed():
    assert at.scanner_request_settlement(
        "nuclei", json.dumps({"stats": {"total-requests": 17}})
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


def test_nuclei_focused_default_and_progress_counter_contract():
    _, argv, timeout_ms = at.build_scanner_argv("nuclei", "https://example.test/", {})
    assert argv[argv.index("-tags") + 1] == "exposure,misconfig,auth-bypass,default-login"
    assert timeout_ms == 300_000
    assert at.scanner_request_reservation("nuclei") == 4_000
    settlement = at.scanner_request_settlement(
        "nuclei",
        "\n".join([
            json.dumps({"duration": "0:00:05", "requests": 73}),
            json.dumps({"duration": "0:00:10", "requests": 149}),
        ]),
    )
    assert settlement == {
        "mode": "exact", "actual": 149, "observed_minimum": 149,
        "source": "scanner_counter",
    }
    string_counter = at.scanner_request_settlement(
        "nuclei",
        json.dumps({"duration": "0:00:10", "requests": "149", "templates": "1183"}),
    )
    assert string_counter == settlement
    assert at.parse_scanner_output(
        "nuclei", json.dumps({"duration": "0:00:10", "requests": "149"})
    )["record_count"] == 0


def test_partial_scanner_results_are_labeled_in_agent_surface():
    run_tool = definition_source("_agent_tool_run_tool")
    assert '"execution_status": status_label' in run_tool
    assert '"complete": status_label == "success"' in run_tool
    assert '"partial_reason": error if status_label != "success" else None' in run_tool
    assert at.scanner_request_settlement("ffuf", "not-json")["mode"] == "unavailable"


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


def test_http_evidence_is_tool_provenance():
    ev = at.http_evidence_item({"method": "GET", "path": "/x"}, {"status": 200, "body_sample": "hi"})
    assert ev["type"] in prov.TOOL_EVIDENCE_KINDS
    # a finding carrying this evidence passes the provenance gate
    g = prov.gate_live_finding({"severity": "high", "evidence": [ev]})
    assert g["passed"] and g["provenance"] == "tool"


# ---------------------------------------------------- shared turn-driver classification --

def test_classify_tool_call_execute():
    kind, sig = al.classify_tool_call("http_request", {"method": "GET", "path": "/a"}, set(), at.CALLABLE_TOOL_NAMES)
    assert kind == "execute"
    assert sig == al.dup_signature("http_request", {"method": "GET", "path": "/a"})


def test_classify_tool_call_duplicate():
    seen = {al.dup_signature("query_kb", {"kind": "findings"})}
    kind, sig = al.classify_tool_call("query_kb", {"kind": "findings"}, seen, at.CALLABLE_TOOL_NAMES)
    assert kind == "duplicate"


def test_classify_tool_call_hallucinated():
    # an unknown tool is flagged BEFORE the dedup check — the model gets the tool list back
    kind, _ = al.classify_tool_call("sqlmap", {"x": 1}, set(), at.CALLABLE_TOOL_NAMES)
    assert kind == "hallucinated"


def test_classify_arg_order_is_stable():
    # dup detection is argument-order-insensitive (dup_signature sorts keys)
    seen = {al.dup_signature("http_request", {"path": "/a", "method": "GET"})}
    kind, _ = al.classify_tool_call("http_request", {"method": "GET", "path": "/a"}, seen, at.CALLABLE_TOOL_NAMES)
    assert kind == "duplicate"


def test_forced_debrief_message_shape():
    msg = al.forced_debrief_message()
    assert "final" in msg.lower() and '"done":true' in msg


def test_terminal_json_is_structural_not_keyword():
    # a real debrief structure -> terminal
    assert tc.has_terminal_json('```json\n{"done":true,"findings":[]}\n```')
    assert tc.has_terminal_json('{"abstained":true}')
    # prose that merely says "done" is NOT a terminal turn (structural, not keyword)
    assert not tc.has_terminal_json("Let me check the basket, I'm done thinking about login.")
    assert not tc.has_terminal_json("I will now probe /api/Cards as user2.")
    assert not tc.has_terminal_json("")


def test_interpret_prose_is_not_terminal():
    # unparseable prose must NOT be a terminal/abstain turn (audit N1) -> caller re-prompts
    d = tc.interpret_assistant("Let me now check the basket endpoints. I'm done thinking.")
    assert d["tool_calls"] == [] and d["findings"] == []
    assert d["done"] is False and d["abstained"] is False


def test_interpret_explicit_abstain_is_terminal():
    d = tc.interpret_assistant('```json\n{"done":true,"findings":[],"abstained":true}\n```')
    assert d["done"] is True and d["abstained"] is True and d["findings"] == []


def test_interpret_dict_no_toolcalls_is_terminal():
    d = tc.interpret_assistant({"findings": [], "abstained": True})
    assert d["done"] is True and d["abstained"] is True


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


def test_attack_scanners_dalfox_sqlmap_present_and_bounded():
    # dalfox + sqlmap join the fixed-argv arsenal: active (approval-gated), bounded reservations,
    # GET-based XSS (no headless/blind/mining), widened SQLi (BEUT incl. time-based inside a
    # 300s wall, level/risk 2, no crawl).
    assert {"dalfox", "sqlmap"}.issubset(at.RUN_TOOL_NAMES)
    for name in ("dalfox", "sqlmap"):
        assert at.SCANNER_ARG_TEMPLATES[name]["risk"] == "active"
        assert at.scanner_request_reservation(name) >= 200

    b, argv, _ = at.build_scanner_argv("dalfox", "http://t/search?q=1", {"severity": "high"})
    assert b == "dalfox"
    assert argv[0] == "url" and argv[argv.index("url") + 1] == "http://t/search?q=1"
    assert "--skip-headless" in argv and "--skip-bav" in argv and "--skip-mining-all" in argv
    assert argv[argv.index("--worker") + 1] == "3" and argv[argv.index("--delay") + 1] == "1000"
    assert argv[argv.index("--only-poc") + 1] == "v"  # default severity -> verified-only PoCs
    assert argv[argv.index("--format") + 1] == "jsonl"

    b, argv, timeout = at.build_scanner_argv("sqlmap", "http://t/item?id=1", {})
    assert b == "sqlmap"
    assert argv[argv.index("-u") + 1] == "http://t/item?id=1"
    assert argv[argv.index("--batch") + 1] == "--technique"  # non-interactive
    assert argv[argv.index("--technique") + 1] == "BEUT"     # boolean/error/union/time-based
    assert argv[argv.index("--level") + 1] == "2" and argv[argv.index("--risk") + 1] == "2"
    assert argv[argv.index("--threads") + 1] == "1" and argv[argv.index("--delay") + 1] == "1"
    assert argv[argv.index("--retries") + 1] == "0"
    assert timeout == 300_000                                # wider window for time-based payloads
    assert at.scanner_request_reservation("sqlmap") == 900
    assert "--crawl" not in " ".join(argv) and "--os-shell" not in " ".join(argv)


def test_attack_scanner_pinning_preserves_host_and_sni():
    _, argv, _ = at.build_scanner_argv("dalfox", "https://t.test:8443/x?a=1", {}, pinned_address="10.0.0.5")
    assert argv[argv.index("url") + 1].startswith("https://10.0.0.5:8443/")
    assert argv[argv.index("--header") + 1] == "Host: t.test:8443"

    _, argv, _ = at.build_scanner_argv("sqlmap", "https://t.test:8443/x?a=1", {}, pinned_address="10.0.0.5")
    assert argv[argv.index("-u") + 1].startswith("https://10.0.0.5:8443/")
    assert argv[argv.index("--host") + 1] == "t.test:8443"


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
    assert at.scanner_request_reservation("nmap") == 60
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
    assert at.scanner_request_reservation("naabu") == 1200
    # rate 10 x the 120s wall must fit inside the wire reservation
    assert int(argv[argv.index("-rate") + 1]) * (timeout // 1000) <= at.scanner_request_reservation("naabu")


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


def test_hunt_scanner_projection_rejects_body_mutation_but_preserves_scan_input():
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
        # Hunt planners cannot turn those private adapter fields into mutation.
        with pytest.raises(CapabilityInputContractError, match="unsupported fields"):
            at.CAPABILITY_REGISTRY.validate_hunt_input(capability, body)
        with pytest.raises(CapabilityInputContractError, match="unsupported fields"):
            at.canonical_hunt_scanner_options(capability, body)


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
    for forbidden in ("tags", "severity", "template_ids", "template_pack_digest"):
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
