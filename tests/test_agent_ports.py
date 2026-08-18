"""Unit tests for the T3MP3ST-ported autonomous-agent primitives.

Pure-stdlib modules, so this runs on the host with no scanner deps:
    python3 tests/test_agent_ports.py
(also importable by pytest). Covers the provenance gate, the text tool-contract shim,
and the honest context packer.
"""
import os
import json
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

import agent_provenance as prov
import agent_text_toolcalls as tc
import agent_context_pack as cp
import agent_tools as at
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
    schemas = at.tool_schemas()  # default includes run_tool
    assert {s["name"] for s in schemas} == {"http_request", "query_kb", "diff", "note", "run_tool"}
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
        "X-Forwarded-For": "1.2.3.4", "Accept": "application/json", "X-Custom": "ok",
    })
    assert "Authorization" not in filtered and "Cookie" not in filtered
    assert "X-Api-Key" not in filtered and "X-Forwarded-For" not in filtered
    assert filtered.get("Accept") == "application/json"
    assert filtered.get("X-Custom") == "ok"


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


def test_run_tool_schema_and_names():
    schemas = at.tool_schemas(include_run_tool=True)
    assert any(s["name"] == "run_tool" for s in schemas)
    assert "run_tool" in at.CALLABLE_TOOL_NAMES
    assert at.tool_schemas(include_run_tool=False) == [s for s in schemas if s["name"] != "run_tool"]


def test_run_tool_argv_templates_hardcode_flags():
    b, argv, timeout = at.build_scanner_argv("httpx", "http://t/x", {})
    assert b == "httpx" and "-json" in argv and "-silent" in argv and argv[argv.index("-u") + 1] == "http://t/x"
    b, argv, timeout = at.build_scanner_argv("nuclei", "http://t/x", {"severity": "high,critical", "tags": "cve,exposure"})
    assert b == "nuclei" and "-jsonl" in argv
    assert "-no-interactsh" in argv
    assert argv[argv.index("-severity") + 1] == "high,critical"
    assert argv[argv.index("-tags") + 1] == "cve,exposure"


def test_run_tool_rejects_flag_injection():
    # a severity/tags value trying to inject flags is rejected -> safe defaults, no extra flags
    _, argv, _ = at.build_scanner_argv("nuclei", "http://t/x", {"severity": "-o /etc/passwd", "tags": "; rm -rf /"})
    assert argv[argv.index("-severity") + 1] == "high,critical"  # bad severity -> default
    assert "-tags" not in argv  # bad tags dropped
    assert "-o" not in argv and "/etc/passwd" not in argv


def test_run_tool_unknown_rejected():
    try:
        at.coerce_run_tool({"name": "metasploit", "target": "/x"})
        assert False
    except at.AgentToolError:
        pass


def test_discovery_scanners_present_and_active_gated():
    # katana + ffuf are part of the arsenal and classified active (deep_hunt-gated), never read_only,
    # so they cannot run in a passive (no-approval) session.
    assert {"katana", "ffuf"}.issubset(at.RUN_TOOL_NAMES)
    for name in ("katana", "ffuf"):
        assert at.SCANNER_ARG_TEMPLATES[name]["risk"] == "active"


def test_katana_argv_is_bounded_and_same_host():
    b, argv, timeout = at.build_scanner_argv("katana", "http://t/app", {})
    assert b == "katana"
    assert argv[argv.index("-u") + 1] == "http://t/app"
    assert "-js-crawl" in argv                                   # JS endpoint extraction on
    assert argv[argv.index("-field-scope") + 1] == "fqdn"        # same host ONLY, never cross-origin
    assert argv[argv.index("-depth") + 1] == "2"                 # bounded depth
    assert argv[argv.index("-crawl-duration") + 1] == "30s"      # hard wall cap
    assert argv[argv.index("-rate-limit") + 1] == "5"
    assert at.scanner_request_reservation("katana") == 150
    assert timeout > 0
    # no form-submission / cross-scope flags leaked in
    for unsafe in ("-form-extraction", "-automatic-form-fill", "-aff", "-display-out-scope", "-do"):
        assert unsafe not in argv


def test_external_scanner_output_is_typed_and_query_values_are_redacted():
    output = at.parse_scanner_output("nuclei", json.dumps({
        "template-id": "cve-test",
        "matched-at": "https://app.test/search?q=secret-value",
        "matcher-name": "body",
        "info": {"name": "Test match", "severity": "high"},
    }))

    assert output["parser_status"] == "parsed"
    record = output["records"][0]
    assert record["kind"] == "template_match"
    assert record["proof_state"] == "candidate"
    assert "secret-value" not in record["matched_at"]
    assert "q=%3Credacted%3E" in record["matched_at"]


def test_scanner_request_reservations_are_conservative_and_explicit():
    assert at.scanner_request_reservation("httpx") == 4
    assert at.scanner_request_reservation("nuclei") == 450
    assert at.scanner_request_reservation("ffuf") == 220


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
    with pytest.raises(at.AgentToolError, match="outside the authorized"):
        at.validate_pinned_scanner_address("127.0.0.1", ["203.0.113.7"])


def test_deep_hunt_has_a_separately_enforced_wire_budget():
    source = open(os.path.join(os.path.dirname(__file__), "..", "api", "api.py"), encoding="utf-8").read()
    assert '"budget_exhausted": "wire_requests"' in source
    assert "wire_request_budget_limit" in source
    assert "wire_requests_reserved\") or 0) + wire_request_reservation" in source
    with pytest.raises(at.AgentToolError, match="user information"):
        at.validate_scanner_execution_target("https://example.test", "https://user@example.test/")


def test_hunt_dns_authorization_is_frozen_in_session_state():
    api_path = os.path.join(os.path.dirname(__file__), "..", "api", "api.py")
    source = open(api_path, encoding="utf-8").read()
    seed_start = source.index("async def _agent_seed_state(")
    apply_start = source.index("async def _agent_apply_reply(")
    http_start = source.index("async def _agent_tool_http_request(")
    run_tool_start = source.index("async def _agent_tool_run_tool(")
    assert (
        'state["authorized_target_addresses"] = await '
        '_resolve_agent_target_addresses(target_url)'
    ) in source[seed_start:apply_start]
    assert "await _resolve_agent_target_addresses" not in source[http_start:run_tool_start]
    assert 'authorized_addresses=state.get("authorized_target_addresses") or []' in source


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
    assert katana["mode"] == "observed_lower_bound"
    assert katana["actual"] is None and katana["observed_minimum"] == 2
    assert at.scanner_request_settlement("ffuf", "not-json")["mode"] == "unavailable"


def test_ffuf_wordlist_tunable_is_injection_proof():
    # a valid selector maps to a BUNDLED list and FUZZ is appended to the same-origin base
    _, argv, _ = at.build_scanner_argv("ffuf", "http://t/base", {"wordlist": "api"})
    assert argv[argv.index("-u") + 1] == "http://t/base/FUZZ"
    assert argv[argv.index("-w") + 1] == at._AGENT_FFUF_WORDLISTS["api"]
    assert "-maxtime" in argv and "-ac" in argv                  # hard wall cap + soft-404 filtering
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
    # GET-based XSS (no headless/blind/mining), boolean/error-only SQLi (no time-based, no crawl).
    assert {"dalfox", "sqlmap"}.issubset(at.RUN_TOOL_NAMES)
    for name in ("dalfox", "sqlmap"):
        assert at.SCANNER_ARG_TEMPLATES[name]["risk"] == "active"
        assert at.scanner_request_reservation(name) >= 200

    b, argv, _ = at.build_scanner_argv("dalfox", "http://t/search?q=1", {"severity": "high"})
    assert b == "dalfox"
    assert argv[0] == "url" and argv[argv.index("url") + 1] == "http://t/search?q=1"
    assert "--skip-headless" in argv and "--skip-bav" in argv and "--skip-mining-all" in argv
    assert argv[argv.index("--worker") + 1] == "3" and argv[argv.index("--delay") + 1] == "200"
    assert argv[argv.index("--only-poc") + 1] == "v"  # default severity -> verified-only PoCs
    assert argv[argv.index("--format") + 1] == "jsonl"

    b, argv, _ = at.build_scanner_argv("sqlmap", "http://t/item?id=1", {})
    assert b == "sqlmap"
    assert argv[argv.index("-u") + 1] == "http://t/item?id=1"
    assert argv[argv.index("--batch") + 1] == "--technique"  # non-interactive
    assert argv[argv.index("--technique") + 1] == "BE"       # boolean+error only
    assert argv[argv.index("--level") + 1] == "1" and argv[argv.index("--risk") + 1] == "1"
    assert "--crawl" not in " ".join(argv) and "--os-shell" not in " ".join(argv)


def test_attack_scanner_pinning_preserves_host_and_sni():
    _, argv, _ = at.build_scanner_argv("dalfox", "https://t.test:8443/x?a=1", {}, pinned_address="10.0.0.5")
    assert argv[argv.index("url") + 1].startswith("https://10.0.0.5:8443/")
    assert argv[argv.index("--header") + 1] == "Host: t.test:8443"

    _, argv, _ = at.build_scanner_argv("sqlmap", "https://t.test:8443/x?a=1", {}, pinned_address="10.0.0.5")
    assert argv[argv.index("-u") + 1].startswith("https://10.0.0.5:8443/")
    assert argv[argv.index("--host") + 1] == "t.test:8443"


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
    # no trailing id segment -> the route itself is the collection
    t = at.derive_bola_verification_targets("/rest/basket", {"basket_id": "15"}, {"basket_id": "16"})
    assert t["collection"] == "/rest/basket"


# ------------------------------------------------------------------------ runner --------

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
