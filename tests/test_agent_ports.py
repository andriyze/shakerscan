"""Unit tests for the T3MP3ST-ported autonomous-agent primitives.

Pure-stdlib modules, so this runs on the host with no scanner deps:
    python3 tests/test_agent_ports.py
(also importable by pytest). Covers the provenance gate, the text tool-contract shim,
and the honest context packer.
"""
import os
import sys

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
            '"details":"user2 read user1 basket","evidence_refs":["resp_2","resp_3"],'
            '"cwe":"CWE-639"}],"abstained":false}\n```')
    fs = tc.parse_final_findings(text)
    assert len(fs) == 1
    assert fs[0]["title"] == "BOLA on basket" and fs[0]["severity"] == "high"
    assert fs[0]["predicate"] == "cross_principal_equivalent"
    assert fs[0]["evidence_refs"] == ["resp_2", "resp_3"]
    assert fs[0]["provenance"] == "model"


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


def test_http_evidence_is_tool_provenance():
    ev = at.http_evidence_item({"method": "GET", "path": "/x"}, {"status": 200, "body_sample": "hi"})
    assert ev["type"] in prov.TOOL_EVIDENCE_KINDS
    # a finding carrying this evidence passes the provenance gate
    g = prov.gate_live_finding({"severity": "high", "evidence": [ev]})
    assert g["passed"] and g["provenance"] == "tool"


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
