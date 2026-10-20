"""Commands offered for copying pass every target-chosen value as one inert shell word.

Each command is pasted into every shell on this host (tests/shell_paste.py): nothing but the
recording stand-ins may run, and they must receive exactly the URL, parameter and payload.
"""

from __future__ import annotations

import json
import shlex
import urllib.parse

import pytest

from api.retest_contract import (
    build_replay_commands,
    current_replay_commands,
    infer_retest_inputs,
)
from api.retest_routes.router import public_retest_row
from scanner.reporting import _ai_safe_commands_for_finding, emit_config_findings
from scanner.scanner_tools.shell_words import shell_word
from tests.shell_paste import PAYLOADS, paste

_FORM = ("-H", "Content-Type: application/x-www-form-urlencoded")


def _only_curl(run):
    assert [tool for tool, _args in run.calls] == ["curl"], run
    return run.calls[0][1]


def _same_url(sent: str, stored: str) -> None:
    """curl got one valid URL naming the same resource as the stored one."""
    assert not any(ch in sent for ch in " []{}\\`\"<>^|") and sent.isascii(), sent
    assert urllib.parse.unquote(sent) == urllib.parse.unquote(stored), (sent, stored)


# --- the helper -------------------------------------------------------------------------------

_WORDS = (*PAYLOADS, "", "'", "''", "\\", "a\\b", "x\\'$(pwn)", "=pwn", "!!", "!pwn", "~root", "*", "?", "[a]",
          "{a,b}", "%s%n%%", "a  b", "-n", "#not-a-comment", "é•", "a\x15b", "\x1b[31m", "\x03pwn", "\x85")


def test_shell_word_reads_back_as_the_same_text_in_every_shell(tmp_path):
    words = [shell_word(value) for value in _WORDS]
    for word in words:
        assert not any(ch < " " or "\x7f" <= ch <= "\x9f" for ch in word), repr(word)
        # Every backslash sits in a "\\" run outside single quotes: fish reads \' inside them.
        assert "\\" not in word.replace('"\\\\"', ""), word
    # A control character comes back as its percent-encoding; everything else exactly.
    expected = "".join("".join(urllib.parse.quote(ch, safe="") if ch < " " or "\x7f" <= ch <= "\x9f" else ch
                               for ch in value) + "\n" for value in _WORDS)
    for run in paste("printf '%s\\n' " + " ".join(words), tmp_path):
        assert run.stdout == expected, run.shell


@pytest.mark.parametrize("value", ["https://example.com/id_rsa", "app.fixture.invalid:443", "a b", "$(id)", "it's"])
def test_shell_word_keeps_the_familiar_shlex_form_for_ordinary_values(value):
    assert shell_word(value) == shlex.quote(value)


# --- retest replay commands -------------------------------------------------------------------

@pytest.mark.parametrize("payload", PAYLOADS)
def test_get_replay_sends_exactly_the_stored_url_and_the_payload(payload, tmp_path):
    url = f"http://app.fixture.invalid/{payload}/search?q=books&page=2"
    attack = f"<script>{payload}</script>"
    plain, injected = build_replay_commands({"finding_type": "xss", "target_url": url, "param": "q", "payload": attack})
    for run in paste(plain, tmp_path):
        args = _only_curl(run)
        assert args[:2] == ("-i", "-k") and len(args) == 3, run
        _same_url(args[2], url)
    for run in paste(injected, tmp_path):
        args = _only_curl(run)
        sent = urllib.parse.urlsplit(args[2])
        _same_url(urllib.parse.urlunsplit(sent._replace(query="")), url.split("?")[0])
        assert urllib.parse.parse_qs(sent.query) == {"q": [attack], "page": ["2"]}, run


@pytest.mark.parametrize("payload", PAYLOADS)
@pytest.mark.parametrize("param", ["q", None])
def test_post_replay_sends_exactly_the_parameter_and_the_payload(payload, param, tmp_path):
    url = f"http://app.fixture.invalid/{payload}/login"
    field = f"user{payload}" if param else None
    plain, posted = build_replay_commands({"finding_type": "sqli", "target_url": url, "method": "POST",
                                           "param": field, "payload": f"' OR {payload}"})
    for run in paste(plain, tmp_path):
        _same_url(_only_curl(run)[2], url)
    for run in paste(posted, tmp_path):
        args = _only_curl(run)
        assert args[:4] == ("-i", "-k", "-X", "POST") and args[5:7] == _FORM and args[7] == "--data", run
        _same_url(args[4], url)
        assert urllib.parse.parse_qs(args[8]) == {field or "payload": [f"' OR {payload}"]}, run


def test_replay_of_a_stored_finding_row_runs_nothing_from_its_url(tmp_path):
    # A browser keeps quotes, $, braces and parentheses in a crawled path.
    url = "http://app.fixture.invalid/'$(touch${IFS}.shell-ran)'/search?q=books"
    inputs = infer_retest_inputs({"title": "Reflected XSS", "tool": "dalfox", "finding_url": url, "target_url": url,
                                  "evidence": json.dumps({"url": url, "param": "q"})})
    commands = build_replay_commands(inputs)
    assert len(commands) == 2
    for command in commands:
        for run in paste(command, tmp_path):
            assert urllib.parse.unquote(_only_curl(run)[2]).startswith("http://app.fixture.invalid/'$(touch${IFS}.shell-ran)'/"), run


@pytest.mark.parametrize("param", ["q';touch .shell-ran;'", "q"])
def test_default_sqli_payload_and_a_quoting_parameter_parse_and_run_nothing(param, tmp_path):
    # The default payload is "' OR '1'='1"; it used to leave the command with an open quote.
    _plain, posted = build_replay_commands({"finding_type": "sqli", "target_url": "http://app.fixture.invalid/login",
                                            "method": "POST", "param": param})
    for run in paste(posted, tmp_path):
        assert urllib.parse.parse_qs(_only_curl(run)[8]) == {param: ["' OR '1'='1"]}, run


def test_exposure_replay_is_one_plain_get():
    assert build_replay_commands({"finding_type": "exposed_file", "target_url": "https://app.fixture.invalid/a b/.env"}) == [
        "curl -i -k https://app.fixture.invalid/a%20b/.env"]


def test_a_stored_row_never_serves_its_old_command_text(tmp_path):
    url = "http://app.fixture.invalid/'$(pwn)'/search?q=books"
    # What a row queued before shell_word holds: the path closes the hand-written quotes.
    old = ["curl -i -k 'http://app.fixture.invalid/%27%24%28pwn%29%27/search?q=books'",
           "curl -i -k 'http://app.fixture.invalid/'$(pwn)'/search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E'"]
    row = {"finding_type": "xss", "target_url": url, "original_url": url, "param": "q", "payload": None,
           "method": "GET", "replay_commands": json.dumps(old)}
    served = public_retest_row(row)["replay_commands"]
    assert served == build_replay_commands(infer_retest_inputs(row)) and served != old
    for command in served:
        paste(command, tmp_path)


def test_structured_replay_entries_and_rows_without_inputs_are_kept():
    plan = [{"description": "Focused AI Gate replay", "scan_id": "s", "prompt_count": 2}]
    assert current_replay_commands({"target_url": "https://ai.fixture.invalid", "replay_commands": json.dumps(plan)}) == plan
    assert current_replay_commands({"replay_commands": ["curl https://example.test"]}) == ["curl https://example.test"]
    assert current_replay_commands({"target_url": "https://app.fixture.invalid", "replay_commands": None}) is None


# --- scanner reproduction and verification commands -------------------------------------------

@pytest.mark.parametrize("payload", PAYLOADS)
def test_scanner_verification_commands_quote_target_paths(payload, tmp_path):
    base = f"https://app.fixture.invalid/{payload}"
    findings = [
        {"tool": "exposed_files", "title": "Exposed file", "evidence": {"url": f"{base}/.git/config", "path": f"{payload}/.git/id_rsa"}},
        {"tool": "graphql_vulnerability", "title": "GraphQL", "evidence": {"evidence": [{"endpoint": f"/{payload}/graphql"}]}},
        {"tool": "waf_detector", "title": "WAF"},
        {"tool": "cors_scanner", "title": "CORS"},
        {"tool": "api_security", "title": "nosql injection"},
    ]
    for finding in findings:
        commands = _ai_safe_commands_for_finding(finding, base, "app.fixture.invalid")
        assert commands, finding
        for command in commands:
            for run in paste(command, tmp_path):
                assert any(arg.startswith("https://app.fixture.invalid/") for _tool, args in run.calls for arg in args), run


def test_config_finding_reproductions_quote_the_host_and_target_urls(tmp_path):
    # A public-looking name (posture findings are skipped for .invalid); nothing leaves the host.
    host, final_url = "app$(pwn).fixture.example.com", "https://app.fixture.example.com/$(pwn)/"
    report = {
        "input": {"target": final_url, "normalized_host": host, "port": 443, "scheme": "https"},
        "http": {"final_url": final_url, "scheme_redirect": "none", "security_headers": {},
                 "csp_evaluation": {"present": False, "issues": []}, "cookies": {"details": [], "issues": []},
                 "security_txt": {"present": False, "url": "https://app.fixture.example.com/'$(pwn)'/.well-known/security.txt"}},
        "tls": {"endpoints": [], "certificate": {"days_remaining": 5, "not_after": "2026-10-24"}, "ocsp": {"stapled": False},
                "sslyze": {"tls_versions": {"tls_1_0": True, "tls_1_2": True}}, "testssl": {"supports_tls13": False}, "nmap": {}},
        "dns": {"mx": [], "spf": None, "dmarc": {"fields": {}, "record": None}, "dnssec": {}, "caa": {"records": []},
                "mta_sts": {}, "tls_rpt": {}},
        "discovery": {},
        "findings": [],
    }
    emit_config_findings(report)
    commands = {finding["evidence"]["reproduction"] for finding in report["findings"]
                if isinstance(finding.get("evidence"), dict) and finding["evidence"].get("reproduction")}
    tools = {command.split()[0] for command in commands}
    assert {"curl", "testssl.sh", "openssl", "echo", "dig"} <= tools, commands
    for command in commands:
        for run in paste(command, tmp_path):
            assert any("$(pwn)" in arg for _tool, args in run.calls for arg in args), (run, command)
