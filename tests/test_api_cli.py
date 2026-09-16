"""`shakerscan api`: the agent kit's one way to call the API, local or remote."""

from __future__ import annotations

import io
import json
import sys
import urllib.error
from pathlib import Path

import pytest

sys.path.insert(0, "scripts")
import api_cli  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


class FakeOpener:
    def __init__(self, status=200, body=b'{"ok": true}'):
        self.status, self.body, self.requests = status, body, []

    def open(self, request, timeout=None):
        self.requests.append(request)
        if self.status >= 400:
            raise urllib.error.HTTPError(request.full_url, self.status, "err", {}, io.BytesIO(self.body))
        return _Response(self.status, self.body)


class _Response(io.BytesIO):
    def __init__(self, status, body):
        super().__init__(body)
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_base_url_precedence_and_validation():
    assert api_cli.base_url(None, {}) == "http://127.0.0.1:8080"
    assert api_cli.base_url(None, {"SHAKERSCAN_API_URL": "https://a.example/"}) == "https://a.example"
    assert api_cli.base_url(None, {"SHAKERSCAN_API_BASE": "https://b.example", "SHAKERSCAN_API_URL": "https://a.example"}) == "https://b.example"
    assert api_cli.base_url("https://c.example", {"SHAKERSCAN_API_BASE": "https://b.example"}) == "https://c.example"
    with pytest.raises(api_cli.ApiCliError):
        api_cli.base_url("ftp://x", {})


def test_token_comes_from_a_file_by_preference_and_travels_only_over_https(tmp_path):
    token_file = tmp_path / "token"
    token_file.write_text("sse_secret\n", encoding="utf-8")
    assert api_cli.bearer_token({"SHAKERSCAN_API_TOKEN_FILE": str(token_file), "SHAKERSCAN_API_TOKEN": "other"}) == "sse_secret"
    assert api_cli.bearer_token({"SHAKERSCAN_API_TOKEN": "sse_env"}) == "sse_env"
    assert api_cli.bearer_token({}) is None
    request = api_cli.build_request("get", "/findings?limit=2", None, api_url="https://a.example", token="sse_secret")
    assert request.full_url == "https://a.example/findings?limit=2"
    assert request.get_header("Authorization") == "Bearer sse_secret"
    with pytest.raises(api_cli.ApiCliError, match="https"):
        api_cli.build_request("GET", "/health", None, api_url="http://127.0.0.1:8080", token="sse_secret")
    plain = api_cli.build_request("GET", "/health", None, api_url="http://127.0.0.1:8080", token=None)
    assert plain.get_header("Authorization") is None


def test_post_sends_compact_json_and_errors_show_the_instance_detail():
    request = api_cli.build_request("POST", "/scans", '{"target": "https://t.example", "policy": {"active_testing": false}}', api_url="https://a.example", token=None)
    assert request.data == b'{"target":"https://t.example","policy":{"active_testing":false}}'
    assert request.get_header("Content-type") == "application/json"
    with pytest.raises(api_cli.ApiCliError, match="JSON"):
        api_cli.build_request("POST", "/scans", "{not json", api_url="https://a.example", token=None)
    opener = FakeOpener(403, json.dumps({"detail": "operation is not enabled for this role in Enterprise beta"}).encode())
    status, text = api_cli.call(request, opener=opener)
    output, code = api_cli.render(status, text)
    assert code == 1 and output == "HTTP 403: operation is not enabled for this role in Enterprise beta"
    output, code = api_cli.render(200, '{"b": 1, "a": [1, 2]}')
    assert code == 0 and output == '{\n  "b": 1,\n  "a": [\n    1,\n    2\n  ]\n}'


def test_the_agent_kit_calls_the_api_only_through_the_helper():
    """Every API call the kit teaches an agent goes through `shakerscan api`, so the same
    instructions work against a local engine and a connected remote instance with a token."""
    kit = [ROOT / "AGENTS.md", *(ROOT / ".claude" / "commands").glob("*.md"), *(ROOT / ".claude" / "agents").glob("*.md"),
           ROOT / "skills" / "shakerscan" / "SKILL.md", *(ROOT / "skills" / "content-discovery" / "references").glob("*.md"),
           *(ROOT / "skills" / "js-analyze" / "references").glob("*.md"), ROOT / "skills" / "ai-security-session" / "references" / "api.md"]
    offenders = [str(p.relative_to(ROOT)) for p in kit if 'curl' in p.read_text(encoding="utf-8") and 'API_BASE' in p.read_text(encoding="utf-8") and any(
        'curl' in line and 'API_BASE' in line for line in p.read_text(encoding="utf-8").splitlines())]
    assert offenders == [], offenders
    hook = (ROOT / ".claude" / "hooks" / "session-start.sh").read_text(encoding="utf-8")
    assert "SHAKERSCAN_MANAGED_INSTANCE" in hook and "shakerscan api GET /health" in hook
    assert "scripts/api_cli.py" in (ROOT / "install" / "index.sh").read_text(encoding="utf-8")
