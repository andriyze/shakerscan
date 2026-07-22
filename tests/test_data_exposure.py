import importlib.util
import os
import re
import sys

_SCANNER_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scanner"))
_spec = importlib.util.spec_from_file_location(
    "shaker_data_exposure_under_test",
    os.path.join(_SCANNER_DIR, "scanner_tools", "data_exposure.py"),
)
_added = _SCANNER_DIR not in sys.path
if _added:
    sys.path.insert(0, _SCANNER_DIR)
try:
    de = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(de)
finally:
    if _added:
        sys.path.remove(_SCANNER_DIR)


def _first_match(body: str):
    for pattern, _title, family, _cwe in de.SENSITIVE_VALUE_PATTERNS:
        if re.search(pattern, body):
            return family
    return None


def test_patterns_match_honey_style_exposures():
    # Mirrors the actual honey responses captured from the live target.
    assert _first_match('{"service_token":"eyJhbGciOiJSUzI1NiIsImtpZCI6IiJ9.aaaa.bbbb"}') in (
        "secret_token_exposure",
    )
    assert _first_match(
        '{"iam":{"AccessKeyId":"AKIA4RCMT6DHZP7WXCQA","SecretAccessKey":"j3BcNHq8WvTk9mXpL2dFgY6hRa1Kz0QeS7oUiVnC"}}'
    ) == "cloud_credential_exposure"
    assert _first_match('{"keys":[{"id":"key_001","key":"FAKE_API_KEY_FULL_CANARY"}]}') == "api_key_exposure"
    assert _first_match("INFO c.acme.AuthFilter : Authorization: Bearer sk-prod-log-unsafe-001-abcdef") == (
        "secret_token_exposure"
    )
    assert _first_match("-----BEGIN RSA PRIVATE KEY-----\nMIIE...") == "private_key_exposure"


def test_patterns_do_not_match_benign_bodies():
    assert _first_match('{"status":"ok","items":[1,2,3],"page":1}') is None
    assert _first_match("<html><body>Welcome to the store</body></html>") is None


def test_get_method_url_parses_worklist_strings_and_dicts():
    assert de._get_method_url("GET /api/k8s/token") == "/api/k8s/token"
    assert de._get_method_url("GET /api/x?id=1&q=2") == "/api/x?id=1&q=2"
    assert de._get_method_url("POST /api/login") is None  # exposure probes reads only
    assert de._get_method_url({"method": "GET", "url": "/a"}) == "/a"
    assert de._get_method_url({"method": "POST", "url": "/a"}) is None
    assert de._get_method_url("https://example.com/api/foo") == "https://example.com/api/foo"
