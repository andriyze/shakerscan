"""Exposure grammars for source and documents that leak credentials without being config files.

Each class has a vulnerable twin that must verify and lookalikes that must not: PHP source
served instead of executed, environment assignments inside the fenced code blocks of a served
Markdown runbook, a credential left in an HTML comment, an anonymous JSON response listing
account records with plaintext passwords, and a Spring actuator audit-event log carrying a key.
Secret values are synthetic canaries assembled at runtime.
"""

from __future__ import annotations

import json

from api.capabilities.exposure_probe import (
    EXPOSURE_PROOF_CONTRACTS,
    classify_exposure,
    redacted_exposure_excerpt,
)
from api.proof_contracts import CANONICAL_PROOF_CONTRACTS

TOKEN = "Kq7" + "vR2mXp9Lz4Wt8Nc1Hb6Jd3Fs"
PASSWORD = "Vt9qLx2Rm7Zp4Kw8sJ3n"


def _classify(path: str, body: str | bytes, content_type: str = "text/plain", status: int = 200):
    data = body.encode() if isinstance(body, str) else body
    return classify_exposure(path=path, status=status, headers={"Content-Type": content_type},
                             body=data)


def _fields(signature) -> set[str]:
    return {item["field"] for item in signature.secret_evidence()}


# --- PHP source ---------------------------------------------------------------------------------

PHP_CONFIG = (
    "<?php\n\n# Database variables\n"
    "$DBMS = getenv('DBMS') ?: 'MySQL';\n"
    "$_APP = array();\n"
    "$_APP[ 'db_server' ]   = getenv('DB_SERVER') ?: '127.0.0.1';\n"
    "$_APP[ 'db_user' ]     = getenv('DB_USER') ?: 'app';\n"
    f"$_APP[ 'db_password' ] = getenv('DB_PASSWORD') ?: '{PASSWORD}';\n"
    "define('AUTH_SALT', getenv('AUTH_SALT'));\n"
    "?>\n"
)


def test_php_source_with_a_literal_password_default_verifies_as_a_config_secret():
    for path, content_type in (("/config/config.inc.php.dist", "application/octet-stream"),
                               ("/config.php.bak", "text/plain"),
                               ("/config.php", "text/html")):
        signature = _classify(path, PHP_CONFIG, content_type)
        assert signature is not None and signature.proves_sensitive_exposure, path
        assert signature.exposure_class == "configuration_secret_file"
        assert signature.matched_pattern == "php_configuration_secret"
        assert _fields(signature) == {"db_password"}
        excerpt = redacted_exposure_excerpt(PHP_CONFIG.encode(), signature)
        assert PASSWORD not in excerpt


def test_php_source_without_a_proven_secret_is_still_source_disclosure():
    weak = PHP_CONFIG.replace(PASSWORD, "p@ssw0rd")
    signature = _classify("/config/config.inc.php.dist", weak, "application/octet-stream")
    assert signature is not None and signature.proves_sensitive_exposure
    assert signature.exposure_class == "backup_or_source_artifact"
    assert signature.proof_contract == "backup_artifact_exposure/v1"
    # The weak value fails the entropy screen, but it is never shown either.
    assert "p@ssw0rd" not in redacted_exposure_excerpt(weak.encode(), signature)
    shell = "<?php\nif (isset($_GET['c'])) { system($_GET['c']); }\n"
    assert _classify("/shell.php", shell, "text/html").exposure_class == "backup_or_source_artifact"


def test_executed_php_and_pages_quoting_php_are_not_source_disclosure():
    assert _classify("/index.php", "<html><body>Hello</body></html>", "text/html") is None
    docs = "<html><body><pre>&lt;?php $db_password = 'x'; ?&gt;</pre></body></html>"
    assert _classify("/docs/php", docs, "text/html") is None
    # A note that only starts with the tag and has no PHP statement is not source.
    assert _classify("/note.txt", "<?php is how a PHP file starts.\nThat is all.") is None
    # Indirect values carry nothing.
    indirect = "<?php\n$config['db_password'] = getenv('DB_PASSWORD');\n"
    signature = _classify("/config.php.bak", indirect)
    assert signature.exposure_class == "backup_or_source_artifact" and not _fields(signature)


# --- Markdown runbooks ----------------------------------------------------------------------------

def test_markdown_fenced_env_assignment_with_a_real_token_verifies():
    body = (
        "# Deploy preview\n\nThe staging deploy API authenticates with a shared team token.\n\n"
        "```bash\n"
        f'export STAGING_DEPLOY_TOKEN="{TOKEN}"\n'
        'curl --header "Authorization: Bearer $STAGING_DEPLOY_TOKEN" https://deploy.invalid/\n'
        "```\n"
    )
    for path, content_type in (("/skills/deploy/SKILL.md", "text/markdown;charset=UTF-8"),
                               ("/notes/transcript.md", "text/plain")):
        signature = _classify(path, body, content_type)
        assert signature is not None and signature.proves_sensitive_exposure, path
        assert signature.exposure_class == "environment_secret_file"
        assert signature.proof_contract == "dotenv_secret_exposure/v1"
        assert _fields(signature) == {"STAGING_DEPLOY_TOKEN"}
        assert TOKEN not in redacted_exposure_excerpt(body.encode(), signature)


def test_markdown_prose_placeholders_and_non_markdown_files_prove_nothing():
    placeholder = "```\nexport API_TOKEN=<your-token>\nDB_PASSWORD=changeme\n```\n"
    assert _classify("/README.md", placeholder, "text/markdown") is None
    prose = f"Set DEPLOY_TOKEN={TOKEN} in your shell before you deploy.\n"
    assert _classify("/README.md", prose, "text/markdown") is None
    # The same fenced block in a file that is not Markdown is not read by this grammar.
    fenced = f"```\nexport DEPLOY_TOKEN={TOKEN}\n```\n"
    assert _classify("/notes.txt", fenced) is None


# --- HTML comments ------------------------------------------------------------------------------

def test_a_credential_in_an_html_comment_verifies():
    page = (
        "<!doctype html><html><head><title>Challenge</title></head><body>"
        f'<!-- test-credentials = {PASSWORD}"-->'
        "<!-- If you like this: check the other challenges! -->"
        "<p>Find the secret.</p></body></html>"
    )
    signature = _classify("/challenge/23", page, "text/html;charset=UTF-8")
    assert signature is not None and signature.proves_sensitive_exposure
    assert signature.exposure_class == "html_comment_secret"
    assert signature.proof_contract == "html_comment_secret_exposure/v1"
    assert signature.severity == "high"
    assert _fields(signature) == {"test-credentials"}
    assert PASSWORD not in redacted_exposure_excerpt(page.encode(), signature)


def test_html_comments_without_a_screened_secret_and_visible_text_prove_nothing():
    for comment in ("<!-- password: changeme -->", "<!-- Replaces a UI snippet dynamically -->",
                    "<!-- password policy: 12 characters -->", "<!-- api_key = ${API_KEY} -->",
                    f"<!-- api_key = {TOKEN} -->"):  # api keys are public in client pages
        page = f"<html><body>{comment}<p>x</p></body></html>"
        assert _classify("/", page, "text/html") is None, comment
    visible = f"<html><body><pre>db_password = {PASSWORD}</pre></body></html>"
    assert _classify("/docs", visible, "text/html") is None


# --- Account records ---------------------------------------------------------------------------

def test_anonymous_account_records_with_plaintext_passwords_verify():
    body = json.dumps({"users": [
        {"admin": False, "email": "a@example.test", "password": "pass1", "username": "name1"},
        {"admin": True, "email": "b@example.test", "password": "pass2", "username": "admin"},
    ]})
    signature = _classify("/users/v1/_debug", body, "application/json")
    assert signature is not None and signature.proves_sensitive_exposure
    assert signature.exposure_class == "credential_record_disclosure"
    assert signature.proof_contract == "credential_record_exposure/v1"
    assert signature.severity == "critical"
    excerpt = redacted_exposure_excerpt(body.encode(), signature)
    assert "pass1" not in excerpt and "pass2" not in excerpt


def test_hashes_masked_values_single_records_and_unnamed_rows_are_not_credential_dumps():
    hashed = json.dumps([
        {"username": "a", "password": "5f4dcc3b5aa765d61d8327deb882cf99"},
        {"username": "b", "password": "$2b$12$" + "a" * 53},
    ])
    assert _classify("/api/users", hashed, "application/json") is None
    masked = json.dumps([{"username": "a", "password": "******"},
                         {"username": "b", "password": "[REDACTED]"}])
    assert _classify("/api/users", masked, "application/json") is None
    single = json.dumps({"user": {"username": "a", "password": PASSWORD}})
    assert _classify("/api/me", single, "application/json") is None
    no_identity = json.dumps([{"id": 1, "password": "x1"}, {"id": 2, "password": "x2"}])
    assert _classify("/api/rows", no_identity, "application/json") is None
    policy = json.dumps([{"username": "a", "password": True}, {"username": "b", "password": None}])
    assert _classify("/api/flags", policy, "application/json") is None


def test_example_records_and_duplicate_identities_do_not_prove_an_account_dump():
    records = [{"username": "a", "password": "pass1"}, {"username": "b", "password": "pass2"}]
    for document in ({"examples": records}, {"example": {"users": records}},
                     {"openapi": "3.0.0", "paths": {}, "users": records},
                     [records[0], records[0]]):
        signature = _classify('/api/users', json.dumps(document), 'application/json')
        assert signature is None or not signature.proves_sensitive_exposure


# --- Actuator audit events ---------------------------------------------------------------------

def test_actuator_audit_events_with_a_received_key_verify_and_plain_logins_do_not():
    key = "39ebcb9f-3cc8-47e4-b459-c926c3c82656"
    leaking = json.dumps({"events": [{
        "data": {"apiKey": key}, "principal": "john", "type": "API_KEY_RECEIVED",
        "timestamp": "2026-10-14T20:10:04Z",
    }]})
    actuator = "application/vnd.spring-boot.actuator.v3+json"
    signature = _classify("/actuator/auditevents", leaking, actuator)
    assert signature is not None and signature.proves_sensitive_exposure
    assert signature.exposure_class == "actuator_secret_disclosure"
    assert key not in redacted_exposure_excerpt(leaking.encode(), signature)
    logins = json.dumps({"events": [{
        "data": {"details": {"remoteAddress": "10.0.0.1"}}, "principal": "john",
        "type": "AUTHENTICATION_SUCCESS", "timestamp": "2026-10-14T20:10:04Z",
    }]})
    signature = _classify("/actuator/auditevents", logins, actuator)
    assert signature is not None and not signature.proves_sensitive_exposure


def test_the_new_contracts_are_registered():
    for name in ("html_comment_secret", "credential_record_disclosure"):
        assert EXPOSURE_PROOF_CONTRACTS[name] in CANONICAL_PROOF_CONTRACTS


def test_the_http_capability_records_cookie_names_only():
    from api.capabilities.http import _cookie_name

    assert _cookie_name("PHPSESSID=abc123; path=/; HttpOnly") == "PHPSESSID"
    assert _cookie_name("connect.sid=s%3Aabc; Path=/") == "connect.sid"
    assert _cookie_name("=novalue") is None
    assert _cookie_name("bad name=1") is None


def test_the_http_capability_reads_cookie_flags_as_attributes_not_substrings():
    from api.capabilities.http import cookie_metadata as _set_cookie_metadata

    # A value, name or Path containing "secure"/"httponly" sets neither flag.
    assert _set_cookie_metadata("session=securehttponly; Path=/secure/httponly") == {
        "name": "session", "secure": False, "httponly": False, "samesite": None,
    }
    assert _set_cookie_metadata("secure_sid=abc; path=/; samesite=Laxish") == {
        "name": "secure_sid", "secure": False, "httponly": False, "samesite": None,
    }
    # Attribute names compare case-insensitively, with or without surrounding space.
    assert _set_cookie_metadata("PHPSESSID=abc; path=/;SECURE ; HttpOnly; SameSite=Strict") == {
        "name": "PHPSESSID", "secure": True, "httponly": True, "samesite": "strict",
    }
    assert _set_cookie_metadata("sid=1; Secure=; samesite=None")["samesite"] == "none"
    assert _set_cookie_metadata("sid=1; Secure=")["secure"] is True
