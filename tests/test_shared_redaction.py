"""Tests for the shared secret-redaction module (R2a).

The point of scanner.redaction is that the API and Model Intake share ONE
sensitive-key set so coverage cannot drift. These tests lock that in plus the
masking/URL/text behaviour the old per-module helpers provided.
"""

from scanner import redaction
from scanner.redaction import (
    SENSITIVE_KEYS,
    is_sensitive_key,
    mask_secret,
    redact_sensitive,
    redact_text,
    redact_url_credentials,
)
from scanner.scanner_tools import model_intake


def test_unified_keyset_covers_both_historical_sources():
    # Previously API-only gap: AWS/Azure/GCP keys were missing from the API set.
    for key in ("aws_access_key_id", "aws_secret_access_key", "azure_sas_token", "gcp_credentials"):
        assert is_sensitive_key(key), key
    # Previously model-intake-only gap: API auth keys were missing from its set.
    for key in ("auth_header", "auth_cookies", "user2_header", "ai_api_key", "login_password"):
        assert is_sensitive_key(key), key


def test_key_matching_normalizes_dashes_and_fragments():
    assert is_sensitive_key("X-Api-Token")          # dash -> underscore, fragment "_token"
    assert is_sensitive_key("customer_password")    # fragment "password"
    assert is_sensitive_key("MY_SECRET_VALUE")      # case-insensitive exact
    assert not is_sensitive_key("username")
    assert not is_sensitive_key("user_id")


def test_model_intake_shares_the_one_keyset():
    # model_intake's public alias must BE the shared set (single source of truth).
    assert model_intake.SENSITIVE_METADATA_KEYS is SENSITIVE_KEYS
    # and it now masks an API-origin key it historically missed.
    out = model_intake.redact_model_intake_value({"auth_header": "Bearer abc", "note": "ok"})
    assert out["auth_header"] == "***"
    assert out["note"] == "ok"


def test_redact_sensitive_recurses_and_preserves_empty():
    payload = {
        "aws_access_key_id": "AKIAEXAMPLE",
        "empty_token": "",
        "nested": {"client_secret": "s3cr3t", "keep": "v"},
        "list": [{"password": "p"}, {"ok": 1}],
    }
    out = redact_sensitive(payload)
    assert out["aws_access_key_id"] == "***"
    assert out["empty_token"] == ""          # empty values are not masked
    assert out["nested"]["client_secret"] == "***"
    assert out["nested"]["keep"] == "v"
    assert out["list"][0]["password"] == "***"
    assert out["list"][1]["ok"] == 1


def test_redact_strings_flag_controls_url_credential_masking():
    url = "https://example.com/m?token=zzz&keep=1"
    # default (API scan-options mode) leaves strings alone
    assert redact_sensitive({"u": url})["u"] == url
    # redact_strings (model-intake mode) masks sensitive query params
    masked = redact_sensitive({"u": url}, redact_strings=True)["u"]
    assert "token=%2A%2A%2A" in masked or "token=***" in masked
    assert "keep=1" in masked


def test_redact_url_credentials_masks_userinfo_password():
    out = redact_url_credentials("https://user:hunter2@host/model")
    assert ":***@host" in out
    assert "hunter2" not in out


def test_mask_secret_partial_and_full():
    assert mask_secret("abcdefghijkl") == "abcd...ijkl"
    assert mask_secret("short") == "*****"
    assert mask_secret("") == ""


def test_redact_text_scrubs_known_patterns():
    assert redact_text("Authorization: Bearer abc.def-123") == "Authorization: Bearer ***"
    assert redact_text("api_key=SECRET&x=1") == "api_key=***&x=1"
    assert redact_text(None) is None
