"""Tests for scanner_tools.bola_comparison.

Pins the cross-user response comparison contract: volatile fields must not
defeat equivalence (fixes BOLA false negatives), and user-specific-data
detection must key on PII-shaped values rather than chrome substrings
(fixes BOLA noise).
"""

from scanner.scanner_tools.bola_comparison import (
    all_responses_equivalent,
    carries_user_specific_data,
    extract_user_specific_signals,
    normalize_response_body,
    response_similarity,
    responses_equivalent,
)


# ---- volatile normalization / equivalence --------------------------------

def test_identical_bodies_are_equivalent():
    body = '{"id": 1, "owner": "alice", "balance": 100}'
    assert responses_equivalent(body, body) is True
    assert response_similarity(body, body) == 1.0


def test_volatile_csrf_token_does_not_defeat_equivalence():
    # Same resource, different per-request CSRF token — a genuine BOLA still
    # returns the same underlying data.
    user1 = '{"id": 1, "owner": "alice", "csrf_token": "aaaaaaaaaaaaaaaaaaaaaaaa1"}'
    user2 = '{"id": 1, "owner": "alice", "csrf_token": "bbbbbbbbbbbbbbbbbbbbbbbb2"}'
    assert responses_equivalent(user1, user2) is True


def test_volatile_timestamp_does_not_defeat_equivalence():
    user1 = '{"id": 1, "owner": "alice", "served_at": "2026-05-29T12:00:00Z"}'
    user2 = '{"id": 1, "owner": "alice", "served_at": "2026-05-29T12:00:05Z"}'
    assert responses_equivalent(user1, user2) is True


def test_volatile_request_id_uuid_does_not_defeat_equivalence():
    user1 = '{"id": 1, "owner": "alice", "request_id": "11111111-2222-3333-4444-555555555555"}'
    user2 = '{"id": 1, "owner": "alice", "request_id": "99999999-8888-7777-6666-aaaaaaaaaaaa"}'
    assert responses_equivalent(user1, user2) is True


def test_genuinely_different_data_is_not_equivalent():
    # The whole point of correct authorization: each user sees their own data.
    user1 = '{"id": 1, "owner": "alice", "balance": 100, "email": "alice@corp.test"}'
    user2 = '{"id": 1, "owner": "bob", "balance": 99999, "email": "bob@corp.test"}'
    assert responses_equivalent(user1, user2) is False


def test_empty_bodies_equivalent_but_one_empty_not():
    assert responses_equivalent("", "") is True
    assert responses_equivalent("data", "") is False


def test_normalize_masks_volatile_and_collapses_whitespace():
    norm = normalize_response_body('{\n  "csrf_token":  "abcabcabcabcabcabcabcabc"\n}')
    assert "abcabcabc" not in norm
    # Whitespace collapsed.
    assert "\n" not in norm


# ---- user-specific data detection ----------------------------------------

def test_email_value_is_user_specific_signal():
    body = '{"id": 1, "email": "alice@corp.test", "name": "Alice"}'
    signals = extract_user_specific_signals(body)
    assert any(s.startswith("email:") for s in signals)
    assert carries_user_specific_data(body) is True


def test_navigation_chrome_is_not_user_specific():
    # The words "Profile", "Account", "email" appear in chrome but there is no
    # actual user data — must NOT register.
    body = (
        "<html><nav><a href='/profile'>Profile</a>"
        "<a href='/account'>Account</a></nav>"
        "<footer>Contact us by email</footer></html>"
    )
    assert carries_user_specific_data(body) is False


def test_error_envelope_is_not_user_specific():
    body = '{"error": "invalid email", "code": "VALIDATION_ERROR"}'
    assert carries_user_specific_data(body) is False


def test_placeholder_email_is_ignored():
    body = '{"email": "noreply@example.com", "support": "test@example.org"}'
    assert carries_user_specific_data(body) is False


def test_populated_identity_field_is_signal():
    body = '{"username": "alice_real", "account_id": "ACCT-99812"}'
    signals = extract_user_specific_signals(body)
    assert any(s.startswith("field:") for s in signals)


def test_boilerplate_identity_values_ignored():
    body = '{"username": "", "email": "null", "full_name": "n/a"}'
    assert carries_user_specific_data(body) is False


# ---- multi-user all-equivalent -------------------------------------------

def test_all_responses_equivalent_with_volatile_differences():
    bodies = [
        '{"id": 1, "owner": "alice", "csrf": "aaaaaaaaaaaaaaaaaaaaaaaa1"}',
        '{"id": 1, "owner": "alice", "csrf": "bbbbbbbbbbbbbbbbbbbbbbbb2"}',
        '{"id": 1, "owner": "alice", "csrf": "cccccccccccccccccccccccc3"}',
    ]
    assert all_responses_equivalent(bodies) is True


def test_all_responses_equivalent_false_when_one_differs():
    bodies = [
        '{"id": 1, "owner": "alice", "balance": 100}',
        '{"id": 1, "owner": "alice", "balance": 100}',
        '{"id": 1, "owner": "bob", "balance": 999999}',
    ]
    assert all_responses_equivalent(bodies) is False


def test_all_responses_equivalent_trivial_cases():
    assert all_responses_equivalent([]) is True
    assert all_responses_equivalent(["only one"]) is True
