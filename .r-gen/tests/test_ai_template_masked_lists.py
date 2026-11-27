"""An unchanged masked list is a no-op, not an ambiguous credential reassignment."""
from __future__ import annotations

import json

import pytest

import secret_store
from runtime import ai_template_secrets as templates


@pytest.fixture
def key(monkeypatch):
    from cryptography.fernet import Fernet

    monkeypatch.setenv("AI_CREDENTIAL_ENC_KEY", Fernet.generate_key().decode())
    monkeypatch.setattr(secret_store, "_loaded", False)
    monkeypatch.setattr(secret_store, "_fernet", None)


@pytest.mark.parametrize("template", [
    {"secret": ["first-canary", "second-canary"]},
    {"secret": [["first-canary", "second-canary"], ["third-canary", "fourth-canary"]]},
    {"secret": [1, 0, True, False, None, ""]},
    {"entries": [{"api_key": "first-canary"}, {"api_key": "second-canary"}]},
    {"headers": [{"name": "Authorization", "value": "first-canary"},
                 {"name": "Authorization", "value": "second-canary"}]},
    {"credentials": [{"key": "first-canary", "value": "third-canary"},
                     {"key": "second-canary", "value": "fourth-canary"}]},
    {"params": [{"key": "client_assertion", "val": "first-canary"},
                {"key": "api_key", "val": "second-canary"}]},
])
def test_unchanged_masked_lists_roundtrip_without_losing_values(key, template):
    original = {"input": "{{prompt}}", **template}
    stored = templates.protect(original)
    shown = templates.public(stored)
    assert "canary" not in json.dumps(shown)
    # Editing a separate, non-secret field must not force re-entry of the list.
    shown["input"] = "{{prompt}} with context"
    updated = templates.protect(shown, stored)
    assert templates.reveal(updated) == {**original, "input": shown["input"]}
    assert templates.public(updated) == shown
    assert templates.reveal(stored) == original
    assert updated["ciphertext"].startswith("enc:fernet:")


@pytest.mark.parametrize("changed", [
    ["***"], ["***", "***", "new-value"], ["new-value", "***"], ["***", "new-value"],
])
def test_edited_ambiguous_secret_lists_do_not_use_positional_restoration(key, changed):
    stored = templates.protect({"secret": ["first-canary", "second-canary"]})
    with pytest.raises(ValueError, match="Masked"):
        templates.protect({"secret": changed}, stored)
    assert templates.reveal(stored)["secret"] == ["first-canary", "second-canary"]


@pytest.mark.parametrize("change", ["delete", "append", "edit_metadata"])
def test_duplicate_named_entries_allow_noop_but_not_ambiguous_edits(key, change):
    original = {"headers": [{"name": "Authorization", "value": value, "enabled": True}
                            for value in ("first-canary", "second-canary")]}
    stored = templates.protect(original)
    shown = templates.public(stored)
    assert templates.reveal(templates.protect(shown, stored)) == original
    if change == "delete":
        shown["headers"].pop(0)
    elif change == "append":
        shown["headers"].append({"name": "Content-Type", "value": "application/json"})
    else:
        shown["headers"][0]["enabled"] = False
    with pytest.raises(ValueError, match="Masked"):
        templates.protect(shown, stored)


def test_same_length_named_reorder_keeps_entry_identity_not_position(key):
    original = {"headers": [{"name": "Authorization", "value": "first-canary"},
                            {"name": "X-Session-Token", "value": "second-canary"}]}
    stored = templates.protect(original)
    shown = templates.public(stored)
    shown["headers"].reverse()
    assert templates.reveal(templates.protect(shown, stored))["headers"] == original["headers"][::-1]


def test_explicit_replacement_secret_list_remains_editable(key):
    stored = templates.protect({"secret": ["first-canary", "second-canary"]})
    replacement = {"secret": ["new-second", "new-first"]}
    assert templates.reveal(templates.protect(replacement, stored)) == replacement


@pytest.mark.parametrize("first,second", [(True, 1), (False, 0), (1, 1.0)])
@pytest.mark.parametrize("change", ["reorder", "edit_metadata"])
def test_json_type_changes_are_edits_in_duplicate_named_masked_entries(key, first, second, change):
    original = {
        "headers": [
            {"name": "Authorization", "value": "first-canary", "metadata": {"enabled": first}},
            {"name": "Authorization", "value": "second-canary", "metadata": {"enabled": second}},
        ],
    }
    stored = templates.protect(original)
    shown = json.loads(json.dumps(templates.public(stored)))
    if change == "reorder":
        shown["headers"].reverse()
    else:
        shown["headers"][0]["metadata"]["enabled"] = second
    # Python equality ignores these edits; JSON retains their distinct types.
    assert shown == templates.public(stored)
    assert json.dumps(shown, sort_keys=True) != json.dumps(templates.public(stored), sort_keys=True)
    with pytest.raises(ValueError, match="Masked"):
        templates.protect(shown, stored)
    assert templates.reveal(stored) == original


def test_object_key_order_is_ignored_in_unchanged_duplicate_masked_lists(key):
    original = {
        "headers": [
            {"name": "Authorization", "value": value, "metadata": {"enabled": True, "slot": 1}}
            for value in ("first-canary", "second-canary")
        ],
    }
    stored = templates.protect(original)
    shown = templates.public(stored)
    shown["headers"] = [
        {"metadata": {"slot": 1, "enabled": True}, "value": item["value"], "name": item["name"]}
        for item in shown["headers"]
    ]
    assert templates.reveal(templates.protect(shown, stored)) == original
