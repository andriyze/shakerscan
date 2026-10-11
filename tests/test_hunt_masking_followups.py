"""Masking follow-ups after #398: gaps the reviews listed as pre-existing, each reproduced first.

1. Capability outputs published a plain SHA-256 of target response data (authz.verify, request
   replays and mutations, SQLi/NoSQLi proofs, NSE, browser console text, device tools, workflow
   receipts): an offline guessing oracle for any secret in it, recognised by the masking or not.
2. ``<input type="password" value="...">`` was masked only when its name looked secret.
3. ``artifact.inspect`` learned dump columns from a 64 KB head cut mid-statement.
4. ``http.experiment`` selected values were guarded by name only, and a value extracted into a
   later step's path was shown in that step's request.

Every value below is a synthetic unit fixture, never a real secret.
"""

from __future__ import annotations

import ast
import asyncio
import html
import json
import random
import sys
from pathlib import Path

import httpx
import pytest

import tests.test_hunt_withheld_values_separators as hostile
from api.capabilities import artifact as artifact_capability
from api.http_experiment import response_summary

masking = sys.modules[artifact_capability.mask_body_text.__module__]
ROOT = Path(__file__).resolve().parents[1]
ACTION = "00000000-0000-4000-8000-0000000009b1"
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0.c2lnbmF0dXJlYnl0ZXM"
TOKEN = "Qx7vKpWz9kLmTy3mNbPb8nVcRc2hXz"


def _hunt(callable_, *args, **kwargs):
    collector = masking.WithheldValues(ACTION)
    with masking.collecting_withheld_values(collector):
        return callable_(*args, **kwargs), collector


# --- 1. No plain digest of response data in a published output ---------------------------------

# (module, the expressions whose plain digests were published). Each now uses the keyed digest.
PUBLISHED_DIGESTS = {
    "api/capabilities/authz_modes.py": ["hashlib.sha256(body)"],
    "api/capabilities/authz_selected.py": ["hashlib.sha256(owner_doc"],
    "api/runtime/request_replay_executor.py": ["hashlib.sha256(result.response_body)"],
    "api/capabilities/request_mutation.py": ["hashlib.sha256(result.response_body)"],
    "api/capabilities/sqli_proof.py": ["_sha256(control.response_body)", "_sha256(payload.response_body)"],
    "api/capabilities/nosqli_verify.py": ["_sha256(result.response_body)", "_sha256(literal.response_body)"],
    "api/capabilities/nse_http_transport.py": ["hashlib.sha256(response.response_body)"],
    "api/capabilities/browser.py": ["hashlib.sha256(text.encode())"],
    "api/device_agent.py": ["hashlib.sha256(body_bytes)", "hashlib.sha256(encoded_value"],
    "api/devices/router.py": ['hashlib.sha256(bytes(replay.get("body")'],
    "api/workflow_experiment.py": ["hashlib.sha256(rendered_value", "hashlib.sha256(value.encode())",
                                   "hashlib.sha256(tail.encode())"],
    "api/scan/action_adapter.py": ["hashlib.sha256(result.response_body)"],
    "scanner/scanner_tools/device_application.py": ["hashlib.sha256(body)", "hashlib.sha256(response_body)"],
    "scanner/scanner_tools/device_control_plane.py": ["hashlib.sha256(response_body)",
                                                      'hashlib.sha256(bytes(describe.get("body")'],
    "scanner/scanner_tools/device_web.py": ["hashlib.sha256(negative_body)"],
}


@pytest.mark.parametrize("module", sorted(PUBLISHED_DIGESTS))
def test_no_plain_digest_of_response_data_is_published(module):
    source = (ROOT / module).read_text(encoding="utf-8")
    ast.parse(source)
    for expression in PUBLISHED_DIGESTS[module]:
        assert expression not in source, (module, expression)


def test_device_state_observations_publish_keyed_digests():
    from api import device_agent

    observation = device_agent.control_state_observation({"status": 200, "body": f'{{"token":"{TOKEN}"}}'.encode()})
    assert observation["body_sha256"].startswith("scrypt-")
    value = device_agent.control_json_pointer_value({"status": 200, "body": f'{{"pin":"{TOKEN}"}}'}, "/pin")
    assert value["found"] and value["value_sha256"].startswith("scrypt-")
    # Comparisons still hold within one installation.
    again = device_agent.control_state_observation({"status": 200, "body": f'{{"token":"{TOKEN}"}}'.encode()})
    assert again["body_sha256"] == observation["body_sha256"]


def test_the_keyed_digest_is_remembered_by_a_keyed_tag_not_a_plain_hash():
    from api.capabilities import secret_material

    first = secret_material.keyed_response_digest(TOKEN.encode())
    assert secret_material.keyed_response_digest(TOKEN.encode()) == first
    assert all(not key.startswith(first) and len(key) == 64 for key in secret_material._RESPONSE_DIGESTS)
    assert len(secret_material._RESPONSE_DIGESTS) <= secret_material._MAX_REMEMBERED_DIGESTS


# --- 2. Password inputs, whatever their name ----------------------------------------------------

def _password_input(value: str, rng: random.Random) -> str:
    attributes = [
        rng.choice(['type="password"', "type='password'", "type=password", 'TYPE="PassWord"']),
        rng.choice(['name="p"', 'name="field_7"', 'id="x1"', ""]),
        rng.choice(['value="' + html.escape(value) + '"', "value='" + html.escape(value, quote=True) + "'"]),
    ]
    rng.shuffle(attributes)
    return "<form><input " + " ".join(item for item in attributes if item) + "></form>"


def test_password_inputs_are_withheld_whatever_their_name():
    rng = random.Random(2903)
    for value in hostile.HOSTILE[:24]:
        if len(value) > 2000:
            continue
        body = _password_input(value, rng)
        template = masking.mask_body_text(_password_input("Zz", random.Random(0)))
        for shown in (masking.mask_body_text(body), _hunt(masking.mask_body_text, body)[0]):
            assert hostile._hostile_leaks(shown, value, template) == [], body


def test_a_password_input_value_is_a_reference_that_binds_it():
    shown, collector = _hunt(masking.mask_body_text, '<input value="Hunter2Pass!x" type="password" name="p">')
    assert shown == '<input value="[withheld:1]" type="password" name="p">'
    assert collector.values == ["Hunter2Pass!x"]


@pytest.mark.parametrize("text", [
    '<input type="text" name="q" value="hello world">',
    '<p>type="password" value="shown in prose"</p>',
    '<input type="hidden" name="page" value="2">',
])
def test_other_inputs_and_prose_are_unchanged(text):
    assert masking.mask_body_text(text) == text


# --- 3. A head cut mid-statement teaches no columns ---------------------------------------------

def test_a_create_table_cut_by_the_head_teaches_nothing_from_its_cut_list():
    assert artifact_capability._whole_statements("a\nCREATE TABLE users (id int,\n name text,\n p") == "a\n"
    assert artifact_capability._whole_statements("CREATE TABLE t (a int);\nINSERT INTO t") == (
        "CREATE TABLE t (a int);\n")


def test_a_dump_head_read_past_the_probe_learns_the_whole_column_list():
    head = "-- " + "x" * (artifact_capability.HEAD_PROBE_BYTES - 30 - 4) + "\n"
    dump = head + "CREATE TABLE users (id int, name text, password text);\n"
    assert len(head) < artifact_capability.HEAD_PROBE_BYTES < len(dump)
    row = "INSERT INTO users VALUES (1,'bob','Zq9vLmT4pRw2Hq');\n"
    collector = masking.WithheldValues(ACTION)
    tables: dict = {}
    for read in (dump.encode()[:artifact_capability.HEAD_PROBE_BYTES], dump.encode()[:artifact_capability.HEAD_READ_BYTES]):
        tables = {}
        collector.sql_tables = {"/backup.sql": tables}
        artifact_capability._learn_head(collector, tables, "/backup.sql", read, {"content-type": "application/sql"})
        columns = [value for key, value in tables.items() if not key.startswith("\0")]
        assert ["id", "name", "p"] not in columns  # never the cut list
    later = masking.WithheldValues(ACTION)
    later.sql_tables, later.sql_path, later.sql_dump_like = collector.sql_tables, "/backup.sql", True
    with masking.collecting_withheld_values(later):
        shown = masking.mask_body_text(row, window=True)
    assert "Zq9vLmT4pRw2Hq" not in shown


# --- 4. Selected and extracted values -----------------------------------------------------------

def _selected(document: dict, paths: list[str], *, hunt: bool):
    body = json.dumps(document).encode()
    response = httpx.Response(200, headers={"content-type": "application/json"}, content=body)
    if hunt:
        return _hunt(response_summary, response, body, selected_json_paths=paths)
    return response_summary(response, body, selected_json_paths=paths), None


@pytest.mark.parametrize("hunt", [False, True])
def test_a_selected_value_is_masked_by_its_shape(hunt):
    document = {"data": {"jwt": JWT, "auth": f"Bearer {TOKEN}", "opaque": TOKEN, "role": "admin", "id": 42}}
    paths = ["$.data.jwt", "$.data.auth", "$.data.opaque", "$.data.role", "$.data.id"]
    summary, collector = _selected(document, paths, hunt=hunt)
    selected = summary["selected_json"]
    text = json.dumps(selected)
    for secret in (JWT, TOKEN):
        assert secret not in text, secret
    assert selected["$.data.role"] == "admin" and selected["$.data.id"] == 42
    assert selected["$.data.auth"].startswith("Bearer ") or selected["$.data.auth"].startswith("***")
    if hunt:
        assert JWT in collector.values and TOKEN in collector.values
        assert {entry["marker"] for entry in summary["withheld_values"]} >= {"[withheld:1]"}
    else:
        assert selected["$.data.opaque"].startswith("*** (withheld scrypt-")


def test_two_different_secrets_still_read_as_a_change():
    from api.http_experiment import compare_summaries

    first, _ = _selected({"v": "Aa1" + TOKEN}, ["$.v"], hunt=False)
    second, _ = _selected({"v": "Bb2" + TOKEN}, ["$.v"], hunt=False)
    same, _ = _selected({"v": "Aa1" + TOKEN}, ["$.v"], hunt=False)
    assert ("Aa1" + TOKEN) not in json.dumps(first["selected_json"])
    assert compare_summaries(first, second)["selected_json_changed"]
    assert not compare_summaries(first, same)["selected_json_changed"]


def test_an_extracted_value_rendered_into_a_path_is_not_shown():
    from api import http_experiment as experiment

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/login":
            return httpx.Response(200, json={"session": {"next": TOKEN}})
        return httpx.Response(200, json={"ok": True})

    payload = {
        "steps": [
            {"label": "control", "method": "GET", "path": "/login",
             "extract": [{"name": "next_id", "source": "json", "path": "$.session.next"}]},
            {"label": "candidate", "method": "GET", "path": "/r/${next_id}", "compare_to": "control"},
        ],
    }
    seen: list[str] = []
    transport = httpx.MockTransport(lambda request: (seen.append(request.url.path), handler(request))[1])
    result = asyncio.run(experiment.execute_experiment("https://example.test", payload, transport=transport))
    assert seen == ["/login", f"/r/{TOKEN}"]  # the value was sent
    text = json.dumps(result)
    assert TOKEN not in text
    assert result["observations"][1]["request"]["path"] == "/r/${next_id}"
