"""Hunt withholds raw target secrets from its archive and its planner, and can still use them (N56).

Soak and lab runs of 2.8.0 against the owned honeypot found raw credential values in the Hunt's
masked HTTP archive (JSON and HAR) and in ``shakerscan_hunt_capability`` outputs read by the model
provider: the ``ak_``/``st_`` values of a ``/backup.sql`` users table (SQL ``INSERT`` rows), the
``ApiKey`` of a ``/web.config`` ``<add key=... value=...>`` pair and a database password in a
``/phpinfo.php`` HTML table. The DAST masked archive withheld its own copies.

Every value below is a synthetic unit fixture shaped like the honeypot's, never a real secret.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import sys
import time
import uuid
from pathlib import Path

import pytest
import secret_store
from runtime.hunt_http_exchange import persist_withheld_values, prepare_http_exchange
from runtime.models import TargetBinding

from api.capabilities import artifact as artifact_capability
from api.capabilities.http import WorkerPrivateHTTPResponse
from api.runtime.http_archive_reader import export_document

# The masking module the capabilities actually import (one ContextVar, one collector type).
masking = sys.modules[artifact_capability.mask_body_text.__module__]
mask_body_text = masking.mask_body_text

# --- Synthetic fixtures (honey-shaped; not real secrets) ---------------------------------------
API_KEYS = [f"ak_{index}f3c9e1a7b2d84c60e5a9f1b3d7c2e8a4" for index in range(4)]
SECRET_TOKENS = [f"st_{index}9b7e2c4a1f6d8e3b5c0a9f7e2d4b6c8a1e3f5d7b9" for index in range(4)]
TWILIO_SID = "A" + "C" + "4f1e9b7c2a8d6e3f5b0c9a7e1d4f2b8c"  # split: a fixture, not a real SID
TWILIO_TOKEN = "d8a3c5e7f9b1d2a4c6e8f0b2d4a6c8e0"
BCRYPT = "$2y$10$" + "Qm7Tz2Lx9Vc4Nb8Rk1Wp6Hd5FaGs3Jd0Ke8Lf2Mg4Nh6Pj8Qk1Rl3S"
WEB_CONFIG_API_KEY = "9e2f7a4c1b8d6e3f5a0c9b7e1d4f2a8c"
CONNECTION_PASSWORD = "Fixture_Conn_Pw_2024!"
PHP_DB_PASSWORD = "Fx_DB_P@ss_2024!"

BACKUP_SQL = f"""-- MySQL dump 10.13 (unit fixture)
DROP TABLE IF EXISTS `users`;
CREATE TABLE `users` (
  `id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(50) NOT NULL,
  `email` varchar(100) NOT NULL,
  `password_hash` varchar(255) NOT NULL,
  `api_key` varchar(64) DEFAULT NULL,
  `secret_token` varchar(128) DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
LOCK TABLES `users` WRITE;
INSERT INTO `users` VALUES
{",".join(
    f"({index + 1},'user{index}','user{index}@fixture.test','{BCRYPT}','{API_KEYS[index]}',"
    f"'{SECRET_TOKENS[index]}','2024-01-0{index + 1} 09:12:44')"
    for index in range(4)
)};
UNLOCK TABLES;
CREATE TABLE `api_keys` (
  `id` int NOT NULL AUTO_INCREMENT,
  `service_name` varchar(100) NOT NULL,
  `api_key` varchar(255) NOT NULL,
  `api_secret` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
);
INSERT INTO `api_keys` VALUES (1,'Twilio','{TWILIO_SID}','{TWILIO_TOKEN}');
"""
WEB_CONFIG = f"""<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <connectionStrings>
    <add name="DefaultConnection" connectionString="Server=sql.fixture.test;Database=App;User Id=app;Password={CONNECTION_PASSWORD};" />
  </connectionStrings>
  <appSettings>
    <add key="ApiKey" value="{WEB_CONFIG_API_KEY}" />
    <add key="TokenUrl" value="https://login.fixture.test/oauth/token" />
    <add key="Environment" value="Production" />
  </appSettings>
</configuration>
"""
PHPINFO = f"""<html><body><h2>Environment</h2>
<table>
<tr class="h"><th>Variable</th><th>Value</th></tr>
<tr><td class="e">DB_HOST </td><td class="v">db.fixture.test </td></tr>
<tr><td class="e">DB_PASSWORD </td><td class="v">{PHP_DB_PASSWORD} </td></tr>
<tr><td class="e">$_SERVER['DB_PASSWORD'] </td><td class="v">{PHP_DB_PASSWORD} </td></tr>
<tr><td class="e">Primary key </td><td class="v">user_id </td></tr>
<tr><td class="e">Token URL </td><td class="v">https://auth.fixture.test/token </td></tr>
</table></body></html>
"""
SQL_SECRETS = (*API_KEYS, *SECRET_TOKENS, TWILIO_SID, TWILIO_TOKEN, BCRYPT)
XML_SECRETS = (WEB_CONFIG_API_KEY, CONNECTION_PASSWORD)
HTML_SECRETS = (PHP_DB_PASSWORD,)
ALL_SECRETS = (*SQL_SECRETS, *XML_SECRETS, *HTML_SECRETS)
CORPUS = (("/backup.sql", BACKUP_SQL), ("/web.config", WEB_CONFIG), ("/phpinfo.php", PHPINFO))

HUNT = str(uuid.UUID(int=401))
ACTION = str(uuid.UUID(int=402))
TARGET = TargetBinding(
    target_id=str(uuid.UUID(int=403)), target_kind="web", canonical_host="honey.fixture.test",
    allowed_origins=("https://honey.fixture.test",), allowed_addresses=("192.0.2.10",),
    allowed_root_domains=("fixture.test",), environment="lab", scope_receipt_id=str(uuid.UUID(int=404)),
)


@pytest.fixture
def encryption_key(monkeypatch, tmp_path):
    from cryptography.fernet import Fernet
    monkeypatch.setenv("AI_CREDENTIAL_ENC_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("RESULTS_DIR", str(tmp_path))
    monkeypatch.setattr(secret_store, "_loaded", False)
    monkeypatch.setattr(secret_store, "_fernet", None)


# --- 1. The formats that leaked -------------------------------------------------------------------

@pytest.mark.parametrize(("name", "body", "secrets"), [
    ("sql", BACKUP_SQL, SQL_SECRETS), ("xml", WEB_CONFIG, XML_SECRETS), ("html", PHPINFO, HTML_SECRETS),
])
def test_corpus_withholds_every_honey_shaped_value(name, body, secrets):
    masked = mask_body_text(body)
    leaked = [secret for secret in secrets if secret in masked]
    assert not leaked, f"{name}: {len(leaked)} raw values remain"


def test_corpus_keeps_the_structure_an_analyst_reads():
    sql = mask_body_text(BACKUP_SQL)
    assert "'user0@fixture.test'" in sql and "'2024-01-01 09:12:44'" in sql and "'Twilio'" in sql
    xml = mask_body_text(WEB_CONFIG)
    assert 'key="ApiKey" value="***"' in xml
    assert 'value="https://login.fixture.test/oauth/token"' in xml
    assert 'value="Production"' in xml
    html = mask_body_text(PHPINFO)
    assert "db.fixture.test" in html and "user_id" in html and "https://auth.fixture.test/token" in html


def test_pg_dump_copy_rows_and_column_lists_are_covered():
    body = (
        "COPY public.users (id, username, password, reset_token) FROM stdin;\n"
        f"1\talice\tWinter2023!\t{API_KEYS[0]}\n\\.\n"
        f"INSERT INTO accounts (name, client_secret) VALUES ('svc', 'LowEntropyPass1');\n"
    )
    masked = mask_body_text(body)
    for secret in ("Winter2023!", API_KEYS[0], "LowEntropyPass1"):
        assert secret not in masked
    assert "alice" in masked and "'svc'" in masked


def test_header_row_names_a_secret_column():
    body = "<table><tr><th>user</th><th>password</th></tr><tr><td>bob</td><td>Hunter2pass</td></tr></table>"
    masked = mask_body_text(body)
    assert "Hunter2pass" not in masked and "<td>bob</td>" in masked


# --- 2. Over-masking (PR #361 review) -------------------------------------------------------------

UUID_VALUE = "550e8400-e29b-41d4-a716-446655440000"
GIT_SHA = "3f786850e387550fdab836ed7e6dc881de23001b"


@pytest.mark.parametrize("text", [
    f"id={UUID_VALUE}",
    f"commit {GIT_SHA}",
    f"INSERT INTO commits VALUES (1,'{GIT_SHA}','{UUID_VALUE}');",
    "Primary key: id",
    "Token URL: https://auth.fixture.test/oauth/token",
    "tokenUrl: https://auth.fixture.test/oauth/token",
    "<td>Primary key</td><td>user_id</td>",
    '<add key="TokenUrl" value="https://login.fixture.test/token" />',
    "tokens_used: 42",
    "See https://docs.fixture.test/api/keys for details",
])
def test_identifiers_urls_and_labels_are_not_masked(text):
    assert mask_body_text(text) == text


def test_json_location_names_keep_their_urls():
    body = json.dumps({"tokenUrl": "https://auth.fixture.test/token", "primary_key": "id",
                       "api_key": WEB_CONFIG_API_KEY})
    masked = mask_body_text(body)
    assert "https://auth.fixture.test/token" in masked and '"primary_key": "id"' in masked
    assert WEB_CONFIG_API_KEY not in masked


# --- 3. The Hunt archive, JSON and HAR ------------------------------------------------------------

def _hunt_rows():
    return [{
        "id": str(uuid.UUID(int=500 + index)), "plane": "hunt", "sequence": index,
        "hunt_run_id": HUNT, "hunt_action_id": ACTION, "capability_name": "artifact.inspect",
        "method": "GET", "url": f"https://honey.fixture.test{path}", "status_code": 200,
        "request_headers": {}, "request_body": None,
        "response_headers": {"content-type": "text/plain"}, "response_body": body,
        "metadata_json": {},
    } for index, (path, body) in enumerate(CORPUS)]


@pytest.mark.parametrize("export_format", ["transactions", "har"])
def test_hunt_masked_archive_holds_no_raw_value(export_format):
    document = export_document(
        _hunt_rows(), export_format=export_format, redaction="redacted",
        owner={"hunt_id": HUNT}, total=3,
    )
    text = json.dumps(document)
    assert [secret for secret in ALL_SECRETS if secret in text] == []
    assert "db.fixture.test" in text  # bodies are present, only the secrets are withheld


# --- 4. Model-facing capability output and the MCP tool result -----------------------------------

def _inspect(monkeypatch, body: str, collector=None):
    async def fake_execute(_target_url, _args, **kwargs):
        kwargs["private_response_sink"](WorkerPrivateHTTPResponse(
            status_code=200, final_url="https://honey.fixture.test/x", _body=body.encode(),
            _headers={"content-type": "text/plain"}, _cookies={},
        ))
        return {"ok": True, "response": {"status": 200}}

    monkeypatch.setattr(artifact_capability, "execute_bound_http_request", fake_execute)

    async def run():
        if collector is None:
            return await artifact_capability.inspect_target_artifact(
                "https://honey.fixture.test", {"path": "/x", "max_bytes": 16_384}, target=TARGET)
        with masking.collecting_withheld_values(collector):
            return await artifact_capability.inspect_target_artifact(
                "https://honey.fixture.test", {"path": "/x", "max_bytes": 16_384}, target=TARGET)

    return asyncio.run(run())


@pytest.mark.parametrize(("path", "body"), CORPUS)
def test_artifact_output_withholds_values_behind_references(monkeypatch, path, body):
    collector = masking.WithheldValues(ACTION)
    result = _inspect(monkeypatch, body, collector)
    text = json.dumps(result)
    assert [secret for secret in ALL_SECRETS if secret in text] == [], path
    entries = result["observation"]["withheld_values"]
    assert entries
    for entry in entries:
        assert masking.WITHHELD_REF_RE.fullmatch(entry["ref"])
        assert entry["marker"] in result["observation"]["text_sample"]
        assert entry["length"] == len(collector.values[int(entry["marker"][10:-1]) - 1])
        assert len(entry["preview"]) <= 4


def test_artifact_output_without_a_worker_collector_masks_plainly(monkeypatch):
    result = _inspect(monkeypatch, BACKUP_SQL)
    assert "withheld_values" not in result["observation"]
    assert "'***'" in result["observation"]["text_sample"]


def _load_mcp():
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("shakerscan_mcp_n56", root / "scripts" / "shakerscan_mcp.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_mcp_capability_tool_result_contains_no_raw_value(monkeypatch):
    from tests.test_mcp_refusal_reasons import ScriptedOpener

    mcp = _load_mcp()
    collector = masking.WithheldValues(ACTION)
    observation = _inspect(monkeypatch, BACKUP_SQL, collector)["observation"]
    hunt_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    client = mcp.ArsenalClient("http://127.0.0.1:8080", poll_seconds=0.01, action_wait_seconds=0.5)
    client.opener = ScriptedOpener({
        ("GET", f"/hunts/{hunt_id}"): {
            "hunt_id": hunt_id, "status": "active",
            "capabilities": [{"name": "artifact.inspect", "input_schema": {"type": "object"}}],
        },
        ("POST", f"/hunts/{hunt_id}/capabilities/artifact.inspect"): {
            "hunt_id": hunt_id, "capability": "artifact.inspect", "action_id": ACTION,
            "action_result": {"status": "success", "observations": [observation]},
        },
    })
    result = client.call_tool("shakerscan_hunt_capability", {
        "hunt_id": hunt_id, "capability_name": "artifact.inspect",
        "input": {"path": "/backup.sql"}, "idempotency_key": "n56-key-1",
    })
    text = json.dumps(result)
    assert [secret for secret in ALL_SECRETS if secret in text] == []
    assert f"withheld://hunt/{ACTION}/1" in text


def test_shared_redactor_keeps_markers_so_references_survive():
    from redaction import redact_text
    assert redact_text("Password=[withheld:2] token: [withheld:3]") == "Password=[withheld:2] token: [withheld:3]"
    assert redact_text("password=hunter22") == "password=***"


# --- 5. A reference round-trips into an outgoing request -----------------------------------------

class _ActionRows:
    """A unit fixture for the two hunt_actions statements the reference path uses."""

    def __init__(self):
        self.rows = {ACTION: {"status": "completed", "private_http_result": None}}

    async def fetchrow(self, sql, *args):
        assert "private_http_result" in sql and str(args[1]) == HUNT
        row = self.rows.get(str(args[0]))
        if row is None or ("status='completed'" in sql and row["status"] != "completed"):
            return None
        return row

    async def execute(self, sql, *args):
        assert "SET private_http_result=$3" in sql and str(args[1]) == HUNT
        self.rows[str(args[0])]["private_http_result"] = args[2]
        return "UPDATE 1"


RUN = {"id": HUNT, "status": "active", "completed_at": None}
POLICY = {"active_testing": True}


def _bind(reference, **destination):
    return {"method": "GET", "path": "/hub/admin",
            "request_bindings": [{"withheld_ref": reference, **destination}]}


def test_reference_round_trips_into_the_outgoing_header(monkeypatch, encryption_key):
    collector = masking.WithheldValues(ACTION)
    observation = _inspect(monkeypatch, BACKUP_SQL, collector)["observation"]
    entry = next(item for item in observation["withheld_values"] if item["preview"].startswith("ak_"))
    conn = _ActionRows()
    sealed = asyncio.run(persist_withheld_values(
        conn, run=RUN, action_id=ACTION, target=TARGET,
        values=collector.shown_values(json.dumps(observation)), status="success",
    ))
    assert sealed == len(observation["withheld_values"])
    ciphertext = conn.rows[ACTION]["private_http_result"]
    assert ciphertext.startswith("enc:fernet:") and API_KEYS[0] not in ciphertext

    inputs, headers, exchange = asyncio.run(prepare_http_exchange(
        conn, run=RUN, action_id=uuid.uuid4(), target=TARGET, context={}, policy=POLICY,
        values=_bind(entry["ref"], header="X-Admin-Token", prefix="Bearer "), trusted_headers={},
    ))
    assert headers == {"X-Admin-Token": f"Bearer {API_KEYS[0]}"}
    assert "request_bindings" not in inputs and API_KEYS[0] not in json.dumps(inputs)
    assert API_KEYS[0] in exchange.bound_values and API_KEYS[0] not in repr(exchange)


@pytest.mark.parametrize("mutate", ["other_target", "unknown_number", "unsealed"])
def test_reference_refuses_outside_its_hunt_target_or_seal(monkeypatch, encryption_key, mutate):
    from dataclasses import replace
    collector = masking.WithheldValues(ACTION)
    observation = _inspect(monkeypatch, BACKUP_SQL, collector)["observation"]
    conn = _ActionRows()
    if mutate != "unsealed":
        asyncio.run(persist_withheld_values(
            conn, run=RUN, action_id=ACTION, target=TARGET,
            values=collector.shown_values(json.dumps(observation)), status="success",
        ))
    reference = f"withheld://hunt/{ACTION}/{63 if mutate == 'unknown_number' else 1}"
    target = replace(TARGET, canonical_host="other.fixture.test") if mutate == "other_target" else TARGET
    with pytest.raises(ValueError, match="withheld value reference"):
        asyncio.run(prepare_http_exchange(
            conn, run=RUN, action_id=uuid.uuid4(), target=target, context={}, policy=POLICY,
            values=_bind(reference, header="X-Admin-Token"), trusted_headers={},
        ))


def test_reference_binding_needs_active_testing():
    from runtime.capability_registry import CAPABILITY_REGISTRY
    from runtime.hunt_http_contract import require_http_request_authority

    good = _bind(f"withheld://hunt/{ACTION}/1", header="X-Admin-Token")
    CAPABILITY_REGISTRY.validate_hunt_input("http.request", good)
    assert require_http_request_authority(good, POLICY) is False  # a read, under active testing
    with pytest.raises(ValueError, match="active_testing"):
        require_http_request_authority(good, {})


@pytest.mark.parametrize("binding", [
    {"withheld_ref": "secret://hunt/x/1", "header": "X-Admin-Token"},
    {"withheld_ref": f"withheld://hunt/{ACTION}/0", "header": "X-Admin-Token"},
    {"withheld_ref": f"withheld://hunt/{ACTION}/1", "header": "X-Admin-Token", "capture_name": "token"},
    {"withheld_ref": f"withheld://hunt/{ACTION}/1", "principal": "primary", "header": "X-Admin-Token"},
    {"withheld_ref": f"withheld://hunt/{ACTION}/1", "header": "Host"},
])
def test_invalid_reference_binding_is_refused(binding):
    from runtime.capability_registry import (
        CAPABILITY_REGISTRY,
        CapabilityInputContractError,
    )
    from runtime.hunt_http_contract import require_http_request_authority

    values = {"method": "GET", "path": "/hub/admin", "request_bindings": [binding]}
    with pytest.raises((ValueError, CapabilityInputContractError)):
        CAPABILITY_REGISTRY.validate_hunt_input("http.request", values)
        require_http_request_authority(values, POLICY)


def test_nothing_is_sealed_without_encryption_or_a_live_hunt(monkeypatch):
    conn = _ActionRows()
    monkeypatch.setattr(secret_store, "_loaded", True)
    monkeypatch.setattr(secret_store, "_fernet", None)
    assert asyncio.run(persist_withheld_values(
        conn, run=RUN, action_id=ACTION, target=TARGET, values={1: "x" * 20}, status="success",
    )) == 0
    assert asyncio.run(persist_withheld_values(
        conn, run={**RUN, "status": "completed"}, action_id=ACTION, target=TARGET,
        values={1: "x" * 20}, status="success",
    )) == 0
    assert conn.rows[ACTION]["private_http_result"] is None


# --- 6. Linear time on a 1 MB body ----------------------------------------------------------------

@pytest.mark.parametrize("unit", [
    "INSERT INTO t VALUES (1,'ak_0f3c9e1a7b2d84c60e5a9f1b3d7c2e8a4'),",
    "<tr><td>DB_PASSWORD</td><td>x</td>",
    "<add key=\"ApiKey\" value=\"v\" />",
    "INSERT INTO t VALUES ('",
    "(((((((((((((",
    "<td><td><td><th>",
    "password = ",
])
def test_masking_a_one_megabyte_hostile_body_is_linear(unit):
    small = unit * (65_536 // len(unit))
    large = unit * (1_048_576 // len(unit))
    started = time.perf_counter()
    mask_body_text(small)
    small_seconds = time.perf_counter() - started
    started = time.perf_counter()
    mask_body_text(large)
    large_seconds = time.perf_counter() - started
    # 16x the input: a linear scan takes ~16x as long; a quadratic one ~256x.
    assert large_seconds < max(0.5, small_seconds * 64), (small_seconds, large_seconds)
    assert large_seconds < 15


def test_withheld_only_workflow_response_scrubs_every_bound_value():
    from api.capabilities.http_workflow import _scrub_bound_values

    response = {"response": {"body_sample": f"welcome admin, your token {API_KEYS[0]} is valid",
                             "selected_headers": {"x-echo": f"Bearer {API_KEYS[0]}"}, "status": 200}}
    scrubbed = _scrub_bound_values(response, [API_KEYS[0]])
    assert API_KEYS[0] not in json.dumps(scrubbed)
    assert scrubbed["response"]["status"] == 200
    assert "welcome admin" in scrubbed["response"]["body_sample"]
