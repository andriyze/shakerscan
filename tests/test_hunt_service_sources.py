"""Hunt settlement evidence participates in shared knowledge without replaying traffic."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
import uuid

import pytest

from api.exposure.hunt_service_sources import (
    HUNT_SOURCES_SQL, MAX_HUNT_SOURCES, MAX_RECEIPT_BYTES,
    hunt_service_sources, validated_hunt_source,
)
from api.exposure.service_actions import canonical_registry, hunt_handoff
from api.exposure.service_inventory import build_inventory
from api.exposure.service_store import target_inventory
from api.hunt.capability_reservations import terminalize_hunt_capability
from api.runtime.budget_reservations import DurableBudgetReservation
from api.runtime.reservation_store import PostgresBudgetReservationStore

NOW = datetime(2026, 9, 23, tzinfo=timezone.utc)
TARGET_ID = "11111111-1111-4111-8111-111111111111"
HUNT_ID = "22222222-2222-4222-8222-222222222222"
ACTION_ID = "33333333-3333-4333-8333-333333333333"
RECEIPT_ID = "44444444-4444-4444-8444-444444444444"
TARGET = {"id": TARGET_ID, "kind": "web", "label": "fixture", "locator": "https://app.example.test"}
OBSERVATION = {"kind": "service", "address": "192.0.2.1", "transport": "tcp", "port": 8443,
               "state": "open", "service": "https", "product": "test-server", "version": "1.2",
               "method": "probed", "banner": "PRIVATE-BANNER"}


def fixture(*, observations=None, capability="service.fingerprint", status="completed", kind="web"):
    running = DurableBudgetReservation.request(
        owner_kind="hunt", owner_id=HUNT_ID, capability_name=capability,
        amounts={"http_requests": 10}, reservation_id="reservation-1", now=NOW,
    ).reserve(now=NOW, lease_seconds=30).start(worker_id="worker-1", now=NOW, lease_seconds=30)
    terminal, receipt = terminalize_hunt_capability(
        running, action_digest="a" * 64, capability_name=capability,
        adapter_name="nmap", adapter_version="1", target_id=TARGET_ID, target_kind=kind,
        capability_input={}, action_status=status, actual_budget={"http_requests": 2},
        worker_id="worker-1", started_at=NOW.isoformat(),
        finished_at=(NOW + timedelta(seconds=1)).isoformat(), receipt_id=RECEIPT_ID,
        result={"timed_out": status == "partial", "receipt_observations": observations if observations is not None else [OBSERVATION]},
    )
    row = {
        "id": terminal.reservation_id, "action_id": ACTION_ID, "hunt_action_id": ACTION_ID,
        "action_digest": "a" * 64, "state_digest": terminal.state_digest,
        "state_json": terminal.canonical_dict(), "receipt_json": receipt.public_dict(),
        "reservation_status": terminal.status, "capability_name": capability,
        "action_status": status, "action_receipt_id": RECEIPT_ID,
        "hunt_id": HUNT_ID, "target_id": TARGET_ID if kind != "device" else None,
        "device_target_id": TARGET_ID if kind == "device" else None, "target_kind": kind,
        "hunt_created_at": NOW, "finished_at": terminal.finished_at,
        "target_context": {"url": TARGET["locator"]} if kind != "device" else {"locator": "192.0.2.1"},
        "authorized_addresses": ["192.0.2.1"],
    }
    return row, running, terminal, receipt


def test_shared_projection_preserves_provenance_without_raw_banners_or_duplicate_records():
    row, _, _, receipt = fixture()
    source = validated_hunt_source(row, TARGET)
    first, _ = build_inventory(TARGET, [source, source], now=NOW)
    assert len(first) == 1 and len(first[0]["evidence"]) == 1
    evidence = first[0]["evidence"][0]
    assert evidence["hunt_id"] == HUNT_ID and evidence["scan_id"] is None
    assert evidence["action_id"] == ACTION_ID and evidence["sha256"] == receipt.receipt_hash
    assert evidence["vantage"] == "worker-1"
    assert first[0]["service"] == "https" and first[0]["port"] == 8443
    assert "PRIVATE-BANNER" not in json.dumps(first)


@pytest.mark.parametrize("status", ["partial", "failed", "cancelled"])
def test_partial_and_interrupted_work_keeps_positive_evidence_without_claiming_completion(status):
    row, *_ = fixture(status=status)
    service = build_inventory(TARGET, [validated_hunt_source(row, TARGET)], now=NOW)[0][0]
    assert service["presence"] == "observed_open"
    assert service["observation_status"] == status
    assert not service["findings"] and not service["cve_candidates"]


@pytest.mark.parametrize("field,value", [
    ("target_id", HUNT_ID), ("device_target_id", TARGET_ID), ("hunt_id", TARGET_ID),
    ("hunt_action_id", HUNT_ID), ("action_digest", "b" * 64), ("state_digest", "b" * 64),
    ("action_receipt_id", ACTION_ID), ("action_status", "running"),
    ("reservation_status", "running"), ("capability_name", "ports.discover"),
    ("target_kind", "device"), ("finished_at", NOW),
])
def test_mismatched_owner_action_receipt_or_settlement_never_becomes_service_knowledge(field, value):
    row, *_ = fixture()
    with pytest.raises(ValueError, match="hunt_service_source_invalid"):
        validated_hunt_source({**row, field: value}, TARGET)


def test_tampered_content_is_rejected_even_when_the_ambient_result_summary_claims_success():
    row, *_ = fixture()
    row["receipt_json"]["observations"][0]["port"] = 22
    row["result_summary"] = {"status": "success"}
    with pytest.raises(ValueError):
        validated_hunt_source(row, TARGET)


@pytest.mark.parametrize("raw", [
    {**OBSERVATION, "address": "192.0.2.99"},
    {**OBSERVATION, "web_origin": "https://other.example.test:8443"},
    {**OBSERVATION, "port": True},
])
def test_unbound_or_malformed_observation_is_a_gap_not_an_asset(raw):
    row, *_ = fixture(observations=[raw, OBSERVATION])
    source = validated_hunt_source(row, TARGET)
    assert source["rejected_observations"] == 1 and len(source["observations"]) == 1


@pytest.mark.parametrize("scheme", ["http", "https"])
def test_selected_same_host_http_services_keep_the_actual_nonstandard_origin(scheme):
    response = {"kind": "http_observation", "request": {"origin": f"{scheme}://app.example.test:8081", "pinned_address": "192.0.2.1"},
                "response": {"status": 302, "body": "PRIVATE-BODY", "location": "https://foreign.test"}}
    row, *_ = fixture(observations=[response], capability="http.request")
    service = build_inventory(TARGET, [validated_hunt_source(row, TARGET)], now=NOW)[0][0]
    assert service["application_origin"] == f"{scheme}://app.example.test:8081"
    assert service["encrypted"] == (scheme == "https")
    assert "foreign.test" not in json.dumps(service) and "PRIVATE-BODY" not in json.dumps(service)


def test_legacy_http_fingerprint_without_backend_address_remains_explicitly_unattributed():
    row, *_ = fixture(observations=[{"kind": "http_fingerprint", "url": TARGET["locator"], "status": 200}], capability="web.probe")
    service = build_inventory(TARGET, [validated_hunt_source(row, TARGET)], now=NOW)[0][0]
    assert service["address"] is None and service["application_origin"] == TARGET["locator"]


@pytest.mark.parametrize("changed", [False, True])
def test_device_locator_changes_preserve_history_and_disable_stale_handoff(changed):
    row, *_ = fixture(kind="device")
    target = {**TARGET, "kind": "device", "locator": "192.0.2.1", "locator_generation": 2,
              "locator_changed_at": NOW + timedelta(seconds=5) if changed else NOW - timedelta(seconds=5)}
    source = validated_hunt_source(row, target)
    service = build_inventory(target, [source], now=NOW)[0][0]
    assert (service["binding_status"] == "historical_locator") is changed
    assert (hunt_handoff(target, service) is None) is changed


def test_changed_web_locator_does_not_silently_rebind_old_hunt_evidence():
    row, *_ = fixture()
    target = {**TARGET, "locator": "https://replacement.example.test"}
    service = build_inventory(target, [validated_hunt_source(row, target)], now=NOW)[0][0]
    assert service["binding_status"] == "historical_locator"
    assert hunt_handoff(target, service) is None


class ReadDB:
    def __init__(self, rows):
        self.rows = rows
        self.queries = []

    async def fetch(self, query, *args):
        self.queries.append((query, args))
        if query == HUNT_SOURCES_SQL:
            assert args[:2] == ("web", uuid.UUID(TARGET_ID))
            assert args[2] == MAX_RECEIPT_BYTES and args[-1] == MAX_HUNT_SOURCES + 1
            return self.rows[:args[-1]]
        if "scan_capability_actions" in query or "FROM findings" in query:
            return []
        raise AssertionError(query)

    async def execute(self, *args):
        raise AssertionError("reading shared knowledge must not write or send target traffic")


@pytest.mark.asyncio
async def test_existing_hunt_receipt_reaches_the_shared_view_and_absence_never_means_clean():
    row, *_ = fixture()
    db = ReadDB([row])
    result = await target_inventory(db, TARGET, {"status": "unavailable"}, None, canonical_registry())
    assert len(result["services"]) == 1 and result["services"][0]["evidence"][0]["hunt_id"] == HUNT_ID
    db.rows.clear()  # deletion/retention of the owner or receipt removes it from this join
    result = await target_inventory(db, TARGET, {"status": "unavailable"}, None, canonical_registry())
    assert result["services"] == [] and not result["sources_truncated"]


@pytest.mark.asyncio
async def test_invalid_and_truncated_sources_are_explicit_without_discarding_usable_evidence():
    row, *_ = fixture()
    broken = {**deepcopy(row), "receipt_json": None}
    rows = [broken, row] + [row] * MAX_HUNT_SOURCES
    sources, warnings, truncated = await hunt_service_sources(ReadDB(rows), TARGET)
    assert truncated and warnings and sources
    assert all(source["hunt_id"] == HUNT_ID for source in sources)


@pytest.mark.asyncio
async def test_actual_reservation_store_persists_the_receipt_used_by_the_shared_projection():
    # The SQL double exercises the production persistence/rehydration path, not just an
    # invented result object. PostgreSQL join/retention acceptance runs separately.
    from tests.test_reservation_store import FakeConn, _row
    row, running, terminal, receipt = fixture()
    conn = FakeConn()
    conn.rows[running.reservation_id] = _row(running, action_id=ACTION_ID)
    store = PostgresBudgetReservationStore()
    before = await store.load(conn, running.reservation_id)
    persisted = await store.persist_terminal(conn, previous=before, terminal=terminal,
                                             ledger_after_settlement={"http_requests": 2}, receipt=receipt)
    after = await store.load(conn, persisted.record.reservation_id)
    projection = validated_hunt_source({**row, **conn.rows[after.record.reservation_id]}, TARGET)
    assert projection["sha256"] == receipt.receipt_hash
    assert projection["observations"][0]["port"] == 8443


def test_service_sql_acceptance_is_wired_into_the_provisioned_ci_database():
    from pathlib import Path
    source = (Path(__file__).resolve().parents[1] / ".github/workflows/hunt-record-integrity.yml").read_text()
    assert "HUNT_TEST_POSTGRES_DSN: postgresql://" in source
    assert "tests/test_hunt_service_sources_postgres.py" in source
    assert "SERVICE_INTELLIGENCE_TEST_DATABASE_URL:" in source
    assert "continue-on-error" not in source


def test_oversized_receipt_is_not_loaded_as_shared_knowledge():
    row, *_ = fixture()
    row["receipt_json"]["oversized"] = "x" * MAX_RECEIPT_BYTES
    with pytest.raises(ValueError, match="over_budget"):
        validated_hunt_source(row, TARGET)


def test_a_port_hint_does_not_refresh_a_previous_product_fingerprint():
    old_row, *_ = fixture()
    hint_row, *_ = fixture(observations=[{**OBSERVATION, "kind": "open_port"}], capability="ports.discover")
    old_source = validated_hunt_source(old_row, TARGET)
    new_source = validated_hunt_source(hint_row, TARGET)
    new_source.update(ref="hunt:new:hint", observed_at=(NOW + timedelta(days=8)).isoformat())
    service = build_inventory(TARGET, [old_source, new_source], now=NOW + timedelta(days=9))[0][0]
    assert service["product"] == "test-server"
    assert service["identity_stale"] is True and service["freshness"] == "recent"
