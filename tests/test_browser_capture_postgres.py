"""Browser capture against real PostgreSQL: create, scoped idempotent batches, live paging,
close, idle close, caps, masking, append-only batch storage, owner binding and the open-capture
refusals (TARGET_ASSET_TEST_DATABASE_URL)."""
import asyncio
import json
import uuid

import pytest
from fastapi import HTTPException

import request_collection_api
from capture import router as capture_router
from capture import store as capture_store
from capture.flows import CaptureBatch, CaptureClose, CaptureCreate, CaptureDropCounts
from scanner_tools.request_collections import RequestSelector, select_requests
from targets.asset_migration import BoundConnectionPool, migrate_target_assets
from targets.asset_inputs_migration import migrate_asset_inputs
from tests.test_target_asset_migration_postgres import database
from tests.test_target_asset_inputs_postgres import prepare, encryption

SECRETS = ("sess-cookie-value-1", "Bearer tok-abcdef123456", "hunter2-password", "qtoken-987654", "setcookie-val")


def flow(url, *, method="GET", body=None, status=200, resource="xhr"):
    return {
        "method": method, "url": url, "resource_type": resource, "status": status,
        "request_headers": [
            {"name": "Cookie", "value": f"sid={SECRETS[0]}"},
            {"name": "Authorization", "value": SECRETS[1]},
            {"name": "Content-Type", "value": "application/json"},
        ],
        "request_body": body,
        "response_headers": [{"name": "Set-Cookie", "value": f"sid={SECRETS[4]}"},
                             {"name": "Content-Type", "value": "application/json"}],
        "response_mime_type": "application/json",
        "response_body": '{"ok": true}',
    }


async def setup(conn, monkeypatch):
    await prepare(conn)
    async with conn.transaction():
        await migrate_target_assets(conn)
        await migrate_asset_inputs(conn)
    pool = BoundConnectionPool(conn)
    monkeypatch.setattr(request_collection_api, "_pool_provider", lambda: pool)
    capture_router.configure_capture_router(lambda: pool)
    return await conn.fetchval(
        "INSERT INTO targets(url,name) VALUES('https://app.example.test','Shop') RETURNING id")


async def detail(call):
    with pytest.raises(HTTPException) as caught:
        await call
    return caught.value.status_code, caught.value.detail


def run(monkeypatch, body):
    encryption(monkeypatch)

    async def go():
        async with database() as conn:
            target = await setup(conn, monkeypatch)
            await body(conn, target)
    asyncio.run(go())


def test_capture_lifecycle_scope_idempotency_paging_and_masking(monkeypatch):
    async def body(conn, target):
        created = await capture_router.create_browser_capture(CaptureCreate(target_id=str(target), name="Login walk"))
        assert created["allowed_origins"] == ["https://app.example.test"]
        assert created["limits"]["max_batch_bytes"] == 16 * 1024 * 1024
        assert created["state"] == "open" and created["capture"]["last_seq"] == 0
        capture_id = created["id"]
        assert await conn.fetchval("SELECT format FROM request_collections WHERE id=$1", uuid.UUID(capture_id)) == "capture"

        first = CaptureBatch.model_validate({"seq": 1, "flows": [
            flow(f"https://app.example.test/api/login?token={SECRETS[3]}&page=2", method="POST",
                 body=json.dumps({"username": "alice", "password": SECRETS[2]})),
            flow("https://cdn.other.test/lib.js", resource="script"),
            flow("http://app.example.test/api/plain"),  # another scheme is another origin
        ], "client_dropped": {"out_of_scope": 4, "assets": 9}})
        ack = await capture_router.append_capture_batch(capture_id, first)
        assert (ack["status"], ack["accepted"], ack["refused_out_of_scope"]) == ("applied", 1, 2)
        assert (ack["first_flow_seq"], ack["last_flow_seq"]) == (1, 1)
        assert ack["capture"]["client_dropped"] == {"out_of_scope": 4, "assets": 9}

        retry = await capture_router.append_capture_batch(capture_id, first)
        assert retry["status"] == "duplicate" and retry["accepted"] == 0
        assert await conn.fetchval("SELECT count(*) FROM request_collection_requests WHERE collection_id=$1",
                                   uuid.UUID(capture_id)) == 1
        status, gap = await detail(capture_router.append_capture_batch(
            capture_id, CaptureBatch(seq=3, flows=[])))
        assert status == 409 and gap["error"] == "capture_seq_gap" and gap["expected_seq"] == 2

        second = CaptureBatch.model_validate({"seq": 2, "flows": [
            flow(f"https://app.example.test/api/items/{n}") for n in range(3)]})
        assert (await capture_router.append_capture_batch(capture_id, second))["last_flow_seq"] == 4

        # Live paging: since_seq returns what was added after the last seq read.
        page = await request_collection_api.list_request_collection_requests(capture_id, since_seq=1, limit=2)
        assert [item["seq"] for item in page["items"]] == [2, 3] and page["has_more"] and page["last_seq"] == 3
        rest = await request_collection_api.list_request_collection_requests(
            capture_id, since_seq=1, limit=2, cursor=page["next_cursor"])
        assert [item["seq"] for item in rest["items"]] == [4] and not rest["has_more"]
        caught_up = await request_collection_api.list_request_collection_requests(capture_id, since_seq=4)
        assert caught_up["items"] == [] and caught_up["last_seq"] == 4
        assert caught_up["capture"]["state"] == "open" and caught_up["capture"]["flow_count"] == 4
        counted = await request_collection_api.list_request_collection_requests(capture_id, count="exact")
        assert counted["total"] == 4 and counted["items"][0]["name"] == "POST /api/login"
        assert "resource:xhr" in counted["items"][0]["tags"] and "status:200" in counted["items"][0]["tags"]
        assert counted["items"][0]["body_field_names"] == ["username", "password"]

        # No API view carries a recorded secret value.
        legacy = await request_collection_api.list_request_collection_requests(capture_id, limit=100, offset=0)
        library = await request_collection_api.list_request_collections(target_id=None, search="", limit=100, offset=0)
        scoped = await request_collection_api.list_request_collections(
            target_id=str(target), search="", limit=100, offset=0, source_format="capture")
        detail_view = await request_collection_api.get_request_collection(capture_id)
        views = json.dumps([ack, page, counted, legacy, library, scoped, detail_view], default=str)
        assert not [secret for secret in SECRETS if secret in views]
        assert [item["id"] for item in scoped["collections"]] == [capture_id]
        assert scoped["collections"][0]["capture"]["state"] == "open"
        assert (await request_collection_api.list_request_collections(
            target_id=str(target), search="", limit=100, offset=0, source_format="har"))["collections"] == []

        # Batches are stored append-only, one encrypted row each; the document stays empty
        # (and its digest unchanged) while the capture is open.
        batches = await conn.fetch(
            """SELECT seq, first_ordinal, entry_count, stored_bytes, encrypted_entries
               FROM request_collection_capture_batches WHERE collection_id=$1 ORDER BY seq""",
            uuid.UUID(capture_id))
        assert [(row["seq"], row["first_ordinal"], row["entry_count"]) for row in batches] == [(1, 0, 1), (2, 1, 3)]
        assert all(row["encrypted_entries"].startswith("enc:fernet:") and row["stored_bytes"] > 0 for row in batches)
        open_digest = await conn.fetchval("SELECT payload_sha256 FROM request_collections WHERE id=$1",
                                          uuid.UUID(capture_id))
        assert capture_store._decrypt(await conn.fetchval(
            "SELECT encrypted_payload FROM request_collections WHERE id=$1", uuid.UUID(capture_id),
        ))["document"]["log"]["entries"] == []

        closed = await capture_router.close_browser_capture(capture_id)
        assert closed["status"] == "closed" and closed["capture"]["closed_reason"] == "client"
        # Closing assembled the batches into the document once and cleared the per-batch copies.
        stored = await conn.fetchval("SELECT encrypted_payload FROM request_collections WHERE id=$1",
                                     uuid.UUID(capture_id))
        assert stored.startswith("enc:fernet:") and SECRETS[0] not in stored
        assert await conn.fetchval("SELECT payload_sha256 FROM request_collections WHERE id=$1",
                                   uuid.UUID(capture_id)) != open_digest
        assert await conn.fetchval(
            """SELECT count(*) FROM request_collection_capture_batches
               WHERE collection_id=$1 AND encrypted_entries IS NOT NULL""", uuid.UUID(capture_id)) == 0
        payload = capture_store._decrypt(stored)
        assert payload["format"] == "capture" and SECRETS[0] in json.dumps(payload)
        # The worker's selection resolves the same request ids as the index, and replays none of
        # the recorded cookies or tokens.
        resolved = select_requests(payload, RequestSelector(safe_methods_only=False))
        assert [item["id"] for item in resolved] == [item["request_id"] for item in legacy["requests"]]
        replayed = json.dumps([{k: v for k, v in item.items() if k != "body"} for item in resolved])
        assert SECRETS[0] not in replayed and SECRETS[1] not in replayed
        status, refused = await detail(capture_router.append_capture_batch(
            capture_id, CaptureBatch(seq=3, flows=[])))
        assert status == 409 and refused["error"] == "capture_closed"
        assert (await capture_router.append_capture_batch(capture_id, second))["status"] == "duplicate"
        assert (await capture_router.close_browser_capture(capture_id))["status"] == "already_closed"
    run(monkeypatch, body)


def test_create_by_url_and_target_resolution_refusals(monkeypatch):
    async def body(conn, target):
        created = await capture_router.create_browser_capture(
            CaptureCreate(target_url="https://APP.example.test:443/some/page"))
        assert created["target_id"] == str(target)
        status, _ = await detail(capture_router.create_browser_capture(
            CaptureCreate(target_url="https://nothing.example.test")))
        assert status == 404
        await conn.execute("UPDATE targets SET is_active=false WHERE id=$1", target)
        status, _ = await detail(capture_router.create_browser_capture(CaptureCreate(target_id=str(target))))
        assert status == 404  # an inactive target takes no new capture
        await conn.execute("UPDATE targets SET is_active=true WHERE id=$1", target)
        status, name = await detail(capture_router.create_browser_capture(
            CaptureCreate(target_id=str(target), name=created["name"])))
        assert status == 409 and name["error"] == "name_in_use"
        har = await conn.fetchval("""INSERT INTO request_collections(target_id,name,format,encrypted_payload,
            payload_sha256,metadata_json) VALUES($1,'Imported','har','enc:fernet:x',$2,'{}') RETURNING id""",
            target, "a" * 64)
        status, not_capture = await detail(capture_router.append_capture_batch(str(har), CaptureBatch(seq=1)))
        assert status == 422 and not_capture["error"] == "not_a_capture"
    run(monkeypatch, body)


def test_idle_captures_close_and_refuse_batches(monkeypatch):
    async def body(conn, target):
        idle = (await capture_router.create_browser_capture(CaptureCreate(target_id=str(target), name="idle")))["id"]
        live = (await capture_router.create_browser_capture(CaptureCreate(target_id=str(target), name="live")))["id"]
        await conn.execute("UPDATE request_collections SET updated_at=NOW()-interval '31 minutes' WHERE id=$1",
                           uuid.UUID(idle))
        assert await capture_store.close_idle_captures(BoundConnectionPool(conn)) == 1
        assert await capture_store.close_idle_captures(BoundConnectionPool(conn)) == 0
        status, refused = await detail(capture_router.append_capture_batch(idle, CaptureBatch(seq=1)))
        assert status == 409 and refused["closed_reason"] == "idle"
        # A batch past the idle bound that arrives before the sweep is refused and closes it.
        await conn.execute("UPDATE request_collections SET updated_at=NOW()-interval '31 minutes' WHERE id=$1",
                           uuid.UUID(live))
        status, refused = await detail(capture_router.append_capture_batch(live, CaptureBatch(seq=1)))
        assert status == 409 and refused["closed_reason"] == "idle"
        assert (await capture_router.close_browser_capture(live))["status"] == "already_closed"
    run(monkeypatch, body)


def test_caps_keep_metadata_after_the_document_fills_and_refuse_past_the_request_cap(monkeypatch):
    async def body(conn, target):
        capture_id = (await capture_router.create_browser_capture(CaptureCreate(target_id=str(target))))["id"]
        monkeypatch.setattr(capture_store, "MAX_DOCUMENT_BYTES", 5_000)
        monkeypatch.setattr(capture_store, "MAX_CAPTURE_FLOWS", 3)
        big = flow("https://app.example.test/page")
        big["response_body"] = "x" * 3_000
        ack = await capture_router.append_capture_batch(capture_id, CaptureBatch.model_validate(
            {"seq": 1, "flows": [big, big, big, big]}))
        assert (ack["accepted"], ack["bodies_dropped"], ack["refused_over_limit"]) == (3, 2, 1)
        assert ack["capture"]["limit_reached"] is True and ack["capture"]["bodies_dropped"] == 2
        closed = await capture_router.close_browser_capture(capture_id, CaptureClose(client_dropped=CaptureDropCounts(assets=2)))
        assert closed["capture"]["bodies_dropped"] == 2 and closed["capture"]["client_dropped"]["assets"] == 2
        entries = capture_store._decrypt(await conn.fetchval(
            "SELECT encrypted_payload FROM request_collections WHERE id=$1", uuid.UUID(capture_id)))["document"]["log"]["entries"]
        assert "text" in entries[0]["response"]["content"]
        assert entries[1]["_bodiesDropped"] and "text" not in entries[1]["response"]["content"]
        headers = {header["name"]: header["value"] for header in entries[1]["request"]["headers"]}
        assert headers["Cookie"] == "***" and headers["Authorization"] == "***"
    run(monkeypatch, body)



async def _binding(conn, capture_id):
    return str(await conn.fetchval(
        "SELECT id FROM request_collection_bindings WHERE collection_id=$1", uuid.UUID(capture_id)))


def test_an_open_capture_cannot_be_selected_until_it_is_closed(monkeypatch):
    async def body(conn, target):
        capture_id = (await capture_router.create_browser_capture(CaptureCreate(target_id=str(target))))["id"]
        await capture_router.append_capture_batch(capture_id, CaptureBatch.model_validate(
            {"seq": 1, "flows": [flow("https://app.example.test/api/items")]}))
        selection = request_collection_api.RequestCollectionSelectionUpsert(
            binding_id=await _binding(conn, capture_id), name="items", replay_policy="safe_reads")
        status, refused = await detail(request_collection_api.upsert_request_collection_selection(capture_id, selection))
        assert status == 409 and refused["error"] == "capture_open" and "close it first" in refused["message"]
        await capture_router.close_browser_capture(capture_id)
        made = await request_collection_api.upsert_request_collection_selection(capture_id, selection)
        assert made["selection"]["selected_request_count"] == 1
        selection_row = await conn.fetchrow(
            "SELECT is_active, revoked_at FROM request_collection_selections WHERE id=$1",
            uuid.UUID(made["selection"]["id"]))
        assert selection_row["is_active"] and selection_row["revoked_at"] is None
    run(monkeypatch, body)


def test_a_same_seq_with_other_flows_is_refused(monkeypatch):
    async def body(conn, target):
        capture_id = (await capture_router.create_browser_capture(CaptureCreate(target_id=str(target))))["id"]
        sent = {"seq": 1, "flows": [flow("https://app.example.test/a")], "client_dropped": {"assets": 1}}
        await capture_router.append_capture_batch(capture_id, CaptureBatch.model_validate(sent))
        # The same flows with newer drop counts are a retry.
        retry = await capture_router.append_capture_batch(
            capture_id, CaptureBatch.model_validate({**sent, "client_dropped": {"assets": 5}}))
        assert retry["status"] == "duplicate"
        status, conflict = await detail(capture_router.append_capture_batch(
            capture_id, CaptureBatch.model_validate({"seq": 1, "flows": [flow("https://app.example.test/b")]})))
        assert status == 409 and conflict["error"] == "capture_seq_conflict"
    run(monkeypatch, body)


def test_only_the_operator_who_opened_a_capture_adds_to_it(monkeypatch):
    async def body(conn, target):
        identity = {"value": "alice@example.test"}
        monkeypatch.setattr(capture_router, "operator_identity", lambda _request: identity["value"])
        capture_id = (await capture_router.create_browser_capture(
            CaptureCreate(target_id=str(target)), http_request=object()))["id"]
        batch = CaptureBatch.model_validate({"seq": 1, "flows": [flow("https://app.example.test/a")]})
        identity["value"] = "mallory@example.test"
        status, refused = await detail(capture_router.append_capture_batch(capture_id, batch, http_request=object()))
        assert status == 403 and refused["error"] == "capture_owner_mismatch"
        identity["value"] = None  # a request with no gateway identity is local-operator
        status, _ = await detail(capture_router.close_browser_capture(capture_id, http_request=object()))
        assert status == 403
        identity["value"] = "alice@example.test"
        assert (await capture_router.append_capture_batch(capture_id, batch, http_request=object()))["status"] == "applied"
        assert (await capture_router.close_browser_capture(capture_id, http_request=object()))["status"] == "closed"
        # Without a gateway (open-source engine) every request is local-operator.
        local = (await capture_router.create_browser_capture(CaptureCreate(target_id=str(target), name="local")))["id"]
        assert (await capture_router.append_capture_batch(local, batch))["status"] == "applied"
    run(monkeypatch, body)


def test_an_import_never_overwrites_a_capture_of_the_same_name(monkeypatch):
    async def body(conn, target):
        capture_id = (await capture_router.create_browser_capture(
            CaptureCreate(target_id=str(target), name="Walk")))["id"]
        har = {"log": {"version": "1.2", "entries": [
            {"request": {"method": "GET", "url": "https://app.example.test/x", "headers": []}}]}}
        status, refused = await detail(request_collection_api.create_request_collection(
            request_collection_api.RequestCollectionCreate(target_id=str(target), name="Walk", document=har)))
        assert status == 409 and refused["error"] == "name_in_use"
        row = await conn.fetchrow("SELECT format, metadata_json FROM request_collections WHERE id=$1",
                                  uuid.UUID(capture_id))
        assert row["format"] == "capture" and json.loads(row["metadata_json"])["capture"]["state"] == "open"
    run(monkeypatch, body)


def test_target_url_lookup_treats_like_wildcards_literally(monkeypatch):
    async def body(conn, target):
        await conn.execute("UPDATE targets SET url='https://app_1.example.test' WHERE id=$1", target)
        await conn.execute("INSERT INTO targets(url,name) VALUES('https://appx1.example.test','Other')")
        created = await capture_router.create_browser_capture(CaptureCreate(target_url="https://app_1.example.test/"))
        assert created["target_id"] == str(target)
        status, _ = await detail(capture_router.create_browser_capture(CaptureCreate(target_url="https://app%1.example.test/")))
        assert status in {404, 422}
        monkeypatch.setattr(capture_store, "_TARGET_MATCH_LIMIT", 1)
        await conn.execute("INSERT INTO targets(url,name) VALUES('https://app_1.example.test.other.test','Twin')")
        status, cut = await detail(capture_router.create_browser_capture(CaptureCreate(target_url="https://app_1.example.test/")))
        assert status == 409 and cut["error"] == "ambiguous_target" and "by id" in cut["message"]
    run(monkeypatch, body)


def test_scan_and_hunt_admission_refuses_an_open_capture(monkeypatch):
    api_module = pytest.importorskip("api.api")

    async def body(conn, target):
        capture_id = (await capture_router.create_browser_capture(CaptureCreate(target_id=str(target))))["id"]
        await capture_router.append_capture_batch(capture_id, CaptureBatch.model_validate(
            {"seq": 1, "flows": [flow("https://app.example.test/api/items")]}))
        status, refused = await detail(api_module._generic_collection_refs(
            conn, target_id=target, target_kind="web", bindings=[{"collection_id": capture_id}]))
        assert status == 409 and refused["error"] == "capture_open"
        await capture_router.close_browser_capture(capture_id)
        refs, _endpoints, _manifest = await api_module._generic_collection_refs(
            conn, target_id=target, target_kind="web", bindings=[{"collection_id": capture_id}])
        assert [ref["collection_id"] for ref in refs] == [capture_id]
    run(monkeypatch, body)
