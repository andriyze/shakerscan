"""Archived payloads read back as they were sent, wherever the evidence store put them.

A payload above the inline ceiling is written to a file or S3 object and its row keeps only a
storage URI. The reader used to select the inline column alone, so a large body read back as
absent while the export still called the archive complete. The batch writer also stored a bytes
body as its Python repr. These tests run the real writer and reader against an in-memory stand-in
for the two tables, whose result columns are taken from the reader's own SELECT.
"""

import hashlib
import json
import re
import sys
import uuid

import pytest

from api.runtime.http_archive import HttpTransaction, archive_recorded_calls
from api.runtime.http_archive_reader import export_document, read_transactions

HUNT = "22222222-2222-4222-8222-222222222222"
TARGET = "33333333-3333-4333-8333-333333333333"
# Larger than the 32 KiB inline ceiling, so the store writes it to a file.
LARGE_BODY = ('{"orders": [' + ",".join(f'{{"id": {n}, "note": "café résumé"}}' for n in range(1100)) + "]}")
assert 40 * 1024 <= len(LARGE_BODY.encode()) < 64 * 1024
LARGE_HEADER = "x" * (40 * 1024)


def _blobs():
    """The sealing module as the archive resolves it at call time (flat or package layout)."""
    try:
        from runtime import archive_blob_secrets
    except ModuleNotFoundError:  # package import layout
        from api.runtime import archive_blob_secrets
    return archive_blob_secrets


def _use_key(monkeypatch, key: str) -> None:
    """Every loaded copy of the key cache must forget its key: which layout the archive
    imports depends on what other test modules put on sys.path."""
    monkeypatch.setenv("AI_CREDENTIAL_ENC_KEY", key)
    for name in ("secret_store", "api.secret_store"):
        module = sys.modules.get(name)
        if module is not None:
            monkeypatch.setattr(module, "_fernet", None)
            monkeypatch.setattr(module, "_loaded", False)


@pytest.fixture(autouse=True)
def archive_key(monkeypatch):
    from cryptography.fernet import Fernet
    monkeypatch.setenv("SHAKERSCAN_HTTP_ARCHIVE", "full")
    monkeypatch.delenv("EVIDENCE_INLINE_MAX_BYTES", raising=False)
    monkeypatch.delenv("EVIDENCE_STORAGE_BACKEND", raising=False)
    _blobs()
    _use_key(monkeypatch, Fernet.generate_key().decode())


class ArchiveDB:
    """The archive's own statements against two in-memory tables.

    Rows returned for the transaction query carry exactly the columns that query selects:
    each ``alias.column [AS name]`` is resolved against the transaction or the evidence object
    its LEFT JOIN names, with JSONB columns returned as text, as asyncpg returns them.
    """

    def __init__(self):
        self.objects: dict[str, dict] = {}
        self.transactions: list[dict] = []
        self.stats: dict[str, int] = {}

    async def fetch(self, query, *params):
        if "SELECT DISTINCT ON (scan_id, content_sha256)" in query:
            digests, owners = params
            return [
                {"id": object_id, "scan_id": item["scan_id"], "content_sha256": item["content_sha256"]}
                for object_id, item in self.objects.items()
                if item["content_sha256"] in digests and (item["scan_id"] in owners or item["scan_id"] is None)
            ]
        if "FROM http_transactions t" in query:
            return [self._select(query, tx) for tx in self.transactions
                    if tx["hunt_run_id"] == params[0] or tx["scan_id"] == params[0]]
        raise AssertionError(query)

    def _select(self, query, tx):
        joins = dict(re.findall(r"LEFT JOIN evidence_objects (\w+) ON \1\.id = t\.(\w+)", query))
        select_list = query.split("SELECT", 1)[1].split("FROM http_transactions", 1)[0]
        row = {}
        for table, column, alias in re.findall(r"(\w+)\.(\w+)(?:\s+AS\s+(\w+))?", select_list):
            source = tx if table == "t" else self.objects.get(tx.get(joins[table])) or {}
            value = source.get(column)
            if column in {"content", "metadata_json"} and value is not None:
                value = json.dumps(value)
            row[alias or column] = value
        return row

    async def execute(self, query, *params):
        if "INSERT INTO evidence_objects" in query:
            for item in json.loads(params[0]):
                self.objects[item["id"]] = item
        elif "INSERT INTO http_transactions" in query:
            self.transactions.extend(json.loads(params[0]))
        elif "INSERT INTO http_archive_stats" in query:
            for key, value in zip(("attempted", "stored", "failed", "dropped"), params[2:]):
                self.stats[key] = self.stats.get(key, 0) + int(value)
        else:
            raise AssertionError(query)


def _call(body: bytes, **overrides) -> HttpTransaction:
    values = dict(
        plane="hunt", hunt_run_id=HUNT, hunt_action_id=str(uuid.uuid4()), target_id=TARGET,
        capability_name="http.request", adapter="bound_http", method="GET",
        url="https://h.test/api/orders", status_code=200,
        request_headers={"accept": "application/json", "x-trace": LARGE_HEADER},
        response_headers={"content-type": "application/json"}, response_body=body,
        metadata={"fidelity": "wire_request"},
    )
    values.update(overrides)
    return HttpTransaction(**values)


async def _archive(db, tmp_path, *calls):
    await archive_recorded_calls(db, list(calls), results_dir=tmp_path, label="hunt test",
                                 owner_kind="hunt", owner_id=HUNT)


def _body(row, field="response_body"):
    return json.loads(row[field]) if isinstance(row[field], str) else row[field]


def _external_files(tmp_path):
    return sorted((tmp_path / "evidence-objects").rglob("*.json"))


@pytest.mark.asyncio
async def test_externally_stored_body_and_headers_round_trip_through_every_export(tmp_path):
    db = ArchiveDB()
    await _archive(db, tmp_path, _call(LARGE_BODY.encode()))

    external = [item for item in db.objects.values() if item["storage_uri"].startswith("local:")]
    assert len(external) == 2, "the 40 KiB body and the 40 KiB header map are both externalized"
    assert all(item["content"] is None for item in external)
    files = _external_files(tmp_path)
    assert len(files) == 2 and not any("orders" in f.read_text() or "xxxx" in f.read_text() for f in files), (
        "externalized payloads stay sealed at rest"
    )

    rows = await read_transactions(db, hunt_run_id=HUNT, results_dir=tmp_path)
    assert len(rows) == 1 and "payload_unavailable" not in rows[0]
    assert _body(rows[0]) == LARGE_BODY
    assert json.loads(rows[0]["request_headers"])["x-trace"] == LARGE_HEADER
    assert not any(key.endswith(("_storage_uri", "_content_sha256", "_size_bytes")) for key in rows[0])

    stats = dict(db.stats)
    assert stats == {"attempted": 1, "stored": 1, "failed": 0, "dropped": 0}
    document = export_document(rows, export_format="transactions", redaction="raw",
                               owner={"hunt_id": HUNT}, total=1, stats=stats)
    assert document["fidelity"] == "complete"
    assert document["transactions"][0]["response"]["body"] == LARGE_BODY
    assert document["transactions"][0]["request"]["headers"]["x-trace"] == LARGE_HEADER

    har = export_document(rows, export_format="har", redaction="raw",
                          owner={"hunt_id": HUNT}, total=1, stats=stats)
    entry = har["log"]["entries"][0]
    assert entry["response"]["content"]["text"] == LARGE_BODY
    assert {"name": "x-trace", "value": LARGE_HEADER} in entry["request"]["headers"]
    assert json.loads(har["log"]["comment"])["fidelity"] == "complete"

    masked = export_document(rows, export_format="transactions", redaction="redacted",
                             owner={"hunt_id": HUNT}, total=1, stats=stats)
    assert masked["transactions"][0]["response"]["body"] == LARGE_BODY


@pytest.mark.asyncio
async def test_a_missing_external_object_is_unavailable_and_the_export_partial(tmp_path):
    db = ArchiveDB()
    await _archive(db, tmp_path, _call(LARGE_BODY.encode()))
    body_object = next(item for item in db.objects.values()
                       if item["storage_uri"].startswith("local:") and item["size_bytes"] > len(LARGE_HEADER) + 100)
    (tmp_path / "evidence-objects" / body_object["storage_uri"].split("evidence_objects/", 1)[1]).unlink()

    rows = await read_transactions(db, hunt_run_id=HUNT, results_dir=tmp_path)
    assert rows[0]["payload_unavailable"] == ["response_body"]
    assert rows[0]["response_body"] is None
    assert json.loads(rows[0]["request_headers"])["x-trace"] == LARGE_HEADER
    for export_format in ("transactions", "har"):
        document = export_document(rows, export_format=export_format, redaction="raw",
                                   owner={"hunt_id": HUNT}, total=1, stats=dict(db.stats))
        envelope = json.loads(document["log"]["comment"]) if export_format == "har" else document
        assert envelope["fidelity"] == "partial"
        assert "can no longer be read" in envelope["fidelity_detail"]


@pytest.mark.asyncio
async def test_an_external_object_sealed_with_another_key_is_unavailable(tmp_path, monkeypatch):
    from cryptography.fernet import Fernet
    db = ArchiveDB()
    await _archive(db, tmp_path, _call(LARGE_BODY.encode()))
    _use_key(monkeypatch, Fernet.generate_key().decode())
    rows = await read_transactions(db, hunt_run_id=HUNT, results_dir=tmp_path)
    assert set(rows[0]["payload_unavailable"]) == {"request_headers", "response_body", "response_headers"}


@pytest.mark.asyncio
async def test_an_external_uri_outside_the_store_is_not_followed(tmp_path):
    db = ArchiveDB()
    await _archive(db, tmp_path, _call(LARGE_BODY.encode()))
    outside = tmp_path / "secret.json"
    outside.write_text(json.dumps(_blobs().envelope(json.dumps("not archive data"))))
    for item in db.objects.values():
        if item["storage_uri"].startswith("local:"):
            item["storage_uri"] = "local:evidence_objects/../../secret.json"
    rows = await read_transactions(db, hunt_run_id=HUNT, results_dir=tmp_path)
    assert set(rows[0]["payload_unavailable"]) == {"request_headers", "response_body"}
    assert "not archive data" not in json.dumps(rows, default=str)


@pytest.mark.asyncio
async def test_external_payload_reads_are_bounded_and_the_omission_is_stated(tmp_path):
    db = ArchiveDB()
    await _archive(db, tmp_path, _call(LARGE_BODY.encode(), request_headers={"accept": "*/*"}),
                   _call(LARGE_BODY.replace("orders", "refunds").encode(), request_headers={"accept": "*/*"},
                         url="https://h.test/api/refunds", sequence=1))
    first_body = db.objects[db.transactions[0]["response_body_object_id"]]
    assert first_body["storage_uri"].startswith("local:")
    # Room for one of the two externalized bodies, not both.
    rows = await read_transactions(db, hunt_run_id=HUNT, results_dir=tmp_path,
                                   external_payload_budget=first_body["size_bytes"] + 64)
    assert _body(rows[0]) == LARGE_BODY and "payload_omitted" not in rows[0]
    assert rows[1]["response_body"] is None and rows[1]["payload_omitted"] == ["response_body"]
    document = export_document(rows, export_format="transactions", redaction="raw",
                               owner={"hunt_id": HUNT}, total=2, stats=dict(db.stats))
    assert document["fidelity"] == "partial" and "omitted from this export" in document["fidelity_detail"]
    assert document["transactions"][1]["payload_omitted"] == ["response_body"]


def _stored_plaintext(db, tmp_path, item):
    if item["content"] is not None:
        return _blobs().reveal(json.dumps(item["content"]))
    path = tmp_path / "evidence-objects" / item["storage_uri"].split("evidence_objects/", 1)[1]
    return _blobs().reveal(path.read_text())


@pytest.mark.asyncio
@pytest.mark.parametrize("body", [b'{"a":1}\xff', LARGE_BODY.encode() + b"\xff"], ids=["inline", "external"])
async def test_the_batch_writer_stores_a_bytes_body_as_its_text_not_its_repr(tmp_path, body):
    db = ArchiveDB()
    await _archive(db, tmp_path, _call(body, request_headers=None, response_headers=None))
    [item] = db.objects.values()
    plaintext = _stored_plaintext(db, tmp_path, item)
    text = body.decode("utf-8", errors="replace")
    assert json.loads(plaintext) == text, "stored as the body's text, not \"b'...'\""
    # The object is named by the digest of what it holds, as the single-blob writer names it.
    assert item["content_sha256"] == hashlib.sha256(plaintext.encode()).hexdigest()
    assert item["content_sha256"] == _blobs().plaintext_digest(text)
    rows = await read_transactions(db, hunt_run_id=HUNT, results_dir=tmp_path)
    assert _body(rows[0]) == text


@pytest.mark.asyncio
async def test_identical_bytes_bodies_still_share_one_object(tmp_path):
    db = ArchiveDB()
    await _archive(db, tmp_path, _call(b"same", request_headers=None, response_headers=None),
                   _call(b"same", request_headers=None, response_headers=None, sequence=1))
    assert len(db.objects) == 1
    assert len({tx["response_body_object_id"] for tx in db.transactions}) == 1


def _legacy_row(db, stored_text, *, body_sha256, external_dir=None):
    """An archive row written the way the batch writer wrote bytes before it decoded them."""
    raw, digest, size = _blobs()._evidence.serialize_evidence_content(stored_text)
    object_id = str(uuid.uuid4())
    sealed = _blobs().envelope(raw)
    item = {"id": object_id, "scan_id": None, "content_sha256": digest, "size_bytes": size,
            "storage_uri": "inline:evidence_objects", "content": sealed}
    if external_dir is not None:
        path = external_dir / "evidence-objects" / "ab" / f"{object_id}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(sealed))
        item.update(content=None, storage_uri=f"local:evidence_objects/ab/{object_id}.json")
    db.objects[object_id] = item
    db.transactions.append({
        "hunt_run_id": HUNT, "scan_id": None, "id": str(uuid.uuid4()), "plane": "hunt",
        "method": "GET", "url": "https://h.test/legacy", "status_code": 200,
        "response_body_object_id": object_id, "response_body_sha256": body_sha256,
        "response_body_bytes": 0, "metadata_json": {},
    })


@pytest.mark.asyncio
@pytest.mark.parametrize("external", [False, True], ids=["inline", "external"])
async def test_a_body_archived_as_its_bytes_repr_reads_back_as_the_body(tmp_path, external):
    body = b'{"a":1}\xff it\'s "quoted"\n'
    db = ArchiveDB()
    _legacy_row(db, repr(body), body_sha256=hashlib.sha256(body).hexdigest(),
                external_dir=tmp_path if external else None)
    rows = await read_transactions(db, hunt_run_id=HUNT, results_dir=tmp_path)
    assert "payload_unavailable" not in rows[0]
    assert _body(rows[0]) == body.decode("utf-8", errors="replace")


@pytest.mark.asyncio
@pytest.mark.parametrize("text", [
    "b'abc' trailing text",
    "not b'abc'",
    "b'unterminated",
    "b'{0}'.format(1)",
    "b'a' + b'b'",
    '{"value": "b\'abc\'"}',
])
async def test_text_that_is_not_exactly_one_bytes_literal_is_left_alone(tmp_path, text):
    db = ArchiveDB()
    _legacy_row(db, text, body_sha256=None)
    rows = await read_transactions(db, hunt_run_id=HUNT, results_dir=tmp_path)
    assert _body(rows[0]) == text


@pytest.mark.asyncio
async def test_a_body_that_really_is_a_bytes_literal_is_kept_when_its_digest_says_so(tmp_path):
    text = "b'hello'"
    db = ArchiveDB()
    _legacy_row(db, text, body_sha256=hashlib.sha256(text.encode()).hexdigest())
    rows = await read_transactions(db, hunt_run_id=HUNT, results_dir=tmp_path)
    assert _body(rows[0]) == text
