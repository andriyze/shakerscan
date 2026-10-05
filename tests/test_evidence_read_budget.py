"""Read caps apply before local/S3 allocation, including ciphertext overhead."""
from io import BytesIO
from http.client import IncompleteRead
from pathlib import Path

import pytest

from api import evidence_storage as store


class Response(BytesIO):
    def __init__(self, body, *, length=True):
        super().__init__(body)
        self.headers = {"Content-Length": str(len(body))} if length else {}
        self.read_sizes = []

    def read(self, size=-1):
        self.read_sizes.append(size)
        assert size >= 0, "bounded S3 reads never ask for an unbounded body"
        return super().read(size)

    def close(self):
        pass


@pytest.mark.parametrize("declared_length", [True, False])
def test_s3_large_object_never_reads_over_remaining_budget(monkeypatch, declared_length):
    response = Response(b"a" * 100, length=declared_length)
    monkeypatch.setattr(store.urllib.request, "urlopen", lambda *args, **kwargs: response)
    cfg = {"endpoint": "http://store.test", "region": "us-east-1", "access_key": "x",
           "secret_key": "y", "session_token": "", "timeout": 2, "path_style": True}
    monkeypatch.setattr(store, "_s3_config", lambda: cfg)
    row = store.hydrate_evidence_content({"storage_uri": "s3:evidence_objects/bucket/evidence-objects/ab/payload.json"},
                                         results_dir=Path("/unused"), max_stored_bytes=40)
    assert row["storage_status"] == "budget_exceeded"
    assert row["content"] is None
    assert response.tell() <= 40
    assert row["storage_bytes_read"] == response.tell()


def test_local_object_size_is_checked_before_opened_stream_is_read(tmp_path, monkeypatch):
    path = tmp_path / "evidence-objects" / "ab" / "payload.json"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"x" * 100)
    original = store._read_stored_bytes
    def check(stream, **kwargs):
        assert stream.tell() == 0
        return original(stream, **kwargs)
    monkeypatch.setattr(store, "_read_stored_bytes", check)
    row = store.hydrate_evidence_content({"storage_uri": "local:evidence_objects/ab/payload.json"},
                                         results_dir=tmp_path, max_stored_bytes=40)
    assert row["storage_status"] == "budget_exceeded" and row["storage_bytes_read"] == 0


@pytest.mark.parametrize("error,spent", [(IncompleteRead(b"x" * 20, 20), 20), (OSError("interrupted"), 40)])
def test_interrupted_reads_still_debit_received_or_reserved_bytes(error, spent):
    class Interrupted:
        def read(self, size):
            assert size == 40
            raise error
    with pytest.raises(store.EvidenceReadFailed) as caught:
        store._read_stored_bytes(Interrupted(), maximum=40)
    assert caught.value.bytes_read == spent
