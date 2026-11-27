"""Browser-capture batch storage (2.11).

Each applied batch of a capture is one row: its ``seq``, the digest of what the recorder sent (so a
retry with the same ``seq`` and different flows is refused), and the batch's HAR entries
encrypted on their own. A batch never rewrites the entries before it; closing the capture
assembles the batches into the collection's encrypted document once, and clears the per-batch
copies (the digest rows stay, for the retry check).

The startup runs this under advisory lock 8675309 on every start, so it is catalog-guarded: on an
up-to-date database it takes no lock on any table. ``db/init.sql`` declares the same table.
"""

from __future__ import annotations


CAPTURE_BATCHES_SCHEMA_SQL = r"""
DO $capture_batches$
BEGIN
    IF to_regclass('request_collection_capture_batches') IS NULL THEN
        CREATE TABLE request_collection_capture_batches (
            collection_id UUID NOT NULL REFERENCES request_collections(id) ON DELETE CASCADE,
            seq INTEGER NOT NULL CHECK (seq >= 1),
            batch_sha256 TEXT NOT NULL CHECK (batch_sha256 ~ '^[0-9a-f]{64}$'),
            first_ordinal INTEGER NOT NULL CHECK (first_ordinal >= 0),
            entry_count INTEGER NOT NULL DEFAULT 0 CHECK (entry_count >= 0),
            stored_bytes BIGINT NOT NULL DEFAULT 0 CHECK (stored_bytes >= 0),
            encrypted_entries TEXT
                CHECK (encrypted_entries IS NULL OR encrypted_entries LIKE 'enc:fernet:%'),
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            PRIMARY KEY (collection_id, seq)
        );
    END IF;
END
$capture_batches$;
"""


__all__ = ["CAPTURE_BATCHES_SCHEMA_SQL"]
