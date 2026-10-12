"""The canonical membership of a retracted entry's history, shared with decision receipts."""
from __future__ import annotations

import json
from typing import Any

KNOWLEDGE_IMPORT_WRITER = "system:knowledge-import"


async def retraction_members(conn: Any, target: Any, entry: Any, *, limit: int | None = None):
    subject = entry['subject']
    if isinstance(subject, str):
        subject = json.loads(subject)
    author = (subject or {}).get('written_by') if entry['written_by'] == KNOWLEDGE_IMPORT_WRITER else None
    if author and str(author).startswith('hunt:'):
        # Every knowledge version by this Hunt, including versions separated by another author.
        return await conn.fetch("""SELECT * FROM target_interpretations
            WHERE target_id=$1 AND written_by=$2 AND subject->>'written_by'=$3
            ORDER BY id LIMIT $4 FOR UPDATE""", target, entry['written_by'], author, limit)
    return await conn.fetch("""WITH RECURSIVE chain(id) AS (
            SELECT $1::uuid
            UNION
            SELECT i.id FROM target_interpretations i JOIN chain c ON i.supersedes=c.id OR i.id=(
                SELECT supersedes FROM target_interpretations WHERE id=c.id)
            WHERE i.target_id=$2 AND i.written_by=$3
              AND ($4::text IS NULL OR i.subject->>'written_by'=$4))
        SELECT i.* FROM target_interpretations i JOIN chain c ON i.id=c.id
        ORDER BY i.id LIMIT $5 FOR UPDATE OF i""",
        entry['id'], target, entry['written_by'], author, limit)
