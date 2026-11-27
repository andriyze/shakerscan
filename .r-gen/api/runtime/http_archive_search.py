"""What an archive search may match: the masked origin and path of each call.

The stored URL is the raw request line a replay needs, so it can hold a value the masked archive
withholds (a userinfo password, a token in the query, a JWT or provider key in the path). Matching
a search against it would let a reader of the masked archive confirm a guessed value one
character at a time. Each call therefore also stores ``search_url``: its URL masked by the rule
the masked export uses, without userinfo, query or fragment. Calls archived before the column
existed have none and match on capability, adapter and method only.
"""

from __future__ import annotations

import urllib.parse
from typing import Any

from .archive_body_masking import withhold_url_userinfo

try:
    from redaction import redact_sensitive
except ModuleNotFoundError:  # package import layout
    from scanner.redaction import redact_sensitive

MAX_SEARCH_URL_CHARS = 2_000

# Always-run startup DDL (targets.asset_migration.run_unified_startup): a catalog check, so a
# restart takes no table lock.
SEARCH_URL_SCHEMA_SQL = """
DO $search_url$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_attribute
        WHERE attrelid='http_transactions'::regclass AND attname='search_url' AND NOT attisdropped
    ) THEN
        ALTER TABLE http_transactions ADD COLUMN search_url TEXT;
    END IF;
END
$search_url$
"""

# Whether the column exists yet: archive writers name it only once it does (http_archive).
SEARCH_URL_PRESENT_SQL = """
SELECT EXISTS (
    SELECT 1 FROM pg_attribute
    WHERE attrelid='http_transactions'::regclass AND attname='search_url' AND NOT attisdropped
)
"""


def searchable_url(url: Any) -> str | None:
    """``scheme://host[:port]/path`` of ``url`` as the masked archive shows it."""
    if not url:
        return None
    # Mask the whole URL first: a password may hold a raw ``?`` or ``#`` that would otherwise
    # end the authority early and leave part of it in the path.
    masked = redact_sensitive(withhold_url_userinfo(str(url)), redact_strings=True, scrub_text=True)
    try:
        parts = urllib.parse.urlsplit(masked)
    except ValueError:
        return None
    host = parts.netloc.rpartition("@")[2]
    origin = f"{parts.scheme}://{host}" if parts.scheme and host else host
    return (origin + parts.path)[:MAX_SEARCH_URL_CHARS] or None


def search_pattern(value: str) -> str:
    """Literal ILIKE pattern; `%`, `_`, and backslash are ordinary search text."""
    escaped = (
        str(value).strip().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    )
    return f"%{escaped}%"


def search_clause(params: list[Any], search: str, *, alias: str = "") -> str:
    """The search predicate over one call's capability, adapter, method and masked path."""
    params.append(search_pattern(search))
    placeholder = f"${len(params)}"
    columns = (
        f"COALESCE({alias}capability_name,'')", f"COALESCE({alias}adapter,'')",
        f"{alias}method", f"COALESCE({alias}search_url,'')",
    )
    return "(" + " OR ".join(f"{column} ILIKE {placeholder} ESCAPE '\\'" for column in columns) + ")"
