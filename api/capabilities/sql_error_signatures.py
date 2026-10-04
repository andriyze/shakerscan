"""One database-error signature set for every SQL injection detector.

The request verifier decides which candidates may escalate to repeated proof and
the proof adapter decides which of them are verified. They kept separate copies
of these patterns and the copies drifted: the verifier never learned that SQLite
reports ``SQLITE_ERROR``, so its ``not_proven`` withheld a reproducible
error-based injection before proof could see it. Both import this tuple instead.
"""

from __future__ import annotations

import re


SQL_ERROR_PATTERNS = tuple(re.compile(pattern, re.IGNORECASE) for pattern in (
    r"you have an error in your sql syntax",
    r"warning.{0,40}mysql",
    r"unclosed quotation mark after the character string",
    r"postgresql.{0,40}(?:error|exception)",
    r"pg_query\(\)",
    # SQLITE_ERROR, SQLiteException, sqlite3_exception, "sqlite error": the
    # separator is optional, which a single shared copy keeps true everywhere.
    r"sqlite(?:3)?[ _-]?(?:error|exception)",
    r"sqlite3\.(?:operational|programming|database|integrity)error",
    # SQLite's tokenizer and parser messages. Both are anchored to SQLite's
    # exact wording -- a double-quoted token (raw, JSON-escaped or HTML-escaped)
    # and the parser's own phrase -- so prose that merely says "syntax error" or
    # "unrecognized" does not match. The token itself may be a quote: near "'".
    r"unrecognized token: (?:\\?\"|&quot;)",
    r"near (?:\\?\"|&quot;)[^\r\n]{0,80}?(?:\\?\"|&quot;): syntax error",
    r"ora-\d{4,5}",
    r"sqlstate\[[0-9a-z]+\]",
    r"syntax error.{0,80}(?:sql|query|database)",
))


def sql_error_signatures(body: bytes) -> tuple[str, ...]:
    """Return the patterns a response body matches, in declaration order."""
    text = body[:2_000_000].decode("utf-8", errors="replace")
    return tuple(
        pattern.pattern for pattern in SQL_ERROR_PATTERNS if pattern.search(text)
    )


__all__ = ["SQL_ERROR_PATTERNS", "sql_error_signatures"]
