"""Values from targets and operators written into log lines.

A target URL, a validation warning or a server banner can carry CR/LF; written verbatim into a
log line it starts a forged entry. log_text() keeps the value on one line and bounds it.
"""

from __future__ import annotations

from typing import Any

LOG_TEXT_LIMIT = 500


def log_text(value: Any, limit: int = LOG_TEXT_LIMIT) -> str:
    text = str(value).replace("\r", "\\r").replace("\n", "\\n")
    return text if len(text) <= limit else text[:limit] + "..."
