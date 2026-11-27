"""Diagnostic and log endpoints, proved by their own output grammar (``debug_interface_exposure``).

Ported from the removed ``scanner_tools/logging_checks`` (which nothing called): the logging and
monitoring endpoints it listed that the exposure probe did not read. Each is proved only by the
structure its framework emits, never by its path: a page that mentions the endpoint has none of it.
"""
from __future__ import annotations

import re
from typing import Any, Mapping

# Read besides the exposure probe's own seed list (read-only GETs of fixed paths).
DIAGNOSTIC_SEED_PATHS: tuple[str, ...] = (
    "/actuator/logfile",
    "/actuator/threaddump",
    "/actuator/loggers",
    "/debug/vars",
    "/_cat/indices",
    "/elmah.axd",
)

# A Spring Boot / Logback / Log4j line: timestamp, then a level within the line's start.
_LOG_LINE_RE = re.compile(
    r"(?m)^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,6})?(?:[+-]\d{2}:?\d{2}|Z)?[ \t]{1,4}"
    r"(?:\[[^\]\r\n]{1,64}\][ \t]{1,4})?(?:TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL)\b")
MIN_LOG_LINES = 3
# ``_cat/indices`` rows: health, state, index name, uuid, then shard counts.
_CAT_INDICES_RE = re.compile(r"(?m)^(?:green|yellow|red)[ \t]+(?:open|close)[ \t]+\S{1,255}[ \t]+[\w-]{20,24}[ \t]+\d+[ \t]+\d+")
_ELMAH_RE = re.compile(r"(?i)<title>\s*Error log for\b[^<]{0,200}</title>")
_ELMAH_MARKER_RE = re.compile(r"(?i)elmah")


def text_signature(path: str, text: str) -> tuple[str, str] | None:
    """``(exposure class, matched pattern)`` of a plain-text diagnostic body, or None."""
    head = text[:200_000]
    if len(_LOG_LINE_RE.findall(head)) >= MIN_LOG_LINES:
        return "debug_interface_exposure", "application_log_file"
    if len(_CAT_INDICES_RE.findall(head)) >= 1:
        return "debug_interface_exposure", "elasticsearch_cat_indices"
    return None


def html_signature(text: str) -> tuple[str, str] | None:
    if _ELMAH_RE.search(text) and _ELMAH_MARKER_RE.search(text[:200_000]):
        return "debug_interface_exposure", "elmah_error_log"
    return None


def json_signature(document: Any) -> tuple[str, str] | None:
    """Go expvar, Spring Boot thread dump and loggers, by the keys each always emits."""
    if not isinstance(document, Mapping):
        return None
    memstats = document.get("memstats")
    if isinstance(document.get("cmdline"), list) and isinstance(memstats, Mapping) and "HeapAlloc" in memstats:
        return "debug_interface_exposure", "go_expvar"
    threads = document.get("threads")
    if (isinstance(threads, list) and threads and isinstance(threads[0], Mapping)
            and "threadName" in threads[0] and "threadState" in threads[0]):
        return "debug_interface_exposure", "spring_actuator_threaddump"
    loggers = document.get("loggers")
    if (isinstance(document.get("levels"), list) and isinstance(loggers, Mapping)
            and isinstance(loggers.get("ROOT"), Mapping)):
        return "debug_interface_exposure", "spring_actuator_loggers"
    return None
