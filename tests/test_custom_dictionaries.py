"""Tests for first-class custom wordlists and file/inline-driven payloads.

These are additive extension points (Phase 0 of the parallel-scan plan): with no
custom input the scanner must behave exactly as before.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

from scanner_tools import active_checks as ac  # noqa: E402
from scanner_tools import discovery as disc  # noqa: E402


def _clear_env():
    for k in (
        "SHAKERSCAN_CUSTOM_SQLI_PAYLOADS",
        "SHAKERSCAN_CUSTOM_XSS_PAYLOADS",
        "SHAKERSCAN_CUSTOM_WORDLIST",
    ):
        os.environ.pop(k, None)
    disc._CUSTOM_WORDLIST_CACHE.clear()


# ---------------------------------------------------------------------------
# Custom payloads
# ---------------------------------------------------------------------------

def test_no_custom_payloads_is_noop():
    _clear_env()
    assert ac._load_custom_payloads("sqli") == []
    assert ac._load_custom_payloads("xss") == []


def test_inline_sqli_payloads_loaded_and_deduped():
    _clear_env()
    os.environ["SHAKERSCAN_CUSTOM_SQLI_PAYLOADS"] = "p1\n# comment\n\np1\np2"
    assert ac._load_custom_payloads("sqli") == ["p1", "p2"]


def test_custom_sqli_appended_to_selection():
    _clear_env()
    base = ac._select_sqli_payloads("mysql")
    os.environ["SHAKERSCAN_CUSTOM_SQLI_PAYLOADS"] = "ZZZ_CUSTOM_SQLI"
    extended = ac._select_sqli_payloads("mysql")
    assert len(extended) == len(base) + 1
    assert any(t == "custom" and p == "ZZZ_CUSTOM_SQLI" for p, t, _ in extended)
    _clear_env()


def test_custom_xss_appended_to_selection():
    _clear_env()
    base = ac._select_xss_payloads("in_html")
    os.environ["SHAKERSCAN_CUSTOM_XSS_PAYLOADS"] = "<x onfocus=alert(1)>"
    extended = ac._select_xss_payloads("in_html")
    assert len(extended) == len(base) + 1
    assert any(t == "custom" for _, t, _ in extended)
    _clear_env()


def test_custom_xss_unknown_context_falls_back_to_in_html():
    _clear_env()
    payloads = ac._select_xss_payloads("totally_unknown_context")
    assert payloads  # falls back to in_html, never empty


# ---------------------------------------------------------------------------
# Custom wordlists
# ---------------------------------------------------------------------------

def test_no_custom_wordlist_returns_none():
    _clear_env()
    assert disc.custom_wordlist_file() is None


def test_custom_wordlist_materialized_deduped_and_stripped():
    _clear_env()
    os.environ["SHAKERSCAN_CUSTOM_WORDLIST"] = "/admin\nbackup\n# note\nadmin\n\napi/v2"
    path = disc.custom_wordlist_file()
    assert path and os.path.exists(path)
    words = open(path).read().split()
    # leading slash stripped, comment/blank dropped, deduped, order preserved
    assert words == ["admin", "backup", "api/v2"]
    _clear_env()


def test_custom_wordlist_cached_per_content():
    _clear_env()
    os.environ["SHAKERSCAN_CUSTOM_WORDLIST"] = "alpha\nbeta"
    first = disc.custom_wordlist_file()
    second = disc.custom_wordlist_file()
    assert first == second  # same content -> same cached file
    _clear_env()
