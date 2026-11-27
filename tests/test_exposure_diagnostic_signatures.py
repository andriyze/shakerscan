"""Log and diagnostic endpoints proved by their own grammar (ported from scanner_tools/logging_checks)."""
from __future__ import annotations

import json

import pytest

from api.capabilities.diagnostic_signatures import DIAGNOSTIC_SEED_PATHS, html_signature, json_signature, text_signature
from api.capabilities.exposure_probe import SENSITIVE_SEED_PATHS

LOG = "\n".join(f"2026-11-27 18:0{n}:12.345  INFO 1 --- [main] c.e.App : started {n}" for n in range(4))
CAT = "green  open products  kDrc9yXCQSeBg4b1rHEDtQ 1 1 1200 0 1.2mb 600kb\nyellow open users AAAAAAAAAAAAAAAAAAAAAA 1 1 3 0 9kb 9kb\n"


def test_each_diagnostic_body_is_recognised_by_its_own_grammar():
    assert text_signature("/actuator/logfile", LOG) == ("debug_interface_exposure", "application_log_file")
    assert text_signature("/_cat/indices", CAT) == ("debug_interface_exposure", "elasticsearch_cat_indices")
    assert json_signature({"cmdline": ["/app"], "memstats": {"HeapAlloc": 1}}) == ("debug_interface_exposure", "go_expvar")
    assert json_signature({"threads": [{"threadName": "main", "threadState": "RUNNABLE"}]})[1] == "spring_actuator_threaddump"
    assert json_signature({"levels": ["INFO"], "loggers": {"ROOT": {"configuredLevel": "INFO"}}})[1] == "spring_actuator_loggers"
    assert html_signature("<title>Error log for /LM/W3SVC on SRV</title><a href='elmah.axd/rss'>") == (
        "debug_interface_exposure", "elmah_error_log")


@pytest.mark.parametrize("body", [
    "2026-11-27 18:00:12 INFO one line only\nsee the docs for /actuator/logfile",
    "The _cat/indices API lists green open indices.",
    "<title>How to read the ELMAH error log</title>",
])
def test_a_page_that_mentions_the_endpoint_is_not_the_endpoint(body):
    assert text_signature("/x", body) is None and html_signature(body) is None
    assert json_signature({"threads": "see docs", "levels": [], "loggers": {}}) is None


def test_the_probe_reads_the_diagnostic_paths():
    assert set(DIAGNOSTIC_SEED_PATHS) <= set(SENSITIVE_SEED_PATHS)
    assert "/actuator/heapdump" not in SENSITIVE_SEED_PATHS
    assert json.dumps(DIAGNOSTIC_SEED_PATHS)
