"""sqlmap and dalfox settle their wire reservation from their own complete request logs.

DAST-1: the release plan's premise that external TLS traffic enters the worker HTTP archive is
false, so continuation could not refund a bounded scanner's unused request hold. sqlmap's `-t`
traffic log and dalfox's HAR are each a complete record of what the tool sent (measured against a
counting origin: sqlmap logged 471/471, dalfox 1,225/1,225). Reading them settles the reservation
exactly. Katana's discovery feed is not a wire log and must stay conservative.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

import api.agent_tools as agent_tools


def test_sqlmap_traffic_log_counts_the_highest_sequential_marker():
    log = "\n".join(f"HTTP request [#{n}]:\nGET /x HTTP/1.1" for n in range(1, 472))
    assert agent_tools.sqlmap_traffic_request_count(log) == 471
    assert agent_tools.sqlmap_traffic_request_count("no markers here") is None


def test_har_counts_entries_and_rejects_non_har():
    har = json.dumps({"log": {"entries": [{"request": {}} for _ in range(1225)]}})
    assert agent_tools.har_request_count(har) == 1225
    assert agent_tools.har_request_count("{}") is None
    assert agent_tools.har_request_count("not json") is None


def test_file_counter_reads_the_tool_log_from_the_scratch_directory(tmp_path: Path):
    (tmp_path / "traffic.log").write_text(
        "HTTP request [#1]:\nHTTP request [#2]:\n", encoding="utf-8"
    )
    counter = agent_tools.scanner_file_request_counter("sqlmap", str(tmp_path))
    assert counter == {"actual": 2, "source": "sqlmap_traffic_log"}

    (tmp_path / "requests.har").write_text(
        json.dumps({"log": {"entries": [{}, {}, {}]}}), encoding="utf-8"
    )
    assert agent_tools.scanner_file_request_counter("dalfox", str(tmp_path)) == {
        "actual": 3, "source": "dalfox_har",
    }


def test_file_counter_is_none_when_the_log_is_absent_or_unreadable(tmp_path: Path):
    assert agent_tools.scanner_file_request_counter("sqlmap", str(tmp_path)) is None
    assert agent_tools.scanner_file_request_counter("katana", str(tmp_path)) is None
    assert agent_tools.scanner_file_request_counter("sqlmap", None) is None


def test_settlement_prefers_the_exact_file_counter_and_refunds_the_reservation():
    settled = agent_tools.scanner_request_settlement(
        "sqlmap", "", file_counter={"actual": 120, "source": "sqlmap_traffic_log"},
    )
    assert settled["mode"] == "exact"
    assert settled["actual"] == 120
    assert settled["source"] == "sqlmap_traffic_log"


def test_settlement_without_a_file_counter_is_unchanged_for_katana():
    settled = agent_tools.scanner_request_settlement("katana", "")
    assert settled["mode"] == "unavailable"
    assert settled["actual"] is None


def test_bind_places_both_tool_logs_inside_the_job_scratch_directory():
    _binary, sqlmap_argv, _ms = agent_tools.build_scanner_argv(
        "sqlmap", "http://t/item?id=1", {},
    )
    bound = agent_tools.bind_scanner_runtime_paths(
        "sqlmap", sqlmap_argv, scratch_dir="/tmp/shakerscan-sqlmap-job-1",
    )
    assert bound[bound.index("-t") + 1] == "/tmp/shakerscan-sqlmap-job-1/traffic.log"
    assert bound[bound.index("--output-dir") + 1] == "/tmp/shakerscan-sqlmap-job-1"

    _binary, dalfox_argv, _ms = agent_tools.build_scanner_argv(
        "dalfox", "http://t/?q=1", {},
    )
    bound = agent_tools.bind_scanner_runtime_paths(
        "dalfox", dalfox_argv, scratch_dir="/tmp/shakerscan-dalfox-job-1",
    )
    assert bound[bound.index("--har-file-path") + 1] == (
        "/tmp/shakerscan-dalfox-job-1/requests.har"
    )


def test_bind_requires_an_absolute_scratch_directory():
    _binary, argv, _ms = agent_tools.build_scanner_argv("dalfox", "http://t/?q=1", {})
    with pytest.raises(agent_tools.AgentToolError):
        agent_tools.bind_scanner_runtime_paths("dalfox", argv, scratch_dir="relative")
