from __future__ import annotations

import asyncio
import json
import sys
from types import SimpleNamespace

import pytest

from scanner.manifests import (
    AtomicManifestSink,
    DiscoveryDeadlines,
    EndpointManifest,
    normalize_endpoint,
)
from scanner.scanner_tools.common import run_streaming
from scanner.scanner_tools import discovery


def test_endpoint_manifest_preserves_method_and_schema_identity_and_normalizes_examples(tmp_path):
    manifest = EndpointManifest()
    manifest.start_producer("seed")
    get = normalize_endpoint(
        method="GET", url="https://API.Example.test/users/123", source="seed"
    )
    delete = normalize_endpoint(
        method="DELETE", url="https://api.example.test/users/456", source="seed"
    )
    graphql_query = normalize_endpoint(
        method="POST", url="https://api.example.test/graphql", source="openapi",
        content_type="application/json", body_schema={"operation": "GetUser"},
    )
    graphql_mutation = normalize_endpoint(
        method="POST", url="https://api.example.test/graphql", source="openapi",
        content_type="application/json", body_schema={"operation": "DeleteUser"},
    )

    assert manifest.add("seed", get) is True
    assert manifest.add("seed", normalize_endpoint(
        method="GET", url="https://api.example.test/users/999", source="crawl"
    )) is False
    assert manifest.add("seed", delete) is True
    assert manifest.add("seed", graphql_query) is True
    assert manifest.add("seed", graphql_mutation) is True
    manifest.finish_producer("seed")
    manifest.finalize()

    payload = manifest.to_dict()
    assert payload["status"] == "complete"
    assert payload["endpoint_count"] == 4
    assert payload["endpoints"][0]["normalized_path"] == "/users/{int}"

    sink = AtomicManifestSink(tmp_path / "manifest.json", flush_seconds=999, flush_new_endpoints=50)
    assert sink.maybe_flush(manifest, force=True) is True
    stored = json.loads((tmp_path / "manifest.json").read_text())
    assert stored["schema_version"] == "endpoint-manifest/v1"
    assert stored["endpoint_count"] == 4


def test_partial_manifest_separates_coverage_from_run_failure():
    manifest = EndpointManifest()
    manifest.start_producer("seed")
    manifest.add("seed", normalize_endpoint(
        method="GET", url="https://example.test/", source="seed"
    ))
    manifest.finish_producer("seed")
    manifest.start_producer("katana")
    for index in range(347):
        manifest.add("katana", normalize_endpoint(
            method="GET", url=f"https://example.test/items/item-{index}/view", source="katana"
        ))
    manifest.finish_producer("katana", status="timed_out", reason="soft_deadline")
    manifest.finalize()

    payload = manifest.to_dict()
    assert payload["status"] == "partial"
    assert payload["endpoint_count"] == 348
    assert payload["producers"]["katana"] == {
        "status": "timed_out", "count": 347, "reason": "soft_deadline", "timed_out": True,
    }
    # The scan's run status can be completed while this independent coverage contract is partial.
    scan_view = {"status": "completed", "coverage": payload}
    assert scan_view["status"] == "completed" and scan_view["coverage"]["status"] == "partial"


def test_manifest_cancellation_is_distinct_from_timeout():
    manifest = EndpointManifest()
    manifest.start_producer("crawl")
    manifest.finish_producer("crawl", status="cancelled", reason="user_cancelled")
    manifest.finalize(cancelled=True)
    assert manifest.to_dict()["status"] == "cancelled"


def test_discovery_deadline_validation():
    assert DiscoveryDeadlines().hard_seconds == 240
    with pytest.raises(ValueError):
        DiscoveryDeadlines(soft_seconds=180, flush_grace_seconds=30, hard_seconds=200)


def test_streaming_timeout_preserves_valid_lines_and_reports_partial():
    script = (
        "import sys,time\n"
        "for i in range(5):\n"
        " print('https://example.test/p%d' % i, flush=True)\n"
        "time.sleep(60)\n"
    )
    seen: list[str] = []
    result = asyncio.run(run_streaming(
        [sys.executable, "-c", script], soft_timeout=0.15, flush_grace=0.05,
        hard_timeout=0.30, on_stdout_line=seen.append,
    ))

    assert result.timed_out is True
    assert result.partial is True
    assert result.soft_deadline_reached is True
    assert seen == [f"https://example.test/p{i}" for i in range(5)]
    assert result.stdout.splitlines() == seen
    assert result.returncode == 124


def test_streaming_user_cancellation_does_not_report_timeout():
    async def scenario():
        cancelled = False

        async def request_cancel() -> bool:
            return cancelled

        async def flip() -> None:
            nonlocal cancelled
            await asyncio.sleep(0.1)
            cancelled = True

        flip_task = asyncio.create_task(flip())
        result = await run_streaming(
            [sys.executable, "-c", "import time; print('seed', flush=True); time.sleep(60)"],
            soft_timeout=5, flush_grace=0, hard_timeout=5, cancel_check=request_cancel,
        )
        await flip_task
        return result

    result = asyncio.run(scenario())

    assert result.cancelled is True
    assert result.timed_out is False
    assert result.status == "cancelled"
    assert result.returncode == 130
    assert result.stdout.strip() == "seed"


def test_live_katana_adapter_uses_streaming_deadlines_and_line_callback(monkeypatch):
    captured = {}

    async def fake_stream(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        kwargs["on_stdout_line"]('{"request":{"method":"POST","endpoint":"https://example.test/api/items"}}')
        return SimpleNamespace(timed_out=True, partial=True, cancelled=False, returncode=124)

    monkeypatch.setattr(discovery, "run_streaming", fake_stream)
    lines = []
    result = asyncio.run(discovery.run_katana_stream(
        "katana", "https://example.test", 4, lines.append,
    ))

    assert captured["cmd"][:5] == ["katana", "-u", "https://example.test", "-jsonl", "-silent"]
    assert captured["kwargs"]["soft_timeout"] == 180.0
    assert captured["kwargs"]["hard_timeout"] == 240.0
    assert lines == ['{"request":{"method":"POST","endpoint":"https://example.test/api/items"}}']
    assert result.timed_out is True and result.partial is True
