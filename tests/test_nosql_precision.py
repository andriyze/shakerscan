import asyncio

from scanner.scanner_tools import active_checks


def test_nosql_json_body_stops_on_method_not_allowed(monkeypatch, capsys):
    calls = []

    async def fake_run(cmd, *args, **kwargs):
        calls.append(cmd)
        return '{"detail":"Method Not Allowed"}__SHAKERSCAN_NOSQL__405__SHAKERSCAN_NOSQL__', "", 0

    monkeypatch.delenv("SCANNER_DEBUG_NOSQL", raising=False)
    monkeypatch.setattr(active_checks, "run", fake_run)

    result = asyncio.run(
        active_checks.nosql_injection_test_json_body(
            "https://example.test/api/features",
            method="POST",
            params=["email", "token"],
        )
    )

    assert result["vulnerable"] is False
    assert result["skipped"] is True
    assert result["reason"] == "method_or_content_type_not_supported"
    assert result["baseline_status"] == 405
    assert result["params_tested"] == 1
    assert len(calls) == 1
    assert capsys.readouterr().err == ""


def test_nosql_json_body_stops_on_unsupported_media_type(monkeypatch):
    calls = []

    async def fake_run(cmd, *args, **kwargs):
        calls.append(cmd)
        return '{"detail":"Unsupported Media Type"}__SHAKERSCAN_NOSQL__415__SHAKERSCAN_NOSQL__', "", 0

    monkeypatch.setattr(active_checks, "run", fake_run)

    result = asyncio.run(
        active_checks.nosql_injection_test_json_body(
            "https://example.test/upload",
            method="POST",
            params=["file"],
        )
    )

    assert result["vulnerable"] is False
    assert result["skipped"] is True
    assert result["baseline_status"] == 415
    assert len(calls) == 1
