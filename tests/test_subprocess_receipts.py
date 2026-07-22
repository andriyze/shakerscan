import asyncio
import os
import sys


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

from scanner_tools import common  # noqa: E402


def test_common_run_records_redacted_subprocess_receipt():
    common.reset_subprocess_receipts()

    out, err, rc = asyncio.run(common.run([
        sys.executable,
        "-c",
        "print('ok')",
        "--token=secret-token",
    ], timeout=5))

    receipts = common.snapshot_subprocess_receipts()
    assert rc == 0
    assert out == "ok"
    assert err == ""
    assert len(receipts) == 1
    receipt = receipts[0]
    assert receipt["tool_name"] == sys.executable
    assert receipt["status"] == "success"
    assert receipt["parser_status"] == "not_run"
    assert receipt["exit_code"] == 0
    assert receipt["timed_out"] is False
    assert receipt["stdout_length"] >= 3
    assert receipt["stdout_preview"] == "ok\n"
    assert "secret-token" not in repr(receipt)
    assert "[REDACTED]" in receipt["redacted_argv"]
    assert len(receipt["command_hash"]) == 64


def test_common_run_records_timeout_receipt():
    common.reset_subprocess_receipts()

    out, err, rc = asyncio.run(common.run([
        sys.executable,
        "-c",
        "import time; time.sleep(2)",
    ], timeout=1))

    receipts = common.snapshot_subprocess_receipts()
    assert rc == 124
    assert out == ""
    assert "timeout after 1s" in err
    assert len(receipts) == 1
    assert receipts[0]["status"] == "timeout"
    assert receipts[0]["parser_status"] == "not_applicable"
    assert receipts[0]["exit_code"] == 124
    assert receipts[0]["timed_out"] is True


def test_common_run_records_bounded_redacted_long_output_artifact(monkeypatch):
    common.reset_subprocess_receipts()
    monkeypatch.setattr(common, "_SUBPROCESS_ARTIFACT_MAX_BYTES", 900)

    secret = "token=secret-token-value"
    out, err, rc = asyncio.run(common.run([
        sys.executable,
        "-c",
        f"print('{secret} ' + 'x' * 1200)",
    ], timeout=5))

    receipts = common.snapshot_subprocess_receipts()
    assert rc == 0
    assert err == ""
    assert secret in out
    artifact = receipts[0]["stdout_artifact"]
    assert artifact["stream"] == "stdout"
    assert artifact["truncated"] is True
    assert artifact["captured_length"] <= 900
    assert "secret-token-value" not in artifact["content"]
    assert "token=[REDACTED]" in artifact["content"]
    assert len(artifact["content_sha256"]) == 64
