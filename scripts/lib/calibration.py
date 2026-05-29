"""Shared helpers for ShakerScan calibration / benchmark drivers.

Both `scripts/dast_calibration.py` and `scripts/honey_calibration.py` queue
scans against a running ShakerScan API, poll for completion, and inspect the
returned reports. The HTTP plumbing and the wait-loop were duplicated across
both scripts; this module is the single source of truth.

Kept dependency-free on purpose so the scripts stay runnable via the system
Python without installing the scanner's full requirements.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any


TERMINAL_SCAN_STATUSES = frozenset({"completed", "failed", "cancelled"})


def request_json(
    url: str,
    *,
    method: str = "GET",
    payload: Any = None,
    timeout: int = 30,
) -> dict[str, Any]:
    """POST/GET JSON and return a parsed body (or {} when empty)."""
    headers: dict[str, str] = {}
    data = None
    if payload is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8")
            return json.loads(body) if body else {}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"{method} {url} failed with HTTP {exc.code}: {body}") from exc


def try_request_json(url: str, *, timeout: int = 15) -> dict[str, Any] | None:
    """Same as request_json but swallows errors and returns None on failure."""
    try:
        return request_json(url, timeout=timeout)
    except Exception:
        return None


def wait_for_scans(
    api: str,
    queued: list[dict[str, Any]],
    *,
    timeout: int,
    poll_interval: float,
    terminal_statuses: frozenset[str] = TERMINAL_SCAN_STATUSES,
    detail_key: str = "detail",
) -> list[dict[str, Any]]:
    """Poll the scans API until each item reaches a terminal state.

    Returns the input list with `detail_key` merged onto each item. Items
    that lack a `scan_id` are skipped from polling but still returned.
    """
    api_root = api.rstrip("/")
    deadline = time.time() + timeout
    pending = {item["scan_id"] for item in queued if item.get("scan_id")}
    details: dict[str, dict[str, Any]] = {}
    while pending and time.time() < deadline:
        for scan_id in list(pending):
            detail = request_json(f"{api_root}/scans/{scan_id}", timeout=60)
            details[scan_id] = detail
            if detail.get("status") in terminal_statuses:
                pending.remove(scan_id)
        if pending:
            time.sleep(poll_interval)
    return [
        {**item, detail_key: details.get(item.get("scan_id") or "", {})}
        for item in queued
    ]
