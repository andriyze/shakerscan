"""Shared cooperative cancellation for scanner modules.

The worker writes ``SHAKERSCAN_CANCEL_FILE`` before terminating the scanner
process group. Scanner modules use this helper to stop between requests and
return partial telemetry during the grace period.
"""

from __future__ import annotations

import asyncio
import os


def scanner_cancel_requested() -> bool:
    cancel_file = os.environ.get("SHAKERSCAN_CANCEL_FILE")
    if not cancel_file:
        return False
    try:
        return os.path.exists(cancel_file)
    except OSError:
        return False


async def wait_for_scanner_cancel(*, poll_seconds: float = 0.1) -> bool:
    """Wait until cancellation is requested.

    Callers should cancel this coroutine when their work completes first.
    """
    delay = max(0.01, float(poll_seconds or 0.1))
    while not scanner_cancel_requested():
        await asyncio.sleep(delay)
    return True
