#!/usr/bin/env python3
"""V2 admission wrapper for the outbound-only broker worker.

The broker transport remains unchanged, but every deterministic Scan lease is admitted through
``worker_v2.run_scan_v2`` before the legacy scanner subprocess is allowed to start. Non-DAST
run kinds continue to delegate through the existing worker implementation.
"""

from __future__ import annotations

import broker_worker as _broker
from worker_v2 import run_scan_v2


# broker_worker resolves this module global when a lease is executed.
_broker.run_scan = run_scan_v2


def main() -> int:
    return _broker.main()


if __name__ == "__main__":
    raise SystemExit(main())
