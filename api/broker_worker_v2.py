#!/usr/bin/env python3
"""V2 entrypoint for the outbound-only broker worker.

The primary worker now owns canonical Scan admission directly. The broker transport
keeps this small entrypoint only to select its outbound-only lease loop.
"""

from __future__ import annotations

import broker_worker as _broker
from worker import run_scan


# broker_worker resolves this module global when a lease is executed.
_broker.run_scan = run_scan


def main() -> int:
    return _broker.main()


if __name__ == "__main__":
    raise SystemExit(main())
