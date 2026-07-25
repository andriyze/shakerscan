#!/usr/bin/env python3
"""Fail-closed entrypoint for the owned-fleet worker-only container."""

from __future__ import annotations

import os
import re
import sys
import uuid


DIGEST_IMAGE_RE = re.compile(r"^\S+@sha256:[0-9a-fA-F]{64}$")


def validate_runtime() -> tuple[str, str]:
    image = os.environ.get("FLEET_WORKER_IMAGE_DIGEST", "").strip()
    if not DIGEST_IMAGE_RE.fullmatch(image):
        raise RuntimeError("FLEET_WORKER_IMAGE_DIGEST must be a digest-pinned image reference")
    node_id = os.environ.get("SHAKERSCAN_NODE_ID", "").strip()
    try:
        parsed = uuid.UUID(node_id)
    except ValueError as exc:
        raise RuntimeError("SHAKERSCAN_NODE_ID must be a UUID") from exc
    return image, str(parsed)


def main() -> int:
    validate_runtime()
    os.execv(sys.executable, [sys.executable, "/app/worker.py"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
