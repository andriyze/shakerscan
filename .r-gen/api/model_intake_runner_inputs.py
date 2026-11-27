"""Versioned, bounded known-answer inputs required by every runtime job."""

from __future__ import annotations

import hashlib
import json
from typing import Any


SUITE_VERSION = "model-intake-embedding-smoke/v1"
MAX_INPUTS = 100
MAX_INPUT_BYTES = 16_384
MAX_TOTAL_BYTES = 256 * 1024
MANDATORY_SMOKE_INPUTS = (
    "corporate security review",
    "knowledge graph entity retrieval",
    "",
    "Unicode boundary: naïve café 東京 🔐",
    "control boundary: \u0000\u0001\t\n",
    "long input boundary: " + ("A" * 4096),
)


def normalize_known_answer_inputs(values: Any) -> list[str]:
    if not isinstance(values, list) or any(not isinstance(item, str) for item in values):
        raise ValueError("known-answer inputs must be a string array")
    normalized: list[str] = []
    seen: set[str] = set()
    for item in (*MANDATORY_SMOKE_INPUTS, *values):
        encoded = item.encode("utf-8")
        if len(encoded) > MAX_INPUT_BYTES:
            raise ValueError("known-answer input exceeds the per-item byte limit")
        if item not in seen:
            seen.add(item)
            normalized.append(item)
    if len(normalized) > MAX_INPUTS:
        raise ValueError("known-answer input count exceeds the suite limit")
    if sum(len(item.encode("utf-8")) for item in normalized) > MAX_TOTAL_BYTES:
        raise ValueError("known-answer inputs exceed the aggregate byte limit")
    return normalized


def suite_identity(values: Any) -> dict[str, Any]:
    normalized = normalize_known_answer_inputs(values)
    digest = hashlib.sha256(
        json.dumps(normalized, ensure_ascii=True, separators=(",", ":")).encode()
    ).hexdigest()
    return {
        "suite_version": SUITE_VERSION,
        "input_count": len(normalized),
        "inputs_sha256": digest,
        "total_utf8_bytes": sum(len(item.encode("utf-8")) for item in normalized),
        "inputs": normalized,
    }


__all__ = [
    "MANDATORY_SMOKE_INPUTS", "MAX_INPUTS", "MAX_INPUT_BYTES", "MAX_TOTAL_BYTES",
    "SUITE_VERSION", "normalize_known_answer_inputs", "suite_identity",
]
