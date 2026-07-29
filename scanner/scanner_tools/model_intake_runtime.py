"""Narrow no-code runtime checks for non-executable model weight formats."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import mmap
import struct
from pathlib import Path
from typing import Any


MAX_HEADER_BYTES = 100_000_000
MAX_TENSORS = 1_000_000
SAMPLE_VALUES_PER_TENSOR = 16
DTYPE_FORMATS: dict[str, tuple[str, int]] = {
    "F64": ("d", 8),
    "F32": ("f", 4),
    "F16": ("e", 2),
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _product(shape: Any) -> int | None:
    if not isinstance(shape, list) or not all(isinstance(item, int) and item >= 0 for item in shape):
        return None
    result = 1
    for item in shape:
        result *= item
    return result


def inspect_safetensors(path: Path, expected_digest: str) -> dict[str, Any]:
    actual_digest = _sha256(path)
    blockers: list[str] = []
    known_answers: list[dict[str, Any]] = []
    if actual_digest != expected_digest:
        blockers.append("artifact_digest_mismatch")
    tensor_count = 0
    sampled_values = 0
    non_finite_values = 0
    invalid_tensors: list[dict[str, Any]] = []
    dtype_counts: dict[str, int] = {}
    try:
        with path.open("rb") as handle:
            length_raw = handle.read(8)
            if len(length_raw) != 8:
                raise ValueError("truncated_header_length")
            header_length = int.from_bytes(length_raw, "little")
            if not 0 < header_length <= MAX_HEADER_BYTES:
                raise ValueError("invalid_header_length")
            header = json.loads(handle.read(header_length).decode("utf-8"))
            if not isinstance(header, dict):
                raise ValueError("header_not_object")
            tensor_items = [(name, value) for name, value in header.items() if name != "__metadata__"]
            if not tensor_items or len(tensor_items) > MAX_TENSORS:
                raise ValueError("tensor_inventory_out_of_bounds")
            tensor_count = len(tensor_items)
            payload_offset = 8 + header_length
            payload_size = path.stat().st_size - payload_offset
            with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
                for name, tensor in tensor_items:
                    offsets = tensor.get("data_offsets") if isinstance(tensor, dict) else None
                    dtype = str(tensor.get("dtype") or "") if isinstance(tensor, dict) else ""
                    shape = tensor.get("shape") if isinstance(tensor, dict) else None
                    elements = _product(shape)
                    if (
                        not isinstance(offsets, list)
                        or len(offsets) != 2
                        or not all(isinstance(item, int) for item in offsets)
                        or offsets[0] < 0
                        or offsets[1] < offsets[0]
                        or offsets[1] > payload_size
                        or elements is None
                    ):
                        invalid_tensors.append({"tensor_ref": hashlib.sha256(str(name).encode()).hexdigest()[:16], "reason": "invalid_metadata"})
                        continue
                    dtype_counts[dtype or "unknown"] = dtype_counts.get(dtype or "unknown", 0) + 1
                    format_spec = DTYPE_FORMATS.get(dtype)
                    if not format_spec or offsets[1] == offsets[0]:
                        continue
                    fmt, item_size = format_spec
                    available = (offsets[1] - offsets[0]) // item_size
                    if available <= 0:
                        continue
                    sample_count = min(SAMPLE_VALUES_PER_TENSOR, available)
                    for sample_index in range(sample_count):
                        element_index = (sample_index * max(1, available - 1)) // max(1, sample_count - 1)
                        start = payload_offset + offsets[0] + element_index * item_size
                        value = struct.unpack_from(f"<{fmt}", mapped, start)[0]
                        sampled_values += 1
                        if not math.isfinite(float(value)):
                            non_finite_values += 1
    except (OSError, ValueError, json.JSONDecodeError, UnicodeDecodeError, struct.error) as exc:
        blockers.append(f"safetensors_load_failed:{type(exc).__name__}:{exc}")
    if invalid_tensors:
        blockers.append("invalid_tensor_metadata")
    if non_finite_values:
        blockers.append("sampled_non_finite_weights")
    known_answers.extend([
        {"id": "artifact-digest-bound", "status": "PASS" if actual_digest == expected_digest else "FAIL"},
        {"id": "tensor-inventory-nonempty", "status": "PASS" if tensor_count > 0 else "FAIL"},
        {"id": "tensor-ranges-loadable", "status": "PASS" if not invalid_tensors else "FAIL"},
        {"id": "sampled-numeric-finiteness", "status": "PASS" if not non_finite_values else "FAIL"},
    ])
    if any(item["status"] != "PASS" for item in known_answers):
        blockers.append("known_answer_non_pass")
    return {
        "status": "FAIL" if blockers else "PASS",
        "artifact_sha256": actual_digest,
        "artifact_loaded": not blockers,
        "model_loaded": False,
        "load_level": "weights",
        "known_answer_tests": known_answers,
        "tensor_count": tensor_count,
        "dtype_counts": dtype_counts,
        "sampled_values": sampled_values,
        "non_finite_values": non_finite_values,
        "invalid_tensor_count": len(invalid_tensors),
        "spawned_processes": 0,
        "network_attempts": [],
        "imports": [],
        "blockers": blockers,
        "limitations": [
            "custom_model_code_not_imported",
            "model_graph_not_instantiated",
            "embedding_known_answers_not_executed",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifact")
    parser.add_argument("expected_digest")
    args = parser.parse_args()
    result = inspect_safetensors(Path(args.artifact), args.expected_digest)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
