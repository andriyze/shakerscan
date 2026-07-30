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
DTYPE_SIZES: dict[str, int] = {
    "BOOL": 1,
    "U8": 1,
    "I8": 1,
    "U16": 2,
    "I16": 2,
    "U32": 4,
    "I32": 4,
    "U64": 8,
    "I64": 8,
    "F16": 2,
    "BF16": 2,
    "F32": 4,
    "F64": 8,
    # Structurally understood, but deliberately not admitted until the
    # numeric sampler supports their exact finite-value encodings.
    "F8_E4M3": 1,
    "F8_E4M3FN": 1,
    "F8_E5M2": 1,
    "F8_E8M0": 1,
}
FLOAT_DTYPES = {name for name in DTYPE_SIZES if name.startswith("F") or name == "BF16"}
SAMPLED_FLOAT_DTYPES = set(DTYPE_FORMATS) | {"BF16"}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _product(shape: Any) -> int | None:
    if not isinstance(shape, list) or not all(type(item) is int and item >= 0 for item in shape):
        return None
    result = 1
    for item in shape:
        result *= item
    return result


def _tensor_ref(name: Any) -> str:
    return hashlib.sha256(str(name).encode("utf-8", "replace")).hexdigest()[:16]


def _load_layout(path: Path) -> dict[str, Any]:
    duplicate_keys: list[str] = []

    def object_pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                duplicate_keys.append(key)
            result[key] = value
        return result

    with path.open("rb") as handle:
        length_raw = handle.read(8)
        if len(length_raw) != 8:
            raise ValueError("truncated_header_length")
        header_length = int.from_bytes(length_raw, "little")
        if not 0 < header_length <= MAX_HEADER_BYTES:
            raise ValueError("invalid_header_length")
        header_raw = handle.read(header_length)
        if len(header_raw) != header_length:
            raise ValueError("truncated_header")
        header = json.loads(header_raw.decode("utf-8"), object_pairs_hook=object_pairs_hook)
    if not isinstance(header, dict):
        raise ValueError("header_not_object")
    if duplicate_keys:
        raise ValueError("duplicate_header_keys")
    metadata = header.get("__metadata__")
    if metadata is not None and (
        not isinstance(metadata, dict)
        or not all(isinstance(key, str) and isinstance(value, str) for key, value in metadata.items())
    ):
        raise ValueError("invalid_metadata_map")
    tensor_items = [(name, value) for name, value in header.items() if name != "__metadata__"]
    if not tensor_items or len(tensor_items) > MAX_TENSORS:
        raise ValueError("tensor_inventory_out_of_bounds")

    payload_offset = 8 + header_length
    payload_size = path.stat().st_size - payload_offset
    if payload_size < 0:
        raise ValueError("negative_payload_size")
    invalid_tensors: list[dict[str, Any]] = []
    tensor_specs: list[dict[str, Any]] = []
    dtype_counts: dict[str, int] = {}
    unsupported_dtypes: set[str] = set()
    for name, tensor in tensor_items:
        ref = _tensor_ref(name)
        if not isinstance(name, str) or not name or not isinstance(tensor, dict):
            invalid_tensors.append({"tensor_ref": ref, "reason": "invalid_tensor_entry"})
            continue
        offsets = tensor.get("data_offsets")
        dtype = tensor.get("dtype")
        elements = _product(tensor.get("shape"))
        if (
            not isinstance(offsets, list)
            or len(offsets) != 2
            or not all(type(item) is int for item in offsets)
            or offsets[0] < 0
            or offsets[1] < offsets[0]
            or offsets[1] > payload_size
            or elements is None
            or not isinstance(dtype, str)
        ):
            invalid_tensors.append({"tensor_ref": ref, "reason": "invalid_tensor_metadata"})
            continue
        item_size = DTYPE_SIZES.get(dtype)
        if item_size is None:
            unsupported_dtypes.add(dtype or "unknown")
            invalid_tensors.append({"tensor_ref": ref, "reason": "unsupported_dtype"})
            continue
        start, end = offsets
        expected_bytes = elements * item_size
        if end - start != expected_bytes:
            invalid_tensors.append({"tensor_ref": ref, "reason": "shape_byte_span_mismatch"})
            continue
        dtype_counts[dtype] = dtype_counts.get(dtype, 0) + 1
        tensor_specs.append({
            "tensor_ref": ref,
            "dtype": dtype,
            "elements": elements,
            "start": start,
            "end": end,
        })

    coverage_errors: list[str] = []
    nonempty = sorted((item for item in tensor_specs if item["end"] > item["start"]), key=lambda item: (item["start"], item["end"]))
    cursor = 0
    for item in nonempty:
        if item["start"] < cursor:
            coverage_errors.append("overlapping_tensor_spans")
        elif item["start"] > cursor:
            coverage_errors.append("unexplained_payload_gap")
        cursor = max(cursor, item["end"])
    if cursor != payload_size:
        coverage_errors.append("unexplained_trailing_payload" if cursor < payload_size else "payload_overrun")
    return {
        "payload_offset": payload_offset,
        "payload_size": payload_size,
        "tensor_count": len(tensor_items),
        "tensor_specs": tensor_specs,
        "dtype_counts": dtype_counts,
        "unsupported_dtypes": sorted(unsupported_dtypes),
        "invalid_tensors": invalid_tensors,
        "coverage_errors": sorted(set(coverage_errors)),
    }


def inspect_safetensors_layout(path: Path) -> dict[str, Any]:
    """Return content-free, fail-closed structural evidence for one complete file."""
    try:
        layout = _load_layout(path)
    except (OSError, ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        return {
            "status": "FAIL",
            "format": "safetensors",
            "error": f"{type(exc).__name__}:{exc}",
            "tensor_count": 0,
        }
    blockers = bool(layout["invalid_tensors"] or layout["coverage_errors"])
    status = "UNSUPPORTED" if layout["unsupported_dtypes"] else "FAIL" if blockers else "PASS"
    return {
        "status": status,
        "format": "safetensors",
        "tensor_count": layout["tensor_count"],
        "dtype_counts": layout["dtype_counts"],
        "invalid_tensors": layout["invalid_tensors"][:100],
        "invalid_tensor_count": len(layout["invalid_tensors"]),
        "unsupported_dtypes": layout["unsupported_dtypes"],
        "payload_size": layout["payload_size"],
        "payload_coverage_complete": not layout["coverage_errors"],
        "coverage_errors": layout["coverage_errors"],
    }


def inspect_safetensors(
    path: Path,
    expected_digest: str,
    *,
    numeric_mode: str = "sampled",
) -> dict[str, Any]:
    if numeric_mode not in {"sampled", "full"}:
        raise ValueError("numeric_mode must be sampled or full")
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
    coverage_errors: list[str] = []
    unsupported_numeric_dtypes: set[str] = set()
    floating_tensor_count = 0
    try:
        layout = _load_layout(path)
        tensor_count = layout["tensor_count"]
        dtype_counts = layout["dtype_counts"]
        invalid_tensors = layout["invalid_tensors"]
        coverage_errors = layout["coverage_errors"]
        if layout["unsupported_dtypes"]:
            blockers.append("unsupported_tensor_dtype")
        with path.open("rb") as handle:
            with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
                for tensor in layout["tensor_specs"]:
                    dtype = tensor["dtype"]
                    if dtype not in FLOAT_DTYPES:
                        continue
                    floating_tensor_count += 1
                    if dtype not in SAMPLED_FLOAT_DTYPES:
                        unsupported_numeric_dtypes.add(dtype)
                        continue
                    format_spec = DTYPE_FORMATS.get(dtype)
                    if tensor["elements"] == 0:
                        continue
                    item_size = DTYPE_SIZES[dtype]
                    available = tensor["elements"]
                    scan_count = available if numeric_mode == "full" else min(SAMPLE_VALUES_PER_TENSOR, available)
                    for sample_index in range(scan_count):
                        element_index = (
                            sample_index
                            if numeric_mode == "full"
                            else (sample_index * max(1, available - 1)) // max(1, scan_count - 1)
                        )
                        start = layout["payload_offset"] + tensor["start"] + element_index * item_size
                        if dtype == "BF16":
                            bits = struct.unpack_from("<H", mapped, start)[0]
                            finite = bits & 0x7F80 != 0x7F80
                        else:
                            fmt = format_spec[0] if format_spec else ""
                            value = struct.unpack_from(f"<{fmt}", mapped, start)[0]
                            finite = math.isfinite(float(value))
                        sampled_values += 1
                        if not finite:
                            non_finite_values += 1
    except (OSError, ValueError, json.JSONDecodeError, UnicodeDecodeError, struct.error) as exc:
        blockers.append(f"safetensors_load_failed:{type(exc).__name__}:{exc}")
    if invalid_tensors:
        blockers.append("invalid_tensor_metadata")
    if coverage_errors:
        blockers.append("incomplete_or_ambiguous_payload_coverage")
    if unsupported_numeric_dtypes:
        blockers.append("numeric_finiteness_unsupported_dtype")
    if floating_tensor_count and sampled_values == 0:
        blockers.append("numeric_finiteness_not_measured")
    if non_finite_values:
        blockers.append("sampled_non_finite_weights")
    known_answers.extend([
        {"id": "artifact-digest-bound", "status": "PASS" if actual_digest == expected_digest else "FAIL"},
        {"id": "tensor-inventory-nonempty", "status": "PASS" if tensor_count > 0 else "FAIL"},
        {"id": "tensor-metadata-valid", "status": "PASS" if not invalid_tensors else "FAIL"},
        {"id": "payload-coverage-complete", "status": "PASS" if not coverage_errors else "FAIL"},
        {
            "id": "sampled-numeric-finiteness",
            "status": (
                "UNSUPPORTED" if unsupported_numeric_dtypes
                else "NOT_MEASURED" if floating_tensor_count and sampled_values == 0
                else "NOT_APPLICABLE" if not floating_tensor_count
                else "PASS" if not non_finite_values else "FAIL"
            ),
            "applicable": bool(floating_tensor_count),
        },
    ])
    if any(item.get("applicable", True) and item["status"] != "PASS" for item in known_answers):
        blockers.append("known_answer_non_pass")
    return {
        "status": "UNSUPPORTED" if unsupported_numeric_dtypes else "FAIL" if blockers else "PASS",
        "artifact_sha256": actual_digest,
        "artifact_loaded": not blockers,
        "model_loaded": False,
        "load_level": "weights",
        "known_answer_tests": known_answers,
        "tensor_count": tensor_count,
        "dtype_counts": dtype_counts,
        "floating_tensor_count": floating_tensor_count,
        "sampled_values": sampled_values,
        "numeric_scan_mode": numeric_mode,
        "non_finite_values": non_finite_values,
        "invalid_tensor_count": len(invalid_tensors),
        "payload_coverage_complete": not coverage_errors,
        "coverage_errors": coverage_errors,
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
    parser.add_argument("--numeric-mode", choices=("sampled", "full"), default="sampled")
    args = parser.parse_args()
    result = inspect_safetensors(Path(args.artifact), args.expected_digest, numeric_mode=args.numeric_mode)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
