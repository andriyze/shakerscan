"""Official safetensors-parser gate plus content-free bounded evidence.

This entry point runs in its own hash-locked virtual environment. The Rust
parser owns format acceptance, tensor inventory, and all full numeric payload
access. ShakerScan's independent layout pass is defense-in-depth only.
"""

from __future__ import annotations

import argparse
import hashlib
from importlib.metadata import version
from itertools import product
import json
from pathlib import Path
from typing import Any

import ml_dtypes as _ml_dtypes  # noqa: F401 -- registers NumPy BF16 support.
import numpy as np
from safetensors import safe_open

from model_intake_runtime import _load_layout, inspect_safetensors


FULL_NUMERIC_DTYPES = {"F64", "F32", "F16", "BF16"}
FULL_NUMERIC_CHUNK_ELEMENTS = 4 * 1024 * 1024


def _crosscheck_official_inventory(path: Path, handle: Any) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    """Bind every independent tensor span to the official parser inventory."""
    layout = _load_layout(path)
    if layout["invalid_tensors"] or layout["coverage_errors"]:
        raise ValueError("independent_layout_not_complete")
    manual = {str(spec["name"]): spec for spec in layout["tensor_specs"]}
    keys = list(handle.keys())
    if len(keys) != layout["tensor_count"] or set(keys) != set(manual):
        raise ValueError("official_manual_tensor_inventory_mismatch")
    official: dict[str, dict[str, Any]] = {}
    for key in keys:
        tensor_slice = handle.get_slice(key)
        observed = {
            "dtype": str(tensor_slice.get_dtype()),
            "shape": list(tensor_slice.get_shape()),
        }
        expected = manual[key]
        if observed["dtype"] != expected["dtype"] or observed["shape"] != expected["shape"]:
            raise ValueError("official_manual_tensor_metadata_mismatch")
        official[key] = observed
    return layout, official


def _block_shape(shape: list[int], maximum_elements: int) -> list[int]:
    blocks = [1 for _ in shape]
    remaining = maximum_elements
    for index in range(len(shape) - 1, -1, -1):
        blocks[index] = min(shape[index], max(1, remaining))
        remaining = max(1, remaining // max(1, blocks[index]))
    return blocks


def _official_tensor_blocks(handle: Any, name: str, shape: list[int]):
    """Yield bounded arrays through safetensors' Rust-validated slice API."""
    if not shape:
        yield handle.get_tensor(name)
        return
    if any(dimension == 0 for dimension in shape):
        return
    blocks = _block_shape(shape, FULL_NUMERIC_CHUNK_ELEMENTS)
    starts = [range(0, dimension, block) for dimension, block in zip(shape, blocks)]
    tensor_slice = handle.get_slice(name)
    for offsets in product(*starts):
        selection = tuple(
            slice(start, min(dimension, start + block))
            for start, dimension, block in zip(offsets, shape, blocks)
        )
        yield tensor_slice[selection]


def _full_numeric_scan(path: Path, handle: Any) -> dict[str, int]:
    """Scan every supported float through official, bounded tensor slices."""
    layout, official = _crosscheck_official_inventory(path, handle)
    checked = 0
    non_finite = 0
    accessed_tensors = 0
    chunks = 0
    for tensor in layout["tensor_specs"]:
        dtype = tensor["dtype"]
        if dtype not in FULL_NUMERIC_DTYPES or not tensor["elements"]:
            continue
        accessed_tensors += 1
        for values in _official_tensor_blocks(handle, tensor["name"], official[tensor["name"]]["shape"]):
            if int(values.size) > FULL_NUMERIC_CHUNK_ELEMENTS:
                raise ValueError("official_tensor_slice_exceeded_element_budget")
            non_finite += int(np.count_nonzero(~np.isfinite(values)))
            checked += int(values.size)
            chunks += 1
    return {
        "values_checked": checked,
        "non_finite_values": non_finite,
        "official_tensors_accessed": accessed_tensors,
        "official_numeric_chunks": chunks,
        "inventory_tensors_crosschecked": len(official),
    }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def inspect_with_official_parser(
    path: Path,
    expected_digest: str,
    *,
    numeric_mode: str = "full",
) -> dict[str, Any]:
    actual_digest = _sha256(path)
    parser_evidence: dict[str, Any] = {
        "name": "huggingface-safetensors-rust",
        "version": version("safetensors"),
        "authority_scope": ["format_acceptance", "tensor_inventory", "numeric_payload_access"],
        "status": "FAIL",
        "tensor_count": 0,
        "inventory_crosscheck_status": "NOT_RUN",
    }
    numeric: dict[str, int] | None = None
    try:
        with safe_open(str(path), framework="np", device="cpu") as handle:
            keys = list(handle.keys())
            slices = [handle.get_slice(key) for key in keys]
            shapes = [list(tensor_slice.get_shape()) for tensor_slice in slices]
            parser_evidence.update({
                "status": "PASS",
                "tensor_count": len(keys),
                "rank_counts": {
                    str(rank): sum(1 for shape in shapes if len(shape) == rank)
                    for rank in sorted({len(shape) for shape in shapes})
                },
                "metadata_present": bool(handle.metadata()),
            })
            _layout, official = _crosscheck_official_inventory(path, handle)
            parser_evidence["inventory_crosscheck_status"] = "PASS"
            parser_evidence["inventory_tensors_crosschecked"] = len(official)
            if numeric_mode == "full":
                numeric = _full_numeric_scan(path, handle)
    except Exception as exc:  # Rust binding exposes typed exceptions by version.
        parser_evidence["error"] = f"{type(exc).__name__}:{exc}"
        if parser_evidence["status"] == "PASS":
            parser_evidence["inventory_crosscheck_status"] = "FAIL"

    # The independent structural pass remains sampled and bounded. Production
    # full mode checks every supported floating value through official slices.
    manual = inspect_safetensors(path, expected_digest, numeric_mode="sampled")
    blockers = list(manual.get("blockers") or [])
    if numeric_mode == "full" and parser_evidence["status"] == "PASS":
        if numeric is not None:
            manual["numeric_values_checked"] = numeric["values_checked"]
            manual["non_finite_values"] = numeric["non_finite_values"]
            manual["numeric_scan_mode"] = "full"
            manual["official_tensors_accessed"] = numeric["official_tensors_accessed"]
            manual["official_numeric_chunks"] = numeric["official_numeric_chunks"]
            if numeric["non_finite_values"]:
                blockers.append("full_scan_non_finite_weights")
        else:
            manual["full_numeric_scan_error"] = parser_evidence.get("error") or "official_numeric_scan_missing"
            blockers.append("full_numeric_scan_failed")
    if parser_evidence["status"] != "PASS":
        blockers.append("official_safetensors_parser_rejected_artifact")
    if parser_evidence["inventory_crosscheck_status"] != "PASS":
        blockers.append("official_safetensors_inventory_crosscheck_failed")
    if actual_digest != expected_digest:
        blockers.append("artifact_digest_mismatch")
    blockers = sorted(set(blockers))
    manual.update({
        "status": "FAIL" if blockers else "PASS",
        "artifact_loaded": not blockers,
        "artifact_sha256": actual_digest,
        "official_parser": parser_evidence,
        "parser_authority": "official_safetensors_rust",
        "blockers": blockers,
    })
    manual.setdefault("known_answer_tests", []).extend([
        {
            "id": "official-parser-accepted-exact-artifact",
            "status": "PASS" if parser_evidence["status"] == "PASS" and actual_digest == expected_digest else "FAIL",
        },
        {
            "id": "official-parser-inventory-crosschecked",
            "status": parser_evidence["inventory_crosscheck_status"],
        },
    ])
    return manual


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifact")
    parser.add_argument("expected_digest")
    parser.add_argument("--numeric-mode", choices=("sampled", "full"), default="full")
    args = parser.parse_args()
    result = inspect_with_official_parser(
        Path(args.artifact),
        args.expected_digest,
        numeric_mode=args.numeric_mode,
    )
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
