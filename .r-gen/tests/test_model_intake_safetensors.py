import hashlib
import json
import struct

from scanner.scanner_tools import model_intake
from scanner.scanner_tools.model_intake_runtime import inspect_safetensors, inspect_safetensors_layout


def _artifact(header, payload=b""):
    raw = json.dumps(header, separators=(",", ":")).encode("utf-8")
    return len(raw).to_bytes(8, "little") + raw + payload


def _write(tmp_path, content):
    path = tmp_path / "model.safetensors"
    path.write_bytes(content)
    return path, hashlib.sha256(content).hexdigest()


def test_complete_valid_layout_and_bf16_finiteness_pass(tmp_path):
    content = _artifact(
        {"weight": {"dtype": "BF16", "shape": [2], "data_offsets": [0, 4]}},
        struct.pack("<HH", 0x3F80, 0x0000),
    )
    path, digest = _write(tmp_path, content)

    layout = inspect_safetensors_layout(path)
    runtime = inspect_safetensors(path, digest)

    assert layout["status"] == "PASS"
    assert layout["payload_coverage_complete"] is True
    assert runtime["status"] == "PASS"
    assert runtime["sampled_values"] == 2


def test_shape_byte_span_mismatch_fails_all_parsing_paths(tmp_path):
    content = _artifact(
        {"weight": {"dtype": "F32", "shape": [2], "data_offsets": [0, 4]}},
        b"\0" * 4,
    )
    path, digest = _write(tmp_path, content)

    layout = inspect_safetensors_layout(path)
    runtime = inspect_safetensors(path, digest)
    intake = model_intake._inspect_safetensors(content)

    assert layout["status"] == "FAIL"
    assert layout["invalid_tensors"][0]["reason"] == "shape_byte_span_mismatch"
    assert runtime["status"] == "FAIL"
    assert intake["valid"] is False
    assert intake["invalid_tensors"][0]["reason"] == "shape_byte_span_mismatch"


def test_overlap_gaps_and_trailing_payload_are_not_accepted(tmp_path):
    overlap = _artifact({
        "a": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]},
        "b": {"dtype": "F32", "shape": [1], "data_offsets": [2, 6]},
    }, b"\0" * 6)
    path, _digest = _write(tmp_path, overlap)
    assert "overlapping_tensor_spans" in inspect_safetensors_layout(path)["coverage_errors"]

    trailing = _artifact(
        {"a": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]}},
        b"\0" * 8,
    )
    path, digest = _write(tmp_path, trailing)
    layout = inspect_safetensors_layout(path)
    runtime = inspect_safetensors(path, digest)
    assert layout["status"] == "FAIL"
    assert "unexplained_trailing_payload" in layout["coverage_errors"]
    assert runtime["payload_coverage_complete"] is False


def test_unknown_dtype_and_unmeasured_float_tensor_fail_closed(tmp_path):
    unknown = _artifact(
        {"weight": {"dtype": "CORP42", "shape": [1], "data_offsets": [0, 1]}},
        b"\0",
    )
    path, digest = _write(tmp_path, unknown)
    assert inspect_safetensors_layout(path)["status"] == "UNSUPPORTED"
    assert inspect_safetensors(path, digest)["status"] != "PASS"

    empty_float = _artifact(
        {"weight": {"dtype": "F32", "shape": [0], "data_offsets": [0, 0]}},
    )
    path, digest = _write(tmp_path, empty_float)
    runtime = inspect_safetensors(path, digest)
    finiteness = next(item for item in runtime["known_answer_tests"] if item["id"] == "sampled-numeric-finiteness")
    assert runtime["status"] == "FAIL"
    assert finiteness["status"] == "NOT_MEASURED"


def test_non_finite_bf16_and_duplicate_header_keys_fail(tmp_path):
    non_finite = _artifact(
        {"weight": {"dtype": "BF16", "shape": [1], "data_offsets": [0, 2]}},
        struct.pack("<H", 0x7F80),
    )
    path, digest = _write(tmp_path, non_finite)
    runtime = inspect_safetensors(path, digest)
    assert runtime["status"] == "FAIL"
    assert runtime["non_finite_values"] == 1

    raw_header = b'{"weight":{"dtype":"F32","shape":[1],"data_offsets":[0,4]},"weight":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}'
    duplicate = len(raw_header).to_bytes(8, "little") + raw_header + b"\0" * 4
    path, _digest = _write(tmp_path, duplicate)
    assert inspect_safetensors_layout(path)["status"] == "FAIL"

