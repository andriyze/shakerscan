"""Offline regressions for the value-free crawler body-shape boundary."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from unittest.mock import patch

import pytest


# Keep this suite independent of the API/database/browser startup. The module
# under test deliberately has only standard-library dependencies.
_SOURCE = Path(__file__).resolve().parents[1] / "api" / "runtime" / "request_shape.py"
_SPEC = importlib.util.spec_from_file_location("request_shape_integrity", _SOURCE)
assert _SPEC is not None and _SPEC.loader is not None
shape = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(shape)


@pytest.mark.parametrize("value", [
    '"SYNTHETIC_PRIVATE_VALUE=42"',
    '["SYNTHETIC_PRIVATE_VALUE=42"]',
    '[{"label":"SYNTHETIC_PRIVATE_VALUE=42"}]',
    '  ["SYNTHETIC_PRIVATE_VALUE=42"]  ',
    '"SYNTHETIC_PRIVATE_VALUE&label=42"',
    '{"label":"SYNTHETIC_PRIVATE_VALUE=42"',
    '["SYNTHETIC_PRIVATE_VALUE=42"',
    '"SYNTHETIC_PRIVATE_VALUE=42',
])
def test_non_object_or_malformed_json_never_becomes_form_fields(value):
    assert shape.public_request_body_shape(value) == (None, ())


@pytest.mark.parametrize("value", [
    None, b"label=SYNTHETIC_PRIVATE_VALUE",
    bytearray(b"label=SYNTHETIC_PRIVATE_VALUE"),
    {"label": "SYNTHETIC_PRIVATE_VALUE=42"},
    ["SYNTHETIC_PRIVATE_VALUE=42"], 42, False,
])
def test_non_text_crawler_values_are_not_stringified(value):
    assert shape.public_request_body_shape(value) == (None, ())


def test_untrusted_object_string_conversion_is_not_called():
    class UntrustedValue:
        def __str__(self):
            raise AssertionError("unexpected string conversion")

    assert shape.public_request_body_shape(UntrustedValue()) == (None, ())


def test_json_decoder_depth_failure_is_contained_without_form_fallback():
    # A small, deterministic test independent of the interpreter recursion limit.
    with patch.object(shape.json, "loads", side_effect=RecursionError):
        assert shape.public_request_body_shape('{"label":"private=value"}') == (None, ())


@pytest.mark.parametrize("value, expected", [
    ('{"label":"SYNTHETIC_PRIVATE_VALUE=42","enabled":true}',
     ("application/json", ("enabled", "label"))),
    ('{"nested":{"private":"SYNTHETIC_PRIVATE_VALUE"},"count":3}',
     ("application/json", ("count", "nested"))),
    ('label=SYNTHETIC_PRIVATE_VALUE&empty=',
     ("application/x-www-form-urlencoded", ("empty", "label"))),
    ('label=one&label=two&sort%5Border%5D=ascending',
     ("application/x-www-form-urlencoded", ("label", "sort[order]"))),
    # Do not regress the existing form parser's acceptance of empty values.
    ('label=one&flag', ("application/x-www-form-urlencoded", ("flag", "label"))),
    ('label=%7B%22private%22%3A%22value%22%7D',
     ("application/x-www-form-urlencoded", ("label",))),
    ('{}', (None, ())), ('[]', (None, ())), ('null', (None, ())),
    ('true', (None, ())), ('123', (None, ())), ('', (None, ())),
])
def test_existing_valid_and_empty_shapes_are_preserved(value, expected):
    assert shape.public_request_body_shape(value) == expected


def test_field_values_do_not_appear_in_serialized_shape():
    result = shape.public_request_body_shape(json.dumps({
        "label": "SYNTHETIC_PRIVATE_VALUE",
        "nested": {"private": "ANOTHER_SYNTHETIC_VALUE"},
    }))
    encoded = json.dumps(result)
    assert "SYNTHETIC_PRIVATE_VALUE" not in encoded
    assert "ANOTHER_SYNTHETIC_VALUE" not in encoded
    assert result == ("application/json", ("label", "nested"))


def test_existing_field_name_filters_are_preserved():
    value = json.dumps({"": "x", "valid": "x", "bad\nname": "x", "x" * 201: "x"})
    assert shape.public_request_body_shape(value) == ("application/json", ("valid",))


def test_exact_ascii_byte_limit_is_still_accepted():
    prefix = 'label='
    value = prefix + 'x' * (shape.MAX_REQUEST_BODY_SHAPE_BYTES - len(prefix))
    assert shape.public_request_body_shape(value) == (
        "application/x-www-form-urlencoded", ("label",),
    )


def test_oversized_text_is_rejected_before_json_decode():
    with patch.object(shape.json, "loads", side_effect=AssertionError("must not decode")):
        assert shape.public_request_body_shape('x' * (shape.MAX_REQUEST_BODY_SHAPE_BYTES + 1)) == (None, ())


def test_utf8_byte_limit_is_not_a_character_limit():
    value = 'label=' + '\u00e9' * (shape.MAX_REQUEST_BODY_SHAPE_BYTES // 2)
    assert len(value) < shape.MAX_REQUEST_BODY_SHAPE_BYTES
    assert shape.public_request_body_shape(value) == (None, ())


def test_json_field_count_limit_is_preserved():
    value = json.dumps({f"field_{n:03}": "x" for n in range(shape.MAX_REQUEST_BODY_FIELDS + 1)})
    content_type, names = shape.public_request_body_shape(value)
    assert content_type == "application/json"
    assert len(names) == shape.MAX_REQUEST_BODY_FIELDS


def test_form_field_count_limit_is_preserved():
    value = '&'.join(f'field_{n}=x' for n in range(shape.MAX_REQUEST_BODY_FIELDS + 1))
    assert shape.public_request_body_shape(value) == (None, ())
