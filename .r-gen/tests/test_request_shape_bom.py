"""BOM-prefixed JSON must never publish a value as a form-field name."""
import importlib.util
from pathlib import Path
import pytest

_SOURCE = Path(__file__).resolve().parents[1] / "api" / "runtime" / "request_shape.py"
_SPEC = importlib.util.spec_from_file_location("request_shape_bom", _SOURCE)
assert _SPEC is not None and _SPEC.loader is not None
shape = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(shape)


@pytest.mark.parametrize("value", [
    '\ufeff{"label":"PRIVATE_VALUE=42"}',
    '\ufeff["PRIVATE_VALUE=42"]',
    ' \ufeff"PRIVATE_VALUE=42"',
])
def test_bom_json_does_not_fall_through_to_form_parsing(value):
    assert shape.public_request_body_shape(value) == (None, ())
