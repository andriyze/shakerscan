"""Serialized objects a page hands its client (ported from scanner_tools/deserialization_tests)."""
from __future__ import annotations

from api.hunt.serialization_signals import serialized_formats


def test_each_format_is_recognised_where_a_client_receives_it():
    assert serialized_formats('<input type="hidden" name="state" value="rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH">') == ["java"]
    assert serialized_formats('{"token":"gASVKAAAAAAAAACMCGJ1aWx0aW5zlIwFZXZhbJSTlC4="}') == ["python_pickle"]
    assert serialized_formats('<a href="/cart?data=O:8:%22stdClass%22:1:{}">') == ["php"]
    assert serialized_formats("AAEAAAD/////AQAAAAAAAAAMAgAAAE") == ["dotnet_binaryformatter"]


def test_ordinary_pages_and_documentation_are_not_serialized_objects():
    assert serialized_formats('<p>PHP serializes objects as O:8:"stdClass":0:{}</p>') == []
    assert serialized_formats("<p>rO0AB</p><script>var a='gASV';</script>") == []
