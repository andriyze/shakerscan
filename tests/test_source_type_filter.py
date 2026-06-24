"""R8: first-class findings source_type taxonomy.

Locks in that model_intake (and the AI sources) filter SEPARATELY from dast, and
that the granular values are distinct. Imports the api module, so it runs where
the API deps are available (the scanner runtime image).
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

import api as api_module  # noqa: E402

f = api_module._source_type_filter_sql


def test_model_intake_separates_from_dast_and_ai():
    mi, dast, ai_gate = f("model_intake"), f("dast"), f("ai_gate")
    assert "model_intake" in mi
    assert mi != dast and mi != ai_gate
    # dast explicitly excludes model_intake and the AI sources
    assert "NOT IN" in dast and "model_intake" in dast and "ai_gate" in dast


def test_granular_values_are_distinct():
    assert f("ai_gate") == " AND f.source = 'ai_gate'"
    assert f("ai_session") == " AND f.source = 'ai_session'"
    assert f("asm") == " AND f.source = 'asm'"
    assert f("manual") == " AND f.source = 'manual'"
    assert f("ai_gate") != f("ai_session")


def test_ai_umbrella_covers_gate_and_session():
    ai = f("ai")
    assert "ai_gate" in ai and "ai_session" in ai and "ai_target_id" in ai


def test_unknown_or_none_is_empty():
    assert f(None) == ""
    assert f("") == ""
    assert f("bogus") == ""
