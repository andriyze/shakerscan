"""Behavioral regression tests for endpoint evaluation; no live target required.

Synthetic labels here are test inputs, not measured application facts. Live evaluate() is
tested at its production-filter boundary; it must not send fixture labels to the filter.
"""

import asyncio
import importlib.util
import json
import sys
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "endpoint_evaluation_under_test", ROOT / "scripts/evaluate_endpoint_reality.py",
)
evaluation = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(evaluation)


def row(path="/objects/1", *, template="/objects/{id}", sample="valid",
        route="real", production="kept", method="GET", auth="anonymous"):
    return {
        "request_sample": path, "route_template": template, "method": method,
        "auth_context": auth, "route_label": route, "sample_label": sample,
        "production": production, "entry": f"{method} {path}",
    }


def test_dropping_junk_is_not_losing_a_template_with_a_useful_representative():
    result = evaluation.score([
        row(), row("/objects/junk", sample="invalid", production="dropped"),
    ])
    assert result["known_template_count"] == 1
    assert result["known_templates_lost"] == []
    assert result["templates_losing_all_useful_samples"] == []
    assert result["template_retention_rate"] == 1
    assert result["useful_template_retention_rate"] == 1
    assert result["samples_of_known_templates"]["invalid"] == {"total": 1, "kept": 0, "dropped": 1}


def test_losing_every_sample_is_one_lost_template_not_two():
    result = evaluation.score([
        row(production="dropped"),
        row("/objects/junk", sample="invalid", production="dropped"),
    ])
    assert len(result["known_templates_lost"]) == 1
    assert result["known_templates_lost"][0]["samples"] == 2
    assert result["template_retention_rate"] == 0
    assert len(result["templates_losing_all_useful_samples"]) == 1


def test_retaining_only_junk_does_not_hide_loss_of_last_useful_sample():
    result = evaluation.score([
        row(production="dropped"), row("/objects/junk", sample="invalid"),
    ])
    assert result["known_templates_lost"] == []
    assert result["template_retention_rate"] == 1
    assert len(result["templates_losing_all_useful_samples"]) == 1
    assert result["useful_template_retention_rate"] == 0


def test_another_valid_sample_preserves_the_useful_representative():
    result = evaluation.score([row(production="dropped"), row("/objects/2")])
    assert result["templates_losing_all_useful_samples"] == []
    assert result["samples_of_known_templates"]["valid"]["dropped"] == 1


@pytest.mark.parametrize("sample", ["invalid", "unknown"])
def test_no_labeled_useful_samples_is_untested_not_success(sample):
    result = evaluation.score([row(sample=sample)])
    assert result["template_retention_rate"] == 1
    assert result["templates_with_useful_samples"] == 0
    assert result["useful_template_retention_rate"] is None
    assert len(result["templates_without_useful_samples"]) == 1


def test_losing_the_only_invalid_sample_still_loses_the_template_from_view():
    result = evaluation.score([row(sample="invalid", production="dropped")])
    assert len(result["known_templates_lost"]) == 1
    assert result["useful_template_retention_rate"] is None


def test_http_methods_have_independent_template_retention():
    result = evaluation.score([row(), row(method="POST", production="dropped")])
    assert result["distinct_route_templates"] == 2
    assert result["known_template_count"] == 2
    assert result["template_retention_rate"] == 0.5
    assert result["known_templates_lost"][0]["method"] == "POST"


def test_auth_contexts_have_independent_template_retention():
    result = evaluation.score([row(auth="principal-a"), row(auth="principal-b", production="dropped")])
    assert result["distinct_route_templates"] == 2
    assert result["template_retention_rate"] == 0.5
    assert result["known_templates_lost"][0]["auth_context"] == "principal-b"


def test_distinct_static_collections_are_not_inferred_as_one_parameter():
    result = evaluation.score([
        row("/api/users", template="/api/users", sample="not_parameterised"),
        row("/api/cards", template="/api/cards", sample="not_parameterised", production="dropped"),
    ])
    assert result["known_template_count"] == 2
    assert result["known_templates_lost"][0]["route_template"] == "/api/cards"


def test_client_route_loss_is_counted():
    result = evaluation.score([
        row("/#/search", template="/#/search", route="client_route",
            sample="not_parameterised", production="dropped"),
    ])
    assert len(result["known_templates_lost"]) == 1
    assert len(result["templates_losing_all_useful_samples"]) == 1


def test_unknown_sample_is_not_unknown_route_coverage():
    result = evaluation.score([row(sample="unknown")])
    assert result["unknown_route_evaluation"] == {
        "status": "not_tested", "total": 0, "kept": 0, "dropped": [], "drop_rate": None,
    }


def test_unknown_route_drop_has_a_real_denominator():
    result = evaluation.score([
        row("/unverified/one", template="/unverified/one", route="unknown", sample="unknown", production="dropped"),
        row("/unverified/two", template="/unverified/two", route="unknown", sample="unknown"),
    ])
    unknown = result["unknown_route_evaluation"]
    assert unknown["status"] == "tested"
    assert unknown["total"] == 2 and unknown["kept"] == 1
    assert len(unknown["dropped"]) == 1 and unknown["drop_rate"] == 0.5
    assert result["known_template_count"] == 0


def test_retaining_unknown_does_not_count_as_proving_a_known_route():
    result = evaluation.score([row(route="unknown", sample="unknown")])
    assert result["unknown_route_evaluation"]["drop_rate"] == 0
    assert result["known_template_count"] == 0
    assert result["template_retention_rate"] is None


def test_absent_samples_are_separate_from_known_template_junk():
    result = evaluation.score([row(route="absent", sample="invalid", production="dropped")])
    assert len(result["absent_dropped"]) == 1
    assert result["known_template_count"] == 0
    assert result["samples_of_known_templates"]["invalid"]["total"] == 0


def test_empty_evaluation_has_no_success_rates():
    result = evaluation.score([])
    assert result["entries"] == 0
    assert result["template_retention_rate"] is None
    assert result["useful_template_retention_rate"] is None
    assert result["unknown_route_evaluation"]["status"] == "not_tested"


def test_fixture_contains_explicit_unknown_routes_not_just_unknown_samples():
    sample = json.loads(evaluation.DEFAULT_SAMPLE.read_text(encoding="utf-8"))
    entries = evaluation.validated_entries(sample["entries"])
    unknown = [e for e in entries if e["route_label"] == "unknown"]
    assert len(unknown) >= 2
    assert all(e["basis"] for e in unknown)
    result = evaluation.score([{**e, "production": "kept"} for e in entries])
    assert result["unknown_route_evaluation"]["total"] == len(unknown)
    assert result["unknown_route_evaluation"]["status"] == "tested"


def test_score_does_not_mutate_input_and_normalizes_defaults():
    original = row(method=" get ")
    del original["auth_context"]
    before = deepcopy(original)
    result = evaluation.score([original])
    assert original == before
    assert result["known_template_count"] == 1
    assert evaluation.validated_entries([original])[0]["method"] == "GET"


@pytest.mark.parametrize("field,value", [
    ("route_label", "typo"), ("sample_label", "typo"),
    ("route_label", []), ("sample_label", {}), ("production", []),
    ("production", None), ("method", "NOPE"), ("auth_context", ""),
    ("route_template", ""), ("request_sample", "https://outside.test/path"),
    ("request_sample", "//outside.test/path"), ("request_sample", "/x\nGET /y"),
])
def test_invalid_inputs_cannot_silently_produce_metrics(field, value):
    entry = row()
    entry[field] = value
    with pytest.raises(ValueError):
        evaluation.score([entry])


def test_contradictory_template_labels_are_rejected():
    with pytest.raises(ValueError, match="conflicting route labels"):
        evaluation.score([row(), row("/objects/2", route="absent")])


def test_duplicate_requests_cannot_inflate_denominators():
    with pytest.raises(ValueError, match="duplicate request sample"):
        evaluation.score([row(), row()])


def test_evaluate_calls_the_production_entry_point_without_answer_key_labels(monkeypatch):
    captured = {}

    async def production_filter(base_url, worklist, options, **kwargs):
        captured.update(base_url=base_url, worklist=worklist, options=options, kwargs=kwargs)
        return worklist[:1]

    monkeypatch.setitem(sys.modules, "asm_inventory", SimpleNamespace(filter_reachable_worklist=production_filter))
    entries = [row(), row("/objects/junk", sample="invalid")]
    before = deepcopy(entries)
    results = asyncio.run(evaluation.evaluate("http://fixture.test", entries, max_probe=3))
    assert captured == {
        "base_url": "http://fixture.test", "worklist": ["GET /objects/1", "GET /objects/junk"],
        "options": None, "kwargs": {"max_probe": 3},
    }
    assert [r["production"] for r in results] == ["kept", "dropped"]
    assert evaluation.score(results)["known_templates_lost"] == []
    assert entries == before


def test_live_evaluation_rejects_unsupported_auth_before_probing(monkeypatch):
    async def must_not_probe(*args, **kwargs):
        pytest.fail("non-anonymous fixture was silently probed anonymously")

    monkeypatch.setitem(sys.modules, "asm_inventory", SimpleNamespace(filter_reachable_worklist=must_not_probe))
    with pytest.raises(ValueError, match="anonymous auth_context only"):
        asyncio.run(evaluation.evaluate("http://fixture.test", [row(auth="principal-a")]))


@pytest.mark.parametrize("unknown_cases", [False, True])
def test_cli_reports_unknown_coverage_and_template_loss(monkeypatch, capsys, unknown_cases):
    entries = [row(), row("/objects/junk", sample="invalid", production="dropped")]
    if unknown_cases:
        entries.append(row("/unverified", template="/unverified", route="unknown", sample="unknown", production="dropped"))

    async def measured(*args, **kwargs):
        return entries

    monkeypatch.setattr(evaluation, "evaluate", measured)
    monkeypatch.setattr(sys, "argv", ["evaluate_endpoint_reality.py", "--base-url", "http://fixture.test"])
    assert evaluation.main() == 0
    output = capsys.readouterr().out
    assert "known templates lost           : 0/1" in output
    assert "last useful representative lost: 0/1" in output
    if unknown_cases:
        assert "unknown-route samples dropped  : 1/1" in output
        assert "UNSUPPORTED DROP: GET /unverified" in output
    else:
        assert "NOT TESTED (0 labeled cases)" in output


def test_cli_json_has_versioned_nonvacuous_unknown_coverage(monkeypatch, capsys):
    async def measured(*args, **kwargs):
        return [row(sample="unknown")]

    monkeypatch.setattr(evaluation, "evaluate", measured)
    monkeypatch.setattr(sys, "argv", ["evaluate_endpoint_reality.py", "--base-url", "http://fixture.test", "--json"])
    assert evaluation.main() == 0
    summary = json.loads(capsys.readouterr().out)["summary"]
    assert summary["schema_version"] == "endpoint-reality-score/v2"
    assert summary["unknown_route_evaluation"]["drop_rate"] is None
