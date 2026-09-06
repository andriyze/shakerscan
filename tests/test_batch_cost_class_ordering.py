"""An expensive body candidate must never displace a cheaper candidate's verdict in a batch.

R1 (2.3.0): a ranked verifier slice mixes cheap query/path candidates (sqlmap query floor ~30s /
160 requests) with expensive body candidates (~420s / 480 requests). The manifest is ranked by
score, and a high-scoring body candidate can outrank a query candidate; funding it first consumed
the wall that the query verdict needed. Measured 2026-09-05: adding one login-body candidate to
Juice Shop's SQLi family took recall 0.44 -> 0.33 because the products-search query verdict was
displaced. The batch now attempts cheaper cost classes first, so an expensive attempt runs only on
the budget cheaper verdicts did not need.
"""
from __future__ import annotations

from api.scan.external_process import (
    batch_attempt_floor,
    batch_row_cost_class,
    order_batch_rows_by_cost_class,
)


def _query(score: int, name: str = "q") -> dict:
    return {"candidate_id": f"query-{score}", "method": "GET",
            "parameter_name": name, "parameter_location": "query", "score": score}


def _body(score: int, name: str = "email") -> dict:
    return {"candidate_id": f"body-{score}", "method": "POST",
            "parameter_name": name, "parameter_location": "body",
            "body_field_names": ["email", "password"], "score": score}


def test_cost_class_puts_query_before_body():
    assert batch_row_cost_class(_query(40)) == 0
    assert batch_row_cost_class(_body(46)) == 1
    # A path candidate is a cheap class too.
    assert batch_row_cost_class({"method": "GET", "parameter_location": "path"}) == 0


def test_a_higher_scored_body_candidate_is_attempted_after_a_cheaper_query():
    # The exact regression shape: the body candidate outscores the query one.
    rows = list(enumerate([_body(46), _query(40)]))
    ordered = order_batch_rows_by_cost_class(rows)
    kinds = [batch_row_cost_class(candidate) for _index, candidate in ordered]
    assert kinds == [0, 1], "the cheaper query candidate must be attempted first"
    # The original manifest indices are preserved so resume and slice accounting are unchanged.
    assert {index for index, _ in ordered} == {0, 1}


def test_score_order_is_preserved_within_a_cost_class():
    rows = list(enumerate([_query(20), _body(50), _query(40), _body(30)]))
    ordered = [candidate["candidate_id"] for _index, candidate in order_batch_rows_by_cost_class(rows)]
    # Queries first in their original (score) order, then bodies in theirs.
    assert ordered == ["query-20", "query-40", "body-50", "body-30"]


def test_body_floor_is_the_expensive_class_and_dwarfs_the_query_floor():
    query = batch_attempt_floor("sqli.verify_batch", body_candidate=False)
    body = batch_attempt_floor("sqli.verify_batch", body_candidate=True)
    assert body["tool_wall_seconds"] > query["tool_wall_seconds"] * 5
    # So on a bounded wall, one body attempt can starve several query verdicts; ordering prevents it.
    assert body["tool_wall_seconds"] // query["tool_wall_seconds"] >= 10
