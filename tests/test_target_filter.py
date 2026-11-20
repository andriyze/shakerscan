"""The repeated target_id filter: one id, several, comma-separated, refused when not a UUID."""
from __future__ import annotations

import uuid

import pytest
from fastapi import HTTPException
from fastapi.params import Query

from api.scan_list_filters import scan_list_filters
from api.target_filter import parse_target_ids

A, B = uuid.uuid4(), uuid.uuid4()


def test_one_several_and_comma_separated_ids_parse_in_order_without_repeats():
    assert parse_target_ids(str(A)) == [A]
    assert parse_target_ids([str(A), str(B), str(A)]) == [A, B]
    assert parse_target_ids([f"{B}, {A}"]) == [B, A]
    assert parse_target_ids(None) is None and parse_target_ids([]) is None and parse_target_ids([" , "]) is None
    # A route function called directly receives its Query(...) default: no filter.
    assert parse_target_ids(Query(None)) is None


def test_a_bad_id_or_too_many_ids_are_refused():
    with pytest.raises(HTTPException) as bad:
        parse_target_ids(["not-a-uuid"])
    assert bad.value.status_code == 400 and "target_id must be a UUID" in bad.value.detail
    with pytest.raises(HTTPException, match=None) as many:
        parse_target_ids([str(uuid.uuid4()) for _ in range(501)])
    assert "at most 500" in many.value.detail


def test_the_scan_list_filter_uses_equality_for_one_id_and_any_for_several():
    sql, values = scan_list_filters(target_id=str(A))
    assert "s.target_id = $1" in sql and values == [A]
    sql, values = scan_list_filters(target_id=[str(A), str(B)])
    assert "s.target_id = ANY($1::uuid[])" in sql and values == [[A, B]]
    with pytest.raises(ValueError, match="target_id must be a UUID"):
        scan_list_filters(target_id=["nope"])
