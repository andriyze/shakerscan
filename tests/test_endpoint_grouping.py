"""Grouping must collapse repetition without merging distinct routes or losing samples.

The measured cases these encode: `/api/Cards` children answered with 2 distinct statuses across
371 siblings (one `{id}` handler), while `/api` children answered with 5 across 462 (many real
collections). Agreement is the evidence; disagreement must block the merge.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))

from hunt.endpoint_grouping import (  # noqa: E402
    HOMOGENEOUS_SIBLINGS,
    ID_SHAPED,
    SPEC_DECLARED,
    UNGROUPED,
    group_endpoint_rows,
)


def row(path, *, method="GET", auth="anonymous", status=401, ident=None, verdict=None, shape=""):
    return {
        "id": ident or path, "method": method, "auth_state": auth, "path": path,
        "last_http_status": status, "last_verdict": verdict, "param_shape": shape,
        "test_status": "untested",
    }


def by_template(groups):
    return {g.template: g for g in groups}


def test_junk_samples_of_one_handler_collapse_into_a_template():
    rows = [row("/api/Cards")] + [
        row(f"/api/Cards/{name}") for name in ("search", "admin", "2fa", "coupon", "basket")
    ]
    groups = by_template(group_endpoint_rows(rows))
    assert "/api/Cards/{param}" in groups
    collapsed = groups["/api/Cards/{param}"]
    assert collapsed.sample_count == 5
    assert collapsed.evidence == HOMOGENEOUS_SIBLINGS
    # The collection itself stays its own route.
    assert "/api/Cards" in groups


def test_distinct_collections_are_never_merged_when_responses_disagree():
    """/api children answered with many statuses: they are separate handlers, not one {id}."""
    rows = [row("/api")] + [
        row("/api/Users", status=401), row("/api/Cards", status=400),
        row("/api/Feedbacks", status=200), row("/api/Quantitys", status=500),
        row("/api/Hints", status=404),
    ]
    groups = by_template(group_endpoint_rows(rows))
    for collection in ("/api/Users", "/api/Cards", "/api/Feedbacks"):
        assert collection in groups, f"{collection} was merged away"
    assert "/api/{param}" not in groups


def test_an_id_shaped_segment_groups_without_needing_siblings():
    rows = [row("/rest/basket"), row("/rest/basket/1"), row("/rest/basket/2")]
    groups = by_template(group_endpoint_rows(rows))
    assert groups["/rest/basket/{id}"].evidence == ID_SHAPED
    assert groups["/rest/basket/{id}"].sample_count == 2


def test_a_specification_template_is_the_strongest_evidence():
    rows = [row("/api/Orders"), row("/api/Orders/abc")]
    groups = by_template(group_endpoint_rows(rows, spec_templates=["/api/Orders/{id}"]))
    assert groups["/api/Orders/{id}"].evidence == SPEC_DECLARED


def test_methods_and_auth_contexts_are_never_merged():
    rows = [
        row("/api/Cards/1", method="GET", auth="anonymous"),
        row("/api/Cards/2", method="POST", auth="anonymous"),
        row("/api/Cards/3", method="GET", auth="user1"),
    ]
    groups = group_endpoint_rows(rows)
    keys = {(g.method, g.auth_state, g.template) for g in groups}
    assert keys == {
        ("GET", "anonymous", "/api/Cards/{id}"),
        ("POST", "anonymous", "/api/Cards/{id}"),
        ("GET", "user1", "/api/Cards/{id}"),
    }


def test_no_sample_is_ever_discarded_so_grouping_is_reversible():
    rows = [row("/api/Cards")] + [
        row(f"/api/Cards/{n}", ident=f"id-{n}") for n in ("search", "admin", "2fa", "coupon")
    ]
    groups = by_template(group_endpoint_rows(rows))
    collapsed = groups["/api/Cards/{param}"]
    assert sorted(collapsed.sample_ids) == ["id-2fa", "id-admin", "id-coupon", "id-search"]
    assert collapsed.sample_count == len(collapsed.sample_ids)


def test_identical_requests_collapse_and_are_reported():
    rows = [row("/rest/products/search", ident="a"), row("/rest/products/search", ident="b")]
    groups = by_template(group_endpoint_rows(rows))
    group = groups["/rest/products/search"]
    assert group.sample_count == 1
    assert any("identical request" in q for q in group.open_questions)


def test_an_unparameterised_path_keeps_its_own_identity():
    groups = by_template(group_endpoint_rows([row("/rest/products/search")]))
    assert groups["/rest/products/search"].evidence == UNGROUPED


def test_a_group_carries_prior_results_and_open_questions():
    rows = [row("/api/Cards")] + [
        row(f"/api/Cards/{n}", verdict="findings" if n == "search" else None)
        for n in ("search", "admin", "2fa", "coupon")
    ]
    group = by_template(group_endpoint_rows(rows))["/api/Cards/{param}"]
    assert group.prior_results.get("findings") == 1
    assert group.prior_results.get("untested") == 3
    assert any("sibling responses" in q for q in group.open_questions)
    assert any("only observed anonymously" in q for q in group.open_questions)


def test_a_child_with_its_own_children_is_a_namespace_not_an_identifier():
    rows = [
        row("/api"), row("/api/v1"), row("/api/v2"), row("/api/v3"), row("/api/v4"),
        row("/api/v1/users"),
    ]
    groups = by_template(group_endpoint_rows(rows))
    # /api/v1 has a child, so it must not be swallowed as an identifier of /api.
    assert "/api/v1" in groups
