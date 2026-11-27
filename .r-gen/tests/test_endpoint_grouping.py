"""Grouping preserves literal routes, all evidence, and an exploration frontier."""

import random

import pytest

from api.hunt.endpoint_grouping import ID_SHAPED, SPEC_DECLARED, UNGROUPED, group_endpoint_rows


def row(path, *, method="GET", auth="anonymous", status=200, ident=None,
        verdict=None, shape="", location="query", content_type="", tested="untested"):
    return {
        "id": ident or path, "method": method, "auth_state": auth, "path": path,
        "last_http_status": status, "last_verdict": verdict, "param_shape": shape,
        "param_location": location, "content_type": content_type, "test_status": tested,
    }


def by_template(rows, **kwargs):
    return {g.template: g for g in group_endpoint_rows(rows, **kwargs)}


@pytest.mark.parametrize("status", [200, 401, 403, None])
def test_equal_statuses_never_merge_distinct_literal_collections(status):
    paths = ["/api", "/api/Users", "/api/Cards", "/api/Feedbacks", "/api/Orders"]
    assert set(by_template([row(path, status=status) for path in paths])) == set(paths)


def test_wordlist_siblings_are_not_route_templates_without_evidence():
    paths = ["/api/cards"] + [f"/api/cards/{name}" for name in ("search", "admin", "export", "coupon")]
    groups = group_endpoint_rows([row(path, status=401) for path in paths])
    assert {g.template for g in groups} == set(paths)
    assert all(g.evidence == UNGROUPED for g in groups)


def test_namespace_survives_even_when_other_siblings_qualify_for_old_merge():
    paths = ["/api", "/api/v1", "/api/v1/users"] + [f"/api/v{i}" for i in range(2, 8)]
    assert set(by_template([row(path) for path in paths])) == set(paths)


def test_identifier_namespace_is_not_swallowed():
    paths = ["/reports/2024", "/reports/2024/annual", "/reports/2025"]
    assert "/reports/2024" in by_template([row(path) for path in paths])


def test_identifier_grouping_is_explicitly_tentative_and_reversible():
    group = by_template([row("/items/1", ident="a"), row("/items/2", ident="b")])["/items/{id}"]
    assert group.evidence == ID_SHAPED
    assert group.as_row()["grouping_inferred"] is True
    assert group.sample_ids == ["a", "b"]
    assert group.sample_count == group.member_count == 2


def test_eight_hex_character_route_name_is_not_an_identifier():
    assert "/api/deadbeef" in by_template([row("/api/deadbeef")])


def test_specification_literal_wins_over_parameter_template():
    groups = by_template([row("/items/search"), row("/items/abc")],
                         spec_templates=["/items/search", "/items/{id}"])
    assert set(groups) == {"/items/search", "/items/{id}"}
    assert all(g.evidence == SPEC_DECLARED for g in groups.values())


def test_slashes_and_client_routes_are_not_silently_normalized():
    paths = ["/items/1", "/items/1/", "/#/view/1", "/#/view/2", "/items", "/items/"]
    groups = group_endpoint_rows([row(path) for path in paths])
    assert len(groups) == len(paths)
    assert {r["path"] for g in groups for r in g.representatives} == set(paths)


def test_methods_principals_body_shapes_locations_and_types_stay_distinct():
    variants = [{}, {"method": "POST"}, {"auth": "user1"}, {"shape": "email"},
                {"location": "json"}, {"content_type": "application/json"}]
    groups = group_endpoint_rows([row("/items/1", ident=str(i), **v) for i, v in enumerate(variants)])
    assert len(groups) == len(variants)
    assert len({g.as_row()["group_id"] for g in groups}) == len(variants)


def test_json_and_form_with_same_field_names_keep_both_results():
    groups = group_endpoint_rows([
        row("/login", method="POST", shape="email,password", location="json",
            content_type="application/json", ident="json", verdict="clean", tested="tested"),
        row("/login", method="POST", shape="email,password", location="form",
            content_type="application/x-www-form-urlencoded", ident="form", verdict="findings"),
    ])
    assert len(groups) == 2
    assert {member for g in groups for member in g.sample_ids} == {"json", "form"}
    assert groups[0].prior_results == {"findings": 1}


def test_duplicate_ids_and_later_findings_are_never_discarded():
    groups = group_endpoint_rows([
        row("/items/1", ident="a", verdict="clean", tested="tested"),
        row("/items/1", ident="b", verdict="findings", tested="tested"),
    ])
    group = groups[0]
    assert group.sample_ids == ["a", "b"]
    assert group.prior_results == {"clean": 1, "findings": 1}
    assert group.sample_count == 1 and group.member_count == 2
    assert group.representatives[0]["id"] == "b"
    assert group.as_row()["duplicate_count"] == 1


def test_representatives_prefer_leads_but_all_samples_remain_accessible():
    rows = [row(f"/items/{i}", ident=str(i)) for i in range(10)]
    rows[-1]["last_verdict"] = "findings"
    group = group_endpoint_rows(rows)[0]
    assert len(group.representatives) == 3
    assert group.representatives[0]["id"] == "9"
    assert len(group.sample_ids) == len(rows)


def test_unexplored_routes_are_not_starved_by_leads_or_clean_history():
    rows = [row(f"/known{i}", verdict="findings", tested="tested") for i in range(20)]
    rows += [row(f"/new{i}") for i in range(5)]
    rows += [row(f"/clean{i}", verdict="clean", tested="tested") for i in range(20)]
    ordered = group_endpoint_rows(rows)
    assert [g.frontier_state for g in ordered[:6]] == ["unresolved_lead", "unexplored"] * 3
    assert all(g.frontier_state == "settled" for g in ordered[-20:])


def test_parameterized_routes_are_not_blanket_deprioritized():
    rows = [row("/a/1")] + [row(f"/z{i}") for i in range(50)]
    assert group_endpoint_rows(rows)[0].template == "/a/{id}"


def test_clean_only_history_does_not_outrank_unexplored_work():
    rows = [row("/clean", verdict="clean", tested="tested"), row("/new")]
    assert [g.template for g in group_endpoint_rows(rows)] == ["/new", "/clean"]


def test_repeated_discovery_does_not_change_frontier_rank():
    base = [row("/a"), row("/z")]
    repeated = base + [row("/z", ident=str(i)) for i in range(20)]
    assert [g.template for g in group_endpoint_rows(base)] == [g.template for g in group_endpoint_rows(repeated)]


def test_order_ids_representatives_and_results_are_input_order_independent():
    rows = [row(f"/items/{i}", ident=str(i), verdict="findings" if i % 2 else None) for i in range(10)]
    rows += [row("/items/1", ident="duplicate", verdict="clean", tested="tested")]
    expected = [g.as_row() for g in group_endpoint_rows(rows)]
    random.Random(27).shuffle(rows)
    assert [g.as_row() for g in group_endpoint_rows(rows)] == expected


@pytest.mark.parametrize("limit", [0, -1, 11, True, "3"])
def test_representative_limit_is_bounded(limit):
    with pytest.raises(ValueError):
        group_endpoint_rows([], representatives_per_group=limit)
