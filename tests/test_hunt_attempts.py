"""The attempt index groups what Hunts already ran on a target, from the action ledger."""
from datetime import datetime, timedelta, timezone

import pytest

from api.hunt.attempts import AttemptQueryError, _filters, group_attempts

NOW = datetime(2026, 11, 17, 12, 0, tzinfo=timezone.utc)
MINE, THEIRS = "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"


def _action(number, *, hunt=MINE, capability="http.request", method="GET", path="/api/orders/41",
            status="completed", principal="anonymous"):
    values = {"method": method, "path": path} if path else {}
    return {"id": f"00000000-0000-4000-8000-{number:012d}", "hunt_run_id": hunt, "capability_name": capability,
            "status": status, "input_summary": {"input": values}, "principal": principal,
            "started_at": NOW - timedelta(minutes=number), "completed_at": NOW - timedelta(minutes=number)}


def test_requests_to_one_route_template_group_across_hunts_and_keep_their_outcomes():
    rows = [_action(1, path="/api/orders/43?debug=1"), _action(2, hunt=THEIRS, path="/api/orders/42", status="failed"),
            _action(3, hunt=THEIRS, path="/api/orders/41")]
    report = group_attempts(rows, current_hunt_id=MINE)
    [group] = report["rows"]
    assert group["route"] == "/api/orders/{id}" and group["method"] == "GET"
    assert (group["attempts"], group["this_hunt_attempts"], group["hunts"]) == (3, 1, 2)
    assert group["outcomes"] == {"completed": 2, "failed": 1}
    # The newest attempt describes the group; the query string is never part of a route.
    assert group["last_action_id"].endswith("000000000001") and group["last_by_this_hunt"] is True
    assert group["first_at"] == (NOW - timedelta(minutes=3)).isoformat()
    assert "debug" not in str(report)


def test_method_principal_and_capability_keep_attempts_apart():
    rows = [_action(1), _action(2, method="DELETE"), _action(3, principal="profile:x@v1/secondary/"),
            _action(4, capability="authz.verify", path=None)]
    keys = {(row["capability"], row["method"], row["principal"]) for row in group_attempts(rows)["rows"]}
    assert keys == {("http.request", "GET", "anonymous"), ("http.request", "DELETE", "anonymous"),
                    ("http.request", "GET", "profile:x@v1/secondary/"), ("authz.verify", None, "anonymous")}


def test_control_plane_actions_are_not_attempts():
    rows = [_action(1, capability="knowledge.record", path=None), _action(2, capability="hypothesis.propose", path=None),
            _action(3)]
    assert [row["capability"] for row in group_attempts(rows)["rows"]] == ["http.request"]


def test_filters_narrow_by_route_method_capability_and_whose_attempt():
    rows = [_action(1, path="/api/orders/1"), _action(2, hunt=THEIRS, path="/api/carts/9", method="POST"),
            _action(3, hunt=THEIRS, capability="authz.verify", path="/api/orders/1")]

    def routes(**filters):
        return [(row["capability"], row["route"]) for row in
                group_attempts(rows, current_hunt_id=MINE, filters=_filters(filters))["rows"]]

    assert routes(path_contains="CARTS") == [("http.request", "/api/carts/{id}")]
    assert routes(method="post") == [("http.request", "/api/carts/{id}")]
    assert routes(capability="authz.verify") == [("authz.verify", "/api/orders/{id}")]
    assert routes(by="this_hunt") == [("http.request", "/api/orders/{id}")]
    assert len(routes(by="other_hunts")) == 2


def test_the_report_is_bounded_and_says_when_groups_were_left_out():
    rows = [_action(number, path=f"/api/thing{number}/list") for number in range(1, 8)]
    report = group_attempts(rows, limit=3)
    assert (report["count"], report["groups_total"], report["has_more"]) == (3, 7, True)
    assert [row["route"] for row in report["rows"]] == ["/api/thing1/list", "/api/thing2/list", "/api/thing3/list"]


@pytest.mark.parametrize("filters", [{"since": "release"}, {"by": "everyone"}, {"method": ""}, {"path_contains": "x" * 201},
                                     {"capability": 7}])
def test_unknown_or_unbounded_filters_are_refused(filters):
    with pytest.raises(AttemptQueryError):
        _filters(filters)
