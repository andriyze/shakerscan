"""The Hunt skill library must never advertise authority or work it cannot deliver."""

import pytest

from api.hunt.skills import (
    MAX_SKILLS_PER_HUNT,
    SKILL_BUDGET_DIMENSIONS,
    HuntSkillError,
    HuntSkillLibrary,
    bind_skills_to_hunt,
    build_skill_spec,
    load_skill_library,
)
from api.hunt.start_contract import MAX_SKILLS
from api.runtime.capability_registry import CAPABILITY_REGISTRY


@pytest.fixture(scope="module")
def library():
    return load_skill_library()


def _spec(**overrides):
    base = {
        "id": "skill.web.example",
        "name": "example",
        "title": "Example",
        "description": "An example skill.",
        "version": "1.0.0",
        "kind": "specialist",
        "phase": "active_testing",
        "risk": "medium",
        "support": "supported",
        "target_kinds": ["web"],
        "capabilities": ["http.request"],
    }
    base.update(overrides)
    return base


def test_the_shipped_library_loads(library):
    assert len(library) >= 30


def test_every_declared_capability_is_real_and_planner_visible(library):
    """A skill naming a capability the planner cannot call would advertise dead work."""
    for spec in library.list():
        for name in (*spec.capabilities, *spec.optional_capabilities):
            assert CAPABILITY_REGISTRY.require(name).planner_visible, (
                f"{spec.skill_id} names non-planner capability {name}"
            )


def test_support_level_matches_the_declared_gap(library):
    for spec in library.list():
        if spec.support == "supported":
            assert not spec.missing_capabilities
            assert spec.capabilities
        elif spec.support == "partial":
            assert spec.missing_capabilities


def test_only_supported_skills_are_bindable(library):
    for spec in library.list():
        assert spec.bindable is (spec.support == "supported")


def test_no_skill_can_reach_shell_or_planner_supplied_argv(library):
    """AI-Native rule 3. The upstream library offers a shell adapter; ShakerScan does not."""
    for spec in library.list():
        names = {*spec.capabilities, *spec.optional_capabilities}
        assert not any("shell" in name for name in names), spec.skill_id
        assert "shell.allowlisted" not in spec.missing_capabilities, (
            f"{spec.skill_id} still treats shell as a missing requirement rather than a "
            "capability ShakerScan refuses to have"
        )


def test_declared_budgets_are_real_hunt_dimensions(library):
    for spec in library.list():
        for name, amount in spec.budget.items():
            assert name in SKILL_BUDGET_DIMENSIONS
            assert amount > 0


def test_the_request_boundary_and_the_library_agree_on_the_cap():
    assert MAX_SKILLS == MAX_SKILLS_PER_HUNT


def test_a_partial_skill_cannot_be_bound_to_a_hunt(library):
    partial = next(s for s in library.list(support="partial"))
    with pytest.raises(HuntSkillError, match="cannot be bound"):
        library.resolve_for_hunt([partial.skill_id], target_kind="web")


def test_a_reference_skill_cannot_be_bound_to_a_hunt(library):
    reference = next(iter(library.list(support="reference")), None)
    if reference is None:
        pytest.skip("no reference skills in the shipped library")
    with pytest.raises(HuntSkillError, match="cannot be bound"):
        library.resolve_for_hunt([reference.skill_id], target_kind="web")


def test_prerequisites_are_expanded_rather_than_demanded(library):
    """25 of 30 skills need the baselining skill; making the operator name it teaches
    nothing and would be pasted from a template every time."""
    dependent = next(
        s for s in library.bindable(target_kind="web") if s.requires_skills
    )
    resolved = library.resolve_for_hunt([dependent.skill_id], target_kind="web")
    resolved_ids = {item.skill_id for item in resolved}
    assert dependent.skill_id in resolved_ids
    for required in dependent.requires_skills:
        assert required in resolved_ids


def test_binding_more_skills_than_the_cap_is_refused(library):
    bindable = [s.skill_id for s in library.bindable(target_kind="web")]
    with pytest.raises(HuntSkillError, match="at most"):
        library.resolve_for_hunt(bindable[: MAX_SKILLS_PER_HUNT + 1], target_kind="web")


def test_a_skill_cannot_be_bound_to_the_wrong_target_kind(library):
    web_skill = library.bindable(target_kind="web")[0]
    with pytest.raises(HuntSkillError, match="does not support target kind"):
        library.resolve_for_hunt([web_skill.skill_id], target_kind="device")


def test_an_unknown_skill_is_refused(library):
    with pytest.raises(HuntSkillError, match="unknown skill"):
        library.resolve_for_hunt(["skill.web.does-not-exist"], target_kind="web")


def test_budget_ceilings_take_the_most_permissive_bound_value(library):
    """Two skills in one hunt must not starve each other; the run profile still caps them."""
    specs = library.resolve_for_hunt(
        [s.skill_id for s in library.bindable(target_kind="web")[:2]], target_kind="web"
    )
    ceilings = HuntSkillLibrary.budget_ceilings(specs)
    for name, amount in ceilings.items():
        assert amount == max(
            spec.budget.get(name, 0) for spec in specs
        )


def test_the_allowlist_is_a_union_the_caller_then_intersects(library):
    """The library reports what the skills want. Narrowing happens against the policy
    allowlist at start, so a skill can lose a capability but never gain one."""
    specs = library.resolve_for_hunt(
        [library.bindable(target_kind="web")[0].skill_id], target_kind="web"
    )
    allowlist = set(HuntSkillLibrary.capability_allowlist(specs))
    for spec in specs:
        assert set(spec.capabilities) <= allowlist


# --- declaration validation -------------------------------------------------------------

def test_an_unknown_capability_is_rejected_at_load():
    with pytest.raises(HuntSkillError, match="unknown capability"):
        build_skill_spec(_spec(capabilities=["http.nope"]), path="x.md", body="")


def test_a_server_only_capability_is_rejected_at_load():
    server_only = next(
        s.name for s in CAPABILITY_REGISTRY.list() if not s.planner_visible
    )
    with pytest.raises(HuntSkillError, match="not planner-visible"):
        build_skill_spec(_spec(capabilities=[server_only]), path="x.md", body="")


def test_claiming_support_while_something_is_missing_is_rejected():
    with pytest.raises(HuntSkillError, match="still missing"):
        build_skill_spec(
            _spec(missing_capabilities=["oob.allocate"]), path="x.md", body=""
        )


def test_a_bindable_skill_must_name_a_capability():
    with pytest.raises(HuntSkillError, match="at least one capability"):
        build_skill_spec(_spec(capabilities=[]), path="x.md", body="")


def test_a_budget_dimension_outside_the_skill_subset_is_rejected():
    with pytest.raises(HuntSkillError, match="not a skill ceiling"):
        build_skill_spec(
            _spec(budget={"max_tcp_ports": 100}), path="x.md", body=""
        )


def test_unknown_manifest_keys_are_rejected_instead_of_silently_ignored():
    with pytest.raises(HuntSkillError, match="unsupported skill fields"):
        build_skill_spec(_spec(budgets={"max_http_requests": 10}), path="x.md", body="")
    with pytest.raises(HuntSkillError, match="unsupported routing fields"):
        build_skill_spec(
            _spec(routing={"trigger": ["typo"]}), path="x.md", body="",
        )


def test_a_malformed_skill_is_quarantined_and_catalog_health_is_visible(tmp_path):
    good = tmp_path / "good.md"
    bad = tmp_path / "bad.md"
    good.write_text(
        "---\n" + "\n".join(f"{key}: {value}" for key, value in {
            "id": "skill.web.good", "name": "good", "title": "Good",
            "description": "Good skill", "version": "1.0.0", "kind": "specialist",
            "phase": "recon", "risk": "low", "support": "supported",
        }.items())
        + "\ntarget_kinds: [web]\ncapabilities: [http.request]\n---\nMethod\n",
        encoding="utf-8",
    )
    bad.write_text("---\nbudget: [unterminated\n---\n", encoding="utf-8")

    loaded = load_skill_library(tmp_path)

    assert [item.skill_id for item in loaded.list()] == ["skill.web.good"]
    assert loaded.health()["status"] == "degraded"
    assert loaded.health()["issue_count"] == 1


def test_a_missing_skill_mount_is_not_reported_as_an_empty_catalog(tmp_path):
    loaded = load_skill_library(tmp_path / "missing")
    assert loaded.health()["status"] == "unavailable"
    with pytest.raises(HuntSkillError, match="catalog is unavailable"):
        loaded.resolve_for_hunt(["skill.web.anything"], target_kind="web")


def test_a_deferred_technique_must_say_what_it_needs():
    with pytest.raises(HuntSkillError, match="what it requires"):
        build_skill_spec(
            _spec(deferred_techniques=[{"technique": "smuggling"}]), path="x.md", body=""
        )


def test_a_skill_cannot_require_one_that_is_not_bindable():
    unbindable = _spec(
        id="skill.web.gap", name="gap", support="partial",
        missing_capabilities=["oob.allocate"],
    )
    dependent = _spec(id="skill.web.dependent", requires_skills=["skill.web.gap"])
    with pytest.raises(HuntSkillError, match="not bindable"):
        HuntSkillLibrary([
            build_skill_spec(unbindable, path="a.md", body=""),
            build_skill_spec(dependent, path="b.md", body=""),
        ])


# --- operator-authorized identity headers ------------------------------------------------

def test_identity_headers_are_refused_by_default():
    """Including the two an origin behind a major edge is most likely to trust.

    CF-Connecting-IP and True-Client-IP were previously absent from the refused set, so a
    planner could always forge exactly the header Cloudflare-fronted origins read.
    """
    import api.agent_tools as agent_tools

    probe = {
        "X-Forwarded-For": "127.0.0.1",
        "X-Real-IP": "127.0.0.1",
        "Forwarded": "for=127.0.0.1",
        "CF-Connecting-IP": "127.0.0.1",
        "True-Client-IP": "127.0.0.1",
        "Client-IP": "127.0.0.1",
        "X-Forwarded": "for=127.0.0.1",
        "Fastly-Client-IP": "127.0.0.1",
        "X-Azure-ClientIP": "127.0.0.1",
        "X-WAF-Probe": "keep-me",
    }
    kept = agent_tools.filter_request_headers(probe)
    assert set(kept) == {"X-WAF-Probe"}


def test_identity_headers_are_permitted_with_explicit_operator_authority():
    import api.agent_tools as agent_tools

    probe = {"CF-Connecting-IP": "127.0.0.1", "X-Forwarded-For": "127.0.0.1"}
    kept = agent_tools.filter_request_headers(probe, allow_identity_headers=True)
    assert set(kept) == {"CF-Connecting-IP", "X-Forwarded-For"}


def test_operator_authority_never_unlocks_credential_or_transport_headers():
    """The operator may authorize identity forgery. Secrets and framing are not theirs to
    waive: a planner-set credential would sit outside the credential store, and a
    planner-set framing header is smuggling, which needs its own capability."""
    import api.agent_tools as agent_tools

    probe = {
        "Authorization": "Bearer x",
        "Cookie": "session=x",
        "Proxy-Authorization": "x",
        "Host": "evil.example",
        "Content-Length": "0",
        "Transfer-Encoding": "chunked",
        "Connection": "keep-alive",
        "Upgrade": "websocket",
        "X-Original-URL": "/admin/users",
        "X-Rewrite-URL": "/admin/users",
        "X-HTTP-Method-Override": "DELETE",
    }
    assert agent_tools.filter_request_headers(probe, allow_identity_headers=True) == {}


def test_forging_identity_requires_active_testing_and_an_approval_receipt():
    from api.hunt.start_contract import HuntStartContractError, normalize_hunt_start_payload

    def start(policy):
        return normalize_hunt_start_payload({
            "target_id": "t1", "target_kind": "web", "goal": "g", "policy": policy,
        })

    with pytest.raises(HuntStartContractError, match="requires active_testing"):
        start({"allow_identity_headers": True})
    with pytest.raises(HuntStartContractError, match="authorization_confirmed"):
        start({"allow_identity_headers": True, "active_testing": True})
    with pytest.raises(HuntStartContractError, match="approval receipt"):
        start({
            "allow_identity_headers": True, "active_testing": True,
            "authorization_confirmed": True,
        })
    contract = start({
        "allow_identity_headers": True, "active_testing": True,
        "authorization_confirmed": True,
        "approval_receipt_id": "11111111-1111-4111-8111-111111111111",
    })
    assert contract.policy.allow_identity_headers is True
    assert contract.public_dict()["policy"]["allow_identity_headers"] is True


def test_the_privileged_rule_has_one_owner():
    """It was previously restated at the start handler and drifted from the contract."""
    from api.hunt.start_contract import HuntStartPolicy

    assert HuntStartPolicy().is_privileged(credentials_requested=False) is False
    assert HuntStartPolicy().is_privileged(credentials_requested=True) is True
    for field in (
        "active_testing", "allow_state_changing_http", "network_discovery",
        "allow_oob_interactions", "allow_identity_headers",
    ):
        policy = HuntStartPolicy(**{field: True})
        assert policy.is_privileged(credentials_requested=False) is True, field


# --- binding must deliver the whole methodology, not part of it --------------------------

def test_binding_is_refused_when_any_required_capability_is_withheld(library):
    """A skill bound with part of its requirements would have the planner follow a
    methodology it cannot carry out, then report the shortfall as a result."""
    session_skill = library.require("skill.web.session-cookie-token-and-jwt-testing")
    passive_only = (
        "browser.interact", "browser.navigate", "http.request", "web.crawl", "web.probe",
    )
    with pytest.raises(HuntSkillError, match="withholds"):
        bind_skills_to_hunt(
            [session_skill.skill_id], target_kind="web",
            allowed_capabilities=passive_only, budget=None, library=library,
        )


def test_a_skill_whose_requirements_are_all_passive_still_binds_passively(library):
    passive_only = (
        "browser.interact", "browser.navigate", "http.request", "web.crawl", "web.probe",
    )
    bound = bind_skills_to_hunt(
        ["skill.web.stateful-crawling-content-and-parameter-discovery"],
        target_kind="web", allowed_capabilities=passive_only, budget=None, library=library,
    )
    assert bound.specs and set(bound.allowed_capabilities) <= set(passive_only)


def test_optional_capabilities_may_be_withheld_without_refusing_the_skill(library):
    """Only required capabilities gate the binding; optional ones simply drop."""
    skill = library.require("skill.web.stateful-crawling-content-and-parameter-discovery")
    available = tuple(skill.capabilities)
    bound = bind_skills_to_hunt(
        [skill.skill_id], target_kind="web",
        allowed_capabilities=available, budget=None, library=library,
    )
    assert set(skill.capabilities) <= set(bound.allowed_capabilities)


def test_the_edge_skill_no_longer_defers_the_client_ip_probe(library):
    """It was deferred pending an operator-authorized tier, which now exists."""
    spec = library.require("skill.web.edge-waf-and-origin-exposure-validation")
    deferred = {item["technique"] for item in spec.deferred_techniques}
    assert "client-ip-header-trust-probe" not in deferred
    assert "client-ip-header-trust" in spec.techniques


def test_authorization_skill_keeps_session_establishment_available(library):
    spec = library.require(
        "skill.web.authorization-idor-bola-bfla-and-property-level-testing"
    )
    assert "two_controlled_identities" in spec.preconditions
    assert "auth.session.establish" in spec.capabilities


# --- cross-target hunt history -----------------------------------------------------------

def test_the_hunt_list_exposes_filters_sorting_and_paging():
    """It took only target_id, status and limit, so there was no way to review hunts across
    targets: no offset, no search, no sort, and a count that was just the page size."""
    from api.hunt.run_service import HUNT_SORT_COLUMNS
    import inspect

    from api.hunt.run_service import HuntRunService

    signature = inspect.signature(HuntRunService.list)
    for name in (
        "target_id", "status", "limit", "offset", "search",
        "target_kind", "budget_profile", "root_domain", "sort_by", "sort_order",
    ):
        assert name in signature.parameters, name
    assert set(HUNT_SORT_COLUMNS) >= {
        "created_at", "updated_at", "completed_at", "status", "target_url",
    }


def test_sortable_columns_are_an_explicit_map_not_client_text():
    """The sort field reaches an ORDER BY, so it is resolved through a fixed map rather
    than interpolated."""
    from api.hunt.run_service import HUNT_SORT_COLUMNS

    assert all(
        value.startswith(("h.", "COALESCE(")) for value in HUNT_SORT_COLUMNS.values()
    )
    assert "; " not in "".join(HUNT_SORT_COLUMNS.values())


def test_the_public_projection_carries_target_identity_and_completion():
    """A cross-target list rendered bare UUIDs and could not show duration, because
    completed_at was in the table but never projected."""
    from api.hunt.run_service import public_hunt_run

    row = {
        "id": "11111111-1111-4111-8111-111111111111",
        "target_kind": "web", "target_id": "22222222-2222-4222-8222-222222222222",
        "objective": "x", "status": "completed", "budget_profile": "fast",
        "policy_json": {}, "budget_json": {}, "budget_used_json": {},
        "target_url": "https://app.example.test", "target_name": "App",
        "root_domain": "example.test", "completed_at": "2026-01-01T00:00:00Z",
        "stop_reason": "completed",
    }
    projection = public_hunt_run(row, include_context=False, include_capabilities=False)
    assert projection["target_url"] == "https://app.example.test"
    assert projection["target_name"] == "App"
    assert projection["root_domain"] == "example.test"
    assert projection["completed_at"] == "2026-01-01T00:00:00Z"
    assert projection["stop_reason"] == "completed"
