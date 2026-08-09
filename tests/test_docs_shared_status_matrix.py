import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXECUTION_DOC = ROOT / "docs" / "dast-asm-architecture.md"
FLEET_DOC = ROOT / "docs" / "multi-node-architecture.md"
DEEP_HUNT_DOC = ROOT / "docs" / "deep-hunt-architecture.md"
FUNCTIONALITY_DOC = ROOT / "docs" / "functionality-reference.md"
RETIRED_DOCS = [
    ROOT / "docs" / "parallel-scan-architecture.md",
    ROOT / "docs" / "continuous-asm-architecture.md",
]


def _flat(path: Path) -> str:
    """Read a doc with every whitespace run collapsed to one space.

    These guards pin down *claims*, not line breaks. Asserting against raw text made a
    NEGATIVE assertion silently vacuous the moment a paragraph was rewrapped — the retired
    claim could return under a different wrap and still pass. Normalizing first means a
    guard fails only when the claim itself changes.
    """
    return re.sub(r"\s+", " ", path.read_text())


def test_execution_architecture_is_consolidated_and_current():
    text = _flat(EXECUTION_DOC)
    assert "Parent, plan, shard, merge" in text
    assert "Continuous ASM loop" in text
    assert "schedule_kind = 'asm_improve'" in text
    assert "severity_rules` may remain advisory" in text

    for retired in RETIRED_DOCS:
        assert not retired.exists()


def test_multi_node_doc_is_build_spec_and_honest_about_fleet_status():
    text = _flat(FLEET_DOC)
    # The implementation is complete, while a Fleet-affecting patch correctly renews its physical
    # release receipt. Do not regress to calling shipped layers drafts or WireGuard supported.
    assert "implementation complete; 0.8.13 broker physical-acceptance renewal pending" in text
    assert "WireGuard remains preview code" in text
    assert "outside the 0.8.13 supported deployment boundary" in text
    assert "Phase 1 implemented vertical-slice contract" in text
    assert "bounded enrollment" in text
    assert "single-use remains the default" in text
    assert "older exact-SHA receipt" in text
    assert "different node to reclaim" in text
    assert "pre-overlay bootstrap contract" in text
    assert "worker cannot call an overlay URL before it has an overlay" in text
    assert "managed `evidence_objects`" in text
    assert "does not make it configuration-only" in text
    assert "explicitly a **lab proof**" in text
    assert "dast-asm-architecture.md" in text
    assert "local Wave 6" not in text
    assert "config + operations task" not in text
    assert "parallel-scan-architecture.md" not in text
    assert "continuous-asm-architecture.md" not in text


def test_multi_node_doc_states_semaphore_failure_posture():
    # Joined nodes fail closed while standalone installs preserve compatibility.
    text = _flat(FLEET_DOC)
    assert "**Built and fleet-enforceable**" in text
    assert "joined nodes fail closed" in text
    assert "Standalone installs retain" in text
    assert "explicit `request_budget_mode=off`" in text
    assert "fails **closed**" in text
    assert "A partitioned node runs uncapped." not in text


def test_deep_hunt_design_authority_is_honest_about_driver_limits():
    text = _flat(DEEP_HUNT_DOC)
    assert "current implementation reference" in text
    assert "not a wire-request count" in text
    assert "external coding agent's tokens" in text
    assert "between completed turns" in text
    assert "restart during an in-flight `planning` turn" in text
    assert "`resp_N` or `scan_N` refs" in text
    assert "does not currently receive a citeable reference" in text
    assert "deliberately **not ported**" in text
    assert "mid-hunt API restart resumes" not in text


def test_deep_hunt_doc_separates_family_names_from_contract_kinds():
    # A debrief `family` must be a value some promoter accepts. `workflow_transition` is the invariant
    # CONTRACT KIND (no canonical_family alias) and `injection` is accepted by neither path, yet both
    # were once advertised. The doc must teach the closed vocabulary and the recorded skip reasons.
    text = _flat(DEEP_HUNT_DOC)
    assert "`family` is a closed vocabulary" in text
    assert "ADVERTISED_FAMILIES" in text
    assert "never the generic" in text
    assert "the invariant **contract kind**, not a family" in text
    assert "family_not_verifiable" in text
    assert "do not consume `_AGENT_AUTO_VERIFY_LIMIT`" in text
    # The Path C table row must name the FAMILY, not the contract kind.
    assert "access_control, field_constraint, workflow |" in text
    assert "field_constraint, workflow** — mutating" in text
    assert "access_control, field_constraint, workflow_transition |" not in text


def test_functionality_reference_does_not_overclaim_keyless_token_bounding():
    # Model-token budgets bound the configured-provider loop only; a keyless session's token budget
    # sizes the seed context pack, because the server cannot meter an external coding agent.
    text = _flat(FUNCTIONALITY_DOC)
    assert "request unit is one tool invocation, not one wire request" in text
    assert "cannot meter an external coding agent's tokens" in text
    assert "turns, and tokens are bounded" not in text


def test_functionality_reference_describes_current_stream_runtime():
    text = _flat(FUNCTIONALITY_DOC)
    assert "six background asyncio loops" in text
    assert "leasing Redis Stream messages" in text
    assert "running a `BLPOP` loop" not in text

    fleet_text = _flat(FLEET_DOC)
    assert "shared `scan_jobs` Redis Stream" in fleet_text
    assert "shared `scan_jobs` Redis list" not in fleet_text
