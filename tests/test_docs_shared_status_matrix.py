from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXECUTION_DOC = ROOT / "docs" / "dast-asm-architecture.md"
FLEET_DOC = ROOT / "docs" / "multi-node-architecture.md"
DEEP_HUNT_DOC = ROOT / "docs" / "deep-hunt-architecture.md"
RETIRED_DOCS = [
    ROOT / "docs" / "parallel-scan-architecture.md",
    ROOT / "docs" / "continuous-asm-architecture.md",
]


def test_execution_architecture_is_consolidated_and_current():
    text = EXECUTION_DOC.read_text()
    assert "Parent, plan, shard, merge" in text
    assert "Continuous ASM loop" in text
    assert "schedule_kind = 'asm_improve'" in text
    assert "severity_rules` may remain advisory" in text

    for retired in RETIRED_DOCS:
        assert not retired.exists()


def test_multi_node_doc_is_build_spec_and_honest_about_fleet_status():
    text = FLEET_DOC.read_text()
    # The doc is a design authority plus a draft vertical slice. It must remain honest about the
    # incomplete bootstrap/artifact/reliability contracts and never resurrect retired sub-docs.
    assert "Phase-1 draft vertical-slice specification" in text
    assert "Phase 1 draft vertical-slice specification" in text
    assert "not implemented yet" in text
    assert "pre-overlay enrollment" in text
    assert "worker cannot call an overlay URL before it has an overlay" in text
    assert "managed `evidence_objects`" in text
    assert "does not make it configuration-only" in text
    assert "explicitly a **lab proof**" in text
    assert "dast-asm-architecture.md" in text
    assert "local Wave 6" not in text
    assert "config + operations task" not in text
    assert "parallel-scan-architecture.md" not in text
    assert "continuous-asm-architecture.md" not in text


def test_deep_hunt_design_authority_is_honest_about_driver_limits():
    text = DEEP_HUNT_DOC.read_text()
    assert "current implementation reference" in text
    assert "not a wire-request count" in text
    assert "external coding agent's tokens" in text
    assert "between completed turns" in text
    assert "restart during an in-flight `planning` turn" in text
    assert "`resp_N` or `scan_N` refs" in text
    assert "does not currently receive a citeable reference" in text
    assert "deliberately **not ported**" in text
    assert "mid-hunt API restart\n  resumes" not in text
