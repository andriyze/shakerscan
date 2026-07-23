from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXECUTION_DOC = ROOT / "docs" / "dast-asm-architecture.md"
FLEET_DOC = ROOT / "docs" / "multi-node-architecture.md"
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
    # The doc has evolved from a pure RFC into a design authority plus a buildable Phase-1 spec,
    # but it must still (a) honestly state the remote fleet is not implemented, (b) point at the
    # consolidated local execution doc, and (c) never resurrect the retired sub-docs.
    assert "Phase-1 implementation spec" in text
    assert "Phase 1 build specification" in text
    assert "not implemented yet" in text
    assert "dast-asm-architecture.md" in text
    assert "parallel-scan-architecture.md" not in text
    assert "continuous-asm-architecture.md" not in text
