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


def test_multi_node_rfc_uses_consolidated_local_architecture():
    text = FLEET_DOC.read_text()
    assert "RFC / design note" in text
    assert "not implemented yet" in text
    assert "dast-asm-architecture.md" in text
    assert "parallel-scan-architecture.md" not in text
    assert "continuous-asm-architecture.md" not in text
