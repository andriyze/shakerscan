from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOCS = [
    ROOT / "docs" / "parallel-scan-architecture.md",
    ROOT / "docs" / "continuous-asm-architecture.md",
    ROOT / "docs" / "multi-node-architecture.md",
]
STATUS_MATRIX_DOCS = DOCS[:2]
ARCHIVED_PROMPT_DOCS = [
    ROOT / "docs" / "archive" / "parallel-scan-agent-task-appendix-2026-07.md",
    ROOT / "docs" / "archive" / "continuous-asm-agent-task-appendix-2026-07.md",
    ROOT / "docs" / "archive" / "multi-node-agent-task-appendix-2026-07.md",
]


def _shared_matrix_block(path: Path) -> str:
    text = path.read_text()
    marker = "## Shared capability status matrix (agent quick read)"
    start = text.index(marker)
    lines = text[start:].splitlines()
    table_started = False
    block: list[str] = []
    for line in lines:
        if line.startswith("| Capability |"):
            table_started = True
        elif table_started and not line.startswith("|"):
            break
        block.append(line)
    return "\n".join(block)


def test_architecture_docs_share_identical_status_matrix():
    blocks = {doc.name: _shared_matrix_block(doc) for doc in STATUS_MATRIX_DOCS}
    canonical = blocks["parallel-scan-architecture.md"]
    assert blocks == {name: canonical for name in blocks}


def test_architecture_prompt_appendices_are_archived_not_live():
    for doc in DOCS:
        assert "AI Agent Task Appendix" not in doc.read_text()

    for doc in ARCHIVED_PROMPT_DOCS:
        text = doc.read_text()
        assert doc.is_file()
        assert "**Archived:**" in text
        assert "AI Agent Task Appendix" in text
