from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOCS = [
    ROOT / "docs" / "parallel-scan-architecture.md",
    ROOT / "docs" / "continuous-asm-architecture.md",
    ROOT / "docs" / "multi-node-architecture.md",
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
    blocks = {doc.name: _shared_matrix_block(doc) for doc in DOCS}
    canonical = blocks["parallel-scan-architecture.md"]
    assert blocks == {name: canonical for name in blocks}
