from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOCS = [
    ROOT / "docs" / "parallel-scan-architecture.md",
    ROOT / "docs" / "continuous-asm-architecture.md",
    ROOT / "docs" / "multi-node-architecture.md",
]

REQUIRED_PROMPT_CONTRACT_BLOCKS = [
    "MODE",
    "EDIT PERMISSION",
    "STATUS PREFLIGHT",
    "DO NOT TOUCH",
    "AUTHORIZATION / BLAST RADIUS",
    "DATA CONTRACTS",
    "ROLLOUT / FALLBACK",
    "FAILURE-MODE MATRIX",
    "TEST COMMANDS",
    "OUTPUT FORMAT",
]

REQUIRED_CONCRETE_PROMPT_BLOCKS = [
    "ROLE",
    "MODE",
    "EDIT PERMISSION",
    "TASK",
    "SOURCE OF TRUTH",
    "STATUS PREFLIGHT",
    "CURRENT STATE",
    "TARGET BEHAVIOR",
    "NON-GOALS",
    "DO NOT TOUCH",
    "SAFETY INVARIANTS",
    "AUTHORIZATION / BLAST RADIUS",
    "DATA CONTRACTS",
    "MIGRATION / BACKFILL / COMPATIBILITY",
    "ROLLOUT / FALLBACK",
    "FAILURE-MODE MATRIX",
    "OBSERVABILITY / UI / REPORT BEHAVIOR",
    "ACCEPTANCE CRITERIA",
    "TESTS REQUIRED",
    "TEST COMMANDS",
    "OUTPUT FORMAT",
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


def _appendix_contract_block(path: Path) -> str:
    text = path.read_text()
    start = text.index("### Required prompt contract")
    end = text.index("Hard rule:", start)
    return text[start:end]


def _concrete_prompt_blocks(path: Path) -> dict[str, str]:
    text = path.read_text()
    chunks = text.split("### Prompt: ")
    prompts: dict[str, str] = {}
    for chunk in chunks[1:]:
        title, body = chunk.split("\n", 1)
        prompts[title.strip()] = body
    return prompts


def test_architecture_prompt_contracts_include_mandatory_blocks():
    missing: dict[str, list[str]] = {}
    for doc in DOCS:
        contract = _appendix_contract_block(doc)
        absent = [block for block in REQUIRED_PROMPT_CONTRACT_BLOCKS if block not in contract]
        if absent:
            missing[doc.name] = absent
    assert missing == {}


def test_concrete_architecture_prompts_include_execution_gates():
    missing: dict[str, list[str]] = {}
    for doc in DOCS:
        for title, body in _concrete_prompt_blocks(doc).items():
            absent = [block for block in REQUIRED_CONCRETE_PROMPT_BLOCKS if block not in body]
            if absent:
                missing[f"{doc.name}: {title}"] = absent
    assert missing == {}
