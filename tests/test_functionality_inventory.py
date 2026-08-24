import subprocess
import sys
from pathlib import Path
import re

from scripts import generate_capability_inventory as inventory


ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "functionality-reference.md"
GENERATOR = ROOT / "scripts" / "generate_capability_inventory.py"


def test_generated_capability_inventory_is_current():
    result = subprocess.run(
        [sys.executable, str(GENERATOR), "--check"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_functionality_reference_covers_every_product_surface():
    text = DOC.read_text(encoding="utf-8")
    required = (
        "## 3. DAST — one Scan, policy, and budgets",
        "## 9. Scaling DAST: parallel scanning and Continuous ASM",
        "## 10. Attack-surface management",
        "## 11. AI red teaming",
        "Evidence instances and exports",
        "Mission campaigns and action ledger",
        "Hypothesis lifecycle",
        "Refuter reviews",
        "## 16. UI, CLI, skills, and agent surfaces",
        "### Public REST Operations",
        "### Check-Family Registry",
        "### Command Arsenal",
        "### Internal Compatibility Scanner Flags",
        "### Wrapper Commands, Make Targets, And Release Gates",
        "### Runtime Environment-Key Inventory",
        "### UI Pages",
        "### Skills, Slash Commands, And Subagents",
        "### Internal Compatibility Scanner Module Inventory",
        "### Durable Storage Inventory",
    )
    assert [item for item in required if item not in text] == []
    assert "All POST/PATCH bodies are JSON" not in text
    assert "#13-where-to-go-deeper" not in text


def test_inventory_extractors_cover_known_authoritative_surfaces():
    operations = inventory.api_operations()
    assert len(operations) >= 190
    paths = {row.path for row in operations}
    assert {
        "/scan/contracts",
        "/scans/{scan_id}/actions",
        "/credential-profiles",
        "/credential-profiles/{profile_id}/rotate",
    } <= paths
    assert {"scan", "help", "rebuild"} <= set(inventory.scanner_wrapper_commands())
    assert "scan-smart" not in inventory.scanner_wrapper_commands()
    assert {"scan-full", "scan-smart"} == set(
        inventory.scanner_wrapper_compatibility_commands()
    )
    assert {"test", "release-gates", "e2e-model-intake"} <= set(inventory.make_targets())
    assert {"test:no-benchmark-fitting", "test:planner-scope"} <= set(inventory.release_gates())
    env_names = {row["name"] for row in inventory.environment_variables()}
    assert {"AI_URL", "DATABASE_URL", "REDIS_URL", "SHAKERSCAN_API_URL"} <= env_names


def test_every_active_document_is_indexed_and_local_links_resolve():
    index = (ROOT / "docs" / "README.md").read_text(encoding="utf-8")
    linked_docs = {
        Path(destination.split("#", 1)[0]).name
        for destination in re.findall(r"\[[^]]+\]\(([^)]+\.md(?:#[^)]*)?)\)", index)
    }
    active_docs = {path.name for path in (ROOT / "docs").glob("*.md") if path.name != "README.md"}
    assert active_docs <= linked_docs

    documents = [ROOT / "README.md", ROOT / "AGENTS.md", ROOT / "CLAUDE.md", *(ROOT / "docs").glob("*.md")]
    missing = []
    for document in documents:
        for destination in re.findall(r"\[[^]]+\]\(([^)]+)\)", document.read_text(encoding="utf-8")):
            if destination.startswith(("http://", "https://", "mailto:", "#")):
                continue
            path_part = destination.split("#", 1)[0]
            if path_part and not (document.parent / path_part).resolve().exists():
                missing.append((str(document.relative_to(ROOT)), destination))
    assert missing == []


def test_minimal_installed_runtime_does_not_link_to_omitted_docs_tree():
    installed_documents = [
        ROOT / "README.md",
        ROOT / "AGENTS.md",
        ROOT / "CLAUDE.md",
        *(ROOT / "skills").rglob("*.md"),
        *(ROOT / ".claude").rglob("*.md"),
    ]
    broken = []
    for document in installed_documents:
        text = document.read_text(encoding="utf-8")
        for destination in re.findall(r"\[[^]]+\]\(([^)]+)\)", text):
            if destination.startswith("docs/"):
                broken.append((str(document.relative_to(ROOT)), destination))
    assert broken == []


def test_installed_skills_do_not_override_the_runtime_api_base():
    skill = (ROOT / "skills/shakerscan/SKILL.md").read_text(encoding="utf-8")
    model_reference = (
        ROOT / "skills/shakerscan/references/model-intake.md"
    ).read_text(encoding="utf-8")
    assert "$API_BASE/openapi.json" in skill
    assert "Use `http://localhost:8080/openapi.json`" not in skill
    assert "API_BASE=http://localhost:8080  # replace with ./scanner.sh status output on a remote host" in model_reference
