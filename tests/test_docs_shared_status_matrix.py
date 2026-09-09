import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CURRENT_VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
EXECUTION_DOC = ROOT / "docs" / "dast-asm-architecture.md"
FLEET_DOC = ROOT / "docs" / "multi-node-architecture.md"
COMPATIBILITY_DOC = ROOT / "docs" / "compatibility.md"
FUNCTIONALITY_DOC = ROOT / "docs" / "functionality-reference.md"
RETIRED_DOCS = [
    ROOT / "docs" / "parallel-scan-architecture.md",
    ROOT / "docs" / "continuous-asm-architecture.md",
]
CANONICAL_PRODUCT_DOCS = [
    ROOT / "README.md",
    ROOT / "WALKTHROUGH.md",
    ROOT / "llms.txt",
    ROOT / "docs" / "README.md",
    ROOT / "docs" / "dast-asm-architecture.md",
    ROOT / "docs" / "mcp.md",
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


def test_canonical_docs_use_one_scan_one_hunt_vocabulary():
    text = "\n".join(_flat(path) for path in CANONICAL_PRODUCT_DOCS)
    lowered = text.lower()
    assert "scan type controls modules" not in lowered
    assert "scan type selects checks" not in lowered
    assert "smart scan" not in lowered
    assert "deep hunt" not in lowered
    assert "one deterministic scan" in lowered
    assert "get /scan/contracts" in lowered
    assert "get /hunts/contract" in lowered


def test_compatibility_and_history_are_explicitly_separated():
    compatibility = _flat(ROOT / "docs" / "compatibility.md")
    assert "not an alternate product surface" in compatibility
    assert "cannot select another engine" in compatibility
    assert "new secret write" in compatibility
    assert "fail closed" in compatibility

    archive = ROOT / "docs" / "archive"
    historical = {
        "smart-scan-policy.md",
        "deep-hunt-architecture.md",
        "source-assisted-scanning-and-microvm-isolation-proposal.md",
        "AUDIT-2026-07.md",
        "audit-evidence-2026-07.md",
        "ai-native-refactor-audit.md",
        "v2-re-audit-2026-08-20.md",
    }
    for name in historical:
        # 2.3.1 deliberately removes these documents from the public tree.
        # Requiring their old contents would undo that cleanup, not protect a contract.
        assert not (archive / name).exists(), name
    archive_index = _flat(archive / "README.md")
    assert "not current product contracts" in archive_index
    assert "Use Git history" in archive_index
    assert re.search(r"commit `[0-9a-f]{40}`", archive_index)
    for retired in (
        "SMART_SCAN_POLICY.md",
        "deep-hunt-architecture.md",
        "source-assisted-scanning-and-microvm-isolation-proposal.md",
        "AUDIT-2026-07.md",
        "audit-evidence-2026-07.md",
        "ai-native-refactor-audit.md",
        "v2-re-audit-2026-08-20.md",
    ):
        assert not (ROOT / "docs" / retired).exists(), retired


def test_mcp_and_encryption_docs_state_the_real_trust_boundaries():
    mcp = _flat(ROOT / "docs" / "mcp.md")
    assert "two deliberately different trust levels" in mcp
    assert "Read-only Arsenal inspection" in mcp
    assert "including state-changing and target-facing operations" in mcp

    functionality = _flat(FUNCTIONALITY_DOC).lower()
    assert "unset = plaintext" not in functionality
    assert "plaintext, backward compatible" not in functionality
    assert "every new secret write" in functionality
    assert "fails new writes closed" in functionality


def test_multi_node_doc_is_build_spec_and_honest_about_fleet_status():
    text = _flat(FLEET_DOC)
    # The implementation is complete, while a Fleet-affecting patch correctly renews its physical
    # release receipt. Do not regress to calling shipped layers drafts or WireGuard supported.
    assert f"implementation complete; {CURRENT_VERSION} broker physical-acceptance renewal pending" in text
    assert "WireGuard remains preview code" in text
    assert f"outside the {CURRENT_VERSION} supported deployment boundary" in text
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


def test_fleet_guide_operator_helper_supports_source_and_curl_installs():
    guide = _flat(ROOT / "docs" / "multi-node-guide.md")
    assert "docker-compose.release.yml" in guide
    assert "FLEET_COMPOSE_FILE=docker-compose.yml" in guide
    assert 'docker compose -p shakerscan -f "$FLEET_COMPOSE_FILE" exec -T api curl' in guide


def test_multi_node_doc_states_semaphore_failure_posture():
    # Joined nodes fail closed while standalone installs preserve compatibility.
    text = _flat(FLEET_DOC)
    assert "**Built and fleet-enforceable**" in text
    assert "joined nodes fail closed" in text
    assert "Standalone installs retain" in text
    assert "explicit `request_budget_mode=off`" in text
    assert "fails **closed**" in text
    assert "A partitioned node runs uncapped." not in text


def test_current_compatibility_reference_does_not_advertise_retired_drivers():
    text = _flat(COMPATIBILITY_DOC)
    assert "retired Hunt write routes return `410 Gone`" in text
    assert "bounded historical reads and cancellation" in text
    assert "not an alternate product surface" in text
    assert "`GET /hunts/contract`" in text
    assert "mid-hunt API restart resumes" not in text


def test_removed_design_details_are_not_reintroduced_as_current_contracts():
    text = _flat(COMPATIBILITY_DOC)
    assert "must not appear in new public write contracts" in text
    assert "Unknown fields remain rejected" in text
    assert "last pre-cleanup Git snapshot" in text
    current = "\n".join(_flat(path) for path in CANONICAL_PRODUCT_DOCS)
    # Retired promoter implementation details must not return as client guidance.
    assert "ADVERTISED_FAMILIES" not in current
    assert "_AGENT_AUTO_VERIFY_LIMIT" not in current


def test_functionality_reference_does_not_overclaim_keyless_token_bounding():
    # Model-token budgets bound the configured-provider loop only; a keyless session's token budget
    # sizes the seed context pack, because the server cannot meter an external coding agent.
    text = _flat(FUNCTIONALITY_DOC)
    assert "external scanners reserve their fail-closed maximum wire request allowance" in text
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
