"""Prepare tested Git blobs on a temporary branch; never create commits or move refs."""
from __future__ import annotations

import ast
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
from urllib.request import Request, urlopen

REPO = "andriyze/shakerscan"
BRANCH = "chore/pr227-candidate-review-preparation"
PARENT = "0bf18b154f7254bf057ce1454bef1aa426cd789d"
BASE_TREE = "ea4d29bfec84c07890d549024e43f844f22d0b02"
PATCH_DIGEST = "8c9a23edf03f2f104a3af4c9100d82beb1000493a5ff4cf8655e12fa40e543e4"
PATCHED = {
    ".github/workflows/ai-boundary-alpha.yml",
    "api/ai_gate/boundary/candidate_context.py", "api/ai_targets/router.py",
    "api/command_arsenal.py", "api/hunt/boundary_candidate.py",
    "api/hunt/interaction_router.py", "api/investigation_candidates.py",
    "api/runtime/capability_registry.py", "docs/README.md",
    "docs/ai-boundary-candidate-review.md", "docs/functionality-reference.md",
    "install/MANIFEST.sha256", "skills/web/29-web-llm-and-ai-feature-security-testing.md",
    "tests/test_ai_boundary_candidate_lookup.py", "tests/test_command_arsenal.py",
    "tests/test_investigation_candidates.py", "tests/test_runtime_capabilities.py",
}
GENERATED = {
    "tests/fixtures/api_contract/routes.json", "tests/fixtures/api_contract/operations.json",
    "tests/fixtures/api_contract/app_contract.json", "docs/generated/public-openapi-manifest.json",
    "ui/src/lib/publicApi.generated.ts",
}
TEMPORARY = {
    ".github/pr227/candidate-review.patch", ".github/pr227/prepare-tree.py",
    ".github/workflows/pr227-prepare-tree.yml",
}


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], text=True).strip()


def assert_source() -> None:
    if os.environ.get("GITHUB_REPOSITORY") != REPO:
        raise RuntimeError("Unexpected repository")
    if os.environ.get("GITHUB_REF") != "refs/heads/" + BRANCH:
        raise RuntimeError("Unexpected preparation branch")
    if git("rev-parse", "HEAD") != os.environ["GITHUB_SHA"]:
        raise RuntimeError("Checkout revision mismatch")
    if git("rev-parse", "HEAD^") != PARENT:
        raise RuntimeError("Preparation must have the reviewed PR head as its direct parent")
    if git("rev-parse", PARENT + "^{tree}") != BASE_TREE:
        raise RuntimeError("Original tree mismatch")
    committed = set(git("diff", "--name-only", PARENT, "HEAD").splitlines())
    if committed != TEMPORARY:
        raise RuntimeError("Preparation commit changed non-temporary files")


def apply() -> None:
    assert_source()
    raw = Path(".github/pr227/candidate-review.patch").read_bytes()
    # The tool-uploaded plaintext patch has one leading space on secondary diff
    # headers. Normalize ONLY that serialization detail, then pin exact tested bytes.
    patch = raw.replace(b"\n diff --git ", b"\ndiff --git ")
    if hashlib.sha256(patch).hexdigest() != PATCH_DIGEST:
        raise RuntimeError("Patch is not the exact locally tested diff")
    Path("artifacts").mkdir(exist_ok=True)
    for args in (("--check",), ()):
        subprocess.run(["git", "apply", "--whitespace=error", *args, "-"], input=patch, check=True)
    subprocess.run(["git", "add", "-N", "--", *sorted(PATCHED)], check=True)
    if set(git("diff", "--name-only").splitlines()) != PATCHED:
        raise RuntimeError("Patch changed unexpected paths")
    subprocess.run(["git", "diff", "--check"], check=True)


def post(endpoint: str, payload: dict) -> dict:
    # This helper is intentionally limited to immutable object creation, never refs.
    if endpoint not in {"git/blobs", "git/trees"}:
        raise RuntimeError("Only Git blob/tree creation is supported")
    token = os.environ["GH_TOKEN"]
    request = Request(
        f"https://api.github.com/repos/{REPO}/{endpoint}",
        data=json.dumps(payload).encode(), method="POST",
        headers={"Authorization": "Bearer " + token, "Accept": "application/vnd.github+json",
                 "Content-Type": "application/json", "X-GitHub-Api-Version": "2022-11-28"},
    )
    with urlopen(request, timeout=45) as response:
        return json.load(response)


def stage() -> None:
    assert_source()
    subprocess.run(["git", "diff", "--check"], check=True)
    changed = set(git("diff", "--name-only").splitlines())
    if changed - PATCHED - GENERATED or not PATCHED <= changed:
        raise RuntimeError("Unexpected or missing prepared files")
    entries = []
    files = []
    for name in sorted(changed):
        path = Path(name)
        if path.is_symlink() or not path.is_file():
            raise RuntimeError("Expected a regular source file")
        content = path.read_bytes()
        text = content.decode("utf-8")
        if name.endswith(".py"):
            ast.parse(text, filename=name)
        expected = hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest()
        blob = post("git/blobs", {"content": text, "encoding": "utf-8"})
        if blob["sha"] != expected:
            raise RuntimeError("GitHub blob bytes do not match the tested file")
        entries.append({"path": name, "mode": "100644", "type": "blob", "sha": expected})
        files.append({"path": name, "sha": expected, "sha256": hashlib.sha256(content).hexdigest()})
    # Base on the original PR tree, not the temporary preparation tree. None of
    # this script, the plaintext patch or the preparation workflow enters the PR.
    tree = post("git/trees", {"base_tree": BASE_TREE, "tree": entries})
    receipt = {"repository": REPO, "source_sha": os.environ["GITHUB_SHA"],
               "parent_sha": PARENT, "tree_sha": tree["sha"],
               "patch_sha256": PATCH_DIGEST, "files": files}
    Path("artifacts/tree.json").write_text(json.dumps(receipt, indent=2) + "\n")
    with tarfile.open("artifacts/prepared-source.tar.gz", "w:gz") as archive:
        for name in sorted(changed):
            archive.add(name, arcname=name, recursive=False)
    print(json.dumps({"tree_sha": tree["sha"], "file_count": len(files)}))


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in {"apply", "stage"}:
        raise SystemExit("Usage: prepare-tree.py apply|stage")
    {"apply": apply, "stage": stage}[sys.argv[1]]()
