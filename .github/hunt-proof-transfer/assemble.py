"""Temporary exact-tree assembly; publish immutable Git objects, never branch refs.

The compressed transport decodes to a readable unified patch, retained in the
validation artifact. Both patch SHA-256 and the complete resulting Git tree are
pinned below. This file and all transfer/workflow files are absent from that tree.
"""
import base64
import gzip
import hashlib
import json
import os
from pathlib import Path
import subprocess
import urllib.request

BASE = "dcf30e43afafe5c2b5a83c83c11cc7c260411df3"
BASE_TREE = "8ec6171d8f629c9f0b131c82747324cff3dc47cc"
EXPECTED_TREE = "af29c1c9001c93ae79105f3a8d4fbb1b25f34378"
PATCH_SHA256 = "56ba0289e54797eda500df58260da12b83191c01dfd0e42bf500391455e6f8cd"
REPOSITORY = "andriyze/shakerscan"
TRANSFER = ".github/hunt-proof-transfer"
WORKFLOW = ".github/workflows/hunt-proof-validate.yml"
OUT = Path("/tmp/hunt-proof-output")


def git(*args):
    return subprocess.check_output(["git", *args], text=True).strip()


assert os.environ["GITHUB_REPOSITORY"] == REPOSITORY
assert os.environ["GITHUB_REF"] == "refs/heads/feat/hunt-verified-discovery"
assert git("rev-parse", BASE + "^{tree}") == BASE_TREE
for path in git("diff", "--name-only", BASE, "HEAD").splitlines():
    assert path.startswith(TRANSFER + "/") or path == WORKFLOW, path
packed = b"".join(Path(TRANSFER, "part" + str(i)).read_bytes() for i in range(4))
patch = gzip.decompress(packed)
assert len(patch) == 58207
assert hashlib.sha256(patch).hexdigest() == PATCH_SHA256
OUT.mkdir(parents=True, exist_ok=True)
patch_path = OUT / "implementation.patch"
patch_path.write_bytes(patch)
# Remove only this temporary transfer apparatus, not any product source.
subprocess.run(["git", "rm", "-rf", "--", TRANSFER, WORKFLOW], check=True)
subprocess.run(["git", "apply", "--check", str(patch_path)], check=True)
subprocess.run(["git", "apply", "--index", str(patch_path)], check=True)
assert git("write-tree") == EXPECTED_TREE
assert not git("diff", "--name-only")
manifest = {"base": BASE, "base_tree": BASE_TREE, "tree": EXPECTED_TREE,
            "patch_sha256": PATCH_SHA256, "files": []}
entries = []
for row in git("diff", "--cached", "--name-status", "--no-renames", BASE).splitlines():
    status, path = row.split("\t", 1)
    if status == "D":
        entries.append({"path": path, "mode": "100644", "type": "blob", "sha": None})
        manifest["files"].append({"path": path, "deleted": True})
        continue
    assert status in {"A", "M"}, row
    data = Path(path).read_bytes()
    mode = git("ls-files", "-s", "--", path).split()[0]
    sha = git("hash-object", "--", path)
    entries.append({"path": path, "mode": mode, "type": "blob", "sha": sha})
    manifest["files"].append({"path": path, "sha": sha, "sha256": hashlib.sha256(data).hexdigest()})

if os.environ.get("PUBLISH_GIT_OBJECTS") == "1":
    token = os.environ["GH_TOKEN"]
    def post(endpoint, payload):
        req = urllib.request.Request(
            "https://api.github.com/repos/" + REPOSITORY + "/git/" + endpoint,
            data=json.dumps(payload).encode(), method="POST",
            headers={"Authorization": "Bearer " + token, "Accept": "application/vnd.github+json",
                     "Content-Type": "application/json", "User-Agent": "hunt-exact-tree-validation"},
        )
        with urllib.request.urlopen(req, timeout=120) as response:
            return json.load(response)
    for entry in entries:
        if entry["sha"] is None:
            continue
        data = Path(entry["path"]).read_bytes()
        result = post("blobs", {"encoding": "base64", "content": base64.b64encode(data).decode()})
        assert result["sha"] == entry["sha"], entry["path"]
    result = post("trees", {"base_tree": BASE_TREE, "tree": entries})
    assert result["sha"] == EXPECTED_TREE
    manifest["immutable_objects_published"] = True
    # No commit/ref/merge/release/deployment API is called by this script.
(OUT / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
print(json.dumps({"tree": EXPECTED_TREE, "files": len(manifest["files"]),
                  "immutable_objects_published": manifest.get("immutable_objects_published", False)}))
