#!/usr/bin/env python3
"""Replace the urllib3 that pip vendors with a newer, hash-locked urllib3, vendored the way pip does it.

pip 26.2.1, the newest pip, vendors urllib3 2.7.0, which carries CVE-2026-97687 and CVE-2026-97689
(fixed in 2.8.0), and the Model Intake image gate carries no waivers. The pip-audit environment has
to keep pip (pip-api runs it on import), so the vendored copy cannot simply be deleted the way the
vendored msgpack and setuptools are. Instead this copies the environment's own urllib3, installed
from pip-audit.lock with hashes, into pip/_vendor/urllib3 and applies pip's vendoring rewrites:

- absolute imports of urllib3 and idna become imports from pip._vendor;
- `import urllib3.connection` and `import urllib3.contrib.pyopenssl` become aliased pip._vendor imports;
- Brotli support is removed, as pip's own patch does.

Applied to upstream urllib3 2.7.0 these rules reproduce pip 26.2.1's vendored copy byte for byte.
The Brotli blocks must match exactly, and afterwards no absolute urllib3, idna or Brotli import may
remain, so an upstream change the rules do not cover fails the build rather than letting pip load a
module from outside its vendor tree. vendor.txt and pip's CycloneDX SBOM then record the version that
is actually present.

Usage: revendor_pip_urllib3.py PIP_VENDOR_DIR URLLIB3_PACKAGE_DIR
"""
from __future__ import annotations

import json
import re
import shutil
import sys
from pathlib import Path

BROTLI_RESPONSE = '''try:
    try:
        import brotlicffi as brotli  # type: ignore[import-not-found]
    except ImportError:
        import brotli  # type: ignore[import-not-found]
except ImportError:
    brotli = None
'''

BROTLI_REQUEST = '''try:
    try:
        import brotlicffi as _unused_module_brotli  # type: ignore[import-not-found] # noqa: F401
    except ImportError:
        import brotli as _unused_module_brotli  # type: ignore[import-not-found] # noqa: F401
except ImportError:
    pass
else:
    ACCEPT_ENCODING += ",br"
'''

# pip's patches: each block must occur exactly once in the named module.
EXACT = (
    ("response.py", BROTLI_RESPONSE, "brotli = None\n"),
    ("util/request.py", BROTLI_REQUEST, ""),
    ("contrib/emscripten/__init__.py", "import urllib3.connection\n",
     "import pip._vendor.urllib3.connection as urllib3_connection\n"),
)

# pip's import rewrites, applied to every module (docstring examples included, as pip does).
REWRITES = (
    (re.compile(r"^(\s*)import urllib3\.contrib\.pyopenssl$", re.M),
     r"\1import pip._vendor.urllib3.contrib.pyopenssl as pyopenssl"),
    (re.compile(r"\burllib3\.contrib\.pyopenssl\.inject_into_urllib3\(\)"), "pyopenssl.inject_into_urllib3()"),
    (re.compile(r"^(\s*)urllib3\.connection\.(\w+) = ", re.M), r"\1urllib3_connection.\2 = "),
    (re.compile(r"^(\s*)import (urllib3|idna)$", re.M), r"\1from pip._vendor import \2"),
)

# Nothing may still import these from outside pip's vendor tree.
FORBIDDEN = re.compile(r"^\s*(?:import|from)\s+(?:urllib3|idna|brotli|brotlicffi)\b", re.M)

VERSION = re.compile(r"^__version__\s*=\s*(?:version\s*=\s*)?['\"]([^'\"]+)['\"]", re.M)


def version_tuple(version: str) -> tuple[int, ...]:
    if not re.fullmatch(r"\d+(\.\d+)*", version):
        raise ValueError(f"unsupported urllib3 version {version!r}")
    return tuple(int(part) for part in version.split("."))


def vendored_version(vendor: Path) -> str:
    matches = re.findall(r"^\s*urllib3==(\S+)$", (vendor / "vendor.txt").read_text(encoding="utf-8"), re.M)
    if len(matches) != 1:
        raise ValueError(f"vendor.txt lists urllib3 {len(matches)} times")
    return matches[0]


def package_version(package: Path) -> str:
    match = VERSION.search((package / "_version.py").read_text(encoding="utf-8"))
    if not match:
        raise ValueError(f"no __version__ in {package / '_version.py'}")
    return match.group(1)


def rewrite_tree(root: Path) -> None:
    """Apply pip's vendoring to an urllib3 package tree in place."""
    for relative, old, new in EXACT:
        path = root / relative
        text = path.read_text(encoding="utf-8")
        if text.count(old) != 1:
            raise ValueError(f"{relative}: expected pip's patch site exactly once, found {text.count(old)}")
        path.write_text(text.replace(old, new), encoding="utf-8")
    for path in sorted(root.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        for pattern, replacement in REWRITES:
            text = pattern.sub(replacement, text)
        path.write_text(text, encoding="utf-8")
    leftovers = [
        f"{path.relative_to(root)}: {match.group(0).strip()}"
        for path in sorted(root.rglob("*.py"))
        for match in FORBIDDEN.finditer(path.read_text(encoding="utf-8"))
    ]
    if leftovers:
        raise ValueError("absolute imports left outside pip's vendor tree: " + "; ".join(leftovers))


def license_text(package: Path, old: Path) -> Path | None:
    licenses = sorted(package.parent.glob(f"urllib3-{package_version(package)}.dist-info/licenses/LICENSE*"))
    if licenses:
        return licenses[0]
    return old / "LICENSE.txt" if (old / "LICENSE.txt").is_file() else None


def update_records(vendor: Path, old_version: str, new_version: str) -> None:
    vendor_txt = vendor / "vendor.txt"
    text = vendor_txt.read_text(encoding="utf-8")
    vendor_txt.write_text(
        re.sub(rf"^(\s*)urllib3=={re.escape(old_version)}$", rf"\g<1>urllib3=={new_version}", text, flags=re.M),
        encoding="utf-8",
    )
    bom_path = vendor / "bom.cdx.json"
    document = json.loads(bom_path.read_text(encoding="utf-8"))
    if document.get("bomFormat") != "CycloneDX":
        raise ValueError("bom.cdx.json is not a CycloneDX SBOM")
    components = [c for c in document.get("components") or [] if c.get("name") == "urllib3"]
    if len(components) != 1:
        raise ValueError(f"bom.cdx.json lists urllib3 {len(components)} times")
    renamed = {}
    for key in ("bom-ref", "purl"):
        value = components[0].get(key)
        if value:
            components[0][key] = value.replace(f"@{old_version}", f"@{new_version}")
            renamed[value] = components[0][key]
    components[0]["version"] = new_version
    for dependency in document.get("dependencies") or []:
        dependency["ref"] = renamed.get(dependency.get("ref"), dependency.get("ref"))
        if "dependsOn" in dependency:
            dependency["dependsOn"] = [renamed.get(ref, ref) for ref in dependency["dependsOn"]]
    bom_path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


def revendor(vendor: Path, package: Path) -> tuple[str, str]:
    old_version = vendored_version(vendor)
    new_version = package_version(package)
    if version_tuple(new_version) == version_tuple(old_version):
        return old_version, new_version
    if version_tuple(new_version) < version_tuple(old_version):
        raise ValueError(f"refusing to replace vendored urllib3 {old_version} with older {new_version}")
    current = vendor / "urllib3"
    staged = vendor / "urllib3.revendor"
    shutil.rmtree(staged, ignore_errors=True)
    shutil.copytree(package, staged, ignore=shutil.ignore_patterns("__pycache__"))
    license_path = license_text(package, current)
    if license_path is not None:
        shutil.copyfile(license_path, staged / "LICENSE.txt")
    try:
        rewrite_tree(staged)
    except (OSError, ValueError):
        shutil.rmtree(staged, ignore_errors=True)
        raise
    shutil.rmtree(current)
    staged.rename(current)
    update_records(vendor, old_version, new_version)
    return old_version, new_version


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: revendor_pip_urllib3.py PIP_VENDOR_DIR URLLIB3_PACKAGE_DIR", file=sys.stderr)
        return 2
    try:
        old_version, new_version = revendor(Path(argv[1]), Path(argv[2]))
    except (OSError, ValueError) as exc:
        print(f"revendor_pip_urllib3: {exc}", file=sys.stderr)
        return 1
    if old_version == new_version:
        print(f"pip already vendors urllib3 {new_version}")
    else:
        print(f"replaced pip's vendored urllib3 {old_version} with {new_version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
