#!/usr/bin/env python3
"""Remove vendored components the image deleted from pip's CycloneDX SBOM.

pip 25+ ships ``pip/_vendor/bom.cdx.json`` describing its vendored packages. The Model Intake
image removes the vendored msgpack and pkg_resources (setuptools) copies from the pip-audit
environment, but a scanner that reads the SBOM (Trivy does) keeps reporting them as installed:
the first 2.2.0 candidates failed the image vulnerability gate on exactly those two entries after
the code was already gone. Deleting the SBOM would hide pip's remaining vendored packages from
every scanner, so the SBOM is pruned to what the environment actually contains instead.

Usage: prune_pip_vendor_sbom.py BOM NAME [NAME ...]
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


def prune_components(document: dict[str, Any], names: set[str]) -> list[str]:
    """Drop the named components and every dependency edge that points at them.

    Returns the names actually removed. A name the SBOM never listed is not an error: pip may
    stop vendoring a package, and the caller asserts the post-condition it cares about.
    """
    if document.get("bomFormat") != "CycloneDX":
        raise ValueError("not a CycloneDX SBOM")
    components = list(document.get("components") or [])
    removed_refs = {
        ref
        for component in components
        if component.get("name") in names
        for ref in (component.get("bom-ref"), component.get("purl"))
        if ref
    }
    removed_names = sorted({
        str(component.get("name")) for component in components if component.get("name") in names
    })
    document["components"] = [
        component for component in components if component.get("name") not in names
    ]
    if "dependencies" in document:
        pruned = []
        for dependency in document.get("dependencies") or []:
            if dependency.get("ref") in removed_refs:
                continue
            dependency = dict(dependency)
            dependency["dependsOn"] = [
                ref for ref in dependency.get("dependsOn") or [] if ref not in removed_refs
            ]
            pruned.append(dependency)
        document["dependencies"] = pruned
    return removed_names


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print("usage: prune_pip_vendor_sbom.py BOM NAME [NAME ...]", file=sys.stderr)
        return 2
    path = Path(argv[1])
    names = set(argv[2:])
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
        removed = prune_components(document, names)
    except (OSError, ValueError) as exc:
        print(f"prune_pip_vendor_sbom: {path}: {exc}", file=sys.stderr)
        return 1
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    remaining = sorted(names - set(removed))
    print(f"pruned {removed or 'nothing'} from {path}; not listed: {remaining or 'none'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
