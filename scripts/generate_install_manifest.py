#!/usr/bin/env python3
"""Generate or verify the SHA-256 manifest of every file the hosted installer downloads.

The installer fetches the host-side runtime file by file from a git tag on raw.githubusercontent.com.
A tag is mutable and the CDN is not a trust boundary, so without a manifest nothing binds the files an
operator receives to the tree the release candidate was certified from. `install/MANIFEST.sha256`
closes that gap: it lists the digest of every path `install/index.sh` downloads, the installer verifies
each file against it, and the release receipt records the manifest's own digest so the installer can
verify the manifest against the published image lock.

    python3 scripts/generate_install_manifest.py          # rewrite install/MANIFEST.sha256
    python3 scripts/generate_install_manifest.py --check  # fail when the committed manifest is stale
"""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "install" / "index.sh"
MANIFEST_PATH = "install/MANIFEST.sha256"
MANIFEST = ROOT / MANIFEST_PATH

_LITERAL = re.compile(r'^\s*download "\$REPO_RAW_BASE/([^"$]+)" ')
_LOOP_HEAD = re.compile(r"^for (\w+) in \\$")
_LOOP_BODY = re.compile(r'^\s*download "\$REPO_RAW_BASE/([^"$]*)\$(\w+)" ')


class ManifestError(RuntimeError):
    pass


def installer_paths(source: str) -> list[str]:
    """Every repository path the installer downloads from the release tree, loops expanded."""
    paths: list[str] = []
    lines = source.splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        literal = _LITERAL.match(line)
        if literal:
            # The manifest cannot list itself; the release image lock carries its digest instead.
            if literal.group(1) != MANIFEST_PATH:
                paths.append(literal.group(1))
            index += 1
            continue
        head = _LOOP_HEAD.match(line)
        if head:
            variable = head.group(1)
            items: list[str] = []
            index += 1
            while index < len(lines):
                item_line = lines[index].strip()
                index += 1
                terminal = item_line.endswith("; do")
                item_line = item_line.removesuffix("; do").removesuffix("\\").strip()
                if item_line:
                    items.append(item_line)
                if terminal:
                    break
            else:
                raise ManifestError(f"unterminated installer loop for {variable}")
            body = _LOOP_BODY.match(lines[index]) if index < len(lines) else None
            if body is not None and body.group(2) == variable:
                prefix = body.group(1)
                paths.extend(f"{prefix}{item}" for item in items)
                index += 1
            # Loops that do not download anything (lock validation, permissions) are skipped.
            continue
        index += 1
    if not paths:
        raise ManifestError("no download lines found in install/index.sh")
    duplicates = sorted({path for path in paths if paths.count(path) > 1})
    if duplicates:
        raise ManifestError(f"installer downloads these paths more than once: {duplicates}")
    return sorted(paths)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def render_manifest(root: Path = ROOT, installer: Path = INSTALLER) -> str:
    paths = installer_paths(installer.read_text(encoding="utf-8"))
    missing = [path for path in paths if not (root / path).is_file()]
    if missing:
        raise ManifestError(f"installer lists files that do not exist: {missing}")
    # sha256sum's own format so any POSIX host can verify with sha256sum -c.
    return "".join(f"{_sha256(root / path)}  {path}\n" for path in paths)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify the committed manifest is current")
    args = parser.parse_args(argv)
    try:
        rendered = render_manifest()
    except (OSError, ManifestError) as exc:
        print(f"install manifest: {exc}", file=sys.stderr)
        return 2
    if args.check:
        current = MANIFEST.read_text(encoding="utf-8") if MANIFEST.is_file() else ""
        if current != rendered:
            expected = dict(line.split("  ", 1) for line in rendered.splitlines())
            actual = dict(line.split("  ", 1) for line in current.splitlines() if "  " in line)
            changed = sorted(
                {path for path, digest in expected.items() if actual.get(path) != digest}
                | {path for path in actual if path not in expected}
            )
            print(
                "install/MANIFEST.sha256 is stale; run scripts/generate_install_manifest.py. "
                f"Changed: {', '.join(changed[:12])}{' ...' if len(changed) > 12 else ''}",
                file=sys.stderr,
            )
            return 1
        print(f"install manifest current: {rendered.count(chr(10))} files")
        return 0
    MANIFEST.write_text(rendered, encoding="utf-8")
    print(f"wrote {MANIFEST} with {rendered.count(chr(10))} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
