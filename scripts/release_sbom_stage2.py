#!/usr/bin/env python3
"""Extend an unsigned stage-one bundle with scoped, independently cataloged evidence.

Catalog the exact platform manifests; never execute or rebuild released images. The
original BuildKit documents remain intact. New catalogs, build inputs and coverage
checks are deliberately not flattened into a misleading single dependency list.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from scripts import release_sbom as sbom
from scripts import release_sbom_coverage as coverage
from scripts.release_sbom_toolchain import Toolchain

EXTENSION = "shakerscan-sbom-coverage/v2"
REPORT = "sbom-coverage.json"
PLAN = "sbom-source-inputs.json"
LIMITS = [
    "Original BuildKit catalogs and fresh Syft catalogs describe exact first-party image digests separately.",
    "Supporting containers describe checked-in Compose defaults, including optional profiles, not customer overrides.",
    "Source-lock inventories describe resolved build inputs, not a guarantee that every listed component runs or is bundled.",
    "Compiled Go metadata and installed Python/core UI metadata are checked; arbitrary native/static code and minified JavaScript attribution can remain incomplete.",
    "Locally built Firecracker guest artifacts remain outside the runtime catalogs; their dependency lock is included only as a source input.",
    "Host software and remote services are outside these artifacts. No vulnerability waivers or severity filters alter the inventory.",
]


def require(condition: object, message: str) -> None:
    sbom.require(condition, message)


def build_input_documents(root: Path, index: dict) -> tuple[dict, dict, list]:
    """Exact source lock resolutions, with file hashes kept distinct from package hashes."""
    root_id = "SPDXRef-BuildInputs"
    root_ref = "shakerscan-build-inputs"
    packages = [{"SPDXID": root_id, "name": "shakerscan-build-inputs", "versionInfo": index["version"],
                 "downloadLocation": "NOASSERTION", "filesAnalyzed": False,
                 "sourceInfo": "Source lock resolutions only; not a runtime/installed-component assertion."}]
    components, relationships, dependencies, inputs = [], [], [], []
    relationships.append({"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": root_id})
    paths = ["scanner/requirements.lock", "api/model_intake_signer.requirements.lock", "runner/guest/requirements.lock"]
    paths += [p.relative_to(root).as_posix() for p in sorted((root / "scanner/model_intake_tools").glob("*.lock"))]
    resolutions = {}
    for relative in paths:
        pins = coverage.python_pins(root / relative)
        inputs.append({"path": relative, "sha256": sbom.sha256((root / relative).read_bytes()), "kind": "python-lock"})
        for name, version in pins.items():
            resolutions.setdefault(("pypi", name, version), []).append(relative)
    relative = "ui/package-lock.json"
    inputs.append({"path": relative, "sha256": sbom.sha256((root / relative).read_bytes()), "kind": "npm-lock"})
    for name, versions in coverage.npm_pins(json.loads((root / relative).read_bytes())).items():
        for version in versions:
            resolutions.setdefault(("npm", name, version), []).append(relative)
    for (ecosystem, name, version), locks in sorted(resolutions.items()):
        purl = f"pkg:{ecosystem}/{quote(name, safe='/')}@{quote(version, safe='')}"
        ident = "SPDXRef-Input-" + sbom.sha256(purl.encode())[:24]
        packages.append({"SPDXID": ident, "name": name, "versionInfo": version, "downloadLocation": "NOASSERTION",
                         "filesAnalyzed": False, "sourceInfo": "Resolved input in " + ", ".join(locks) + "; not an installed-package assertion.",
                         "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": purl}]})
        relationships.append({"spdxElementId": root_id, "relationshipType": "DEPENDS_ON", "relatedSpdxElement": ident})
        components.append({"type": "library", "bom-ref": ident, "name": name, "version": version, "purl": purl,
                           "properties": [{"name": "shakerscan:scope", "value": "source-lock-resolution"},
                                          {"name": "shakerscan:input-files", "value": ",".join(locks)}]})
        dependencies.append({"ref": ident, "dependsOn": []})
    spdx = {"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "dataLicense": "CC0-1.0",
            "name": "ShakerScan source lock inputs", "documentNamespace": f"https://github.com/{index['repository']}/sbom/{index['source_sha']}/build-inputs",
            "creationInfo": {"created": index["generated_at"], "creators": ["Tool: shakerscan-release-sbom-2"]},
            "packages": packages, "relationships": relationships}
    cdx = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
           "metadata": {"timestamp": index["generated_at"], "component": {"type": "application", "bom-ref": root_ref,
                        "name": "shakerscan-build-inputs", "version": index["version"],
                        "properties": [{"name": "shakerscan:scope", "value": "source-lock-resolution-not-runtime"}]}},
           "components": components, "dependencies": [{"ref": root_ref, "dependsOn": [c["bom-ref"] for c in components]}] + dependencies}
    return spdx, cdx, inputs



def client_cdx(document: dict) -> dict:
    """Lossless mapping of our own client SPDX file inventory, not a general converter.

    Syft's general SPDX converter currently drops file names for this file-level
    input. Do not accept that lossy output or guess identities by matching hashes.
    """
    require(len(document["packages"]) == 1, "client conversion expects one archive package")
    package = document["packages"][0]
    purls = coverage.spdx_purls(document)
    require(len(purls) == 1, "client package must have one identity")
    root = {"type": "application", "bom-ref": package["SPDXID"], "name": package["name"],
            "version": package["versionInfo"], "purl": next(iter(purls)),
            "hashes": [{"alg": "SHA-256", "content": next(c["checksumValue"] for c in package["checksums"] if c["algorithm"] == "SHA256")}],
            "properties": [{"name": "shakerscan:source-info", "value": package["sourceInfo"]}]}
    components = [{"type": "file", "bom-ref": f["SPDXID"], "name": f["fileName"],
                   "hashes": [{"alg": {"SHA256": "SHA-256", "SHA1": "SHA-1"}[c["algorithm"]], "content": c["checksumValue"]} for c in f["checksums"]]}
                  for f in document["files"]]
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "metadata": {"timestamp": document["creationInfo"]["created"], "component": root,
                         "tools": {"components": [{"type": "application", "name": "shakerscan-client-sbom-mapper", "version": "2"}]}},
            "components": components,
            "dependencies": [{"ref": root["bom-ref"], "dependsOn": [f["bom-ref"] for f in components]}]}

def document_pair(documents: dict, label: str, spdx: dict, cdx: dict, tool: Toolchain) -> dict:
    sbom.validate_spdx(spdx)
    coverage.validate_cdx(cdx)
    tool.validate(spdx)
    tool.validate(cdx)
    require(coverage.spdx_purls(spdx) <= coverage.cdx_purls(cdx), "CycloneDX conversion lost package identities")
    spdx_name, cdx_name = label + ".spdx.json", label + ".cdx.json"
    require(spdx_name not in documents and cdx_name not in documents, "duplicate stage-two document")
    documents[spdx_name] = sbom.json_bytes(spdx)
    documents[cdx_name] = sbom.json_bytes(cdx)
    return {"spdx": spdx_name, "cyclonedx": cdx_name,
            "spdx_sha256": sbom.sha256(documents[spdx_name]), "cyclonedx_sha256": sbom.sha256(documents[cdx_name])}


def source_identity(root: Path, expected: str) -> None:
    actual = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    require(actual == expected, "source checkout differs from artifact source commit")
    # Ignore untracked output/tool directories, but never use edited tracked source as evidence.
    changed = subprocess.check_output(["git", "-C", str(root), "status", "--porcelain", "--untracked-files=no"], text=True)
    require(not changed.strip(), "source checkout has modified tracked files")


def enhance(directory: Path, root: Path, tools: Path, output: Path) -> None:
    require(not (directory / sbom.BUNDLE).exists(), "cannot enhance a signed bundle")
    require(not output.exists(), "stage-two output already exists")
    index = sbom.verify_bundle(directory)
    require(index["coverage"]["stage"] == 1 and "extension" not in index, "expected an unextended stage-one bundle")
    source_identity(root, index["source_sha"])
    tool = Toolchain(tools)
    documents = {name: (directory / name).read_bytes() for name in index["files"]}
    extra, reports = [], []
    for artifact in index["artifacts"]:
        tool.validate(json.loads(documents[artifact["sbom"]]))
    extension = {"schema_version": EXTENSION, "catalogs": extra, "toolchain": tool.receipt,
                 "source_inputs": PLAN, "coverage_report": REPORT}
    plan = {"source_sha": index["source_sha"], "kind": index["kind"], "inputs": []}
    if index["kind"] == "client":
        for artifact in index["artifacts"]:
            spdx = json.loads(documents[artifact["sbom"]])
            cdx = client_cdx(spdx)
            tool.validate(cdx)
            coverage.validate_cdx(cdx)
            require(coverage.spdx_purls(spdx) <= coverage.cdx_purls(cdx), "client conversion lost package identities")
            name = artifact["file"] + ".cdx.json"
            documents[name] = sbom.json_bytes(cdx)
            extra.append({"scope": "client-archive-files", "distribution": artifact["distribution"],
                          "cyclonedx": name, "cyclonedx_sha256": sbom.sha256(documents[name])})
        limits = sbom.CLIENT_LIMITS + ["SPDX and CycloneDX documents pass pinned official JSON schemas; signatures and completeness are separate properties."]
    else:
        inventory = sbom.load_json(root / "install/release-images.json")
        services = coverage.supporting_images(root / "docker-compose.release.yml", inventory)
        plan.update(first_party=inventory, supporting_services=services,
                    compose_sha256=sbom.sha256((root / "docker-compose.release.yml").read_bytes()))
        validate_release_image_inventory(index, plan)
        subjects = [dict(a, scope="first-party-runtime") for a in index["artifacts"]]
        for service in services:
            platforms = coverage.service_platforms(sbom.run_json(["docker", "buildx", "imagetools", "inspect", service["image_reference"], "--raw"]))
            for platform, digest in platforms.items():
                subjects.append(dict(service, scope="supporting-service-runtime", platform=platform, platform_digest=digest))
        for subject in subjects:
            reference = subject["image_reference"].split("@")[0] + "@" + subject["platform_digest"]
            print(f"Cataloging {subject['image']} {subject['platform']} by digest", flush=True)
            # Sequential, bounded working directories avoid retaining all multi-GB images.
            with tempfile.TemporaryDirectory() as temporary:
                native, spdx, cdx = tool.scan("registry:" + reference, Path(temporary) / "scan")
                coverage.validate_native_source(native, reference, subject["platform"])
                report = coverage.coverage_report(subject["image"], native, root)
                report.update(platform=subject["platform"], platform_digest=subject["platform_digest"])
                if subject["scope"] == "first-party-runtime":
                    original = json.loads(documents[subject["sbom"]])
                    report["independent_purls_not_in_buildkit"] = sorted(coverage.spdx_purls(spdx) - coverage.spdx_purls(original))
                    report["buildkit_purls_not_in_independent"] = sorted(coverage.spdx_purls(original) - coverage.spdx_purls(spdx))
                reports.append(report)
                pair = document_pair(documents, "shakerscan-" + index["version"] + "-runtime-" + subject["image"].replace("_", "-") + "-" + subject["platform"].replace("/", "-"), spdx, cdx, tool)
                extra.append({k: subject[k] for k in ("image", "image_reference", "index_digest", "platform", "platform_digest", "scope")} | pair)
        spdx, cdx, inputs = build_input_documents(root, index)
        extra.append({"scope": "source-lock-resolution"} | document_pair(documents, "shakerscan-" + index["version"] + "-build-inputs", spdx, cdx, tool))
        plan["inputs"] = inputs
        limits = LIMITS
    documents[PLAN] = sbom.json_bytes(plan)
    documents[REPORT] = sbom.json_bytes({"schema_version": EXTENSION, "status": "pass", "checks": reports,
                                      "schema_validation": "official-pinned-json-schemas-plus-semantic-checks",
                                      "limitations": limits})
    documents[sbom.README] = ("# ShakerScan release SBOMs - stage two\n\n" + "\n".join("- " + x for x in limits) +
        "\n\nVerify sbom-index.sigstore.json against the expected GitHub publishing workflow first, then run "
        "scripts/release_sbom.py verify. The signed index binds all catalogs and coverage evidence to artifacts. "
        "Checksums do not authenticate a publisher. See docs/sbom.md.\n").encode()
    index["coverage"] = {"stage": 2, "completeness": "partial", "limitations": limits}
    index["extension"] = extension
    index["generator"]["version"] = "2"
    index["files"] = {n: sbom.sha256(d) for n, d in sorted(documents.items())}
    documents[sbom.INDEX] = sbom.json_bytes(index)
    documents[sbom.SUMS] = "".join(f"{sbom.sha256(data)}  {name}\n" for name, data in sorted(documents.items())).encode()
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=output.parent) as temporary:
        stage = Path(temporary) / "bundle"
        stage.mkdir()
        for name, data in documents.items():
            require(sbom.safe_name(name) == Path(name).name, "unsafe output filename")
            (stage / name).write_bytes(data)
        sbom.verify_bundle(stage)
        stage.rename(output)
    print(f"Stage two: wrote {len(extra)} additional catalog pairs/conversions to {output}")


def validate_release_image_inventory(index: dict, plan: dict) -> None:
    """The source inventory, not the surviving catalogs, defines completeness."""
    inventory = plan.get("first_party", {})
    require(isinstance(inventory, dict) and inventory.get("schema_version") == "shakerscan-release-images/v1", "missing source image inventory")
    images = inventory.get("images")
    require(isinstance(images, list) and images, "empty source image inventory")
    expected = {}
    for image in images:
        require(isinstance(image, dict), "invalid source image entry")
        key = image.get("key")
        require(isinstance(key, str) and re.fullmatch(r"[a-z][a-z0-9_]*", key) and key not in expected, "duplicate/invalid source image key")
        require(isinstance(image.get("repository"), str), "invalid source image repository")
        repository, _ = coverage.canonical_image(image["repository"], False)
        expected[key] = repository
    actual = set()
    for artifact in index.get("artifacts", []):
        key, platform = artifact.get("image"), artifact.get("platform")
        require(key in expected and platform in sbom.PLATFORMS, "unexpected first-party image or platform")
        repository, digest = coverage.canonical_image(artifact.get("image_reference", ""))
        require(repository == expected[key] and digest == artifact.get("index_digest"), "first-party repository/digest differs from source inventory")
        require((key, platform) not in actual, "duplicate first-party platform")
        actual.add((key, platform))
    require(actual == {(key, platform) for key in expected for platform in sbom.PLATFORMS},
            "incomplete first-party images against source inventory")


def verify_extension(directory: Path, index: dict) -> set[str]:
    """Offline semantic/integrity checks. Official schema validation occurs before sealing."""
    extension = index.get("extension", {})
    require(index.get("coverage", {}).get("stage") == 2 and extension.get("schema_version") == EXTENSION, "invalid stage-two extension")
    files = index["files"]
    require(extension.get("source_inputs") == PLAN and extension.get("coverage_report") == REPORT and PLAN in files and REPORT in files, "missing stage-two coverage evidence")
    plan, report = sbom.load_json(directory / PLAN), sbom.load_json(directory / REPORT)
    require(plan.get("source_sha") == index["source_sha"] and plan.get("kind") == index["kind"], "stage-two source mismatch")
    require(report.get("status") == "pass" and report.get("schema_version") == EXTENSION, "stage-two coverage failed")
    if index["kind"] == "engine":
        validate_release_image_inventory(index, plan)
    require(extension.get("toolchain", {}).get("syft_version") and extension["toolchain"].get("schema_git_blobs"), "missing pinned toolchain identities")
    spdx_files, cdx_files, subjects = set(), set(), set()
    build_inputs = 0
    bindings = {a["image"]: (a["image_reference"], a["index_digest"], "first-party-runtime") for a in index["artifacts"]} if index["kind"] == "engine" else {}
    for service in plan.get("supporting_services", []):
        require(service["image"] not in bindings, "duplicate supporting-service identity")
        bindings[service["image"]] = (service["image_reference"], service["index_digest"], "supporting-service-runtime")
    for catalog in extension.get("catalogs", []):
        cdx_name = catalog.get("cyclonedx")
        require(cdx_name in files and cdx_name.endswith(".cdx.json") and cdx_name not in cdx_files, "missing/duplicate CycloneDX catalog")
        require(catalog.get("cyclonedx_sha256") == files[cdx_name], "CycloneDX hash binding mismatch")
        coverage.validate_cdx(sbom.load_json(directory / cdx_name))
        cdx_files.add(cdx_name)
        if index["kind"] == "client":
            require(catalog.get("scope") == "client-archive-files", "invalid client catalog scope")
            subject = catalog.get("distribution")
            require(subject in ("wheel", "sdist"), "invalid converted distribution")
        else:
            name = catalog.get("spdx")
            require(name in files and name.endswith(".spdx.json") and name not in spdx_files, "missing/duplicate runtime SPDX catalog")
            require(catalog.get("spdx_sha256") == files[name], "SPDX hash binding mismatch")
            sbom.validate_spdx(sbom.load_json(directory / name))
            spdx_files.add(name)
            if catalog.get("scope") == "source-lock-resolution":
                build_inputs += 1
                continue
            require(catalog.get("scope") in ("first-party-runtime", "supporting-service-runtime"), "invalid runtime catalog scope")
            require(bindings.get(catalog.get("image")) == (catalog.get("image_reference"), catalog.get("index_digest"), catalog.get("scope")), "runtime image differs from release/Compose binding")
            subject = (catalog.get("image"), catalog.get("platform"), catalog.get("platform_digest"))
            require(subject[1] in sbom.PLATFORMS and isinstance(subject[2], str) and sbom.DIGEST.fullmatch(subject[2]), "invalid runtime subject")
            require(catalog.get("image_reference", "").endswith("@" + catalog.get("index_digest", "invalid")), "runtime index mismatch")
        require(subject not in subjects, "duplicate stage-two subject")
        subjects.add(subject)
    require(cdx_files == {n for n in files if n.endswith(".cdx.json")}, "unindexed CycloneDX document")
    if index["kind"] == "client":
        require(subjects == {"wheel", "sdist"}, "missing client CycloneDX conversion")
    else:
        expected_first = {(a["image"], a["platform"], a["platform_digest"]) for a in index["artifacts"]}
        require(expected_first <= subjects and build_inputs == 1, "missing first-party or build-input catalog")
        services = plan.get("supporting_services", [])
        require(services and plan.get("inputs"), "missing supporting-service/source-lock plan")
        expected_keys = {(a["image"], a["platform"]) for a in index["artifacts"]} | {(a["image"], p) for a in services for p in sbom.PLATFORMS}
        require({s[:2] for s in subjects} == expected_keys, "incomplete supporting-service platform coverage")
        checked = {(r.get("image"), r.get("platform"), r.get("platform_digest")) for r in report.get("checks", [])}
        require(checked == subjects, "coverage report does not cover every runtime subject")
    return spdx_files


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, default=ROOT)
    parser.add_argument("--tools", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        enhance(args.directory, args.source_root, args.tools, args.output)
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        raise SystemExit(f"stage-two SBOM: {exc}") from None


if __name__ == "__main__":
    main()
