"""Release-specific coverage rules, kept separate from format/catalog generation."""
from __future__ import annotations

import json
from pathlib import Path
import re
from urllib.parse import unquote, urlsplit

PLATFORMS = ("linux/amd64", "linux/arm64")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


def require(condition: object, message: str) -> None:
    if not condition:
        raise ValueError(message)


def default_image(value: str) -> tuple[str, str | None]:
    """Read checked-in defaults, never the operator's environment or .env file."""
    require(isinstance(value, str), "Compose image must be a string")
    match = re.fullmatch(r"\$\{([A-Z][A-Z0-9_]*):-([^{}$]+)\}", value)
    if match:
        return match[2], match[1]
    require("$" not in value, "unsupported image interpolation; explicitly inventory it")
    return value, None


def canonical_image(value: str, require_digest: bool = True) -> tuple[str, str]:
    parts = value.split("@")
    require(len(parts) <= 2, "invalid image identity")
    repository = parts[0]
    if ":" in repository.rsplit("/", 1)[-1]:
        repository = repository.rsplit(":", 1)[0]
    first = repository.split("/", 1)[0]
    if "/" not in repository:
        repository = "docker.io/library/" + repository
    elif "." not in first and ":" not in first:
        repository = "docker.io/" + repository
    require(re.fullmatch(r"(?:docker\.io|quay\.io)/[a-z0-9][a-z0-9_./-]+", repository), "unexpected image registry/repository")
    digest = parts[1] if len(parts) == 2 else ""
    require(not require_digest or DIGEST.fullmatch(digest), "supporting-service image must be digest pinned")
    return repository, digest


def supporting_images(compose_path: Path, inventory: dict) -> list[dict]:
    import yaml
    class UniqueLoader(yaml.SafeLoader):
        pass
    def unique_mapping(loader, node, deep=False):
        pairs = loader.construct_pairs(node, deep=deep)
        require(len(pairs) == len({key for key, _ in pairs}), "duplicate Compose mapping key")
        return dict(pairs)
    UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping)
    compose = yaml.load(compose_path.read_text(), Loader=UniqueLoader)
    first_party = {canonical_image(i["repository"], False)[0] for i in inventory["images"]}
    grouped = {}
    for name, service in compose["services"].items():
        require(re.fullmatch(r"[a-z][a-z0-9_-]*", name), "unsafe Compose service name")
        require(isinstance(service, dict) and "image" in service, f"release service lacks image: {name}")
        default, variable = default_image(service["image"])
        repository, _ = canonical_image(default, False)
        if repository in first_party:
            continue
        repository, digest = canonical_image(default)
        reference = repository + "@" + digest
        group = grouped.setdefault(reference, {"image": "service-" + name, "image_reference": reference,
                                                "index_digest": digest, "deployments": []})
        profiles = service.get("profiles", [])
        require(isinstance(profiles, list) and all(isinstance(p, str) for p in profiles), "invalid service profiles")
        group["deployments"].append({"service": name, "profiles": profiles, "optional": bool(profiles),
                                     "default_image": default, "override_variable": variable})
    require(grouped, "release contains no supporting-service images")
    return sorted(grouped.values(), key=lambda value: value["image"])


def service_platforms(document: dict) -> dict[str, str]:
    require(document.get("schemaVersion") == 2 and isinstance(document.get("manifests"), list), "supporting image is not a platform index")
    platforms = {}
    for entry in document["manifests"]:
        p = entry.get("platform", {})
        key = f"{p.get('os')}/{p.get('architecture')}"
        if key not in PLATFORMS:
            continue  # Upstreams also publish Windows, arm/v7, ppc64le and attestations.
        require(p.get("variant", "") in ("", "v8") if key.endswith("arm64") else p.get("variant", "") in ("", "v1"), "unsupported platform variant")
        require(key not in platforms, "duplicate supporting-service platform")
        require(isinstance(entry.get("digest"), str) and DIGEST.fullmatch(entry["digest"]), "invalid service platform digest")
        platforms[key] = entry["digest"]
    require(set(platforms) == set(PLATFORMS), "supporting image must supply amd64 and arm64")
    return platforms


def python_pins(path: Path) -> dict[str, str]:
    pins = {}
    text = path.read_text().replace("\\\n", " ")
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = re.match(r"([A-Za-z0-9_.-]+)(?:\[[^]]+\])?==([^\s;]+)(?:\s|;|$)", line)
        if match is None:
            direct = re.match(r"([A-Za-z0-9_.-]+) @ (https://\S+)(?:\s|$)", line)
            require(direct is not None, f"unsupported/unpinned requirement in {path.name}")
            url = urlsplit(direct[2])
            require(re.fullmatch(r"sha256=[0-9a-f]{64}", url.fragment), "direct wheel input needs a SHA-256 pin")
            wheel = unquote(url.path.rsplit("/", 1)[-1]).split("-")
            require(len(wheel) >= 5 and wheel[-1].endswith(".whl"), "direct input is not an identifiable wheel")
            name = re.sub(r"[-_.]+", "-", direct[1]).lower()
            require(re.sub(r"[-_.]+", "-", wheel[0]).lower() == name, "direct wheel name mismatch")
            version = wheel[1]
        else:
            name = re.sub(r"[-_.]+", "-", match[1]).lower()
            version = match[2]
        require(name not in pins or pins[name] == version, "conflicting requirement pins")
        pins[name] = version
    require(pins, "empty Python lock")
    return pins


def npm_pins(lock: dict) -> dict[str, set[str]]:
    require(lock.get("lockfileVersion") in (2, 3) and isinstance(lock.get("packages"), dict), "unsupported npm lock")
    pins = {}
    for path, package in lock["packages"].items():
        if not path:
            continue
        require("node_modules/" in path and not package.get("link"), "unresolved npm workspace/link")
        name = package.get("name") or path.rsplit("node_modules/", 1)[-1]
        version = package.get("version")
        require(isinstance(version, str) and version, "unresolved npm version")
        pins.setdefault(name, set()).add(version)
    return pins


def validate_native_source(native: dict, reference: str, platform: str) -> None:
    source = native.get("source", {})
    metadata = source.get("metadata", {})
    require(source.get("type") == "image", "Syft did not inventory an image")
    require(metadata.get("manifestDigest") == reference.rsplit("@", 1)[1], "Syft inventory describes the wrong manifest")
    require(metadata.get("architecture") == platform.split("/")[1] and metadata.get("os") == "linux", "Syft inventory platform mismatch")
    require(isinstance(native.get("artifacts"), list) and native["artifacts"], "empty independent runtime inventory")


def _paths(package: dict) -> set[str]:
    return {p["path"] for p in package.get("locations", []) if isinstance(p.get("path"), str)}


def coverage_report(image: str, native: dict, root: Path) -> dict:
    packages = native["artifacts"]
    report = {"image": image, "package_count": len(packages), "checks": [], "limitations": [
        "Presence and version evidence are not vulnerability reachability or exploitability.",
        "Cataloger coverage is not proof that all native/static or vendored libraries were identified.",
    ]}
    types = {p.get("type") for p in packages}
    require(types & {"deb", "apk", "rpm"}, f"{image}: OS-package inventory missing")
    report["checks"].append("OS package catalog present")
    if image in ("scanner", "api", "model_intake", "signer"):
        lock = root / ("api/model_intake_signer.requirements.lock" if image == "signer" else "scanner/requirements.lock")
        expected = python_pins(lock)
        actual = {(re.sub(r"[-_.]+", "-", p["name"]).lower(), p.get("version")) for p in packages
                  if p.get("type") == "python" and any("site-packages/" in path or "dist-packages/" in path for path in _paths(p))}
        missing = sorted(f"{n}=={v}" for n, v in expected.items() if (n, v) not in actual)
        require(not missing, f"{image}: installed Python pins missing from inventory: {', '.join(missing[:12])}")
        report["checks"].append(f"{len(expected)} Python lock pins observed in installed package metadata")
    if image == "model_intake":
        for lock in sorted((root / "scanner/model_intake_tools").glob("*.lock")):
            prefix = "/opt/model-intake-tools/" + lock.stem + "/"
            actual = {(re.sub(r"[-_.]+", "-", p["name"]).lower(), p.get("version")) for p in packages
                      if p.get("type") == "python" and any(path.startswith(prefix) and "site-packages/" in path for path in _paths(p))}
            missing = sorted(f"{n}=={v}" for n, v in python_pins(lock).items() if (n, v) not in actual)
            require(not missing, f"{lock.stem}: isolated tool environment coverage missing: {', '.join(missing[:12])}")
            report["checks"].append(f"{lock.stem} isolated environment pins observed")
    if image in ("scanner", "model_intake", "api"):
        if image == "api":
            expected_paths = {"/usr/local/bin/docker"}
        else:
            dockerfile = (root / "scanner/Dockerfile").read_text()
            expected_paths = set(re.findall(r"^COPY --from=go-builder \S+ (/opt/tools/\S+)$", dockerfile, re.M))
            require(expected_paths, "no Go binary destinations in scanner Dockerfile")
            if image == "model_intake":
                expected_paths |= {"/opt/tools/trivy", "/opt/tools/osv-scanner"}
        observed = {}
        for path in sorted(expected_paths):
            matches = [p for p in packages if p.get("type") == "go-module" and path in _paths(p)
                       and p.get("metadata", {}).get("goCompiledVersion")]
            require(matches, f"{image}: compiled Go dependency metadata missing for {path}")
            observed[path] = {"go_versions": sorted({p["metadata"]["goCompiledVersion"] for p in matches}),
                              "modules": sorted({p["name"] + "@" + (p.get("version") or "unknown") for p in matches})}
        report["go_binaries"] = observed
        report["checks"].append(f"compiled Go module records observed for {len(observed)} shipped binary paths")
    if image == "ui":
        lock = json.loads((root / "ui/package-lock.json").read_bytes())
        expected = npm_pins(lock)
        actual = {(p["name"], p.get("version")) for p in packages if p.get("type") == "npm"
                  and any(path.endswith("package.json") and "node_modules/" in path for path in _paths(p))}
        for name in ("next", "react", "react-dom"):
            require(any((name, version) in actual for version in expected.get(name, set())), f"UI runtime {name} missing or differs from source lock")
        report["checks"].append("Next.js, React and React DOM runtime metadata agrees with the certified source lock")
        report["unattributed_lock_components"] = sorted(n + "@" + v for n, versions in expected.items() for v in versions if (n, v) not in actual)
        report["limitations"].append("Unobserved lock entries may be build-only, platform-conditional or bundled/minified; not classified as absent runtime code.")
    return report


def spdx_purls(document: dict) -> set[str]:
    return {r["referenceLocator"] for p in document.get("packages", []) for r in p.get("externalRefs", [])
            if r.get("referenceType") == "purl" and r.get("referenceLocator")}


def cdx_purls(document: dict) -> set[str]:
    def walk(items):
        for item in items:
            if item.get("purl"):
                yield item["purl"]
            yield from walk(item.get("components", []))
    return set(walk([document.get("metadata", {}).get("component", {})] + document.get("components", [])))


def validate_cdx(document: dict) -> None:
    require(document.get("bomFormat") == "CycloneDX" and document.get("specVersion") == "1.6", "invalid CycloneDX identity")
    require(isinstance(document.get("version"), int) and document["version"] >= 1, "invalid CycloneDX document version")
    refs = set()
    def visit(components):
        require(isinstance(components, list), "invalid CycloneDX components")
        for component in components:
            require(isinstance(component, dict) and component.get("name"), "unnamed CycloneDX component")
            ref = component.get("bom-ref")
            if ref:
                require(isinstance(ref, str) and ref not in refs, "duplicate CycloneDX component reference")
                refs.add(ref)
            visit(component.get("components", []))
    root = document.get("metadata", {}).get("component")
    visit(([root] if root else []) + document.get("components", []))
    require(refs, "empty CycloneDX inventory")
    for dep in document.get("dependencies", []):
        require(dep.get("ref") in refs and all(value in refs for value in dep.get("dependsOn", [])), "dangling CycloneDX dependency")
