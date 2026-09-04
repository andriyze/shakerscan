from pathlib import Path
import re

import yaml


ROOT = Path(__file__).resolve().parents[1]


def _service_block(compose: str, service: str) -> str:
    match = re.search(
        rf"(?ms)^  {re.escape(service)}:\n.*?(?=^  [A-Za-z0-9_-]+:\n|\Z)",
        compose,
    )
    assert match is not None, service
    return match.group(0)


def test_release_images_keep_docker_client_at_control_plane_boundary():
    compose = (ROOT / "docker-compose.release.yml").read_text()
    workflow = (ROOT / ".github" / "workflows" / "release-candidate.yml").read_text()
    dockerfile = (ROOT / "scanner" / "Dockerfile").read_text()
    api_dockerfile = (ROOT / "scanner" / "Dockerfile.api").read_text()

    assert "${API_IMAGE:-shakerscan/shakerscan-api:latest}" in _service_block(compose, "api")
    assert "${SCANNER_IMAGE:-shakerscan/shakerscan-scanner:latest}" in _service_block(compose, "worker")
    assert "DOCKER_CLI_SHA256" not in dockerfile
    assert "ARG SCANNER_RUNTIME_IMAGE=" in api_dockerfile
    assert "FROM ${SCANNER_RUNTIME_IMAGE}" in api_dockerfile
    assert "AS scanner-runtime" in api_dockerfile
    assert "USER 10002:10002" in api_dockerfile
    assert "COPY --from=scanner-runtime /opt/tools" not in api_dockerfile
    assert "DOCKER_CLI_SHA256_X86_64" in api_dockerfile
    assert "DOCKER_CLI_SHA256_AARCH64" in api_dockerfile
    assert "BUILDX_VERSION" not in dockerfile
    assert "docker buildx version" in api_dockerfile

    assert "SCANNER_RUNTIME_IMAGE=shakerscan-scanner:release-candidate" in workflow
    assert "file: scanner/Dockerfile.api" in workflow
    assert "worker image must not contain Docker" in workflow
    assert "runtime API must not carry Buildx" in workflow


def test_official_and_manual_publishers_ship_native_multiarch_api_image():
    workflow = (ROOT / ".github" / "workflows" / "release-candidate.yml").read_text()
    publisher = (ROOT / "scripts" / "publish-images.sh").read_text()

    assert "API_IMAGE: shakerscan/shakerscan-api" in workflow
    assert "platform: linux/amd64" in workflow
    assert "platform: linux/arm64" in workflow
    assert "id: api" in workflow
    assert "SCANNER_RUNTIME_IMAGE=${{ env.SCANNER_IMAGE }}@${{ steps.scanner.outputs.digest }}" in workflow
    assert "steps.api.outputs.digest" in workflow
    assert "Create API control-plane manifest list" in workflow
    assert 'docker buildx imagetools inspect "${API_IMAGE}:${CANDIDATE_TAG}"' in workflow

    assert 'API_REPO="${API_IMAGE_REPO:-shakerscan/shakerscan-api}"' in publisher
    assert '--build-arg "SCANNER_RUNTIME_IMAGE=$SCANNER_REPO:$TAG"' in publisher
    assert '-f scanner/Dockerfile.api' in publisher
    assert 'API_TAGS=(-t "$API_REPO:$TAG")' in publisher


def test_release_images_publish_sboms_and_verified_final_digest_provenance():
    workflow = (ROOT / ".github" / "workflows" / "release-candidate.yml").read_text()
    promotion = (ROOT / ".github" / "workflows" / "release.yml").read_text()

    assert workflow.count("provenance: mode=max") == 5
    assert workflow.count("sbom: true") == 5
    attest_uses = re.findall(r"uses: actions/attest@([0-9a-f]{40})", workflow)
    assert len(attest_uses) == 5
    assert len(set(attest_uses)) == 1
    assert workflow.count("push-to-registry: true") == 5
    assert workflow.count("create-storage-record: false") == 5
    # merge verifies the five final manifests; meta additionally verifies a reusable
    # build-on-main set inside one loop before certifying by digest.
    assert workflow.count("gh attestation verify") == 6
    assert "github-actions-sigstore" in workflow
    assert "final-multiarch-image-digests" in workflow
    assert "attestations: write" in workflow

    assert "attestations: read" in promotion
    assert "Reverify signed candidate provenance" in promotion
    assert "gh attestation verify" in promotion
    assert ".provenance.verified == true" in promotion


def test_release_scans_every_final_manifest_and_requires_explicit_waivers():
    workflow = (ROOT / ".github" / "workflows" / "release-candidate.yml").read_text()
    promotion = (ROOT / ".github" / "workflows" / "release.yml").read_text()
    # The scans run in parallel with certification; they still gate publication because
    # promotion accepts only a candidate run whose overall conclusion is success.
    assert "needs: [meta, merge]\n" in workflow[workflow.index("  certify:"):]
    assert "  vulnerability-scan:\n" in workflow
    assert '== "success $CANDIDATE_SHA"' in promotion
    for image in ("scanner", "api", "ui", "signer", "model-intake"):
        assert f"- name: {image}" in workflow
    assert "severity: HIGH,CRITICAL" in workflow
    assert "ignore-unfixed: true" in workflow
    assert "skip-dirs: ${{ matrix.target.skip_dirs }}" in workflow
    assert "skip-files: ${{ matrix.target.skip_files }}" in workflow
    model_intake = workflow.split("- name: model-intake", 1)[1].split("- name: ui", 1)[0]
    assert 'skip_dirs: ""' in model_intake
    assert 'skip_files: ""' in model_intake
    assert "/opt/model-intake-tools" not in workflow
    assert "/opt/tools/trivy,/opt/tools/osv-scanner" not in workflow
    assert '--skip-dirs "${{ matrix.target.skip_dirs }}"' in workflow
    assert '--skip-files "${{ matrix.target.skip_files }}"' in workflow
    assert "exit-code: 1" in workflow
    assert "scanners: vuln" in workflow
    assert "TRIVY_PLATFORM: ${{ matrix.platform.value }}" in workflow
    assert "value: linux/amd64" in workflow
    assert "value: linux/arm64" in workflow
    assert "validate_vulnerability_waivers.py" in workflow


def test_release_images_remove_fixable_runtime_vulnerabilities():
    scanner = (ROOT / "scanner" / "Dockerfile").read_text()
    ui = (ROOT / "ui" / "Dockerfile").read_text()

    assert "golang:1.27.0-bookworm@sha256:" in scanner
    assert "github.com/projectdiscovery/nuclei/v3/cmd/nuclei v3.11.1" in scanner
    for dependency in (
        "github.com/getkin/kin-openapi@v0.144.0",
        "github.com/go-git/go-git/v5@v5.19.2",
        "github.com/labstack/echo/v4@v4.15.3",
        "golang.org/x/mod@v0.40.0",
    ):
        assert dependency in scanner
    assert "pip uninstall -y --break-system-packages msgpack setuptools" in scanner
    assert "pip uninstall -y --break-system-packages pip" in scanner
    assert 'find_spec("pip") is None' in scanner
    assert "nikto masscan python3-pip" not in scanner
    for build_only_package in (
        "python3-venv", "python3.12-venv", "python3-pip-whl", "python3-setuptools-whl",
    ):
        assert build_only_package in scanner.split("apt-get purge -y --auto-remove", 1)[1]
    assert scanner.index("COPY scanner/Dockerfile /opt/build-inputs/scanner.Dockerfile") > (
        scanner.index("pip uninstall -y --break-system-packages pip")
    )
    assert "rm -f /usr/lib/python3/dist-packages/distutils-precedence.pth" in scanner
    assert "test -z \"$(python -c 'pass' 2>&1)\"" in scanner

    assert "node:26-alpine@sha256:" in ui
    assert ui.count("apk add --no-cache --upgrade") == 2
    assert ui.count("APK_TOOLS_VERSION=3.0.8-r0") == 2
    assert ui.count("OPENSSL_VERSION=3.5.8-r0") == 2
    assert ui.count("Pinned Alpine security update failed after 4 attempts") == 2
    assert "rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx" in ui


def test_release_component_builds_have_independent_retry_domains():
    workflow = yaml.safe_load(
        (ROOT / ".github" / "workflows" / "release-candidate.yml").read_text()
    )
    jobs = workflow["jobs"]

    assert {"build-runtime", "build-ui", "build-signer"} <= set(jobs)
    assert jobs["merge"]["needs"] == [
        "meta", "validate", "build-runtime", "build-ui", "build-signer",
    ]
    runtime_steps = "\n".join(step.get("name", "") for step in jobs["build-runtime"]["steps"])
    ui_steps = "\n".join(step.get("name", "") for step in jobs["build-ui"]["steps"])
    signer_steps = "\n".join(step.get("name", "") for step in jobs["build-signer"]["steps"])
    assert "Build and push scanner by digest" in runtime_steps
    assert "Build and push API control plane by digest" in runtime_steps
    assert "Build and push Model Intake by digest" in runtime_steps
    assert "Build and push UI by digest" not in runtime_steps
    assert "Build and push signer by digest" not in runtime_steps
    assert "Build and push UI by digest" in ui_steps
    assert "Build and push signer by digest" in signer_steps

    # The API and Model Intake images both derive from the scanner digest built in the same job, so
    # they share the runtime retry domain; UI and signer stay independent.
    expected_cache_scopes = {
        "build-runtime": ("scanner", "api", "model-intake"),
        "build-ui": ("ui",),
        "build-signer": ("signer",),
    }
    for job_name, scopes in expected_cache_scopes.items():
        build_steps = [
            step for step in jobs[job_name]["steps"]
            if step.get("uses", "").startswith("docker/build-push-action@")
        ]
        assert len(build_steps) == len(scopes)
        for step, scope in zip(build_steps, scopes, strict=True):
            assert step["with"]["cache-from"] == (
                f"type=gha,scope={scope}-${{{{ env.PLATFORM_PAIR }}}}"
            )
            assert step["with"]["cache-to"] == (
                f"type=gha,mode=max,scope={scope}-${{{{ env.PLATFORM_PAIR }}}}"
            )


def test_scanner_image_bakes_release_identity_for_broker_workers():
    dockerfile = (ROOT / "scanner" / "Dockerfile").read_text()
    compose = (ROOT / "docker-compose.yml").read_text()
    workflow = (ROOT / ".github" / "workflows" / "release-candidate.yml").read_text()

    assert "ARG SCANNER_VERSION=dev" in dockerfile
    assert "ARG SCANNER_SOURCE_REVISION=unknown" in dockerfile
    assert "ENV SCANNER_VERSION=${SCANNER_VERSION}" in dockerfile
    assert "release-manifest.json" in dockerfile
    assert dockerfile.index("ARG SCANNER_VERSION=dev") > dockerfile.index("COPY api/*.py /app/")
    assert dockerfile.index("ARG SCANNER_VERSION=dev") > dockerfile.index("RUN pip install")
    assert "release_identity.py --verify" in (ROOT / "scanner" / "entrypoint.sh").read_text()
    # Only services that actually own a scanner build carry build arguments.
    # Agent, device, and sandbox consumers reuse the worker image so a clean
    # source start cannot export the same multi-gigabyte image repeatedly.
    # The API overlay starts from the Playwright base, so it must receive the identity too.
    for service in ("fleet-edge", "worker", "gungnir-worker", "api"):
        assert "SCANNER_VERSION: ${SCANNER_VERSION:-dev}" in _service_block(compose, service)
        assert "SCANNER_SOURCE_REVISION: ${GIT_COMMIT:-unknown}" in _service_block(compose, service)
    assert "SCANNER_RUNTIME_IMAGE: ${SCANNER_LOCAL_WORKER_IMAGE:-shakerscan-worker:local}" in _service_block(compose, "api")
    for service in ("agent-tool-worker", "device-worker", "model-intake-sandbox", "model-intake-worker"):
        assert "SCANNER_VERSION: ${SCANNER_VERSION:-dev}" not in _service_block(compose, service)
    # validate: scanner + API docker builds; build-runtime: scanner + API build-push steps.
    assert workflow.count("SCANNER_VERSION=${{ needs.meta.outputs.version }}") == 4
    assert "Verify baked scanner release identity" in workflow
    assert "SCANNER_SOURCE_REVISION=${{ needs.meta.outputs.candidate_sha }}" in workflow
    assert "0.0.0-intentional-mismatch" in workflow
    assert "accepted an intentionally wrong deployment identity" in workflow
    assert 'baked SCANNER_VERSION=$baked_version; expected $VERSION' in workflow


def _build_step_for(workflow: Path, dockerfile: str) -> dict:
    document = yaml.safe_load(workflow.read_text())
    steps = [
        step
        for job in document["jobs"].values()
        for step in job.get("steps", [])
        if isinstance(step, dict) and (step.get("with") or {}).get("file") == dockerfile
    ]
    assert len(steps) == 1, (workflow.name, dockerfile, len(steps))
    return steps[0]


def _step_named(workflow: Path, name: str) -> dict:
    document = yaml.safe_load(workflow.read_text())
    steps = [
        step
        for job in document["jobs"].values()
        for step in job.get("steps", [])
        if isinstance(step, dict) and step.get("name") == name
    ]
    assert len(steps) == 1, (workflow.name, name, len(steps))
    return steps[0]


def test_api_image_bakes_the_same_release_identity_environment_as_the_runtime():
    """The slim control plane starts again from the Playwright base, so it does not inherit
    the scanner's ENV. build-on-main 33886615072 pushed an API image whose SCANNER_VERSION was
    empty and every arch failed the baked-identity gate. Every API build site must pass the
    scanner's own identity, and the Dockerfile must fail closed against the copied manifest."""
    api_dockerfile = (ROOT / "scanner" / "Dockerfile.api").read_text()
    assert "ARG SCANNER_VERSION=dev" in api_dockerfile
    assert "ARG SCANNER_SOURCE_REVISION=unknown" in api_dockerfile
    assert "ENV SCANNER_VERSION=${SCANNER_VERSION}" in api_dockerfile
    assert "ENV SHAKERSCAN_BUILD_VERSION=${SCANNER_VERSION}" in api_dockerfile
    assert "ENV SHAKERSCAN_SOURCE_REVISION=${SCANNER_SOURCE_REVISION}" in api_dockerfile
    assert 'test -n "$SCANNER_VERSION" && test -n "$SHAKERSCAN_SOURCE_REVISION"' in api_dockerfile
    assert 'SCANNER_EXPECTED_VERSION="$SCANNER_VERSION"' in api_dockerfile
    assert 'SCANNER_EXPECTED_REVISION="$SHAKERSCAN_SOURCE_REVISION"' in api_dockerfile
    assert api_dockerfile.count("release_identity.py --verify") == 1
    # Declared after the heavy layers and after the manifest it is checked against.
    version_arg = api_dockerfile.index("ARG SCANNER_VERSION=dev")
    assert version_arg > api_dockerfile.index("install -m 0755 /tmp/docker/docker")
    assert version_arg > api_dockerfile.index("pip uninstall")
    assert version_arg > api_dockerfile.index(
        "COPY --from=scanner-runtime /opt/shakerscan/release-manifest.json"
    )

    reusable = ROOT / ".github" / "workflows" / "_build-images.yml"
    candidate = ROOT / ".github" / "workflows" / "release-candidate.yml"
    for workflow, version, revision in (
        (reusable, "${{ inputs.version }}", "${{ inputs.candidate_sha }}"),
        (candidate, "${{ needs.meta.outputs.version }}", "${{ needs.meta.outputs.candidate_sha }}"),
    ):
        scanner_args = _build_step_for(workflow, "scanner/Dockerfile")["with"]["build-args"].splitlines()
        api_args = _build_step_for(workflow, "scanner/Dockerfile.api")["with"]["build-args"].splitlines()
        for argument in (f"SCANNER_VERSION={version}", f"SCANNER_SOURCE_REVISION={revision}"):
            assert argument in scanner_args, (workflow.name, argument)
            assert argument in api_args, (workflow.name, argument)
        assert any(line.startswith("SCANNER_RUNTIME_IMAGE=") for line in api_args)

    validate_build = _step_named(candidate, "Build locked API control-plane image")["run"]
    assert "--build-arg SCANNER_VERSION=${{ needs.meta.outputs.version }}" in validate_build
    assert "--build-arg SCANNER_SOURCE_REVISION=${{ needs.meta.outputs.candidate_sha }}" in validate_build
    validate_check = _step_named(candidate, "Verify locked API control-plane image")["run"]
    assert "shakerscan-api:release-candidate | awk -F= '$1 == \"SCANNER_VERSION\" {print $2}'" in validate_check

    publisher = (ROOT / "scripts" / "publish-images.sh").read_text()
    api_build = publisher[publisher.index("ShakerScan API Control Plane"):publisher.index("-f scanner/Dockerfile.api")]
    assert '"${SCANNER_BUILD_ARGS[@]}"' in api_build

    smoke = (ROOT / "scripts" / "docker_api_overlay_smoke.sh").read_text()
    assert '--build-arg "SCANNER_VERSION=$worker_version"' in smoke
    assert '--build-arg "SCANNER_SOURCE_REVISION=$worker_revision"' in smoke
    assert "for name in SCANNER_VERSION SHAKERSCAN_BUILD_VERSION SHAKERSCAN_SOURCE_REVISION" in smoke


def test_scanner_image_contains_runtime_device_catalog():
    dockerfile = (ROOT / "scanner" / "Dockerfile").read_text()

    assert "COPY scanner/data /app/data" in dockerfile
    assert (ROOT / "scanner" / "data" / "device_api_catalog.json").is_file()


def test_release_api_image_contains_hunt_methodology_catalog():
    dockerfile = (ROOT / "scanner" / "Dockerfile").read_text()

    assert "COPY skills/web /app/skills/web" in dockerfile
    assert (ROOT / "skills" / "web" / "README.md").is_file()
    assert len(list((ROOT / "skills" / "web").glob("[0-9][0-9]-*.md"))) == 31


def test_fresh_installer_downloads_every_hunt_methodology_asset():
    installers = (
        (ROOT / "install" / "index.sh").read_text(),
        (ROOT / "install" / "index.html").read_text(),
    )
    assets = [
        path.relative_to(ROOT / "skills" / "web").as_posix()
        for path in (ROOT / "skills" / "web").rglob("*.md")
    ]
    assert len(assets) == 39
    for installer in installers:
        assert 'mkdir -p "$INSTALL_STAGE/skills/web/core"' in installer
        for relative in assets:
            assert relative.split("/")[-1] in installer


def test_release_compose_has_dedicated_agent_tool_fast_lane():
    release = (ROOT / "docker-compose.release.yml").read_text()
    local = (ROOT / "docker-compose.yml").read_text()

    for compose in (release, local):
        assert "agent-tool-worker:" in compose
        assert "AGENT_TOOL_ONLY_WORKER=true" in compose
        assert "AGENT_TOOL_QUEUE_NAME=" in compose
