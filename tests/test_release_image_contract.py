from pathlib import Path
import re


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
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text()
    dockerfile = (ROOT / "scanner" / "Dockerfile").read_text()

    assert "${API_IMAGE_REPO:-shakerscan/shakerscan-api}" in _service_block(compose, "api")
    assert "${SCANNER_IMAGE_REPO:-shakerscan/shakerscan-scanner}" in _service_block(compose, "worker")
    assert "ARG INSTALL_DOCKER_CLI=0" in dockerfile
    assert "DOCKER_CLI_SHA256_X86_64" in dockerfile
    assert "DOCKER_CLI_SHA256_AARCH64" in dockerfile
    assert "BUILDX_VERSION" not in dockerfile
    assert "docker buildx version;" not in dockerfile

    assert "docker build --build-arg INSTALL_DOCKER_CLI=1" in workflow
    assert "worker image must not contain Docker" in workflow
    assert "runtime API must not carry Buildx" in workflow


def test_official_and_manual_publishers_ship_native_multiarch_api_image():
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text()
    publisher = (ROOT / "scripts" / "publish-images.sh").read_text()

    assert "API_IMAGE: shakerscan/shakerscan-api" in workflow
    assert "platform: linux/amd64" in workflow
    assert "platform: linux/arm64" in workflow
    assert "id: api" in workflow
    assert "INSTALL_DOCKER_CLI=1" in workflow
    assert "steps.api.outputs.digest" in workflow
    assert "Create API control-plane manifest list" in workflow
    assert 'docker buildx imagetools inspect "${API_IMAGE}:${VERSION}"' in workflow

    assert 'API_REPO="${API_IMAGE_REPO:-shakerscan/shakerscan-api}"' in publisher
    assert '--build-arg "INSTALL_DOCKER_CLI=1"' in publisher
    assert 'SCANNER_BUILD_ARGS=(--build-arg "SCANNER_VERSION=$VERSION_LABEL")' in publisher
    assert 'API_TAGS=(-t "$API_REPO:$TAG")' in publisher


def test_scanner_image_bakes_release_identity_for_broker_workers():
    dockerfile = (ROOT / "scanner" / "Dockerfile").read_text()
    compose = (ROOT / "docker-compose.yml").read_text()

    assert "ARG SCANNER_VERSION=dev" in dockerfile
    assert "ENV SCANNER_VERSION=${SCANNER_VERSION}" in dockerfile
    assert compose.count("SCANNER_VERSION: ${SCANNER_VERSION:-dev}") >= 5
