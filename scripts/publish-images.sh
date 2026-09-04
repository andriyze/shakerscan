#!/usr/bin/env bash
# Build and optionally push ShakerScan Docker Hub images with OCI labels.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

SCANNER_REPO="${SCANNER_IMAGE_REPO:-shakerscan/shakerscan-scanner}"
API_REPO="${API_IMAGE_REPO:-shakerscan/shakerscan-api}"
UI_REPO="${UI_IMAGE_REPO:-shakerscan/shakerscan-ui}"
SIGNER_REPO="${MODEL_INTAKE_SIGNER_IMAGE_REPO:-shakerscan/shakerscan-model-intake-signer}"
MODEL_INTAKE_REPO="${MODEL_INTAKE_IMAGE_REPO:-shakerscan/shakerscan-model-intake}"
TAG="${SCANNER_IMAGE_TAG:-}"
SOURCE_URL="${SOURCE_URL:-https://github.com/andriyze/shakerscan}"
IMAGE_URL="${IMAGE_URL:-https://hub.docker.com/r/shakerscan}"
PUSH=0
TAG_LATEST=0
ALLOW_DIRTY=0
NO_CACHE=0
PLATFORM=""

usage() {
    cat <<'EOF'
Usage: scripts/publish-images.sh [options]

Builds shakerscan/shakerscan-scanner and shakerscan/shakerscan-ui with OCI
image labels. With --push, --platform is required so release operators do not
accidentally publish a slow emulated multi-architecture build or a single-arch
tag over an official manifest.

Options:
  --push                  Push built images to the registry
  --latest                Also tag/push :latest
  --tag TAG               Image tag to use (default: VERSION file)
  --scanner-repo REPO     Scanner image repo (default: shakerscan/shakerscan-scanner)
  --api-repo REPO         API image repo (default: shakerscan/shakerscan-api)
  --ui-repo REPO          UI image repo (default: shakerscan/shakerscan-ui)
  --signer-repo REPO      Model Intake signer image repo
  --platform PLATFORM     build platform(s), e.g. linux/amd64 or linux/amd64,linux/arm64
  --no-cache              Build without cache
  --allow-dirty           Allow publishing from a dirty git worktree
  -h, --help              Show this help

Environment overrides:
  SCANNER_IMAGE_REPO, API_IMAGE_REPO, UI_IMAGE_REPO, MODEL_INTAKE_SIGNER_IMAGE_REPO,
  SCANNER_IMAGE_TAG, SOURCE_URL, IMAGE_URL

Examples:
  scripts/publish-images.sh --tag 0.3.2 --platform linux/arm64
  scripts/publish-images.sh --tag 0.3.2 --push --platform linux/amd64
  scripts/publish-images.sh --tag 0.3.2 --push --latest --platform linux/amd64,linux/arm64
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --push)
            PUSH=1
            shift
            ;;
        --latest)
            TAG_LATEST=1
            shift
            ;;
        --tag)
            TAG="${2:-}"
            if [[ -z "$TAG" ]]; then
                echo "Error: --tag requires a value" >&2
                exit 1
            fi
            shift 2
            ;;
        --scanner-repo)
            SCANNER_REPO="${2:-}"
            if [[ -z "$SCANNER_REPO" ]]; then
                echo "Error: --scanner-repo requires a value" >&2
                exit 1
            fi
            shift 2
            ;;
        --api-repo)
            API_REPO="${2:-}"
            if [[ -z "$API_REPO" ]]; then
                echo "Error: --api-repo requires a value" >&2
                exit 1
            fi
            shift 2
            ;;
        --ui-repo)
            UI_REPO="${2:-}"
            if [[ -z "$UI_REPO" ]]; then
                echo "Error: --ui-repo requires a value" >&2
                exit 1
            fi
            shift 2
            ;;
        --signer-repo)
            SIGNER_REPO="${2:-}"
            if [[ -z "$SIGNER_REPO" ]]; then
                echo "Error: --signer-repo requires a value" >&2
                exit 1
            fi
            shift 2
            ;;
        --platform)
            PLATFORM="${2:-}"
            if [[ -z "$PLATFORM" ]]; then
                echo "Error: --platform requires a value" >&2
                exit 1
            fi
            shift 2
            ;;
        --no-cache)
            NO_CACHE=1
            shift
            ;;
        --allow-dirty)
            ALLOW_DIRTY=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Error: unknown option: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

if [[ -z "$TAG" ]]; then
    if [[ -f VERSION ]]; then
        TAG="$(head -n 1 VERSION | tr -d '[:space:]')"
    fi
fi

if [[ -z "$TAG" ]]; then
    echo "Error: no image tag provided and VERSION is empty/missing" >&2
    exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
    echo "Error: docker is required" >&2
    exit 1
fi

if ! docker info >/dev/null 2>&1; then
    echo "Error: Docker is not running or is not accessible" >&2
    exit 1
fi

if ! docker buildx version >/dev/null 2>&1; then
    echo "Error: docker buildx is required for release builds" >&2
    exit 1
fi

REVISION="unknown"
SHORT_REVISION="unknown"
DIRTY_SUFFIX=""
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    REVISION="$(git rev-parse HEAD)"
    SHORT_REVISION="$(git rev-parse --short HEAD)"
    if ! git diff --quiet --ignore-submodules -- || ! git diff --cached --quiet --ignore-submodules --; then
        if [[ "$ALLOW_DIRTY" -ne 1 ]]; then
            echo "Error: git worktree is dirty. Commit first or pass --allow-dirty." >&2
            exit 1
        fi
        DIRTY_SUFFIX="-dirty"
    fi
fi

CREATED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
VERSION_LABEL="$TAG"
REVISION_LABEL="${REVISION}${DIRTY_SUFFIX}"

if [[ -z "$PLATFORM" ]]; then
    if [[ "$PUSH" -eq 1 ]]; then
        echo "Error: --push requires explicit --platform. Use the GitHub Release workflow for official multi-arch releases." >&2
        exit 1
    else
        PLATFORM="$(docker info --format '{{.OSType}}/{{.Architecture}}')"
        if [[ "$PLATFORM" == "linux/aarch64" ]]; then
            PLATFORM="linux/arm64"
        fi
    fi
fi

BUILD_ARGS=(--platform "$PLATFORM")
SCANNER_BUILD_ARGS=(
  --build-arg "SCANNER_VERSION=$VERSION_LABEL"
  --build-arg "SCANNER_SOURCE_REVISION=$REVISION_LABEL"
)
OUTPUT_ARGS=()
if [[ "$PUSH" -eq 1 ]]; then
    OUTPUT_ARGS+=(--push)
else
    if [[ "$PLATFORM" == *,* ]]; then
        echo "Error: multi-platform builds require --push. Use one platform for local builds." >&2
        exit 1
    fi
    OUTPUT_ARGS+=(--load)
fi
if [[ "$NO_CACHE" -eq 1 ]]; then
    BUILD_ARGS+=(--no-cache)
fi

COMMON_LABELS=(
    --label "org.opencontainers.image.created=$CREATED"
    --label "org.opencontainers.image.version=$VERSION_LABEL"
    --label "org.opencontainers.image.revision=$REVISION_LABEL"
    --label "org.opencontainers.image.source=$SOURCE_URL"
    --label "org.opencontainers.image.url=$IMAGE_URL"
    --label "org.opencontainers.image.documentation=$SOURCE_URL#readme"
    --label "org.opencontainers.image.licenses=AGPL-3.0-only"
    --label "org.opencontainers.image.vendor=ShakerScan"
)

echo "Publishing metadata:"
echo "  version:  $VERSION_LABEL"
echo "  revision: $REVISION_LABEL"
echo "  created:  $CREATED"
echo "  scanner:  $SCANNER_REPO:$TAG"
echo "  api:      $API_REPO:$TAG"
echo "  ui:       $UI_REPO:$TAG"
echo "  signer:   $SIGNER_REPO:$TAG"
echo "  intake:   $MODEL_INTAKE_REPO:$TAG"
echo "  platform: $PLATFORM"
echo

SCANNER_TAGS=(-t "$SCANNER_REPO:$TAG")
API_TAGS=(-t "$API_REPO:$TAG")
UI_TAGS=(-t "$UI_REPO:$TAG")
SIGNER_TAGS=(-t "$SIGNER_REPO:$TAG")
MODEL_INTAKE_TAGS=(-t "$MODEL_INTAKE_REPO:$TAG")
if [[ "$TAG_LATEST" -eq 1 ]]; then
    SCANNER_TAGS+=(-t "$SCANNER_REPO:latest")
    API_TAGS+=(-t "$API_REPO:latest")
    UI_TAGS+=(-t "$UI_REPO:latest")
    SIGNER_TAGS+=(-t "$SIGNER_REPO:latest")
    MODEL_INTAKE_TAGS+=(-t "$MODEL_INTAKE_REPO:latest")
fi

docker buildx build \
    "${BUILD_ARGS[@]}" \
    "${SCANNER_BUILD_ARGS[@]}" \
    "${OUTPUT_ARGS[@]}" \
    "${COMMON_LABELS[@]}" \
    --label "org.opencontainers.image.title=ShakerScan Scanner" \
    --label "org.opencontainers.image.description=Open-source DAST scanner API, worker, and security tooling image" \
    "${SCANNER_TAGS[@]}" \
    -f scanner/Dockerfile \
    .

docker buildx build \
    "${BUILD_ARGS[@]}" \
    "${OUTPUT_ARGS[@]}" \
    "${COMMON_LABELS[@]}" \
    --label "org.opencontainers.image.title=ShakerScan API Control Plane" \
    --label "org.opencontainers.image.description=ShakerScan API with checksum-pinned Docker client for Model Intake guest staging" \
    --build-arg "SCANNER_RUNTIME_IMAGE=$SCANNER_REPO:$TAG" \
    "${API_TAGS[@]}" \
    -f scanner/Dockerfile.api \
    .

docker buildx build \
    "${BUILD_ARGS[@]}" \
    "${OUTPUT_ARGS[@]}" \
    "${COMMON_LABELS[@]}" \
    --label "org.opencontainers.image.title=ShakerScan Model Intake" \
    --label "org.opencontainers.image.description=ShakerScan Model Intake worker and sandbox: the scanner runtime plus the artifact-scanning toolchain" \
    --build-arg "SCANNER_RUNTIME_IMAGE=$SCANNER_REPO:$TAG" \
    "${MODEL_INTAKE_TAGS[@]}" \
    -f scanner/Dockerfile.model-intake \
    .

docker buildx build \
    "${BUILD_ARGS[@]}" \
    "${OUTPUT_ARGS[@]}" \
    "${COMMON_LABELS[@]}" \
    --label "org.opencontainers.image.title=ShakerScan Model Intake Signer" \
    --label "org.opencontainers.image.description=Narrow Model Intake admission signer trust service" \
    "${SIGNER_TAGS[@]}" \
    -f api/model_intake_signer.Dockerfile \
    .

docker buildx build \
    "${BUILD_ARGS[@]}" \
    "${OUTPUT_ARGS[@]}" \
    "${COMMON_LABELS[@]}" \
    --label "org.opencontainers.image.title=ShakerScan UI" \
    --label "org.opencontainers.image.description=Open-source ShakerScan web dashboard" \
    --build-arg "NEXT_PUBLIC_APP_VERSION=$TAG" \
    "${UI_TAGS[@]}" \
    -f ui/Dockerfile \
    ./ui

if [[ "$PUSH" -ne 1 ]]; then
    echo
    echo "Build complete. Re-run with --push --platform $PLATFORM to publish this platform."
    echo "Use the GitHub Release workflow for official linux/amd64 + linux/arm64 manifests."
fi
