#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE_DIGEST="${MODEL_INTAKE_WEBHOOK_IMAGE_DIGEST:-}"
API_URL="${SHAKERSCAN_API_URL:-}"
VERIFIER_TOKEN="${MODEL_INTAKE_DEPLOYMENT_VERIFIER_TOKEN:-}"
ISSUER_NAME="${MODEL_INTAKE_WEBHOOK_CLUSTER_ISSUER:-shakerscan-ca}"

if [[ ! "$IMAGE_DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    echo "MODEL_INTAKE_WEBHOOK_IMAGE_DIGEST must be an immutable sha256 digest" >&2
    exit 1
fi
if [[ ! "$API_URL" =~ ^https:// ]]; then
    echo "SHAKERSCAN_API_URL must use HTTPS" >&2
    exit 1
fi
if [[ ${#VERIFIER_TOKEN} -lt 32 ]]; then
    echo "MODEL_INTAKE_DEPLOYMENT_VERIFIER_TOKEN must contain at least 32 characters" >&2
    exit 1
fi
for command in kubectl sed; do
    command -v "$command" >/dev/null || { echo "$command is required" >&2; exit 1; }
done

temporary="$(mktemp)"
cleanup() { rm -f "$temporary"; }
trap cleanup EXIT
sed \
    -e "s|REPLACE_WITH_DIGEST|$IMAGE_DIGEST|g" \
    -e "s|REPLACE_WITH_CLUSTER_ISSUER|$ISSUER_NAME|g" \
    "$ROOT_DIR/deploy/kubernetes/model-intake-validating-webhook.yaml" > "$temporary"
kubectl create namespace shakerscan-system --dry-run=client -o yaml | kubectl apply -f -
kubectl -n shakerscan-system create secret generic shakerscan-model-admission-config \
    --from-literal=api-url="$API_URL" \
    --from-literal=verifier-token="$VERIFIER_TOKEN" \
    --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f "$temporary"
kubectl -n shakerscan-system rollout status deployment/shakerscan-model-admission --timeout=180s
echo "Label only intended namespaces with: shakerscan.dev/model-admission=enabled"
