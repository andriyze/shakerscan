#!/usr/bin/env bash
set -euo pipefail

IMAGE="${MODEL_INTAKE_GUEST_IMAGE:-shakerscan-model-intake-guest:selftest}"
PLATFORM="${MODEL_INTAKE_GUEST_PLATFORM:-linux/amd64}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEMP_DIR="$(mktemp -d)"
cleanup() {
    # The container deliberately writes as a different uid during this
    # boundary test. Remove its bind-mounted children as container root first,
    # then let the invoking user remove the now-empty private temp directory.
    if docker image inspect "$IMAGE" >/dev/null 2>&1; then
        docker run --rm --network none -v "$TEMP_DIR:/cleanup" \
            --entrypoint /bin/rm "$IMAGE" -rf /cleanup/input /cleanup/output \
            >/dev/null 2>&1 || true
    fi
    rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

mkdir -p "$TEMP_DIR/input/model" "$TEMP_DIR/output/work"
chmod -R 0777 "$TEMP_DIR"
docker build --platform "$PLATFORM" -f "$ROOT_DIR/runner/guest/Dockerfile" -t "$IMAGE" "$ROOT_DIR"

DOCKER=(docker run --rm --platform "$PLATFORM" --network none --entrypoint /opt/venv/bin/python)
"${DOCKER[@]}" -v "$TEMP_DIR/input:/input" "$IMAGE" -c '
from pathlib import Path
from transformers import BertConfig, BertModel, BertTokenizer
p = Path("/input/model")
v = p / "vocab.txt"
v.write_text("[PAD]\n[UNK]\n[CLS]\n[SEP]\n[MASK]\nsecurity\nreview\nknowledge\ngraph\nembedding\nbounded\nwarmup\n")
BertTokenizer(str(v)).save_pretrained(p)
BertModel(BertConfig(vocab_size=12, hidden_size=16, num_hidden_layers=1, num_attention_heads=2, intermediate_size=32)).save_pretrained(p, safe_serialization=False)
(Path("/input") / "job.json").write_text("{\"mode\":\"conversion\",\"trust_remote_code\":false,\"allow_pickle\":true,\"known_answer_inputs\":[\"security review\",\"knowledge graph embedding\"]}")
'

for phase in import deserialize_convert tensor_equivalence embedding_equivalence teardown; do
    "${DOCKER[@]}" \
        -v "$TEMP_DIR/input:/input:ro" -v "$TEMP_DIR/output:/output" \
        "$IMAGE" /opt/shakerscan/guest_worker.py --phase "$phase"
done
"${DOCKER[@]}" \
    -v "$TEMP_DIR/input:/input:ro" -v "$TEMP_DIR/output:/output" \
    "$IMAGE" /opt/shakerscan/guest_worker.py --finalize 0
"${DOCKER[@]}" -v "$TEMP_DIR/output:/output:ro" "$IMAGE" -c '
import json
r = json.load(open("/output/result.json"))
assert r["status"] == "PASS", r
assert r["tensor_inventory_equivalent"] is True, r
assert r["numeric_equivalence_status"] == "PASS", r
assert r["embedding_equivalence_status"] == "PASS", r
assert r["embedding_max_abs_difference"] == 0.0, r
print("model-intake guest conversion self-test: PASS")
'
