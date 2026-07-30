"""Fixed-function guest workload. Model-controlled command execution is absent."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import sys
import traceback

INPUT = Path("/input")
OUTPUT = Path("/output")
WORK = OUTPUT / "work"
STATE = WORK / "state.json"


def _load_state() -> dict:
    try:
        return json.loads(STATE.read_text())
    except (OSError, json.JSONDecodeError):
        return {"phases": {}, "errors": []}


def _save(state: dict) -> None:
    STATE.write_text(json.dumps(state, sort_keys=True, separators=(",", ":")))


def inventory() -> None:
    interfaces = sorted(name for _idx, name in socket.if_nameindex())
    print(json.dumps({"guest_interfaces": interfaces}, sort_keys=True))


def run_phase(phase: str) -> None:
    state = _load_state()
    job = json.loads((INPUT / "job.json").read_text())
    model_path = INPUT / "model"
    try:
        if phase == "import":
            import torch  # noqa: F401
            import transformers  # noqa: F401
            state["phases"][phase] = "PASS"
        elif phase == "tokenizer":
            from transformers import AutoTokenizer
            trust = bool(job.get("trust_remote_code"))
            tokenizer = AutoTokenizer.from_pretrained(model_path, local_files_only=True, trust_remote_code=trust)
            state["tokenizer_class"] = f"{tokenizer.__class__.__module__}.{tokenizer.__class__.__name__}"
            state["phases"][phase] = "PASS"
        elif phase == "model_load":
            from transformers import AutoModel
            trust = bool(job.get("trust_remote_code"))
            model = AutoModel.from_pretrained(
                model_path, local_files_only=True, trust_remote_code=trust,
                use_safetensors=not bool(job.get("allow_pickle")),
            )
            state["model_class"] = f"{model.__class__.__module__}.{model.__class__.__name__}"
            state["phases"][phase] = "PASS"
        elif phase == "warmup":
            import torch
            from transformers import AutoModel, AutoTokenizer
            trust = bool(job.get("trust_remote_code"))
            tokenizer = AutoTokenizer.from_pretrained(model_path, local_files_only=True, trust_remote_code=trust)
            model = AutoModel.from_pretrained(
                model_path, local_files_only=True, trust_remote_code=trust,
                use_safetensors=not bool(job.get("allow_pickle")),
            ).eval()
            encoded = tokenizer(["bounded warmup"], padding=True, truncation=True, return_tensors="pt")
            with torch.inference_mode():
                model(**encoded)
            state["phases"][phase] = "PASS"
        elif phase == "inference":
            import torch
            from transformers import AutoModel, AutoTokenizer
            trust = bool(job.get("trust_remote_code"))
            tokenizer = AutoTokenizer.from_pretrained(model_path, local_files_only=True, trust_remote_code=trust)
            model = AutoModel.from_pretrained(
                model_path, local_files_only=True, trust_remote_code=trust,
                use_safetensors=not bool(job.get("allow_pickle")),
            ).eval()
            texts = job.get("known_answer_inputs") or ["security review", "knowledge graph embedding"]
            encoded = tokenizer(texts, padding=True, truncation=True, return_tensors="pt")
            with torch.inference_mode():
                output = model(**encoded)
            hidden = output.last_hidden_state
            mask = encoded.get("attention_mask", torch.ones(hidden.shape[:2], dtype=hidden.dtype)).unsqueeze(-1)
            vectors = (hidden * mask).sum(1) / mask.sum(1).clamp(min=1)
            vector_bytes = vectors.detach().to(torch.float32).cpu().contiguous().numpy().tobytes()
            state["embedding_output_sha256"] = hashlib.sha256(vector_bytes).hexdigest()
            state["embedding_shape"] = list(vectors.shape)
            expected = job.get("known_answer_embedding_sha256")
            state["embedding_known_answers_status"] = "PASS" if not expected or expected == state["embedding_output_sha256"] else "FAIL"
            state["phases"][phase] = "PASS"
        elif phase == "teardown":
            import gc
            gc.collect()
            state["phases"][phase] = "PASS"
        else:
            raise ValueError("unsupported phase")
    except Exception as exc:
        state["phases"][phase] = "FAIL"
        state["errors"].append({"phase": phase, "type": type(exc).__name__, "message": str(exc)[:2000]})
        (WORK / f"error.{phase}.txt").write_text(traceback.format_exc()[-8000:])
        _save(state)
        raise
    _save(state)


def finalize(status: int) -> None:
    state = _load_state()
    try:
        interfaces = json.loads((OUTPUT / "interfaces.json").read_text()).get("guest_interfaces", [])
    except (OSError, json.JSONDecodeError):
        interfaces = []
    result = {
        "status": "PASS" if status == 0 and all(state.get("phases", {}).get(p) == "PASS" for p in ("import", "tokenizer", "model_load", "warmup", "inference", "teardown")) else "FAIL",
        "artifact_loaded": state.get("phases", {}).get("model_load") == "PASS",
        "model_loaded": state.get("phases", {}).get("model_load") == "PASS",
        "embedding_known_answers_status": state.get("embedding_known_answers_status", "NOT_RUN"),
        "embedding_output_sha256": state.get("embedding_output_sha256"),
        "embedding_shape": state.get("embedding_shape"),
        "guest_interfaces": interfaces,
        "phases": state.get("phases", {}),
        "errors": state.get("errors", []),
    }
    (OUTPUT / "result.json").write_text(json.dumps(result, sort_keys=True, separators=(",", ":")))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inventory", action="store_true")
    parser.add_argument("--phase", choices=("import", "tokenizer", "model_load", "warmup", "inference", "teardown"))
    parser.add_argument("--finalize", type=int)
    args = parser.parse_args()
    if args.inventory:
        inventory()
    elif args.phase:
        run_phase(args.phase)
    elif args.finalize is not None:
        finalize(args.finalize)
    else:
        parser.error("one fixed operation is required")
    return 0


if __name__ == "__main__":
    sys.exit(main())
