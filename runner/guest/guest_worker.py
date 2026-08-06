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

# A known-answer digest is byte-exact evidence. Keep all CPU reduction
# libraries single-threaded before PyTorch imports so large embedding models
# cannot change floating-point reduction order between microVM executions.
for _thread_env in ("OMP_NUM_THREADS", "MKL_NUM_THREADS", "OPENBLAS_NUM_THREADS"):
    os.environ[_thread_env] = "1"

_TORCH_THREAD_LIMITS_CONFIGURED = False


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_state() -> dict:
    try:
        return json.loads(STATE.read_text())
    except (OSError, json.JSONDecodeError):
        return {"phases": {}, "errors": []}


def _save(state: dict) -> None:
    STATE.write_text(json.dumps(state, sort_keys=True, separators=(",", ":")))


def _source_bin(model_path: Path) -> Path:
    candidates = sorted(model_path.glob("*.bin"))
    if len(candidates) != 1:
        raise ValueError("conversion requires exactly one top-level .bin artifact")
    return candidates[0]


def _state_dict(value):
    import torch
    if isinstance(value, dict) and isinstance(value.get("state_dict"), dict):
        value = value["state_dict"]
    if not isinstance(value, dict) or not value:
        raise ValueError("source artifact is not a non-empty state dictionary")
    normalized = {}
    for key, tensor in value.items():
        if not isinstance(key, str) or not isinstance(tensor, torch.Tensor):
            raise ValueError("source state dictionary contains a non-tensor member")
        normalized[key] = tensor.detach().cpu().contiguous()
    return normalized


def _install_transformers_compatibility() -> None:
    """Install only identity-preserving aliases required by reviewed legacy code.

    Some older Hugging Face repositories import ``Conv1D`` from
    ``transformers.modeling_utils``.  Current Transformers exposes the same
    class from ``transformers.pytorch_utils``.  Binding that exact class under
    its former public location lets the digest-pinned runtime assess the
    repository without editing model-controlled source or relaxing the loader.
    """
    import transformers.modeling_utils as modeling_utils
    if not hasattr(modeling_utils, "Conv1D"):
        from transformers.pytorch_utils import Conv1D
        modeling_utils.Conv1D = Conv1D


def _configure_deterministic_torch(torch) -> None:
    global _TORCH_THREAD_LIMITS_CONFIGURED
    # PyTorch only permits set_num_interop_threads before parallel work starts
    # and at most once per process. Conversion equivalence deliberately loads
    # the source and converted model in the same bounded phase, so make the
    # process-wide thread setup idempotent while reseeding each evaluation.
    if not _TORCH_THREAD_LIMITS_CONFIGURED:
        torch.set_num_threads(1)
        torch.set_num_interop_threads(1)
        _TORCH_THREAD_LIMITS_CONFIGURED = True
    torch.manual_seed(0)
    torch.use_deterministic_algorithms(True)


def _mean_embeddings(model_path: Path, texts: list[str], *, trust: bool, safe: bool):
    import gc
    import torch
    # Compare the two serializers under one deterministic CPU execution
    # contract. Parallel reduction order can otherwise introduce small output
    # drift even when every source and target tensor is byte-equivalent.
    _configure_deterministic_torch(torch)
    _install_transformers_compatibility()
    from transformers import AutoModel, AutoTokenizer
    tokenizer = AutoTokenizer.from_pretrained(model_path, local_files_only=True, trust_remote_code=trust)
    model = AutoModel.from_pretrained(
        model_path, local_files_only=True, trust_remote_code=trust, use_safetensors=safe,
    ).eval()
    encoded = tokenizer(texts, padding=True, truncation=True, return_tensors="pt")
    with torch.inference_mode():
        output = model(**encoded)
    hidden = output.last_hidden_state
    mask = encoded.get("attention_mask", torch.ones(hidden.shape[:2], dtype=hidden.dtype)).unsqueeze(-1)
    vectors = ((hidden * mask).sum(1) / mask.sum(1).clamp(min=1)).detach().to(torch.float32).cpu().clone()
    # Source and converted serializers are evaluated sequentially in one
    # phase. Drop every model-owned object before loading the second copy so a
    # large model cannot retain both parameter sets through Python cycles.
    del output, hidden, mask, encoded, model, tokenizer
    gc.collect()
    return vectors


def _job_artifact(model_path: Path, job: dict) -> Path:
    relative = Path(str(job.get("artifact_path") or ""))
    if not relative.parts or relative.is_absolute() or ".." in relative.parts:
        raise ValueError("loader profile artifact path is unsafe")
    artifact = model_path / relative
    if not artifact.is_file() or artifact.is_symlink():
        raise ValueError("loader profile artifact is missing")
    return artifact


def _onnx_embeddings(model_path: Path, texts: list[str], job: dict):
    import numpy as np
    import onnxruntime as ort
    from transformers import AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(model_path, local_files_only=True, trust_remote_code=False)
    encoded = tokenizer(texts, padding=True, truncation=True, return_tensors="np")
    options = ort.SessionOptions()
    options.intra_op_num_threads = 1
    options.inter_op_num_threads = 1
    options.execution_mode = ort.ExecutionMode.ORT_SEQUENTIAL
    session = ort.InferenceSession(
        str(_job_artifact(model_path, job)),
        sess_options=options,
        providers=["CPUExecutionProvider"],
    )
    input_names = {item.name for item in session.get_inputs()}
    inputs = {
        name: np.asarray(value)
        for name, value in encoded.items()
        if name in input_names
    }
    missing = input_names - set(inputs)
    if missing:
        raise ValueError(f"tokenizer did not produce required ONNX inputs: {sorted(missing)}")
    outputs = session.run(None, inputs)
    if not outputs:
        raise ValueError("ONNX model produced no outputs")
    hidden = np.asarray(outputs[0])
    if hidden.ndim == 3:
        mask = np.asarray(encoded.get("attention_mask", np.ones(hidden.shape[:2], dtype=np.int64)))
        expanded = np.expand_dims(mask, -1).astype(hidden.dtype, copy=False)
        vectors = (hidden * expanded).sum(axis=1) / np.clip(expanded.sum(axis=1), 1, None)
    elif hidden.ndim == 2:
        vectors = hidden
    else:
        raise ValueError(f"unsupported ONNX embedding output rank: {hidden.ndim}")
    return np.ascontiguousarray(vectors, dtype=np.float32), session


def inventory() -> None:
    interfaces = sorted(name for _idx, name in socket.if_nameindex())
    print(json.dumps({"guest_interfaces": interfaces}, sort_keys=True))


def run_phase(phase: str) -> None:
    state = _load_state()
    job = json.loads((INPUT / "job.json").read_text())
    model_path = INPUT / "model"
    profile_id = str(job.get("profile_id") or "")
    onnx_profile = profile_id == "onnx-embedding"
    try:
        if phase == "import":
            if onnx_profile:
                import onnxruntime  # noqa: F401
                import transformers  # noqa: F401
            else:
                import torch  # noqa: F401
                import transformers  # noqa: F401
                _install_transformers_compatibility()
            state["phases"][phase] = "PASS"
        elif phase == "tokenizer":
            _install_transformers_compatibility()
            from transformers import AutoTokenizer
            trust = bool(job.get("trust_remote_code"))
            tokenizer = AutoTokenizer.from_pretrained(model_path, local_files_only=True, trust_remote_code=trust)
            state["tokenizer_class"] = f"{tokenizer.__class__.__module__}.{tokenizer.__class__.__name__}"
            state["phases"][phase] = "PASS"
        elif phase == "model_load":
            if onnx_profile:
                _vectors, session = _onnx_embeddings(model_path, ["bounded model load"], job)
                state["model_class"] = f"{session.__class__.__module__}.{session.__class__.__name__}"
            else:
                _install_transformers_compatibility()
                from transformers import AutoModel
                trust = bool(job.get("trust_remote_code"))
                model = AutoModel.from_pretrained(
                    model_path, local_files_only=True, trust_remote_code=trust,
                    use_safetensors=not bool(job.get("allow_pickle")),
                )
                state["model_class"] = f"{model.__class__.__module__}.{model.__class__.__name__}"
            state["phases"][phase] = "PASS"
        elif phase == "warmup":
            if onnx_profile:
                _onnx_embeddings(model_path, ["bounded warmup"], job)
            else:
                import torch
                _configure_deterministic_torch(torch)
                _install_transformers_compatibility()
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
            texts = job.get("known_answer_inputs") or ["security review", "knowledge graph embedding"]
            if onnx_profile:
                vectors, _session = _onnx_embeddings(model_path, texts, job)
                vector_bytes = vectors.tobytes()
                shape = list(vectors.shape)
            else:
                import torch
                _configure_deterministic_torch(torch)
                _install_transformers_compatibility()
                from transformers import AutoModel, AutoTokenizer
                trust = bool(job.get("trust_remote_code"))
                tokenizer = AutoTokenizer.from_pretrained(model_path, local_files_only=True, trust_remote_code=trust)
                model = AutoModel.from_pretrained(
                    model_path, local_files_only=True, trust_remote_code=trust,
                    use_safetensors=not bool(job.get("allow_pickle")),
                ).eval()
                encoded = tokenizer(texts, padding=True, truncation=True, return_tensors="pt")
                with torch.inference_mode():
                    output = model(**encoded)
                hidden = output.last_hidden_state
                mask = encoded.get("attention_mask", torch.ones(hidden.shape[:2], dtype=hidden.dtype)).unsqueeze(-1)
                vectors = (hidden * mask).sum(1) / mask.sum(1).clamp(min=1)
                vector_bytes = vectors.detach().to(torch.float32).cpu().contiguous().numpy().tobytes()
                shape = list(vectors.shape)
            state["embedding_output_sha256"] = hashlib.sha256(vector_bytes).hexdigest()
            state["embedding_shape"] = shape
            expected = job.get("known_answer_embedding_sha256")
            state["embedding_known_answers_status"] = (
                "NOT_CONFIGURED" if not expected
                else "PASS" if expected == state["embedding_output_sha256"]
                else "FAIL"
            )
            state["phases"][phase] = state["embedding_known_answers_status"]
            if state["embedding_known_answers_status"] != "PASS":
                raise ValueError("known-answer embedding digest is absent or does not match")
        elif phase == "deserialize_convert":
            import shutil
            import torch
            from safetensors.torch import save_file
            source = _source_bin(model_path)
            tensors = _state_dict(torch.load(source, map_location="cpu", weights_only=True))
            converted = WORK / "converted"
            converted.mkdir(exist_ok=False)
            for item in sorted(model_path.rglob("*")):
                if not item.is_file() or item.is_symlink() or item.suffix.lower() in {".bin", ".pt", ".pth", ".ckpt", ".safetensors"}:
                    continue
                relative = item.relative_to(model_path)
                target = converted / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(item, target)
            target = converted / "model.safetensors"
            save_file(tensors, target)
            state["source_artifact_sha256"] = _sha256(source)
            state["target_artifact_sha256"] = _sha256(target)
            state["tensor_count"] = len(tensors)
            state["phases"][phase] = "PASS"
        elif phase == "tensor_equivalence":
            import torch
            from safetensors.torch import load_file
            source = _state_dict(torch.load(_source_bin(model_path), map_location="cpu", weights_only=True))
            target = load_file(WORK / "converted" / "model.safetensors", device="cpu")
            if set(source) != set(target):
                raise ValueError("converted tensor key inventory differs")
            max_abs = 0.0
            for key in sorted(source):
                if source[key].shape != target[key].shape or source[key].dtype != target[key].dtype:
                    raise ValueError(f"converted tensor metadata differs: {key}")
                if source[key].numel():
                    difference = (source[key].to(torch.float64) - target[key].to(torch.float64)).abs().max().item()
                    max_abs = max(max_abs, float(difference))
            state["tensor_inventory_equivalent"] = True
            state["numeric_max_abs_difference"] = max_abs
            state["numeric_equivalence_status"] = "PASS" if max_abs == 0.0 else "FAIL"
            state["phases"][phase] = "PASS" if max_abs == 0.0 else "FAIL"
            if max_abs != 0.0:
                raise ValueError("converted tensor values differ")
        elif phase == "embedding_equivalence":
            import torch
            texts = job.get("known_answer_inputs") or ["security review", "knowledge graph embedding"]
            trust = bool(job.get("trust_remote_code"))
            source_vectors = _mean_embeddings(model_path, texts, trust=trust, safe=False)
            target_vectors = _mean_embeddings(WORK / "converted", texts, trust=trust, safe=True)
            if source_vectors.shape != target_vectors.shape:
                raise ValueError("converted embedding shape differs")
            max_abs = float((source_vectors - target_vectors).abs().max().item()) if source_vectors.numel() else 0.0
            cosine = torch.nn.functional.cosine_similarity(source_vectors, target_vectors, dim=-1)
            min_cosine = float(cosine.min().item()) if cosine.numel() else 1.0
            state["embedding_max_abs_difference"] = max_abs
            state["embedding_min_cosine_similarity"] = min_cosine
            state["embedding_equivalence_status"] = "PASS" if max_abs <= 1e-6 and min_cosine >= 0.999999 else "FAIL"
            state["phases"][phase] = state["embedding_equivalence_status"]
            if state["embedding_equivalence_status"] != "PASS":
                raise ValueError("converted embeddings differ")
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
    job = json.loads((INPUT / "job.json").read_text())
    mode = job.get("mode")
    required = (
        ("import", "tokenizer", "model_load", "warmup", "inference", "teardown")
        if mode == "runtime"
        else ("import", "deserialize_convert", "tensor_equivalence", "embedding_equivalence", "teardown")
    )
    result = {
        "status": "PASS" if status == 0 and all(state.get("phases", {}).get(p) == "PASS" for p in required) else "FAIL",
        "mode": mode,
        "artifact_loaded": state.get("phases", {}).get("model_load") == "PASS",
        "model_loaded": state.get("phases", {}).get("model_load") == "PASS",
        "embedding_known_answers_status": state.get("embedding_known_answers_status", "NOT_RUN"),
        "embedding_output_sha256": state.get("embedding_output_sha256"),
        "embedding_shape": state.get("embedding_shape"),
        "guest_interfaces": interfaces,
        "phases": state.get("phases", {}),
        "errors": state.get("errors", []),
        "source_artifact_sha256": state.get("source_artifact_sha256"),
        "target_artifact_sha256": state.get("target_artifact_sha256"),
        "tensor_count": state.get("tensor_count"),
        "tensor_inventory_equivalent": state.get("tensor_inventory_equivalent"),
        "numeric_max_abs_difference": state.get("numeric_max_abs_difference"),
        "numeric_equivalence_status": state.get("numeric_equivalence_status"),
        "embedding_max_abs_difference": state.get("embedding_max_abs_difference"),
        "embedding_min_cosine_similarity": state.get("embedding_min_cosine_similarity"),
        "embedding_equivalence_status": state.get("embedding_equivalence_status"),
    }
    (OUTPUT / "result.json").write_text(json.dumps(result, sort_keys=True, separators=(",", ":")))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inventory", action="store_true")
    parser.add_argument("--phase", choices=(
        "import", "tokenizer", "model_load", "warmup", "inference", "teardown",
        "deserialize_convert", "tensor_equivalence", "embedding_equivalence",
    ))
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
