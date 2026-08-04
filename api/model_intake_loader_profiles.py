"""Provider-neutral, digest-bound loader profile selection."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


PROFILE_SCHEMA = "model-loader-profile/v1"

PROFILE_TEMPLATES = {
    "transformers-embedding-safetensors": {
        "artifact_extensions": [".safetensors"],
        "libraries": ["transformers", "sentence-transformers"],
        "entrypoint": "transformers.AutoModel.from_pretrained",
        "trust_remote_code": False,
        "allow_pickle": False,
        "network": "none",
    },
    "transformers-embedding-reviewed-custom-code": {
        "artifact_extensions": [".safetensors"],
        # Hugging Face repositories commonly declare sentence-transformers at
        # the model-card level while their reviewed custom implementation is
        # still loaded through transformers.AutoModel. Treat both canonical
        # library labels consistently; the format, reviewed-code digest, fixed
        # entrypoint, and no-network requirements remain unchanged.
        "libraries": ["transformers", "sentence-transformers"],
        "entrypoint": "transformers.AutoModel.from_pretrained",
        "trust_remote_code": True,
        "allow_pickle": False,
        "network": "none",
        "requires_reviewed_custom_code_digest": True,
    },
    "onnx-embedding": {
        "artifact_extensions": [".onnx"],
        "libraries": ["onnxruntime"],
        "entrypoint": "onnxruntime.InferenceSession",
        "trust_remote_code": False,
        "allow_pickle": False,
        "network": "none",
    },
}

CONVERSION_PROFILE_ID = "transformers-pytorch-bin-to-safetensors-v1"


def digest_json(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def resolve_loader_profile(
    repository_manifest: dict[str, Any],
    *,
    artifact_path: str,
    runtime_image_digest: str,
    reviewed_custom_code_sha256: str | None = None,
) -> dict[str, Any]:
    extension = Path(artifact_path).suffix.lower()
    library = str(repository_manifest.get("library_name") or "transformers").lower()
    custom_code = bool(repository_manifest.get("custom_code_required"))
    if extension in {".bin", ".pt", ".pth", ".ckpt"}:
        return {
            "status": "BLOCKED",
            "reason": "executable_serialization_requires_controlled_conversion",
            "conversion_target": "safetensors",
            "profile": None,
        }
    if extension == ".safetensors" and custom_code:
        template_id = "transformers-embedding-reviewed-custom-code"
    elif extension == ".safetensors":
        template_id = "transformers-embedding-safetensors"
    elif extension == ".onnx":
        template_id = "onnx-embedding"
    else:
        return {"status": "UNSUPPORTED", "reason": "no_loader_profile_for_format", "profile": None}
    template = PROFILE_TEMPLATES[template_id]
    if library not in template["libraries"]:
        return {"status": "UNSUPPORTED", "reason": "runtime_library_not_supported_by_profile", "profile": None}
    if template.get("requires_reviewed_custom_code_digest") and not reviewed_custom_code_sha256:
        return {"status": "BLOCKED", "reason": "reviewed_custom_code_digest_required", "profile": None}
    profile = {
        "schema_version": PROFILE_SCHEMA,
        "profile_id": template_id,
        "artifact_path": artifact_path,
        "runtime_image_digest": runtime_image_digest,
        "entrypoint": template["entrypoint"],
        "trust_remote_code": template["trust_remote_code"],
        "allow_pickle": template["allow_pickle"],
        "network": template["network"],
        "reviewed_custom_code_sha256": reviewed_custom_code_sha256,
        "selection_facts": {
            "extension": extension,
            "library_name": library,
            "custom_code_required": custom_code,
            "architectures": sorted(str(item) for item in repository_manifest.get("architectures") or []),
        },
    }
    profile["profile_sha256"] = digest_json(profile)
    return {"status": "READY", "reason": None, "profile": profile}


def resolve_conversion_profile(
    repository_manifest: dict[str, Any],
    *,
    artifact_path: str,
    runtime_image_digest: str,
    reviewed_custom_code_sha256: str | None = None,
) -> dict[str, Any]:
    extension = Path(artifact_path).suffix.lower()
    library = str(repository_manifest.get("library_name") or "transformers").lower()
    custom_code = bool(repository_manifest.get("custom_code_required"))
    if extension != ".bin":
        return {"status": "UNSUPPORTED", "reason": "conversion_requires_pytorch_bin", "profile": None}
    if library not in {"transformers", "sentence-transformers"}:
        return {"status": "UNSUPPORTED", "reason": "conversion_library_not_supported", "profile": None}
    if custom_code and not reviewed_custom_code_sha256:
        return {"status": "BLOCKED", "reason": "reviewed_custom_code_digest_required", "profile": None}
    profile = {
        "schema_version": PROFILE_SCHEMA,
        "profile_id": CONVERSION_PROFILE_ID,
        "artifact_path": artifact_path,
        "runtime_image_digest": runtime_image_digest,
        "operation": "pytorch-bin-to-safetensors",
        "source_deserializer": "torch.load(weights_only=True,map_location=cpu)",
        "target_serializer": "safetensors.torch.save_file",
        "trust_remote_code": custom_code,
        "allow_pickle": True,
        "allow_pickle_scope": "single-reviewed-source-artifact-inside-firecracker",
        "network": "none",
        "reviewed_custom_code_sha256": reviewed_custom_code_sha256,
        "selection_facts": {
            "extension": extension,
            "library_name": library,
            "custom_code_required": custom_code,
            "architectures": sorted(str(item) for item in repository_manifest.get("architectures") or []),
        },
    }
    profile["profile_sha256"] = digest_json(profile)
    return {"status": "READY", "reason": None, "profile": profile}


__all__ = [
    "CONVERSION_PROFILE_ID", "PROFILE_SCHEMA", "PROFILE_TEMPLATES",
    "resolve_conversion_profile", "resolve_loader_profile",
]
