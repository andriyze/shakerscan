"""Provider-neutral source-adapter contract for Model Intake.

The contract deliberately describes capabilities independently from any named
model. Adding a registry means registering another adapter; scan policy can
then fail closed when a requested operation is not implemented.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


CAPABILITY_STATUSES = {"implemented", "unsupported", "not_applicable"}


@dataclass(frozen=True)
class ModelSourceAdapter:
    id: str
    display_name: str
    aliases: tuple[str, ...]
    reference_schemes: tuple[str, ...]
    resolve: str
    immutable_resolution: str
    artifact_acquisition: str
    repository_manifest: str
    repository_snapshot: str
    authentication: str
    notes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for value in (
            self.resolve,
            self.immutable_resolution,
            self.artifact_acquisition,
            self.repository_manifest,
            self.repository_snapshot,
        ):
            if value not in CAPABILITY_STATUSES:
                raise ValueError(f"invalid adapter capability status: {value}")

    def public(self) -> dict[str, Any]:
        value = asdict(self)
        value["aliases"] = list(self.aliases)
        value["reference_schemes"] = list(self.reference_schemes)
        value["notes"] = list(self.notes)
        return value


_ADAPTERS: dict[str, ModelSourceAdapter] = {}
_ALIASES: dict[str, str] = {}


def register_adapter(adapter: ModelSourceAdapter, *, replace: bool = False) -> None:
    canonical = adapter.id.strip().lower()
    if not canonical:
        raise ValueError("adapter id is required")
    if canonical in _ADAPTERS and not replace:
        raise ValueError(f"adapter already registered: {canonical}")
    aliases = {canonical, *(alias.strip().lower() for alias in adapter.aliases)}
    collisions = sorted(alias for alias in aliases if alias in _ALIASES and _ALIASES[alias] != canonical)
    if collisions and not replace:
        raise ValueError(f"adapter aliases already registered: {', '.join(collisions)}")
    _ADAPTERS[canonical] = adapter
    for alias in aliases:
        _ALIASES[alias] = canonical


def get_adapter(kind: str | None) -> ModelSourceAdapter | None:
    canonical = _ALIASES.get(str(kind or "").strip().lower())
    return _ADAPTERS.get(canonical) if canonical else None


def adapter_capabilities(kind: str | None) -> dict[str, Any]:
    adapter = get_adapter(kind)
    if adapter:
        return adapter.public()
    return {
        "id": str(kind or "unknown"),
        "display_name": "Unknown provider",
        "aliases": [],
        "reference_schemes": [],
        "resolve": "unsupported",
        "immutable_resolution": "unsupported",
        "artifact_acquisition": "unsupported",
        "repository_manifest": "unsupported",
        "repository_snapshot": "unsupported",
        "authentication": "none",
        "notes": ["No Model Intake source adapter is registered for this provider."],
    }


def adapter_catalog() -> list[dict[str, Any]]:
    return [adapter.public() for adapter in sorted(_ADAPTERS.values(), key=lambda item: item.id)]


for _adapter in (
    ModelSourceAdapter(
        id="huggingface",
        display_name="Hugging Face Hub",
        aliases=("hf",),
        reference_schemes=("hf", "https"),
        resolve="implemented",
        immutable_resolution="implemented",
        artifact_acquisition="implemented",
        repository_manifest="implemented",
        repository_snapshot="implemented",
        authentication="optional_bearer_token_worker_side",
        notes=("Repository operations require a Hub commit SHA and complete sibling inventory.",),
    ),
    ModelSourceAdapter(
        id="http",
        display_name="HTTPS artifact",
        aliases=("https",),
        reference_schemes=("https", "http"),
        resolve="implemented",
        immutable_resolution="unsupported",
        artifact_acquisition="implemented",
        repository_manifest="not_applicable",
        repository_snapshot="not_applicable",
        authentication="signed_url_or_operator_headers",
        notes=("Production intake requires HTTPS and a trusted expected digest or attestation.",),
    ),
    ModelSourceAdapter(
        id="s3",
        display_name="Amazon S3",
        aliases=(),
        reference_schemes=("s3", "https"),
        resolve="implemented",
        immutable_resolution="unsupported",
        artifact_acquisition="implemented",
        repository_manifest="not_applicable",
        repository_snapshot="not_applicable",
        authentication="presigned_https_url",
    ),
    ModelSourceAdapter(
        id="gcs",
        display_name="Google Cloud Storage",
        aliases=("gs",),
        reference_schemes=("gs", "gcs", "https"),
        resolve="implemented",
        immutable_resolution="unsupported",
        artifact_acquisition="implemented",
        repository_manifest="not_applicable",
        repository_snapshot="not_applicable",
        authentication="signed_https_url",
    ),
    ModelSourceAdapter(
        id="azure_blob",
        display_name="Azure Blob Storage",
        aliases=("azure",),
        reference_schemes=("azure", "https"),
        resolve="implemented",
        immutable_resolution="unsupported",
        artifact_acquisition="implemented",
        repository_manifest="not_applicable",
        repository_snapshot="not_applicable",
        authentication="sas_https_url",
    ),
    ModelSourceAdapter(
        id="oci",
        display_name="OCI registry",
        aliases=(),
        reference_schemes=("oci",),
        resolve="implemented",
        immutable_resolution="implemented",
        artifact_acquisition="unsupported",
        repository_manifest="unsupported",
        repository_snapshot="unsupported",
        authentication="not_implemented",
        notes=("Digest parsing is supported; native registry acquisition is not yet enabled.",),
    ),
    ModelSourceAdapter(
        id="mlflow",
        display_name="MLflow Model Registry",
        aliases=(),
        reference_schemes=("mlflow", "models", "runs"),
        resolve="implemented",
        immutable_resolution="unsupported",
        artifact_acquisition="unsupported",
        repository_manifest="unsupported",
        repository_snapshot="unsupported",
        authentication="not_implemented",
        notes=("Use an exported immutable artifact URL until a tracking-server adapter is configured.",),
    ),
):
    register_adapter(_adapter)
