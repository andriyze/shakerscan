"""Typed Model Intake provider registry for non-scanner capabilities."""

from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ProviderDescriptor:
    id: str
    kind: str
    implementation: str
    trust_boundary: str
    optional: bool = False


class ModelIntakeProvider:
    descriptor: ProviderDescriptor

    def readiness(self) -> dict[str, Any]:
        raise NotImplementedError

    def result(self, *, ready: bool, status: str, **details: Any) -> dict[str, Any]:
        return {**asdict(self.descriptor), "ready": ready, "status": status, **details}


class SandboxExecutionProvider(ModelIntakeProvider):
    descriptor = ProviderDescriptor(
        id="isolated-sandbox-service",
        kind="execution_provider",
        implementation="model_intake_sandbox",
        trust_boundary="separate_no_egress_container",
    )

    def readiness(self) -> dict[str, Any]:
        queue_root = Path(os.getenv("MODEL_INTAKE_SANDBOX_QUEUE_DIR") or "/results/model-intake-sandbox")
        heartbeat = queue_root / "heartbeat.json"
        try:
            age_seconds = max(0.0, time.time() - heartbeat.stat().st_mtime)
        except OSError:
            age_seconds = None
        service_ready = age_seconds is not None and age_seconds <= 15
        raw_adapters = os.getenv("MODEL_INTAKE_SANDBOX_RUNTIME_ADAPTERS_JSON")
        adapter_extensions: list[str] = []
        configuration_valid = True
        if raw_adapters:
            try:
                parsed = json.loads(raw_adapters)
                configuration_valid = isinstance(parsed, dict)
                if configuration_valid:
                    adapter_extensions = sorted(str(key) for key in parsed)
            except (TypeError, ValueError):
                configuration_valid = False
        ready = bool(service_ready and configuration_valid)
        return self.result(
            ready=ready,
            status="READY" if ready else "UNAVAILABLE",
            service_heartbeat_age_seconds=round(age_seconds, 3) if age_seconds is not None else None,
            runtime_adapter_configuration_valid=configuration_valid,
            runtime_adapter_extensions=adapter_extensions,
            limitation=(
                None if adapter_extensions
                else "format inspection is available, but executable load and known-answer testing require a runtime adapter"
            ),
        )


class EmbeddingEvaluationProvider(ModelIntakeProvider):
    descriptor = ProviderDescriptor(
        id="embedding-security-evaluator",
        kind="evaluation_provider",
        implementation="model_intake_evaluation",
        trust_boundary="content_free_bounded_vectors_and_observations",
    )

    def readiness(self) -> dict[str, Any]:
        return self.result(
            ready=True,
            status="READY",
            runtime_receipt_derivation_included=True,
            data_plane_runner_included=False,
            evaluates=[
                "retrieval_quality", "acl_and_tenant_isolation", "poisoning", "sensitive_leakage",
                "dimension_and_collision", "stability", "deletion", "capacity",
            ],
            limitation="an approved runner must produce artifact-bound vectors and data-plane observations",
        )


class EmbeddedPolicyProvider(ModelIntakeProvider):
    descriptor = ProviderDescriptor(
        id="embedded-admission-policy",
        kind="policy_provider",
        implementation="model_intake_policy_profiles",
        trust_boundary="shakerscan_api_and_database",
    )

    def readiness(self) -> dict[str, Any]:
        return self.result(
            ready=True,
            status="READY",
            enforcement="server_side_non_weakenable_profile_resolution",
        )


class CoreReportProvider(ModelIntakeProvider):
    descriptor = ProviderDescriptor(
        id="core-report-exporter",
        kind="report_provider",
        implementation="model_intake_report_and_evidence_export",
        trust_boundary="shakerscan_api_and_evidence_store",
    )

    def readiness(self) -> dict[str, Any]:
        return self.result(
            ready=True,
            status="READY",
            formats=[
                "normalized_json", "printable_html", "browser_pdf", "sarif",
                "evidence_export", "signed_admission_package",
            ],
            admission_authority="isolated_signer_plus_active_lifecycle_registry",
            limitation=(
                "report rendering alone never authorizes deployment; consumers must verify the exact signed "
                "allow package and active lifecycle record"
            ),
        )


PROVIDERS: tuple[ModelIntakeProvider, ...] = (
    SandboxExecutionProvider(),
    EmbeddingEvaluationProvider(),
    EmbeddedPolicyProvider(),
    CoreReportProvider(),
)


def provider_readiness() -> dict[str, Any]:
    providers = [provider.readiness() for provider in PROVIDERS]
    required = [provider for provider in providers if not provider["optional"]]
    return {
        "schema_version": "model-intake-provider-readiness/v1",
        "status": "READY" if all(provider["ready"] for provider in required) else "DEGRADED",
        "providers": providers,
    }
