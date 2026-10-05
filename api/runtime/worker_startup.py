"""Startup guards an evidence-producing worker applies before it takes any job."""

from __future__ import annotations

import os
from collections.abc import Mapping

# Admission/control-plane signing authority belongs to the signer service alone. A worker
# that executes target-facing tools must never hold it.
FORBIDDEN_SIGNER_VARIABLES = (
    "MODEL_INTAKE_ADMISSION_SIGNING_KEY_PEM",
    "MODEL_INTAKE_CONTROL_PLANE_SIGNING_KEY_PEM",
    "MODEL_INTAKE_SIGNER_AWS_KMS_KEY_ID",
)


def reject_admission_signer_material(env: Mapping[str, str] | None = None) -> None:
    environment = os.environ if env is None else env
    if any(environment.get(name) for name in FORBIDDEN_SIGNER_VARIABLES):
        raise RuntimeError(
            "worker preflight failed: admission signing material must not be present in an evidence-producing worker"
        )
