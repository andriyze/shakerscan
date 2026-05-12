"""Package import compatibility for local tooling.

Runtime containers execute modules from the API directory directly, where
bare imports like ``ai_gate`` work. Local tests and scripts may import modules
as ``api.*`` instead, so expose the same module names in that context.
"""

from __future__ import annotations

import sys

from . import ai_control_requirements as _ai_control_requirements
from . import ai_redteam_artifacts as _ai_redteam_artifacts
from . import ai_gate as _ai_gate

sys.modules.setdefault("ai_control_requirements", _ai_control_requirements)
sys.modules.setdefault("ai_redteam_artifacts", _ai_redteam_artifacts)
sys.modules.setdefault("ai_gate", _ai_gate)
