"""AI Gate target, scan, surface, and operations-router domain."""

# Keep admission aligned with the canonical shipped probe catalog. This runs
# after router definitions exist, before consumers import its public constants.
from . import router

try:
    from ai_gate.probe_registry import PROBE_PACK_DEFINITIONS
except ModuleNotFoundError:
    from ..ai_gate.probe_registry import PROBE_PACK_DEFINITIONS

router.AI_PROBE_PACKS.update(PROBE_PACK_DEFINITIONS)
