"""Shared trusted execution primitives for Scan and Hunt."""

# Load narrow, idempotent compatibility hardening before any runtime submodule is used.
# Remove this import after the methods are native in every supported V2 release.
from .v2_runtime_hardening import apply_runtime_hardening as _apply_runtime_hardening

_apply_runtime_hardening()
