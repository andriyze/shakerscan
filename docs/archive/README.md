# Retired engineering documents

Point-in-time audits, migration ledgers, and superseded implementation plans were removed
from the current source tree during 2.3.1 cleanup. They are ordinary historical documentation,
not current product contracts. Current guides are indexed in [../README.md](../README.md).

The last pre-cleanup snapshot is commit `ae5a4e231ff2f8f24eeb0abaded1df121cdcf7db`.
Use Git history to retrieve the former `docs/archive/` documents. Release notes and
benchmark-integrity ledgers remain in the repository because they carry public contracts.

Removing a file here does not remove earlier Git history, forks, or released artifacts.
Confirmed secrets require revocation/rotation and a separately reviewed history-remediation
process, not an archive directory or a link to the exposed value.
