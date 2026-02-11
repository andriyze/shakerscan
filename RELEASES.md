# Shaker Scan Release Mapping

This file tracks which git commit produced each published Docker image tag.

| Version | Git Commit | Scanner Image | UI Image |
| --- | --- | --- | --- |
| 0.2.0 | `8e2d887b03e44921daf2b3ff9b87f4b2bff3ce04` | `shakerscan/shakerscan-scanner:0.2.0` | `shakerscan/shakerscan-ui:0.2.0` |

## Release Workflow

1. Update `VERSION` with the new release (for example `0.2.1`).
2. Build and push images with that tag for scanner and UI.
3. Add a new row to the table with the exact git commit and image tags.
4. Create a git tag with the same version (`git tag v0.2.1`).
