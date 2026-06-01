# ShakerScan Release Mapping

This file tracks which git commit produced each published Docker image tag.

`./scanner.sh start` uses the moving `latest` Docker tag by default. Use `./scanner.sh start --image-tag <version>` when you need a reproducible pinned release.

| Version | Git Commit | Scanner Image | UI Image |
| --- | --- | --- | --- |
| 0.5.5 | `8dfa7d7c8f58838ab6ee3d44640cb14ffbf27a0d` | `shakerscan/shakerscan-scanner:0.5.5` | `shakerscan/shakerscan-ui:0.5.5` |
| 0.4.2 | `5e1f484469cfc3a9aa1c031613df0b8aada65254` | `shakerscan/shakerscan-scanner:0.4.2` | `shakerscan/shakerscan-ui:0.4.2` |
| 0.4.1 | `65e87ba5a7d7f48982b7f2cb3fb3d9fe4ed53ef1` | `shakerscan/shakerscan-scanner:0.4.1` | `shakerscan/shakerscan-ui:0.4.1` |
| 0.4.0 | pending | `shakerscan/shakerscan-scanner:0.4.0` | `shakerscan/shakerscan-ui:0.4.0` |
| 0.3.1 | `662d2f8e3618c25a1d29e1a1b62b3e740b54d143` | `shakerscan/shakerscan-scanner:0.3.1` | `shakerscan/shakerscan-ui:0.3.1` |
| 0.3.0 | `e0c100c79f0d8058973906ef082f2c5143c7bca7` | `shakerscan/shakerscan-scanner:0.3.0` | `shakerscan/shakerscan-ui:0.3.0` |
| 0.2.0 | `8e2d887b03e44921daf2b3ff9b87f4b2bff3ce04` | `shakerscan/shakerscan-scanner:0.2.0` | `shakerscan/shakerscan-ui:0.2.0` |

## Release Workflow

1. Finish and test changes on a feature branch such as `imp`.
2. Update `VERSION` with the new release, for example `0.4.2`.
3. Add a new row to this table. Use `pending` until the release commit exists.
4. Open and merge the branch to `main`.
5. Replace `pending` with the exact merge/release commit SHA if it changed.
6. Create and push a git tag from `main`:

   ```bash
   git checkout main
   git pull
   git tag v0.4.2
   git push origin v0.4.2
   ```

7. The GitHub `Release` workflow builds and pushes multi-architecture Docker images for `linux/amd64` and `linux/arm64`, then creates or updates the GitHub Release.

Manual image publishing is also available from a clean checkout:

```bash
scripts/publish-images.sh --push --latest
```

Use manual publishing only for emergency rebuilds. The normal release path is a `v*.*.*` git tag on `main`.
