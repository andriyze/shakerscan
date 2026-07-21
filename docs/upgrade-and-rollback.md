# Upgrade and Rollback

ShakerScan upgrades are in-place and run database migrations when the API and workers start. Required
schema invariants fail closed: if a migration cannot complete safely, the affected service exits
instead of running against a partially upgraded database.

## Before upgrading

Do not begin an upgrade while scans or evidence-retention operations are active. Record the current
release and create a backup:

```bash
cd ~/.shakerscan
shakerscan status
cat VERSION
shakerscan backup
```

`shakerscan backup` creates a private, timestamped directory under `~/.shakerscan/backups/` by
default. It contains:

- a PostgreSQL custom-format dump;
- the `results/` artifact tree;
- `.env` as `runtime.env`, when present;
- `VERSION`, release Compose configuration, and a small manifest.

The backup contains sensitive scan evidence and configuration. Keep it encrypted or on storage with
equivalent access controls. A directory containing `.incomplete` is not a valid restore point.

To write outside the runtime directory:

```bash
shakerscan backup /secure/path/shakerscan-backups
```

## Upgrade

Download the runtime first without starting it, then start explicitly:

```bash
curl -fsSL https://install.shakerscan.com | SHAKERSCAN_START=0 sh
cd ~/.shakerscan
shakerscan start
shakerscan status
```

After startup, confirm the API health check, UI, worker build status, existing targets/findings, and a
safe Quick scan. Do not run `shakerscan reset` to recover from a migration failure; reset deletes the
database volume.

If startup reports a fatal schema invariant, preserve the logs and backup. The error identifies the
failed invariant and whether automatic repair was attempted. Repair the database offline or restore
the pre-upgrade backup before retrying.

## Roll back after a failed upgrade

Rollback has two parts: restore the pre-upgrade data, then restore the previous release runtime and
images. Replace the example paths and version with the values from the backup manifest.

Stop ShakerScan and start only PostgreSQL:

```bash
cd ~/.shakerscan
shakerscan stop
docker compose -f docker-compose.release.yml up -d postgres
```

Restore the database dump. These commands replace the current database, so verify the backup path
before running them:

```bash
docker compose -f docker-compose.release.yml exec -T postgres \
  dropdb -U scanner --if-exists scanner
docker compose -f docker-compose.release.yml exec -T postgres \
  createdb -U scanner scanner
docker compose -f docker-compose.release.yml exec -T postgres \
  pg_restore --exit-on-error -U scanner -d scanner \
  < /secure/path/shakerscan-backups/shakerscan-TIMESTAMP/postgres.dump
```

Move the failed-upgrade result tree aside, restore the archived artifacts and configuration, then
install the previous tagged runtime without starting it:

```bash
mv results "results.failed-upgrade-$(date -u +%Y%m%dT%H%M%SZ)"
tar -xzf /secure/path/shakerscan-backups/shakerscan-TIMESTAMP/results.tar.gz -C ~/.shakerscan
cp /secure/path/shakerscan-backups/shakerscan-TIMESTAMP/runtime.env ~/.shakerscan/.env

curl -fsSL https://install.shakerscan.com | \
  SHAKERSCAN_RAW_BASE=https://raw.githubusercontent.com/andriyze/shakerscan/vPREVIOUS_VERSION \
  SHAKERSCAN_START=0 sh
SCANNER_IMAGE_TAG=PREVIOUS_VERSION SHAKERSCAN_PULL_IMAGES=1 shakerscan start --prebuilt
shakerscan status
```

Keep the failed-upgrade data and logs until the rollback is verified. A database upgraded by a newer
release is not assumed to be backward-compatible with an older image; restoring the matching
pre-upgrade dump is the supported rollback path.
