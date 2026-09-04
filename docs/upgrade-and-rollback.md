# Upgrade and Rollback

**Status:** current source/installer upgrade runbook; reconciled 2026-08-29.

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

For a managed-HTTPS Fleet control plane, also preserve the existing Compose `caddy-data` and
`caddy-config` volumes. The ordinary installer and upgrade flow below leave them intact. Do not use
`docker compose down -v`, `shakerscan reset`, or manual volume deletion during an upgrade: those
actions erase Caddy's ACME account and certificates and force new issuance, which can hit public-CA
duplicate-certificate limits during repeated rebuilds.

To write outside the runtime directory:

```bash
shakerscan backup /secure/path/shakerscan-backups
```

## Upgrade

Download the runtime first without starting it, then start explicitly:

### Installs that live in another directory

The hosted installer defaults to `~/.shakerscan`. If your existing install lives elsewhere (for
example a source checkout you started with `./scanner.sh start`), upgrade it in place by naming that
directory, so its `.env` secrets, `results/` evidence, and Docker volumes stay together:

```bash
SHAKERSCAN_HOME=/path/to/your/install sh -c 'curl -fsSL https://install.shakerscan.com | sh'
```

Running the installer into a new directory while an older install's Docker volumes exist under the
same Compose project fails closed with `a PostgreSQL data volume ... already exists, but .env has no
POSTGRES_PASSWORD`. That volume belongs to the other directory. Either upgrade that directory as
above, or set `SHAKERSCAN_ADOPT_EXISTING_DATA=1` to take the volume over from the new directory; the
database password is then rotated and the old directory's `results/` evidence is not visible to the
new install.

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

SHAKERSCAN_INSTALL_VERSION=PREVIOUS_VERSION SHAKERSCAN_START=0 \
  sh -c "$(curl -fsSL https://install.shakerscan.com)"
SCANNER_IMAGE_TAG=PREVIOUS_VERSION SHAKERSCAN_PULL_IMAGES=1 shakerscan start --prebuilt
shakerscan status
```

`SHAKERSCAN_INSTALL_VERSION` names the exact tag to restore, and the dispatcher then runs that
tag's own installer against that tag's files. Piping into `sh` with the variable set on the *left*
of the pipe sets it for `curl`, not for the installer, which is why the command reads the script
into `sh -c` instead. `SHAKERSCAN_RAW_BASE` remains available for an arbitrary source tree and now
also suppresses channel resolution, so a pinned base is no longer replaced by current stable.

Keep the failed-upgrade data and logs until the rollback is verified. A database upgraded by a newer
release is not assumed to be backward-compatible with an older image; restoring the matching
pre-upgrade dump is the supported rollback path.
