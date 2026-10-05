# Upgrade and Rollback

**Status:** current source/installer upgrade runbook; reconciled 2026-09-30.

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
- the `results/` artifact tree, **without** the encryption key `results/.credential_enc.key`;
- `.env` as `runtime.env`, when present, without an `AI_CREDENTIAL_ENC_KEY` line;
- `VERSION`, release Compose configuration, and a manifest that records the encryption key's
  fingerprint (`encryption_key_fingerprint`).

Stored credentials, request collections and sessions in the dump are encrypted with that key, so a
backup holding both would expose every secret to whoever holds the backup. Keep the key separately
(it stays in `results/` on the install). `shakerscan backup --include-key` adds it when you need a
self-contained backup; treat that one as the most sensitive file you have.

The backup contains sensitive scan evidence and configuration. Keep it encrypted or on storage with
equivalent access controls. A directory containing `.incomplete` is not a valid restore point.

The newest 5 complete backups are kept and older ones are removed after each backup
(`SHAKERSCAN_BACKUP_KEEP`, `0` keeps every backup). Backups hold copies of records you may later
delete, so delete them when you no longer need them:

```bash
shakerscan backup list                      # name, state, whether it holds the key, size
shakerscan backup delete shakerscan-TIMESTAMP
shakerscan backup delete all                # every backup, including PostgreSQL upgrade copies
```

Target unification replaces the legacy device and input tables with compatibility views. Before
starting the new API/workers against an existing legacy database, the launcher automatically creates
a backup and stops the upgrade if that backup fails. Rebuilds of a running API use the same check.
Compatibility views do not support booting an older engine against the converted database.
Downgrade by restoring the pre-upgrade dump and artifacts with the previous release and its saved
configuration; simply switching images back is insufficient.

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

The oldest directly supported upgrade base is **0.8.18**. Installations older than that must first
upgrade to 0.8.18, confirm health and create a fresh backup, then upgrade to the current stable
release. Release certification exercises both the immediately previous stable version and 0.8.18;
versions older than the pinned minimum are not covered by the direct-migration guarantee.

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

No separate stop is needed. When `start` finds an earlier release still answering, ShakerScan
containers running without the API, or containers the API started outside Compose, it first pulls
(for a source checkout, builds) the new images, then stops every ShakerScan container the way
`shakerscan stop` does and starts the new release. An enabled connected-device worker and Gungnir CT monitor come back on the new image,
and the running worker count is kept. Volumes, `results/`, and `.env` are not touched.

After startup, confirm the API health check, UI, worker build status, existing targets/findings, and a
safe Quick scan. Do not run `shakerscan reset` to recover from a migration failure; reset deletes the
database volume.

If startup reports a fatal schema invariant, preserve the logs and backup. The error identifies the
failed invariant and whether automatic repair was attempted. Repair the database offline or restore
the pre-upgrade backup before retrying.

### "Resource is still in use" or a container name already in use

`shakerscan stop` removes every ShakerScan container, including the ones a plain
`docker compose down` leaves attached: the dedicated network worker and opt-in Gungnir CT monitor,
workers added from the UI or `/workers` scaler (the API creates them through the Docker socket, so
Compose cannot see them), and one-off `docker compose run` containers. Releases before this change
left them running, which produced these symptoms:

- `Network shakerscan_default  Resource is still in use` (and the same for
  `shakerscan_signer-control`) during `shakerscan stop`;
- `Conflict. The container name "/shakerscan-worker-N" is already in use` during an upgrade;
- `network shakerscan_default has active endpoints` when Compose had to recreate the network;
- startup failing closed on build identity because some workers were still on the previous image.

`shakerscan doctor` names containers left running without the API and anything else still attached
to a project network. On a runtime whose launcher predates this change, clear the leftovers by hand.
These commands remove containers only; the PostgreSQL and Redis volumes, `results/`, and `.env` stay:

```bash
cd ~/.shakerscan
docker network inspect -f '{{.Name}}: {{range .Containers}}{{.Name}} {{end}}' \
  shakerscan_default shakerscan_signer-control
shakerscan stop
docker ps -aq --filter label=com.docker.compose.project=shakerscan | xargs -r docker rm -f
docker network rm shakerscan_default shakerscan_signer-control
curl -fsSL https://install.shakerscan.com | sh
```

Use the runtime's Compose project name if `COMPOSE_PROJECT_NAME` changed it. If `docker network rm`
still reports active endpoints, detach a listed non-ShakerScan container with
`docker network disconnect -f shakerscan_default <name>`; a name that matches no container is a stale
endpoint, which `sudo systemctl restart docker` clears (common after a Docker or OS package upgrade).
Afterwards network scanning starts automatically unless `SHAKERSCAN_NETWORK_WORKER_ENABLED=false`.
Re-enable the opt-in CT monitor with `shakerscan gungnir start` if you used it.
Never use `docker compose down -v`, `shakerscan reset`, `docker system prune --volumes`, or
`scripts/clean-shakerscan.sh` for this: each deletes the database.

### Root installs: the API's user id

A root install runs the API as the dedicated id 10002, which owns `results/` and the encryption
key. If a host account or group already uses that id, `start` refuses rather than letting that
account read the key. Choose a free id once; the launcher saves it as `SHAKERSCAN_ROOT_API_UID`
in `.env`, moves the files the previous id owned under `results/` to the new one, and reuses it on
later starts:

```bash
SHAKERSCAN_ROOT_API_UID=20000 shakerscan start
```

The id must be between 1 and 2147483647 and must not be 10001, the Model Intake sandbox. A
non-root install runs the API as the invoking user and ignores this setting. Starting an existing
non-root install with `sudo` moves the files your user's API wrote under `results/` to the root
API id; your own id is never used as the root API identity. Going back to a non-root start
afterwards needs `sudo chown -R "$(id -u):$(id -g)" ~/.shakerscan/results`, because a non-root
launcher cannot take files back from another id.

## PostgreSQL 18

Releases from this one run PostgreSQL 18; every earlier release ran PostgreSQL 16. A newer PostgreSQL
major cannot open older data files, and PostgreSQL 18 images keep each major's data in its own
directory under `/var/lib/postgresql`, so the data moves from the `postgres-data` volume to a new
`postgres-cluster` volume. `shakerscan start` (and therefore the installer) does this automatically
before anything can start PostgreSQL:

1. it stops the running stack, starts PostgreSQL 16 on the existing data, and records every table's
   row count, every sequence, and every role;
2. it writes `pg_dumpall` to a private `backups/postgres-16-to-18-TIMESTAMP/` directory;
3. it restores the dump into a new PostgreSQL 18 cluster, stopping at the first error;
4. it compares row counts, sequences, and role password hashes with the source and publishes the new
   cluster only if they all match.

Nothing is written to the PostgreSQL 16 data (PostgreSQL's own startup and shutdown aside): the
`postgres-data` volume stays as it was, for rollback. Plan for free space of about the database size
for the dump on the host and 1.2 times the database size in Docker's disk; the upgrade checks both
before it starts. Most installs take a few minutes.

To run the step on its own, without starting the stack, or to see where an install stands:

```bash
shakerscan db-upgrade            # migrate now if needed, then print the status
shakerscan db-upgrade --status   # target image, what each volume holds, and the plan
```

If the upgrade fails, it says why and where the details are (`restore.log`, `verify.diff`), publishes
nothing, and does not start the stack; the PostgreSQL 16 data is untouched. Fix the cause and run
`shakerscan start` again, or keep using the previous release. A `POSTGRES_IMAGE` override must name a
PostgreSQL 18 or newer image.

If `start` reports that `postgres-cluster` already holds a PostgreSQL 18 cluster that was not
migrated, PostgreSQL 18 was started before the upgrade ran (for example with a raw
`docker compose up`) and initialized an empty database. The real data is still in `postgres-data`;
`shakerscan db-upgrade --remigrate` sets the new cluster aside and migrates.

The upgrade records a fingerprint of the PostgreSQL 16 data it copied. If an earlier release later
runs on that data again (a rollback, below) and you then return to this release, `start` stops and
says the PostgreSQL 16 data has been used since it was copied, because the PostgreSQL 18 copy may be
missing what was written during the rollback. Choose explicitly:

```bash
shakerscan db-upgrade --remigrate      # copy the 16 data again; the current 18 data is set aside
shakerscan db-upgrade --keep-current   # keep the 18 data; rollback-time changes are not carried over
```

Both ask for confirmation.

The PostgreSQL 16 data, the upgrade's dump in `backups/`, and any copy `--remigrate` set aside are
kept for **30 days** and then deleted by the next `start`. A full second copy of the database is
otherwise easy to forget on a small disk, and a rollback copy loses its value quickly: after a
month on 18, rolling back to it would discard a month of work. During the last 7 days every
`start` announces the date; `shakerscan db-upgrade --status` always shows it. Automatic deletion
never touches data a rollback has used since the copy (that start refuses, as above) or a copy
made before source fingerprints existed; those wait for `--remove-legacy`.

Change the period with `SHAKERSCAN_POSTGRES_LEGACY_RETENTION_DAYS` in `.env` (in days; `0` keeps
the data until you remove it). To reclaim the space now, after checking the upgraded release:

```bash
shakerscan db-upgrade --remove-legacy
```

That asks for confirmation and removes the only copy a previous release can start with.

`shakerscan reset` deletes both volumes.

## Roll back after a failed upgrade

Rollback has two parts: restore the pre-upgrade data, then restore the previous release runtime and
images. Replace the example paths and version with the values from the backup manifest.

To go back from PostgreSQL 18 to a release that runs PostgreSQL 16, skip the database restore below
and only reinstall the previous release (the last part of this section). That release reads the
`postgres-data` volume, which still holds the data exactly as it was when the upgrade copied it;
changes made after the upgrade are not in it. Do not start the new release's PostgreSQL with
`docker compose up` for this. When you upgrade again afterwards, `start` asks whether to copy the
rolled-back data again or keep the earlier PostgreSQL 18 data (see PostgreSQL 18 above).

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
moved="results.failed-upgrade-$(date -u +%Y%m%dT%H%M%SZ)"
mv results "$moved"
tar -xzf /secure/path/shakerscan-backups/shakerscan-TIMESTAMP/results.tar.gz -C ~/.shakerscan
# The backup does not carry the encryption key: put the install's key back before starting, or
# stored credentials, collections and sessions cannot be decrypted.
[ -f results/.credential_enc.key ] || cp "$moved/.credential_enc.key" results/.credential_enc.key
cp /secure/path/shakerscan-backups/shakerscan-TIMESTAMP/runtime.env ~/.shakerscan/.env
# If the install set AI_CREDENTIAL_ENC_KEY in .env instead, add that line back to .env.

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
