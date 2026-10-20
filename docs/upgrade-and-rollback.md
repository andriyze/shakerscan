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

A `start` that changes the release version also saves the database first, to
`backups/pre-upgrade-<time>-<from>-to-<to>/` (the newest two are kept, and until a start succeeds
also the first one of that upgrade, taken before any migration ran), and stops if that fails. The
version it upgrades from is the one the running API reports. When nothing is running, the launcher
uses the release it recorded at its last start; if a launcher older than 2.10 (which keeps no such
record, for example after a rollback) or the installer has run since, it saves the database anyway
and names the backup `unverified-<recorded>`. `shakerscan reset` starts the emptied stack exactly as
`start` does, without this backup.

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

Before a start that changes the release, the launcher offers a complete `shakerscan backup` (the
database, scan results and configuration, written to `backups/` on the host, outside Docker). In a
terminal it asks, defaulting to yes; without a terminal it takes only the automatic database dump
above. `SHAKERSCAN_UPGRADE_BACKUP=full` takes the complete backup without asking,
`SHAKERSCAN_UPGRADE_BACKUP=database` never asks. When the complete backup is taken, it holds the
database and no separate pre-upgrade dump is made. A failed backup stops the upgrade with nothing
changed.

## Disk space, images and Redis

The launcher manages its own Docker images and Redis; you never need to remove Docker volumes, and
nothing here suggests `docker system prune --volumes` (it deletes the database).

Checks before an upgrade changes anything:

- Docker's storage must hold the images still to download plus room for the databases; older
  ShakerScan images nothing keeps are removed first.
- The install directory (`backups/`, `results/`) needs at least 2 GB free
  (`SHAKERSCAN_INSTALL_DIR_MIN_FREE_GB`); with less, an upgrade stops and any other start warns.
- The running release's PostgreSQL and Redis must be saving their data to their Docker volumes: a
  Redis whose last save failed (often a full disk), or data outside its volume, stops the upgrade
  while the running release keeps running. `shakerscan doctor` names the problem.
- A start never creates an empty database over a lost one: when this install has run before and its
  database volume is missing, `start` stops and points to `backups/`. To start empty on purpose:
  `SHAKERSCAN_ALLOW_NEW_DATABASE=1 shakerscan start` (`shakerscan reset` does this itself).
- A start never runs PostgreSQL 18 beside PostgreSQL 16 data with no `postgres-cluster` volume (the
  `postgres-data` volume of a release before 2.6): `start`, `restart` and every other command that
  would start PostgreSQL stop before anything is downloaded, stopped or removed. Data that was never
  migrated is pointed to 2.10.0; when this install has run PostgreSQL 18 before, `postgres-data` is
  the copy a migration kept and `start` points to `backups/` (see PostgreSQL 18 below).

Images:

```bash
shakerscan images          # every ShakerScan image on this host, and why it is kept
shakerscan images prune    # remove the ones nothing keeps
```

An image is kept when it belongs to the release this install runs, to a release kept for rollback,
to the current or kept release of another install on this host, or when any container (running or
stopped) uses it. Third-party images (PostgreSQL, Redis) and volumes are never removed.
`SHAKERSCAN_KEEP_RELEASES` sets how many releases are kept, this one included (default 2: this
release and one to roll back to; 1 keeps no rollback images). After a successful start, older
ShakerScan images of this install are removed automatically (`SHAKERSCAN_PRUNE_OLD_IMAGES=0` keeps
them). The release that was actually running before an upgrade is the one kept for rollback, even
after a rollback by an older launcher. Every install that starts with a 2.11 or later launcher is
registered in `~/.local/state/shakerscan/installs`, so one install's cleanup never removes another,
stopped install's images; an install under another user account is not visible there.

Redis holds queues and job state only; scans, findings and evidence are in PostgreSQL. A damaged
Redis is repaired during `start`. If Redis's data is lost or it cannot start at all:

```bash
shakerscan redis           # health, persistence and volume
shakerscan redis reset     # keep a copy in backups/redis-<time>/, recreate Redis empty, reconnect services
```

After a reset, Scans that were waiting to start are queued again automatically within about ten
minutes; a Scan that was running is marked with an unknown outcome and can be started again.
`shakerscan status` and `doctor` warn when Docker or the install directory is short of space,
when the database or Redis volume of an install that has run before is missing, or when the
PostgreSQL 16 `postgres-data` volume was never migrated or sits beside `postgres-cluster` with no
record of its migration (see PostgreSQL 18 below).

## Upgrade

The oldest directly supported upgrade base for the database schema is **0.8.18**. Installations
older than that must first upgrade to 0.8.18, confirm health and create a fresh backup, then upgrade
to the current stable release. Release certification exercises both the immediately previous stable
version and 0.8.18; versions older than the pinned minimum are not covered by the direct-migration
guarantee. Every release before 2.6, 0.8.18 included, runs PostgreSQL 16, whose data this release
does not migrate: upgrade such an install to 2.10.0 first (see PostgreSQL 18 below). The 0.8.18
certification covers the schema migration on PostgreSQL 18, not the PostgreSQL 16 data files.

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

ShakerScan runs PostgreSQL 18, with the data in the `postgres-cluster` volume. Releases before 2.6
ran PostgreSQL 16 with the data in the `postgres-data` volume. 2.6 to 2.10 migrated it on their
first start, kept `postgres-data` as a copy for rollback, and recorded the migration in
`backups/postgres-16-to-18-<time>/shakerscan-migration.txt`. This release does not migrate
PostgreSQL 16 data. When `postgres-data` exists without `postgres-cluster`, `start` stops with
nothing changed, and every other command that would start PostgreSQL refuses before it changes
anything. A `POSTGRES_IMAGE` override must name a PostgreSQL 18 image.

**Data that was never migrated** (this install has no release record of 2.10 or later and no
migration record in `backups/`). Upgrade through 2.10.0: it copies the data into PostgreSQL 18,
compares row counts, sequences and roles with the source, and leaves `postgres-data` in place:

```bash
curl -fsSL https://install.shakerscan.com | SHAKERSCAN_INSTALL_VERSION=2.10.0 sh
shakerscan status      # then check in the UI that your targets and scans are there
curl -fsSL https://install.shakerscan.com | sh
```

For an install outside `~/.shakerscan`, add `SHAKERSCAN_HOME=/path/to/your/install` beside the other
variable in both installer commands. In a source checkout, use the `v2.10.0` tag instead: the
installer would replace the checkout's files with a release's and switch it to prebuilt images.

```bash
git checkout v2.10.0 && ./scanner.sh start --local
# check in the UI that your targets and scans are there, then return to your branch
git checkout <your-branch> && ./scanner.sh start --local
```

To start this release with an empty database instead (the `postgres-data` volume is not touched), run
`SHAKERSCAN_ALLOW_NEW_DATABASE=1 shakerscan start`.

**The database volume is missing and `postgres-data` is still there.** On an install that has run
PostgreSQL 18 before (a release record, or a migration record in `backups/`), `postgres-cluster` was
lost, for example by `docker compose down -v`. `postgres-data` beside it is the copy the migration
kept: it holds the data as it was on the day of the migration, which `start` names when the record is
in `backups/`, and nothing recorded since. `start` stops and points to `backups/`: restore the newest
backup there (see Roll back after a failed upgrade, below). Only when no backup is newer than that
copy is it worth migrating it again through 2.10.0 as above, knowing that everything recorded after
the migration is missing from it. One exception: on an install that went straight from a release
before 2.6 to 2.11.0 (next paragraph) and lost `postgres-cluster` since, `postgres-data` is the only
copy of your data and the pre-upgrade dumps are of the empty database; upgrade through 2.10.0 as above.

**An install that 2.11.0 started on an empty database.** 2.11.0 did not refuse: on an install
upgraded directly from a release before 2.6 it created a new, empty `postgres-cluster` beside
`postgres-data`, and any pre-upgrade dump it took is of the empty database. The PostgreSQL 16 data in
`postgres-data` was not changed. `status` and `doctor` warn about `postgres-data` beside
`postgres-cluster` while `backups/` holds no record of migrating it. To move the data across, use the
2.10.0 launcher, which sets the empty cluster aside and copies `postgres-data` again (it asks you to
type `remigrate`):

```bash
curl -fsSL https://install.shakerscan.com | SHAKERSCAN_INSTALL_VERSION=2.10.0 SHAKERSCAN_START=0 sh
shakerscan db-upgrade --remigrate
shakerscan start
shakerscan status      # then check in the UI that your targets and scans are there
curl -fsSL https://install.shakerscan.com | sh
```

What was recorded on the empty database stays in the set-aside copy inside `postgres-cluster`; it is
not merged. 2.10.0 records this migration in `backups/` as well, so the warning stops.

**The copy kept after a migration.** This release neither reads nor removes `postgres-data`: after a
migration it is an old copy of the data as it was migrated. While `backups/` holds the record of that
migration, `status` and `doctor` say nothing about it. Without the record (the backups were deleted,
or the install directory was replaced) they warn while both volumes exist. If ShakerScan shows the
targets and scans you had before 2.11, the migration took place and `postgres-data` is only the old
copy: once you no longer need it to roll back to a release before 2.6, `docker volume rm
shakerscan_postgres-data` (with your Compose project name in place of `shakerscan`) removes it and
the warning. If ShakerScan shows none of them, follow the previous paragraph instead.

`shakerscan reset` deletes the `postgres-cluster` database volume, not `postgres-data`.

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
