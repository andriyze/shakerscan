# Local clean reinstall

**Status:** maintained operator guide.

From a source checkout, preview the exact local cleanup first:

```bash
bash scripts/clean-shakerscan.sh --dry-run
bash scripts/clean-shakerscan.sh
```

The second command asks for `DELETE SHAKERSCAN` once. `--yes` skips that prompt,
not the path, ownership, Docker access or removal checks. `--home PATH` selects a
custom runtime and `--project NAME` selects its Compose project. Use the same
project that started the installation, not an unrelated application's project.

## What is removed

Project-labeled Docker containers, volumes and networks are deleted before the
verified runtime directory. This includes database/queue volumes and evidence,
credentials and backups stored inside the runtime. Docker images are kept by
default. `--images` also removes first-party image references used by the selected
project's containers, without force-removing images used elsewhere. Previously
cached images with no project container are retained.

Only the client's `config.json`, `token`, its agent-workspace records and a
launcher shim pointing at this runtime are removed. Unknown client-directory files
and package-manager-owned launchers are preserved. `--keep-client` preserves all
client state. Client state inside the runtime cannot be kept while recursively
deleting that runtime.

The client keeps two more directories, resolved as the client resolves them
(`SHAKERSCAN_STATE_DIR`/`SHAKERSCAN_DATA_DIR`, then `XDG_STATE_HOME`/`XDG_DATA_HOME`,
then beside `SHAKERSCAN_CONFIG_DIR` as `<dir>.state`/`<dir>.data`, then the defaults):

- `~/.local/state/shakerscan/workspaces/`: the records `shakerscan agent` keeps of
  each agent workspace. Plain `*.json` files there (and in `superseded/`) that are
  the client's records (they name its `schema_version`) are removed; links are never
  followed or removed through, other files stay.
- `~/.local/share/shakerscan/agent`: the default agent workspace. It may hold your
  own work, so it is kept unless `--agent-workspace` is given, and then only if it
  is a plain directory owned by you whose `AGENTS.md` starts with the note
  `shakerscan agent` writes. The same applies to `~/.config/shakerscan/agent` and
  `~/.config/shakerscan/workspaces`, where client 0.8.1 kept them.

A state or data directory that is a symlink, a shared directory or not owned by
you stops the cleanup before anything is removed.

External/unlabeled volumes, remote object storage, backups outside the runtime,
systemd/WireGuard configuration and host-wide `/etc/shakerscan`, `/opt/shakerscan`
and `/var/lib/shakerscan` integrations are not removed automatically: their names
alone do not establish ownership by this installation. Review any separately
installed host integrations before reusing the host. The success message confirms
local runtime/project cleanup, not host-wide erasure or deletion of backups.

## Failed cleanup

An unavailable Docker daemon or a failed resource listing is an error, not an
empty inventory. Local runtime/client files are retained until all selected
Docker containers, volumes and networks have been removed and verified absent.
After a partial Docker failure, some resources may already be gone; no rollback
is possible. Correct the reported problem and rerun the command. A local file
removal failure also returns nonzero rather than reporting successful cleanup.

Start Docker Desktop/Engine when offline. For a Linux socket-permission error,
run as the installation owner and use `--sudo-docker` if appropriate; do not run
the entire script under sudo, which can change HOME and the selected daemon.
The helper pins the owner's Unix-socket endpoint. Remote SSH/TCP contexts are
not supported by this local cleanup command.

Cleanup uses Docker project labels directly; it does not evaluate Compose files
or `.env` and therefore does not require a PostgreSQL password just to uninstall.
Runtime directories must contain the ShakerScan launcher and Compose markers.
Home/shared directories, symlink deletion roots and unrecognized runtimes are
rejected. A missing runtime with an accessible daemon is supported for retries.
Stop other installation/update processes while cleaning; do not mutate the
runtime or its Docker resources during confirmation.

## Regression checks

```bash
bash tests/test_clean_shakerscan.sh
```

The standard-library tests use inert Docker/sudo/removal commands and isolated
temporary fixtures. The dedicated CI workflow exercises native `/bin/bash` on
Ubuntu and macOS. These tests require neither a running Docker daemon nor real
data deletion.
