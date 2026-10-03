"""Launcher upgrade admission requires a successful backup for an existing legacy schema."""
from pathlib import Path
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(('kind','initialized','backup_status','expected'),[
    ('r','t',0,'backup\nlaunch'),
    ('r','t',7,'backup'),
    ('v','t',0,'launch'),
    ('r','f',0,'launch'),
])
def test_backup_boundary_preserves_first_start_and_blocks_failed_upgrade(kind,initialized,backup_status,expected):
    script = """
set -e
source "$1"
compose() {
    case "$*" in
        *"/proc/1/comm"*) printf 'postgres\\n' ;;
        *"SELECT relkind"*) printf '%s\\n' "$KIND" ;;
        *"SELECT to_regclass"*) printf '%s\\n' "$INITIALIZED" ;;
    esac
}
create_backup() { echo backup; return "$BACKUP_STATUS"; }
ensure_target_upgrade_backup || exit 7
echo launch
"""
    import os
    result = subprocess.run(['bash','-c',script,'fixture',str(ROOT/'scripts/target_upgrade_backup.sh')],
        env={**os.environ,'KIND':kind,'INITIALIZED':initialized,'BACKUP_STATUS':str(backup_status)},
        text=True,capture_output=True,timeout=10)
    events = '\n'.join(line for line in result.stdout.splitlines() if line in {'backup','launch'})
    assert events == expected
    assert result.returncode == (7 if backup_status and kind == 'r' and initialized == 't' else 0)


def test_the_backup_waits_for_the_final_postgres_process_not_the_init_server(tmp_path):
    """A fresh volume's temporary init server answers pg_isready and then shuts down; a dump
    taken then failed CI with "the database system is shutting down"."""
    import os
    polls = tmp_path / 'polls'
    script = """
set -e
source "$1"
sleep() { :; }
compose() {
    case "$*" in
        *"/proc/1/comm"*)
            echo poll >> "$POLLS"
            if [ "$(wc -l < "$POLLS")" -lt 3 ]; then printf 'bash\\n'; else printf 'postgres\\n'; fi ;;
        *"pg_isready"*) return 0 ;;  # the init server answers too: readiness alone is not enough
        *"SELECT relkind"*) echo query >> "$POLLS"; printf 'r\\n' ;;
        *"SELECT to_regclass"*) printf 't\\n' ;;
    esac
}
create_backup() { echo backup; }
ensure_target_upgrade_backup
"""
    result = subprocess.run(['bash', '-c', script, 'fixture', str(ROOT / 'scripts/target_upgrade_backup.sh')],
                            env={**os.environ, 'POLLS': str(polls)}, text=True, capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr
    # Nothing is queried or dumped until the init server is gone.
    assert polls.read_text().split() == ['poll', 'poll', 'poll', 'query']
    assert 'backup' in result.stdout.split()
