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
