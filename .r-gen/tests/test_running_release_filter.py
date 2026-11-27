"""Third-party images must not abort a launcher running with errexit enabled."""
import pytest

from tests.test_upgrade_safety import run


@pytest.mark.parametrize('operation', ['note_running_release', 'remember_running_release'])
@pytest.mark.parametrize('images', [
    'a-app z-redis', 'a-redis z-app', 'a-postgres z-redis',
])
def test_release_inventory_filter_keeps_app_images_without_exiting_on_other_images(tmp_path, operation, images):
    body = '''
    set -e
    running_api_version() { echo 2.10.0; }
    project_container_image_ids() { printf '%s\\n' REPLACE_IMAGES; }
    image_is_shakerscan() { case "$1" in *-app) return 0 ;; *) return 1 ;; esac; }
    REPLACE_OPERATION
    echo reached-next-launcher-step
    printf 'noted:%s\\nimages:%s\\n' "$RELEASE_RUNNING_NOTED" "$RELEASE_RUNNING_IMAGES"
    if [ -f "$RELEASE_STATE_PREVIOUS" ]; then cat "$RELEASE_STATE_PREVIOUS"; fi
    '''.replace('REPLACE_IMAGES', images).replace('REPLACE_OPERATION', operation)
    result = run(tmp_path, body)
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'reached-next-launcher-step' in result.stdout
    app_ids = [x for x in images.split() if x.endswith('-app')]
    if operation == 'note_running_release':
        assert 'noted:1' in result.stdout
        assert 'images:' + '\n'.join(app_ids) + '\n' in result.stdout
    elif app_ids:
        assert '# release 2.10.0\n' + '\n'.join(app_ids) + '\n' in result.stdout
    else:
        assert not (tmp_path / '.release-images.previous').exists()
    assert not any(x in result.stdout for x in ['a-postgres', 'a-redis', 'z-redis'])
