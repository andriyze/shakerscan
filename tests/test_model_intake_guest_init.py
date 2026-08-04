from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_guest_init_mounts_are_idempotent_and_verified() -> None:
    script = (ROOT / "runner" / "guest" / "guest-init").read_text()

    assert "ensure_mounted /proc proc proc" in script
    assert "ensure_mounted /sys sysfs sysfs" in script
    assert "ensure_mounted /dev devtmpfs devtmpfs" in script
    assert 'findmnt -rn -T "$target" -o FSTYPE | grep -qx "$filesystem"' in script
    assert "mount -t devtmpfs devtmpfs /dev" not in script
