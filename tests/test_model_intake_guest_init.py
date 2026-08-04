from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_guest_init_mounts_are_idempotent_and_verified() -> None:
    script = (ROOT / "runner" / "guest" / "guest-init").read_text()

    assert "ensure_mounted /proc proc proc" in script
    assert "ensure_mounted /sys sysfs sysfs" in script
    assert "ensure_mounted /dev devtmpfs devtmpfs" in script
    assert 'findmnt -rn -T "$target" -o FSTYPE | grep -qx "$filesystem"' in script
    assert "mount -t devtmpfs devtmpfs /dev" not in script
    assert "mount -t tmpfs -o size=256m,nosuid,nodev,noexec tmpfs /tmp" in script
    assert "chmod 1777 /tmp" in script
    assert "mkdir -p /tmp/modelrunner/huggingface/modules" in script
    assert "chown -R 65532:65532 /tmp/modelrunner" in script
    assert "export HOME=/tmp/modelrunner" in script
    assert "export HF_MODULES_CACHE=/tmp/modelrunner/huggingface/modules" in script
    assert "export HF_HUB_OFFLINE=1" in script
    assert "export TRANSFORMERS_OFFLINE=1" in script
    assert 'phases="import tokenizer model_load warmup inference"' in script
    assert 'phases="import deserialize_convert tensor_equivalence embedding_equivalence"' in script
    assert 'guest_worker.py --phase teardown || teardown_status=$?' in script
    assert "sync\numount /output\n/bin/busybox reboot -f" in script
    assert "poweroff" not in script
