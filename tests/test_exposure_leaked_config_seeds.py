"""Secret-bearing deployment files are probed seeds, and their usual content is proven."""
import pytest

from capabilities.exposure_probe import SENSITIVE_SEED_PATHS, classify_exposure

SEEDS = ("/secrets.env", "/kubeconfig.yaml", "/.claude/mcp.json", "/config/config.inc.php.dist")

# Synthetic, worthless values in each file's ordinary shape. An MCP configuration is proven by
# whatever credential grammar its values carry (e.g. cloud keys), so it has no sample here.
SAMPLES = {
    "/secrets.env": ("text/plain", "DATABASE_PASSWORD=Zq8vT2mLw9xR4bN7cY3k\n"
                     "SESSION_SECRET=P6dF0aJ1sH5gE8uW2oQ3tY6\n"),
    "/kubeconfig.yaml": ("application/octet-stream",
                         "apiVersion: v1\nkind: Config\nclusters:\n- cluster:\n    server: https://k8s.example.test:6443\n"
                         "  name: prod\nusers:\n- name: deployer\n  user:\n"
                         "    token: Zq8vT2mLw9xR4bN7cY3kP6dF0aJ1sH5gE8uW2oQ3tY6\n"),
    "/config/config.inc.php.dist": ("text/plain",
                                    "<?php\n$_APP = array();\n$_APP['db_server'] = '127.0.0.1';\n"
                                    "$_APP['db_user'] = 'app';\n$_APP['db_password'] = 'Zq8vT2mLw9xR4bN7';\n"),
}


def test_the_leaked_deployment_files_are_seeds():
    for path in SEEDS:
        assert path in SENSITIVE_SEED_PATHS


@pytest.mark.parametrize("path", sorted(SAMPLES))
def test_a_leaked_deployment_file_is_proven_from_its_content(path):
    content_type, body = SAMPLES[path]
    signature = classify_exposure(path=path, status=200, headers={"content-type": content_type},
                                  body=body.encode())
    assert signature is not None and signature.proves_sensitive_exposure, path


def test_the_same_paths_answering_a_page_prove_nothing():
    page = b"<!doctype html><html><body><h1>Not here</h1></body></html>"
    for path in SEEDS:
        assert classify_exposure(path=path, status=200, headers={"content-type": "text/html"},
                                 body=page) is None
