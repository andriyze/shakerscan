"""pip's vendored urllib3 is replaced with the environment's hash-locked urllib3, vendored as pip does it.

pip 26.2.1 vendors urllib3 2.7.0 (CVE-2026-97687, CVE-2026-97689) and the pip-audit environment has to
keep pip. The re-vendoring must apply every rewrite pip applies, refuse an upstream shape its rules do
not cover instead of leaving pip importing modules from outside its vendor tree, and make vendor.txt
and pip's SBOM describe the copy that is actually installed. Against the real wheels the rules
reproduce pip 26.2.1's vendored urllib3 2.7.0 byte for byte; these tests pin the same rules on a
small tree that has every patch site.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scanner" / "model_intake_tools" / "revendor_pip_urllib3.py"

sys.path.insert(0, str(SCRIPT.parent))
import revendor_pip_urllib3  # noqa: E402

sys.path.pop(0)

UPSTREAM = {
    "__init__.py": "from .poolmanager import PoolManager\n",
    "_version.py": "__version__ = version = '2.8.0'\n",
    "poolmanager.py": '"""\n.. code-block:: python\n\n    import urllib3\n"""\n',
    "response.py": (
        "import typing\n\n" + revendor_pip_urllib3.BROTLI_RESPONSE + "\nfrom . import util\n"
    ),
    "util/__init__.py": "",
    "util/request.py": (
        'ACCEPT_ENCODING = "gzip,deflate"\n' + revendor_pip_urllib3.BROTLI_REQUEST + "\ntry:\n    pass\nexcept ImportError:\n    pass\n"
    ),
    "util/url.py": "def _idna_encode(name):\n    try:\n        import idna\n    except ImportError:\n        raise\n",
    "contrib/__init__.py": "",
    "contrib/pyopenssl.py": (
        '"""\n    try:\n        import urllib3.contrib.pyopenssl\n        urllib3.contrib.pyopenssl.inject_into_urllib3()\n'
        '    except ImportError:\n        pass\n"""\n\ndef _dnsname(name):\n    import idna\n'
    ),
    "contrib/emscripten/__init__.py": (
        "import urllib3.connection\n\ndef inject_into_urllib3():\n"
        "    urllib3.connection.HTTPConnection = object  # type: ignore[misc,assignment]\n"
        "    urllib3.connection.HTTPSConnection = object  # type: ignore[misc,assignment]\n"
    ),
}


def _tree(root: Path, files: dict[str, str]) -> Path:
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def _pip_vendor(root: Path, version: str = "2.7.0") -> Path:
    vendor = root / "pip" / "_vendor"
    _tree(vendor / "urllib3", {"__init__.py": "OLD = True\n", "LICENSE.txt": "old license\n", "stale.py": ""})
    (vendor / "vendor.txt").write_text(f"requests==2.34.2\n    urllib3=={version}\nrich==14.2.0\n", encoding="utf-8")
    ref = f"pkg:pypi/urllib3@{version}"
    (vendor / "bom.cdx.json").write_text(json.dumps({
        "bomFormat": "CycloneDX",
        "components": [
            {"name": "urllib3", "version": version, "bom-ref": ref, "purl": ref},
            {"name": "requests", "version": "2.34.2", "bom-ref": "pkg:pypi/requests@2.34.2"},
        ],
        "dependencies": [{"ref": "bom-ref:pip", "dependsOn": ["pkg:pypi/requests@2.34.2", ref]}, {"ref": ref}],
    }), encoding="utf-8")
    return vendor


def _site_packages(root: Path, files: dict[str, str] = UPSTREAM) -> Path:
    package = _tree(root / "site-packages" / "urllib3", files)
    _tree(root / "site-packages" / "urllib3-2.8.0.dist-info" / "licenses", {"LICENSE.txt": "MIT, new\n"})
    return package


def test_the_vendored_copy_is_replaced_and_rewritten_like_pip(tmp_path):
    vendor = _pip_vendor(tmp_path)
    assert revendor_pip_urllib3.revendor(vendor, _site_packages(tmp_path)) == ("2.7.0", "2.8.0")

    urllib3 = vendor / "urllib3"
    assert not (urllib3 / "stale.py").exists(), "files from the old vendored copy must not survive"
    assert (urllib3 / "LICENSE.txt").read_text() == "MIT, new\n"
    assert "from pip._vendor import urllib3" in (urllib3 / "poolmanager.py").read_text()
    assert (urllib3 / "response.py").read_text() == "import typing\n\nbrotli = None\n\nfrom . import util\n"
    request = (urllib3 / "util" / "request.py").read_text()
    assert request.startswith('ACCEPT_ENCODING = "gzip,deflate"\n\ntry:') and "brotli" not in request
    assert "from pip._vendor import idna" in (urllib3 / "util" / "url.py").read_text()
    pyopenssl = (urllib3 / "contrib" / "pyopenssl.py").read_text()
    assert "import pip._vendor.urllib3.contrib.pyopenssl as pyopenssl\n        pyopenssl.inject_into_urllib3()" in pyopenssl
    assert "    from pip._vendor import idna\n" in pyopenssl
    emscripten = (urllib3 / "contrib" / "emscripten" / "__init__.py").read_text()
    assert emscripten.startswith("import pip._vendor.urllib3.connection as urllib3_connection\n")
    assert "    urllib3_connection.HTTPSConnection = object" in emscripten
    assert "urllib3.connection." not in emscripten
    assert not (vendor / "urllib3.revendor").exists()


def test_vendor_txt_and_the_sbom_name_the_installed_version(tmp_path):
    vendor = _pip_vendor(tmp_path)
    revendor_pip_urllib3.revendor(vendor, _site_packages(tmp_path))

    assert (vendor / "vendor.txt").read_text() == "requests==2.34.2\n    urllib3==2.8.0\nrich==14.2.0\n"
    document = json.loads((vendor / "bom.cdx.json").read_text())
    [component] = [c for c in document["components"] if c["name"] == "urllib3"]
    assert component == {"name": "urllib3", "version": "2.8.0",
                         "bom-ref": "pkg:pypi/urllib3@2.8.0", "purl": "pkg:pypi/urllib3@2.8.0"}
    assert "2.7.0" not in json.dumps(document)
    assert document["dependencies"][0]["dependsOn"] == ["pkg:pypi/requests@2.34.2", "pkg:pypi/urllib3@2.8.0"]


def test_an_upstream_shape_the_rules_do_not_cover_fails_and_leaves_pip_intact(tmp_path):
    # A new absolute import would make pip load a second urllib3 from outside its vendor tree.
    files = dict(UPSTREAM, **{"util/ssl_.py": "import urllib3.exceptions\n"})
    vendor = _pip_vendor(tmp_path)
    with pytest.raises(ValueError, match=r"absolute imports left .*util/ssl_\.py: import urllib3"):
        revendor_pip_urllib3.revendor(vendor, _site_packages(tmp_path, files))
    assert (vendor / "urllib3" / "__init__.py").read_text() == "OLD = True\n"
    assert "urllib3==2.7.0" in (vendor / "vendor.txt").read_text()
    assert not (vendor / "urllib3.revendor").exists()


def test_a_changed_brotli_block_is_refused(tmp_path):
    files = dict(UPSTREAM, **{"response.py": "import typing\n\nbrotli = _load_brotli()\n"})
    with pytest.raises(ValueError, match="response.py: expected pip's patch site exactly once, found 0"):
        revendor_pip_urllib3.revendor(_pip_vendor(tmp_path), _site_packages(tmp_path, files))


def test_an_older_replacement_is_refused_and_the_same_version_is_a_no_op(tmp_path):
    older = _pip_vendor(tmp_path / "older", version="2.9.0")
    with pytest.raises(ValueError, match="older 2.8.0"):
        revendor_pip_urllib3.revendor(older, _site_packages(tmp_path / "older"))

    same = _pip_vendor(tmp_path / "same", version="2.8.0")
    assert revendor_pip_urllib3.revendor(same, _site_packages(tmp_path / "same")) == ("2.8.0", "2.8.0")
    assert (same / "urllib3" / "__init__.py").read_text() == "OLD = True\n"


def test_the_cli_reports_failure_with_a_nonzero_exit(tmp_path):
    vendor = _pip_vendor(tmp_path)
    (vendor / "vendor.txt").write_text("requests==2.34.2\n", encoding="utf-8")
    result = subprocess.run([sys.executable, str(SCRIPT), str(vendor), str(_site_packages(tmp_path))],
                            capture_output=True, text=True)
    assert result.returncode == 1
    assert "vendor.txt lists urllib3 0 times" in result.stderr


def test_the_image_revendors_before_pip_is_exercised():
    dockerfile = (ROOT / "scanner" / "Dockerfile.model-intake").read_text(encoding="utf-8")
    step = 'python3 /opt/model-intake-locks/revendor_pip_urllib3.py "$vendor"'
    assert step in dockerfile
    assert dockerfile.index('rm -rf "$vendor/msgpack"') < dockerfile.index(step)
    assert dockerfile.index(step) < dockerfile.index('-m pip --version >/dev/null')
    assert dockerfile.index(step) < dockerfile.index("/opt/tools/pip-audit-offline --build-cache")
    assert "v.__version__ == urllib3.__version__ and v.__file__ != urllib3.__file__" in dockerfile
