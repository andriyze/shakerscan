import io
import tarfile
import zipfile

from scanner.scanner_tools import model_intake_archives as archives


def test_recursive_zip_inventory_finds_nested_pickle_and_traversal(tmp_path):
    nested = io.BytesIO()
    with zipfile.ZipFile(nested, "w") as child:
        child.writestr("data.pkl", b"pickle")
    artifact = tmp_path / "model.zip"
    with zipfile.ZipFile(artifact, "w") as outer:
        outer.writestr("nested.zip", nested.getvalue())
        outer.writestr("../escape.py", b"print('no')")

    result = archives.inspect_archive(artifact)

    assert result["complete"] is True
    assert "nested.zip!/data.pkl" in result["pickle_entries"]
    assert "../escape.py" in result["path_traversal_entries"]
    assert result["max_depth_observed"] == 1


def test_tar_inventory_flags_links_devices_and_executable_members(tmp_path):
    artifact = tmp_path / "model.tar"
    with tarfile.open(artifact, "w") as archive:
        script = b"#!/bin/sh\n"
        info = tarfile.TarInfo("bin/install.sh")
        info.size = len(script)
        archive.addfile(info, io.BytesIO(script))
        link = tarfile.TarInfo("latest")
        link.type = tarfile.SYMTYPE
        link.linkname = "bin/install.sh"
        archive.addfile(link)

    result = archives.inspect_archive(artifact)

    assert result["is_tar"] is True
    assert "bin/install.sh" in result["executable_entries"]
    assert "latest" in result["archive_link_entries"]
    assert result["unsafe"] is True


def test_archive_member_budget_fails_closed(monkeypatch, tmp_path):
    artifact = tmp_path / "many.zip"
    with zipfile.ZipFile(artifact, "w") as archive:
        archive.writestr("one", b"1")
        archive.writestr("two", b"2")
    monkeypatch.setattr(archives, "MAX_ARCHIVE_MEMBERS", 1)

    result = archives.inspect_archive(artifact)

    assert result["complete"] is False
    assert "member_count_limit" in result["limit_reasons"]
