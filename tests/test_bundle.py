import io
import tarfile
from pathlib import Path

import pytest
from tartarus.bundle import create_bundle, verify_bundle
from tartarus.errors import TartarusError


def test_empty_locked_bundle_round_trip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("tartarus.bundle._locked_artifacts", list)
    bundle = create_bundle(tmp_path / "offline.tar.gz", tmp_path / "cache")
    assert verify_bundle(bundle)["artifacts"] == []


def test_bundle_rejects_path_traversal(tmp_path: Path) -> None:
    bundle = tmp_path / "bad.tar.gz"
    with tarfile.open(bundle, "w:gz") as archive:
        content = b"bad"
        member = tarfile.TarInfo("../escape")
        member.size = len(content)
        archive.addfile(member, io.BytesIO(content))
    with pytest.raises(TartarusError, match="unsafe bundle member"):
        verify_bundle(bundle)


def test_bundle_rejects_unlocked_extra_files(tmp_path: Path) -> None:
    bundle = tmp_path / "extra.tar.gz"
    with tarfile.open(bundle, "w:gz") as archive:
        content = b"not permitted"
        member = tarfile.TarInfo("secrets/config")
        member.size = len(content)
        archive.addfile(member, io.BytesIO(content))
    with pytest.raises(TartarusError, match="unexpected bundle member"):
        verify_bundle(bundle)
