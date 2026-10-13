from __future__ import annotations

import runpy
from pathlib import Path

import pytest

SCRIPT = (
    Path(__file__).parents[1]
    / "ansible/roles/tartarus_remnux/files/tartarus-yara-input"
)
INPUT = runpy.run_path(str(SCRIPT))
find_single_elf = INPUT["find_single_elf"]
is_elf = INPUT["is_elf"]
member_is_safe = INPUT["member_is_safe"]


def test_input_identifies_elf_and_rejects_pe_content(tmp_path: Path) -> None:
    elf = tmp_path / "sample.elf"
    elf.write_bytes(b"\x7fELF" + b"\x00" * 60)
    pe = tmp_path / "renamed.elf"
    pe.write_bytes(b"MZ" + b"\x00" * 62)

    assert is_elf(elf)
    assert not is_elf(pe)


@pytest.mark.parametrize(
    "name",
    ("../escape", "/absolute/sample", "C:/sample", "folder/../../escape"),
)
def test_zip_member_validation_rejects_escaping_paths(name: str) -> None:
    assert not member_is_safe(name)


def test_zip_must_contain_exactly_one_elf(tmp_path: Path) -> None:
    first = tmp_path / "first"
    first.write_bytes(b"\x7fELF")
    assert find_single_elf(tmp_path) == first

    (tmp_path / "second").write_bytes(b"\x7fELF")
    with pytest.raises(SystemExit, match="exactly one ELF; found 2"):
        find_single_elf(tmp_path)


def test_zip_rejects_symbolic_links(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.write_bytes(b"\x7fELF")
    (tmp_path / "link").symlink_to(target)

    with pytest.raises(SystemExit, match="symbolic link"):
        find_single_elf(tmp_path)
