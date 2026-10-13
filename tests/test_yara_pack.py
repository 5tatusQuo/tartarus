from __future__ import annotations

import json
import runpy
import zipfile
from pathlib import Path

import pytest

SCRIPT = (
    Path(__file__).parents[1]
    / "ansible/roles/tartarus_remnux/files/tartarus-yara-pack-build"
)
PACK = runpy.run_path(str(SCRIPT))
PackError = PACK["PackError"]
build_pack = PACK["build_pack"]


def _rule(name: str, quality: int, condition: str, strings: str = "") -> str:
    identifier = f"id-{name}"
    logic_hash = f"hash-{name}"
    string_section = f"\n\tstrings:\n{strings}" if strings else ""
    return f"""
rule {name}
{{
    meta:
        id = "{identifier}"
        logic_hash = "{logic_hash}"
        source_url = "https://example.invalid/{name}"
        quality = {quality}{string_section}
    condition:
        {condition}
}}
"""


def _inputs(tmp_path: Path, *, allow: list[dict] | None = None) -> tuple[Path, Path]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    source = tmp_path / "full.yar"
    source.write_text(
        'import "elf"\nimport "pe"\n'
        + """
private rule IsElf
{
    meta:
        id = "id-IsElf"
        logic_hash = "hash-IsElf"
        quality = 80
    strings:
        $header = { 7f 45 4c 46 }
    condition:
        $header at 0
}
"""
        + _rule("DirectHeader", 80, "uint32(0) == 0x464c457f")
        + _rule("BigEndianHeader", 80, "uint32be(0) == 0x7f454c46")
        + _rule("ElfModule", 80, "elf.type == elf.ET_EXEC")
        + _rule("ViaPrivate", 80, "IsElf and filesize < 1MB")
        + _rule("LinuxNamedPe", 90, "uint16(0) == 0x5a4d and pe.is_32bit()")
        + _rule("LowQualityElf", 60, "uint16(0) == 0x457f")
        + _rule("GenericReviewed", 90, "filesize < 1MB"),
        encoding="utf-8",
    )
    overrides = tmp_path / "overrides.json"
    overrides.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "selection_policy": "tartarus-elf-v1",
                "minimum_quality": 70,
                "allow": allow or [],
                "deny": [],
            }
        ),
        encoding="utf-8",
    )
    return source, overrides


def _build(tmp_path: Path, *, allow: list[dict] | None = None) -> dict:
    source, overrides = _inputs(tmp_path, allow=allow)
    return build_pack(
        source,
        overrides,
        tmp_path / "tartarus-elf.yar",
        tmp_path / "manifest.json",
        "test-release",
    )


def test_selector_keeps_only_guarded_quality_rules_and_private_dependencies(
    tmp_path: Path,
) -> None:
    manifest = _build(tmp_path)
    selected = {item["identifier"] for item in manifest["rules"]}

    assert selected == {
        "BigEndianHeader",
        "DirectHeader",
        "ElfModule",
        "IsElf",
        "ViaPrivate",
    }
    assert manifest["counts"] == {
        "upstream": 8,
        "public": 4,
        "private": 1,
        "compiled": 5,
        "excluded": 3,
    }
    assert "LinuxNamedPe" not in selected
    assert "LowQualityElf" not in selected
    assert manifest["imports"] == ["elf"]
    generated = (tmp_path / "tartarus-elf.yar").read_text(encoding="utf-8")
    assert 'import "elf"' in generated
    assert 'import "pe"' not in generated


def test_reviewed_allowlist_requires_the_exact_logic_hash(tmp_path: Path) -> None:
    allowed = [{"id": "id-GenericReviewed", "logic_hash": "hash-GenericReviewed"}]
    manifest = _build(tmp_path, allow=allowed)
    assert "GenericReviewed" in {item["identifier"] for item in manifest["rules"]}

    with pytest.raises(PackError, match="logic hash changed"):
        _build(
            tmp_path / "mismatch",
            allow=[{"id": "id-GenericReviewed", "logic_hash": "wrong"}],
        )


def test_pinned_full_release_generates_the_reviewed_golden_pack(tmp_path: Path) -> None:
    archive = (
        Path(__file__).parents[1]
        / ".tartarus/cache/artifacts/yara-forge-rules-full-20261011.zip"
    )
    if not archive.is_file():
        pytest.skip("pinned YARA Forge Full artifact is not present in the local cache")
    with zipfile.ZipFile(archive) as handle:
        source = tmp_path / "yara-rules-full.yar"
        source.write_bytes(handle.read("packages/full/yara-rules-full.yar"))
    overrides = Path(__file__).parents[1] / (
        "ansible/roles/tartarus_remnux/files/tartarus-yara-overrides.json"
    )
    manifest = build_pack(
        source,
        overrides,
        tmp_path / "tartarus-elf.yar",
        tmp_path / "manifest.json",
        "20261011",
    )

    assert manifest["counts"]["public"] == 376
    assert manifest["counts"]["private"] == 3
    assert manifest["counts"]["compiled"] == 379
    assert any(
        item["identifier"] == "SIGNATURE_BASE_MAL_ELF_Xlogin_Nov24_1"
        for item in manifest["rules"]
    )
