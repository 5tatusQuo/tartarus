from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

from .errors import TartarusError


def triage_elf(path: Path) -> dict[str, Any]:
    with path.open("rb") as handle:
        header = handle.read(64)
    if len(header) < 20 or header[:4] != b"\x7fELF":
        raise TartarusError("sample is not an ELF file")
    elf_class = header[4]
    data = header[5]
    if elf_class not in {1, 2} or data not in {1, 2}:
        raise TartarusError("sample has an unsupported ELF identification header")
    endian = "<" if data == 1 else ">"
    elf_type, machine = struct.unpack_from(endian + "HH", header, 16)
    if header[6] != 1:
        raise TartarusError("sample has an unsupported ELF version")
    if elf_type not in {2, 3}:
        raise TartarusError("sample must be an executable or shared-object ELF")
    return {
        "class": 32 if elf_class == 1 else 64,
        "endianness": "little" if data == 1 else "big",
        "type": elf_type,
        "machine": machine,
    }


def supports_native_sandbox_execution(metadata: dict[str, Any]) -> bool:
    return (
        metadata["class"] == 64
        and metadata["endianness"] == "little"
        and metadata["machine"] == 62
    )
