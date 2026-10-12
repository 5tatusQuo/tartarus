from pathlib import Path

import pytest
from tartarus.errors import TartarusError
from tartarus.manifest import collect_artifact, create_case, create_run, stage_sample


def test_case_sample_run_and_artifact(tmp_path: Path) -> None:
    case = create_case(tmp_path, "case-1")
    sample = tmp_path / "input.elf"
    sample.write_bytes(b"\x7fELF\x02\x01\x01" + b"\x00" * 9 + b"\x02\x00\x3e\x00" + b"\x00" * 44)
    staged = stage_sample(tmp_path, case["case_id"], sample)
    run = create_run(tmp_path, "case-1", staged["sample_id"], "standard", "test", "run-1")
    artifact = tmp_path / "trace.txt"
    artifact.write_text("fixture", encoding="utf-8")
    record = collect_artifact(tmp_path / "case-1" / "run-1" / "run.json", artifact)
    assert record["size"] == 7
    assert run["status"] == "prepared"


def test_ids_cannot_escape_evidence_root(tmp_path: Path) -> None:
    with pytest.raises(TartarusError, match="invalid case ID"):
        create_case(tmp_path, "../escape")


def test_run_rejects_invalid_sample_identifier(tmp_path: Path) -> None:
    with pytest.raises(TartarusError, match="invalid sample ID"):
        create_run(tmp_path, "case-1", "../escape", "standard", "test")
