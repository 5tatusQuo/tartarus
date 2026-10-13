from __future__ import annotations

import json
import mimetypes
import shutil
import zipfile
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from .elf import triage_elf
from .errors import TartarusError
from .util import atomic_json, load_json, new_id, safe_id, utc_now

MAX_SAMPLE_BYTES = 1024**3


def project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def schema(name: str) -> dict[str, Any]:
    return json.loads(schema_path(name).read_text())


def schema_path(name: str) -> Path:
    repository_path = project_root() / "schemas" / f"{name}.schema.json"
    packaged_path = Path(__file__).parent / "schemas" / f"{name}.schema.json"
    return repository_path if repository_path.is_file() else packaged_path


def validate(name: str, document: dict[str, Any]) -> None:
    errors = sorted(
        Draft202012Validator(schema(name)).iter_errors(document), key=lambda e: list(e.path)
    )
    if errors:
        raise TartarusError(f"invalid {name}: {errors[0].message}")


def create_case(evidence_root: Path, case_id: str | None = None) -> dict[str, Any]:
    identifier = safe_id(case_id or new_id("case"), "case ID")
    case_dir = evidence_root / identifier
    if case_dir.exists():
        raise TartarusError(f"case already exists: {identifier}")
    document = {
        "schema_version": "1.0",
        "case_id": identifier,
        "created_at": utc_now(),
        "samples": [],
    }
    validate("case-manifest", document)
    atomic_json(case_dir / "case.json", document)
    case_dir.chmod(0o700)
    return document


def stage_sample(evidence_root: Path, case_id: str, source: Path) -> dict[str, Any]:
    safe_id(case_id, "case ID")
    case_file = evidence_root / case_id / "case.json"
    case = load_json(case_file)
    source = source.resolve(strict=True)
    if not source.is_file():
        raise TartarusError(f"sample is not a regular file: {source}")
    if source.stat().st_size > MAX_SAMPLE_BYTES:
        raise TartarusError("sample exceeds the 1 GiB execution input limit")
    sample_id = new_id("sample")
    is_zip = zipfile.is_zipfile(source)
    elf = None if is_zip else triage_elf(source)
    destination = evidence_root / case_id / "samples" / sample_id / "sample.bin"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.parent.chmod(0o700)
    shutil.copyfile(source, destination)
    destination.chmod(0o400)
    record = {
        "sample_id": sample_id,
        "original_name": source.name,
        "size": source.stat().st_size,
        "staged_at": utc_now(),
        "media_type": "application/zip" if is_zip else "application/x-elf",
    }
    if elf is not None:
        record["elf"] = elf
    else:
        record["archive"] = {"format": "zip"}
    case["samples"].append(record)
    validate("case-manifest", case)
    atomic_json(case_file, case)
    return record


def create_run(
    evidence_root: Path,
    case_id: str,
    sample_id: str,
    profile: str,
    release: str,
    run_id: str | None = None,
) -> dict[str, Any]:
    safe_id(case_id, "case ID")
    safe_id(sample_id, "sample ID")
    identifier = safe_id(run_id or new_id("run"), "run ID")
    sample_path = evidence_root / case_id / "samples" / sample_id / "sample.bin"
    if not sample_path.is_file():
        raise TartarusError("sample is not staged")
    run_dir = evidence_root / case_id / identifier
    if run_dir.exists():
        raise TartarusError(f"run already exists: {identifier}")
    document = {
        "schema_version": "1.0",
        "case_id": case_id,
        "run_id": identifier,
        "sample": {"sample_id": sample_id},
        "telemetry_profile": profile,
        "tartarus_release": release,
        "status": "prepared",
        "started_at": utc_now(),
        "artifacts": [],
        "visibility_gaps": [],
    }
    validate("run-manifest", document)
    atomic_json(run_dir / "run.json", document)
    run_dir.chmod(0o700)
    return document


def collect_artifact(
    run_file: Path, source: Path, kind: str = "application/octet-stream"
) -> dict[str, Any]:
    run = load_json(run_file)
    source = source.resolve(strict=True)
    relative = Path("artifacts") / "manual" / f"{new_id('artifact')}-{source.name}"
    destination = run_file.parent / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    destination.chmod(0o600)
    record = {
        "relative_path": relative.as_posix(),
        "media_type": mimetypes.guess_type(source.name)[0] or kind,
        "size": destination.stat().st_size,
        "collection_status": "collected",
        "collected_at": utc_now(),
    }
    run["artifacts"].append(record)
    validate("run-manifest", run)
    atomic_json(run_file, run)
    return record
