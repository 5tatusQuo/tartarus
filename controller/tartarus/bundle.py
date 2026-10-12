from __future__ import annotations

import json
import shutil
import tarfile
import tempfile
from pathlib import Path

import yaml

from .errors import TartarusError
from .manifest import project_root
from .util import utc_now


def _locked_artifacts() -> list[dict[str, str]]:
    value = yaml.safe_load((project_root() / "versions.lock.yml").read_text(encoding="utf-8"))
    artifacts = value.get("artifacts", [])
    if not isinstance(artifacts, list):
        raise TartarusError("versions.lock.yml artifacts must be a list")
    return artifacts


def _artifact_path(root: Path, filename: str) -> Path:
    path = (root / filename).resolve()
    resolved_root = root.resolve()
    if resolved_root not in path.parents or Path(filename).is_absolute():
        raise TartarusError(f"unsafe artifact filename: {filename}")
    return path


def create_bundle(output: Path, cache_root: Path) -> Path:
    if output.exists():
        raise TartarusError(f"refusing to overwrite bundle: {output}")
    inventory = {"schema_version": "1.0", "created_at": utc_now(), "artifacts": []}
    with tempfile.TemporaryDirectory(prefix="tartarus-bundle-") as temporary:
        staging = Path(temporary)
        for artifact in _locked_artifacts():
            filename = artifact["filename"]
            source = _artifact_path(cache_root / "artifacts", filename)
            if not source.is_file():
                raise TartarusError(f"locked artifact is absent from cache: {filename}")
            target = _artifact_path(staging / "artifacts", filename)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            inventory["artifacts"].append(
                {
                    "filename": filename,
                    "size": target.stat().st_size,
                }
            )
        (staging / "inventory.json").write_text(
            json.dumps(inventory, indent=2) + "\n", encoding="utf-8"
        )
        output.parent.mkdir(parents=True, exist_ok=True)
        with tarfile.open(output, "w:gz") as archive:
            archive.add(staging / "inventory.json", arcname="inventory.json")
            if (staging / "artifacts").exists():
                archive.add(staging / "artifacts", arcname="artifacts")
    return output


def verify_bundle(bundle: Path) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="tartarus-verify-") as temporary:
        root = Path(temporary).resolve()
        with tarfile.open(bundle, "r:gz") as archive:
            allowed = {"inventory.json"}
            allowed.update(f"artifacts/{item['filename']}" for item in _locked_artifacts())
            for member in archive.getmembers():
                resolved = (root / member.name).resolve()
                if root not in resolved.parents and resolved != root:
                    raise TartarusError(f"unsafe bundle member: {member.name}")
                normalized = member.name.rstrip("/")
                if normalized != "artifacts" and normalized not in allowed:
                    raise TartarusError(f"unexpected bundle member: {member.name}")
                if member.issym() or member.islnk():
                    raise TartarusError(f"links are not permitted in bundles: {member.name}")
                if not (member.isfile() or member.isdir()):
                    raise TartarusError(f"unsupported bundle member: {member.name}")
            for member in archive.getmembers():
                destination = root / member.name
                if member.isdir():
                    destination.mkdir(parents=True, exist_ok=True)
                elif member.isfile():
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    source = archive.extractfile(member)
                    if source is None:
                        raise TartarusError(f"could not read bundle member: {member.name}")
                    with destination.open("wb") as output:
                        shutil.copyfileobj(source, output)
        inventory_path = root / "inventory.json"
        try:
            inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise TartarusError("bundle inventory is missing or invalid") from exc
        inventory_items = inventory.get("artifacts", [])
        expected = {item["filename"]: item for item in _locked_artifacts()}
        observed = {item.get("filename"): item for item in inventory_items}
        if set(observed) != set(expected):
            raise TartarusError("bundle inventory does not exactly match versions.lock.yml")
        for item in inventory_items:
            path = _artifact_path(root / "artifacts", item["filename"])
            if not path.is_file():
                raise TartarusError(f"bundle artifact is missing: {item['filename']}")
            if item.get("size") != path.stat().st_size:
                raise TartarusError(f"bundle artifact size mismatch: {item['filename']}")
        return inventory
