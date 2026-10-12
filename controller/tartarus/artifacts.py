from __future__ import annotations

import shutil
import tarfile
import tempfile
import urllib.request
from pathlib import Path

import yaml

from .errors import TartarusError
from .manifest import project_root


def locked_artifacts() -> list[dict[str, str]]:
    lock = yaml.safe_load((project_root() / "versions.lock.yml").read_text(encoding="utf-8"))
    artifacts = lock.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise TartarusError("versions.lock.yml contains no locked artifacts")
    required = {"filename", "url"}
    for item in artifacts:
        if (
            not isinstance(item, dict)
            or not required <= set(item)
            or ("role" in item) == ("destination" in item)
        ):
            raise TartarusError("locked artifact entry is incomplete")
    return artifacts


def acquire_artifacts(cache_root: Path, offline_bundle: Path | None = None) -> list[Path]:
    artifact_root = cache_root / "artifacts"
    artifact_root.mkdir(parents=True, exist_ok=True)
    if offline_bundle:
        _import_bundle(offline_bundle, artifact_root)
    acquired: list[Path] = []
    for item in locked_artifacts():
        destination = artifact_root / item["filename"]
        if destination.is_file():
            acquired.append(destination)
            continue
        if offline_bundle:
            raise TartarusError(f"offline bundle is missing {item['filename']}")
        with tempfile.NamedTemporaryFile(
            dir=artifact_root, prefix="download-", delete=False
        ) as handle:
            temporary = Path(handle.name)
            try:
                with urllib.request.urlopen(item["url"], timeout=1800) as response:
                    shutil.copyfileobj(response, handle)
            except (OSError, TimeoutError) as exc:
                temporary.unlink(missing_ok=True)
                raise TartarusError(
                    f"failed to download locked artifact {item['filename']}: {exc}"
                ) from exc
        temporary.replace(destination)
        acquired.append(destination)
    return acquired


def inject_artifacts(rendered_source: Path, cache_root: Path) -> None:
    for item in locked_artifacts():
        source = cache_root / "artifacts" / item["filename"]
        if not source.is_file():
            raise TartarusError(f"cached artifact is missing: {item['filename']}")
        destination = (
            rendered_source / item["destination"] / item["filename"]
            if "destination" in item
            else rendered_source / "ansible" / "roles" / item["role"] / "files" / item["filename"]
        )
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)


def _import_bundle(bundle: Path, artifact_root: Path) -> None:
    with tarfile.open(bundle, "r:gz") as archive:
        members = {member.name: member for member in archive.getmembers()}
        for item in locked_artifacts():
            member = members.get(f"artifacts/{item['filename']}")
            if not member or not member.isfile():
                continue
            source = archive.extractfile(member)
            if source is None:
                continue
            with tempfile.NamedTemporaryFile(
                dir=artifact_root, prefix="import-", delete=False
            ) as handle:
                temporary = Path(handle.name)
                shutil.copyfileobj(source, handle)
            temporary.replace(artifact_root / item["filename"])
