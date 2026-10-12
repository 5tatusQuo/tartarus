from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path
from typing import Any

import yaml

from .artifacts import locked_artifacts
from .errors import TartarusError
from .manifest import project_root, validate
from .util import atomic_json, load_json, sha256_file, utc_now


def source_revision(allow_development: bool = False) -> str:
    root = project_root()
    try:
        commit = _git(root, "rev-parse", "HEAD")
        dirty = _git(root, "status", "--porcelain")
        tags = _git(root, "tag", "--points-at", "HEAD").splitlines()
    except (OSError, subprocess.CalledProcessError) as exc:
        if allow_development:
            return "development-uncommitted"
        raise TartarusError("prepare requires an immutable Git commit or tag") from exc
    if dirty and not allow_development:
        raise TartarusError(
            "prepare requires a clean worktree; use --development only for local testing"
        )
    if tags:
        return f"tag:{min(tags)}@{commit}"
    if allow_development:
        return f"development:{commit}{'-dirty' if dirty else ''}"
    return f"commit:{commit}"


def write_prepare_manifest(
    cache_root: Path,
    profile: str,
    revision: str,
    rendered_source: Path,
    base_source_files: list[dict[str, str]],
) -> dict[str, Any]:
    lock = yaml.safe_load((rendered_source / "versions.lock.yml").read_text(encoding="utf-8"))
    rendered_source_files = source_inventory(rendered_source)
    manifest = {
        "schema_version": "1.0",
        "generated_at": utc_now(),
        "tartarus_release": revision,
        "profile": profile,
        "resolved_inputs": {
            "architecture": lock["architecture"],
            "minimum_ludus_version": lock["minimum_ludus_version"],
            "build_tools": lock["build_tools"],
            "images": lock["images"],
            "package_repositories": lock["package_repositories"],
            "components": lock["components"],
            "schemas": {
                path.name: sha256_file(path)
                for path in sorted((project_root() / "schemas").glob("*.json"))
            },
            "policies": {
                path.name: sha256_file(path)
                for path in sorted((project_root() / "policies").glob("*.yml"))
            },
            "controller_requirements_sha256": sha256_file(project_root() / "requirements.lock"),
            "artifacts": [
                {
                    "filename": item["filename"],
                    "url": item["url"],
                    "algorithm": item["algorithm"],
                    "digest": item["digest"],
                }
                for item in locked_artifacts()
            ],
            "source_tree_sha256": source_inventory_hash(base_source_files),
            "source_files": base_source_files,
            "rendered_source_tree_sha256": source_inventory_hash(rendered_source_files),
            "blueprint": f"tartarus/tartarus-{profile}",
            "blueprint_sha256": sha256_file(
                rendered_source / "blueprints" / f"tartarus-{profile}" / "range-config.yml"
            ),
            "template_build_identifiers": {
                path.parent.name: f"sha256:{sha256_file(path)}"
                for path in sorted((rendered_source / "templates").rglob("*.pkr.hcl"))
            },
        },
    }
    validate("deployment-manifest", manifest)
    atomic_json(cache_root / "state" / "prepare-manifest.json", manifest)
    return manifest


def source_inventory(root: Path) -> list[dict[str, str]]:
    return [
        {"path": path.relative_to(root).as_posix(), "sha256": sha256_file(path)}
        for path in sorted(root.rglob("*"))
        if path.is_file()
    ]


def source_inventory_hash(source_files: list[dict[str, str]]) -> str:
    aggregate = hashlib.sha256()
    for item in source_files:
        aggregate.update(item["path"].encode())
        aggregate.update(b"\0")
        aggregate.update(item["sha256"].encode())
        aggregate.update(b"\n")
    return aggregate.hexdigest()


def finalize_deployment_manifest(
    cache_root: Path,
    *,
    range_id: str,
    authenticated_user: str,
    guests: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    path = cache_root / "state" / "prepare-manifest.json"
    manifest = load_json(path)
    manifest["deployment"] = {
        "range_id": range_id,
        "authenticated_user": authenticated_user,
        "completed_at": utc_now(),
        "guests": guests,
    }
    validate("deployment-manifest", manifest)
    atomic_json(path, manifest)
    return manifest


def _git(root: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    ).stdout.strip()
