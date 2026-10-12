from __future__ import annotations

import json
import re
import sys
import tomllib
import urllib.request
from pathlib import Path

import yaml
from jsonschema import Draft7Validator, Draft202012Validator

ROOT = Path(__file__).parents[1]


def main() -> int:
    for path in ROOT.rglob("*.yml"):
        if any(part.startswith(".") for part in path.relative_to(ROOT).parts):
            continue
        yaml.safe_load(path.read_text(encoding="utf-8"))
    for path in (ROOT / "schemas").glob("*.json"):
        Draft202012Validator.check_schema(json.loads(path.read_text(encoding="utf-8")))
    with urllib.request.urlopen(
        "https://docs.ludus.cloud/schemas/range-config.json", timeout=30
    ) as response:
        ludus_schema = json.load(response)
    for path in (ROOT / "blueprints").glob("*/range-config.yml"):
        errors = list(
            Draft7Validator(ludus_schema).iter_errors(
                yaml.safe_load(path.read_text(encoding="utf-8"))
            )
        )
        if errors:
            raise ValueError(f"{path}: {errors[0].message}")
    lock = yaml.safe_load((ROOT / "versions.lock.yml").read_text(encoding="utf-8"))
    for name, image in lock["images"].items():
        packer = next((ROOT / "templates" / name.removesuffix("-template")).glob("*.pkr.hcl"))
        text = packer.read_text(encoding="utf-8")
        if f"{image['algorithm']}:{image['digest']}" not in text:
            raise ValueError(f"{packer}: ISO input differs from versions.lock.yml")
        matches = [item for item in lock["artifacts"] if item["url"] == image["url"]]
        if len(matches) != 1 or matches[0]["digest"] != image["digest"]:
            raise ValueError(f"{name}: ISO is not included in the offline artifact lock")
    requirements = (ROOT / "requirements.lock").read_text(encoding="utf-8")
    if "--hash=sha256:" not in requirements:
        raise ValueError("requirements.lock does not contain package hashes")
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    if any("==" not in item for item in project["project"]["dependencies"]):
        raise ValueError("controller direct dependencies must be exact pins")
    home_pattern = "/" + "Users" + r"/[^/\s]+"
    forbidden = re.compile(
        r"(?:BEGIN [A-Z ]*PRIVATE KEY|"
        + home_pattern
        + r"|(?:api[_ -]?key|token)\s*[:=]\s*[A-Za-z0-9+/]{16,})",
        re.IGNORECASE,
    )
    excluded = {"Ludus-Connection-Guide.md", "COMPACT-REFERENCE-PLAN.md", "PORTABLE-PUBLIC-PLAN.md"}
    for path in ROOT.rglob("*"):
        if (
            not path.is_file()
            or path.name in excluded
            or ".git" in path.parts
            or ".tartarus" in path.parts
            or ".venv" in path.parts
        ):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if forbidden.search(text):
            raise ValueError(f"potential local identity or secret in {path}")
    print("repository validation passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
