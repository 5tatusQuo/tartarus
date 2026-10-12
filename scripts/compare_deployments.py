from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def comparable(path: Path) -> dict[str, Any]:
    manifest = json.loads(path.read_text(encoding="utf-8"))
    inputs = manifest["resolved_inputs"]
    guests = manifest.get("deployment", {}).get("guests", {})
    return {
        "schema_version": manifest["schema_version"],
        "tartarus_release": manifest["tartarus_release"],
        "profile": manifest["profile"],
        "source_tree_sha256": inputs["source_tree_sha256"],
        "components": inputs["components"],
        "schemas": inputs["schemas"],
        "policies": inputs["policies"],
        "controller_requirements_sha256": inputs["controller_requirements_sha256"],
        "artifacts": inputs["artifacts"],
        "images": inputs["images"],
        "template_build_identifiers": inputs["template_build_identifiers"],
        "guest_builds": {
            role: {"kernel": guest["kernel"], "packages": guest["packages"]}
            for role, guest in guests.items()
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compare reproducible fields from two Tartarus DeploymentManifests"
    )
    parser.add_argument("first", type=Path)
    parser.add_argument("second", type=Path)
    args = parser.parse_args()
    first = comparable(args.first)
    second = comparable(args.second)
    if first != second:
        raise SystemExit("deployment manifests differ in reproducibility-controlled fields")
    print("deployment manifests are equivalent")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
