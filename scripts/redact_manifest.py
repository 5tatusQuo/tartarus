from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

REDACTED_KEYS = {
    "address",
    "accessible_ranges",
    "authenticated_user",
    "local_addresses",
    "nodes",
    "pools",
    "range_id",
    "server_config",
}


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: "<redacted>" if key in REDACTED_KEYS else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    document = json.loads(args.source.read_text(encoding="utf-8"))
    args.destination.parent.mkdir(parents=True, exist_ok=True)
    args.destination.write_text(json.dumps(redact(document), indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
