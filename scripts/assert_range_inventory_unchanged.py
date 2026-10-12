from __future__ import annotations

import argparse
import json
from pathlib import Path


def range_ids(path: Path) -> set[str]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, list):
        raise TypeError(f"expected a JSON range list in {path}")
    return {
        item["rangeID"]
        for item in value
        if isinstance(item, dict) and isinstance(item.get("rangeID"), str)
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("before", type=Path)
    parser.add_argument("after", type=Path)
    args = parser.parse_args()
    before = range_ids(args.before)
    after = range_ids(args.after)
    if before != after:
        raise SystemExit(
            f"unrelated range inventory changed: before={sorted(before)} after={sorted(after)}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
