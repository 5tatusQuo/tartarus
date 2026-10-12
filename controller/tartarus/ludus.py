from __future__ import annotations

import json
import os
import shutil
import subprocess
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from .errors import TartarusError


@dataclass(frozen=True)
class CommandResult:
    args: tuple[str, ...]
    stdout: str
    stderr: str
    returncode: int


def authenticated_user(config: Path | None = None) -> str:
    result = run_ludus(("users", "list", "--json"), config=config, timeout=30)
    try:
        users = json.loads(result.stdout)
        identifiers = [item["userID"] for item in users if isinstance(item, dict)]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise TartarusError("could not resolve the authenticated Ludus user") from exc
    if len(identifiers) != 1:
        raise TartarusError("expected exactly one authenticated Ludus user")
    return identifiers[0]


def run_ludus(
    arguments: Iterable[str],
    *,
    config: Path | None = None,
    timeout: int = 120,
    sensitive: bool = False,
) -> CommandResult:
    executable = shutil.which("ludus")
    if not executable:
        raise TartarusError("ludus CLI was not found on PATH")
    args = (executable, *tuple(arguments))
    environment = os.environ.copy()
    if config:
        environment["LUDUS_CONFIG"] = str(config)
    try:
        completed = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=environment,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise TartarusError(f"ludus command timed out after {timeout}s") from exc
    result = CommandResult(args, completed.stdout, completed.stderr, completed.returncode)
    if completed.returncode:
        detail = (
            "sensitive command failed; output redacted"
            if sensitive
            else (completed.stderr or completed.stdout or "unknown error").strip()
        )
        raise TartarusError(f"ludus command failed ({completed.returncode}): {detail}")
    return result
