from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from .config import Config
from .errors import TartarusError


def ensure_controller_ssh_key(config: Config) -> tuple[Path, str]:
    secret_root = config.cache_root / "secrets"
    secret_root.mkdir(parents=True, exist_ok=True)
    secret_root.chmod(0o700)
    private_key = secret_root / "controller_ed25519"
    public_key = private_key.with_suffix(".pub")
    if not private_key.is_file() or not public_key.is_file():
        executable = shutil.which("ssh-keygen")
        if not executable:
            raise TartarusError("ssh-keygen was not found on PATH")
        completed = subprocess.run(
            [
                executable,
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                "tartarus-controller",
                "-f",
                str(private_key),
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        if completed.returncode:
            raise TartarusError("failed to generate the controller SSH key")
    private_key.chmod(0o600)
    public = public_key.read_text(encoding="utf-8").strip()
    if not public.startswith("ssh-ed25519 "):
        raise TartarusError("controller SSH public key is invalid")
    return private_key, public
