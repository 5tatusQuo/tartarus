from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

import yaml

from .config import Config
from .errors import TartarusError
from .ludus import run_ludus
from .proxmox_agent import ProxmoxGuestAgent


@dataclass(frozen=True)
class Guest:
    name: str
    address: str
    user: str
    password: str | None
    vmid: int
    node: str = "ludus"


def range_guests(config: Config, range_id: str) -> dict[str, Guest]:
    result = run_ludus(("--range", range_id, "range", "inventory"), config=config.ludus_config)
    try:
        lines = result.stdout.splitlines()
        document_start = next(index for index, line in enumerate(lines) if line == "all:")
        inventory = yaml.safe_load("\n".join(lines[document_start:]))
        hosts = inventory["all"]["children"][range_id]["hosts"]
    except (KeyError, StopIteration, TypeError, yaml.YAMLError) as exc:
        raise TartarusError(f"could not parse inventory for range {range_id}") from exc
    roles = {"elk": "-elk-01", "remnux": "-remnux-01", "sandbox": "-linux-sbx-01"}
    guests: dict[str, Guest] = {}
    for role, suffix in roles.items():
        matches = [(name, values) for name, values in hosts.items() if name.endswith(suffix)]
        if len(matches) != 1:
            raise TartarusError(f"expected exactly one {role} guest in range {range_id}")
        name, values = matches[0]
        address = values.get("ansible_host")
        user = values.get("ludus_template_user") or values.get("ansible_user")
        password = values.get("ludus_template_password")
        if not isinstance(address, str) or not isinstance(user, str):
            raise TartarusError(f"{role} guest is not running or lacks SSH inventory data")
        vmid = values.get("proxmox_vmid")
        if not isinstance(vmid, int):
            raise TartarusError(f"{role} guest lacks a Proxmox VM ID")
        node = values.get("proxmox_node", "ludus")
        if not isinstance(node, str):
            raise TartarusError(f"{role} guest lacks a Proxmox node")
        guests[role] = Guest(
            name,
            address,
            user,
            password if isinstance(password, str) else None,
            vmid,
            node,
        )
    return guests


class Remote:
    def __init__(self, config: Config, guest: Guest):
        self.config = config
        self.guest = guest
        self.known_hosts = config.cache_root / "ssh" / "known_hosts"
        self.known_hosts.parent.mkdir(parents=True, exist_ok=True)
        self.known_hosts.touch(mode=0o600, exist_ok=True)
        self.known_hosts.chmod(0o600)
        self.agent = (
            ProxmoxGuestAgent(
                config,
                node=guest.node,
                vmid=guest.vmid,
                name=guest.name,
            )
            if config.remote_transport == "proxmox-agent"
            else None
        )

    def run(
        self, command: tuple[str, ...], *, sudo: bool = False, timeout: int = 120
    ) -> subprocess.CompletedProcess[str]:
        if self.agent:
            completed = self.agent.run(command, timeout=timeout)
            if completed.returncode:
                detail = completed.stderr.strip() or "remote command failed"
                raise TartarusError(f"remote operation failed on {self.guest.name}: {detail}")
            return completed
        remote_command = " ".join(shlex.quote(part) for part in command)
        input_text = None
        if sudo:
            if not self._controller_key().is_file():
                raise TartarusError(f"controller key is unavailable for {self.guest.name}")
            remote_command = "sudo -n -- " + remote_command
        return self._execute(
            [*self._ssh_base(), f"{self.guest.user}@{self.guest.address}", remote_command],
            input_text=input_text,
            timeout=timeout,
        )

    def push(self, source: Path, destination: str, timeout: int = 120) -> None:
        if self.agent:
            self.agent.push(source, destination, timeout=timeout)
            return
        self._execute(
            [
                *self._scp_base(),
                str(source),
                f"{self.guest.user}@{self.guest.address}:{destination}",
            ],
            timeout=timeout,
        )

    def pull(self, source: str, destination: Path, timeout: int = 300) -> None:
        if self.agent:
            self.agent.pull(source, destination, timeout=timeout)
            return
        destination.parent.mkdir(parents=True, exist_ok=True)
        self._execute(
            [
                *self._scp_base(),
                f"{self.guest.user}@{self.guest.address}:{source}",
                str(destination),
            ],
            timeout=timeout,
        )

    def streaming_command(self, command: tuple[str, ...]) -> list[str]:
        """Build an SSH command for a long-lived standard-I/O service."""
        if not self._controller_key().is_file():
            raise TartarusError(f"controller key is unavailable for {self.guest.name}")
        remote_command = "exec " + " ".join(shlex.quote(part) for part in command)
        return [
            *self._ssh_base(),
            f"{self.guest.user}@{self.guest.address}",
            remote_command,
        ]

    def _ssh_base(self) -> list[str]:
        executable = shutil.which("ssh")
        if not executable:
            raise TartarusError("ssh client was not found on PATH")
        return [executable, *self._connection_options()]

    def _scp_base(self) -> list[str]:
        executable = shutil.which("scp")
        if not executable:
            raise TartarusError("scp client was not found on PATH")
        return [executable, *self._connection_options()]

    def _connection_options(self) -> list[str]:
        options = [
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            f"UserKnownHostsFile={self.known_hosts}",
            "-o",
            "ConnectTimeout=15",
            "-o",
            "IdentitiesOnly=yes",
        ]
        controller_key = self._controller_key()
        if controller_key.is_file():
            options.extend(["-i", str(controller_key)])
        return options

    def _controller_key(self) -> Path:
        return self.config.cache_root / "secrets" / "controller_ed25519"

    def _execute(
        self, args: list[str], *, input_text: str | None = None, timeout: int
    ) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        temporary: Path | None = None
        if self.guest.password and not self._controller_key().is_file():
            descriptor, name = tempfile.mkstemp(prefix="tartarus-askpass-")
            temporary = Path(name)
            os.write(descriptor, b"#!/bin/sh\nexec printenv TARTARUS_SSH_PASSWORD\n")
            os.close(descriptor)
            temporary.chmod(0o700)
            environment.update(
                {
                    "SSH_ASKPASS": str(temporary),
                    "SSH_ASKPASS_REQUIRE": "force",
                    "TARTARUS_SSH_PASSWORD": self.guest.password,
                    "DISPLAY": environment.get("DISPLAY", "tartarus:0"),
                }
            )
        try:
            completed = subprocess.run(
                args,
                input=input_text,
                capture_output=True,
                text=True,
                env=environment,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise TartarusError(f"remote operation timed out on {self.guest.name}") from exc
        finally:
            if temporary:
                temporary.unlink(missing_ok=True)
        if completed.returncode:
            detail = completed.stderr.strip() or "remote command failed"
            raise TartarusError(f"remote operation failed on {self.guest.name}: {detail}")
        return completed
