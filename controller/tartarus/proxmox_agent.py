from __future__ import annotations

import base64
import json
import shlex
import ssl
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any

from .config import Config
from .errors import TartarusError
from .ludus import run_ludus


class ProxmoxGuestAgent:
    """Bounded command and file transport through the Proxmox QEMU guest agent."""

    _chunk_size = 32 * 1024

    def __init__(self, config: Config, *, node: str, vmid: int, name: str):
        if not config.proxmox_url:
            raise TartarusError("Proxmox guest-agent transport requires proxmox_url")
        self.config = config
        self.node = node
        self.vmid = vmid
        self.name = name
        self.base = config.proxmox_url.rstrip("/") + "/api2/json"
        if config.proxmox_tls_verify:
            self.context = ssl.create_default_context(
                cafile=str(config.proxmox_ca_file) if config.proxmox_ca_file else None
            )
        else:
            self.context = ssl._create_unverified_context()
        self.headers = self._authenticate()

    def run(self, command: tuple[str, ...], *, timeout: int) -> subprocess.CompletedProcess[str]:
        if not command:
            raise TartarusError("guest-agent command cannot be empty")
        shell_command = (
            "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; exec "
            + shlex.join(command)
        )
        fields = [("command", item) for item in ("/bin/sh", "-c", shell_command)]
        started = self._request("POST", "agent/exec", fields=fields, timeout=15)
        try:
            pid = int(started["pid"])
        except (KeyError, TypeError, ValueError) as exc:
            raise TartarusError(f"guest-agent execution did not start on {self.name}") from exc
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            status = self._request(
                "GET", "agent/exec-status", fields=[("pid", str(pid))], timeout=15
            )
            if status.get("exited") == 1:
                stdout = status.get("out-data") or ""
                stderr = status.get("err-data") or ""
                if status.get("out-truncated"):
                    raise TartarusError(f"guest-agent stdout was truncated on {self.name}")
                if status.get("err-truncated"):
                    raise TartarusError(f"guest-agent stderr was truncated on {self.name}")
                return subprocess.CompletedProcess(
                    command,
                    int(status.get("exitcode", 1)),
                    stdout,
                    stderr,
                )
            time.sleep(0.5)
        raise TartarusError(f"remote operation timed out on {self.name}")

    def push(self, source: Path, destination: str, *, timeout: int) -> None:
        identifier = uuid.uuid4().hex
        prefix = f"/tmp/.tartarus-upload-{identifier}"
        deadline = time.monotonic() + timeout
        try:
            with source.open("rb") as handle:
                index = 0
                while chunk := handle.read(self._chunk_size):
                    if time.monotonic() >= deadline:
                        raise TartarusError(f"remote operation timed out on {self.name}")
                    self._file_write(
                        f"{prefix}.{index:06d}", base64.b64encode(chunk).decode("ascii")
                    )
                    index += 1
            quoted_destination = shlex.quote(destination)
            quoted_prefix = shlex.quote(prefix) + ".*"
            command = (
                f": > {quoted_destination}; "
                f'for part in {quoted_prefix}; do base64 -d "$part" >> {quoted_destination}; '
                'rm -f "$part"; done'
            )
            result = self.run(
                ("/bin/sh", "-c", command), timeout=max(1, int(deadline - time.monotonic()))
            )
            self._ensure_success(result)
        except Exception:
            self.run(("/bin/sh", "-c", f"rm -f {shlex.quote(prefix)}.*"), timeout=30)
            raise

    def pull(self, source: str, destination: Path, *, timeout: int) -> None:
        size_result = self.run(("stat", "-c", "%s", source), timeout=min(timeout, 30))
        self._ensure_success(size_result)
        try:
            size = int(size_result.stdout.strip())
        except ValueError as exc:
            raise TartarusError(f"could not determine remote file size on {self.name}") from exc
        identifier = uuid.uuid4().hex
        temporary = f"/tmp/.tartarus-pull-{identifier}"
        deadline = time.monotonic() + timeout
        destination.parent.mkdir(parents=True, exist_ok=True)
        try:
            with destination.open("wb") as handle:
                for index, _offset in enumerate(range(0, size, self._chunk_size)):
                    remaining = max(1, int(deadline - time.monotonic()))
                    command = (
                        f"dd if={shlex.quote(source)} bs={self._chunk_size} skip={index} count=1 "
                        f"2>/dev/null | base64 -w0 > {shlex.quote(temporary)}"
                    )
                    result = self.run(("/bin/sh", "-c", command), timeout=remaining)
                    self._ensure_success(result)
                    encoded = self._file_read(temporary)
                    try:
                        handle.write(base64.b64decode(encoded, validate=True))
                    except ValueError as exc:
                        raise TartarusError(
                            f"guest-agent returned invalid file data from {self.name}"
                        ) from exc
            if destination.stat().st_size != size:
                raise TartarusError(
                    f"guest-agent file size changed during transfer from {self.name}"
                )
        finally:
            self.run(("rm", "-f", temporary), timeout=30)

    def _authenticate(self) -> dict[str, str]:
        output = run_ludus(
            ("users", "creds", "get", "--json"),
            config=self.config.ludus_config,
            timeout=30,
            sensitive=True,
        ).stdout
        try:
            credentials = json.loads(output)["result"]
            username = f"{credentials['proxmoxUsername']}@{credentials['proxmoxRealm']}"
            password = credentials["proxmoxPassword"]
            auth = self._raw_request(
                "POST",
                "/access/ticket",
                fields=[("username", username), ("password", password)],
                timeout=15,
                headers={},
            )
            return {
                "Cookie": "PVEAuthCookie=" + auth["ticket"],
                "CSRFPreventionToken": auth["CSRFPreventionToken"],
            }
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise TartarusError("Proxmox authentication failed; credentials were redacted") from exc

    def _request(
        self,
        method: str,
        action: str,
        *,
        fields: list[tuple[str, str]] | None = None,
        timeout: int,
    ) -> Any:
        node = urllib.parse.quote(self.node, safe="")
        return self._raw_request(
            method,
            f"/nodes/{node}/qemu/{self.vmid}/{action}",
            fields=fields,
            timeout=timeout,
            headers=self.headers,
        )

    def _raw_request(
        self,
        method: str,
        path: str,
        *,
        fields: list[tuple[str, str]] | None,
        timeout: int,
        headers: dict[str, str],
    ) -> Any:
        encoded = urllib.parse.urlencode(fields or [], doseq=True)
        url = self.base + path
        data = None
        if method == "GET" and encoded:
            url += "?" + encoded
        elif method != "GET":
            data = encoded.encode()
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, context=self.context, timeout=timeout) as response:
                payload = json.loads(response.read())
            return payload["data"]
        except (OSError, urllib.error.URLError, KeyError, json.JSONDecodeError) as exc:
            raise TartarusError(
                f"Proxmox guest-agent request failed on {self.name}; credentials were redacted"
            ) from exc

    def _file_write(self, path: str, content: str) -> None:
        self._request(
            "POST",
            "agent/file-write",
            fields=[("file", path), ("content", content)],
            timeout=30,
        )

    def _file_read(self, path: str) -> str:
        value = self._request("GET", "agent/file-read", fields=[("file", path)], timeout=30)
        content = value.get("content") if isinstance(value, dict) else None
        if not isinstance(content, str):
            raise TartarusError(f"guest-agent could not read a file on {self.name}")
        return content

    def _ensure_success(self, result: subprocess.CompletedProcess[str]) -> None:
        if result.returncode:
            detail = result.stderr.strip() or "remote command failed"
            raise TartarusError(f"remote operation failed on {self.name}: {detail}")
