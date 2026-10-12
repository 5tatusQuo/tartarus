from __future__ import annotations

import ipaddress
import json
import os
import tomllib
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from platformdirs import user_cache_path, user_config_path, user_data_path

from .errors import TartarusError

PROFILES = {"compact", "standard", "large"}
REMOTE_TRANSPORTS = {"ssh", "proxmox-agent"}


def default_config_path() -> Path:
    return Path(os.environ.get("TARTARUS_CONFIG", user_config_path("tartarus") / "config.toml"))


@dataclass(frozen=True)
class Config:
    profile: str = "compact"
    evidence_root: Path = field(default_factory=lambda: user_data_path("tartarus") / "evidence")
    cache_root: Path = field(default_factory=lambda: user_cache_path("tartarus"))
    ludus_config: Path | None = None
    proxmox_url: str | None = None
    proxmox_ca_file: Path | None = None
    proxmox_tls_verify: bool = True
    remote_transport: str = "ssh"
    management_sources: tuple[str, ...] = ()
    always_blocked_networks: tuple[str, ...] = ()
    memory_reserve_percent: int = 15
    datastore_reserve_percent: int = 20
    artifact_quota_gib: int = 20
    host_memory_gib: float | None = None
    telemetry_retention_days: int = 14
    manifest_retention_days: int = 30

    def validate(self) -> None:
        if self.profile not in PROFILES:
            raise TartarusError(f"unsupported profile: {self.profile}")
        for label, networks in (
            ("management_sources", self.management_sources),
            ("always_blocked_networks", self.always_blocked_networks),
        ):
            for network in networks:
                try:
                    ipaddress.ip_network(network, strict=True)
                except ValueError as exc:
                    raise TartarusError(f"invalid CIDR in {label}: {network}") from exc
        management = [ipaddress.ip_network(value) for value in self.management_sources]
        blocked = [ipaddress.ip_network(value) for value in self.always_blocked_networks]
        if any(left.overlaps(right) for left in management for right in blocked):
            raise TartarusError("management and always-blocked networks must not overlap")
        if not self.management_sources:
            raise TartarusError("at least one management source CIDR is required")
        if not self.always_blocked_networks:
            raise TartarusError("at least one always-blocked infrastructure CIDR is required")
        if not 1 <= self.memory_reserve_percent <= 90:
            raise TartarusError("memory reserve must be between 1 and 90 percent")
        if not 1 <= self.datastore_reserve_percent <= 90:
            raise TartarusError("datastore reserve must be between 1 and 90 percent")
        if self.artifact_quota_gib < 1:
            raise TartarusError("artifact quota must be positive")
        if self.host_memory_gib is not None and self.host_memory_gib <= 0:
            raise TartarusError("host memory must be positive")
        if self.telemetry_retention_days < 1 or self.manifest_retention_days < 1:
            raise TartarusError("retention periods must be positive")
        if self.proxmox_url and not self.proxmox_url.startswith("https://"):
            raise TartarusError("Proxmox URL must use HTTPS")
        if self.remote_transport not in REMOTE_TRANSPORTS:
            raise TartarusError(f"unsupported remote transport: {self.remote_transport}")
        if self.remote_transport == "proxmox-agent" and not self.proxmox_url:
            raise TartarusError("the Proxmox agent transport requires proxmox_url")
        if self.proxmox_ca_file and not self.proxmox_ca_file.is_file():
            raise TartarusError("Proxmox CA file does not exist")

    def public_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["evidence_root"] = str(self.evidence_root)
        value["cache_root"] = str(self.cache_root)
        value["ludus_config"] = str(self.ludus_config) if self.ludus_config else None
        value["proxmox_ca_file"] = str(self.proxmox_ca_file) if self.proxmox_ca_file else None
        return value


def load_config(path: Path | None = None) -> Config:
    config_path = path or default_config_path()
    try:
        raw = tomllib.loads(config_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise TartarusError(f"configuration not found: {config_path}; run 'tartarus init'") from exc
    except tomllib.TOMLDecodeError as exc:
        raise TartarusError(f"invalid configuration {config_path}: {exc}") from exc
    overrides = {
        "evidence_root": os.environ.get("TARTARUS_EVIDENCE_ROOT"),
        "cache_root": os.environ.get("TARTARUS_CACHE_ROOT"),
        "ludus_config": os.environ.get("TARTARUS_LUDUS_CONFIG"),
    }
    for key, value in overrides.items():
        if value:
            raw[key] = value
    allowed = set(Config.__dataclass_fields__)
    unknown = set(raw) - allowed
    if unknown:
        raise TartarusError(f"unknown configuration keys: {', '.join(sorted(unknown))}")
    for key in ("evidence_root", "cache_root", "ludus_config", "proxmox_ca_file"):
        if raw.get(key) is not None:
            raw[key] = Path(raw[key]).expanduser()
    for key in ("management_sources", "always_blocked_networks"):
        if key in raw:
            raw[key] = tuple(raw[key])
    config = Config(**raw)
    config.validate()
    return config


def save_config(config: Config, path: Path | None = None) -> Path:
    config.validate()
    config_path = path or default_config_path()
    config_path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        f"profile = {json.dumps(config.profile)}",
        f"evidence_root = {json.dumps(str(config.evidence_root))}",
        f"cache_root = {json.dumps(str(config.cache_root))}",
    ]
    if config.ludus_config:
        lines.append(f"ludus_config = {json.dumps(str(config.ludus_config))}")
    if config.proxmox_url:
        lines.append(f"proxmox_url = {json.dumps(config.proxmox_url)}")
    if config.proxmox_ca_file:
        lines.append(f"proxmox_ca_file = {json.dumps(str(config.proxmox_ca_file))}")
    lines.append(f"proxmox_tls_verify = {str(config.proxmox_tls_verify).lower()}")
    lines.append(f"remote_transport = {json.dumps(config.remote_transport)}")
    for key, values in (
        ("management_sources", config.management_sources),
        ("always_blocked_networks", config.always_blocked_networks),
    ):
        rendered = ", ".join(json.dumps(item) for item in values)
        lines.append(f"{key} = [{rendered}]")
    lines.extend(
        [
            f"memory_reserve_percent = {config.memory_reserve_percent}",
            f"datastore_reserve_percent = {config.datastore_reserve_percent}",
            f"artifact_quota_gib = {config.artifact_quota_gib}",
        ]
    )
    if config.host_memory_gib is not None:
        lines.append(f"host_memory_gib = {config.host_memory_gib}")
    lines.append(f"telemetry_retention_days = {config.telemetry_retention_days}")
    lines.append(f"manifest_retention_days = {config.manifest_retention_days}")
    temporary = config_path.with_name(f".{config_path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, config_path)
    finally:
        temporary.unlink(missing_ok=True)
    return config_path
