from __future__ import annotations

import ipaddress
import json
import re
import shutil
import socket
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import yaml

from .artifacts import locked_artifacts
from .config import Config
from .errors import TartarusError
from .ludus import authenticated_user, run_ludus
from .manifest import project_root, validate
from .proxmox import inspect_proxmox
from .util import digest_file, utc_now

PROFILE_MEMORY = {"compact": 16, "standard": 32, "large": 64}
PROFILE_LOGICAL_CPUS = {"compact": 16, "standard": 16, "large": 20}
PROFILE_STORAGE_GIB = {"compact": 220, "standard": 240, "large": 300}
MINIMUM_LUDUS = (2, 3, 7)


def _json_output(output: str) -> Any:
    for line in reversed(output.splitlines()):
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            continue
    raise TartarusError("command returned no valid JSON")


def _version_tuple(value: str) -> tuple[int, int, int]:
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", value)
    if not match:
        raise TartarusError("could not parse Ludus version")
    return tuple(int(part) for part in match.groups())


def inspect_environment(config: Config, host_memory_gib: float | None = None) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    proxmox = None
    if config.proxmox_url:
        try:
            proxmox = inspect_proxmox(config)
            nodes = proxmox["nodes"] if proxmox else []
            checks.append(
                {
                    "name": "proxmox_api",
                    "status": "pass" if nodes else "fail",
                    "nodes": nodes,
                }
            )
            if nodes:
                if host_memory_gib is None and config.host_memory_gib is None:
                    host_memory_gib = max(
                        node["memory_total_bytes"] for node in nodes
                    ) / 1024**3
                growth_values = [node.get("recent_swap_growth_bytes") for node in nodes]
                swap_stable = all(
                    value is not None and value <= 64 * 1024**2 for value in growth_values
                )
                checks.append(
                    {
                        "name": "host_swap",
                        "status": "pass" if swap_stable else "fail",
                        "observed_used_bytes": sum(node["swap_used_bytes"] for node in nodes),
                        "recent_growth_bytes": sum(value or 0 for value in growth_values),
                        "criterion": "no sustained swap growth across recent RRD samples",
                    }
                )
        except TartarusError as exc:
            checks.append({"name": "proxmox_api", "status": "fail", "detail": str(exc)})
    try:
        result = run_ludus(("version", "--json"), config=config.ludus_config, timeout=15)
        version = _json_output(result.stdout)
        client = version.get("version", "")
        server = version.get("result", "")
        compatible = (
            _version_tuple(client) >= MINIMUM_LUDUS and _version_tuple(server) >= MINIMUM_LUDUS
        )
        checks.append(
            {
                "name": "ludus_compatibility",
                "status": "pass" if compatible else "fail",
                "client": client,
                "server": server,
            }
        )
    except TartarusError as exc:
        checks.append({"name": "ludus_compatibility", "status": "fail", "detail": str(exc)})

    try:
        user = authenticated_user(config.ludus_config)
        ranges = _json_output(
            run_ludus(("range", "accessible", "--json"), config=config.ludus_config).stdout
        )
        checks.append(
            {
                "name": "ludus_identity_and_ranges",
                "status": "pass",
                "authenticated_user": user,
                "accessible_ranges": ranges,
            }
        )
    except TartarusError as exc:
        checks.append({"name": "ludus_identity_and_ranges", "status": "fail", "detail": str(exc)})

    try:
        diagnostics = _json_output(
            run_ludus(("diagnostics", "--json"), config=config.ludus_config, timeout=30).stdout
        )
        cores = diagnostics.get("cpu", {}).get("cores", 0)
        checks.append(
            {
                "name": "host_cpu",
                "status": "pass" if cores >= PROFILE_LOGICAL_CPUS[config.profile] else "fail",
                "observed_logical_cpus": cores,
                "required_logical_cpus": PROFILE_LOGICAL_CPUS[config.profile],
            }
        )
        pools = diagnostics.get("storage_pools", [])
        storage_ok = any(
            pool.get("free_percentage", 0) >= config.datastore_reserve_percent
            and pool.get("free_gb", 0) >= PROFILE_STORAGE_GIB[config.profile]
            for pool in pools
        )
        checks.append(
            {
                "name": "host_datastore_reserve",
                "status": "pass" if storage_ok else "fail",
                "required_free_percent": config.datastore_reserve_percent,
                "required_free_gib": PROFILE_STORAGE_GIB[config.profile],
                "pools": [
                    {
                        "name": pool.get("name"),
                        "free_gb": pool.get("free_gb"),
                        "free_percentage": pool.get("free_percentage"),
                    }
                    for pool in pools
                ],
            }
        )
    except TartarusError as exc:
        checks.append({"name": "host_diagnostics", "status": "fail", "detail": str(exc)})

    disk = shutil.disk_usage(_existing_parent(config.evidence_root))
    quota = config.artifact_quota_gib * 1024**3
    checks.append(
        {
            "name": "evidence_capacity",
            "status": "pass" if disk.free >= quota else "fail",
            "free_bytes": disk.free,
            "required_bytes": quota,
        }
    )
    cache_disk = shutil.disk_usage(_existing_parent(config.cache_root))
    cache_required = 8 * 1024**3
    checks.append(
        {
            "name": "preparation_cache_capacity",
            "status": "pass" if cache_disk.free >= cache_required else "fail",
            "free_bytes": cache_disk.free,
            "required_bytes": cache_required,
        }
    )
    minimum = PROFILE_MEMORY[config.profile]
    host_memory_gib = host_memory_gib or config.host_memory_gib
    if host_memory_gib is None:
        checks.append(
            {
                "name": "host_memory",
                "status": "unknown",
                "detail": "supply --host-memory-gib because this Ludus edition does not expose host RAM",
                "required_gib": minimum,
            }
        )
    else:
        reserve_adjusted = host_memory_gib * (1 - config.memory_reserve_percent / 100)
        guest_ram = {"compact": 12, "standard": 20, "large": 46}[config.profile]
        checks.append(
            {
                "name": "host_memory",
                "status": "pass"
                if host_memory_gib >= minimum and reserve_adjusted >= guest_ram
                else "fail",
                "observed_gib": host_memory_gib,
                "required_gib": minimum,
                "guest_ram_gib": guest_ram,
                "reserve_percent": config.memory_reserve_percent,
                "source": "operator-supplied",
            }
        )

    try:
        templates = _json_output(
            run_ludus(("templates", "list", "--json"), config=config.ludus_config).stdout
        )
        required = {"tartarus-debian-12-template"}
        built = {item.get("name") for item in templates if item.get("built") is True}
        missing = sorted(required - built)
        checks.append(
            {
                "name": "tartarus_templates",
                "status": "pass" if not missing else "not_prepared",
                "missing": missing,
            }
        )
    except TartarusError as exc:
        checks.append({"name": "tartarus_templates", "status": "fail", "detail": str(exc)})

    try:
        sources = run_ludus(("source", "list", "--json"), config=config.ludus_config).stdout
        blueprints = run_ludus(("blueprint", "list", "--json"), config=config.ludus_config).stdout
        expected_blueprint = f"tartarus/tartarus-{config.profile}"
        prepared = "tartarus" in sources and expected_blueprint in blueprints
        checks.append(
            {
                "name": "tartarus_source",
                "status": "pass" if prepared else "not_prepared",
                "required_blueprint": expected_blueprint,
            }
        )
    except TartarusError as exc:
        checks.append({"name": "tartarus_source", "status": "fail", "detail": str(exc)})

    for name, command in (
        ("ansible_roles", ("ansible", "role", "list", "--json")),
        ("ansible_collections", ("ansible", "collection", "list", "--json")),
    ):
        try:
            inventory = _json_output(run_ludus(command, config=config.ludus_config).stdout)
            checks.append({"name": name, "status": "pass", "inventory": inventory})
        except TartarusError as exc:
            checks.append({"name": name, "status": "fail", "detail": str(exc)})

    dependencies_input: list[dict[str, Any]] = list(locked_artifacts())
    lock = yaml.safe_load((project_root() / "versions.lock.yml").read_text(encoding="utf-8"))
    artifact_urls = {item["url"] for item in dependencies_input}
    dependencies_input.extend(
        {"filename": name, **details}
        for name, details in lock["images"].items()
        if details["url"] not in artifact_urls
    )
    with ThreadPoolExecutor(max_workers=4) as executor:
        dependencies = list(
            executor.map(
                lambda item: _dependency_status(config.cache_root, item), dependencies_input
            )
        )
    checks.append(
        {
            "name": "locked_dependency_availability",
            "status": "pass" if all(item["available"] for item in dependencies) else "fail",
            "dependencies": dependencies,
        }
    )

    local_addresses = _local_addresses()
    conflicts = []
    declared = [ipaddress.ip_network(value) for value in config.always_blocked_networks]
    for address in local_addresses:
        for network in declared:
            if address in network:
                conflicts.append({"address": str(address), "declared_network": str(network)})
    checks.append(
        {
            "name": "controller_address_declarations",
            "status": "pass" if not conflicts else "fail",
            "local_addresses": [str(item) for item in local_addresses],
            "conflicts": conflicts,
            "range_addressing": "allocated by Ludus; blueprints contain VLAN-relative addresses only",
        }
    )

    ready = not any(check["status"] in {"fail", "unknown"} for check in checks)
    report = {
        "schema_version": "1.0",
        "generated_at": utc_now(),
        "profile": config.profile,
        "ready": ready,
        "checks": checks,
    }
    validate("environment-report", report)
    return report


def _existing_parent(path: Path) -> Path:
    candidate = path.expanduser()
    while not candidate.exists() and candidate != candidate.parent:
        candidate = candidate.parent
    return candidate


def _dependency_status(cache_root: Path, item: dict[str, Any]) -> dict[str, Any]:
    cached = cache_root / "artifacts" / item["filename"]
    if cached.is_file() and digest_file(cached, item["algorithm"]) == item["digest"]:
        return {"filename": item["filename"], "available": True, "source": "verified_cache"}
    request = urllib.request.Request(item["url"], method="HEAD")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            available = 200 <= response.status < 400
    except (OSError, urllib.error.URLError):
        available = False
    return {
        "filename": item["filename"],
        "available": available,
        "source": "upstream" if available else "unavailable",
    }


def _local_addresses() -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    addresses: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
    try:
        for item in socket.getaddrinfo(socket.gethostname(), None):
            address = ipaddress.ip_address(item[4][0].split("%")[0])
            if not address.is_loopback:
                addresses.add(address)
    except socket.gaierror:
        pass
    return sorted(addresses, key=lambda value: (value.version, int(value)))
