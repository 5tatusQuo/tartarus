from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from .config import Config
from .errors import TartarusError
from .ludus import run_ludus


def inspect_proxmox(config: Config) -> dict[str, Any] | None:
    if not config.proxmox_url:
        return None
    credentials_output = run_ludus(
        ("users", "creds", "get", "--json"),
        config=config.ludus_config,
        timeout=30,
        sensitive=True,
    ).stdout
    try:
        result = json.loads(credentials_output)["result"]
        username = f"{result['proxmoxUsername']}@{result['proxmoxRealm']}"
        password = result["proxmoxPassword"]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise TartarusError(
            "Ludus returned invalid Proxmox credentials; values were redacted"
        ) from exc
    context = (
        ssl.create_default_context(
            cafile=str(config.proxmox_ca_file) if config.proxmox_ca_file else None
        )
        if config.proxmox_tls_verify
        else ssl._create_unverified_context()
    )
    base = config.proxmox_url.rstrip("/") + "/api2/json"
    login = urllib.request.Request(
        base + "/access/ticket",
        data=urllib.parse.urlencode({"username": username, "password": password}).encode(),
        method="POST",
    )
    try:
        with urllib.request.urlopen(login, context=context, timeout=15) as response:
            auth = json.loads(response.read())["data"]
        headers = {
            "Cookie": "PVEAuthCookie=" + auth["ticket"],
            "CSRFPreventionToken": auth["CSRFPreventionToken"],
        }
        nodes = _get(base + "/nodes", headers, context)
        observed = []
        for node in nodes:
            encoded_node = urllib.parse.quote(node["node"])
            status = _get(base + f"/nodes/{encoded_node}/status", headers, context)
            history = _get(
                base + f"/nodes/{encoded_node}/rrddata?timeframe=hour&cf=AVERAGE",
                headers,
                context,
            )
            recent_swap = [
                float(item["swapused"])
                for item in history
                if isinstance(item, dict) and isinstance(item.get("swapused"), int | float)
            ][-5:]
            swap_growth = (
                max(0, int(recent_swap[-1] - recent_swap[0]))
                if len(recent_swap) >= 2
                else None
            )
            observed.append(
                {
                    "node": node["node"],
                    "memory_total_bytes": status["memory"]["total"],
                    "memory_free_bytes": status["memory"]["free"],
                    "swap_used_bytes": status["swap"]["used"],
                    "recent_swap_growth_bytes": swap_growth,
                    "cpu_usage": status["cpu"],
                }
            )
    except (OSError, urllib.error.URLError, KeyError, json.JSONDecodeError) as exc:
        raise TartarusError("Proxmox discovery failed; credentials were redacted") from exc
    return {"nodes": observed}


def _get(url: str, headers: dict[str, str], context: ssl.SSLContext) -> Any:
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, context=context, timeout=15) as response:
        return json.loads(response.read())["data"]
