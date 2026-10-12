from __future__ import annotations

import base64
import json
import ssl
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from .config import Config
from .errors import TartarusError
from .remote import Remote, range_guests
from .util import atomic_json, load_json


def bootstrap_credentials(config: Config, range_id: str) -> Path:
    guests = range_guests(config, range_id)
    elk = Remote(config, guests["elk"])
    credentials_raw = elk.run(("cat", "/root/tartarus-bootstrap.json"), sudo=True).stdout
    ca_pem = elk.run(("cat", "/etc/elasticsearch/tartarus-tls/ca.crt"), sudo=True).stdout
    try:
        credentials = json.loads(credentials_raw)
    except json.JSONDecodeError as exc:
        raise TartarusError("ELK credential bootstrap is invalid") from exc
    if not all(credentials.get(key) for key in ("elastic_password", "agent_api_key")):
        raise TartarusError("ELK credential bootstrap is incomplete")
    credentials["agent_api_key"] = _normalize_agent_api_key(credentials["agent_api_key"])
    secret_root = config.cache_root / "secrets" / range_id
    secret_root.mkdir(parents=True, exist_ok=True)
    secret_root.chmod(0o700)
    atomic_json(secret_root / "elastic.json", credentials)
    (secret_root / "ca.crt").write_text(ca_pem, encoding="utf-8")
    (secret_root / "ca.crt").chmod(0o600)
    agent_config = secret_root / "elastic-agent.yml"
    agent_config.write_text(
        _agent_configuration(guests["elk"].address, credentials["agent_api_key"]),
        encoding="utf-8",
    )
    agent_config.chmod(0o600)
    for role in ("remnux", "sandbox"):
        remote = Remote(config, guests[role])
        remote.push(secret_root / "ca.crt", "/tmp/tartarus-ca.crt")
        remote.push(agent_config, "/tmp/tartarus-elastic-agent.yml")
        try:
            remote.run(
                (
                    "install",
                    "-o",
                    "root",
                    "-g",
                    "root",
                    "-m",
                    "0644",
                    "/tmp/tartarus-ca.crt",
                    "/etc/elastic-agent/tartarus-ca.crt",
                ),
                sudo=True,
            )
            remote.run(
                (
                    "install",
                    "-o",
                    "root",
                    "-g",
                    "root",
                    "-m",
                    "0600",
                    "/tmp/tartarus-elastic-agent.yml",
                    "/etc/elastic-agent/elastic-agent.yml",
                ),
                sudo=True,
            )
            remote.run(("systemctl", "enable", "elastic-agent"), sudo=True)
            remote.run(("systemctl", "restart", "elastic-agent"), sudo=True)
        finally:
            remote.run(("rm", "-f", "/tmp/tartarus-ca.crt", "/tmp/tartarus-elastic-agent.yml"))
    return secret_root


def _normalize_agent_api_key(value: str) -> str:
    if ":" in value:
        return value
    try:
        decoded = base64.b64decode(value, validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError) as exc:
        raise TartarusError("ELK agent API key has an invalid encoding") from exc
    if ":" not in decoded:
        raise TartarusError("ELK agent API key has an invalid format")
    return decoded


def _agent_configuration(elastic_host: str, api_key: str) -> str:
    return f"""outputs:
  default:
    type: elasticsearch
    hosts: [\"https://{elastic_host}:9200\"]
    api_key: \"{api_key}\"
    ssl.certificate_authorities: [\"/etc/elastic-agent/tartarus-ca.crt\"]
    ssl.verification_mode: certificate
inputs:
  - id: tartarus-journal
    type: journald
    use_output: default
    streams:
      - id: tartarus-journal-stream
        data_stream: {{type: logs, dataset: tartarus.journal, namespace: default}}
  - id: tartarus-audit
    type: logfile
    use_output: default
    streams:
      - id: tartarus-audit-stream
        paths: [/var/log/audit/audit.log]
        data_stream: {{type: logs, dataset: tartarus.audit, namespace: default}}
  - id: tartarus-inetsim
    type: logfile
    use_output: default
    streams:
      - id: tartarus-inetsim-stream
        paths: [/var/log/inetsim/*.log]
        exclude_files: ['\\.gz$']
        data_stream: {{type: logs, dataset: tartarus.inetsim, namespace: default}}
  - id: tartarus-system-metrics
    type: system/metrics
    use_output: default
    streams:
      - id: tartarus-system-stream
        metricsets: [cpu, load, memory, process_summary, filesystem, network]
        period: 30s
        data_stream: {{type: metrics, dataset: tartarus.metrics, namespace: default}}
"""


def elastic_request(
    config: Config,
    range_id: str,
    path: str,
    *,
    method: str = "GET",
    body: dict[str, Any] | None = None,
) -> dict[str, Any]:
    guests = range_guests(config, range_id)
    secret_root = config.cache_root / "secrets" / range_id
    if not (secret_root / "elastic.json").is_file():
        bootstrap_credentials(config, range_id)
    credentials = load_json(secret_root / "elastic.json")
    token = base64.b64encode(f"elastic:{credentials['elastic_password']}".encode()).decode()
    data = json.dumps(body).encode() if body is not None else None
    if config.remote_transport == "proxmox-agent":
        command = [
            "curl",
            "--silent",
            "--show-error",
            "--fail",
            "--cacert",
            "/etc/elasticsearch/tartarus-tls/ca.crt",
            "--user",
            f"elastic:{credentials['elastic_password']}",
            "--request",
            method,
            "--header",
            "Content-Type: application/json",
        ]
        if body is not None:
            command.extend(("--data", json.dumps(body)))
        command.append(f"https://127.0.0.1:9200/{path.lstrip('/')}")
        try:
            value = json.loads(Remote(config, guests["elk"]).run(tuple(command), timeout=30).stdout)
        except (TartarusError, json.JSONDecodeError) as exc:
            raise TartarusError(
                f"Elastic request failed for {path}; credentials were redacted"
            ) from exc
    else:
        request = urllib.request.Request(
            f"https://{guests['elk'].address}:9200/{path.lstrip('/')}",
            data=data,
            method=method,
            headers={"Authorization": f"Basic {token}", "Content-Type": "application/json"},
        )
        context = ssl.create_default_context(cafile=str(secret_root / "ca.crt"))
        try:
            with urllib.request.urlopen(request, context=context, timeout=30) as response:
                value = json.loads(response.read())
        except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
            raise TartarusError(
                f"Elastic request failed for {path}; credentials were redacted"
            ) from exc
    if not isinstance(value, dict):
        raise TartarusError("Elastic returned an unexpected response")
    return value


def telemetry_health(config: Config, range_id: str) -> dict[str, Any]:
    bootstrap_credentials(config, range_id)
    guests = range_guests(config, range_id)
    agents: dict[str, bool] = {}
    for role in ("remnux", "sandbox"):
        result = Remote(config, guests[role]).run(("systemctl", "is-active", "elastic-agent"))
        agents[role] = result.stdout.strip() == "active"
    cluster = elastic_request(config, range_id, "_cluster/health")
    return {
        "range_id": range_id,
        "cluster_status": cluster.get("status"),
        "agents": agents,
        "healthy": cluster.get("status") in {"green", "yellow"} and all(agents.values()),
    }


def telemetry_search(config: Config, range_id: str, query: str, size: int = 50) -> dict[str, Any]:
    if not 1 <= size <= 200:
        raise TartarusError("search size must be between 1 and 200")
    if not query or len(query) > 512:
        raise TartarusError("search query must be between 1 and 512 characters")
    body = {
        "size": size,
        "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
        "query": {"query_string": {"query": query}},
    }
    result = elastic_request(config, range_id, "logs-*,metrics-*/_search", method="POST", body=body)
    hits = result.get("hits", {}).get("hits", [])
    return {"range_id": range_id, "count": len(hits), "hits": hits}


def record_lifecycle(config: Config, range_id: str, event: dict[str, Any]) -> None:
    document = {"@timestamp": event.get("timestamp"), **event, "range_id": range_id}
    elastic_request(
        config,
        range_id,
        "tartarus-runs/_doc",
        method="POST",
        body=document,
    )
