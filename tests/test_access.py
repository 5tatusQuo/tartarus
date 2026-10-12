import json
import subprocess
from pathlib import Path

from tartarus.access import operator_access
from tartarus.config import Config
from tartarus.remote import Guest


def test_operator_access_exposes_only_operator_credentials(
    tmp_path: Path, monkeypatch
) -> None:
    key = tmp_path / "secrets" / "controller_ed25519"
    key.parent.mkdir()
    key.write_text("private", encoding="utf-8")
    guests = {
        "elk": Guest("T1-elk-01", "10.1.10.10", "debian", "ignored", 110),
        "remnux": Guest("T1-remnux-01", "10.1.20.20", "debian", "ignored", 114),
        "sandbox": Guest("T1-linux-sbx-01", "10.1.30.30", "debian", "ignored", 115),
    }
    monkeypatch.setattr("tartarus.access.range_guests", lambda *_: guests)

    class FakeRemote:
        def __init__(self, *_args, **_kwargs):
            pass

        def run(self, *_args, **_kwargs):
            bootstrap = {
                "elastic_password": "generated-password",
                "kibana_password": "service-password",
                "agent_api_key": "service-api-key",
            }
            return subprocess.CompletedProcess((), 0, json.dumps(bootstrap), "")

    monkeypatch.setattr("tartarus.access.Remote", FakeRemote)
    config = Config(
        evidence_root=tmp_path / "evidence",
        cache_root=tmp_path,
        management_sources=("198.51.100.2/32",),
        always_blocked_networks=("192.0.2.0/24",),
    )

    result = operator_access(config, "T1")

    assert result["kibana"] == {
        "url": "http://10.1.10.10:5601",
        "username": "elastic",
        "password": "generated-password",
    }
    assert result["ssh"]["private_key"] == str(key)
    assert result["ssh"]["guests"]["sandbox"] == {
        "address": "10.1.30.30",
        "username": "debian",
    }
    serialized = json.dumps(result)
    assert "service-password" not in serialized
    assert "service-api-key" not in serialized
