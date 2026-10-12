import io
import json
import tarfile
from pathlib import Path

import pytest
from tartarus.config import Config
from tartarus.errors import TartarusError
from tartarus.lifecycle import _check_quota, _safe_extract, _visibility_gaps, rebuild_sandbox
from tartarus.ludus import CommandResult
from tartarus.remote import Guest


def test_visibility_gap_detection(tmp_path: Path) -> None:
    sandbox = tmp_path / "artifacts" / "sandbox"
    remnux = tmp_path / "artifacts" / "remnux"
    sandbox.mkdir(parents=True)
    remnux.mkdir(parents=True)
    (sandbox / "audit-status.txt").write_text("lost 3\n", encoding="utf-8")
    (remnux / "run-capture.log").write_text("Packets dropped: 7\n", encoding="utf-8")
    assert _visibility_gaps(tmp_path) == ["audit_lost:3", "packet_drops:7"]


def test_quota_and_evidence_archive_fail_closed(tmp_path: Path) -> None:
    config = Config(
        evidence_root=tmp_path,
        cache_root=tmp_path,
        artifact_quota_gib=1,
        management_sources=("198.51.100.2/32",),
        always_blocked_networks=("192.0.2.0/24",),
    )
    with pytest.raises(TartarusError, match="quota"):
        _check_quota(config, tmp_path, 1024**3 + 1)

    archive = tmp_path / "unsafe.tar"
    with tarfile.open(archive, "w") as handle:
        member = tarfile.TarInfo("../escape")
        member.size = 1
        handle.addfile(member, io.BytesIO(b"x"))
    with pytest.raises(TartarusError, match="unsafe evidence"):
        _safe_extract(archive, tmp_path / "output")


def test_sandbox_rebuild_exits_testing_before_destroy(tmp_path: Path, monkeypatch) -> None:
    config = Config(
        evidence_root=tmp_path,
        cache_root=tmp_path,
        management_sources=("198.51.100.2/32",),
        always_blocked_networks=("192.0.2.0/24",),
    )
    guest = Guest("T1-linux-sbx-01", "192.0.2.30", "debian", None, 103)
    monkeypatch.setattr(
        "tartarus.lifecycle.range_guests", lambda *_: {"sandbox": guest}
    )
    statuses = iter(
        (
            {"rangeState": "SUCCESS", "testingEnabled": True},
            {"rangeState": "DEPLOYING", "testingEnabled": False},
            {"rangeState": "SUCCESS", "testingEnabled": False},
        )
    )
    calls: list[tuple[str, ...]] = []

    def fake_ludus(arguments, **_kwargs):
        command = tuple(arguments)
        calls.append(command)
        stdout = json.dumps(next(statuses)) if command[-3:] == ("testing", "status", "--json") else ""
        return CommandResult(("ludus", *command), stdout, "", 0)

    monkeypatch.setattr("tartarus.lifecycle.run_ludus", fake_ludus)
    monkeypatch.setattr("tartarus.lifecycle.time.sleep", lambda _seconds: None)
    monkeypatch.setattr("tartarus.verify.verify_range", lambda *_: {"passed": True})

    assert rebuild_sandbox(config, "T1", wait_seconds=1) == {"passed": True}
    assert calls.index(("--range", "T1", "testing", "stop")) < calls.index(
        ("--range", "T1", "vm", "destroy", "103", "--no-prompt")
    )
    assert ("--range", "T1", "range", "deploy", "--force") in calls
    assert not any("--limit" in command for command in calls)
    assert ("--range", "T1", "testing", "start") in calls
