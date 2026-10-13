import io
import json
import tarfile
from pathlib import Path

import pytest
from tartarus.config import Config
from tartarus.errors import TartarusError
from tartarus.lifecycle import (
    _check_quota,
    _safe_extract,
    _visibility_gaps,
    assert_analysis_pair_ready,
    mark_analysis_pair_tainted,
    rebuild_sandbox,
)
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


def test_pair_recovery_destroys_both_guests_before_stopping_testing(
    tmp_path: Path, monkeypatch
) -> None:
    config = Config(
        evidence_root=tmp_path,
        cache_root=tmp_path,
        management_sources=("198.51.100.2/32",),
        always_blocked_networks=("192.0.2.0/24",),
    )
    remnux = Guest("T1-remnux-01", "192.0.2.20", "debian", None, 102)
    sandbox = Guest("T1-linux-sbx-01", "192.0.2.30", "debian", None, 103)
    monkeypatch.setattr(
        "tartarus.lifecycle.range_guests",
        lambda *_: {"remnux": remnux, "sandbox": sandbox},
    )
    statuses = iter(
        (
            {"rangeState": "SUCCESS", "testingEnabled": True},
            {"rangeState": "SUCCESS", "testingEnabled": False},
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
    testing_stop = calls.index(("--range", "T1", "testing", "stop"))
    assert calls.index(("--range", "T1", "vm", "destroy", "102", "--no-prompt")) < testing_stop
    assert calls.index(("--range", "T1", "vm", "destroy", "103", "--no-prompt")) < testing_stop
    assert ("--range", "T1", "range", "deploy", "--force") in calls
    assert not any("--limit" in command for command in calls)
    assert ("--range", "T1", "testing", "start") in calls


def test_pair_taint_blocks_other_runs_and_legacy_recovery_is_not_accepted(
    tmp_path: Path, monkeypatch
) -> None:
    config = Config(evidence_root=tmp_path, cache_root=tmp_path)
    remnux = Guest("T1-remnux-01", "192.0.2.20", "debian", None, 102)
    sandbox = Guest("T1-linux-sbx-01", "192.0.2.30", "debian", None, 103)
    monkeypatch.setattr(
        "tartarus.lifecycle.range_guests",
        lambda *_: {"remnux": remnux, "sandbox": sandbox},
    )
    recovery = {
        "schema_version": "1.0",
        "range_id": "T1",
        "state": "clean",
        "phase": "verified",
        "run_id": None,
        "tainted_at": None,
        "verified_at": "2026-10-13T00:00:00+00:00",
        "guests": {
            "remnux": {"status": "verified", "current": {"name": remnux.name, "vmid": 102, "address": remnux.address}},
            "sandbox": {"status": "verified", "current": {"name": sandbox.name, "vmid": 103, "address": sandbox.address}},
        },
        "failure": None,
    }
    state_path = tmp_path / "state" / "ranges" / "T1-analysis-pair.json"
    with pytest.raises(TartarusError, match="unverified"):
        assert_analysis_pair_ready(config, "T1")
    state_path.parent.mkdir(parents=True)
    state_path.write_text(json.dumps(recovery), encoding="utf-8")
    run_file = tmp_path / "run.json"
    run_file.write_text(
        json.dumps(
            {
                "schema_version": "1.0", "case_id": "case-1", "run_id": "run-1",
                "sample": {"sample_id": "sample-1"}, "telemetry_profile": "standard",
                "tartarus_release": "test", "status": "prepared",
                "started_at": "2026-10-13T00:00:00+00:00", "artifacts": [],
                "visibility_gaps": [], "recovery_verified": True,
            }
        ),
        encoding="utf-8",
    )

    mark_analysis_pair_tainted(config, "T1", run_file)
    assert assert_analysis_pair_ready(config, "T1", run_id="run-1")["state"] == "tainted"
    with pytest.raises(TartarusError, match="tainted"):
        assert_analysis_pair_ready(config, "T1", run_id="run-2")


def test_pair_recovery_failure_quarantines_the_range(tmp_path: Path, monkeypatch) -> None:
    config = Config(evidence_root=tmp_path, cache_root=tmp_path)
    remnux = Guest("T1-remnux-01", "192.0.2.20", "debian", None, 102)
    sandbox = Guest("T1-linux-sbx-01", "192.0.2.30", "debian", None, 103)
    monkeypatch.setattr(
        "tartarus.lifecycle.range_guests",
        lambda *_: {"remnux": remnux, "sandbox": sandbox},
    )

    def fake_ludus(arguments, **_kwargs):
        command = tuple(arguments)
        if command[-3:] == ("testing", "status", "--json"):
            return CommandResult(
                ("ludus", *command),
                json.dumps({"rangeState": "SUCCESS", "testingEnabled": True}),
                "",
                0,
            )
        raise TartarusError("destroy failed")

    monkeypatch.setattr("tartarus.lifecycle.run_ludus", fake_ludus)

    with pytest.raises(TartarusError, match="destroy failed"):
        rebuild_sandbox(config, "T1", wait_seconds=1)
    state = json.loads(
        (tmp_path / "state" / "ranges" / "T1-analysis-pair.json").read_text()
    )
    assert state["state"] == "quarantined"
    assert state["phase"] == "failed"
