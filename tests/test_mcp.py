import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from tartarus.config import Config
from tartarus.errors import TartarusError
from tartarus.mcp_gateway import (
    FUNCTION_RE,
    TOOLS,
    _archive_tool,
    _gdb_execute,
    _gdb_execute_resilient,
    _record_tool_result,
    _require_debug_run,
    _script_name,
    _string,
    _workflow_control,
)
from tartarus.web.jobs import JobStore


def test_mcp_surface_covers_ghidra_gdb_and_telemetry() -> None:
    names = {tool["name"] for tool in TOOLS}
    assert {
        "analysis_capabilities",
        "telemetry_search",
        "ghidra_script",
        "gdb_execute",
    } <= names
    assert not any(name.startswith("radare2_") for name in names)
    assert "shell" not in names
    for tool in TOOLS:
        assert {"range_id", "run_id"} <= set(tool["inputSchema"]["required"])


def test_sample_derived_function_names_are_constrained() -> None:
    assert FUNCTION_RE.fullmatch("main")
    assert not FUNCTION_RE.fullmatch("main; shell")
    with pytest.raises(TartarusError):
        _string({}, "run_id")


def test_gdb_requires_a_debug_run() -> None:
    _require_debug_run({"debug_session": True})
    with pytest.raises(TartarusError, match="gdbserver"):
        _require_debug_run({"debug_session": False})


def test_script_names_match_the_requested_analysis_engine() -> None:
    assert _script_name({"script_name": "AgentGraph.java"}, ".java") == "AgentGraph.java"
    with pytest.raises(TartarusError):
        _script_name({"script_name": "../AgentGraph.java"}, ".java")
    with pytest.raises(TartarusError):
        _script_name({"script_name": "agent_analysis.py"}, ".java")


class ArchiveToolRemote:
    def __init__(self, available: str | None) -> None:
        self.available = available

    def run(self, command, *, timeout):
        assert timeout == 60
        if command[1] == self.available:
            return SimpleNamespace(stdout=f"/usr/bin/{self.available}\n")
        raise TartarusError("not found")


def test_archive_tool_supports_modern_7zz_and_explains_missing_package() -> None:
    assert _archive_tool(ArchiveToolRemote("7zz")) == "/usr/bin/7zz"
    with pytest.raises(TartarusError, match="p7zip-full"):
        _archive_tool(ArchiveToolRemote(None))


def test_agent_can_update_operator_and_request_safe_cancellation(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    cache = tmp_path / "cache"
    evidence.mkdir()
    cache.mkdir()
    config = Config(
        evidence_root=evidence,
        cache_root=cache,
        management_sources=("198.51.100.2/32",),
        always_blocked_networks=("192.0.2.0/24",),
    )
    store = JobStore(cache)
    job, token = store.create(
        case_id="case-1",
        sample_id="sample-1",
        range_id="range-1",
        run_id="run-1",
        scope={},
    )
    store.approve(job["job_id"], token)
    store.transition(job["job_id"], "analyzing", message="Analysis started.")

    update = _workflow_control(
        config,
        "run-1",
        "workflow_update",
        {"message": "Architecture limits dynamic analysis.", "level": "warning"},
    )
    cancel = _workflow_control(
        config,
        "run-1",
        "workflow_cancel",
        {"reason": "No safe emulator is available."},
    )

    assert update["accepted"] is True
    assert cancel == {"accepted": True, "status": "cancel_requested"}
    assert store.active()["job_id"] == job["job_id"]
    assert store.get(job["job_id"])["failure"] == "No safe emulator is available."


class RecordingRemote:
    def __init__(self) -> None:
        self.command: tuple[str, ...] = ()

    def run(self, command, *, timeout):
        self.command = command
        assert timeout == 900
        return SimpleNamespace(stdout="registers and stack\n")


def test_gdb_execute_preserves_a_multi_command_analysis_sequence() -> None:
    remote = RecordingRemote()
    output = _gdb_execute(
        remote,
        "10.1.30.30",
        "/var/spool/tartarus/static/run-1/sample",
        ["break main", "continue", "info threads", "x/32gx $sp"],
    )

    assert output == "registers and stack\n"
    rendered = list(remote.command)
    assert "target remote 10.1.30.30:2345" in rendered
    for value in ("break main", "continue", "info threads", "x/32gx $sp"):
        assert value in rendered


class RestartingSandbox:
    def __init__(self) -> None:
        self.listening = False
        self.commands: list[tuple[str, ...]] = []

    def run(self, command, *, sudo=False, timeout=120):
        self.commands.append(command)
        if command[0] == "ss":
            return SimpleNamespace(stdout="LISTEN\n" if self.listening else "")
        if command[0] == "pkill":
            raise TartarusError("no old debugger")
        if command[0] == "systemd-run":
            self.listening = True
            return SimpleNamespace(stdout="started\n")
        raise AssertionError(command)


def test_gdb_execute_restarts_a_consumed_debugger_session(monkeypatch) -> None:
    remnux = RecordingRemote()
    sandbox = RestartingSandbox()
    monkeypatch.setattr("tartarus.mcp_gateway.time.sleep", lambda _seconds: None)

    output = _gdb_execute_resilient(
        remnux,
        sandbox,
        "10.1.30.30",
        "/var/spool/tartarus/static/run-1/sample",
        "run-1",
        ["break main", "continue"],
    )

    assert output.startswith("TARTARUS: debugger session restarted at sample entry")
    assert any(command[0] == "systemd-run" for command in sandbox.commands)


def test_each_tool_result_is_added_to_the_run_manifest(tmp_path: Path) -> None:
    run_dir = tmp_path / "case-1" / "run-1"
    run_dir.mkdir(parents=True)
    run_file = run_dir / "run.json"
    run = {
        "schema_version": "1.0",
        "case_id": "case-1",
        "run_id": "run-1",
        "sample": {"sample_id": "sample-1"},
        "telemetry_profile": "standard",
        "tartarus_release": "test",
        "status": "running",
        "started_at": "2026-10-12T00:00:00Z",
        "range_id": "T1",
        "debug_session": True,
        "artifacts": [],
        "visibility_gaps": [],
    }
    run_file.write_text(json.dumps(run), encoding="utf-8")

    result = _record_tool_result(
        run_file,
        run,
        "radare2_mcp_show_info",
        {"file_path": "/var/spool/tartarus/static/run-1/sample"},
        "analysis output",
        None,
    )

    assert result["ok"] is True
    artifact = json.loads(run_file.read_text(encoding="utf-8"))["artifacts"][0]
    evidence = run_dir / artifact["relative_path"]
    assert evidence.is_file()
    assert result == json.loads(evidence.read_text(encoding="utf-8"))
    assert artifact["size"] == evidence.stat().st_size
    assert artifact["collection_status"] == "collected"


def test_failed_tool_result_is_also_retained(tmp_path: Path) -> None:
    run_dir = tmp_path / "case-1" / "run-1"
    run_dir.mkdir(parents=True)
    run_file = run_dir / "run.json"
    run = {
        "schema_version": "1.0",
        "case_id": "case-1",
        "run_id": "run-1",
        "sample": {"sample_id": "sample-1"},
        "telemetry_profile": "standard",
        "tartarus_release": "test",
        "status": "running",
        "started_at": "2026-10-12T00:00:00Z",
        "range_id": "T1",
        "debug_session": True,
        "artifacts": [],
        "visibility_gaps": [],
    }
    run_file.write_text(json.dumps(run), encoding="utf-8")

    result = _record_tool_result(
        run_file,
        run,
        "ghidra_script",
        {"range_id": "T1", "run_id": "run-1"},
        None,
        "script failed",
    )

    assert result["ok"] is False
    assert result["error"] == "script failed"
    assert len(json.loads(run_file.read_text(encoding="utf-8"))["artifacts"]) == 1
