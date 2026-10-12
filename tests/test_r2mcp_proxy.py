import io
import json
from pathlib import Path
from types import SimpleNamespace

from tartarus.config import Config
from tartarus.r2mcp_proxy import _tool_error, proxy_radare2_mcp


class FakeProcess:
    def __init__(self, responses: str) -> None:
        self.stdin = io.StringIO()
        self.stdout = io.StringIO(responses)
        self.returncode = None

    def poll(self):
        return self.returncode

    def terminate(self) -> None:
        self.returncode = 0

    def wait(self, timeout: int) -> int:
        assert timeout == 5
        self.returncode = 0
        return 0

    def kill(self) -> None:
        self.returncode = -9


class FakeRemote:
    def __init__(self, *_args, **_kwargs) -> None:
        pass

    def streaming_command(self, command):
        assert command == (
            "r2mcp",
            "-p",
            "-s",
            "/var/spool/tartarus/static/run-1",
            "-C",
            "both",
        )
        return ["ssh", "remnux", "r2mcp"]


def test_native_radare2_proxy_relays_protocol_and_records_tool_calls(
    tmp_path: Path, monkeypatch
) -> None:
    initialize = {"jsonrpc": "2.0", "id": 1, "result": {"serverInfo": {"name": "r2mcp"}}}
    tool_response = {
        "jsonrpc": "2.0",
        "id": 2,
        "result": {"content": [{"type": "text", "text": "functions"}]},
    }
    process = FakeProcess(json.dumps(initialize) + "\n" + json.dumps(tool_response) + "\n")
    recorded = []
    monkeypatch.setattr("tartarus.r2mcp_proxy.subprocess.Popen", lambda *_a, **_k: process)
    monkeypatch.setattr(
        "tartarus.r2mcp_proxy._current_run",
        lambda *_a: (tmp_path / "run.json", {"run_id": "run-1", "range_id": "T1"}),
    )
    monkeypatch.setattr(
        "tartarus.r2mcp_proxy.range_guests",
        lambda *_a: {"remnux": SimpleNamespace(name="remnux")},
    )
    monkeypatch.setattr("tartarus.r2mcp_proxy.Remote", FakeRemote)
    monkeypatch.setattr(
        "tartarus.r2mcp_proxy._record_tool_result",
        lambda *args: recorded.append(args),
    )
    requests = "\n".join(
        (
            json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}),
            json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "list_functions", "arguments": {}},
                }
            ),
        )
    ) + "\n"
    output = io.StringIO()
    config = Config(
        evidence_root=tmp_path,
        cache_root=tmp_path,
        management_sources=("198.51.100.2/32",),
        always_blocked_networks=("192.0.2.0/24",),
    )

    assert proxy_radare2_mcp(config, "T1", "run-1", io.StringIO(requests), output) == 0
    assert [json.loads(line)["id"] for line in output.getvalue().splitlines()] == [1, 2]
    assert recorded[0][2] == "radare2_mcp_list_functions"
    assert recorded[0][3] == {}
    assert recorded[0][5] is None


def test_native_radare2_proxy_extracts_tool_errors() -> None:
    assert _tool_error({"error": {"message": "bad request"}}) == "bad request"
    assert (
        _tool_error(
            {
                "result": {
                    "isError": True,
                    "content": [{"type": "text", "text": "analysis failed"}],
                }
            }
        )
        == "analysis failed"
    )
    assert _tool_error({"result": {"content": []}}) is None
    assert (
        _tool_error(
            {
                "result": {
                    "content": [{"type": "text", "text": "Failed to open file."}]
                }
            }
        )
        == "Failed to open file."
    )
