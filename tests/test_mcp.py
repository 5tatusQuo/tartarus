import json
from pathlib import Path

import pytest
from tartarus.errors import TartarusError
from tartarus.mcp_gateway import FUNCTION_RE, TOOLS, _require_debug_run, _string


def test_mcp_surface_has_no_raw_command_tool() -> None:
    names = {tool["name"] for tool in TOOLS}
    assert "shell" not in names
    assert "radare2_command" not in names
    assert {"ghidra_decompile", "gdb_breakpoint_step", "telemetry_search"} <= names


def test_sample_derived_function_names_are_constrained() -> None:
    assert FUNCTION_RE.fullmatch("main")
    assert not FUNCTION_RE.fullmatch("main; shell")
    with pytest.raises(TartarusError):
        _string({}, "run_id")


def test_gdb_requires_current_approved_debug_run(tmp_path: Path) -> None:
    run_dir = tmp_path / "case" / "run-1"
    run_dir.mkdir(parents=True)
    manifest = {"run_id": "run-1", "range_id": "T1", "status": "running", "debug_session": True}
    (run_dir / "run.json").write_text(json.dumps(manifest), encoding="utf-8")
    _require_debug_run(tmp_path, "T1", "run-1")
    manifest["debug_session"] = False
    (run_dir / "run.json").write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(TartarusError, match="approved debug run"):
        _require_debug_run(tmp_path, "T1", "run-1")
