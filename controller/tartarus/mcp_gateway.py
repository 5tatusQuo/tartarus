from __future__ import annotations

import json
import re
import sys
from typing import Any

from .config import load_config
from .errors import TartarusError
from .remote import Remote, range_guests
from .telemetry import telemetry_health, telemetry_search
from .util import safe_id

FUNCTION_RE = re.compile(r"^[A-Za-z_.$?][A-Za-z0-9_.$?@-]{0,255}$")
MAX_TOOL_OUTPUT_BYTES = 4 * 1024 * 1024


def _object(required: list[str]) -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": required,
        "properties": {name: {"type": "string", "maxLength": 512} for name in required},
    }


TOOLS = [
    {
        "name": "telemetry_health",
        "description": "Check Elastic and agent health",
        "inputSchema": _object(["range_id"]),
    },
    {
        "name": "telemetry_search",
        "description": "Run a bounded Elastic query-string search",
        "inputSchema": _object(["range_id", "query"]),
    },
    {
        "name": "radare2_functions",
        "description": "List functions from the inert current-run sample",
        "inputSchema": _object(["range_id", "run_id"]),
    },
    {
        "name": "radare2_strings",
        "description": "List strings from the inert current-run sample",
        "inputSchema": _object(["range_id", "run_id"]),
    },
    {
        "name": "ghidra_import",
        "description": "Import and analyze the inert current-run sample",
        "inputSchema": _object(["range_id", "run_id"]),
    },
    {
        "name": "ghidra_functions",
        "description": "List functions in the current-run Ghidra project",
        "inputSchema": _object(["range_id", "run_id"]),
    },
    {
        "name": "ghidra_decompile",
        "description": "Decompile one named function",
        "inputSchema": _object(["range_id", "run_id", "function"]),
    },
    {
        "name": "ghidra_disassembly",
        "description": "Return bounded disassembly for one named function",
        "inputSchema": _object(["range_id", "run_id", "function"]),
    },
    {
        "name": "ghidra_strings",
        "description": "List bounded defined strings from the current project",
        "inputSchema": _object(["range_id", "run_id"]),
    },
    {
        "name": "ghidra_xrefs",
        "description": "List bounded references to one named function",
        "inputSchema": _object(["range_id", "run_id", "function"]),
    },
    {
        "name": "gdb_registers",
        "description": "Read registers from the approved current gdbserver session",
        "inputSchema": _object(["range_id", "run_id"]),
    },
    {
        "name": "gdb_breakpoint_step",
        "description": "Set one validated breakpoint, continue, single-step, and inspect registers",
        "inputSchema": _object(["range_id", "run_id", "location"]),
    },
    {
        "name": "gdb_memory",
        "description": "Read at most 256 bytes from the approved current gdbserver session",
        "inputSchema": _object(["range_id", "run_id", "address", "length"]),
    },
]


def dispatch(name: str, arguments: dict[str, Any]) -> Any:
    config = load_config()
    range_id = safe_id(_string(arguments, "range_id"), "range ID")
    if name == "telemetry_health":
        return telemetry_health(config, range_id)
    if name == "telemetry_search":
        return telemetry_search(config, range_id, _string(arguments, "query"), 50)
    guests = range_guests(config, range_id)
    remnux = Remote(config, guests["remnux"])
    run_id = safe_id(_string(arguments, "run_id"), "run ID")
    _require_current_run(config.evidence_root, range_id, run_id)
    if name in {"gdb_registers", "gdb_breakpoint_step", "gdb_memory"}:
        _require_debug_run(config.evidence_root, range_id, run_id)
    if name == "gdb_registers":
        return _bounded_output(
            remnux.run(
                (
                    "gdb",
                    "-q",
                    "-batch",
                    "-ex",
                    f"target remote {guests['sandbox'].address}:2345",
                    "-ex",
                    "info registers",
                )
            ).stdout
        )
    if name == "gdb_breakpoint_step":
        location = _string(arguments, "location")
        if not FUNCTION_RE.fullmatch(location) and not re.fullmatch(
            r"\*0x[a-fA-F0-9]{1,16}", location
        ):
            raise TartarusError("invalid breakpoint location")
        return _bounded_output(
            remnux.run(
                (
                    "gdb",
                    "-q",
                    "-batch",
                    "-ex",
                    f"target remote {guests['sandbox'].address}:2345",
                    "-ex",
                    f"break {location}",
                    "-ex",
                    "continue",
                    "-ex",
                    "stepi",
                    "-ex",
                    "info registers",
                    "-ex",
                    "x/16gx $sp",
                    "-ex",
                    "detach",
                ),
                timeout=120,
            ).stdout
        )
    if name == "gdb_memory":
        address = _string(arguments, "address")
        if not re.fullmatch(r"0x[a-fA-F0-9]{1,16}", address):
            raise TartarusError("invalid memory address")
        try:
            length = int(_string(arguments, "length"))
        except ValueError as exc:
            raise TartarusError("memory length must be an integer") from exc
        if not 1 <= length <= 256:
            raise TartarusError("memory length must be between 1 and 256 bytes")
        return _bounded_output(
            remnux.run(
                (
                    "gdb",
                    "-q",
                    "-batch",
                    "-ex",
                    f"target remote {guests['sandbox'].address}:2345",
                    "-ex",
                    f"x/{length}bx {address}",
                    "-ex",
                    "detach",
                )
            ).stdout
        )
    sample = f"/var/spool/tartarus/static/{run_id}/sample"
    if name in {"radare2_functions", "radare2_strings"}:
        command = "aaa;aflj" if name.endswith("functions") else "izj"
        output = _bounded_output(
            remnux.run(
                (
                    "r2",
                    "-q",
                    "-e",
                    "io.cache=true",
                    "-c",
                    f"e cfg.sandbox=true;{command}",
                    sample,
                )
            ).stdout
        )
        return json.loads(output)
    project = f"/var/spool/tartarus/ghidra/{run_id}"
    analyze = remnux.run(("which", "analyzeHeadless")).stdout.strip()
    base = (analyze, project, "tartarus", "-scriptPath", "/opt/tartarus/ghidra-scripts")
    if name == "ghidra_import":
        return _bounded_output(
            remnux.run((*base, "-import", sample, "-overwrite"), timeout=600).stdout
        )
    if name == "ghidra_functions":
        return _bounded_output(
            remnux.run(
                (
                    *base,
                    "-process",
                    "sample",
                    "-noanalysis",
                    "-postScript",
                    "TartarusFunctions.java",
                ),
                timeout=300,
            ).stdout
        )
    if name == "ghidra_strings":
        return _bounded_output(
            remnux.run(
                (*base, "-process", "sample", "-noanalysis", "-postScript", "TartarusStrings.java"),
                timeout=300,
            ).stdout
        )
    if name in {"ghidra_decompile", "ghidra_disassembly", "ghidra_xrefs"}:
        function = _string(arguments, "function")
        if not FUNCTION_RE.fullmatch(function):
            raise TartarusError("invalid function name")
        script = {
            "ghidra_decompile": "TartarusDecompile.java",
            "ghidra_disassembly": "TartarusDisassembly.java",
            "ghidra_xrefs": "TartarusXrefs.java",
        }[name]
        return _bounded_output(
            remnux.run(
                (
                    *base,
                    "-process",
                    "sample",
                    "-noanalysis",
                    "-postScript",
                    script,
                    function,
                ),
                timeout=300,
            ).stdout
        )
    raise TartarusError(f"unknown bounded tool: {name}")


def _string(arguments: dict[str, Any], key: str) -> str:
    value = arguments.get(key)
    if not isinstance(value, str) or not value:
        raise TartarusError(f"{key} must be a non-empty string")
    return value


def _bounded_output(value: str) -> str:
    if len(value.encode("utf-8")) > MAX_TOOL_OUTPUT_BYTES:
        raise TartarusError("bounded tool output exceeded 4 MiB")
    return value


def _current_run_manifest(evidence_root, run_id: str) -> dict[str, Any]:
    matches = list(evidence_root.glob(f"*/{run_id}/run.json"))
    if len(matches) != 1:
        raise TartarusError("current run manifest was not found")
    return json.loads(matches[0].read_text(encoding="utf-8"))


def _require_current_run(evidence_root, range_id: str, run_id: str) -> None:
    manifest = _current_run_manifest(evidence_root, run_id)
    if manifest.get("range_id") != range_id or manifest.get("status") != "running":
        raise TartarusError("analysis access is limited to the current running case")


def _require_debug_run(evidence_root, range_id: str, run_id: str) -> None:
    manifest = _current_run_manifest(evidence_root, run_id)
    if manifest.get("range_id") != range_id or manifest.get("debug_session") is not True:
        raise TartarusError("GDB access is limited to the current approved debug run")


def main() -> int:
    for line in sys.stdin:
        identifier: Any = None
        try:
            request = json.loads(line)
            identifier = request.get("id")
            method = request.get("method")
            if method == "initialize":
                result = {
                    "protocolVersion": "2025-06-18",
                    "serverInfo": {"name": "tartarus", "version": "0.1.0"},
                    "capabilities": {"tools": {}},
                }
            elif method == "tools/list":
                result = {"tools": TOOLS}
            elif method == "tools/call":
                params = request.get("params", {})
                value = dispatch(params.get("name", ""), params.get("arguments", {}))
                result = {"content": [{"type": "text", "text": json.dumps(value)}]}
            elif method == "notifications/initialized":
                continue
            else:
                raise TartarusError("unsupported MCP method")
            response = {"jsonrpc": "2.0", "id": identifier, "result": result}
        except (TartarusError, ValueError, KeyError, TypeError) as exc:
            response = {
                "jsonrpc": "2.0",
                "id": identifier,
                "error": {"code": -32000, "message": str(exc)},
            }
        print(json.dumps(response), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
