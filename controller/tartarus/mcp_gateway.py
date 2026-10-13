from __future__ import annotations

import json
import re
import sys
import tempfile
import time
import uuid
from pathlib import Path, PurePosixPath
from typing import Any

from .config import Config, load_config
from .errors import TartarusError
from .manifest import validate
from .remote import Remote, range_guests
from .telemetry import telemetry_health, telemetry_search
from .util import atomic_json, load_json, safe_id, utc_now

FUNCTION_RE = re.compile(r"^[A-Za-z_.$?][A-Za-z0-9_.$?@-]{0,255}$")
SCRIPT_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,127}\.java$")
MAX_TOOL_OUTPUT_BYTES = 32 * 1024 * 1024


def _schema(required: list[str], properties: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": required,
        "properties": properties,
    }


def _strings(*names: str) -> dict[str, Any]:
    return {name: {"type": "string", "minLength": 1} for name in names}


RUN = _strings("range_id", "run_id")

TOOLS = [
    {
        "name": "workflow_update",
        "description": "Publish a bounded operator-facing progress or limitation message",
        "inputSchema": _schema(
            ["range_id", "run_id", "message", "level"],
            {
                **RUN,
                "message": {"type": "string", "minLength": 1, "maxLength": 2000},
                "level": {"enum": ["info", "warning"]},
            },
        ),
    },
    {
        "name": "workflow_cancel",
        "description": "Ask the controller to cancel safely and show the reason to the operator",
        "inputSchema": _schema(
            ["range_id", "run_id", "reason"],
            {**RUN, "reason": {"type": "string", "minLength": 1, "maxLength": 2000}},
        ),
    },
    {
        "name": "analysis_capabilities",
        "description": "Inventory the local analysis tools available for the current run",
        "inputSchema": _schema(["range_id", "run_id"], RUN),
    },
    {
        "name": "archive_members",
        "description": "List the staged ZIP members during the current run's preparation phase",
        "inputSchema": _schema(
            ["range_id", "run_id", "password"],
            {**RUN, "password": {"type": "string", "maxLength": 1024}},
        ),
    },
    {
        "name": "archive_extract_elf",
        "description": "Extract one agent-selected ZIP member and accept it only if it is an ELF",
        "inputSchema": _schema(
            ["range_id", "run_id", "member", "password"],
            {
                **RUN,
                "member": {"type": "string", "minLength": 1, "maxLength": 4096},
                "password": {"type": "string", "maxLength": 1024},
            },
        ),
    },
    {
        "name": "telemetry_health",
        "description": "Check Elastic and agent health and retain the result with the run",
        "inputSchema": _schema(["range_id", "run_id"], RUN),
    },
    {
        "name": "telemetry_search",
        "description": "Search local Elastic telemetry for the current run",
        "inputSchema": _schema(
            ["range_id", "run_id", "query"],
            {
                **RUN,
                "query": {"type": "string", "minLength": 1, "maxLength": 4096},
                "size": {"type": "integer", "minimum": 1, "maximum": 200},
            },
        ),
    },
    {
        "name": "ghidra_import",
        "description": "Import and analyze the current-run sample",
        "inputSchema": _schema(["range_id", "run_id"], RUN),
    },
    {
        "name": "ghidra_functions",
        "description": "List functions in the current-run Ghidra project",
        "inputSchema": _schema(["range_id", "run_id"], RUN),
    },
    {
        "name": "ghidra_decompile",
        "description": "Decompile one named function",
        "inputSchema": _schema(
            ["range_id", "run_id", "function"], {**RUN, **_strings("function")}
        ),
    },
    {
        "name": "ghidra_disassembly",
        "description": "Return the disassembly for one named function",
        "inputSchema": _schema(
            ["range_id", "run_id", "function"], {**RUN, **_strings("function")}
        ),
    },
    {
        "name": "ghidra_strings",
        "description": "List defined strings from the current Ghidra project",
        "inputSchema": _schema(["range_id", "run_id"], RUN),
    },
    {
        "name": "ghidra_xrefs",
        "description": "List references to one named function",
        "inputSchema": _schema(
            ["range_id", "run_id", "function"], {**RUN, **_strings("function")}
        ),
    },
    {
        "name": "ghidra_script",
        "description": "Run an agent-supplied Ghidra Java script against the current project",
        "inputSchema": _schema(
            ["range_id", "run_id", "script_name", "source"],
            {
                **RUN,
                "script_name": {"type": "string", "pattern": SCRIPT_RE.pattern},
                "source": {"type": "string", "minLength": 1},
                "arguments": {"type": "array", "items": {"type": "string"}},
            },
        ),
    },
    {
        "name": "gdb_registers",
        "description": "Read registers from the current gdbserver session",
        "inputSchema": _schema(["range_id", "run_id"], RUN),
    },
    {
        "name": "gdb_breakpoint_step",
        "description": "Set a breakpoint, continue, step, and inspect the current context",
        "inputSchema": _schema(
            ["range_id", "run_id", "location"], {**RUN, **_strings("location")}
        ),
    },
    {
        "name": "gdb_memory",
        "description": "Read memory from the current gdbserver session",
        "inputSchema": _schema(
            ["range_id", "run_id", "address", "length"],
            {
                **RUN,
                "address": {"type": "string", "minLength": 1},
                "length": {"type": "integer", "minimum": 1},
            },
        ),
    },
    {
        "name": "gdb_execute",
        "description": "Run a sequence of GDB commands against the current gdbserver session",
        "inputSchema": _schema(
            ["range_id", "run_id", "commands"],
            {
                **RUN,
                "commands": {
                    "type": "array",
                    "minItems": 1,
                    "items": {"type": "string", "minLength": 1},
                },
            },
        ),
    },
]


def dispatch(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    config = load_config()
    range_id = safe_id(_string(arguments, "range_id"), "range ID")
    run_id = safe_id(_string(arguments, "run_id"), "run ID")
    run_file, run = _current_run(config.evidence_root, range_id, run_id)
    try:
        value = _execute_tool(config, run, name, arguments)
    except (TartarusError, ValueError, KeyError, TypeError) as exc:
        return _record_tool_result(run_file, run, name, arguments, None, str(exc))
    return _record_tool_result(run_file, run, name, arguments, value, None)


def _execute_tool(
    config: Config, run: dict[str, Any], name: str, arguments: dict[str, Any]
) -> Any:
    range_id = run["range_id"]
    run_id = run["run_id"]
    if name in {"workflow_update", "workflow_cancel"}:
        return _workflow_control(config, run_id, name, arguments)
    guests = range_guests(config, range_id)
    remnux = Remote(config, guests["remnux"])
    sandbox = Remote(config, guests["sandbox"])
    sample = f"/var/spool/tartarus/static/{run_id}/sample"

    if name in {"archive_members", "archive_extract_elf"}:
        if run.get("status") != "preparing":
            raise TartarusError("archive tools are available only during input preparation")
        archive = f"/var/spool/tartarus/static/{run_id}/input.zip"
        password = _password(arguments)
        seven_zip = _archive_tool(remnux)
        if name == "archive_members":
            return _tool_output(
                remnux.run(
                    (seven_zip, "l", "-slt", f"-p{password}", archive),
                    timeout=300,
                ).stdout
            )
        member = _string(arguments, "member")
        member_path = PurePosixPath(member)
        if (
            member_path.is_absolute()
            or ".." in member_path.parts
            or "\\" in member
            or not member_path.name
        ):
            raise TartarusError("archive member path is unsafe")
        output_dir = f"/var/spool/tartarus/static/{run_id}/archive-output"
        remnux.run(("rm", "-rf", output_dir), timeout=60)
        remnux.run(("mkdir", "-m", "0700", output_dir), timeout=60)
        remnux.run(
            (
                seven_zip,
                "e",
                "-y",
                f"-p{password}",
                f"-o{output_dir}",
                archive,
                member,
            ),
            timeout=900,
        )
        extracted = f"{output_dir}/{member_path.name}"
        validation = (
            "import os,shutil,stat,sys;"
            "p,d=sys.argv[1:3];s=os.lstat(p);"
            "assert stat.S_ISREG(s.st_mode) and s.st_size<=1073741824;"
            "assert open(p,'rb').read(4)==b'\\x7fELF';"
            "shutil.copyfile(p,d);os.chmod(d,0o400)"
        )
        remnux.run(("python3", "-c", validation, extracted, sample), timeout=300)
        return {"prepared": True, "member": member, "sample": sample}

    if name == "analysis_capabilities":
        return _capabilities(remnux)
    if name == "telemetry_health":
        return telemetry_health(config, range_id)
    if name == "telemetry_search":
        size = _integer(arguments, "size", default=50)
        query = _string(arguments, "query")
        scoped_query = f'({query}) AND "{run_id}"'
        return telemetry_search(config, range_id, scoped_query, size)

    project = f"/var/spool/tartarus/ghidra/{run_id}"
    analyze = remnux.run(("which", "analyzeHeadless")).stdout.strip()
    base = (analyze, project, "tartarus", "-scriptPath", "/opt/tartarus/ghidra-scripts")
    if name == "ghidra_import":
        return _tool_output(
            remnux.run((*base, "-import", sample, "-overwrite"), timeout=900).stdout
        )
    if name in {"ghidra_functions", "ghidra_strings"}:
        script = {
            "ghidra_functions": "TartarusFunctions.java",
            "ghidra_strings": "TartarusStrings.java",
        }[name]
        return _ghidra_post_script(remnux, base, script, ())
    if name in {"ghidra_decompile", "ghidra_disassembly", "ghidra_xrefs"}:
        function = _string(arguments, "function")
        if not FUNCTION_RE.fullmatch(function):
            raise TartarusError("invalid function name")
        script = {
            "ghidra_decompile": "TartarusDecompile.java",
            "ghidra_disassembly": "TartarusDisassembly.java",
            "ghidra_xrefs": "TartarusXrefs.java",
        }[name]
        return _ghidra_post_script(remnux, base, script, (function,))
    if name == "ghidra_script":
        script_name = _script_name(arguments, ".java")
        script_dir = f"{project}/agent-scripts"
        remnux.run(("mkdir", "-p", script_dir))
        _push_text(remnux, _string(arguments, "source"), f"{script_dir}/{script_name}")
        custom_base = (
            analyze,
            project,
            "tartarus",
            "-scriptPath",
            f"/opt/tartarus/ghidra-scripts;{script_dir}",
        )
        return _ghidra_post_script(
            remnux, custom_base, script_name, tuple(_string_list(arguments, "arguments"))
        )

    if name in {"gdb_registers", "gdb_breakpoint_step", "gdb_memory", "gdb_execute"}:
        _require_debug_run(run)
        if name == "gdb_registers":
            commands = ["info registers"]
        elif name == "gdb_breakpoint_step":
            location = _string(arguments, "location")
            commands = [
                f"break {location}",
                "continue",
                "stepi",
                "info registers",
                "x/16gx $sp",
            ]
        elif name == "gdb_memory":
            length = _integer(arguments, "length")
            commands = [f"x/{length}bx {_string(arguments, 'address')}"]
        else:
            commands = _string_list(arguments, "commands")
        return _gdb_execute_resilient(
            remnux,
            sandbox,
            guests["sandbox"].address,
            sample,
            run_id,
            commands,
        )

    raise TartarusError(f"unknown analysis tool: {name}")


def _workflow_control(
    config: Config, run_id: str, name: str, arguments: dict[str, Any]
) -> dict[str, Any]:
    from .web.jobs import JobStore

    store = JobStore(config.cache_root, reconcile=False)
    matches = [job for job in store.list() if job["run_id"] == run_id]
    if len(matches) != 1:
        raise TartarusError("current workflow job could not be resolved")
    job = matches[0]
    if job["status"] not in {"queued", "running", "cancel_requested"}:
        raise TartarusError("workflow is no longer active")
    if name == "workflow_update":
        message = _string(arguments, "message")
        level = _string(arguments, "level")
        if level not in {"info", "warning"}:
            raise TartarusError("invalid workflow update level")
        event = store.append_event(
            job["job_id"], job["phase"], f"AI agent: {message}", level=level
        )
        return {"accepted": True, "event_cursor": event["cursor"]}
    reason = _string(arguments, "reason")
    updated = store.transition(
        job["job_id"],
        "attention",
        status="cancel_requested",
        message=f"AI agent requested safe cancellation: {reason}",
        resumability="safe_cleanup_only",
        failure=reason,
    )
    return {"accepted": True, "status": updated["status"]}


def _archive_tool(remnux: Remote) -> str:
    for name in ("7z", "7zz"):
        try:
            path = remnux.run(("which", name), timeout=60).stdout.strip()
        except TartarusError:
            continue
        if path:
            return path
    raise TartarusError(
        "REMnux is missing a supported 7-Zip tool; install p7zip-full or refresh the range"
    )


def _ghidra_post_script(
    remote: Remote, base: tuple[str, ...], script: str, arguments: tuple[str, ...]
) -> str:
    return _tool_output(
        remote.run(
            (
                *base,
                "-process",
                "sample",
                "-noanalysis",
                "-postScript",
                script,
                *arguments,
            ),
            timeout=900,
        ).stdout
    )


def _gdb_execute(remote: Remote, sandbox_address: str, sample: str, commands: list[str]) -> str:
    argv = [
        "gdb",
        "-q",
        "-batch",
        sample,
        "-ex",
        "set confirm off",
        "-ex",
        "set pagination off",
        "-ex",
        f"target remote {sandbox_address}:2345",
    ]
    for command in commands:
        if "\x00" in command:
            raise TartarusError("GDB command contains a NUL byte")
        argv.extend(("-ex", command))
    return _tool_output(remote.run(tuple(argv), timeout=900).stdout)


def _gdb_execute_resilient(
    remnux: Remote,
    sandbox: Remote,
    sandbox_address: str,
    sample: str,
    run_id: str,
    commands: list[str],
) -> str:
    restarted = False
    if not _gdbserver_listening(sandbox):
        _restart_gdbserver(sandbox, run_id)
        restarted = True
    try:
        output = _gdb_execute(remnux, sandbox_address, sample, commands)
    except TartarusError:
        if restarted:
            raise
        _restart_gdbserver(sandbox, run_id)
        restarted = True
        output = _gdb_execute(remnux, sandbox_address, sample, commands)
    if restarted:
        return "TARTARUS: debugger session restarted at sample entry\n" + output
    return output


def _gdbserver_listening(sandbox: Remote) -> bool:
    return bool(
        sandbox.run(
            ("ss", "-H", "-lnt", "sport", "=", ":2345"),
            timeout=60,
        ).stdout.strip()
    )


def _restart_gdbserver(sandbox: Remote, run_id: str) -> None:
    try:
        sandbox.run(("pkill", "-u", "tartarus-runner", "-x", "gdbserver"), sudo=True)
    except TartarusError:
        pass
    run_dir = f"/var/spool/tartarus/runs/{run_id}"
    unit = f"tartarus-gdb-mcp-{uuid.uuid4().hex[:8]}.service"
    sandbox.run(
        (
            "systemd-run",
            "--unit",
            unit,
            "--slice",
            "tartarus-runner.slice",
            "--collect",
            "--property=RuntimeMaxSec=900s",
            "--property=KillMode=control-group",
            "--property=NoNewPrivileges=yes",
            "--property=LimitFSIZE=1073741824",
            f"--property=StandardOutput=append:{run_dir}/gdb-mcp.stdout.log",
            f"--property=StandardError=append:{run_dir}/gdb-mcp.stderr.log",
            "--uid=tartarus-runner",
            "--gid=tartarus-runner",
            f"--working-directory={run_dir}",
            "gdbserver",
            ":2345",
            "./sample",
        ),
        sudo=True,
        timeout=60,
    )
    time.sleep(1)
    if not _gdbserver_listening(sandbox):
        raise TartarusError("restarted gdbserver did not open the analysis port")


def _capabilities(remote: Remote) -> dict[str, Any]:
    probes = {
        "ghidra": (
            "grep",
            "^application.version=",
            "/opt/ghidra_11.4.2_PUBLIC/Ghidra/application.properties",
        ),
        "radare2": ("r2", "-v"),
        "radare2_mcp": ("r2mcp", "-v"),
        "gdb": ("gdb", "--version"),
    }
    result: dict[str, Any] = {}
    for name, command in probes.items():
        try:
            completed = remote.run(command, timeout=60)
            result[name] = {
                "available": True,
                "version": (completed.stdout or completed.stderr).splitlines()[0],
            }
        except (TartarusError, IndexError) as exc:
            result[name] = {"available": False, "error": str(exc)}
    result["interfaces"] = {
        "ghidra": "headless project adapter and custom Java scripts",
        "radare2": "native r2mcp server through tartarus-r2mcp",
        "gdb": "current-run remote gdbserver command adapter",
        "telemetry": "run-scoped Elastic search",
        "evidence": "per-call ToolResult artifacts",
    }
    return result


def _push_text(remote: Remote, value: str, destination: str) -> None:
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
        temporary = Path(handle.name)
        handle.write(value)
    try:
        remote.push(temporary, destination, timeout=300)
    finally:
        temporary.unlink(missing_ok=True)


def _record_tool_result(
    run_file: Path,
    run: dict[str, Any],
    operation: str,
    arguments: dict[str, Any],
    value: Any,
    error: str | None,
) -> dict[str, Any]:
    artifact_dir = run_file.parent / "artifacts" / "mcp"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    artifact_path = artifact_dir / f"{operation}-{uuid.uuid4().hex}.json"
    relative_path = artifact_path.relative_to(run_file.parent).as_posix()
    result = {
        "schema_version": "1.0",
        "ok": error is None,
        "operation": operation,
        "data": {
            "arguments": _redact_arguments(arguments),
            "result": value,
            "recorded_at": utc_now(),
            "evidence_path": relative_path,
        },
        "error": error,
    }
    validate("tool-result", result)
    atomic_json(artifact_path, result)
    record = {
        "relative_path": relative_path,
        "media_type": "application/json",
        "size": artifact_path.stat().st_size,
        "collection_status": "collected",
        "collected_at": utc_now(),
    }
    latest_run = load_json(run_file)
    latest_run["artifacts"].append(record)
    validate("run-manifest", latest_run)
    atomic_json(run_file, latest_run)
    return result


def _string(arguments: dict[str, Any], key: str) -> str:
    value = arguments.get(key)
    if not isinstance(value, str) or not value:
        raise TartarusError(f"{key} must be a non-empty string")
    return value


def _password(arguments: dict[str, Any]) -> str:
    value = arguments.get("password")
    if not isinstance(value, str) or len(value) > 1024:
        raise TartarusError("archive password must be a string of at most 1024 characters")
    return value


def _redact_arguments(arguments: dict[str, Any]) -> dict[str, Any]:
    return {
        key: "<redacted>" if key in {"password", "archive_password"} else value
        for key, value in arguments.items()
    }


def _string_list(arguments: dict[str, Any], key: str) -> list[str]:
    value = arguments.get(key, [])
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise TartarusError(f"{key} must be a list of non-empty strings")
    return value


def _integer(arguments: dict[str, Any], key: str, default: int | None = None) -> int:
    value = arguments.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise TartarusError(f"{key} must be a positive integer")
    return value


def _script_name(arguments: dict[str, Any], suffix: str) -> str:
    value = _string(arguments, "script_name")
    if not SCRIPT_RE.fullmatch(value) or not value.endswith(suffix):
        raise TartarusError(f"script_name must be a valid {suffix} filename")
    return value


def _tool_output(value: str) -> str:
    if len(value.encode("utf-8")) > MAX_TOOL_OUTPUT_BYTES:
        raise TartarusError("tool output exceeded the 32 MiB MCP transport limit")
    return value


def _current_run(evidence_root: Path, range_id: str, run_id: str) -> tuple[Path, dict[str, Any]]:
    matches = list(evidence_root.glob(f"*/{run_id}/run.json"))
    if len(matches) != 1:
        raise TartarusError("current run manifest was not found")
    manifest = load_json(matches[0])
    if manifest.get("range_id") != range_id or manifest.get("status") not in {
        "preparing",
        "running",
    }:
        raise TartarusError("analysis access requires the current preparing or running case")
    return matches[0], manifest


def _require_debug_run(manifest: dict[str, Any]) -> None:
    if manifest.get("debug_session") is not True:
        raise TartarusError("the current run did not start a gdbserver session")


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
                    "serverInfo": {"name": "tartarus", "version": "0.2.0"},
                    "capabilities": {"tools": {"listChanged": False}},
                }
            elif method == "tools/list":
                result = {"tools": TOOLS}
            elif method == "tools/call":
                params = request.get("params", {})
                value = dispatch(params.get("name", ""), params.get("arguments", {}))
                result = {
                    "content": [{"type": "text", "text": json.dumps(value)}],
                    "isError": not value["ok"],
                }
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
