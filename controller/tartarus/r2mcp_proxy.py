from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from typing import Any, TextIO

from .config import Config, load_config
from .errors import TartarusError
from .mcp_gateway import _current_run, _record_tool_result
from .remote import Remote, range_guests
from .util import safe_id


def proxy_radare2_mcp(
    config: Config,
    range_id: str,
    run_id: str,
    input_stream: TextIO,
    output_stream: TextIO,
) -> int:
    range_id = safe_id(range_id, "range ID")
    run_id = safe_id(run_id, "run ID")
    run_file, run = _current_run(config.evidence_root, range_id, run_id)
    remnux = Remote(config, range_guests(config, range_id)["remnux"])
    analysis_dir = f"/var/spool/tartarus/static/{run_id}"
    command = remnux.streaming_command(("r2mcp", "-p", "-s", analysis_dir, "-C", "both"))
    process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=sys.stderr,
        text=True,
        bufsize=1,
    )
    if process.stdin is None or process.stdout is None:
        process.kill()
        raise TartarusError("could not open the radare2 MCP standard-I/O streams")
    try:
        for line in input_stream:
            try:
                request = json.loads(line)
            except json.JSONDecodeError as exc:
                raise TartarusError("radare2 MCP request is not valid JSON") from exc
            process.stdin.write(line)
            process.stdin.flush()
            if "id" not in request:
                continue
            response_line = process.stdout.readline()
            if not response_line:
                raise TartarusError("radare2 MCP closed before it returned a response")
            try:
                response = json.loads(response_line)
            except json.JSONDecodeError as exc:
                raise TartarusError("radare2 MCP returned invalid JSON") from exc
            if request.get("method") == "tools/call":
                params = request.get("params", {})
                tool_name = str(params.get("name", "unknown"))
                operation = "radare2_mcp_" + re.sub(r"[^A-Za-z0-9_.-]", "_", tool_name)
                error = _tool_error(response)
                _record_tool_result(
                    run_file,
                    run,
                    operation,
                    params.get("arguments", {}),
                    response,
                    error,
                )
            output_stream.write(response_line)
            output_stream.flush()
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
    return process.returncode or 0


def _tool_error(response: dict[str, Any]) -> str | None:
    if "error" in response:
        error = response["error"]
        return str(error.get("message", error)) if isinstance(error, dict) else str(error)
    result = response.get("result")
    if isinstance(result, dict) and result.get("isError") is True:
        content = result.get("content", [])
        if isinstance(content, list) and content and isinstance(content[0], dict):
            return str(content[0].get("text", "radare2 MCP tool failed"))
        return "radare2 MCP tool failed"
    if isinstance(result, dict):
        content = result.get("content", [])
        if isinstance(content, list):
            for item in content:
                if not isinstance(item, dict):
                    continue
                message = item.get("text")
                if isinstance(message, str) and message.startswith(
                    ("Failed to ", "No file is currently open.")
                ):
                    return message
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Proxy the native radare2 MCP server over SSH")
    parser.add_argument("--range-id", required=True)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    try:
        return proxy_radare2_mcp(
            load_config(), args.range_id, args.run_id, sys.stdin, sys.stdout
        )
    except (TartarusError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
