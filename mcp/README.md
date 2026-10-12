# Tartarus MCP gateway

`tartarus-mcp` is the local standard-input and standard-output MCP server for Ghidra, GDB, and telemetry.
`tartarus-r2mcp` is the local standard-input and standard-output proxy for the native radare2 MCP server on REMnux.
It does not use a cloud service.

## Tool groups

- `analysis_capabilities` records the installed analysis engines and optional components.
- `telemetry_health` and `telemetry_search` query local Elastic services for the current run.
- `ghidra_import`, `ghidra_functions`, `ghidra_decompile`, `ghidra_disassembly`, `ghidra_strings`, and `ghidra_xrefs` provide common Ghidra operations.
- `ghidra_script` runs agent-supplied Java analysis logic in the current Ghidra project.
- `gdb_registers`, `gdb_breakpoint_step`, `gdb_memory`, and `gdb_execute` control the current sandbox `gdbserver` session.
- The native radare2 MCP server supplies file, analysis, function, string, import, export, section, symbol, cross-reference, decompilation, and disassembly tools.

Each `tartarus-mcp` tool call requires a running `range_id` and `run_id`.
The `tartarus-r2mcp` command takes these values when it starts and applies them to all native radare2 MCP calls in that session.
GDB calls also require a run that started with `--debug` because that option starts `gdbserver` in the sandbox.

Each successful or failed tool call creates a ToolResult JSON file in:

```text
<evidence-root>/<case-id>/<run-id>/artifacts/mcp/
```

Tartarus hashes the file and adds it to the run manifest before it returns the result to the MCP client.

## Client configuration

Start the server with the configuration file for the local installation:

```bash
TARTARUS_CONFIG=/path/to/config.toml tartarus-mcp
```

Start the radare2 MCP proxy for a running analysis:

```bash
TARTARUS_CONFIG=/path/to/config.toml \
  tartarus-r2mcp --range-id <range-id> --run-id <run-id>
```

The server supports MCP initialization, tool discovery, and tool calls over JSON-RPC lines on standard input and standard output.

For an MCP client that uses JSON configuration, use this pattern:

```json
{
  "mcpServers": {
    "tartarus": {
      "command": "/path/to/tartarus/.venv/bin/tartarus-mcp",
      "env": {
        "TARTARUS_CONFIG": "/path/to/tartarus/.tartarus/config.toml"
      }
    },
    "tartarus-radare2": {
      "command": "/path/to/tartarus/.venv/bin/tartarus-r2mcp",
      "args": [
        "--range-id",
        "<range-id>",
        "--run-id",
        "<run-id>"
      ],
      "env": {
        "TARTARUS_CONFIG": "/path/to/tartarus/.tartarus/config.toml"
      }
    }
  }
}
```

Replace the two identifiers for each run.
The proxy uses the controller SSH key and the active WireGuard route to connect to REMnux.
