# Analysis-agent validation

## Test identity

- Date: 2026-10-12
- Case: `benign-elf-final`
- Run: `agent-test-20261012b`
- Fixture: Debian BusyBox 1.35.0, x86-64 ELF
- Sample ID: `sample-benign-busybox`
- Purpose: Test the agent workflow with a known benign file. Do not assess the fixture as malware.

## Actions and observations

The agent used the Tartarus MCP gateway for these actions:

- Get the radare2 function and string inventories.
- Get the Ghidra function and string inventories.
- Decompile the `entry` function.
- Disassemble the `entry` function.
- Get cross-references for the `entry` function.
- Search the local telemetry store for run evidence.

Radare2 identified 1,208 functions. Ghidra and radare2 identified BusyBox strings and multicall behavior. The `entry` function used the normal C runtime handoff. Radare2 also identified `main` at address `0x8637`. This result showed the value of comparison between analysis tools.

The sandbox ran the fixture with the name `sample`. The fixture wrote `sample: applet not found` to standard error and exited. It did not create a filesystem difference. This behavior supports the benign BusyBox multicall hypothesis. The test did not produce evidence for an APT attribution, a malicious IOC, a MITRE ATT&CK mapping, or a Sigma rule.

The historical collected run manifest records the artifacts and successful legacy sandbox recovery. This does not prove analysis-pair recovery under the current policy.

## Defects found

The first Ghidra disassembly request failed with Ghidra 11.4 because `TartarusDisassembly.java` declared a helper named `getFunction`. That name conflicted with a final Ghidra API method. The helper is now named `findFunctionByName`. The next MCP request returned the function disassembly.

The range verifier also had two unrelated false failures. It used the obsolete HTTPS Kibana address, and it required host NTP synchronization even when the guest clock was correct. The verifier now uses the local HTTP Kibana address and checks the actual clock difference.

## MCP integration validation

A second run, `mcp-e2e-20261012`, started the same benign fixture with the `deep` telemetry profile and a GDB session. The test used the JSON-RPC standard-input and standard-output interface of `tartarus-mcp`. It did not call gateway implementation functions directly.

The live test completed these operations:

- Discover Ghidra 11.4.2, radare2, GDB 15.2, and telemetry.
- Upload and run an agent-supplied Ghidra Java script. The script identified the fixture and counted 1,830 Ghidra functions.
- Decompile, disassemble, and get cross-references for `entry` through the standard Ghidra tools.
- Connect GDB to the sandbox `gdbserver`, inspect threads, registers, stack memory, instructions, and mappings, set a breakpoint, step one instruction, and detach.
- Check local Elastic health and retrieve events scoped to the run identifier.

The gateway created 12 ToolResult artifacts during the live test, including the first failed custom Ghidra request. All 12 files were present at the paths in their run-manifest records. The failure identified that Ghidra uses a semicolon between custom script directories. The corrected request succeeded.

The audit found that `r2mcp` 1.8.8 was not ABI-compatible with radare2 6.0.4. Tartarus now pins radare2 6.1.8, the release used by the radare2 MCP build, and connects to the native MCP server through `tartarus-r2mcp`.

A third run, `r2mcp-e2e-20261012b`, validated the native `Radare2 MCP Connector` 1.8.8 through the local proxy. The native server advertised 42 radare2 tools in two result pages. It opened the fixture, completed level-2 analysis, found 1,688 functions, identified `main` and `entry0`, and returned binary information, entry points, decompiler inventory, decompilation, disassembly, and cross-references.

The first native request also found a deployment permission defect. The REMnux analysis user owned the static-analysis directory but could not traverse `/var/spool/tartarus`. The REMnux role now permits traversal of that parent while it keeps each child directory access-controlled. The repeated native session succeeded.

The native test created 23 radare2 MCP ToolResult artifacts and one `analysis_capabilities` artifact. The retained artifacts include failed and successful calls. The manifest recorded the path, byte size, and collection status for each artifact.

The first teardown exposed a stale Tartarus role on the Ludus server. The stale role tried to install radare2 6.0.4 after the live upgrade to 6.1.8. Ludus rejected the downgrade, and Tartarus correctly recorded `collected_with_gaps` and `sandbox_rebuild_failed`. The controller then updated the registered Tartarus source and completed a forced deployment with the current role.

The final run, `r2mcp-e2e-20261012c`, repeated native tool discovery and analysis after that deployment. It discovered all 42 tools across both MCP result pages. It retained eight native radare2 ToolResult artifacts and one capability artifact. All nine artifacts were present with the sizes recorded in the manifest. The final run has `status: collected`, `recovery_verified: true`, and no visibility gaps. Its rebuilt sandbox passed the complete range verifier.

## AI reporting validation

The `tartarus report generate` command was tested end to end against the completed
`r2mcp-e2e-20261012c` benign run with the installed Codex CLI and its configured provider.
Codex inspected the permitted retained evidence and returned the versioned `AnalysisHandoff`
structure. Tartarus rejected the first handoff because one cited filename differed from the
inventory by one character. The bounded repair loop returned the validation failure to Codex.
The second handoff corrected the citation and passed schema, path, function-artifact, completion,
and reporting-scope validation.

The rendered report is 35,081 bytes and contains all 17 required report sections. It records five
static findings, three function-analysis entries, five dynamic findings, three network findings,
and nine explicit visibility gaps. It correctly reports no supported IOC, ATT&CK mapping,
attribution, or Sigma rule for the benign fixture. The final state is `analysis_incomplete`
because only `entry0` has complete retained decompilation and disassembly, the two retained
function totals conflict, and alternate BusyBox applet paths were not exercised. The report links
each material claim to an existing run-relative evidence file and records the passing and failing
completion gates explicitly.
