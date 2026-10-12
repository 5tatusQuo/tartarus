# Analysis-agent validation

## Test identity

- Date: 2026-10-12
- Case: `benign-elf-final`
- Run: `agent-test-20261012b`
- Fixture: Debian BusyBox 1.35.0, x86-64 ELF
- SHA-256: `e33f1c2f043b9ea275056861f94041f9581601aedffc33df77f63a4f47ea12e4`
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

The collected run manifest records verified artifact hashes and successful sandbox recovery. The range returned to the `SUCCESS` state with all four virtual machines powered on.

## Defects found

The first Ghidra disassembly request failed with Ghidra 11.4 because `TartarusDisassembly.java` declared a helper named `getFunction`. That name conflicted with a final Ghidra API method. The helper is now named `findFunctionByName`. The next MCP request returned the function disassembly.

The range verifier also had two unrelated false failures. It used the obsolete HTTPS Kibana address, and it required host NTP synchronization even when the guest clock was correct. The verifier now uses the local HTTP Kibana address and checks the actual clock difference.

## Capability gaps

This test has the state `analysis_incomplete` against the full contract in `AGENTS.md`:

- The current GDB MCP has only register, single breakpoint-and-step, and small memory-read operations. The test run did not enable its debug session.
- The gateway does not retain each material MCP request and response as a hashed run artifact.
- The telemetry search did not isolate the sample activity cleanly from analysis and QEMU guest-agent activity.
- Binary Ninja and a Binary Ninja MCP server are not installed.
- The current Ghidra MCP does not expose all operations listed in the agent contract.

These are MCP implementation gaps. They are not limits that the analysis agent must accept. Complete these interfaces before the reporting agent treats a future analysis as complete.
