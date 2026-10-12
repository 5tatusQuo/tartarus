# Tartarus Compact Reference Deployment Plan

**Status:** Implemented in source; deployment-specific acceptance testing required
**Reference target:** A small, single-node Ludus/Proxmox host with 16 GiB RAM and 8 cores/16 threads
**Portable project plan:** [PORTABLE-PUBLIC-PLAN.md](PORTABLE-PUBLIC-PLAN.md)

## 1. Purpose

This document defines the first end-to-end Tartarus deployment profile. It turns the broader portable project into a concrete three-VM Linux malware-analysis range that can run on a modest Ludus machine without weakening the containment or evidence requirements.

The reference host used to derive this profile had approximately 15.35 GiB RAM, 8 physical cores/16 threads, and ample local storage. Those values are a compatibility target, not identifiers or assumptions embedded in the project. Tartarus must discover equivalent resources on each operator's host before deployment.

The range consists of:

1. **ELK-01:** Elasticsearch, Kibana, log ingestion, telemetry correlation, and analysis metadata.
2. **REMNUX-01:** INetSim, network capture, Ghidra, radare2, GDB, and controlled MCP adapters.
3. **LINUX-SBX-01:** A disposable Debian sandbox for executing Linux ELF samples.
4. **Ludus router:** External enforcement point for VLAN routing, egress controls, and management access.

The sandbox and REMnux exchange only experiment traffic. Both send narrowly permitted telemetry to ELK. The controller runs outside the range, pulls evidence from guests, and never places Ludus or Proxmox credentials inside a VM.

## 2. Reference resources

| Component | Template | vCPU | RAM | Role |
|---|---|---:|---:|---|
| ELK-01 | Tartarus Debian 12 | 4 | 4 GiB | Elasticsearch, Kibana, ingest |
| REMNUX-01 | Tartarus Ubuntu 20.04/REMnux | 2 | 4 GiB | Fake services, capture, reverse engineering |
| LINUX-SBX-01 | Tartarus Debian 12 | 2 | 2 GiB | Disposable execution guest |
| Ludus router | Supported Ludus router template | 2 | 2 GiB maximum, 1 GiB minimum | Routing and containment |

The configured maximum is 12 GiB of guest RAM including the router. Deployment must leave at least 15% host RAM available and must fail rather than rely on sustained swapping.

ELK runs as a secured single-node stack with a 2 GiB Elasticsearch JVM heap. The compact profile deliberately omits Fleet Server and Logstash. It uses standalone Elastic Agent with Elastic Defend disabled.

If simultaneous boot, a benign workload, or Ghidra analysis causes sustained host swap or leaves less than the memory reserve, this profile is not accepted on that host. The operator must reduce unrelated workloads or use the `standard` profile from the portable plan.

## 3. Network and containment

Ludus assigns one interface to each VM, so the logical security zones are separate VLANs routed by the Ludus router rather than multiple guest NICs. Ludus documents this single-interface and per-range VLAN model in its [networking guide](https://docs.ludus.cloud/docs/infrastructure-operations/networking/).

| VLAN | Logical zone | Members |
|---:|---|---|
| 10 | Monitoring | ELK-01 |
| 20 | Analysis services | REMNUX-01 |
| 30 | Untrusted execution | LINUX-SBX-01 |

Complete addresses are resolved from `ludus range inventory`; no range number or subnet is hardcoded.

The range policy uses:

- `external_default: REJECT`
- `inter_vlan_default: REJECT`
- `wireguard_vlan_default: REJECT`
- Operator-supplied management CIDRs and always-blocked infrastructure networks
- IPv6 disabled in guests unless equivalent routed filtering has been explicitly configured and tested

Only these flows are permitted:

| Source | Destination | Traffic |
|---|---|---|
| Sandbox | REMnux | Experiment traffic and simulated services |
| REMnux | Sandbox | TCP 2345 during an approved `gdbserver` session |
| Sandbox/REMnux | ELK | Authenticated TLS ingestion on TCP 9200 |
| Approved management client | ELK | SSH and Kibana |
| Approved management client | REMnux/sandbox | Controller SSH operations and evidence pulling |

Guests cannot initiate connections to WireGuard clients, public networks, the Proxmox host, the Ludus API, or operator-defined infrastructure networks. Isolation tests are repeated with the sandbox guest firewall disabled to prove that enforcement occurs on the Ludus router.

Ludus testing mode remains enabled as an additional egress barrier. ELK and REMnux use `testing.snapshot: false`; the sandbox is snapshot-eligible. A testing-mode rollback is allowed for benign validation only. Every untrusted run ends with sandbox destruction and redeployment.

## 4. Reproducible provisioning

The reference deployment uses the Tartarus source and bootstrap CLI defined in the portable plan. It does not rely on templates, roles, or packages already installed by another range.

Required locked components include:

- Ludus 2.3.7 or a tested compatible later release
- Tartarus-owned Debian 12 and Ubuntu 20.04/REMnux templates
- Elastic Stack and Elastic Agent 9.5.5
- `badsectorlabs.ludus_remnux` 1.0.1
- The local Tartarus MCP gateway plus the native radare2 MCP server
- Pinned Ghidra, radare2, GDB, INetSim, Zeek, and sandbox package versions recorded in `versions.lock.yml`

The REMnux role is applied only to its supported Ubuntu 20.04 base. Its upstream requirements explicitly name that template; Tartarus must fail on a distribution mismatch rather than attempt an untested installation. See the [REMnux Ludus role](https://github.com/badsectorlabs/ludus_remnux).

Package acquisition and template creation happen during a trusted preparation phase. Runtime guests start under the final locked network policy and do not require general internet access for deployment, reset, or analysis.

Generated TLS keys, Elastic API keys, SSH material, and passwords are installation-specific secrets. Ansible tasks handling them use `no_log`, and none are stored in the blueprint, range configuration, repository, run manifest, or diagnostic output.

## 5. Telemetry and storage

### Always-on collection

- `auditd` owns the Linux audit subsystem and records process execution, privilege-relevant activity, and writes to selected persistence/configuration paths.
- `systemd-journald` records kernel, boot, service, authentication, and collector failures with bounded retention.
- Standalone Elastic Agent ships audit logs, journal/system logs, and 30-second host metrics. Elastic Defend and Auditd Manager are not enabled.
- REMnux records INetSim requests and capture status/drop counters.
- The run controller emits lifecycle records for start, stop, profile, sample hash, host role, and evidence export.

### On-demand collection

- `strace -f` with duration and output limits
- Targeted `bpftrace` programs validated for the pinned kernel
- `/proc`, `ss`, `lsof`, process-tree, and memory-map snapshots
- Before/after filesystem hashing for selected paths
- Bounded `dumpcap` PCAP capture
- GDB client on REMnux connected to a short-lived sandbox `gdbserver`

The `lightweight`, `standard`, and `deep` telemetry profiles control only on-demand instrumentation. They do not alter containment.

Raw PCAP, traces, samples, memory captures, Ghidra projects, and reports remain outside Elasticsearch. The controller pulls them into its configured evidence root using:

```text
<evidence-root>/<case_id>/<run_id>/
```

Guests receive no write access to controller storage. Each artifact is hashed before and after transfer. The default quota is 20 GiB per run; insufficient guest spool or controller capacity blocks execution unless the operator approves an explicit override.

Elasticsearch stores normalized events, artifact metadata, hashes, run boundaries, and visibility gaps. High-volume telemetry defaults to 14-day retention and run/manifest metadata to 30 days, with values configurable per installation.

## 6. Reverse-engineering and AI interfaces

An inert copy of each ELF is staged on REMnux and hash-verified. It is never executed there.

- The headless Ghidra adapter exposes import, functions, disassembly, decompilation, strings, cross-references, and agent-supplied Java analysis scripts for the current sample and project.
- The native radare2 MCP server exposes its analysis, function, string, import, export, section, symbol, cross-reference, decompilation, and disassembly tools through the local `tartarus-r2mcp` proxy.
- The GDB adapter accepts multi-command analysis sequences for the current sandbox `gdbserver`. It supports breakpoints, watchpoints, stepping, threads, registers, stacks, memory, signals, and controlled state changes.
- Every MCP tool result is stored as a hashed artifact in the current run manifest.
- MCP services use local stdio or stdio over SSH. No MCP listener binds to a malware-facing guest interface.

The controller exposes lifecycle commands separately from the analysis MCP tools:

```text
tartarus range prepare|deploy|status|verify|destroy
tartarus case create
tartarus sample stage
tartarus run start|stop|collect
tartarus sandbox rebuild
tartarus telemetry health|search
tartarus report generate
```

Every execution operation requires a `run_id` and enforces timeout, CPU, memory, process-count, file-size, trace-size, and artifact-size limits. Root sample execution, external network exceptions, destructive range removal, and quota overrides require explicit approval.

Sample strings, debugger output, disassembly, packet contents, and log messages are always untrusted data and cannot modify tool policy or become controller instructions.

## 7. Per-run lifecycle

1. Create `case_id` and `run_id`; record the sample SHA-256, profile, image/build manifest, and tool versions.
2. Verify the sandbox is newly deployed, clocks are synchronized, forbidden routes are blocked, fake services and ELK are healthy, capture is ready, and evidence capacity is available.
3. Perform static ELF triage and optional Ghidra/radare2 analysis from an inert REMnux copy.
4. Start PCAP and requested probes before transferring the sample to a unique sandbox run directory.
5. Verify the sandbox copy's SHA-256 and execute it as the unprivileged `tartarus-runner` inside systemd/cgroup resource limits.
6. Stop the complete process tree, close `gdbserver`, finalize traces and PCAP, and record audit/packet loss and backpressure.
7. Pull artifacts to the controller, rehash them, ingest searchable metadata, and generate the run report and canonical JSON manifest.
8. Destroy and redeploy the sandbox from the pinned template.
9. Repeat isolation and telemetry smoke tests before marking the range ready.

## 8. Acceptance tests

### Reproducibility

- Deploy exclusively from a tagged Tartarus source and declared local inputs.
- Validate the blueprint against the installed Ludus schema.
- Run every role twice without unintended changes.
- Verify image, package, adapter, and integration versions against `versions.lock.yml`.

### Capacity and performance

- Boot the router and all three VMs without sustained host swap.
- Preserve at least the configured host memory and disk reserve.
- Measure CPU, RSS, disk writes, ingest volume/latency, audit loss, and packet loss for all telemetry profiles.
- Make a benign sampled event searchable within 60 seconds.

### Isolation

- Block public IPv4/IPv6, public DNS, management clients, Proxmox, Ludus, and operator-defined infrastructure networks from the sandbox.
- Repeat the tests after disabling its guest firewall.
- Permit only the intended REMnux, ingestion, and temporary debugging flows.

### Telemetry and analysis

- Observe benign process execution, a persistence-path write, journal/kernel output, and metrics in Elasticsearch.
- Observe sandbox-to-REMnux DNS and HTTP activity in INetSim logs and PCAP.
- Produce size-controlled `strace` and filesystem-difference artifacts.
- Disassemble a benign ELF through Ghidra and radare2 MCP.
- Set a breakpoint, step, inspect registers and memory, and query mappings through GDB MCP; prove the port closes afterward.
- Detect deliberate audit loss, packet drops, output backpressure, and quota exhaustion.

### Recovery

- Complete a benign run and evidence export.
- Destroy/redeploy the sandbox.
- Prove no sample, process, run credential, or altered configuration survives.
- Re-run containment and telemetry checks and validate every controller-side artifact hash.

## 9. Deferred capabilities

- Proxmox/vSwitch traffic mirroring is opt-in host maintenance. Ludus documents that disabling bridge ageing requires root-level Proxmox configuration; it is not changed automatically by Tartarus.
- Fleet, a dedicated evidence appliance, WORM storage, kernel-malware execution, Windows analysis guests, ARM guests, and controlled real-internet experiments are outside the compact v1 profile.
- A host that cannot pass the compact capacity gate must use a larger machine or a different profile; Tartarus does not time-share core evidence services during a run.
