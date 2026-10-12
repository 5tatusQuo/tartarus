# Tartarus

<p align="center">
  <img src="assets/tartarus-icon.png" alt="Tartarus project icon" width="192">
</p>

Tartarus is a portable controller for a contained Ludus Linux analysis range.
It analyzes Executable and Linkable Format (ELF) files.

The compact profile supplies these components:

- An Elasticsearch, Logstash, and Kibana (ELK) server
- A REMnux analysis server
- A disposable Debian sandbox
- A Ludus router with deny-by-default rules

> **WARNING:** Do not run an untrusted file until range verification passes.
> A failed verification can identify a containment or evidence risk.

## Requirements

Use Python 3.11 or a later version.
Use a supported Ludus installation and a Proxmox environment.

The compact profile requires these minimum host resources:

- 16 logical processors
- 16 GiB of memory
- 220 GiB of free storage
- 20 percent free storage capacity

## Install the controller

1. Create a Python virtual environment.

   ```bash
   python3 -m venv .venv
   ```

2. Activate the virtual environment.

   ```bash
   . .venv/bin/activate
   ```

3. Install the locked dependencies.

   ```bash
   python -m pip install -r requirements.lock
   ```

4. Install the controller from this repository.

   ```bash
   python -m pip install --no-deps -e .
   ```

5. Make sure that the command is available.

   ```bash
   tartarus --help
   ```

## Configure the controller

Keep installation addresses in the local configuration.
Do not commit these addresses to the repository.

Create the configuration and run the host checks:

```bash
tartarus init \
  --profile compact \
  --evidence-root /secure/tartarus-evidence \
  --cache-root /secure/tartarus-cache \
  --host-memory-gib 16 \
  --management-source 198.51.100.2/32 \
  --always-blocked-network 192.0.2.0/24
tartarus doctor
```

The Classless Inter-Domain Routing (CIDR) values are installation inputs.
Replace the example values with the values for your environment.

### Select a guest transport

Secure Shell (SSH) is the default guest transport.

Use the Proxmox guest-agent transport when these conditions apply:

- The controller can connect to Proxmox.
- The controller cannot route traffic to the range networks.

Add these values to the generated configuration:

```toml
remote_transport = "proxmox-agent"
proxmox_url = "https://proxmox.example:8006"
proxmox_ca_file = "/path/to/proxmox-ca.pem"
```

The guest-agent transport uses the Proxmox credentials that Ludus supplies.
It applies size limits to commands, uploads, and evidence downloads.

> **CAUTION:** Keep `proxmox_tls_verify` enabled on production networks.
> Disable it only on an explicitly trusted laboratory network.

## Prepare and deploy the range

1. Download and verify the locked artifacts.

   ```bash
   tartarus prepare --yes
   ```

2. Deploy the range.

   ```bash
   tartarus deploy --yes
   ```

3. Record the range identifier from the deployment output.

4. Verify the deployed range.

   ```bash
   tartarus verify --range-id <range-id>
   ```

The verifier checks containment, telemetry, tracing, capture, and GNU Debugger (GDB) controls.
It also checks audit loss, capacity, tool versions, and recovery readiness.
The verifier fails closed when a required check fails.

## Get operator access

Get the Kibana login and the guest Secure Shell (SSH) connection data:

```bash
tartarus credentials show --range-id <range-id>
```

The command prints the generated Kibana password. Protect the terminal output.
Use the `elastic` account to sign in to Kibana.

Use the listed guest username and the listed controller private key for SSH.
Tartarus installs this key during deployment.
Do not use the image bootstrap password after deployment.

The `kibana_system` account and the Elastic Agent API key are service credentials.
Do not use them for an interactive login.
Ludus manages the Proxmox credentials and the WireGuard configuration.

Commands that change state show their resolved scope.
Use `--yes` to approve a high-impact change or sample execution.
Use `--confirm` to approve permanent range removal or a manual sandbox rebuild.

The `prepare` command creates a temporary source upload.
It adds the operator CIDR values to that upload.
It does not change the repository.

## Analyze an ELF file

1. Create an evidence case.

   ```bash
   tartarus case create --case-id demo
   ```

2. Stage the ELF file.

   ```bash
   tartarus sample stage --case-id demo ./benign-elf
   ```

   Record the `sample_id` from the command output.

3. Start the analysis run.

   ```bash
   tartarus run start \
     --range-id <range-id> \
     --case-id demo \
     --sample-id <sample-id> \
     --telemetry-profile standard \
     --yes
   ```

4. Collect an additional local artifact if necessary.

   ```bash
   tartarus run collect \
     --case-id demo \
     --run-id <run-id> \
     ./capture.pcapng
   ```

5. Stop the run and recover the sandbox.

   ```bash
   tartarus run stop \
     --case-id demo \
     --run-id <run-id> \
     --yes
   ```

The stop operation completes the packet capture and bounded traces.
It transfers the evidence to controller-owned storage.
It checks that each transferred file arrived with the expected size.

The operation then destroys and redeploys the sandbox.
It runs the live verification suite on the replacement sandbox.
Tartarus does not accept a new run until recovery verification passes.

The controller does not give a guest write access to the evidence root.

## Examine the evidence

Each completed run contains a `run.json` manifest and a `report.md` report.
The manifest records artifact paths, sizes, and collection status.
It also records visibility gaps and the sandbox recovery result.

Create a separate report if necessary:

```bash
tartarus report generate \
  --case-id <case-id> \
  --run-id <run-id> \
  --output <path>
```

This command does not overwrite the report in the run directory.

Treat all sample-derived text and analysis results as untrusted data.

## Containment controls

The Ludus router is the external enforcement point.
It rejects these traffic types:

- Public network traffic
- Infrastructure network traffic
- Guest-to-management traffic
- Inter-VLAN traffic that the configuration does not declare

The guests do not use Internet Protocol version 6 (IPv6).
The sandbox runs the sample from an unprivileged account.
Systemd applies process, memory, processor, duration, and file-size limits.

The local `tartarus-mcp` server uses standard input and standard output.
It is the primary tool interface for the analysis agent.
The analysis agent uses it to control telemetry, Ghidra, and GDB in the local range.
The `tartarus-r2mcp` proxy connects the agent to the native radare2 MCP server on REMnux.

The [analysis-agent instructions](AGENTS.md) define the required MCP workflow and the evidence completion gate.
The gateways support native radare2 MCP tools, GDB command sequences, agent-supplied Ghidra scripts, run-scoped telemetry searches, and capability discovery.
They record each MCP call as a run artifact before they return the result.
See [MCP client configuration](mcp/README.md#client-configuration) for both local server commands.

## Build and release controls

By default, `prepare` accepts only a clean immutable commit or tag.
Use `--development` only for local source tests.

Tartarus downloads version-pinned third-party packages into the user cache.
It checks that the packages are present before it adds them to the temporary Ludus source.
It does not add these packages to a release archive.

The project locks `badsectorlabs.ludus_remnux` version 1.0.1 for source compatibility.
The owned image build uses the version-pinned REMnux 1.4.3 installer.
It uses REMnux distribution `v2024.44.3`.

## Verify portability

1. Deploy the same immutable release and profile on two new Ludus hosts.

2. Compare the deployment manifests.

   ```bash
   python scripts/compare_deployments.py first.json second.json
   ```

The comparison excludes installation identities, addresses, credentials, and timestamps.
It also excludes rendered controller keys.
Packages, kernels, artifacts, images, templates, schemas, and source inputs must match.

## Project documents

- [Portable public plan](PORTABLE-PUBLIC-PLAN.md)
- [Security and operating constraints](SECURITY.md)
- [Analysis-agent instructions](AGENTS.md)
- [Analysis-agent validation](docs/ANALYSIS-AGENT-VALIDATION.md)
- [Optional external traffic capture](docs/EXTERNAL-CAPTURE.md)

Tartarus does not automatically change the Proxmox host for external traffic capture.

## Controlled-language statement

This README uses ASD-STE100-style controlled English.
The document is not an ASD-STE100 compliance certificate.
Technical names, command names, and software terms remain unchanged where necessary.

## License

The project does not grant a license.
Release archives do not contain third-party artifacts.
Tartarus gets these artifacts from their upstream publishers.
