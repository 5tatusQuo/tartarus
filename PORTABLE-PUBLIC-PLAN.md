# Tartarus Portable Public Project Plan

**Status:** Implemented public-source contract; tagged-release acceptance remains release-specific
**Initial tested profile:** [COMPACT-REFERENCE-PLAN.md](COMPACT-REFERENCE-PLAN.md)

## 1. Project outcome

Tartarus will be published as a self-contained Ludus source plus a Python bootstrap and analysis controller. Operators supply their own Ludus/Proxmox environment, credentials, management networks, evidence storage, and capacity profile.

The repository must not embed an operator identity, range ID, range number, IP subnet, Ludus URL, Proxmox URL, WireGuard address, home directory, credentials, or assumptions about resources installed for another range.

Initial platform support is:

- Ludus 2.3.7 as the minimum tested release, plus explicitly tested later releases
- AMD64 Ludus/Proxmox hosts
- Linux and macOS controllers with Python 3.11 or later
- Windows controllers through WSL2; native Windows is deferred
- Installation into a fresh Ludus instance or alongside unrelated existing ranges

Tagged releases are reproducibility boundaries. Documentation and automation must use a Git tag or immutable commit rather than an unpinned `main` branch.

No project `LICENSE` file will be added. Third-party code and binaries are fetched from their upstream locations rather than copied into Tartarus releases.

## 2. Public repository structure

```text
tartarus/
├── README.md
├── SECURITY.md
├── CONTRIBUTING.md
├── CHANGELOG.md
├── COMPACT-REFERENCE-PLAN.md
├── PORTABLE-PUBLIC-PLAN.md
├── source.yml
├── pyproject.toml
├── versions.lock.yml
├── blueprints/
│   ├── tartarus-compact/
│   ├── tartarus-standard/
│   └── tartarus-large/
├── templates/
│   ├── tartarus-debian-12/
│   └── tartarus-remnux-ubuntu-20.04/
├── ansible/roles/
├── controller/
├── mcp/
├── policies/
├── schemas/
└── tests/
```

Package the blueprints, templates, roles, and collections using the documented [Ludus source layout](https://docs.ludus.cloud/docs/using-ludus/sources/). Each blueprint contains standard metadata, range configuration, and pinned requirements as described in the [Ludus blueprint documentation](https://docs.ludus.cloud/docs/using-ludus/blueprints/).

Use Tartarus-prefixed resource names. Existing templates or roles with generic/upstream names cannot silently satisfy Tartarus dependencies.

## 3. Installation experience

The primary public workflow is:

```text
git clone <public-repository>
cd tartarus
python3 -m pip install .
tartarus init
tartarus doctor
tartarus prepare
tartarus deploy
tartarus verify
```

### Command responsibilities

- `tartarus init` creates user-local configuration and records the Ludus CLI configuration, optional Proxmox URL, evidence root, management sources, always-blocked networks, and desired profile.
- `tartarus doctor` performs read-only compatibility and capacity discovery.
- `tartarus prepare` registers the exact Tartarus release, downloads and verifies dependencies, and builds missing Tartarus templates.
- `tartarus deploy` creates a new range for the authenticated Ludus user and applies the selected blueprint.
- `tartarus verify` runs benign containment, telemetry, analysis, resource, and recovery acceptance tests.
- `tartarus destroy` removes only the explicitly selected Tartarus-managed range and requires confirmation.

Every mutating command prints the resolved server, authenticated user, range, release, capacity profile, resource requirements, and exact intended changes before acting. It never deletes or overwrites an unrelated range, VM, template, source, or evidence directory.

Use `platformdirs` for local storage and support these overrides:

- `TARTARUS_CONFIG`
- `TARTARUS_CACHE_ROOT`
- `TARTARUS_EVIDENCE_ROOT`
- `TARTARUS_LUDUS_CONFIG`

WireGuard configuration export is a separate command that writes directly to a caller-selected file with mode `0600`. It never prints private keys and never enables or modifies a VPN connection automatically.

## 4. Discovery and profiles

### Read-only discovery

`tartarus doctor` collects:

- Ludus client/server versions and API reachability
- Authenticated user and accessible ranges
- Existing sources, blueprints, templates, roles, and collections
- CPU and datastore information from `ludus diagnostics`
- Proxmox node memory and current resource consumption when an explicit `proxmox_url` is configured
- Required upstream and ISO reachability, or availability of an offline bundle
- Local/routed address conflicts with the future range
- Controller evidence-storage capacity

When Proxmox credentials are obtained through Ludus, they remain in memory and are sent only to the operator-configured Proxmox endpoint. They cannot appear in subprocess arguments, logs, errors, manifests, shell history, configuration files, or diagnostic bundles.

The Ludus API may not expose host RAM on every edition. If memory cannot be discovered safely, `doctor` requires `--host-memory-gib` or explicit profile selection and records the value as operator-supplied. It never guesses.

### Capacity profiles

| Profile | Minimum host | ELK | REMnux | Sandbox | Intended deployment |
|---|---:|---:|---:|---:|---|
| `compact` | 16 GiB RAM, 8 cores/16 threads | 4 vCPU, 4 GiB | 2 vCPU, 4 GiB | 2 vCPU, 2 GiB | Personal/small Ludus host |
| `standard` | 32 GiB RAM | 6 vCPU, 8 GiB | 4 vCPU, 6 GiB | 4 vCPU, 4 GiB | Recommended general deployment |
| `large` | 64 GiB RAM | 8 vCPU, 24 GiB | 6 vCPU, 12 GiB | 4 vCPU, 8 GiB | High-volume analysis |

Router resources are included in capacity calculations. Deployment fails if it would leave less than 15% RAM, 20% datastore space, or a larger operator-configured reserve.

Profiles change capacity and retention defaults only. Containment, evidence integrity, reset behavior, and security gates are invariant.

## 5. Reproducible build inputs

- Supply Tartarus-owned Packer definitions for Debian 12 and Ubuntu 20.04/REMnux rather than binding to an operator's similarly named template.
- Pin ISO URLs and hashes, operating-system packages, Elastic artifacts, integration assets, Python dependencies, Ghidra scripts, and MCP adapters in `versions.lock.yml`.
- Pin Elastic Stack and Agent 9.5.5, the REMnux Ludus role 1.0.1, and the analysis-engine versions used by the local Tartarus MCP gateway.
- Record every resolved URL, hash, package version, template build identifier, and Tartarus commit in `DeploymentManifest`.
- Verify upstream checksums before installation and Tartarus-recorded hashes before reuse from cache.
- Fail on an operating-system, architecture, kernel, dependency, or checksum mismatch; do not silently upgrade or fall back.

Third-party artifacts are downloaded during `prepare` into a user cache excluded from version control. Release archives contain lock metadata and retrieval logic, not redistributed third-party binaries.

Support:

```text
tartarus bundle create
tartarus bundle verify
tartarus prepare --offline <bundle>
```

An offline bundle contains verified artifacts and a signed or hash-verified inventory. It never contains credentials, WireGuard material, samples, evidence, or generated deployment secrets.

## 6. Portable range design

Use stable relative VLANs within the range allocated by Ludus:

- VLAN 10: monitoring/ELK
- VLAN 20: REMnux/analysis services
- VLAN 30: disposable sandbox

Use stable last-octet assignments but resolve complete addresses from `ludus range inventory`. Ludus assigns one network interface per VM, so the router and VLAN policy form the external containment boundary. See [Ludus networking](https://docs.ludus.cloud/docs/infrastructure-operations/networking/).

Default policies are:

- External traffic: `REJECT`
- Inter-VLAN traffic: `REJECT`
- WireGuard-to-VLAN traffic: `REJECT`
- Guest IPv6: disabled until equivalent IPv6 routing policy is configured and tested

`init` requires operators to identify management sources and always-blocked infrastructure networks. Tartarus does not assume a particular LAN or WireGuard subnet.

Permitted flows are limited to sandbox-to-REMnux experiment traffic, short-lived REMnux-to-sandbox GDB, authenticated guest-to-ELK ingestion, and approved management-to-SSH/Kibana access. Guest-initiated access to management clients, Ludus, Proxmox, infrastructure networks, and public networks is denied.

The trusted build phase may access upstream artifacts. A deployed range begins under the final offline policy and must not reopen guest internet access for installation, reset, or routine operation.

Do not change Proxmox bridge ageing or other host networking automatically. Publish a separate opt-in external-capture procedure for operators who explicitly perform the required root maintenance. The baseline captures experiment traffic at REMnux and reports that trust limitation.

## 7. Telemetry, evidence, and run correlation

The baseline uses:

- A single-node, TLS-protected Elasticsearch/Kibana deployment
- Standalone Elastic Agent on REMnux and the sandbox
- No Elastic Defend, Fleet Server, Logstash, or competing audit subsystem owner
- Narrow `auditd` rules, bounded journald, 30-second system metrics, INetSim logs, and controller lifecycle events
- On-demand PCAP, `strace`, targeted `bpftrace`, process/socket snapshots, filesystem differences, GDB, and memory inspection

Fleet may be added later as an opt-in feature; it cannot change the canonical event and run manifest schemas.

Generate installation-specific TLS and API credentials during deployment. Ansible uses `no_log`; secrets are delivered only to their intended services and controller key storage. They never appear in blueprints, Git, exported range configuration, reports, or test fixtures.

Store raw samples, PCAPs, traces, memory images, Ghidra projects, and reports under the controller-selected evidence root. Guests cannot push to or enumerate that store. The controller pulls each artifact and verifies its hash again after transfer.

Canonical correlation fields include:

- `case_id`
- `run_id`
- `sample.sha256`
- logical host and observer roles
- original and normalized timestamps
- telemetry profile
- Tartarus release and deployment-manifest hash
- artifact hash, relative path, media type, size, and collection status
- visibility gaps and dropped-event counters

Use timestamp/host/process joins for native kernel or audit events that cannot safely carry a dynamic `run_id`. Preserve original event time and the run interval used for correlation.

## 8. Controller and public interfaces

Stable commands:

```text
tartarus init
tartarus doctor
tartarus range prepare|deploy|status|verify|destroy
tartarus case create
tartarus sample stage
tartarus run start|stop|collect
tartarus sandbox rebuild
tartarus telemetry health|search
tartarus report generate
tartarus bundle create|verify
tartarus wireguard export
```

Stable versioned JSON schemas:

- `EnvironmentReport`
- `DeploymentManifest`
- `CaseManifest`
- `RunManifest`
- `ArtifactRecord`
- `VerificationReport`
- `ApprovalRequest`
- `ToolResult`

The local MCP gateway exposes analysis-engine operations for the current run. It does not use a cloud service.

- Ghidra supports its standard analysis operations and agent-supplied Java scripts in the current project.
- The native radare2 MCP server runs on REMnux and is connected to the agent through the local `tartarus-r2mcp` standard-input and standard-output proxy.
- GDB supports multi-command debugging of the current short-lived sandbox `gdbserver`, including controlled state changes.
- Each MCP request and result is retained as a hashed run artifact.
- MCP uses stdio or stdio over SSH; no listener binds to an analysis-facing interface.

Root execution, external network exceptions, destructive range removal, quota overrides, and changes to containment policy require explicit operator approval. All sample-derived content is treated as untrusted data.

## 9. Run and recovery contract

1. Create a case and run manifest and hash the sample on the controller.
2. Verify a clean sandbox, final network policy, clock synchronization, ELK/agent health, REMnux services, capture readiness, and evidence capacity.
3. Perform static analysis from an inert REMnux copy.
4. Start capture and selected probes before staging the sandbox copy.
5. Verify the sandbox hash and execute with privilege, duration, CPU, memory, process-count, and output limits.
6. Stop the process tree and debugger, finalize telemetry, and record drop/backpressure counters.
7. Pull and rehash artifacts, ingest metadata, and generate a report plus canonical manifest.
8. Destroy and redeploy the sandbox from the pinned template after every untrusted run.
9. Re-run isolation and telemetry smoke tests before accepting another run.

Snapshot rollback is limited to benign acceptance fixtures. It is not the recovery mechanism for untrusted execution.

## 10. Public repository and release gates

### Pull-request CI

- Python unit and integration tests across supported versions and controller platforms
- JSON Schema compatibility tests
- Ludus configuration validation against the minimum and current supported schema
- `ansible-lint`, YAML lint, syntax, handler, and idempotency tests
- Packer format and validation without downloading/building images
- Lockfile and checksum verification
- Secret scanning and checks for real operator names, paths, addresses, tokens, private keys, samples, and evidence
- Redaction tests covering CLI output, structured logs, errors, reports, and diagnostics
- Failure tests for unsupported versions, capacity shortfall, address conflict, offline dependency gaps, interrupted deployment, and stale state

### Tagged-release test

1. Begin with a Ludus instance containing no Tartarus resources.
2. Install exclusively from the proposed immutable tag.
3. Build the Tartarus templates and deploy the compact profile.
4. Execute the complete benign telemetry, capture, static-analysis, and GDB fixture.
5. Export and verify evidence, then destroy/redeploy the sandbox.
6. Repeat isolation and telemetry tests after recovery.
7. Remove the Tartarus range and prove unrelated resources remain unchanged.
8. Validate standard and large blueprint generation; run them on suitably sized hosts when available.
9. Publish redacted deployment and verification manifests with the release.

### Portability acceptance

Two fresh Ludus machines using the same Tartarus tag, capacity profile, and declared inputs must produce equivalent templates, policies, packages, tool versions, schemas, and acceptance outcomes.

Permitted machine-specific differences are limited to:

- Generated range IDs and addresses
- Installation credentials and certificates
- Host capacity and storage identifiers
- Timestamps
- Controller configuration and evidence paths

No deployment may depend on another user's range resources. Re-running `prepare` and every Ansible role must be idempotent. Interrupted operations must be resumable without deleting pre-existing infrastructure.

## 11. Scope boundaries

The first public release targets user-space Linux ELF analysis. Native Windows controllers, ARM hosts, Windows malware guests, kernel malware, bootkits, privileged container escape research, automatic Proxmox host changes, Fleet, dedicated evidence appliances, and intentional real-internet execution are deferred.

Operators remain responsible for securing their Ludus/Proxmox installation, authorizing possession and execution of samples, choosing retention policies, and meeting local legal or organizational requirements.
