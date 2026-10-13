# Changelog

- Use verified clean-snapshot restoration for both analysis guests after every run, reducing
  recovery time while preserving evidence collection and the fail-closed readiness gate.

## 0.1.0 - unreleased

- Added the initial controller, evidence manifests, offline bundles, versioned schemas, Ludus blueprints, owned Packer definitions, baseline Ansible roles, and containment policies.
- Added live containment/telemetry/static-analysis/debugger acceptance probes, TLS Elastic ingestion, bounded run execution, verified evidence collection, automatic analysis-pair recovery, and report generation.
- Added version-pinned controller dependencies, ISOs and third-party artifacts, resumable deployment, collision-safe resource ownership, redacted release acceptance automation, and cross-host deployment comparison.
- Replaced manifest-summary reports with a Codex-driven evidence review, structured analysis handoff, citation and Sigma validation, completion gates, and bounded automatic repair.
- Added a pinned, resource-bounded YARA-X pre-analysis scan with a deterministic 379-rule
  Tartarus ELF pack derived from YARA Forge Full, normalized scan evidence for the analysis agent,
  YARA-only CLI and console workflows, and an isolated low-token handoff probe.
