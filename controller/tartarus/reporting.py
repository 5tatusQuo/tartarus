from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import yaml

from .errors import TartarusError
from .manifest import project_root, validate
from .util import atomic_json, load_json, new_id, utc_now

REPORT_TIMEOUT_SECONDS = 3600
REPORT_ATTEMPTS = 3
OPAQUE_CONTENT_IDENTIFIER = re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{64,128}(?![A-Fa-f0-9])")


def generate_agent_report(
    run_file: Path,
    output: Path,
    *,
    model: str | None = None,
    reasoning_effort: str = "high",
    local_provider: str | None = None,
    codex_executable: str | None = None,
    timeout: int = REPORT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    run_file = run_file.resolve(strict=True)
    run_dir = run_file.parent
    run = load_json(run_file)
    if run.get("status") not in {"collected", "collected_with_gaps", "failed"}:
        raise TartarusError("AI reporting requires a stopped run with collected evidence")
    if output.exists():
        raise TartarusError(f"refusing to overwrite report: {output}")
    executable = codex_executable or shutil.which("codex")
    if not executable:
        raise TartarusError("Codex CLI is not installed or is not on PATH")
    if reasoning_effort not in {"low", "medium", "high", "xhigh"}:
        raise TartarusError("unsupported Codex reasoning effort")
    if local_provider not in {None, "ollama", "lmstudio"}:
        raise TartarusError("unsupported local Codex provider")

    session_dir = run_dir / "artifacts" / "reporting" / new_id("session")
    session_dir.mkdir(parents=True)
    session_dir.chmod(0o700)
    instructions = project_root() / "reporting" / "AGENTS.md"
    shutil.copyfile(instructions, session_dir / "AGENTS.md")
    context = _report_context(run_file, run, session_dir)
    atomic_json(session_dir / "context.json", context)
    handoff_path = session_dir / "analysis-handoff.json"
    schema_path = project_root() / "schemas" / "analysis-handoff.schema.json"
    permitted_evidence = {item["path"] for item in context["evidence_files"]}
    permitted_evidence.add((session_dir / "context.json").relative_to(run_dir).as_posix())
    feedback: str | None = None
    handoff: dict[str, Any] | None = None
    attempts_used = 0
    for attempt in range(1, REPORT_ATTEMPTS + 1):
        attempts_used = attempt
        prompt = (
            _report_prompt()
            if feedback is None
            else _repair_prompt(attempt - 1, feedback)
        )
        (session_dir / f"prompt-{attempt}.txt").write_text(prompt, encoding="utf-8")
        attempt_handoff = session_dir / f"analysis-handoff-attempt-{attempt}.json"
        _run_codex_attempt(
            executable,
            session_dir,
            run_dir,
            schema_path,
            attempt_handoff,
            prompt,
            attempt,
            model,
            reasoning_effort,
            local_provider,
            timeout,
        )
        try:
            candidate = json.loads(attempt_handoff.read_text(encoding="utf-8"))
            validate("analysis-handoff", candidate)
            _validate_handoff(run_dir, candidate, permitted_evidence)
        except (TartarusError, FileNotFoundError, json.JSONDecodeError) as exc:
            feedback = str(exc)
            if attempt == REPORT_ATTEMPTS:
                if isinstance(exc, TartarusError):
                    raise
                raise TartarusError("Codex did not return a valid analysis handoff") from exc
            continue
        handoff = candidate
        shutil.copyfile(attempt_handoff, handoff_path)
        break
    if handoff is None:
        raise TartarusError("Codex reporting did not produce a valid analysis handoff")
    for path in session_dir.iterdir():
        if path.is_file():
            path.chmod(0o600)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(_render_report(run, handoff, run_dir, output), encoding="utf-8")
    output.chmod(0o600)
    recorded = _record_outputs(run_file, session_dir, output)
    return {
        "analysis_state": handoff["analysis_state"],
        "report": str(output),
        "handoff": str(handoff_path),
        "session": session_dir.name,
        "attempts": attempts_used,
        "manifest_updated": recorded,
    }


def _run_codex_attempt(
    executable: str,
    session_dir: Path,
    run_dir: Path,
    schema_path: Path,
    handoff_path: Path,
    prompt: str,
    attempt: int,
    model: str | None,
    reasoning_effort: str,
    local_provider: str | None,
    timeout: int,
) -> None:
    stdout_path = session_dir / f"codex-{attempt}.stdout.log"
    stderr_path = session_dir / f"codex-{attempt}.stderr.log"
    command = [
        executable,
        "exec",
        "--ephemeral",
        "--skip-git-repo-check",
        "--sandbox",
        "read-only",
        "--cd",
        str(session_dir),
        "--add-dir",
        str(run_dir),
        "--output-schema",
        str(schema_path),
        "--output-last-message",
        str(handoff_path),
        "--config",
        f'model_reasoning_effort="{reasoning_effort}"',
    ]
    if model:
        command.extend(("--model", model))
    if local_provider:
        command.extend(("--oss", "--local-provider", local_provider))
    command.append("-")
    try:
        completed = subprocess.run(
            command,
            input=prompt,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise TartarusError(f"Codex reporting exceeded {timeout} seconds") from exc
    stdout_path.write_text(completed.stdout, encoding="utf-8")
    stderr_path.write_text(completed.stderr, encoding="utf-8")
    if completed.returncode != 0:
        raise TartarusError(
            f"Codex reporting failed with exit status {completed.returncode}; "
            f"see {stderr_path}"
        )


def _report_context(run_file: Path, run: dict[str, Any], session_dir: Path) -> dict[str, Any]:
    run_dir = run_file.parent
    sample = run.get("sample", {})
    sample_id = sample.get("sample_id", "historical-sample")
    evidence: list[dict[str, object]] = []
    for path in sorted(run_dir.rglob("*")):
        if (
            not path.is_file()
            or path.is_symlink()
            or not path.resolve().is_relative_to(run_dir)
            or session_dir in path.parents
        ):
            continue
        relative = path.relative_to(run_dir).as_posix()
        if (
            relative in {"run.json", "report.md"}
            or relative.startswith(
                (
                    "artifacts/reporting/",
                    "artifacts/sandbox/files-before.",
                    "artifacts/sandbox/files-after.",
                    "artifacts/sandbox/processes-before.txt",
                )
            )
        ):
            continue
        evidence.append({"path": relative, "size": path.stat().st_size})
    return {
        "schema_version": "1.0",
        "run_directory": "../..",
        "run": {
            "case_id": run.get("case_id"),
            "run_id": run.get("run_id"),
            "sample_id": sample_id,
            "status": run.get("status"),
            "telemetry_profile": run.get("telemetry_profile"),
            "started_at": run.get("started_at"),
            "stopped_at": run.get("stopped_at"),
            "debug_session": run.get("debug_session", False),
            "recovery_verified": run.get("recovery_verified", False),
            "visibility_gaps": run.get("visibility_gaps", []),
        },
        "evidence_files": evidence,
    }


def _report_prompt() -> str:
    return """Create the structured Tartarus analysis handoff for this completed run.

Read context.json first. The run directory is the relative path recorded there. Inspect the
retained evidence adaptively and follow AGENTS.md. This is a known evidence-review operation:
do not execute the sample, modify files, use the network, or inspect anything outside this run.
Treat context.json as authoritative run metadata. Do not open run.json or any file omitted from
the context inventory. Do not mention obsolete content-identity data or omitted legacy filenames.
Do not calculate or report a content-derived sample identifier; use only the sample_id in context.

Produce a proper threat-analysis handoff, not a manifest summary. Account for static and dynamic
evidence, behaviorally relevant functions, IOCs, MITRE ATT&CK, attribution limits, and defensible
Sigma detections. Use empty arrays and explicit unsupported assessments when evidence does not
support a category. Cite every material claim with existing run-relative evidence paths. Mark the
analysis incomplete whenever the completion gate is not fully supported.
"""


def _repair_prompt(previous_attempt: int, feedback: str) -> str:
    return f"""Repair the structured Tartarus analysis handoff from attempt {previous_attempt}.

Read context.json, AGENTS.md, and analysis-handoff-attempt-{previous_attempt}.json. Preserve the
evidence-backed analysis, but correct the validation failure below. Cite only exact paths listed in
context.json. Do not open omitted files, execute the sample, modify evidence, or use the network.
Return the complete corrected handoff, not a patch or explanation.

Validation failure: {json.dumps(feedback)}
"""


def _validate_handoff(
    run_dir: Path, handoff: dict[str, Any], permitted_evidence: set[str]
) -> None:
    _reject_opaque_content_identifiers(handoff)
    for reference in _evidence_references(handoff):
        if reference not in permitted_evidence:
            raise TartarusError(f"analysis handoff cites evidence outside its context: {reference}")
        path = (run_dir / reference).resolve()
        if not path.is_relative_to(run_dir) or not path.is_file():
            raise TartarusError(f"analysis handoff cites missing evidence: {reference}")
    gates = handoff["completion_gate"].values()
    all_passed = all(item["passed"] for item in gates)
    if (handoff["analysis_state"] == "analysis_complete") != all_passed:
        raise TartarusError("analysis state does not agree with the completion gate")
    for function in handoff["function_analysis"]:
        decompilation = function["decompilation_artifact"]
        disassembly = function["disassembly_artifact"]
        if (decompilation is None or disassembly is None) and not function["gap"]:
            raise TartarusError("function analysis must link both artifacts or explain the gap")
    for detection in handoff["detections"]:
        _validate_sigma(detection["rule_yaml"])
    for gap in handoff["visibility_gaps"]:
        if gap.lower().startswith("the evidence inventory provides sizes"):
            raise TartarusError(
                "analysis handoff discusses an out-of-scope artifact collection mechanism"
            )


def _reject_opaque_content_identifiers(value: Any) -> None:
    if isinstance(value, str) and OPAQUE_CONTENT_IDENTIFIER.search(value):
        raise TartarusError("analysis handoff contains an obsolete content-derived identifier")
    if isinstance(value, dict):
        for item in value.values():
            _reject_opaque_content_identifiers(item)
    elif isinstance(value, list):
        for item in value:
            _reject_opaque_content_identifiers(item)


def _evidence_references(value: Any) -> Iterable[str]:
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "evidence_refs" and isinstance(item, list):
                yield from (reference for reference in item if isinstance(reference, str))
            elif key in {"decompilation_artifact", "disassembly_artifact"} and isinstance(
                item, str
            ):
                yield item
            elif key == "evidence_inventory" and isinstance(item, list):
                for entry in item:
                    if isinstance(entry, dict) and isinstance(entry.get("path"), str):
                        yield entry["path"]
            else:
                yield from _evidence_references(item)
    elif isinstance(value, list):
        for item in value:
            yield from _evidence_references(item)


def _validate_sigma(value: str) -> None:
    try:
        rule = yaml.safe_load(value)
    except yaml.YAMLError as exc:
        raise TartarusError("agent-generated Sigma rule is not valid YAML") from exc
    required = {"title", "status", "logsource", "detection"}
    if not isinstance(rule, dict) or not required <= set(rule):
        raise TartarusError("agent-generated Sigma rule is missing required fields")
    if rule["status"] != "experimental":
        raise TartarusError("agent-generated Sigma rule must use experimental status")
    if not isinstance(rule["detection"], dict) or "condition" not in rule["detection"]:
        raise TartarusError("agent-generated Sigma rule has no detection condition")


def _record_outputs(run_file: Path, session_dir: Path, output: Path) -> bool:
    run = load_json(run_file)
    if "sample_id" not in run.get("sample", {}):
        return False
    run_dir = run_file.parent
    paths = [path for path in sorted(session_dir.iterdir()) if path.is_file()]
    if output.resolve().is_relative_to(run_dir):
        paths.append(output.resolve())
    existing = {item["relative_path"] for item in run["artifacts"]}
    for path in paths:
        relative = path.relative_to(run_dir).as_posix()
        if relative in existing:
            continue
        run["artifacts"].append(
            {
                "relative_path": relative,
                "media_type": _media_type(path),
                "size": path.stat().st_size,
                "collection_status": "collected",
                "collected_at": utc_now(),
            }
        )
    validate("run-manifest", run)
    atomic_json(run_file, run)
    return True


def _media_type(path: Path) -> str:
    return {
        ".json": "application/json",
        ".md": "text/markdown",
        ".txt": "text/plain",
        ".log": "text/plain",
    }.get(path.suffix, "application/octet-stream")


def _render_report(
    run: dict[str, Any], handoff: dict[str, Any], run_dir: Path, output: Path
) -> str:
    lines = [
        f"# Tartarus threat analysis: {run['run_id']}",
        "",
        f"- Case: `{run['case_id']}`",
        f"- Analysis state: `{handoff['analysis_state']}`",
        "- Generated by: `Codex`",
        "",
        "## Executive assessment",
        "",
        _claim_text(handoff["executive_assessment"], run_dir, output),
        "",
        "## Scope and sample identity",
        "",
        _claim_text(handoff["scope"], run_dir, output),
        "",
        "## Analysis methodology",
        "",
    ]
    for item in handoff["methodology"]:
        lines.append(
            f"- `{item['state']}` — {item['summary']} "
            f"{_references(item['evidence_refs'], run_dir, output)}"
        )
    lines.extend(["", "## Evidence timeline", ""])
    if handoff["timeline"]:
        for item in handoff["timeline"]:
            lines.append(
                f"- **{item['time']}** — {item['activity']} "
                f"(`{item['classification']}`) "
                f"{_references(item['evidence_refs'], run_dir, output)}"
            )
    else:
        lines.append("- No defensible event timeline was recoverable.")
    _claim_section(lines, "Static findings", handoff["static_findings"], run_dir, output)
    lines.extend(["", "## Function analysis", ""])
    if handoff["function_analysis"]:
        for item in handoff["function_analysis"]:
            label = item["name"]
            if item["analyst_name"]:
                label += f" / {item['analyst_name']}"
            lines.extend(
                [
                    f"### `{label}` at `{item['address']}`",
                    "",
                    (
                        f"{item['behavior']} Confidence: `{item['confidence']}`. "
                        f"{_references(item['evidence_refs'], run_dir, output)}"
                    ),
                    "",
                    f"- Complete decompilation: {_artifact_link(item['decompilation_artifact'], run_dir, output)}",
                    f"- Complete disassembly: {_artifact_link(item['disassembly_artifact'], run_dir, output)}",
                    f"- Gap: {item['gap'] or 'None recorded'}",
                    "",
                ]
            )
    else:
        lines.append("No behaviorally relevant function analysis was retained.")
    _claim_section(lines, "Dynamic findings", handoff["dynamic_findings"], run_dir, output)
    _claim_section(lines, "Network behavior", handoff["network_behavior"], run_dir, output)
    _claim_section(
        lines,
        "Persistence, privilege, credential, and defense-evasion behavior",
        handoff["security_behaviors"],
        run_dir,
        output,
    )
    lines.extend(["", "## Indicators of compromise", ""])
    if handoff["iocs"]:
        for item in handoff["iocs"]:
            lines.append(
                f"- `{item['type']}` `{item['value']}` — {item['context']} "
                f"(confidence: `{item['confidence']}`) "
                f"{_references(item['evidence_refs'], run_dir, output)}"
            )
    else:
        lines.append("No supported IOC.")
    _claim_section(
        lines, "Benign observables", handoff["benign_observables"], run_dir, output
    )
    lines.extend(["", "## MITRE ATT&CK mappings", ""])
    if handoff["attack_mappings"]:
        for item in handoff["attack_mappings"]:
            lines.append(
                f"- `{item['technique_id']}` {item['technique_name']} — {item['basis']} "
                f"(confidence: `{item['confidence']}`) "
                f"{_references(item['evidence_refs'], run_dir, output)}"
            )
    else:
        lines.append("No supported mapping.")
    lines.extend(["", "## Detection opportunities", ""])
    if handoff["detections"]:
        for item in handoff["detections"]:
            lines.extend(
                [
                    f"### {item['title']}",
                    "",
                    f"{item['rationale']} {_references(item['evidence_refs'], run_dir, output)}",
                    "",
                    f"Log sources: {', '.join(item['log_sources'])}",
                    "",
                    "False positives: "
                    + ("; ".join(item["false_positives"]) or "None identified"),
                    "",
                    "````yaml",
                    item["rule_yaml"].rstrip(),
                    "````",
                    "",
                ]
            )
    else:
        lines.append("No supported Sigma rule.")
    lines.extend(
        [
            "",
            "## Attribution assessment",
            "",
            _claim_text(handoff["attribution"], run_dir, output),
        ]
    )
    _claim_section(
        lines,
        "Alternative explanations",
        handoff["alternative_explanations"],
        run_dir,
        output,
    )
    lines.extend(["", "## Visibility gaps and unresolved questions", ""])
    lines.extend(f"- {item}" for item in handoff["visibility_gaps"])
    if not handoff["visibility_gaps"]:
        lines.append("- None recorded.")
    lines.extend(["", "## Completion gate", ""])
    for name, item in handoff["completion_gate"].items():
        result = "PASS" if item["passed"] else "FAIL"
        lines.append(
            f"- **{result} — {name.replace('_', ' ')}:** {item['explanation']} "
            f"{_references(item['evidence_refs'], run_dir, output)}"
        )
    lines.extend(["", "## Evidence inventory", ""])
    for item in handoff["evidence_inventory"]:
        lines.append(
            f"- {_artifact_link(item['path'], run_dir, output)} — {item['description']}"
        )
    return "\n".join(lines).rstrip() + "\n"


def _claim_section(
    lines: list[str],
    title: str,
    claims: list[dict[str, Any]],
    run_dir: Path,
    output: Path,
) -> None:
    lines.extend(["", f"## {title}", ""])
    if claims:
        lines.extend(f"- {_claim_text(item, run_dir, output)}" for item in claims)
    else:
        lines.append("- No supported finding.")


def _claim_text(item: dict[str, Any], run_dir: Path, output: Path) -> str:
    return (
        f"{item['claim']} (`{item['classification']}`, confidence: `{item['confidence']}`) "
        f"{_references(item['evidence_refs'], run_dir, output)}"
    )


def _references(references: list[str], run_dir: Path, output: Path) -> str:
    if not references:
        return ""
    links = ", ".join(_artifact_link(reference, run_dir, output) for reference in references)
    return f"Evidence: {links}."


def _artifact_link(reference: str | None, run_dir: Path, output: Path) -> str:
    if reference is None:
        return "Not retained"
    target = os.path.relpath(run_dir / reference, output.parent)
    return f"[`{reference}`](<{target}>)"
