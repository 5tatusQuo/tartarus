from __future__ import annotations

import base64
import html
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
CONTRACTION = re.compile(
    r"\b(?:aren't|can't|couldn't|didn't|doesn't|don't|hadn't|hasn't|haven't|isn't|"
    r"shouldn't|wasn't|weren't|won't|wouldn't|it's|that's|there's|they're|we're|"
    r"we've|you're|you've)\b",
    re.IGNORECASE,
)
WHOLE_PROGRAM_MAP_SCRIPT = "TartarusFinalWholeProgramMap.java"
DEEP_FUNCTION_EXPORT_SCRIPT = "TartarusFinalRelevantDeepExport.java"


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
    annex = _technical_annex_path(output)
    output.write_text(_render_report(run, handoff, run_dir, output, annex), encoding="utf-8")
    annex.write_text(_render_technical_annex(run, handoff, run_dir, annex), encoding="utf-8")
    for path in (output, annex):
        path.chmod(0o600)
    recorded = _record_outputs(run_file, session_dir, (output, annex))
    return {
        "analysis_state": handoff["analysis_state"],
        "report": str(output),
        "technical_annex": str(annex),
        "handoff": str(handoff_path),
        "session": session_dir.name,
        "attempts": attempts_used,
        "manifest_updated": recorded,
    }


def render_retained_report(
    run_file: Path,
    handoff_path: Path,
    output: Path,
    *,
    replace: bool = False,
) -> dict[str, Any]:
    """Render a previously validated agent handoff without repeating agent inference."""
    run_file = run_file.resolve(strict=True)
    run_dir = run_file.parent
    handoff_path = handoff_path.resolve(strict=True)
    if not handoff_path.is_relative_to(run_dir):
        raise TartarusError("analysis handoff must be inside the run directory")
    run = load_json(run_file)
    if run.get("status") not in {"collected", "collected_with_gaps", "failed"}:
        raise TartarusError("report rendering requires a stopped run with collected evidence")
    handoff = load_json(handoff_path)
    validate("analysis-handoff", handoff)
    permitted_evidence = {
        path.relative_to(run_dir).as_posix()
        for path in run_dir.rglob("*")
        if path.is_file() and not path.is_symlink()
    }
    _validate_handoff(run_dir, handoff, permitted_evidence)
    if output.exists() and not replace:
        raise TartarusError(f"refusing to overwrite report: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    annex = _technical_annex_path(output)
    if annex.exists() and not replace:
        raise TartarusError(f"refusing to overwrite technical annex: {annex}")
    output.write_text(_render_report(run, handoff, run_dir, output, annex), encoding="utf-8")
    annex.write_text(_render_technical_annex(run, handoff, run_dir, annex), encoding="utf-8")
    for path in (output, annex):
        path.chmod(0o600)
    recorded = _record_outputs(run_file, handoff_path.parent, (output, annex))
    return {
        "analysis_state": handoff["analysis_state"],
        "report": str(output),
        "technical_annex": str(annex),
        "handoff": str(handoff_path),
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
            or (path.parent == run_dir and path.suffix == ".md")
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

Return schema version 2.0. Write the reader-facing fields in ASD-STE100 Simplified Technical
English. Create a human threat-analysis narrative, not a decompilation report. Explain what the
sample is, what capabilities it contains, what behavior the sandbox observed, and why the findings
matter. Distinguish static capability from observed execution. Keep function-level detail in the
structured function index so the renderer can place it in a separate technical annex.
Use a title that names the sample or software and states the main finding. Do not mention Tartarus,
the run, the case, reporting controls, or the analysis process in the title or reader summary.
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
    _validate_simplified_english(handoff)
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


def _validate_simplified_english(handoff: dict[str, Any]) -> None:
    failures: list[str] = []
    if re.search(r"\b(?:Tartarus|run|case)\b", handoff["report_title"], re.IGNORECASE):
        failures.append("report_title contains internal workflow language")
    values: list[tuple[str, str]] = []

    def add_claims(name: str, claims: list[dict[str, Any]]) -> None:
        values.extend((f"{name}[{index}]", item["claim"]) for index, item in enumerate(claims))

    add_claims("reader_summary", handoff["reader_summary"])
    add_claims("key_findings", handoff["key_findings"])
    add_claims("dynamic_findings", handoff["dynamic_findings"])
    add_claims("network_behavior", handoff["network_behavior"])
    add_claims("security_behaviors", handoff["security_behaviors"])
    add_claims("alternative_explanations", handoff["alternative_explanations"])
    for name in ("scope", "executive_assessment", "risk_assessment", "attribution"):
        values.append((name, handoff[name]["claim"]))
    for index, item in enumerate(handoff["capabilities"]):
        values.extend(
            [
                (f"capabilities[{index}].description", item["description"]),
                (f"capabilities[{index}].security_relevance", item["security_relevance"]),
            ]
        )
    values.extend(
        (f"execution_flow[{index}].description", item["description"])
        for index, item in enumerate(handoff["execution_flow"])
    )
    values.extend(
        (f"timeline[{index}].activity", item["activity"])
        for index, item in enumerate(handoff["timeline"])
    )
    values.extend(
        (f"attack_mappings[{index}].basis", item["basis"])
        for index, item in enumerate(handoff["attack_mappings"])
    )
    values.extend(
        (f"iocs[{index}].context", item["context"])
        for index, item in enumerate(handoff["iocs"])
    )
    values.extend(
        (f"detections[{index}].rationale", item["rationale"])
        for index, item in enumerate(handoff["detections"])
    )
    values.extend(
        (f"recommended_actions[{index}]", value)
        for index, value in enumerate(handoff["recommended_actions"])
    )
    values.extend(
        (f"visibility_gaps[{index}]", value)
        for index, value in enumerate(handoff["visibility_gaps"])
    )
    for name, value in values:
        if re.search(
            r"\b(?:context inventory|authoritative context|reporting control)\b",
            value,
            re.IGNORECASE,
        ):
            failures.append(f"{name} contains internal workflow language")
        if ";" in value or "—" in value:
            failures.append(f"{name} uses prohibited punctuation")
        if CONTRACTION.search(value):
            failures.append(f"{name} uses a contraction")
        for sentence in re.split(r"(?<=[.!?])\s+", value):
            words = re.findall(r"\b[\w'-]+\b", sentence)
            if len(words) > 25:
                failures.append(f"{name} has a sentence with more than 25 words")
                break
    if failures:
        raise TartarusError("ASD-STE100 validation failures: " + "; ".join(failures))


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


def _record_outputs(
    run_file: Path, session_dir: Path, outputs: Iterable[Path]
) -> bool:
    run = load_json(run_file)
    if "sample_id" not in run.get("sample", {}):
        return False
    run_dir = run_file.parent
    paths = [path for path in sorted(session_dir.iterdir()) if path.is_file()]
    for output in outputs:
        if output.resolve().is_relative_to(run_dir):
            paths.append(output.resolve())
    existing = {item["relative_path"]: item for item in run["artifacts"]}
    for path in paths:
        relative = path.relative_to(run_dir).as_posix()
        if relative in existing:
            existing[relative]["media_type"] = _media_type(path)
            existing[relative]["size"] = path.stat().st_size
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


def _technical_annex_path(output: Path) -> Path:
    return output.with_name(f"{output.stem}-technical-annex{output.suffix}")


def _render_report(
    run: dict[str, Any],
    handoff: dict[str, Any],
    run_dir: Path,
    output: Path,
    annex: Path,
) -> str:
    classification = handoff["threat_classification"].replace("_", " ").title()
    lines = [
        f"# {handoff['report_title']}",
        "",
        f"**Assessment:** {classification}  ",
        f"**Confidence:** {handoff['confidence'].title()}  ",
        f"**Sample:** `{run['sample']['sample_id']}`  ",
        f"**Case:** `{run['case_id']}`  ",
        "**Language:** ASD-STE100 Simplified Technical English  ",
        "**Prepared by:** Tartarus analysis agent",
        "",
        "## Executive summary",
        "",
    ]
    for item in handoff["reader_summary"]:
        lines.extend([_reader_claim(item, run_dir, output), ""])
    lines.extend(["## Key findings", ""])
    for item in handoff["key_findings"]:
        lines.append(f"- {_reader_claim(item, run_dir, output)}")
    lines.extend(
        [
            "",
            "## What we analyzed",
            "",
            _reader_claim(handoff["scope"], run_dir, output),
            "",
            "| Property | Result |",
            "|---|---|",
            f"| File type | {_markdown_cell(handoff['sample_profile']['file_type'])} |",
            f"| Architecture | {_markdown_cell(handoff['sample_profile']['architecture'])} |",
            f"| Platform | {_markdown_cell(handoff['sample_profile']['platform'])} |",
            f"| Linkage | {_markdown_cell(handoff['sample_profile']['linkage'])} |",
            f"| Protections | {_markdown_cell(', '.join(handoff['sample_profile']['protections']) or 'None identified')} |",
            f"| Identified role | {_markdown_cell(handoff['sample_profile']['identified_role'])} |",
            "",
            _references(handoff["sample_profile"]["evidence_refs"], run_dir, output),
            "",
            "## What the binary does",
            "",
        ]
    )
    status_labels = {
        "observed": "Observed during execution",
        "static_capability": "Present in the code",
        "not_observed": "Not observed during execution",
        "unresolved": "Unresolved",
    }
    for capability in handoff["capabilities"]:
        lines.extend(
            [
                f"### {capability['name']}",
                "",
                f"**Status:** {status_labels[capability['status']]}  ",
                f"**Confidence:** {capability['confidence'].title()}",
                "",
                capability["description"],
                "",
                f"**Security relevance:** {capability['security_relevance']}",
                "",
                _references(capability["evidence_refs"], run_dir, output),
                "",
            ]
        )
    lines.extend(["## How execution proceeds", ""])
    for item in sorted(handoff["execution_flow"], key=lambda value: value["order"]):
        lines.append(
            f"{item['order']}. **{item['stage']}:** {item['description']} "
            f"{_references(item['evidence_refs'], run_dir, output)}"
        )
    lines.extend(["", "## What we observed during execution", ""])
    _reader_claim_list(lines, handoff["dynamic_findings"], run_dir, output)
    if handoff["timeline"]:
        lines.extend(["", "### Execution timeline", ""])
        for item in handoff["timeline"]:
            lines.append(
                f"- **{item['time']}:** {item['activity']} "
                f"{_references(item['evidence_refs'], run_dir, output)}"
            )
    lines.extend(["", "## Security assessment", ""])
    lines.extend([_reader_claim(handoff["risk_assessment"], run_dir, output), ""])
    lines.extend(["### Network behavior", ""])
    _reader_claim_list(lines, handoff["network_behavior"], run_dir, output)
    lines.extend(["", "### Persistence, privilege, and credential behavior", ""])
    _reader_claim_list(lines, handoff["security_behaviors"], run_dir, output)
    lines.extend(["", "### MITRE ATT&CK", ""])
    if handoff["attack_mappings"]:
        for item in handoff["attack_mappings"]:
            lines.append(
                f"- **{item['technique_id']} {item['technique_name']}:** {item['basis']} "
                f"{_references(item['evidence_refs'], run_dir, output)}"
            )
    else:
        lines.append("The evidence does not support a MITRE ATT&CK mapping.")
    lines.extend(["", "## Indicators and detection", "", "### Indicators of compromise", ""])
    if handoff["iocs"]:
        lines.extend(["| Type | Value | Context | Confidence |", "|---|---|---|---|"])
        for item in handoff["iocs"]:
            lines.append(
                "| "
                + " | ".join(
                    _markdown_cell(value)
                    for value in (
                        item["type"],
                        item["value"],
                        item["context"],
                        item["confidence"].title(),
                    )
                )
                + " |"
            )
    else:
        lines.append("The evidence does not support an indicator of compromise.")
    lines.extend(["", "### Detection guidance", ""])
    if handoff["detections"]:
        for item in handoff["detections"]:
            lines.extend(
                [
                    f"#### {item['title']}",
                    "",
                    f"{item['rationale']} {_references(item['evidence_refs'], run_dir, output)}",
                    "",
                    f"Required log sources: {', '.join(item['log_sources'])}.",
                    "",
                    "````yaml",
                    item["rule_yaml"].rstrip(),
                    "````",
                    "",
                ]
            )
    else:
        lines.append("The collected log fields do not support a useful Sigma rule.")
    lines.extend(["", "## Analyst assessment", ""])
    lines.extend([_reader_claim(handoff["executive_assessment"], run_dir, output), ""])
    lines.extend([_reader_claim(handoff["attribution"], run_dir, output), ""])
    if handoff["alternative_explanations"]:
        lines.extend(["### Alternative explanations", ""])
        _reader_claim_list(lines, handoff["alternative_explanations"], run_dir, output)
    lines.extend(["", "## Recommended actions", ""])
    if handoff["recommended_actions"]:
        lines.extend(f"- {item}" for item in handoff["recommended_actions"])
    else:
        lines.append("No response action is necessary for this sample.")
    lines.extend(["", "## Analysis limits", ""])
    if handoff["visibility_gaps"]:
        lines.extend(f"- {item}" for item in handoff["visibility_gaps"])
    else:
        lines.append("The analysis did not identify a material visibility gap.")
    annex_target = os.path.relpath(annex, output.parent)
    lines.extend(
        [
            "",
            "## Technical material",
            "",
            (
                "The technical annex contains the function records, complete function map, "
                "method, evidence index, and completion checks."
            ),
            "",
            f"Open the [technical annex](<{annex_target}>).",
        ]
    )
    return _compact_evidence_links("\n".join(lines).rstrip() + "\n")


def _compact_evidence_links(report: str) -> str:
    pattern = re.compile(r"\[`([^`]+)`\]\(<([^>]+)>\)")
    references: dict[str, tuple[int, str]] = {}

    def replace(match: re.Match[str]) -> str:
        reference, target = match.groups()
        if reference not in references:
            references[reference] = (len(references) + 1, target)
        number, retained_target = references[reference]
        return f"[E{number}](<{retained_target}>)"

    compact = pattern.sub(replace, report).rstrip()
    if not references:
        return compact + "\n"
    lines = [compact, "", "## Evidence references", ""]
    for reference, (number, target) in references.items():
        lines.append(f"- **E{number}:** [`{reference}`](<{target}>)")
    return "\n".join(lines).rstrip() + "\n"


def _reader_claim(item: dict[str, Any], run_dir: Path, output: Path) -> str:
    return f"{item['claim']} {_references(item['evidence_refs'], run_dir, output)}".strip()


def _reader_claim_list(
    lines: list[str], claims: list[dict[str, Any]], run_dir: Path, output: Path
) -> None:
    if claims:
        lines.extend(f"- {_reader_claim(item, run_dir, output)}" for item in claims)
    else:
        lines.append("The analysis did not identify applicable behavior.")


def _render_technical_annex(
    run: dict[str, Any], handoff: dict[str, Any], run_dir: Path, output: Path
) -> str:
    lines = [
        f"# Technical annex: {handoff['report_title']}",
        "",
        f"- Run: `{run['run_id']}`",
        f"- Sample: `{run['sample']['sample_id']}`",
        f"- Analysis state: `{handoff['analysis_state']}`",
        "",
        "## Function analysis records",
        "",
    ]
    if handoff["function_analysis"]:
        for item in handoff["function_analysis"]:
            label = item["name"]
            if item["analyst_name"]:
                label += f" / {item['analyst_name']}"
            lines.extend(
                [
                    f"### `{label}` at `{item['address']}`",
                    "",
                    f"{item['behavior']} {_references(item['evidence_refs'], run_dir, output)}",
                    "",
                    f"- Confidence: {item['confidence'].title()}",
                    f"- Complete decompilation: {_artifact_link(item['decompilation_artifact'], run_dir, output)}",
                    f"- Complete disassembly: {_artifact_link(item['disassembly_artifact'], run_dir, output)}",
                    f"- Analysis gap: {item['gap'] or 'None'}",
                    "",
                ]
            )
    else:
        lines.append("No behaviorally relevant function record was retained.")
    _complete_function_map(lines, run_dir, output)
    lines.extend(["", "## Analysis method", ""])
    for item in handoff["methodology"]:
        lines.append(
            f"- **{item['state'].replace('_', ' ').title()}:** {item['summary']} "
            f"{_references(item['evidence_refs'], run_dir, output)}"
        )
    lines.extend(["", "## Completion checks", ""])
    for name, item in handoff["completion_gate"].items():
        result = "Pass" if item["passed"] else "Fail"
        lines.append(
            f"- **{result}, {name.replace('_', ' ')}:** {item['explanation']} "
            f"{_references(item['evidence_refs'], run_dir, output)}"
        )
    lines.extend(["", "## Evidence index", ""])
    for item in handoff["evidence_inventory"]:
        lines.append(
            f"- {_artifact_link(item['path'], run_dir, output)}: {item['description']}"
        )
    return "\n".join(lines).rstrip() + "\n"


def _complete_function_map(lines: list[str], run_dir: Path, output: Path) -> None:
    lines.extend(["", "## Complete function map", ""])
    artifact = _ghidra_script_artifact(
        run_dir, WHOLE_PROGRAM_MAP_SCRIPT, "TARTARUS_FINAL_MAP_SUMMARY"
    )
    if artifact is None:
        lines.append("No retained whole-program Ghidra map was available.")
        return
    relative, result = artifact
    rows, summary = _parse_whole_program_map(result)
    deep = _ghidra_script_artifact(
        run_dir, DEEP_FUNCTION_EXPORT_SCRIPT, "TARTARUS_FINAL_DEEP_SUMMARY"
    )
    lines.append(
        f"This table maps all **{summary['functions']}** functions discovered by Ghidra: "
        f"**{summary['program']}** local program functions and **{summary['thunks']}** import "
        f"thunks. It classifies **{summary['relevant']}** functions as behaviorally relevant. "
        f"The retained source map is {_artifact_link(relative, run_dir, output)}."
    )
    if deep is not None:
        lines.extend(
            [
                "",
                (
                    "Complete decompilation and instruction-level disassembly for every "
                    "behaviorally relevant function are retained in "
                    f"{_artifact_link(deep[0], run_dir, output)}."
                ),
            ]
        )
    lines.extend(
        [
            "",
            "| Address | Size | Function | Kind | Classification | Callers | Callees | Imports | Referenced strings | Coverage rationale |",
            "|---|---:|---|---|---|---|---|---|---|---|",
        ]
    )
    for row in rows:
        kind = "import thunk" if row["thunk"] else "program"
        cells = [
            row["address"],
            str(row["size"]),
            row["name"],
            kind,
            row["classification"],
            row["callers"] or "None",
            row["callees"] or "None",
            row["imports"] or "None",
            row["strings"] or "None",
            row["reason"],
        ]
        lines.append("| " + " | ".join(_markdown_cell(cell) for cell in cells) + " |")


def _ghidra_script_artifact(
    run_dir: Path, script_name: str, result_marker: str
) -> tuple[str, str] | None:
    matches: list[tuple[Path, str]] = []
    for path in (run_dir / "artifacts" / "mcp").glob("ghidra_script-*.json"):
        try:
            document = load_json(path)
        except (OSError, json.JSONDecodeError):
            continue
        data = document.get("data")
        if not isinstance(data, dict):
            continue
        arguments = data.get("arguments")
        result = data.get("result")
        if (
            isinstance(arguments, dict)
            and isinstance(result, str)
            and (arguments.get("script_name") == script_name or result_marker in result)
        ):
            matches.append((path, result))
    if not matches:
        return None
    path, result = max(matches, key=lambda item: item[0].stat().st_mtime_ns)
    return path.relative_to(run_dir).as_posix(), result


def _parse_whole_program_map(result: str) -> tuple[list[dict[str, Any]], dict[str, int]]:
    rows: list[dict[str, Any]] = []
    summary: dict[str, int] | None = None
    for line in result.splitlines():
        marker = line.find("TARTARUS_FINAL_MAP\t")
        if marker >= 0:
            fields = _strip_ghidra_suffix(line[marker:]).split("\t")
            if len(fields) != 11:
                raise TartarusError("retained whole-program map contains a malformed function row")
            try:
                size = int(fields[2])
            except ValueError as exc:
                raise TartarusError(
                    "retained whole-program map contains a nonnumeric function size"
                ) from exc
            rows.append(
                {
                    "address": fields[1],
                    "size": size,
                    "name": _decode_map_field(fields[3]),
                    "thunk": fields[4] == "true",
                    "callers": _decode_map_field(fields[5]),
                    "callees": _decode_map_field(fields[6]),
                    "strings": _decode_map_field(fields[7]),
                    "imports": _decode_map_field(fields[8]),
                    "classification": _decode_map_field(fields[9]),
                    "reason": _decode_map_field(fields[10]),
                }
            )
            continue
        marker = line.find("TARTARUS_FINAL_MAP_SUMMARY\t")
        if marker >= 0:
            values = _strip_ghidra_suffix(line[marker:]).split("\t")[1:]
            try:
                summary = {key: int(value) for key, value in (item.split("=", 1) for item in values)}
            except (TypeError, ValueError) as exc:
                raise TartarusError("retained whole-program map has a malformed summary") from exc
    required = {"functions", "thunks", "program", "relevant"}
    if summary is None or not required <= summary.keys():
        raise TartarusError("retained whole-program map has no complete summary")
    if len(rows) != summary["functions"]:
        raise TartarusError("retained whole-program map function count does not match its summary")
    return rows, summary


def _decode_map_field(value: str) -> str:
    if not value:
        return ""
    try:
        return base64.b64decode(value, validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError) as exc:
        raise TartarusError("retained whole-program map contains invalid encoded text") from exc


def _strip_ghidra_suffix(value: str) -> str:
    return re.sub(r" \(GhidraScript\)\s*$", "", value)


def _markdown_cell(value: object) -> str:
    escaped = html.escape(str(value), quote=False).replace("`", "&#96;").replace("|", "&#124;")
    return escaped.replace("\r", " ").replace("\n", "<br>")


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
