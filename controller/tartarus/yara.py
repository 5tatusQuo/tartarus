from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .errors import TartarusError
from .manifest import validate
from .remote import Remote
from .util import atomic_json, load_json, utc_now

YARA_ARTIFACT = "artifacts/yara/scan.json"
YARA_RULESET_ARTIFACT = "artifacts/yara/ruleset-manifest.json"
MAX_SCANNER_RESPONSE_BYTES = 8 * 1024 * 1024


def scan_staged_sample(remote: Remote, run_file: Path, sample: str) -> dict[str, Any]:
    """Run the bounded REMnux scanner and retain normalized, controller-owned evidence."""
    run = load_json(run_file)
    started_at = utc_now()
    response = remote.run(
        ("/usr/local/sbin/tartarus-yara-scan", sample), timeout=140
    ).stdout
    if len(response.encode("utf-8")) > MAX_SCANNER_RESPONSE_BYTES:
        raise TartarusError("YARA scanner response exceeded 8 MiB")
    try:
        envelope = json.loads(response)
    except json.JSONDecodeError as exc:
        raise TartarusError("YARA scanner returned invalid JSON") from exc
    ruleset_manifest = envelope.get("ruleset_manifest")
    if not isinstance(ruleset_manifest, dict):
        detail = envelope.get("stderr")
        suffix = f": {str(detail)[:1000]}" if detail else ""
        raise TartarusError(f"YARA scanner did not return a valid ruleset manifest{suffix}")
    validate("yara-ruleset-manifest", ruleset_manifest)
    ruleset_output = run_file.parent / YARA_RULESET_ARTIFACT
    atomic_json(ruleset_output, ruleset_manifest)

    raw = envelope.get("stdout", "")
    if not isinstance(raw, str):
        raw = ""
    matches, warnings = _normalize_matches(raw)
    stderr = envelope.get("stderr", "")
    if isinstance(stderr, str) and stderr.strip():
        warnings.append(stderr.strip()[:4096])
    timed_out = envelope.get("timed_out") is True
    truncated = envelope.get("truncated") is True
    exit_status = envelope.get("returncode")
    status = (
        "timed_out"
        if timed_out
        else "complete"
        if exit_status == 0 and not truncated
        else "failed"
    )
    error = None
    if status != "complete":
        error = (
            "YARA scan timed out"
            if timed_out
            else "YARA scan output exceeded its retention limit"
            if truncated
            else "YARA-X exited unsuccessfully"
        )
    document = {
        "schema_version": "1.1",
        "case_id": run["case_id"],
        "run_id": run["run_id"],
        "sample_id": run["sample"]["sample_id"],
        "status": status,
        "engine": {"name": "YARA-X", "version": str(envelope.get("engine_version", "unknown"))},
        "ruleset": {
            "name": ruleset_manifest["name"],
            "version": ruleset_manifest["version"],
            "selection_policy": ruleset_manifest["selection_policy"],
            "upstream": ruleset_manifest["upstream"],
            "rule_count": ruleset_manifest["counts"]["compiled"],
            "public_rule_count": ruleset_manifest["counts"]["public"],
            "private_rule_count": ruleset_manifest["counts"]["private"],
            "manifest_artifact": YARA_RULESET_ARTIFACT,
        },
        "started_at": started_at,
        "finished_at": utc_now(),
        "elapsed_seconds": max(0.0, float(envelope.get("elapsed_seconds", 0))),
        "peak_rss_kib": max(0, int(envelope.get("peak_rss_kib", 0))),
        "exit_status": exit_status if isinstance(exit_status, int) else None,
        "match_count": len(matches),
        "matches": matches,
        "warnings": list(dict.fromkeys(warnings)),
        "error": error,
        "truncated": truncated,
    }
    validate("yara-scan", document)
    output = run_file.parent / YARA_ARTIFACT
    atomic_json(output, document)
    relative = output.relative_to(run_file.parent).as_posix()
    run["artifacts"].append(
        {
            "relative_path": relative,
            "media_type": "application/json",
            "size": output.stat().st_size,
            "collection_status": "collected",
            "collected_at": utc_now(),
        }
    )
    run["artifacts"].append(
        {
            "relative_path": YARA_RULESET_ARTIFACT,
            "media_type": "application/json",
            "size": ruleset_output.stat().st_size,
            "collection_status": "collected",
            "collected_at": utc_now(),
        }
    )
    run["yara_scan"] = {
        "status": status,
        "artifact": relative,
        "engine_version": document["engine"]["version"],
        "ruleset_version": document["ruleset"]["version"],
        "rule_count": document["ruleset"]["rule_count"],
        "match_count": len(matches),
        "elapsed_seconds": document["elapsed_seconds"],
        "peak_rss_kib": document["peak_rss_kib"],
        "truncated": document["truncated"],
    }
    validate("run-manifest", run)
    atomic_json(run_file, run)
    if status != "complete":
        raise TartarusError(error or "YARA scan failed")
    return document


def _normalize_matches(raw: str) -> tuple[list[dict[str, Any]], list[str]]:
    if not raw.strip():
        return [], []
    documents: list[Any] = []
    warnings: list[str] = []
    try:
        documents = [json.loads(raw)]
    except json.JSONDecodeError:
        for line in raw.splitlines():
            if not line.strip():
                continue
            try:
                documents.append(json.loads(line))
            except json.JSONDecodeError:
                warnings.append("YARA-X emitted an unparseable JSON line")
    candidates: list[dict[str, Any]] = []
    for document in documents:
        candidates.extend(_rule_objects(document))
    matches: list[dict[str, Any]] = []
    for rule in candidates:
        identifier = rule.get("identifier") or rule.get("rule") or rule.get("name")
        if not isinstance(identifier, str) or not identifier:
            continue
        patterns = rule.get("patterns") or rule.get("strings") or []
        normalized_patterns: list[dict[str, Any]] = []
        if isinstance(patterns, list):
            for pattern in patterns[:200]:
                if not isinstance(pattern, dict):
                    continue
                offset = pattern.get("offset", 0)
                preview = (
                    pattern.get("preview")
                    or pattern.get("match")
                    or pattern.get("data")
                    or pattern.get("matched_data")
                    or ""
                )
                length = pattern.get("length") or pattern.get("match_length") or len(str(preview))
                normalized_patterns.append(
                    {
                        "identifier": str(pattern.get("identifier") or pattern.get("name") or ""),
                        "offset": max(0, int(offset)) if isinstance(offset, (int, float)) else 0,
                        "length": max(0, int(length)) if isinstance(length, (int, float)) else 0,
                        "preview": str(preview)[:256],
                    }
                )
        metadata = rule.get("metadata") or rule.get("meta") or {}
        matches.append(
            {
                "identifier": identifier,
                "namespace": str(rule.get("namespace") or ""),
                "tags": [str(value) for value in rule.get("tags", [])] if isinstance(rule.get("tags", []), list) else [],
                "metadata": metadata if isinstance(metadata, dict) else {},
                "patterns": normalized_patterns,
            }
        )
    return matches, warnings


def _rule_objects(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        result: list[dict[str, Any]] = []
        for item in value:
            result.extend(_rule_objects(item))
        return result
    if not isinstance(value, dict):
        return []
    if any(key in value for key in ("identifier", "rule")):
        return [value]
    result = []
    for key in ("rules", "matches", "results", "files"):
        if key in value:
            result.extend(_rule_objects(value[key]))
    return result
