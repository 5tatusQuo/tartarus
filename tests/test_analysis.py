import json
import sys
from pathlib import Path

import pytest
from tartarus.analysis import _analysis_prompt, _codex_failure_detail, run_analysis_agent
from tartarus.errors import TartarusError
from tartarus.manifest import create_case, create_run, stage_sample, validate
from tartarus.util import atomic_json, load_json


def _journal(*, complete: bool = True) -> dict:
    references = {
        family: [f"artifacts/mcp/{family}.json"]
        for family in ("ghidra", "radare2", "gdb", "telemetry")
    }
    states = [
        {
            "state": state,
            "summary": f"Completed {state}.",
            "evidence_refs": references["ghidra"],
        }
        for state in (
            "intake",
            "verified",
            "static_triage",
            "static_deep_dive",
            "dynamic_observation",
            "hypothesis_testing",
            "coverage_review",
        )
    ]
    states.append(
        {
            "state": "analysis_complete" if complete else "analysis_incomplete",
            "summary": "Coverage gate evaluated.",
            "evidence_refs": references["ghidra"],
        }
    )
    return {
        "schema_version": "1.0",
        "analysis_state": "analysis_complete" if complete else "analysis_incomplete",
        "states": states,
        "tool_families": {
            family: {
                "used": True,
                "successful_calls": 1,
                "evidence_refs": evidence_refs,
                "summary": f"Used {family} MCP.",
            }
            for family, evidence_refs in references.items()
        },
        "hypotheses": [
            {
                "hypothesis": "The fixture returns normally.",
                "result": "confirmed",
                "confidence": "high",
                "evidence_refs": references["gdb"],
            }
        ],
        "function_coverage": {
            "ghidra_count": 1,
            "radare2_count": 1,
            "accounted_for": complete,
            "inventory_refs": references["ghidra"] + references["radare2"],
            "deep_analysis_count": 1,
            "excluded_thunk_count": 0,
            "explanation": "The only function was mapped.",
        },
        "material_findings": [
            {
                "claim": "The fixture returns normally.",
                "classification": "observed",
                "confidence": "high",
                "evidence_refs": references["gdb"],
            }
        ],
        "visibility_gaps": [] if complete else ["Function coverage is incomplete."],
        "next_actions": [] if complete else ["Complete function mapping."],
    }


def _running_run(tmp_path: Path) -> Path:
    create_case(tmp_path, "case-1")
    sample = tmp_path / "fixture.elf"
    sample.write_bytes(b"\x7fELF\x02\x01\x01" + b"\x00" * 9 + b"\x02\x00\x3e\x00" + b"\x00" * 44)
    staged = stage_sample(tmp_path, "case-1", sample)
    run = create_run(tmp_path, "case-1", staged["sample_id"], "deep", "test", "run-1")
    run_file = tmp_path / "case-1" / "run-1" / "run.json"
    run.update(
        {
            "status": "running",
            "range_id": "TARTARUS-1",
            "debug_session": True,
            "execution_limit_seconds": 3600,
            "remote_started_at": "2026-10-12T01:00:00Z",
        }
    )
    atomic_json(run_file, run)
    operations = {
        "ghidra": "ghidra_functions",
        "radare2": "radare2_mcp_list_functions",
        "gdb": "gdb_registers",
        "telemetry": "telemetry_health",
    }
    artifact_dir = run_file.parent / "artifacts" / "mcp"
    artifact_dir.mkdir(parents=True)
    for family, operation in operations.items():
        atomic_json(
            artifact_dir / f"{family}.json",
            {
                "schema_version": "1.0",
                "ok": True,
                "operation": operation,
                "data": {
                    "arguments": {},
                    "result": "fixture",
                    "recorded_at": "2026-10-12T01:00:00Z",
                    "evidence_path": f"artifacts/mcp/{family}.json",
                },
                "error": None,
            },
        )
    return run_file


def _fake_codex(tmp_path: Path, journal: dict) -> Path:
    answer = tmp_path / "answer.json"
    answer.write_text(json.dumps(journal), encoding="utf-8")
    executable = tmp_path / "codex-fixture"
    executable.write_text(
        "#!" + sys.executable + "\n"
        "import pathlib, shutil, sys\n"
        "target = pathlib.Path(sys.argv[sys.argv.index('--output-last-message') + 1])\n"
        f"shutil.copyfile({str(answer)!r}, target)\n",
        encoding="utf-8",
    )
    executable.chmod(0o700)
    return executable


def test_analysis_agent_records_validated_complete_journal(tmp_path: Path) -> None:
    run_file = _running_run(tmp_path)
    config = tmp_path / "config.toml"
    config.write_text("fixture = true\n", encoding="utf-8")

    result = run_analysis_agent(
        run_file,
        codex_executable=str(_fake_codex(tmp_path, _journal())),
        config_path=config,
    )

    assert result["analysis_state"] == "analysis_complete"
    artifacts = load_json(run_file)["artifacts"]
    assert any(item["relative_path"].endswith("analysis-journal.json") for item in artifacts)
    assert any(item["relative_path"].endswith("codex.stdout.jsonl") for item in artifacts)


def test_analysis_prompt_does_not_prejudge_sample_identity_or_compatibility(tmp_path: Path) -> None:
    run_file = _running_run(tmp_path)
    run = load_json(run_file)
    run.update(
        execution_mode="static_only",
        sample_architecture="ELF32 little-endian machine 93",
    )

    prompt = _analysis_prompt(run, run_file.parent)

    assert "machine 93" not in prompt
    assert "static_only" not in prompt
    assert "unsupported architecture" not in prompt
    assert "No sample family" in prompt


def test_analysis_agent_rejects_false_tool_usage_claim(tmp_path: Path) -> None:
    run_file = _running_run(tmp_path)
    config = tmp_path / "config.toml"
    config.write_text("fixture = true\n", encoding="utf-8")
    journal = _journal()
    journal["tool_families"]["gdb"]["successful_calls"] = 2

    with pytest.raises(TartarusError, match="miscounts successful gdb"):
        run_analysis_agent(
            run_file,
            codex_executable=str(_fake_codex(tmp_path, journal)),
            config_path=config,
        )


def test_archive_preparation_schema_is_accepted_by_strict_providers() -> None:
    validate(
        "archive-preparation",
        {"prepared": True, "member": "payload.elf", "failure": None},
    )
    validate(
        "archive-preparation",
        {"prepared": False, "member": "", "failure": "archive listing failed"},
    )


def test_codex_failure_detail_extracts_nested_provider_message() -> None:
    stdout = json.dumps(
        {
            "type": "error",
            "error": {"message": "Invalid response schema: prepared requires a type."},
        }
    )
    assert _codex_failure_detail(stdout, "fallback") == (
        "Invalid response schema: prepared requires a type."
    )
