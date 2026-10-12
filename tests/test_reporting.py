import base64
import json
import sys
from pathlib import Path

import pytest
from tartarus.errors import TartarusError
from tartarus.manifest import create_case, create_run, stage_sample
from tartarus.reporting import generate_agent_report
from tartarus.util import atomic_json, load_json


def _handoff(reference: str = "evidence.txt") -> dict:
    claim = {
        "claim": "The retained fixture evidence does not support malicious behavior.",
        "classification": "observed",
        "confidence": "high",
        "evidence_refs": [reference],
    }
    gate = {
        "passed": False,
        "explanation": "The fixture does not contain complete function coverage.",
        "evidence_refs": [reference],
    }
    return {
        "schema_version": "1.0",
        "analysis_state": "analysis_incomplete",
        "scope": claim,
        "executive_assessment": claim,
        "methodology": [
            {"state": "intake", "summary": "Reviewed the retained fixture.", "evidence_refs": [reference]},
            {
                "state": "analysis_incomplete",
                "summary": "Recorded the function-coverage gap.",
                "evidence_refs": [reference],
            },
        ],
        "timeline": [
            {
                "time": "relative start",
                "activity": "The fixture emitted a benign test message.",
                "classification": "observed",
                "evidence_refs": [reference],
            }
        ],
        "static_findings": [claim],
        "function_analysis": [
            {
                "address": "unknown",
                "name": "entry",
                "analyst_name": None,
                "behavior": "No complete function artifacts were retained.",
                "confidence": "low",
                "evidence_refs": [reference],
                "decompilation_artifact": None,
                "disassembly_artifact": None,
                "gap": "Complete decompilation and disassembly are absent.",
            }
        ],
        "dynamic_findings": [claim],
        "network_behavior": [],
        "security_behaviors": [],
        "iocs": [],
        "benign_observables": [claim],
        "attack_mappings": [],
        "detections": [],
        "attribution": claim,
        "alternative_explanations": [claim],
        "visibility_gaps": ["Complete function coverage is absent."],
        "evidence_inventory": [
            {"path": reference, "description": "Benign reporting fixture evidence."}
        ],
        "completion_gate": {
            "sample_and_artifacts": gate,
            "function_coverage": gate,
            "function_details": gate,
            "static_dynamic_correlation": gate,
            "process_attribution": gate,
            "intelligence_rules": gate,
            "explicit_gaps": gate,
            "sandbox_recovery": gate,
        },
    }


def _completed_run(tmp_path: Path) -> Path:
    create_case(tmp_path, "case-1")
    sample = tmp_path / "fixture.elf"
    sample.write_bytes(b"\x7fELF\x02\x01\x01" + b"\x00" * 9 + b"\x02\x00\x3e\x00" + b"\x00" * 44)
    staged = stage_sample(tmp_path, "case-1", sample)
    run = create_run(tmp_path, "case-1", staged["sample_id"], "standard", "test", "run-1")
    run_file = tmp_path / "case-1" / "run-1" / "run.json"
    run["status"] = "collected"
    run["stopped_at"] = "2026-10-12T01:00:00Z"
    run["recovery_verified"] = True
    atomic_json(run_file, run)
    (run_file.parent / "evidence.txt").write_text("known benign fixture\n", encoding="utf-8")
    return run_file


def _fake_codex(tmp_path: Path, handoff: dict) -> Path:
    answer = tmp_path / "answer.json"
    answer.write_text(json.dumps(handoff), encoding="utf-8")
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


def _repairing_fake_codex(tmp_path: Path) -> Path:
    invalid = tmp_path / "invalid-answer.json"
    valid = tmp_path / "valid-answer.json"
    invalid.write_text(json.dumps(_handoff("missing.txt")), encoding="utf-8")
    valid.write_text(json.dumps(_handoff()), encoding="utf-8")
    executable = tmp_path / "codex-repair-fixture"
    executable.write_text(
        "#!" + sys.executable + "\n"
        "import pathlib, shutil, sys\n"
        "target = pathlib.Path(sys.argv[sys.argv.index('--output-last-message') + 1])\n"
        f"source = pathlib.Path({str(invalid)!r} if 'attempt-1' in target.name else {str(valid)!r})\n"
        "shutil.copyfile(source, target)\n",
        encoding="utf-8",
    )
    executable.chmod(0o700)
    return executable


def test_codex_reporting_pipeline_creates_and_records_a_threat_report(tmp_path: Path) -> None:
    run_file = _completed_run(tmp_path)
    output = run_file.parent / "report.md"
    result = generate_agent_report(
        run_file,
        output,
        codex_executable=str(_fake_codex(tmp_path, _handoff())),
    )

    report = output.read_text(encoding="utf-8")
    assert result["analysis_state"] == "analysis_incomplete"
    assert result["manifest_updated"] is True
    assert "## Executive assessment" in report
    assert "## Function analysis" in report
    assert "No supported IOC." in report
    assert "No supported mapping." in report
    assert "No supported Sigma rule." in report
    artifacts = load_json(run_file)["artifacts"]
    assert any(item["relative_path"] == "report.md" for item in artifacts)
    assert any(item["relative_path"].endswith("analysis-handoff.json") for item in artifacts)


def test_report_embeds_every_function_from_retained_whole_program_map(tmp_path: Path) -> None:
    run_file = _completed_run(tmp_path)
    mcp_dir = run_file.parent / "artifacts" / "mcp"
    mcp_dir.mkdir(parents=True)

    def encoded(value: str) -> str:
        return base64.b64encode(value.encode()).decode()

    rows = [
        ["00100000", "12", encoded("entry"), "false", "", encoded("00100020:worker"), "", "", encoded("entry_dispatch"), encoded("program entry")],
        ["00100020", "8", encoded("worker"), "false", encoded("00100000:entry"), "", encoded("safe | text"), encoded("write"), encoded("filesystem"), encoded("observable file behavior")],
    ]
    result = "\n".join(
        [
            "INFO  fixture> TARTARUS_FINAL_MAP\t" + "\t".join(row) + " (GhidraScript)  "
            for row in rows
        ]
        + [
            "INFO  fixture> TARTARUS_FINAL_MAP_SUMMARY\tfunctions=2\tthunks=0\tprogram=2\trelevant=2 (GhidraScript)  "
        ]
    )
    atomic_json(
        mcp_dir / "ghidra_script-fixture.json",
        {
            "data": {
                "arguments": {"script_name": "TartarusFinalWholeProgramMap.java"},
                "result": result,
            }
        },
    )

    output = run_file.parent / "report.md"
    generate_agent_report(
        run_file,
        output,
        codex_executable=str(_fake_codex(tmp_path, _handoff())),
    )

    report = output.read_text(encoding="utf-8")
    assert "## Complete function map" in report
    assert "maps all **2** functions" in report
    assert "| 00100000 | 12 | entry |" in report
    assert "| 00100020 | 8 | worker |" in report
    assert "safe &#124; text" in report


def test_reporting_rejects_a_missing_evidence_reference(tmp_path: Path) -> None:
    run_file = _completed_run(tmp_path)

    with pytest.raises(TartarusError, match="outside its context"):
        generate_agent_report(
            run_file,
            run_file.parent / "report.md",
            codex_executable=str(_fake_codex(tmp_path, _handoff("missing.txt"))),
        )


def test_reporting_repairs_a_rejected_handoff(tmp_path: Path) -> None:
    run_file = _completed_run(tmp_path)

    result = generate_agent_report(
        run_file,
        run_file.parent / "report.md",
        codex_executable=str(_repairing_fake_codex(tmp_path)),
    )

    assert result["attempts"] == 2
    assert result["analysis_state"] == "analysis_incomplete"
