import json
import subprocess
import sys
from pathlib import Path

from tartarus.analysis import _analysis_prompt, _codex_command, run_yara_handoff_probe
from tartarus.config import Config
from tartarus.lifecycle import start_remote_run
from tartarus.manifest import create_case, create_run, stage_sample
from tartarus.remote import Guest
from tartarus.util import atomic_json, load_json
from tartarus.yara import _normalize_matches, scan_staged_sample


def _ruleset_manifest() -> dict:
    return {
        "schema_version": "1.0",
        "name": "Tartarus ELF",
        "version": "20261011+tartarus-elf-v1",
        "selection_policy": "tartarus-elf-v1",
        "upstream": {"name": "YARA Forge Full", "version": "20261011"},
        "minimum_quality": 70,
        "counts": {
            "upstream": 12450,
            "public": 376,
            "private": 3,
            "compiled": 379,
            "excluded": 12071,
        },
        "imports": ["elf", "hash", "pe"],
        "exclusion_counts": {
            "no_explicit_elf_guard": 11429,
            "private_not_required": 21,
            "quality_below_minimum": 621,
        },
        "rules": [
            {
                "identifier": "ELF_Test_Rule",
                "id": "test-id",
                "logic_hash": "test-hash",
                "source_url": "https://example.invalid/rule",
                "quality": 85,
                "private": False,
                "inclusion_reason": "elf_header",
                "dependencies": [],
            }
        ],
    }


class ScannerRemote:
    def run(self, command, *, timeout=120):
        assert command == ("/usr/local/sbin/tartarus-yara-scan", "/staged/sample")
        assert timeout == 140
        raw = {
            "rules": [
                {
                    "rule": "ELF_Test_Rule",
                    "tags": ["elf"],
                    "meta": {"description": "fixture"},
                    "strings": [
                        {"identifier": "$elf", "offset": 0, "match": "\\x7fELF"}
                    ],
                }
            ]
        }
        envelope = {
            "engine_version": "1.21.0",
            "ruleset_manifest": _ruleset_manifest(),
            "returncode": 0,
            "timed_out": False,
            "elapsed_seconds": 0.25,
            "peak_rss_kib": 32768,
            "stdout": json.dumps(raw),
            "stderr": "",
            "truncated": False,
        }
        return subprocess.CompletedProcess(command, 0, json.dumps(envelope), "")


def _run_file(tmp_path: Path) -> Path:
    create_case(tmp_path, "case-1")
    sample = tmp_path / "fixture.elf"
    sample.write_bytes(
        b"\x7fELF\x02\x01\x01" + b"\x00" * 9 + b"\x02\x00\x3e\x00" + b"\x00" * 44
    )
    record = stage_sample(tmp_path, "case-1", sample)
    run = create_run(tmp_path, "case-1", record["sample_id"], "lightweight", "test", "run-1")
    run["range_id"] = "TARTARUS-1"
    run_file = tmp_path / "case-1" / "run-1" / "run.json"
    atomic_json(run_file, run)
    return run_file


def test_yara_scan_is_normalized_and_registered(tmp_path: Path) -> None:
    run_file = _run_file(tmp_path)

    result = scan_staged_sample(ScannerRemote(), run_file, "/staged/sample")

    assert result["status"] == "complete"
    assert result["match_count"] == 1
    assert result["matches"][0]["identifier"] == "ELF_Test_Rule"
    run = load_json(run_file)
    assert run["yara_scan"]["match_count"] == 1
    assert run["yara_scan"]["peak_rss_kib"] == 32768
    assert run["yara_scan"]["rule_count"] == 379
    assert (run_file.parent / run["yara_scan"]["artifact"]).is_file()
    assert (run_file.parent / "artifacts/yara/ruleset-manifest.json").is_file()


def test_yara_normalizer_accepts_ndjson() -> None:
    first = json.dumps({"rule": "one", "tags": []})
    second = json.dumps({"rule": "two", "tags": []})
    matches, warnings = _normalize_matches(first + "\n" + second)
    assert [match["identifier"] for match in matches] == ["one", "two"]
    assert warnings == []


def test_handoff_probe_has_no_mcp_configuration_and_preserves_ids(tmp_path: Path) -> None:
    run_file = _run_file(tmp_path)
    scan_staged_sample(ScannerRemote(), run_file, "/staged/sample")
    answer = {
        "schema_version": "1.0",
        "sample_id": load_json(run_file)["sample"]["sample_id"],
        "yara_artifact": "artifacts/yara/scan.json",
        "match_count": 1,
        "observed_rule_ids": ["ELF_Test_Rule"],
        "summary": "The normalized YARA result reached the probe.",
        "analysis_leads": ["Validate the rule match independently."],
        "full_analysis_performed": False,
    }
    source = tmp_path / "answer.json"
    source.write_text(json.dumps(answer), encoding="utf-8")
    executable = tmp_path / "codex-fixture"
    executable.write_text(
        "#!" + sys.executable + "\n"
        "import pathlib, shutil, sys\n"
        "prompt = sys.stdin.read()\n"
        "assert '<yara_context>' in prompt\n"
        "assert 'ELF_Test_Rule' in prompt\n"
        "assert 'Read context.json' not in prompt\n"
        "target = pathlib.Path(sys.argv[sys.argv.index('--output-last-message') + 1])\n"
        f"shutil.copyfile({str(source)!r}, target)\n",
        encoding="utf-8",
    )
    executable.chmod(0o700)

    result = run_yara_handoff_probe(run_file, codex_executable=str(executable))

    assert result["observed_rule_ids"] == ["ELF_Test_Rule"]
    handoff_root = run_file.parent / "artifacts" / "yara"
    context = json.loads(next(handoff_root.glob("handoff-*/context.json")).read_text())
    assert context["ruleset"]["name"] == "Tartarus ELF"
    command = _codex_command(
        executable="codex",
        run=load_json(run_file),
        config_path=None,
        journal_path=tmp_path / "result.json",
        model=None,
        reasoning_effort="low",
        local_provider=None,
        output_schema="yara-handoff",
        include_mcp=False,
    )
    assert not any("mcp_servers" in argument for argument in command)


def test_full_analysis_prompt_exposes_yara_as_untrusted_leads(tmp_path: Path) -> None:
    run_file = _run_file(tmp_path)
    scan_staged_sample(ScannerRemote(), run_file, "/staged/sample")

    prompt = _analysis_prompt(load_json(run_file), run_file.parent)

    assert "artifacts/yara/scan.json" in prompt
    assert "untrusted leads" in prompt
    assert "independent static or dynamic evidence" in prompt


def test_remote_run_scans_before_static_analysis_or_execution(
    tmp_path: Path, monkeypatch
) -> None:
    run_file = _run_file(tmp_path)
    config = Config(evidence_root=tmp_path, cache_root=tmp_path, artifact_quota_gib=1)
    remnux = Guest("range-remnux-01", "192.0.2.20", "debian", None, 102)
    sandbox = Guest("range-linux-sbx-01", "192.0.2.30", "debian", None, 103)
    events: list[str] = []

    class FakeRemote:
        def __init__(self, _config, guest):
            self.guest = guest

        def run(self, command, *, sudo=False, timeout=120):
            if command[:3] == ("df", "-B1", "--output=avail"):
                stdout = "Avail\n2147483648\n"
            elif command[:5] == ("ip", "-j", "route", "show", "default"):
                stdout = '[{"dev":"eth0"}]'
            else:
                events.append(f"run:{self.guest.name}:{command[0]}")
                stdout = ""
            return subprocess.CompletedProcess(command, 0, stdout, "")

    monkeypatch.setattr("tartarus.verify.verify_range", lambda *_: {"passed": True})
    monkeypatch.setattr(
        "tartarus.lifecycle.range_guests", lambda *_: {"remnux": remnux, "sandbox": sandbox}
    )
    monkeypatch.setattr("tartarus.lifecycle.Remote", FakeRemote)
    monkeypatch.setattr("tartarus.lifecycle.assert_analysis_pair_ready", lambda *_args, **_kwargs: {})
    monkeypatch.setattr("tartarus.lifecycle.mark_analysis_pair_tainted", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(
        "tartarus.lifecycle._stage",
        lambda remote, *_args, **_kwargs: events.append(f"stage:{remote.guest.name}"),
    )
    monkeypatch.setattr(
        "tartarus.lifecycle.scan_staged_sample",
        lambda *_args, **_kwargs: events.append("yara"),
    )
    monkeypatch.setattr(
        "tartarus.lifecycle._static_analysis",
        lambda *_args, **_kwargs: events.append("static"),
    )
    monkeypatch.setattr("tartarus.lifecycle.record_lifecycle", lambda *_args, **_kwargs: None)

    start_remote_run(config, "range-1", run_file, 30)

    assert events.index("yara") < events.index("static")
    assert events.index("static") < events.index("stage:range-linux-sbx-01")
