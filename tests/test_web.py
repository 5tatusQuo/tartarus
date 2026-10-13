from __future__ import annotations

import io
import json
import threading
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient
from tartarus.config import Config
from tartarus.errors import ApprovalRequired, AuthenticationRequired, TartarusError
from tartarus.manifest import create_case, create_run, stage_sample
from tartarus.providers import ChatGPTCodexProvider
from tartarus.web.app import SessionSecurity, create_app
from tartarus.web.jobs import JobStore, WorkflowRunner
from tartarus.web.oauth import ChatGPTAuth
from tartarus.web.service import ConsoleService


def _config(tmp_path: Path) -> Config:
    evidence = tmp_path / "evidence"
    cache = tmp_path / "cache"
    evidence.mkdir()
    cache.mkdir()
    return Config(
        evidence_root=evidence,
        cache_root=cache,
        management_sources=("198.51.100.2/32",),
        always_blocked_networks=("192.0.2.0/24",),
    )


def _elf() -> bytes:
    return b"\x7fELF\x02\x01\x01" + b"\x00" * 9 + b"\x02\x00\x3e\x00" + b"\x00" * 44


def _zip(*members: tuple[str, bytes]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in members:
            archive.writestr(name, content)
    return output.getvalue()


def test_job_approval_is_one_time_and_events_are_cursor_addressed(tmp_path: Path) -> None:
    store = JobStore(tmp_path)
    job, token = store.create(
        case_id="case-1",
        sample_id="sample-1",
        range_id="range-1",
        run_id="run-1",
        scope={"operation": "test"},
    )
    assert store.events(job["job_id"], 0)[0]["cursor"] == 1
    approved = store.approve(job["job_id"], token)
    assert approved["status"] == "queued"
    assert [item["cursor"] for item in store.events(job["job_id"], 1)] == [2]
    with pytest.raises(ApprovalRequired):
        store.approve(job["job_id"], token)


def test_job_store_never_resumes_an_interrupted_workflow(tmp_path: Path) -> None:
    store = JobStore(tmp_path)
    job, token = store.create(
        case_id="case-1",
        sample_id="sample-1",
        range_id="range-1",
        run_id="run-1",
        scope={},
    )
    store.approve(job["job_id"], token)
    reconciled = JobStore(tmp_path).get(job["job_id"])
    assert reconciled["status"] == "needs_attention"
    assert reconciled["resumability"] == "safe_cleanup_only"


def test_workflow_authentication_failure_runs_safe_cleanup(tmp_path: Path) -> None:
    store = JobStore(tmp_path)
    job, token = store.create(
        case_id="case-1",
        sample_id="sample-1",
        range_id="range-1",
        run_id="run-1",
        scope={},
    )
    store.approve(job["job_id"], token)
    cleaned: list[str] = []

    def operation(_job, _store):
        raise AuthenticationRequired("authorization expired")

    def cleanup(current, _store):
        cleaned.append(current["job_id"])

    runner = WorkflowRunner(store, operation, cleanup)
    runner.start(job["job_id"])
    assert runner._thread is not None
    runner._thread.join(timeout=2)

    assert cleaned == [job["job_id"]]
    assert store.get(job["job_id"])["status"] == "needs_attention"


def test_upload_uses_random_temporary_path_and_rejects_unsafe_filename(tmp_path: Path) -> None:
    config = _config(tmp_path)
    case = create_case(config.evidence_root, "case-1")
    jobs = JobStore(config.cache_root)
    service = ConsoleService(config, jobs, ChatGPTAuth(config.cache_root))
    record = service.stage_upload(case["case_id"], "fixture.elf", io.BytesIO(_elf()))
    assert record["original_name"] == "fixture.elf"
    assert not any((config.cache_root / "ui" / "uploads").iterdir())
    with pytest.raises(TartarusError, match="not an ELF"):
        service.stage_upload(case["case_id"], "invalid.elf", io.BytesIO(b"not-elf"))
    assert not any((config.cache_root / "ui" / "uploads").iterdir())
    with pytest.raises(TartarusError, match="filename"):
        service.stage_upload(case["case_id"], "../fixture.elf", io.BytesIO(_elf()))


def test_zip_upload_stages_archive_without_opening_it(tmp_path: Path) -> None:
    config = _config(tmp_path)
    case = create_case(config.evidence_root, "case-1")
    service = ConsoleService(config, JobStore(config.cache_root), ChatGPTAuth(config.cache_root))
    archive = _zip(("../payload.elf", _elf()), ("instructions.txt", b"untrusted"))
    record = service.stage_upload(
        case["case_id"],
        "fixture.zip",
        io.BytesIO(archive),
    )

    assert record["original_name"] == "fixture.zip"
    assert record["media_type"] == "application/zip"
    assert record["archive"] == {"format": "zip"}
    assert "elf" not in record
    assert not any((config.cache_root / "ui" / "uploads").iterdir())
    staged = config.evidence_root / "case-1" / "samples" / record["sample_id"] / "sample.bin"
    assert staged.read_bytes() == archive


def test_archive_password_is_only_held_in_transient_workflow_memory(
    tmp_path: Path, monkeypatch
) -> None:
    config = _config(tmp_path)
    case = create_case(config.evidence_root, "case-1")
    service = ConsoleService(config, JobStore(config.cache_root), ChatGPTAuth(config.cache_root))
    sample = service.stage_upload(
        case["case_id"],
        "protected.zip",
        io.BytesIO(_zip(("payload.elf", _elf()))),
    )
    service.auth.status = lambda: {"connected": True, "plan_usage": True}
    service._assert_managed = lambda _range_id: None
    monkeypatch.setattr(
        "tartarus.web.service.assert_analysis_pair_ready",
        lambda *_args, **_kwargs: {
            "state": "clean",
            "phase": "verified",
            "guests": {
                "remnux": {"status": "verified"},
                "sandbox": {"status": "verified"},
            },
            "failure": None,
        },
    )
    state = config.cache_root / "state"
    state.mkdir()
    (state / "prepare-manifest.json").write_text(
        json.dumps(
            {
                "tartarus_release": "test",
                "deployment": {"range_id": "range-1"},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    job, _token = service.prepare_workflow(
        range_id="range-1",
        case_id="case-1",
        sample_id=sample["sample_id"],
        telemetry_profile="deep",
        duration=300,
        archive_password="infected",
    )

    assert "infected" not in json.dumps(job)
    assert "infected" not in json.dumps(service.jobs.events(job["job_id"]))
    assert service._workflow_secrets[job["job_id"]] == "infected"
    assert job["approval"]["scope"]["archive_password_provided"] is True


def test_yara_only_workflow_without_probe_does_not_require_chatgpt(
    tmp_path: Path, monkeypatch
) -> None:
    config = _config(tmp_path)
    create_case(config.evidence_root, "case-1")
    sample_path = tmp_path / "fixture.elf"
    sample_path.write_bytes(_elf())
    sample = stage_sample(config.evidence_root, "case-1", sample_path)
    service = ConsoleService(config, JobStore(config.cache_root), ChatGPTAuth(config.cache_root))
    service.auth.status = lambda: {"connected": False, "plan_usage": False}
    service._assert_managed = lambda _range_id: None
    monkeypatch.setattr(
        "tartarus.web.service.assert_analysis_pair_ready",
        lambda *_args, **_kwargs: {
            "state": "clean",
            "phase": "verified",
            "guests": {
                "remnux": {"status": "verified"},
                "sandbox": {"status": "verified"},
            },
            "failure": None,
        },
    )
    state = config.cache_root / "state"
    state.mkdir()
    (state / "prepare-manifest.json").write_text(
        json.dumps({"tartarus_release": "test", "deployment": {"range_id": "range-1"}}),
        encoding="utf-8",
    )

    job, _token = service.prepare_workflow(
        range_id="range-1",
        case_id="case-1",
        sample_id=sample["sample_id"],
        telemetry_profile="lightweight",
        duration=300,
        mode="yara_only",
        handoff_probe=False,
    )

    assert job["approval"]["scope"]["mode"] == "yara_only"
    assert job["approval"]["scope"]["handoff_probe"] is False


def test_chatgpt_authorization_uses_pkce_and_rejects_state_mismatch(tmp_path: Path) -> None:
    auth = ChatGPTAuth(tmp_path)
    url = auth.begin("http://127.0.0.1:8741/auth/chatgpt/callback")
    query = parse_qs(urlparse(url).query)
    assert query["client_id"] == ["dynamic_agent_client"]
    assert query["code_challenge_method"] == ["S256"]
    assert "chatgpt.tokens.use.direct" in query["scope"][0]
    with pytest.raises(TartarusError, match="state"):
        auth.complete({"state": "wrong", "code": "unused"})


def test_chatgpt_provider_keeps_token_out_of_process_arguments() -> None:
    provider = ChatGPTCodexProvider(lambda: "secret-token")
    command, environment = provider.prepare(["codex", "exec", "-"])
    assert "secret-token" not in " ".join(command)
    assert environment["TARTARUS_CHATGPT_ACCESS_TOKEN"] == "secret-token"
    assert "app-server" in provider.app_server_command()


def test_chatgpt_refreshes_before_a_long_running_request(tmp_path: Path, monkeypatch) -> None:
    auth = ChatGPTAuth(tmp_path)
    auth._write_credentials(
        {
            "access_token": "nearly-expired",
            "expires_at": (datetime.now(UTC) + timedelta(minutes=20)).isoformat(),
            "scopes": ["chatgpt.tokens.use.direct"],
        }
    )
    refreshed = {"access_token": "fresh-token"}
    monkeypatch.setattr(auth, "_refresh", lambda _record: refreshed)

    assert auth.access_token() == "fresh-token"


def test_console_sets_security_headers_and_requires_csrf(tmp_path: Path) -> None:
    config = _config(tmp_path)
    client = TestClient(create_app(config))
    response = client.get("/api/cases")
    assert response.status_code == 200
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert client.post("/api/cases", json={"case_id": "case-1"}).status_code == 403

    security = SessionSecurity(config.cache_root)
    session = "test-session"
    client.cookies.set("tartarus_session", security.sign(session))
    response = client.post(
        "/api/cases",
        json={"case_id": "case-1"},
        headers={"X-CSRF-Token": security.csrf(session)},
    )
    assert response.status_code == 200


def test_slow_range_lookup_does_not_block_unrelated_requests(tmp_path: Path) -> None:
    app = create_app(_config(tmp_path))
    entered = threading.Event()
    release = threading.Event()

    def slow_ranges() -> list[dict[str, object]]:
        entered.set()
        release.wait(timeout=5)
        return []

    app.state.service.list_ranges = slow_ranges
    with TestClient(app) as client, ThreadPoolExecutor(max_workers=1) as executor:
        pending = executor.submit(client.get, "/range")
        assert entered.wait(timeout=1)
        started = time.monotonic()
        response = client.get("/api/cases")
        elapsed = time.monotonic() - started
        release.set()
        assert pending.result(timeout=2).status_code == 200

    assert response.status_code == 200
    assert elapsed < 1


def test_homepage_does_not_wait_for_ludus_authentication(tmp_path: Path) -> None:
    app = create_app(_config(tmp_path))

    def unexpected_probe() -> dict[str, object]:
        raise AssertionError("homepage must not synchronously probe Ludus")

    app.state.service.ludus_status = unexpected_probe
    with TestClient(app) as client:
        response = client.get("/")
        status = client.get("/api/status")

    assert response.status_code == 200
    assert "Checking Ludus authentication in the background" in response.text
    assert status.status_code == 200


def test_failed_job_page_explains_failure_and_offers_restart(tmp_path: Path) -> None:
    app = create_app(_config(tmp_path))
    job, _token = app.state.jobs.create(
        case_id="case-1",
        sample_id="sample-1",
        range_id="range-1",
        run_id="run-1",
        scope={"duration_seconds": 300, "telemetry_profile": "deep"},
    )
    app.state.jobs.transition(
        job["job_id"],
        "failed",
        status="failed",
        message="Workflow failed: provider rejected the response schema.",
        failure="Provider rejected the response schema.",
    )

    with TestClient(app) as client:
        response = client.get(f"/jobs/{job['job_id']}")

    assert response.status_code == 200
    assert "Workflow stopped safely" in response.text
    assert "Provider rejected the response schema." in response.text
    assert "Start a new analysis" in response.text


def test_report_renderer_does_not_enable_embedded_html(tmp_path: Path) -> None:
    config = _config(tmp_path)
    create_case(config.evidence_root, "case-1")
    source = tmp_path / "fixture"
    source.write_bytes(_elf())
    sample = stage_sample(config.evidence_root, "case-1", source)
    create_run(config.evidence_root, "case-1", sample["sample_id"], "standard", "test", "run-1")
    run_dir = config.evidence_root / "case-1" / "run-1"
    (run_dir / "report.md").write_text("# Finding\n<script>alert(1)</script>", encoding="utf-8")
    (run_dir / "report-technical-annex.md").write_text("# Annex", encoding="utf-8")
    response = TestClient(create_app(config)).get("/reports/case-1/run-1")
    assert response.status_code == 200
    assert "<script>alert(1)</script>" not in response.text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in response.text
