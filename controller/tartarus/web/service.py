from __future__ import annotations

import json
import shutil
import tempfile
import threading
from pathlib import Path
from typing import Any, BinaryIO

from ..analysis import prepare_archive_with_agent, run_analysis_agent
from ..config import Config
from ..elf import triage_elf
from ..errors import TartarusError
from ..lifecycle import (
    assert_analysis_pair_ready,
    cancel_pre_execution_run,
    pair_recovery_state,
    quarantine_analysis_pair,
    rebuild_sandbox,
    recover_analysis_pair,
    start_remote_run,
    stop_remote_run,
    stop_static_analysis_run,
)
from ..ludus import authenticated_user, run_ludus
from ..manifest import MAX_SAMPLE_BYTES, create_case, create_run, stage_sample, validate
from ..providers import ChatGPTCodexProvider
from ..remote import range_guests
from ..reporting import generate_agent_report
from ..telemetry import telemetry_health
from ..util import atomic_json, load_json, new_id, safe_id
from ..verify import verify_range
from .jobs import JobStore
from .oauth import ChatGPTAuth


class ConsoleService:
    def __init__(self, config: Config, jobs: JobStore, auth: ChatGPTAuth):
        self.config = config
        self.jobs = jobs
        self.auth = auth
        self._workflow_secrets: dict[str, str] = {}
        self._secret_lock = threading.Lock()

    def overview(self) -> dict[str, Any]:
        runs = self.list_runs()
        return {
            "ludus_connected": None,
            "ludus_user": None,
            "chatgpt": self.auth.status(),
            "active_job": self.jobs.active(),
            "recent_runs": runs[:5],
            "case_count": len(self.list_cases()),
            "run_count": len(runs),
            "evidence_free_bytes": shutil.disk_usage(self.config.evidence_root).free,
        }

    def ludus_status(self) -> dict[str, Any]:
        try:
            user = authenticated_user(self.config.ludus_config)
            connected = True
            detail = "Authenticated with the Ludus controller."
        except TartarusError as exc:
            user = None
            connected = False
            detail = str(exc)
        return {
            "ludus_connected": connected,
            "ludus_user": user,
            "detail": detail,
        }

    def list_ranges(self) -> list[dict[str, Any]]:
        result = run_ludus(("range", "accessible", "--json"), config=self.config.ludus_config)
        try:
            value = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise TartarusError("could not parse accessible Ludus ranges") from exc
        items = value if isinstance(value, list) else value.get("ranges", [])
        ranges = []
        for item in items if isinstance(items, list) else []:
            if not isinstance(item, dict):
                continue
            range_id = item.get("rangeID") or item.get("range_id") or item.get("id")
            if range_id:
                ranges.append({"range_id": str(range_id), "name": item.get("name") or str(range_id)})
        return ranges

    def range_detail(self, range_id: str) -> dict[str, Any]:
        self._assert_managed(range_id)
        guests = range_guests(self.config, range_id)
        try:
            telemetry = telemetry_health(self.config, range_id)
        except TartarusError as exc:
            telemetry = {"healthy": False, "detail": str(exc)}
        return {
            "range_id": range_id,
            "telemetry": telemetry,
            "analysis_pair_recovery": pair_recovery_state(self.config, range_id),
            "guests": [
                {
                    "role": role,
                    "name": guest.name,
                    "address": guest.address,
                    "username": guest.user,
                    "vmid": guest.vmid,
                }
                for role, guest in sorted(guests.items())
            ],
        }

    def verify(self, range_id: str) -> dict[str, Any]:
        self._assert_managed(range_id)
        return verify_range(self.config, range_id)

    def rebuild(self, range_id: str) -> dict[str, Any]:
        self._assert_managed(range_id)
        return rebuild_sandbox(self.config, range_id)

    def list_cases(self) -> list[dict[str, Any]]:
        result = []
        if not self.config.evidence_root.is_dir():
            return result
        for path in self.config.evidence_root.glob("*/case.json"):
            if path.is_symlink():
                continue
            try:
                case = load_json(path)
                validate("case-manifest", case)
            except (OSError, TartarusError):
                continue
            result.append(case)
        return sorted(result, key=lambda item: item["created_at"], reverse=True)

    def create_case(self, case_id: str | None = None) -> dict[str, Any]:
        return create_case(self.config.evidence_root, case_id or None)

    def stage_upload(
        self,
        case_id: str,
        filename: str,
        source: BinaryIO,
    ) -> dict[str, Any]:
        safe_id(case_id, "case ID")
        display_name = Path(filename).name
        if not display_name or display_name != filename or display_name in {".", ".."}:
            raise TartarusError("upload filename is invalid")
        upload_root = self.config.cache_root / "ui" / "uploads"
        upload_root.mkdir(parents=True, exist_ok=True)
        upload_root.chmod(0o700)
        total = 0
        temporary_path: Path | None = None
        try:
            descriptor, name = tempfile.mkstemp(prefix="upload-", dir=upload_root)
            temporary_path = Path(name)
            with open(descriptor, "wb", closefd=True) as output:
                while chunk := source.read(1024 * 1024):
                    total += len(chunk)
                    if total > MAX_SAMPLE_BYTES:
                        raise TartarusError("sample exceeds the 1 GiB execution input limit")
                    output.write(chunk)
            temporary_path.chmod(0o600)
            record = stage_sample(self.config.evidence_root, case_id, temporary_path)
            case_path = self.config.evidence_root / case_id / "case.json"
            case = load_json(case_path)
            for sample in case["samples"]:
                if sample["sample_id"] == record["sample_id"]:
                    sample["original_name"] = display_name
                    record = sample
                    break
            validate("case-manifest", case)
            atomic_json(case_path, case)
            return record
        finally:
            if temporary_path:
                temporary_path.unlink(missing_ok=True)

    def list_runs(self) -> list[dict[str, Any]]:
        result = []
        if not self.config.evidence_root.is_dir():
            return result
        for path in self.config.evidence_root.glob("*/*/run.json"):
            if path.is_symlink():
                continue
            try:
                run = load_json(path)
                validate("run-manifest", run)
            except (OSError, TartarusError):
                continue
            result.append(self._run_projection(run, path.parent))
        return sorted(result, key=lambda item: item["started_at"], reverse=True)

    def run_detail(self, case_id: str, run_id: str) -> dict[str, Any]:
        path = self._run_file(case_id, run_id)
        run = load_json(path)
        validate("run-manifest", run)
        return self._run_projection(run, path.parent) | {"artifacts": run["artifacts"]}

    def report(self, case_id: str, run_id: str, annex: bool = False) -> Path:
        run_dir = self._run_file(case_id, run_id).parent
        target = run_dir / ("report-technical-annex.md" if annex else "report.md")
        if not target.is_file() or target.is_symlink() or not target.resolve().is_relative_to(run_dir):
            raise TartarusError("report is not available")
        return target

    def artifact(self, case_id: str, run_id: str, relative_path: str) -> Path:
        run_file = self._run_file(case_id, run_id)
        run = load_json(run_file)
        allowed = {
            item["relative_path"]
            for item in run["artifacts"]
            if item.get("collection_status") == "collected"
        }
        if relative_path not in allowed:
            raise TartarusError("artifact is not present in the run manifest")
        target = (run_file.parent / relative_path).resolve()
        if not target.is_relative_to(run_file.parent.resolve()) or not target.is_file() or target.is_symlink():
            raise TartarusError("artifact path is unsafe")
        return target

    def prepare_workflow(
        self,
        *,
        range_id: str,
        case_id: str,
        sample_id: str,
        telemetry_profile: str,
        duration: int,
        archive_password: str | None = None,
    ) -> tuple[dict[str, Any], str]:
        auth_status = self.auth.status()
        if not auth_status["connected"] or not auth_status["plan_usage"]:
            raise TartarusError("connect a ChatGPT account with plan usage before starting analysis")
        self._assert_managed(range_id)
        recovery = assert_analysis_pair_ready(self.config, range_id)
        safe_id(case_id, "case ID")
        safe_id(sample_id, "sample ID")
        if telemetry_profile not in {"lightweight", "standard", "deep"}:
            raise TartarusError("unsupported telemetry profile")
        if not 1 <= duration <= 3600:
            raise TartarusError("duration must be between 1 and 3600 seconds")
        sample = self.config.evidence_root / case_id / "samples" / sample_id / "sample.bin"
        if not sample.is_file() or sample.is_symlink():
            raise TartarusError("sample is not staged")
        case = load_json(self.config.evidence_root / case_id / "case.json")
        sample_record = next(
            (item for item in case["samples"] if item["sample_id"] == sample_id),
            None,
        )
        if sample_record is None:
            raise TartarusError("sample is not present in the case manifest")
        is_archive = sample_record["media_type"] == "application/zip"
        if archive_password and not is_archive:
            raise TartarusError("a ZIP password can only be supplied for a ZIP analysis input")
        deployment = load_json(self.config.cache_root / "state" / "prepare-manifest.json")
        if deployment.get("deployment", {}).get("range_id") != range_id:
            raise TartarusError("selected range is not identified by the deployment manifest")
        run_id = new_id("run")
        scope = {
            "operation": "execute ELF in disposable sandbox and complete guided analysis",
            "range_id": range_id,
            "case_id": case_id,
            "sample_id": sample_id,
            "run_id": run_id,
            "telemetry_profile": telemetry_profile,
            "duration_seconds": duration,
            "debug_session": True,
            "input_type": "zip" if is_archive else "elf",
            "archive_password_provided": bool(archive_password) if is_archive else False,
            "post_run_action": "collect evidence, rebuild and verify both analysis guests, generate report",
        }
        created = self.jobs.create(
            case_id=case_id,
            sample_id=sample_id,
            range_id=range_id,
            run_id=run_id,
            scope=scope,
        )
        self.jobs.set_analysis_pair_recovery(created[0]["job_id"], recovery)
        created = (self.jobs.get(created[0]["job_id"]), created[1])
        if is_archive:
            with self._secret_lock:
                self._workflow_secrets[created[0]["job_id"]] = archive_password or ""
        return created

    def execute_workflow(self, job: dict[str, Any], store: JobStore) -> None:
        job_id = job["job_id"]
        scope = job["approval"]["scope"]
        with self._secret_lock:
            archive_password = self._workflow_secrets.pop(job_id, None)
        self.auth.access_token()
        store.transition(job_id, "verification", message="AI authorization is valid. Running the complete range verification gate.")
        verification = self.verify(job["range_id"])
        if not verification["passed"]:
            quarantine_analysis_pair(
                self.config,
                job["range_id"],
                "range readiness verification failed",
            )
            self._sync_job_recovery(job_id, job["range_id"])
            raise TartarusError("range verification failed; the sample was not executed")
        deployment = load_json(self.config.cache_root / "state" / "prepare-manifest.json")
        run = create_run(
            self.config.evidence_root,
            job["case_id"],
            job["sample_id"],
            scope["telemetry_profile"],
            deployment["tartarus_release"],
            job["run_id"],
        )
        run_file = self._run_file(job["case_id"], run["run_id"])
        prepared_sample: Path | None = None
        try:
            if scope.get("input_type") == "zip":
                if archive_password is None:
                    raise TartarusError(
                        "archive password context was lost; return to New analysis and retry"
                    )
                store.transition(
                    job_id,
                    "preparing",
                    message="The AI agent is selecting and preparing the archived ELF on REMnux.",
                    resumability="safe_cleanup_only",
                )
                try:
                    prepared_sample = prepare_archive_with_agent(
                        self.config,
                        run_file,
                        job["range_id"],
                        archive_password,
                        provider=ChatGPTCodexProvider(self.auth.access_token),
                    )
                    self._sync_job_recovery(job_id, job["range_id"])
                except Exception:
                    current = store.get(job_id)
                    if current["status"] == "cancel_requested":
                        cancel_pre_execution_run(self.config, run_file)
                        self._sync_job_recovery(job_id, job["range_id"])
                        store.transition(
                            job_id,
                            "attention",
                            status="needs_attention",
                            message="The AI agent canceled before execution; both analysis guests were recovered.",
                            resumability="safe_cleanup_only",
                            failure=current["failure"],
                        )
                        return
                    raise
            analysis_sample = prepared_sample or (
                self.config.evidence_root
                / job["case_id"]
                / "samples"
                / job["sample_id"]
                / "sample.bin"
            )
            # Validation is controller-owned, but its result is deliberately not projected into
            # the run or prompt. The analysis agent must establish all sample facts itself.
            triage_elf(analysis_sample)
            store.transition(
                job_id,
                "starting",
                message="Staging the prepared ELF and starting bounded debug execution.",
                resumability="safe_cleanup_only",
            )
            start_remote_run(
                self.config,
                job["range_id"],
                run_file,
                int(scope["duration_seconds"]),
                True,
                sample_override=prepared_sample,
            )
            self._sync_job_recovery(job_id, job["range_id"])
        finally:
            if prepared_sample is not None:
                prepared_sample.unlink(missing_ok=True)
        analysis_failure: Exception | None = None
        try:
            store.transition(
                job_id,
                "analyzing",
                message="The AI agent is identifying the sample and correlating static, dynamic, debugger, and telemetry evidence.",
            )
            run_analysis_agent(
                run_file,
                provider=ChatGPTCodexProvider(self.auth.access_token),
            )
        except Exception as exc:  # noqa: BLE001 - cleanup must still occur
            analysis_failure = exc
            store.append_event(job_id, "analyzing", f"Analysis stopped: {exc}", level="error")
        current_status = store.get(job_id)["status"]
        if current_status == "cancel_requested":
            cancel_reason = store.get(job_id)["failure"]
            store.transition(
                job_id,
                "collecting",
                message="The AI agent requested cancellation. Starting the required safe cleanup path.",
            )
            stop_remote_run(self.config, run_file)
            self._sync_job_recovery(job_id, job["range_id"])
            store.transition(
                job_id,
                "attention",
                status="needs_attention",
                message="AI-requested cancellation completed with evidence collection and containment verification.",
                resumability="safe_cleanup_only",
                failure=cancel_reason,
            )
            return
        if current_status == "needs_attention":
            return
        store.transition(
            job_id,
            "collecting",
            message="Stopping execution and collecting controller-owned evidence.",
        )
        stop_remote_run(self.config, run_file)
        self._sync_job_recovery(job_id, job["range_id"])
        recovery_message = "The disposable analysis pair was rebuilt and verification passed."
        store.transition(job_id, "recovering", message=recovery_message)
        store.transition(job_id, "reporting", message="Generating the evidence-linked report and technical annex.")
        generate_agent_report(
            run_file,
            run_file.parent / "report.md",
            provider=ChatGPTCodexProvider(self.auth.access_token),
        )
        if analysis_failure:
            raise TartarusError(f"analysis was incomplete, but evidence recovery and reporting finished: {analysis_failure}")
        store.transition(
            job_id,
            "complete",
            status="completed",
            message="Analysis, evidence recovery, and reporting are complete.",
            resumability="complete",
        )

    def emergency_stop(self, job_id: str) -> dict[str, Any]:
        job = self.jobs.get(job_id)
        run_file = self._run_file(job["case_id"], job["run_id"])
        if not run_file.is_file():
            raise TartarusError("run has not reached remote execution")
        self.jobs.append_event(job_id, "collecting", "Operator requested emergency stop.", level="warning")
        run = load_json(run_file)
        try:
            if run.get("execution_mode") == "static_only":
                stop_static_analysis_run(self.config, run_file)
            else:
                stop_remote_run(self.config, run_file)
        finally:
            self._sync_job_recovery(job_id, job["range_id"])
        return self.jobs.transition(
            job_id,
            "attention",
            status="needs_attention",
            message="Execution stopped, evidence collected, and analysis-pair recovery attempted.",
            resumability="safe_cleanup_only",
            failure="Workflow was stopped by the operator.",
        )

    def recover_failed_job(self, job: dict[str, Any], store: JobStore) -> None:
        """Finish only approved safe cleanup after a workflow exception."""
        state = pair_recovery_state(self.config, job["range_id"])
        if state["state"] == "clean":
            store.set_analysis_pair_recovery(job["job_id"], state)
            return
        run_file = self._run_file(job["case_id"], job["run_id"])
        if not run_file.is_file():
            return
        store.append_event(
            job["job_id"], "recovering", "Resuming required analysis-pair cleanup."
        )
        try:
            recover_analysis_pair(self.config, job["range_id"], run_file=run_file)
        finally:
            store.set_analysis_pair_recovery(
                job["job_id"], pair_recovery_state(self.config, job["range_id"])
            )

    def resume_interrupted_recoveries(self) -> None:
        jobs = [
            job
            for job in self.jobs.list()
            if job["status"] == "needs_attention"
            and pair_recovery_state(self.config, job["range_id"])["state"]
            in {"unverified", "tainted", "recovering", "quarantined"}
            and self._run_file(job["case_id"], job["run_id"]).is_file()
        ]
        if not jobs:
            return

        def cleanup() -> None:
            for job in jobs:
                try:
                    self.recover_failed_job(job, self.jobs)
                except TartarusError as exc:
                    self.jobs.append_event(
                        job["job_id"],
                        "attention",
                        f"Automatic recovery remains quarantined: {exc}",
                        level="error",
                    )

        threading.Thread(
            target=cleanup, daemon=True, name="tartarus-interrupted-recovery"
        ).start()

    def _sync_job_recovery(self, job_id: str, range_id: str) -> None:
        self.jobs.set_analysis_pair_recovery(job_id, pair_recovery_state(self.config, range_id))

    def _assert_managed(self, range_id: str) -> None:
        from ..cli import assert_managed_range

        assert_managed_range(self.config, range_id)

    def _run_file(self, case_id: str, run_id: str) -> Path:
        safe_id(case_id, "case ID")
        safe_id(run_id, "run ID")
        return self.config.evidence_root / case_id / run_id / "run.json"

    @staticmethod
    def _run_projection(run: dict[str, Any], run_dir: Path) -> dict[str, Any]:
        return {
            "case_id": run["case_id"],
            "run_id": run["run_id"],
            "sample_id": run["sample"]["sample_id"],
            "range_id": run.get("range_id"),
            "status": run["status"],
            "telemetry_profile": run["telemetry_profile"],
            "started_at": run["started_at"],
            "stopped_at": run.get("stopped_at"),
            "recovery_verified": run.get("recovery_verified"),
            "analysis_pair_recovery": run.get("analysis_pair_recovery"),
            "visibility_gaps": run["visibility_gaps"],
            "artifact_count": len(run["artifacts"]),
            "report_available": (run_dir / "report.md").is_file(),
            "annex_available": (run_dir / "report-technical-annex.md").is_file(),
        }
