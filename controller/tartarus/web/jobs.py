from __future__ import annotations

import json
import secrets
import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from ..errors import ApprovalRequired, AuthenticationRequired, TartarusError
from ..manifest import validate
from ..util import atomic_json, load_json, new_id, utc_now

ACTIVE_STATUSES = {"queued", "running", "cancel_requested"}


class JobStore:
    """Durable workflow state with an append-only, cursor-addressed event stream."""

    def __init__(self, cache_root: Path, *, reconcile: bool = True):
        self.root = cache_root / "ui" / "jobs"
        self.root.mkdir(parents=True, exist_ok=True)
        self.root.chmod(0o700)
        self._lock = threading.RLock()
        self._approval_tokens: dict[str, tuple[str, datetime]] = {}
        if reconcile:
            self.reconcile_interrupted()

    def list(self) -> list[dict[str, Any]]:
        with self._lock:
            jobs = [load_json(path) for path in self.root.glob("*.json")]
        return sorted(jobs, key=lambda item: item["created_at"], reverse=True)

    def get(self, job_id: str) -> dict[str, Any]:
        path = self._path(job_id)
        if not path.is_file():
            raise TartarusError("workflow job was not found")
        return load_json(path)

    def active(self) -> dict[str, Any] | None:
        return next((item for item in self.list() if item["status"] in ACTIVE_STATUSES), None)

    def create(
        self,
        *,
        case_id: str,
        sample_id: str,
        range_id: str,
        run_id: str,
        scope: dict[str, Any],
    ) -> tuple[dict[str, Any], str]:
        with self._lock:
            if self.active():
                raise TartarusError("another mutating workflow is already active")
            now = datetime.now(UTC)
            job_id = new_id("job")
            expires = now + timedelta(minutes=10)
            document = {
                "schema_version": "1.0",
                "job_id": job_id,
                "case_id": case_id,
                "sample_id": sample_id,
                "range_id": range_id,
                "run_id": run_id,
                "phase": "approval",
                "status": "pending_approval",
                "created_at": now.isoformat(),
                "updated_at": now.isoformat(),
                "approval": {
                    "approved": False,
                    "expires_at": expires.isoformat(),
                    "scope": scope,
                },
                "event_cursor": 0,
                "resumability": "not_started",
                "failure": None,
                "analysis_pair_recovery": None,
            }
            token = secrets.token_urlsafe(32)
            self._approval_tokens[job_id] = (token, expires)
            self._save(document)
            self.append_event(job_id, "approval", "Execution approval is required.")
            return self.get(job_id), token

    def approve(self, job_id: str, token: str) -> dict[str, Any]:
        with self._lock:
            job = self.get(job_id)
            active = self.active()
            if active and active["job_id"] != job_id:
                raise TartarusError("another mutating workflow is already active")
            expected = self._approval_tokens.pop(job_id, None)
            if not expected or not secrets.compare_digest(expected[0], token):
                raise ApprovalRequired("approval token is invalid or has already been used")
            if datetime.now(UTC) >= expected[1]:
                raise ApprovalRequired("approval token has expired")
            job["approval"]["approved"] = True
            job["approval"]["approved_at"] = utc_now()
            job["status"] = "queued"
            job["phase"] = "verification"
            job["updated_at"] = utc_now()
            self._save(job)
            self.append_event(job_id, "approval", "Operator approved the recorded execution scope.")
            return self.get(job_id)

    def transition(
        self,
        job_id: str,
        phase: str,
        *,
        status: str = "running",
        message: str,
        resumability: str | None = None,
        failure: str | None = None,
    ) -> dict[str, Any]:
        with self._lock:
            job = self.get(job_id)
            job.update(phase=phase, status=status, updated_at=utc_now(), failure=failure)
            if resumability:
                job["resumability"] = resumability
            self._save(job)
            self.append_event(job_id, phase, message, level="error" if failure else "info")
            return self.get(job_id)

    def append_event(
        self, job_id: str, phase: str, message: str, *, level: str = "info"
    ) -> dict[str, Any]:
        with self._lock:
            job = self.get(job_id)
            cursor = job["event_cursor"] + 1
            event = {
                "cursor": cursor,
                "timestamp": utc_now(),
                "phase": phase,
                "level": level,
                "message": _bounded_message(message),
            }
            path = self._events_path(job_id)
            descriptor = path.open("a", encoding="utf-8")
            try:
                descriptor.write(json.dumps(event, sort_keys=True) + "\n")
                descriptor.flush()
            finally:
                descriptor.close()
            path.chmod(0o600)
            job["event_cursor"] = cursor
            job["updated_at"] = utc_now()
            self._save(job)
            return event

    def set_analysis_pair_recovery(
        self, job_id: str, recovery: dict[str, Any] | None
    ) -> dict[str, Any]:
        with self._lock:
            job = self.get(job_id)
            job["analysis_pair_recovery"] = recovery
            job["updated_at"] = utc_now()
            self._save(job)
            return job

    def events(self, job_id: str, after: int = 0) -> list[dict[str, Any]]:
        self.get(job_id)
        path = self._events_path(job_id)
        if not path.is_file():
            return []
        result = []
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("cursor", 0) > after:
                result.append(event)
        return result[-500:]

    def reconcile_interrupted(self) -> None:
        with self._lock:
            for job in self.list():
                if job["status"] not in ACTIVE_STATUSES:
                    continue
                job.update(
                    phase="attention",
                    status="needs_attention",
                    updated_at=utc_now(),
                    resumability="safe_cleanup_only",
                    failure="The operator console stopped while this workflow was active.",
                )
                self._save(job)
                self.append_event(
                    job["job_id"],
                    "attention",
                    "Automatic execution was not resumed. Inspect the run and use safe cleanup.",
                    level="warning",
                )

    def _save(self, document: dict[str, Any]) -> None:
        validate("workflow-job", document)
        atomic_json(self._path(document["job_id"]), document)

    def _path(self, job_id: str) -> Path:
        if not job_id or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for char in job_id):
            raise TartarusError("invalid workflow job ID")
        return self.root / f"{job_id}.json"

    def _events_path(self, job_id: str) -> Path:
        return self._path(job_id).with_suffix(".events.jsonl")


def _bounded_message(message: str) -> str:
    text = " ".join(str(message).replace("\x00", "").split())
    return text[:2000]


class WorkflowRunner:
    """Runs a workflow in one background thread without weakening cleanup semantics."""

    def __init__(
        self,
        store: JobStore,
        operation: Callable[[dict[str, Any], JobStore], None],
        cleanup: Callable[[dict[str, Any], JobStore], None] | None = None,
    ):
        self.store = store
        self.operation = operation
        self.cleanup = cleanup
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

    def start(self, job_id: str) -> None:
        with self._lock:
            if self._thread and self._thread.is_alive():
                raise TartarusError("another workflow worker is active")
            job = self.store.get(job_id)
            if job["status"] != "queued" or not job["approval"]["approved"]:
                raise ApprovalRequired("workflow has not been approved")
            self._thread = threading.Thread(
                target=self._run, args=(job_id,), daemon=True, name=f"tartarus-{job_id}"
            )
            self._thread.start()

    def _run(self, job_id: str) -> None:
        job = self.store.get(job_id)
        try:
            self.operation(job, self.store)
        except AuthenticationRequired as exc:
            cleanup_failure = self._safe_cleanup(job_id)
            self.store.transition(
                job_id,
                "attention",
                status="needs_attention",
                message=str(exc),
                resumability="blocked",
                failure=str(exc) if cleanup_failure is None else f"{exc}; recovery failed: {cleanup_failure}",
            )
        except Exception as exc:  # noqa: BLE001 - persist all background failures
            cleanup_failure = self._safe_cleanup(job_id)
            current = self.store.get(job_id)
            if current["status"] == "cancel_requested":
                self.store.transition(
                    job_id,
                    "attention",
                    status="needs_attention",
                    message="The AI agent canceled the workflow before execution completed.",
                    resumability="safe_cleanup_only",
                    failure=current["failure"] or str(cleanup_failure or exc),
                )
                return
            self.store.transition(
                job_id,
                "failed",
                status="failed",
                message=f"Workflow failed: {exc}",
                resumability="safe_cleanup_only",
                failure=str(exc) if cleanup_failure is None else f"{exc}; recovery failed: {cleanup_failure}",
            )

    def _safe_cleanup(self, job_id: str) -> Exception | None:
        if self.cleanup is None:
            return None
        try:
            self.cleanup(self.store.get(job_id), self.store)
        except Exception as exc:  # noqa: BLE001 - the recovery state records the detail
            return exc
        return None
