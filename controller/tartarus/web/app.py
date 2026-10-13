from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import secrets
import urllib.parse
from pathlib import Path
from typing import Annotated, Any

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
    StreamingResponse,
)
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader, select_autoescape
from markdown_it import MarkdownIt
from markupsafe import Markup
from pydantic import BaseModel, Field

from ..config import Config, load_config
from ..doctor import inspect_environment
from ..errors import ApprovalRequired, TartarusError
from ..manifest import project_root
from .jobs import JobStore, WorkflowRunner
from .oauth import ChatGPTAuth
from .service import ConsoleService

PACKAGE_ROOT = Path(__file__).parent
TERMINAL_JOB_STATUSES = {"completed", "failed", "needs_attention"}


class WorkflowRequest(BaseModel):
    range_id: str
    case_id: str
    sample_id: str
    telemetry_profile: str = "deep"
    duration: int = Field(default=300, ge=1, le=3600)
    archive_password: str | None = Field(default=None, max_length=1024)


class ApprovalBody(BaseModel):
    token: str


class CaseBody(BaseModel):
    case_id: str | None = None


class RebuildBody(BaseModel):
    confirmation: str


def create_app(config: Config | None = None) -> FastAPI:
    resolved = config or load_config()
    jobs = JobStore(resolved.cache_root)
    auth = ChatGPTAuth(resolved.cache_root)
    service = ConsoleService(resolved, jobs, auth)
    runner = WorkflowRunner(jobs, service.execute_workflow, service.recover_failed_job)
    service.resume_interrupted_recoveries()
    sessions = SessionSecurity(resolved.cache_root)
    templates = Environment(
        loader=FileSystemLoader(PACKAGE_ROOT / "templates"),
        autoescape=select_autoescape(("html", "xml")),
    )
    markdown = MarkdownIt("commonmark", {"html": False, "linkify": False})

    def evidence_link(tokens, index, options, env):
        token = tokens[index]
        href = token.attrGet("href")
        if href and not href.startswith(("/", "#")) and not urllib.parse.urlsplit(href).scheme:
            relative = urllib.parse.unquote(href)
            parts = [part for part in relative.split("/") if part]
            if parts and not any(part in {".", ".."} for part in parts):
                case_id = urllib.parse.quote(str(env["case_id"]), safe="")
                run_id = urllib.parse.quote(str(env["run_id"]), safe="")
                path = urllib.parse.quote("/".join(parts), safe="/")
                token.attrSet("href", f"/api/runs/{case_id}/{run_id}/artifacts/{path}")
                token.attrSet("download", "")
        return markdown.renderer.renderToken(tokens, index, options, env)

    markdown.renderer.rules["link_open"] = evidence_link
    app = FastAPI(
        title="Tartarus Operator Console",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.config = resolved
    app.state.jobs = jobs
    app.state.auth = auth
    app.state.service = service
    app.state.runner = runner
    app.mount("/static", StaticFiles(directory=PACKAGE_ROOT / "static"), name="static")

    @app.get("/brand/tartarus-icon.png", include_in_schema=False)
    async def brand_icon():
        packaged = PACKAGE_ROOT / "static" / "tartarus-icon.png"
        return FileResponse(packaged if packaged.is_file() else project_root() / "assets" / "tartarus-icon.png")

    @app.middleware("http")
    async def secure_requests(request: Request, call_next):
        session, is_new = sessions.session(request.cookies.get("tartarus_session"))
        request.state.session = session
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            supplied = request.headers.get("x-csrf-token")
            if not supplied or not secrets.compare_digest(supplied, sessions.csrf(session)):
                return JSONResponse({"detail": "CSRF validation failed"}, status_code=403)
        response = await call_next(request)
        if is_new:
            response.set_cookie(
                "tartarus_session",
                sessions.sign(session),
                httponly=True,
                samesite="strict",
                secure=request.url.scheme == "https",
                max_age=8 * 60 * 60,
            )
        response.headers.update(
            {
                "Content-Security-Policy": "default-src 'self'; img-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self' https://auth.openai.com",
                "Referrer-Policy": "no-referrer",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Cache-Control": "no-store",
                "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
            }
        )
        return response

    @app.exception_handler(TartarusError)
    async def tartarus_error(_request: Request, exc: TartarusError):
        status = 409 if isinstance(exc, ApprovalRequired) else 400
        return JSONResponse({"detail": str(exc)}, status_code=status)

    def render(request: Request, template: str, **context: Any) -> HTMLResponse:
        base = {
            "request": request,
            "csrf_token": sessions.csrf(request.state.session),
            "current_path": request.url.path,
            "chatgpt": auth.status(),
        }
        return HTMLResponse(templates.get_template(template).render(base | context))

    @app.get("/", response_class=HTMLResponse)
    async def overview_page(request: Request):
        overview = await asyncio.to_thread(service.overview)
        return render(request, "overview.html", overview=overview)

    @app.get("/analysis/new", response_class=HTMLResponse)
    async def new_analysis_page(request: Request):
        ranges = await asyncio.to_thread(_safe, service.list_ranges, [])
        return render(
            request,
            "analysis.html",
            ranges=ranges,
            cases=service.list_cases(),
        )

    @app.get("/runs", response_class=HTMLResponse)
    async def runs_page(request: Request):
        return render(request, "runs.html", runs=service.list_runs(), jobs=jobs.list())

    @app.get("/runs/{case_id}/{run_id}", response_class=HTMLResponse)
    async def run_page(request: Request, case_id: str, run_id: str):
        return render(request, "run.html", run=service.run_detail(case_id, run_id), jobs=jobs.list())

    @app.get("/jobs/{job_id}", response_class=HTMLResponse)
    async def job_page(request: Request, job_id: str):
        return render(request, "job.html", job=jobs.get(job_id))

    @app.get("/reports/{case_id}/{run_id}", response_class=HTMLResponse)
    async def report_page(request: Request, case_id: str, run_id: str):
        report = service.report(case_id, run_id).read_text(encoding="utf-8")
        annex_path = service.report(case_id, run_id, annex=True)
        annex = annex_path.read_text(encoding="utf-8") if annex_path.is_file() else ""
        return render(
            request,
            "report.html",
            run=service.run_detail(case_id, run_id),
            report_html=Markup(markdown.render(report, {"case_id": case_id, "run_id": run_id})),
            annex_html=Markup(markdown.render(annex, {"case_id": case_id, "run_id": run_id})),
        )

    @app.get("/reports", response_class=HTMLResponse)
    async def reports_page(request: Request):
        reports = [run for run in service.list_runs() if run["report_available"]]
        return render(request, "reports.html", reports=reports)

    @app.get("/range", response_class=HTMLResponse)
    async def range_page(request: Request):
        ranges = await asyncio.to_thread(_safe, service.list_ranges, [])
        details = []
        for item in ranges:
            details.append(
                await asyncio.to_thread(
                    _safe,
                    lambda item=item: service.range_detail(item["range_id"]),
                    item,
                )
            )
        return render(request, "range.html", ranges=details)

    @app.get("/settings", response_class=HTMLResponse)
    async def settings_page(request: Request):
        overview = await asyncio.to_thread(service.overview)
        return render(
            request,
            "settings.html",
            overview=overview,
            config=resolved.public_dict(),
        )

    @app.get("/api/status")
    async def api_status():
        return await asyncio.to_thread(service.overview)

    @app.get("/api/ludus")
    async def api_ludus():
        return await asyncio.to_thread(service.ludus_status)

    @app.post("/api/diagnostics")
    async def api_diagnostics():
        return await asyncio.to_thread(inspect_environment, resolved)

    @app.get("/api/ranges")
    async def api_ranges():
        return await asyncio.to_thread(service.list_ranges)

    @app.get("/api/ranges/{range_id}")
    async def api_range(range_id: str):
        return await asyncio.to_thread(service.range_detail, range_id)

    @app.post("/api/ranges/{range_id}/verify")
    async def api_verify(range_id: str):
        return await asyncio.to_thread(service.verify, range_id)

    @app.post("/api/ranges/{range_id}/rebuild")
    async def api_rebuild(range_id: str, body: RebuildBody):
        if body.confirmation != range_id:
            raise HTTPException(400, "type the range ID to confirm analysis-pair rebuild")
        return await asyncio.to_thread(service.rebuild, range_id)

    @app.get("/api/cases")
    async def api_cases():
        return service.list_cases()

    @app.post("/api/cases")
    async def api_create_case(body: CaseBody):
        return await asyncio.to_thread(service.create_case, body.case_id)

    @app.post("/api/cases/{case_id}/samples")
    async def api_upload(
        case_id: str,
        sample: Annotated[UploadFile, File()],
    ):
        if not sample.filename:
            raise HTTPException(400, "sample filename is required")
        try:
            return await asyncio.to_thread(
                service.stage_upload,
                case_id,
                sample.filename,
                sample.file,
            )
        finally:
            await sample.close()

    @app.get("/api/runs")
    async def api_runs():
        return service.list_runs()

    @app.get("/api/runs/{case_id}/{run_id}")
    async def api_run(case_id: str, run_id: str):
        return service.run_detail(case_id, run_id)

    @app.get("/api/runs/{case_id}/{run_id}/artifacts/{relative_path:path}")
    async def api_artifact(case_id: str, run_id: str, relative_path: str):
        path = service.artifact(case_id, run_id, relative_path)
        return FileResponse(path, filename=path.name, media_type="application/octet-stream")

    @app.post("/api/workflows")
    async def api_prepare_workflow(body: WorkflowRequest):
        job, token = await asyncio.to_thread(service.prepare_workflow, **body.model_dump())
        return {"job": job, "approval_token": token}

    @app.post("/api/workflows/{job_id}/approve")
    async def api_approve(job_id: str, body: ApprovalBody):
        job = jobs.approve(job_id, body.token)
        runner.start(job_id)
        return job

    @app.get("/api/workflows/{job_id}")
    async def api_job(job_id: str):
        return jobs.get(job_id)

    @app.post("/api/workflows/{job_id}/emergency-stop")
    async def api_emergency_stop(job_id: str):
        return await asyncio.to_thread(service.emergency_stop, job_id)

    @app.get("/api/workflows/{job_id}/events")
    async def api_job_events(request: Request, job_id: str, after: int = 0):
        async def stream():
            cursor = max(after, int(request.headers.get("last-event-id", "0") or 0))
            while True:
                if await request.is_disconnected():
                    return
                events = jobs.events(job_id, cursor)
                for event in events:
                    cursor = event["cursor"]
                    yield f"id: {cursor}\nevent: progress\ndata: {json.dumps(event)}\n\n"
                job = jobs.get(job_id)
                if job["status"] in TERMINAL_JOB_STATUSES and cursor >= job["event_cursor"]:
                    yield f"event: done\ndata: {json.dumps(job)}\n\n"
                    return
                if not events:
                    heartbeat = {
                        "phase": job["phase"],
                        "status": job["status"],
                        "updated_at": job["updated_at"],
                    }
                    yield f"event: heartbeat\ndata: {json.dumps(heartbeat)}\n\n"
                await asyncio.sleep(1)

        return StreamingResponse(stream(), media_type="text/event-stream")

    @app.get("/api/chatgpt")
    async def api_chatgpt():
        return auth.status()

    @app.get("/auth/chatgpt/start")
    async def chatgpt_start(request: Request):
        port = request.url.port or 8741
        redirect_uri = f"http://127.0.0.1:{port}/auth/chatgpt/callback"
        return RedirectResponse(auth.begin(redirect_uri), status_code=303)

    @app.get("/auth/chatgpt/callback", name="chatgpt_callback")
    async def chatgpt_callback(request: Request):
        values = {key: value for key, value in request.query_params.items()}
        await asyncio.to_thread(auth.complete, values)
        return RedirectResponse("/settings?connected=1", status_code=303)

    @app.post("/auth/chatgpt/disconnect")
    async def chatgpt_disconnect():
        revoked = await asyncio.to_thread(auth.disconnect)
        return {"connected": False, "revoked": revoked}

    return app


class SessionSecurity:
    def __init__(self, cache_root: Path):
        root = cache_root / "secrets"
        root.mkdir(parents=True, exist_ok=True)
        root.chmod(0o700)
        self.key_path = root / "ui-session.key"
        if not self.key_path.is_file():
            self.key_path.write_bytes(secrets.token_bytes(32))
            self.key_path.chmod(0o600)
        self.key = self.key_path.read_bytes()

    def sign(self, session: str) -> str:
        signature = hmac.new(self.key, session.encode(), hashlib.sha256).hexdigest()
        return f"{session}.{signature}"

    def session(self, cookie: str | None) -> tuple[str, bool]:
        if cookie and "." in cookie:
            value, signature = cookie.rsplit(".", 1)
            expected = hmac.new(self.key, value.encode(), hashlib.sha256).hexdigest()
            if secrets.compare_digest(signature, expected):
                return value, False
        return secrets.token_urlsafe(32), True

    def csrf(self, session: str) -> str:
        return hmac.new(self.key, f"csrf:{session}".encode(), hashlib.sha256).hexdigest()


def _safe(operation, fallback):
    try:
        return operation()
    except TartarusError:
        return fallback
