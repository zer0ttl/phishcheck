"""Single-page upload interface."""

from collections.abc import AsyncGenerator
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import UploadFile
from starlette.formparsers import MultiPartException, MultiPartParser
from starlette.requests import ClientDisconnect

from . import service
from .config import ApplicationSettings
from .triage import VERDICT_LABELS

MAX_FORM_OVERHEAD = 1024 * 1024
WEB_DIR = Path(__file__).parent
templates = Jinja2Templates(directory=WEB_DIR / "templates")


class RequestTooLarge(MultiPartException):
    pass


async def _bounded_stream(request: Request, limit: int) -> AsyncGenerator[bytes, None]:
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > limit:
            raise RequestTooLarge("Upload exceeds the request size limit")
        yield chunk


def create_app(settings: ApplicationSettings | None = None) -> FastAPI:
    settings = settings or ApplicationSettings()
    request_limit = settings.max_input_bytes + MAX_FORM_OVERHEAD
    app = FastAPI(title="Phishcheck")
    app.mount("/static", StaticFiles(directory=WEB_DIR / "static"), name="static")

    @app.get("/", response_class=HTMLResponse)
    def home(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(request, "index.html")

    @app.post("/", response_class=HTMLResponse)
    async def upload(request: Request) -> HTMLResponse:
        async def log_rejection(
            reason: str,
            status: service.RunStatus,
            http_status: int,
            detail: str | None = None,
        ) -> HTMLResponse:
            run = await run_in_threadpool(
                service.record_failure,
                "upload",
                None,
                status,
                reason,
                settings,
                diagnostic_detail=detail,
            )
            return templates.TemplateResponse(
                request,
                "index.html",
                {"error": reason, "persistence_error": run.persistence_error},
                status_code=500 if run.persistence_error else http_status,
            )

        content_type = request.headers.get("content-type", "").split(";", 1)[0]
        if content_type.strip().lower() != "multipart/form-data":
            return await log_rejection(
                "Choose an email file and an action.", "invalid_input", 400
            )
        try:
            form = await MultiPartParser(
                request.headers,
                _bounded_stream(request, request_limit),
                max_files=1,
                max_fields=1,
                max_part_size=1024,
            ).parse()
        except RequestTooLarge as exc:
            return await log_rejection(str(exc), "oversized", 413)
        except ClientDisconnect:
            return await log_rejection("The upload was interrupted.", "error", 400)
        except OSError as exc:
            return await log_rejection(
                "Could not read the upload.",
                "error",
                500,
                f"{type(exc).__name__}: {exc}",
            )
        except (MultiPartException, ValueError):
            return await log_rejection(
                "Invalid upload. Choose one email file and an action.",
                "invalid_input",
                400,
            )
        try:
            file = form.get("file")
            action = form.get("action")
            if not isinstance(file, UploadFile) or action not in ("parse", "triage"):
                return await log_rejection(
                    "Choose an email file and an action.", "invalid_input", 400
                )
            process = service.parse if action == "parse" else service.triage
            run = await run_in_threadpool(
                process, file.file, file.filename or "upload", settings
            )
        finally:
            await form.close()

        status = {"success": 200, "invalid_input": 400, "oversized": 413}.get(
            run.status, 500
        )
        if run.persistence_error:
            status = 500
        return templates.TemplateResponse(
            request,
            "index.html",
            {
                "action": action,
                "parsed": run.parsed,
                "reply_to": [
                    header.value
                    for header in (run.parsed.headers_all if run.parsed else ())
                    if header.name.casefold() == "reply-to"
                ],
                "verdict": run.verdict,
                "verdict_label": run.verdict.label if run.verdict else None,
                "verdict_labels": VERDICT_LABELS,
                "verdict_summary": run.verdict.summary_lines() if run.verdict else [],
                "error": run.diagnostic,
                "persistence_error": run.persistence_error,
            },
            status_code=status,
        )

    return app
