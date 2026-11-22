"""Shared orchestration and history for CLI and web email processing."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any, BinaryIO, Literal

from .config import ApplicationSettings
from .extraction import TikaClient
from .history import record_run
from .models import EmailInput, FormatDetection, ParseReport
from .parsing import EmailConversionError, InvalidEmail, parse_email, read_email

if TYPE_CHECKING:
    from collections.abc import Callable

    from .config import Settings
    from .modules import Assessment
    from .tracing import TracingSettings
    from .triage import DecisionEvidence, Verdict


type Action = Literal["parse", "triage"]
type HistoryAction = Action | Literal["upload"]
type RunStatus = Literal["success", "invalid_input", "oversized", "error"]
type Assessor = Callable[[DecisionEvidence, Settings | None], Assessment]
type ProviderOptions = Settings | Callable[[], Settings] | None
type TracingOptions = TracingSettings | Callable[[], TracingSettings] | None


@dataclass(frozen=True)
class RunResult:
    status: RunStatus
    run_id: int | None = None
    parsed: ParseReport | None = None
    verdict: Verdict | None = None
    diagnostic: str | None = None
    persistence_error: str | None = None
    detection: FormatDetection | None = None


def _save(
    action: HistoryAction,
    filename: str | None,
    settings: ApplicationSettings,
    result: RunResult,
    *,
    source: EmailInput | None = None,
    triage_data: dict[str, Any] | None = None,
    diagnostic_detail: str | None = None,
) -> RunResult:
    classifications: list[str] = []
    if result.verdict is not None:
        classifications.extend(result.verdict.attacks)
        if result.verdict.final_verdict != "needs_review":
            classifications.append(result.verdict.final_verdict)
    try:
        run_id = record_run(
            settings.database_path,
            action,
            result.status,
            filename=filename,
            sha256=source.sha256 if source is not None else None,
            original=source.data if source is not None else None,
            parsed=result.parsed,
            triage=triage_data,
            detection=source.detection.model_dump(mode="json")
            if source is not None
            else None,
            diagnostics=tuple(
                message for message in (result.diagnostic, diagnostic_detail) if message
            ),
            classifications=tuple(classifications),
        )
    except (OSError, sqlite3.Error, ValueError, TypeError):
        return replace(
            result,
            persistence_error=(
                "Could not save run history. Check that PHISHCHECK_DATABASE_PATH "
                "points to a writable SQLite database and try again."
            ),
        )
    return replace(result, run_id=run_id)


def record_failure(
    action: HistoryAction,
    filename: str | None,
    status: RunStatus,
    diagnostic: str,
    settings: ApplicationSettings | None = None,
    *,
    diagnostic_detail: str | None = None,
) -> RunResult:
    """Record an attempt rejected before a file stream was available."""
    return _save(
        action,
        filename,
        settings or ApplicationSettings(),
        RunResult(status=status, diagnostic=diagnostic),
        diagnostic_detail=diagnostic_detail,
    )


def _run(
    action: Action,
    stream: BinaryIO,
    filename: str,
    settings: ApplicationSettings | None,
    tika: TikaClient | None,
    *,
    assessor: Assessor | None = None,
    provider_settings: ProviderOptions = None,
    tracing_settings: TracingOptions = None,
) -> RunResult:
    settings = settings or ApplicationSettings()
    source = None
    try:
        source = read_email(stream, filename, settings)
        parsed = parse_email(source, settings, tika or TikaClient(settings.tika_url))
    except InvalidEmail as exc:
        original = source if source is not None else exc.source
        detection = original.detection if original is not None else None
        message = str(exc)
        if detection is not None and "Magika:" not in message:
            message += f" (Magika: {detection.label})"
        return _save(
            action,
            filename,
            settings,
            RunResult(
                status="oversized" if exc.oversized else "invalid_input",
                diagnostic=message,
                detection=detection,
            ),
            source=original,
        )
    except Exception as exc:
        if isinstance(exc, EmailConversionError):
            message = str(exc)
        elif source is None and isinstance(exc, OSError):
            message = "Could not read the email file."
        else:
            message = "Email processing failed. See the run history for details."
        return _save(
            action,
            filename,
            settings,
            RunResult(status="error", diagnostic=message),
            source=source,
            diagnostic_detail=f"{type(exc).__name__}: {exc}",
        )

    if action == "parse":
        return _save(
            action,
            filename,
            settings,
            RunResult(status="success", parsed=parsed),
            source=source,
        )

    from .modules import AssessmentError, AssessmentStage, assess
    from .tracing import TracingSettings, trace_assessment
    from .triage import project_evidence

    stage = None
    diagnostic_detail = None
    try:
        evidence = project_evidence(parsed)
        stage = AssessmentStage(evidence=evidence)
        provider = (
            provider_settings() if callable(provider_settings) else provider_settings
        )
        tracing = tracing_settings() if callable(tracing_settings) else tracing_settings
        with trace_assessment(tracing or TracingSettings()):
            assessment = (assessor or assess)(evidence, provider)
        stage = assessment.stage
        result = RunResult(status="success", parsed=parsed, verdict=assessment.verdict)
    except AssessmentError as exc:
        stage = exc.stage
        if exc.__cause__ is not None:
            diagnostic_detail = f"{type(exc.__cause__).__name__}: {exc.__cause__}"
        result = RunResult(status="error", parsed=parsed, diagnostic=str(exc))
    except Exception as exc:
        diagnostic_detail = f"{type(exc).__name__}: {exc}"
        result = RunResult(
            status="error",
            parsed=parsed,
            diagnostic="Decision provider failed. Check DSPy provider configuration and availability.",
        )
    triage_data = stage.model_dump(mode="json") if stage is not None else {}
    if result.verdict is not None:
        triage_data["verdict"] = result.verdict.model_dump(mode="json")
    return _save(
        action,
        filename,
        settings,
        result,
        source=source,
        triage_data=triage_data,
        diagnostic_detail=diagnostic_detail,
    )


def parse(
    stream: BinaryIO,
    filename: str,
    settings: ApplicationSettings | None = None,
    tika: TikaClient | None = None,
) -> RunResult:
    return _run("parse", stream, filename, settings, tika)


def triage(
    stream: BinaryIO,
    filename: str,
    settings: ApplicationSettings | None = None,
    tika: TikaClient | None = None,
    *,
    assessor: Assessor | None = None,
    provider_settings: ProviderOptions = None,
    tracing_settings: TracingOptions = None,
) -> RunResult:
    return _run(
        "triage",
        stream,
        filename,
        settings,
        tika,
        assessor=assessor,
        provider_settings=provider_settings,
        tracing_settings=tracing_settings,
    )


def run_file(
    action: Action,
    path: str | Path,
    settings: ApplicationSettings | None = None,
    tika: TikaClient | None = None,
    *,
    assessor: Assessor | None = None,
    provider_settings: ProviderOptions = None,
    tracing_settings: TracingOptions = None,
) -> RunResult:
    file_path = Path(path)
    try:
        stream = file_path.open("rb")
    except OSError as exc:
        return record_failure(
            action,
            file_path.name,
            "error",
            "Could not open the email file.",
            settings,
            diagnostic_detail=f"{type(exc).__name__}: {exc}",
        )
    with stream:
        return _run(
            action,
            stream,
            file_path.name,
            settings,
            tika,
            assessor=assessor,
            provider_settings=provider_settings,
            tracing_settings=tracing_settings,
        )


def parse_file(path: str | Path, settings: Any = None, tika: Any = None) -> ParseReport:
    """Parse an on-disk input using the original report-only interface."""
    result = run_file("parse", path, settings, tika)
    if result.persistence_error:
        raise RuntimeError(result.persistence_error)
    if result.parsed is not None:
        return result.parsed
    if result.status in {"invalid_input", "oversized"}:
        raise InvalidEmail(result.diagnostic or "Invalid email")
    raise RuntimeError(result.diagnostic or "Email processing failed")
