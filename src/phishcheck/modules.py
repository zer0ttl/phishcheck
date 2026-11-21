"""DSPy email triage using the native TypeSafe decision provider."""

import base64
import os
from typing import Any, ClassVar

import dspy
from dspy.lm15 import NotConfiguredError, TypeSafeLM
from pydantic import BaseModel, JsonValue, TypeAdapter

from .config import Settings
from .signatures import LABELS, AssessEmail
from .triage import (
    DecisionEvidence,
    ModelChoice,
    PhishingEvidenceScore,
    Verdict,
    classify,
)

_REQUEST_PAYLOAD = TypeAdapter(dict[str, JsonValue])


class AssessmentStage(BaseModel):
    evidence: DecisionEvidence
    request_payload: dict[str, JsonValue] | None = None
    response_body: str | None = None
    response_body_base64: str | None = None
    response_status: int | None = None
    usage: dict[str, JsonValue] | None = None


class Assessment(BaseModel):
    verdict: Verdict
    stage: AssessmentStage


class AssessmentError(RuntimeError):
    def __init__(self, message: str, stage: AssessmentStage) -> None:
        super().__init__(message)
        self.stage = stage


class _RecordingTypeSafe(TypeSafeLM):  # type: ignore[misc]  # DSPy has no typing marker.
    supports_decision_requests: ClassVar[bool] = True
    stage: AssessmentStage

    def _send(self, request: Any) -> Any:
        # The native adapter validates typed answers after receiving the HTTP body.
        # Capture here so errors in JSON, HTTP status or typed answers keep the payload.
        self.stage.request_payload = _REQUEST_PAYLOAD.validate_json(request.body)
        response = super()._send(request)
        self.stage.response_status = response.status
        try:
            self.stage.response_body = response.body.decode("utf-8")
        except UnicodeDecodeError:
            self.stage.response_body_base64 = base64.b64encode(response.body).decode(
                "ascii"
            )
        return response


class EmailAssessor(dspy.Module):  # type: ignore[misc]  # DSPy has no typing marker.
    def __init__(self) -> None:
        super().__init__()
        self.predictor = dspy.Predict(AssessEmail)

    def forward(self, evidence: dict[str, JsonValue]) -> dspy.Prediction:
        return self.predictor(evidence=evidence)


def assess(evidence: DecisionEvidence, settings: Settings | None = None) -> Assessment:
    stage = AssessmentStage(evidence=evidence)
    try:
        effective = settings if settings is not None else Settings()
    except ValueError as exc:
        raise AssessmentError(
            "Invalid decision provider configuration.", stage
        ) from exc
    options = dict(effective.lm_kwargs)
    model_name = effective.model.removeprefix("typesafe:")
    if (
        model_name == effective.model
        or not model_name
        or options.pop("engine", "auto") not in ("auto", "lm15")
        or options.pop("model_type", "auto") != "auto"
    ):
        raise AssessmentError(
            "Email triage requires a TypeSafe System One model (typesafe:<model>) and the native DSPy engine.",
            stage,
        )

    if options.pop("cache", False) is not False:
        raise AssessmentError(
            "Email triage requires cache=false to record each provider response.",
            stage,
        )

    api_key = effective.api_key or os.getenv("TYPESAFE_API_KEY")
    if not api_key:
        raise AssessmentError(
            "Set DSPY_API_KEY or TYPESAFE_API_KEY for email triage.", stage
        )
    try:
        provider_options = (
            {"base_url": effective.api_base} if effective.api_base else {}
        )
        engine = _RecordingTypeSafe(api_key=api_key, **provider_options)
        engine.stage = stage
        lm = dspy.LM(model=effective.model, engine=engine, cache=False, **options)
    except (NotConfiguredError, TypeError, ValueError) as exc:
        raise AssessmentError(
            "Invalid decision provider configuration.", stage
        ) from exc
    try:
        with dspy.context(lm=lm, track_usage=effective.track_usage):
            prediction = EmailAssessor()(evidence=evidence.model_dump(mode="json"))
        stage.usage = prediction.get_lm_usage()
        probabilities = {}
        for name in LABELS:
            probability = prediction[name].probability
            if probability is None:
                raise ValueError("Missing typed answer probability")
            probabilities[name] = probability
        choice = prediction["email_verdict"]
        score = prediction["phishing_evidence_score"]
        verdict = classify(
            evidence,
            probabilities,
            model_choice=ModelChoice(
                choice=choice.value,
                probabilities=choice.probabilities,
                confidence=choice.confidence,
            ),
            phishing_evidence_score=PhishingEvidenceScore(
                score=score.value,
                probabilities=score.probabilities,
                confidence=score.confidence,
            ),
            benign_explanation=prediction["benign_explanation"].probability,
        )
        return Assessment(verdict=verdict, stage=stage)
    except Exception as exc:
        raise AssessmentError(
            "Decision provider failed to return a complete typed assessment.", stage
        ) from exc
    finally:
        engine.close()
