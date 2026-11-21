"""Evidence projection and deterministic verdict rules."""

import json
from collections.abc import Callable, Mapping
from typing import Annotated, Literal

from dspy.adapters.types.base_type import CUSTOM_TYPE_START_IDENTIFIER
from pydantic import BaseModel, Field, TypeAdapter

from .models import EmailLink, ParseReport
from .signatures import INSTRUCTIONS, LABELS, STATE_FIELDS

STATE_BUDGET = 16 * 1024
SELECTED_HEADERS = (
    "From",
    "Sender",
    "Reply-To",
    "Return-Path",
    "To",
    "Subject",
    "Authentication-Results",
    "Received-SPF",
    "DKIM-Signature",
)
TRUSTED_REQUIREMENTS = {
    "drive_by_download": "destination_behavior",
    "compromised_sender": "account_evidence",
    "email_thread_hijacking": "thread_evidence",
    "polymorphic": "campaign_samples",
    "trusted_third_party_impersonation": "relationship_evidence",
    "incorrectly_submitted": "submission_context",
    "phishing_simulation": "authorized_simulation",
}
SENDER_FIELDS = tuple(
    f"headers.{name}" for name in SELECTED_HEADERS if name not in {"Subject", "To"}
)
ATTACHMENT_FIELDS = (
    "attachments.name",
    "attachments.content_type",
    "attachments.text",
    "attachments.detected_type",
)
PURPOSE_FIELDS = ("headers.Subject", "body", "urls")
SOURCE_FIELDS = {
    "spoofing": SENDER_FIELDS,
    "malicious_attachment": ATTACHMENT_FIELDS,
    "malicious_url": ("urls",),
    "drive_by_download": ("urls",),
    "malware": ("urls", *ATTACHMENT_FIELDS, "body"),
    "targeted": ("headers.To", *PURPOSE_FIELDS),
    "high_value_target": ("headers.To", *PURPOSE_FIELDS),
    "legitimate_email": (*SENDER_FIELDS, *PURPOSE_FIELDS),
    "impersonation": (*SENDER_FIELDS, *PURPOSE_FIELDS),
    "government_agency_impersonation": (*SENDER_FIELDS, *PURPOSE_FIELDS),
    "third_party_impersonation": (*SENDER_FIELDS, *PURPOSE_FIELDS),
    "trusted_third_party_impersonation": (*SENDER_FIELDS, *PURPOSE_FIELDS),
    "vip_impersonation": (*SENDER_FIELDS, *PURPOSE_FIELDS),
}
NON_ATTACK_FINDINGS = (
    "phishing_simulation",
    "incorrectly_submitted",
    "unsolicited_email",
    "legitimate_email",
)
Probability = Annotated[float, Field(strict=True, ge=0, le=1, allow_inf_nan=False)]
PROBABILITY = TypeAdapter(Probability)
SUPPORTED_THRESHOLD = 0.80
type EmailVerdict = Literal[
    "likely_phishing", "likely_legitimate", "unsolicited_bulk_email", "needs_review"
]
type ReviewReason = Literal[
    "model_needs_review",
    "low_choice_probability",
    "conflicting_attack_findings",
    "incomplete_evidence_for_benign_choice",
    "supported_benign_explanation",
]

VERDICT_LABELS: dict[EmailVerdict, str] = {
    "likely_phishing": "Likely phishing",
    "likely_legitimate": "Likely legitimate",
    "unsolicited_bulk_email": "Unsolicited bulk email",
    "needs_review": "Needs review",
}
REVIEW_MESSAGES: dict[ReviewReason, str] = {
    "model_needs_review": "Jev found the evidence insufficient or conflicting.",
    "low_choice_probability": "The model's choice probability is below 80%.",
    "conflicting_attack_findings": "Supported attack findings conflict with the model's choice.",
    "incomplete_evidence_for_benign_choice": "Some email evidence was unavailable or incomplete.",
    "supported_benign_explanation": "Email evidence supports an ordinary explanation for the suspicious behavior.",
}


class AttachmentEvidence(BaseModel):
    name: str | None = None
    content_type: str | None = None
    status: Literal["not_extracted", "complete", "unavailable", "truncated"]
    text: str | None = None
    detected_type: str | None = None
    text_truncated: bool = False


class DecisionEvidence(BaseModel):
    headers: dict[str, str] = Field(default_factory=dict)
    body: str | None = None
    urls: list[EmailLink] = Field(default_factory=list)
    attachments: list[AttachmentEvidence] = Field(default_factory=list)
    body_status: Literal["complete", "absent", "unavailable", "truncated"] = "absent"
    omissions: list[Literal["headers", "body", "urls", "attachments"]] = Field(
        default_factory=list
    )
    destination_behavior: bool = False
    account_evidence: bool = False
    thread_evidence: bool = False
    campaign_samples: bool = False
    relationship_evidence: bool = False
    submission_context: bool = False
    authorized_simulation: bool = False


class Judgment(BaseModel):
    classification: str
    probability: float | None = Field(default=None, ge=0, le=1, allow_inf_nan=False)
    status: Literal["supported", "unsupported", "uncertain", "insufficient_evidence"]
    missing_field: str | None = None
    evidence_fields: list[str] = Field(default_factory=list)


class ModelChoice(BaseModel):
    choice: EmailVerdict
    probabilities: dict[EmailVerdict, Probability]
    confidence: Probability

    @property
    def probability(self) -> float:
        return self.probabilities[self.choice]


class PhishingEvidenceScore(BaseModel):
    score: Annotated[float, Field(strict=True, ge=0, le=4, allow_inf_nan=False)]
    probabilities: dict[Literal[0, 1, 2, 3, 4], Probability]
    confidence: Probability


class Verdict(BaseModel):
    final_verdict: EmailVerdict
    model_choice: ModelChoice
    phishing_evidence_score: PhishingEvidenceScore
    benign_explanation: Probability
    review_reasons: list[ReviewReason]
    attacks: list[str]
    outcome: Literal["classified", "needs_review"]
    judgments: list[Judgment]

    @property
    def label(self) -> str:
        return VERDICT_LABELS[self.final_verdict]

    def summary_lines(self) -> list[str]:
        lines = [
            f"Phishing evidence strength: {self.phishing_evidence_score.score:.1f} out of 4"
        ]
        if self.attacks:
            findings = ", ".join(label.replace("_", " ") for label in self.attacks)
            lines.append(f"Supported findings: {findings}")
        if self.model_choice.choice != self.final_verdict:
            choice = VERDICT_LABELS[self.model_choice.choice]
            lines.append(
                f"Jev selected {choice} ({self.model_choice.probability:.0%})."
            )
        lines.extend(REVIEW_MESSAGES[reason] for reason in self.review_reasons)
        return lines


def _inert(value: str) -> str:
    # DSPy interprets this reserved marker as a typed media part. Escape its
    # first angle bracket so uploaded text stays inside the JSON data part.
    return value.replace(
        CUSTOM_TYPE_START_IDENTIFIER,
        r"\u003c" + CUSTOM_TYPE_START_IDENTIFIER[1:],
    )


def project_evidence(report: ParseReport) -> DecisionEvidence:
    evidence = DecisionEvidence(
        body_status=report.body_status,
        omissions=["headers", "body", "urls", "attachments"],
    )

    def fits() -> bool:
        state = {
            "instructions": INSTRUCTIONS,
            "input_fields": STATE_FIELDS,
            "inputs": {"evidence": evidence.model_dump(mode="json")},
        }
        return len(json.dumps(state).encode()) <= STATE_BUDGET

    def fit_text(value: str, assign: Callable[[str], None], limit: int) -> bool:
        low, high = 0, min(len(value), limit)
        while low < high:
            length = (low + high + 1) // 2
            assign(value[:length])
            if fits():
                low = length
            else:
                high = length - 1
        assign(value[:low])
        return low == len(value)

    headers = {key.casefold(): value for key, value in report.headers.items()}
    headers_complete = True
    for key in SELECTED_HEADERS:
        if key.casefold() not in headers:
            continue
        evidence.headers[key] = ""
        if not fits():
            del evidence.headers[key]
            headers_complete = False
            break
        if not fit_text(
            _inert(headers[key.casefold()]),
            lambda value: evidence.headers.__setitem__(key, value),
            512,
        ):
            headers_complete = False
    if headers_complete:
        evidence.omissions.remove("headers")

    urls_complete = True
    for link in report.urls:
        url = _inert(link["url"])
        if len(url) > 2048:
            urls_complete = False
            continue
        label = _inert(link["text"])
        if len(label) > 512:
            urls_complete = False
        evidence.urls.append({"text": label[:512], "url": url})
        if not fits():
            evidence.urls.pop()
            urls_complete = False
            break
    if urls_complete:
        evidence.omissions.remove("urls")

    attachments_complete = not any(
        warning.startswith("Additional attachments omitted")
        for warning in report.warnings
    )
    for attachment in report.attachments:
        projected = AttachmentEvidence(
            name=_inert(attachment.name)[:256] if attachment.name else attachment.name,
            content_type=_inert(attachment.content_type)[:128]
            if attachment.content_type
            else attachment.content_type,
            status=attachment.status,
            detected_type=_inert(attachment.detection.label)
            if attachment.detection
            else None,
        )
        evidence.attachments.append(projected)
        if not fits():
            evidence.attachments.pop()
            attachments_complete = False
            break
        if attachment.text:
            projected.text = ""
            if not fits():
                projected.text = None
                projected.text_truncated = True
            else:
                projected.text_truncated = not fit_text(
                    _inert(attachment.text),
                    lambda value: setattr(projected, "text", value),
                    2048,
                )
            if projected.text_truncated:
                attachments_complete = False
        if (
            projected.name != attachment.name
            or projected.content_type != attachment.content_type
        ):
            attachments_complete = False
    if attachments_complete:
        evidence.omissions.remove("attachments")

    if not report.body or fit_text(
        _inert(report.body),
        lambda value: setattr(evidence, "body", value),
        STATE_BUDGET,
    ):
        evidence.omissions.remove("body")
    return evidence


def classify(
    evidence: DecisionEvidence,
    probabilities: Mapping[str, float | None],
    *,
    model_choice: ModelChoice,
    phishing_evidence_score: PhishingEvidenceScore,
    benign_explanation: float,
) -> Verdict:
    benign_explanation = PROBABILITY.validate_python(benign_explanation)
    judgments: list[Judgment] = []
    present = {f"headers.{name}" for name, value in evidence.headers.items() if value}
    present.update(name for name in ("body", "urls") if getattr(evidence, name))
    present.update(
        field
        for field in ATTACHMENT_FIELDS
        if any(
            getattr(attachment, field.removeprefix("attachments."))
            for attachment in evidence.attachments
        )
    )
    incomplete = (
        bool(evidence.omissions)
        or evidence.body_status in {"unavailable", "truncated"}
        or any(attachment.status != "complete" for attachment in evidence.attachments)
    )
    for label in LABELS:
        probability = probabilities.get(label)
        if probability is not None:
            probability = PROBABILITY.validate_python(probability)
        fields = [
            field
            for field in SOURCE_FIELDS.get(label, PURPOSE_FIELDS)
            if field in present
        ]
        missing = TRUSTED_REQUIREMENTS.get(label)
        if missing is not None and getattr(evidence, missing):
            fields.append(missing)
            missing = None
        if label in {"legitimate_email", "unsolicited_email"} and incomplete:
            if evidence.body_status in {"unavailable", "truncated"}:
                missing = "body"
            elif evidence.omissions:
                missing = evidence.omissions[0]
            else:
                missing = "attachments.text"
        if label == "malicious_attachment" and not any(
            a.text for a in evidence.attachments
        ):
            missing = (
                "attachments.text"
                if evidence.attachments or "attachments" in evidence.omissions
                else "attachments"
            )
        if label == "malicious_url" and not evidence.urls:
            missing = "urls"
        if missing is not None or probability is None:
            judgments.append(
                Judgment(
                    classification=label,
                    status="insufficient_evidence",
                    missing_field=missing or "probability",
                    evidence_fields=fields,
                )
            )
        else:
            judgments.append(
                Judgment(
                    classification=label,
                    probability=probability,
                    evidence_fields=fields,
                    status="supported"
                    if probability >= SUPPORTED_THRESHOLD
                    else "unsupported"
                    if probability <= 0.2
                    else "uncertain",
                )
            )

    supported = {j.classification for j in judgments if j.status == "supported"}
    attacks = [
        label
        for label in LABELS
        if label in supported and label not in NON_ATTACK_FINDINGS
    ]
    choice = model_choice.choice
    review_reasons: list[ReviewReason] = []
    if choice == "needs_review":
        review_reasons.append("model_needs_review")
    if model_choice.probability < SUPPORTED_THRESHOLD:
        review_reasons.append("low_choice_probability")
    if choice in {"likely_legitimate", "unsolicited_bulk_email"}:
        if attacks:
            review_reasons.append("conflicting_attack_findings")
        if incomplete:
            review_reasons.append("incomplete_evidence_for_benign_choice")
    if choice == "likely_phishing" and benign_explanation >= SUPPORTED_THRESHOLD:
        review_reasons.append("supported_benign_explanation")
    final_verdict: EmailVerdict = "needs_review" if review_reasons else choice
    return Verdict(
        final_verdict=final_verdict,
        model_choice=model_choice,
        phishing_evidence_score=phishing_evidence_score,
        benign_explanation=benign_explanation,
        review_reasons=review_reasons,
        attacks=attacks,
        outcome="needs_review" if final_verdict == "needs_review" else "classified",
        judgments=judgments,
    )
