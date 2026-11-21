"""Deterministic email verdicts and the model evidence budget."""

import json
from collections.abc import Mapping

import pytest

from phishcheck.models import Attachment, EmailLink, ParseReport
from phishcheck.triage import (
    AttachmentEvidence,
    DecisionEvidence,
    EmailVerdict,
    ModelChoice,
    PhishingEvidenceScore,
    Verdict,
    classify,
    project_evidence,
)


def decide(
    evidence: DecisionEvidence,
    findings: Mapping[str, float | None],
    choice: EmailVerdict = "needs_review",
    probability: float = 0.9,
    explanation: float = 0.1,
) -> Verdict:
    return classify(
        evidence,
        findings,
        model_choice=ModelChoice(
            choice=choice, probabilities={choice: probability}, confidence=0.7
        ),
        phishing_evidence_score=PhishingEvidenceScore(
            score=3.1, probabilities={3: 0.9, 4: 0.1}, confidence=0.5
        ),
        benign_explanation=explanation,
    )


def test_thresholds_and_unavailable_corroboration() -> None:
    verdict = decide(
        DecisionEvidence(),
        {
            "financial_fraud": 0.8,
            "spoofing": 0.2,
            "targeted": 0.5,
            "compromised_sender": 1,
        },
    )
    by_name = {entry.classification: entry for entry in verdict.judgments}
    assert len(by_name) == 26
    assert verdict.attacks == ["financial_fraud"]
    assert by_name["spoofing"].status == "unsupported"
    assert by_name["targeted"].status == "uncertain"
    assert by_name["compromised_sender"].status == "insufficient_evidence"
    assert by_name["compromised_sender"].probability is None
    assert by_name["compromised_sender"].missing_field == "account_evidence"


def test_trusted_simulation_can_coexist_with_attacks() -> None:
    verdict = decide(
        DecisionEvidence(authorized_simulation=True),
        {"spoofing": 0.9, "financial_fraud": 0.9, "phishing_simulation": 1},
    )
    assert verdict.attacks == ["spoofing", "financial_fraud"]
    assert verdict.judgments[-1].classification == "phishing_simulation"
    assert verdict.judgments[-1].status == "supported"


@pytest.mark.parametrize(
    "body_status,expected",
    [
        ("absent", "unsolicited_bulk_email"),
        ("unavailable", "needs_review"),
        ("truncated", "needs_review"),
    ],
)
def test_material_extraction_gates_benign_verdicts(
    body_status: str, expected: str
) -> None:
    evidence = DecisionEvidence.model_validate({"body_status": body_status})
    verdict = decide(
        evidence,
        {"legitimate_email": 0.95, "unsolicited_email": 0.9},
        "unsolicited_bulk_email",
    )
    assert verdict.final_verdict == expected
    assert verdict.outcome == (
        "needs_review" if expected == "needs_review" else "classified"
    )


def test_projection_bounds_utf8_and_redacts_unselected_fields() -> None:
    evidence = project_evidence(
        ParseReport(
            filename="secret.eml",
            sha256="digest",
            headers={"sUbJeCt": "Invoice", "X-Secret": "private"},
            body='🚀"\\\n' * 8000,
            body_status="complete",
            urls=[{"text": "Invoice", "url": "https://example.test/invoice"}],
            attachments=[
                Attachment(name="invoice.txt", status="complete", text="test")
            ],
        )
    )
    state = evidence.model_dump(mode="json")
    assert len(json.dumps({"inputs": {"evidence": state}}).encode()) <= 16 * 1024
    assert state["headers"] == {"Subject": "Invoice"}
    assert evidence.body and len(evidence.body) < 8000
    assert "body" in evidence.omissions
    assert "filename" not in state


def test_absent_and_unavailable_attachments_are_distinguishable() -> None:
    probabilities = {"legitimate_email": 0.9, "malicious_attachment": 0.9}
    absent = decide(DecisionEvidence(), probabilities, "likely_legitimate")
    unavailable = decide(
        DecisionEvidence(attachments=[AttachmentEvidence(status="unavailable")]),
        probabilities,
        "likely_legitimate",
    )
    assert absent.final_verdict == "likely_legitimate"
    assert unavailable.outcome == "needs_review"
    absent_judgment = next(
        j for j in absent.judgments if j.classification == "malicious_attachment"
    )
    unavailable_judgment = next(
        j for j in unavailable.judgments if j.classification == "malicious_attachment"
    )
    assert absent_judgment.missing_field == "attachments"
    assert unavailable_judgment.missing_field == "attachments.text"


@pytest.mark.parametrize("probability", [float("nan"), float("inf"), -0.01, 1.01, True])
def test_invalid_probability_is_rejected(probability: float) -> None:
    with pytest.raises(ValueError):
        decide(DecisionEvidence(), {"financial_fraud": probability})


def test_judgments_reference_available_source_fields() -> None:
    evidence = DecisionEvidence(
        headers={"From": "sender@example.test", "Authentication-Results": "dkim=fail"},
        urls=[{"text": "Invoice", "url": "https://example.test/invoice"}],
        attachments=[
            AttachmentEvidence(status="complete", text="invoice", detected_type="txt")
        ],
    )
    verdict = decide(
        evidence, {"spoofing": 0.95, "malicious_attachment": 0.9, "malicious_url": 0.85}
    )
    judgments = {entry.classification: entry for entry in verdict.judgments}
    assert judgments["spoofing"].evidence_fields == [
        "headers.From",
        "headers.Authentication-Results",
    ]
    assert judgments["malicious_url"].evidence_fields == ["urls"]
    assert judgments["malicious_attachment"].evidence_fields == [
        "attachments.text",
        "attachments.detected_type",
    ]


def test_link_projection_keeps_pairs_and_marks_shortened_or_omitted_links() -> None:
    report = ParseReport(
        filename="test.eml",
        sha256="hash",
        headers={},
        body=None,
        body_status="absent",
        urls=[
            {"text": "too long", "url": "https://example.test/" + "a" * 2048},
            {"text": "a" * 513, "url": "https://example.test/retained"},
            *[
                EmailLink(text="another link", url="https://example.test/" + "b" * 1900)
                for _ in range(12)
            ],
        ],
        attachments=[],
    )
    evidence = project_evidence(report)
    assert evidence.urls[0] == {
        "text": "a" * 512,
        "url": "https://example.test/retained",
    }
    assert len(evidence.urls) < len(report.urls) - 1
    assert all(set(link) == {"text", "url"} for link in evidence.urls)
    assert "urls" in evidence.omissions


def test_headline_is_explicit() -> None:
    verdict = decide(
        DecisionEvidence(), {"financial_fraud": 0.91}, "likely_phishing", 0.8
    )
    assert verdict.final_verdict == "likely_phishing"
    assert verdict.review_reasons == []
    assert "disposition" not in verdict.model_dump()


def test_all_applicable_review_reasons_are_collected() -> None:
    verdict = decide(
        DecisionEvidence(omissions=["headers"]),
        {"financial_fraud": 0.9},
        "likely_legitimate",
        0.79,
    )
    assert verdict.final_verdict == verdict.outcome == "needs_review"
    assert verdict.review_reasons == [
        "low_choice_probability",
        "conflicting_attack_findings",
        "incomplete_evidence_for_benign_choice",
    ]
    assert "Jev selected Likely legitimate (79%)." in verdict.summary_lines()


def test_supported_benign_explanation_holds_back_phishing_verdict() -> None:
    verdict = decide(
        DecisionEvidence(), {"spoofing": 0.9}, "likely_phishing", 0.92, 0.8
    )
    assert verdict.final_verdict == "needs_review"
    assert verdict.review_reasons == ["supported_benign_explanation"]
    assert verdict.attacks == ["spoofing"]


def test_model_can_choose_needs_review() -> None:
    verdict = decide(DecisionEvidence(), {})
    assert verdict.final_verdict == "needs_review"
    assert verdict.review_reasons == ["model_needs_review"]
