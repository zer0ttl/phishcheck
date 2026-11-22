"""Exercise upload actions through the FastAPI entry point."""

import json
from pathlib import Path

import pytest
from bs4 import BeautifulSoup
from fastapi.testclient import TestClient

from phishcheck.web import create_app

MAIL = (
    b"From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
    b"<script>synthetic</script> https://example.com/evidence\r\n"
)


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> TestClient:
    monkeypatch.setenv("PHISHCHECK_DATABASE_PATH", str(tmp_path / "history.sqlite"))
    monkeypatch.setenv("DSPY_API_BASE", "http://127.0.0.1:1")
    monkeypatch.setenv("DSPY_API_KEY", "synthetic-key")
    return TestClient(create_app())


def test_parse_upload(client: TestClient) -> None:
    assert 'enctype="multipart/form-data"' in client.get("/").text
    response = client.post(
        "/", files={"file": ("fixture.eml", MAIL)}, data={"action": "parse"}
    )
    assert response.status_code == 200
    assert "&lt;script&gt;" in response.text
    assert "<script>" not in response.text
    assert "https://example.com/evidence" in response.text
    assert 'href="https://example.com/evidence"' not in response.text


def test_html_link_pair_is_rendered_as_inert_text(client: TestClient) -> None:
    mail = (
        b"From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Links\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n\r\n"
        b'<a href="https://example.com/destination">Read the &lt;report&gt;</a>\r\n'
    )
    response = client.post(
        "/", files={"file": ("links.eml", mail)}, data={"action": "parse"}
    )
    assert response.status_code == 200
    rendered = BeautifulSoup(response.text, "html.parser")
    assert rendered.find("a") is None
    report = rendered.find("pre")
    assert report is not None
    assert json.loads(report.get_text())["urls"] == [
        {"text": "Read the <report>", "url": "https://example.com/destination"}
    ]


def test_invalid_upload(client: TestClient) -> None:
    assert client.post("/", data={"action": "parse"}).status_code == 400
    response = client.post(
        "/", files={"file": ("fixture.eml", b"invalid")}, data={"action": "parse"}
    )
    assert response.status_code == 400


def test_oversized_request(monkeypatch: pytest.MonkeyPatch, client: TestClient) -> None:
    monkeypatch.setattr("phishcheck.web.MAX_FORM_OVERHEAD", 1024)
    monkeypatch.setenv("PHISHCHECK_MAX_INPUT_BYTES", "1024")
    client = TestClient(create_app())
    response = client.post(
        "/", files={"file": ("fixture.eml", MAIL * 50)}, data={"action": "parse"}
    )
    assert response.status_code == 413


def test_triage_upload(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    from phishcheck.config import Settings
    from phishcheck.modules import Assessment, AssessmentStage
    from phishcheck.triage import (
        DecisionEvidence,
        ModelChoice,
        PhishingEvidenceScore,
        classify,
    )

    def assess(evidence: DecisionEvidence, settings: Settings | None) -> Assessment:
        assert "synthetic" in (evidence.body or "")
        return Assessment(
            verdict=classify(
                evidence,
                {"malicious_url": 0.95},
                model_choice=ModelChoice(
                    choice="likely_legitimate",
                    probabilities={"likely_legitimate": 0.9},
                    confidence=0.8,
                ),
                phishing_evidence_score=PhishingEvidenceScore(
                    score=3.0, probabilities={3: 1.0}, confidence=0.9
                ),
                benign_explanation=0.1,
            ),
            stage=AssessmentStage(evidence=evidence),
        )

    monkeypatch.setattr("phishcheck.modules.assess", assess)
    response = client.post(
        "/", files={"file": ("fixture.eml", MAIL)}, data={"action": "triage"}
    )
    assert response.status_code == 200
    assert "<h2>Needs review</h2>" in response.text
    assert "Phishing evidence strength: 3.0 out of 4" in response.text
    assert "Jev selected Likely legitimate (90%)." in response.text
    assert "Supported attack findings conflict" in response.text
    assert "malicious_url" in response.text
    assert "Parsed email" in response.text


def test_triage_failed_provider_preserves_report(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    from phishcheck.config import Settings
    from phishcheck.modules import AssessmentError, AssessmentStage
    from phishcheck.triage import DecisionEvidence

    def assess(evidence: DecisionEvidence, settings: Settings | None) -> None:
        raise AssessmentError(
            "Provider unavailable", AssessmentStage(evidence=evidence)
        )

    monkeypatch.setattr("phishcheck.modules.assess", assess)
    response = client.post(
        "/", files={"file": ("fixture.eml", MAIL)}, data={"action": "triage"}
    )
    assert response.status_code == 500
    assert "Provider unavailable" in response.text
    assert "Parsed email" in response.text
    assert "&lt;script&gt;" in response.text
