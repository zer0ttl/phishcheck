"""Run the shared EML fixture corpus through Phishcheck's public service."""

import hashlib
import json
import os
from pathlib import Path

import pytest

from phishcheck.config import ApplicationSettings, Settings
from phishcheck.history import read_run
from phishcheck.service import run_file
from phishcheck.signatures import LABELS
from phishcheck.tracing import TracingSettings

PROJECT_ROOT = Path(__file__).resolve().parents[1]
LIVE = os.environ.get("PHISHCHECK_LIVE_TESTS") == "1"
fixture_dir = os.environ.get("PHISHCHECK_EML_FIXTURES")
FIXTURES = (
    sorted(Path(fixture_dir).expanduser().resolve().glob("*.eml"))
    if fixture_dir
    else []
)

if not FIXTURES and (fixture_dir or LIVE):
    raise pytest.UsageError(
        "Set PHISHCHECK_EML_FIXTURES to a directory containing .eml files"
    )


@pytest.fixture
def application(tmp_path: Path) -> ApplicationSettings:
    return ApplicationSettings(database_path=tmp_path / "corpus.sqlite")


@pytest.fixture(scope="module")
def provider() -> Settings:
    return Settings(_env_file=PROJECT_ROOT / ".env")  # type: ignore[call-arg]


@pytest.mark.parametrize("eml", FIXTURES, ids=lambda path: path.name)
def test_parse_corpus(eml: Path, application: ApplicationSettings) -> None:
    result = run_file("parse", eml, application)
    assert result.status == "success", result.diagnostic
    assert result.persistence_error is None
    assert result.parsed is not None
    report = result.parsed
    assert report.filename == eml.name
    assert report.sha256 == hashlib.sha256(eml.read_bytes()).hexdigest()
    assert report.body_status == "complete"
    assert report.body
    assert all(set(link) == {"text", "url"} for link in report.urls)
    if eml.name == "with_urls_html.eml":
        assert len(report.urls) == 6
        assert {
            "text": "Click HERE now",
            "url": "https://styled.example.com/promo",
        } in report.urls
    if eml.name == "multipart_text_and_html.eml":
        assert [part.content_type for part in report.body_parts] == [
            "text/plain",
            "text/html",
        ]


@pytest.mark.skipif(not LIVE, reason="Set PHISHCHECK_LIVE_TESTS=1 to call the provider")
@pytest.mark.parametrize("eml", FIXTURES, ids=lambda path: path.name)
def test_live_triage_corpus(
    eml: Path, application: ApplicationSettings, provider: Settings
) -> None:
    result = run_file(
        "triage",
        eml,
        application,
        provider_settings=provider,
        tracing_settings=TracingSettings(enabled=False),
    )
    assert result.persistence_error is None
    assert result.run_id is not None
    saved = read_run(application.database_path, result.run_id)
    assert saved is not None and saved.snapshot is not None
    triage = saved.snapshot["triage"] or {}
    status = triage.get("response_status")
    assert result.status == "success", (
        f"{eml.name}: {result.diagnostic} (provider HTTP {status})"
    )
    assert result.parsed is not None
    assert result.verdict is not None
    assert isinstance(status, int) and 200 <= status < 300
    assert triage["request_payload"]
    answers = json.loads(triage["response_body"])["answers"]
    assert len(answers) == 29
    assert answers["email_verdict"]["type"] == "choice"
    assert answers["phishing_evidence_score"]["type"] == "score"
    assert answers["benign_explanation"]["type"] == "noul"
    assert saved.snapshot["version"] == 3
    verdict = result.verdict
    assert [judgment.classification for judgment in verdict.judgments] == list(LABELS)
    assert "disposition" not in triage["verdict"]
    assert triage["verdict"] == verdict.model_dump(mode="json")
    print(
        f"LIVE\t{eml.name}\t{verdict.final_verdict}\t"
        f"{verdict.phishing_evidence_score.score:.2f}\t"
        f"{verdict.model_choice.choice} ({verdict.model_choice.probability:.1%})\t"
        f"{verdict.benign_explanation:.1%}\t"
        f"{','.join(verdict.review_reasons) or '-'}\t{','.join(verdict.attacks) or '-'}"
    )
