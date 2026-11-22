"""Completed runs can be reopened without parsing or another provider call."""

import hashlib
import json
import sqlite3
from contextlib import closing
from io import BytesIO
from pathlib import Path
from typing import Never

import pytest

from phishcheck.history import read_original, read_run, record_run
from phishcheck.models import ParseReport


def test_run_round_trips_evidence_and_original_upload(tmp_path: Path) -> None:
    database = tmp_path / "state" / "runs.sqlite3"
    original = b"From: person@example.test\r\nSubject: Original\r\n\r\nBytes\r\n"
    parsed = ParseReport(
        filename="original.eml",
        sha256="fixture-hash",
        headers={"From": "person@example.test"},
        body="Bytes",
        body_status="complete",
        urls=[{"text": "Read more", "url": "https://example.test"}],
        attachments=[],
    )
    first = record_run(
        database,
        "parse",
        "success",
        parsed=parsed,
        sha256=parsed.sha256,
        filename=parsed.filename,
        original=original,
    )
    second = record_run(database, "parse", "success", sha256=parsed.sha256)

    assert first != second
    saved = read_run(database, first)
    assert saved is not None
    assert saved.action == "parse"
    assert saved.sha256 == parsed.sha256
    assert saved.status == "success"
    assert saved.snapshot == {
        "version": 3,
        "parsed": parsed.model_dump(mode="json"),
        "triage": None,
        "diagnostics": [],
    }
    assert read_original(database, first) == ("original.eml", original)
    assert read_original(database, second) is None


def test_invalid_email_keeps_original_but_oversized_and_interrupted_reads_do_not(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from phishcheck.service import parse

    database = tmp_path / "runs.sqlite3"
    monkeypatch.setenv("PHISHCHECK_DATABASE_PATH", str(database))
    invalid = b"ordinary text"
    failed = parse(BytesIO(invalid), "invalid.eml")
    assert failed.status == "invalid_input"
    assert failed.run_id is not None
    assert read_original(database, failed.run_id) == ("invalid.eml", invalid)
    saved = read_run(database, failed.run_id)
    assert saved is not None
    assert saved.snapshot is not None
    assert saved.snapshot["diagnostics"]

    monkeypatch.setenv("PHISHCHECK_MAX_INPUT_BYTES", "32")
    oversized = parse(BytesIO(b"x" * 33), "oversized.eml")
    assert oversized.status == "oversized"
    assert oversized.run_id is not None
    assert read_original(database, oversized.run_id) is None

    class InterruptedRead(BytesIO):
        def read(self, size: int | None = -1) -> bytes:
            super().read(5)
            raise OSError("stream interrupted")

    interrupted = parse(InterruptedRead(invalid), "interrupted.eml")
    assert interrupted.status == "error"
    assert interrupted.run_id is not None
    assert read_original(database, interrupted.run_id) is None


def test_metadata_only_history_remains_readable_after_new_run(tmp_path: Path) -> None:
    database = tmp_path / "old.sqlite3"
    with closing(sqlite3.connect(database)) as connection, connection:
        connection.execute(
            "CREATE TABLE triage_attempts (id INTEGER PRIMARY KEY, "
            "created_at TEXT NOT NULL, sha256 TEXT, status TEXT NOT NULL, classifications TEXT)"
        )
        connection.execute(
            "INSERT INTO triage_attempts VALUES(1, '2026-05-01T00:00:00+00:00', "
            "'legacy-hash', 'ok', 'legitimate_email')"
        )

    saved = read_run(database, 1)
    assert saved is not None
    assert saved.action == "triage"
    assert saved.classifications == ("legitimate_email",)
    assert saved.snapshot is None
    assert not saved.original_available
    assert read_original(database, 1) is None

    assert record_run(database, "parse", "success") == 2
    saved = read_run(database, 1)
    assert saved is not None
    assert saved.sha256 == "legacy-hash"
    assert saved.snapshot is None


def test_history_write_error_keeps_the_parse_report(tmp_path: Path) -> None:
    from phishcheck.config import ApplicationSettings
    from phishcheck.service import parse

    original = Path(__file__).with_name("fixtures").joinpath("plain.eml").read_bytes()
    result = parse(
        BytesIO(original),
        "plain.eml",
        ApplicationSettings(database_path=tmp_path),
    )

    assert result.status == "success"
    assert result.parsed is not None
    assert result.run_id is None
    assert result.persistence_error is not None
    assert "PHISHCHECK_DATABASE_PATH" in result.persistence_error


def test_outlook_conversion_error_keeps_unconverted_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from phishcheck.config import ApplicationSettings
    from phishcheck.service import parse

    original = bytes.fromhex("d0cf11e0a1b11ae1") + bytes(512)
    database = tmp_path / "runs.sqlite3"
    monkeypatch.setenv("PATH", str(tmp_path))
    failed = parse(
        BytesIO(original),
        "message.msg",
        ApplicationSettings(database_path=database),
    )

    assert failed.status == "error"
    assert failed.run_id is not None
    assert "msgconvert" in (failed.diagnostic or "")
    assert read_original(database, failed.run_id) == ("message.msg", original)
    saved = read_run(database, failed.run_id)
    assert saved is not None
    assert saved.snapshot is not None
    assert saved.snapshot["detection"]["status"]
    assert saved.sha256 == hashlib.sha256(original).hexdigest()


def test_triage_provider_failure_keeps_parse_and_provider_evidence(
    tmp_path: Path,
) -> None:
    from phishcheck.config import ApplicationSettings, Settings
    from phishcheck.modules import AssessmentError, AssessmentStage
    from phishcheck.service import triage
    from phishcheck.triage import DecisionEvidence

    database = tmp_path / "runs.sqlite3"
    original = Path(__file__).with_name("fixtures").joinpath("plain.eml").read_bytes()

    def fail(evidence: DecisionEvidence, settings: Settings | None) -> Never:
        raise AssessmentError(
            "Provider returned an invalid response",
            AssessmentStage(
                evidence=evidence,
                request_payload={"synthetic": "request"},
                response_body='{"unexpected": true}',
                response_status=200,
            ),
        )

    failed = triage(
        BytesIO(original),
        "plain.eml",
        ApplicationSettings(database_path=database),
        assessor=fail,
    )

    assert failed.status == "error"
    assert failed.parsed is not None
    assert failed.run_id == 1
    assert read_original(database, 1) == ("plain.eml", original)
    saved = read_run(database, 1)
    assert saved is not None
    assert saved.action == "triage"
    assert saved.snapshot is not None
    assert saved.snapshot["parsed"] == failed.parsed.model_dump(mode="json")
    assert saved.snapshot["triage"]["request_payload"] == {"synthetic": "request"}
    assert saved.snapshot["triage"]["response_body"] == '{"unexpected": true}'
    assert not saved.classifications
    assert read_run(database, 2) is None


@pytest.mark.parametrize(
    "label,is_attack",
    [("malicious_url", True), ("legitimate_email", False)],
)
def test_triage_round_trips_full_multipart_evidence_and_verdict(
    tmp_path: Path, label: str, is_attack: bool
) -> None:
    from email.message import EmailMessage

    from phishcheck.config import ApplicationSettings, Settings
    from phishcheck.extraction import TikaClient
    from phishcheck.models import ExtractedContent
    from phishcheck.modules import Assessment, AssessmentStage
    from phishcheck.service import parse, triage
    from phishcheck.triage import (
        DecisionEvidence,
        EmailVerdict,
        ModelChoice,
        PhishingEvidenceScore,
        classify,
    )

    message = EmailMessage()
    message["From"] = "person@example.test"
    message["To"] = "recipient@example.test"
    message["Date"] = "Thu, 20 Nov 2025 12:00:00 +0000"
    message["Message-ID"] = "<history@example.test>"
    message["Subject"] = "Multipart example"
    message["X-Example"] = "first value"
    message["X-Example"] = "second value"
    message.set_content("Plain body with https://example.test/path")
    message.add_alternative(
        '<p>Complete HTML body</p><a href="https://example.test/path">View it</a>',
        subtype="html",
    )
    message.add_attachment(
        b"input", maintype="application", subtype="octet-stream", filename="report.bin"
    )
    message.set_boundary("phishcheck-history-mixed")
    next(message.iter_parts()).set_boundary("phishcheck-history-alternative")
    original = message.as_bytes()

    class Extractor(TikaClient):
        def extract(
            self, data: bytes, *, deadline: float | None = None
        ) -> ExtractedContent:
            return ExtractedContent(
                status="complete",
                text="full attachment text",
                metadata={"X-Resource": "report.bin"},
            )

    expected: EmailVerdict = "likely_phishing" if is_attack else "likely_legitimate"

    def assess_fixture(
        evidence: DecisionEvidence, settings: Settings | None
    ) -> Assessment:
        return Assessment(
            verdict=classify(
                evidence,
                {label: 0.83, "impersonation": 0.04},
                model_choice=ModelChoice(
                    choice=expected, probabilities={expected: 0.9}, confidence=0.8
                ),
                phishing_evidence_score=PhishingEvidenceScore(
                    score=2.5, probabilities={2: 0.5, 3: 0.5}, confidence=0.5
                ),
                benign_explanation=0.1,
            ),
            stage=AssessmentStage(evidence=evidence, response_body='{"fixture": true}'),
        )

    database = tmp_path / "runs.sqlite3"
    settings = ApplicationSettings(database_path=database)
    parsed = parse(BytesIO(original), "multipart.eml", settings)
    assert parsed.run_id == 1
    assert parsed.status == "success", parsed.diagnostic
    first = read_run(database, 1)
    assert first is not None
    assert first.snapshot is not None
    assert first.snapshot["parsed"]["attachments"][0]["status"] == "unavailable"

    result = triage(
        BytesIO(original),
        "multipart.eml",
        settings,
        Extractor(None),
        assessor=assess_fixture,
    )

    assert result.status == "success"
    assert result.run_id == 2
    saved = read_run(database, 2)
    assert saved is not None
    assert saved.sha256 == first.sha256
    assert saved.snapshot is not None
    parsed_evidence = saved.snapshot["parsed"]
    assert parsed_evidence["urls"] == [
        {"text": "View it", "url": "https://example.test/path"}
    ]
    assert saved.snapshot["triage"]["evidence"]["urls"] == parsed_evidence["urls"]
    assert [part["content_type"] for part in parsed_evidence["body_parts"]] == [
        "text/plain",
        "text/html",
    ]
    assert "Complete HTML body" in parsed_evidence["body_parts"][1]["content"]
    assert [
        header["value"]
        for header in parsed_evidence["headers_all"]
        if header["name"] == "X-Example"
    ] == ["first value", "second value"]
    attachment = parsed_evidence["attachments"][0]
    assert attachment["text"] == "full attachment text"
    assert attachment["extraction"]["metadata"] == {"X-Resource": "report.bin"}

    assert saved.classifications == ((label, expected) if is_attack else (expected,))
    verdict = saved.snapshot["triage"]["verdict"]
    if is_attack:
        assert verdict["attacks"] == [label]
    assert verdict["final_verdict"] == expected
    assert "disposition" not in verdict
    assert verdict["phishing_evidence_score"]["score"] == 2.5
    excluded_from_display = next(
        item
        for item in verdict["judgments"]
        if item["classification"] == "impersonation"
    )
    assert excluded_from_display == {
        "classification": "impersonation",
        "probability": 0.04,
        "status": "unsupported",
        "missing_field": None,
        "evidence_fields": ["headers.From", "headers.Subject", "body", "urls"],
    }
    assert read_original(database, 2) == ("multipart.eml", original)
    assert read_run(database, 3) is None


def test_outlook_success_preserves_bytes_before_conversion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from phishcheck.config import ApplicationSettings
    from phishcheck.service import parse

    converter = tmp_path / "msgconvert"
    converter.write_text(
        "#!/bin/sh\n"
        "cat > \"$2\" <<'EOF'\n"
        "From: person@example.test\n"
        "To: recipient@example.test\n"
        "Subject: Converted message\n"
        "\n"
        "Converted body.\n"
        "EOF\n"
    )
    converter.chmod(0o700)
    monkeypatch.setenv("PATH", f"{tmp_path}:/usr/bin:/bin")
    original = bytes.fromhex("d0cf11e0a1b11ae1") + bytes(range(256))
    database = tmp_path / "runs.sqlite3"

    result = parse(
        BytesIO(original),
        "message.msg",
        ApplicationSettings(database_path=database),
    )

    assert result.status == "success", result.diagnostic
    assert result.parsed is not None
    assert result.parsed.body == "Converted body."
    assert result.run_id is not None
    assert read_original(database, result.run_id) == ("message.msg", original)


@pytest.mark.parametrize("version", [1, 2])
def test_old_versions_preserve_original_links_and_provider_payload(
    tmp_path: Path,
    version: int,
) -> None:
    database = tmp_path / "history.sqlite"
    run_id = record_run(database, "triage", "success")
    links: list[object] = (
        ["https://example.test"]
        if version == 1
        else [{"text": "Example", "url": "https://example.test"}]
    )
    snapshot = {
        "version": version,
        "parsed": {"urls": links},
        "triage": {
            "verdict": {"disposition": "legitimate_email"},
            "request_payload": {"state": {"inputs": {"evidence": {"urls": links}}}},
        },
        "diagnostics": [],
    }
    with closing(sqlite3.connect(database)) as connection, connection:
        connection.execute(
            "UPDATE triage_attempts SET snapshot = ? WHERE id = ?",
            (json.dumps(snapshot), run_id),
        )
    saved = read_run(database, run_id)
    assert saved is not None
    assert saved.snapshot == snapshot
