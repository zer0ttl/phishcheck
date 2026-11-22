"""Command-line and installed entry-point behavior."""

import errno
import importlib.metadata
import json
import socket
from pathlib import Path

import pytest

from phishcheck import cli

FIXTURE = Path(__file__).parent / "fixtures" / "plain.eml"


def test_public_entry_points() -> None:
    distribution = importlib.metadata.distribution("phishcheck")
    assert any(
        point.name == "phishcheck" and point.value == "phishcheck.cli:main"
        for point in distribution.entry_points
    )


def test_help_needs_no_database(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    database = tmp_path / "history.sqlite"
    monkeypatch.setenv("PHISHCHECK_DATABASE_PATH", str(database))
    with pytest.raises(SystemExit) as error:
        cli.main(["--help"])
    assert error.value.code == 0
    assert not database.exists()


def test_parse_output(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("PHISHCHECK_DATABASE_PATH", str(tmp_path / "history.sqlite"))
    assert cli.main(["parse", str(FIXTURE)]) == 0
    text = capsys.readouterr().out
    assert "Body:" in text
    assert "https://example.com/info -> https://example.com/info" in text
    assert cli.main(["parse", str(FIXTURE), "--json"]) == 0
    output = capsys.readouterr()
    assert not output.err
    report = json.loads(output.out)
    assert report["filename"] == FIXTURE.name
    assert report["urls"] == [
        {"text": "https://example.com/info", "url": "https://example.com/info"}
    ]


def test_invalid_json_diagnostic(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("PHISHCHECK_DATABASE_PATH", str(tmp_path / "history.sqlite"))
    invalid = tmp_path / "invalid.eml"
    invalid.write_bytes(b"not an email")
    assert cli.main(["parse", str(invalid), "--json"]) == 2
    output = capsys.readouterr()
    assert not output.out
    diagnostic = json.loads(output.err)
    assert "Magika:" in diagnostic["error"]
    assert diagnostic["detection"]["label"]


def test_serve_occupied_port(monkeypatch: pytest.MonkeyPatch) -> None:
    with socket.socket() as occupied:
        occupied.bind(("127.0.0.1", 0))
        occupied.listen()
        port = occupied.getsockname()[1]
        monkeypatch.setattr(cli, "DEFAULT_PORT", port)
        with cli.bind_socket("127.0.0.1") as selected:
            assert selected.getsockname()[1] > port
        with pytest.raises(OSError) as error:
            cli.bind_socket("127.0.0.1", port)
        assert error.value.errno == errno.EADDRINUSE


def test_serve_bind_error_does_not_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from unittest.mock import MagicMock

    unavailable = MagicMock()
    unavailable.bind.side_effect = PermissionError(errno.EACCES, "permission denied")
    factory = MagicMock(return_value=unavailable)
    monkeypatch.setattr("phishcheck.cli.socket.socket", factory)
    with pytest.raises(PermissionError):
        cli.bind_socket("127.0.0.1")
    factory.assert_called_once()
    unavailable.close.assert_called_once()


def test_serve_prints_selected_address(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    from unittest.mock import MagicMock

    monkeypatch.setenv("PHISHCHECK_DATABASE_PATH", str(tmp_path / "history.sqlite"))
    server = MagicMock()
    server.started = True
    monkeypatch.setattr("uvicorn.Server", lambda config: server)
    with socket.socket() as available:
        available.bind(("127.0.0.1", 0))
        port = available.getsockname()[1]
    assert cli.main(["serve", "-p", str(port)]) == 0
    assert f"http://127.0.0.1:{port}" in capsys.readouterr().out
    server.run.assert_called_once()


def test_triage_headline_and_json(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from phishcheck.config import Settings
    from phishcheck.modules import Assessment, AssessmentStage
    from phishcheck.triage import (
        DecisionEvidence,
        ModelChoice,
        PhishingEvidenceScore,
        classify,
    )

    def assess(evidence: DecisionEvidence, settings: Settings | None) -> Assessment:
        return Assessment(
            verdict=classify(
                evidence,
                {"spoofing": 0.9},
                model_choice=ModelChoice(
                    choice="likely_phishing",
                    probabilities={"likely_phishing": 0.9},
                    confidence=0.8,
                ),
                phishing_evidence_score=PhishingEvidenceScore(
                    score=3.0,
                    probabilities={3: 1.0},
                    confidence=0.9,
                ),
                benign_explanation=0.1,
            ),
            stage=AssessmentStage(evidence=evidence),
        )

    monkeypatch.setenv("PHISHCHECK_DATABASE_PATH", str(tmp_path / "history.sqlite"))
    monkeypatch.setattr("phishcheck.modules.assess", assess)
    assert cli.main(["triage", str(FIXTURE)]) == 0
    output = capsys.readouterr().out.splitlines()
    assert output[:3] == [
        "Verdict: Likely phishing",
        "Phishing evidence strength: 3.0 out of 4",
        "Supported findings: spoofing",
    ]
    assert cli.main(["triage", str(FIXTURE), "--json"]) == 0
    triage = json.loads(capsys.readouterr().out)["triage"]
    assert triage["final_verdict"] == "likely_phishing"
    assert "disposition" not in triage
