"""CLI success, failure and override contract."""

import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import dspy
import pytest

from emailscan import cli


def test_cli_json_and_overrides(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Pass effective settings and write only the public result fields."""
    monkeypatch.setenv("DSPY_API_BASE", "https://provider.example")
    monkeypatch.setenv("DSPY_API_KEY", "environment-key")
    configure, tracing, assessor = MagicMock(), MagicMock(), MagicMock()
    assessor.return_value.return_value = dspy.Prediction(
        investigate=SimpleNamespace(value=False, probability=0.1),
        risk=SimpleNamespace(value=0.0, level=0),
        category=SimpleNamespace(value="benign"),
        private_metadata="omit",
    )
    monkeypatch.setattr(cli, "configure", configure)
    monkeypatch.setattr(cli, "configure_tracing", tracing)
    monkeypatch.setattr(cli, "EventAssessor", assessor)
    assert (
        cli.main(
            [
                "--text",
                "Scheduled login",
                "--model",
                "typesafe:override",
                "--api-key",
                "cli-key",
                "--tracking-uri",
                "http://tracking",
                "--experiment-name",
                "test",
                "--no-tracing",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out) == {
        "investigate": {"value": False, "probability": 0.1},
        "risk": {"value": 0.0, "level": 0},
        "category": {"value": "benign"},
    }
    settings = configure.call_args.args[0]
    assert settings.model == "typesafe:override"
    assert settings.api_base == "https://provider.example"
    assert settings.api_key == "cli-key"
    assert tracing.call_args.args[0].enabled is False
    assert tracing.call_args.args[0].tracking_uri == "http://tracking"
    assert tracing.call_args.args[0].experiment_name == "test"
    assessor.return_value.assert_called_once_with(event="Scheduled login")


def test_cli_provider_error(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Report an inference failure without emitting result JSON."""
    monkeypatch.setattr(cli, "configure", MagicMock())
    monkeypatch.setattr(cli, "configure_tracing", MagicMock())
    assessor = MagicMock()
    assessor.return_value.side_effect = RuntimeError("provider offline")
    monkeypatch.setattr(cli, "EventAssessor", assessor)
    assert cli.main(["--text", "Scheduled login"]) == 1
    assert capsys.readouterr().out == ""
    assert "Project execution failed" in caplog.text


@pytest.mark.parametrize("argv", [[], ["--text", ""], ["--text", " \n"]])
def test_cli_requires_text(argv: list[str], monkeypatch: pytest.MonkeyPatch) -> None:
    """Reject missing or blank input before configuring the provider."""
    configure = MagicMock()
    monkeypatch.setattr(cli, "configure", configure)
    with pytest.raises(SystemExit) as error:
        cli.main(argv)
    assert error.value.code == 2
    configure.assert_not_called()


def test_help_needs_no_configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    """Render help without configuring a provider."""
    configure = MagicMock()
    monkeypatch.setattr(cli, "configure", configure)
    with pytest.raises(SystemExit) as error:
        cli.main(["--help"])
    assert error.value.code == 0
    configure.assert_not_called()


@pytest.mark.parametrize(
    "invalid_judgment",
    [
        {"investigate": SimpleNamespace(value=True, probability=1.5)},
        {"risk": SimpleNamespace(value=1.0, level=5)},
        {"category": SimpleNamespace(value="unknown")},
    ],
)
def test_cli_rejects_invalid_prediction(
    invalid_judgment: dict[str, SimpleNamespace],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Validate each judgment before emitting JSON."""
    monkeypatch.setattr(cli, "configure", MagicMock())
    monkeypatch.setattr(cli, "configure_tracing", MagicMock())
    assessor = MagicMock()
    judgments = {
        "investigate": SimpleNamespace(value=False, probability=0.1),
        "risk": SimpleNamespace(value=0.0, level=0),
        "category": SimpleNamespace(value="benign"),
    }
    judgments.update(invalid_judgment)
    assessor.return_value.return_value = dspy.Prediction(**judgments)
    monkeypatch.setattr(cli, "EventAssessor", assessor)
    assert cli.main(["--text", "Scheduled login"]) == 1
    assert capsys.readouterr().out == ""
