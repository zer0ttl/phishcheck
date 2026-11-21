"""Optional tracing contract without a real server."""

import importlib
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from phishcheck import tracing


def test_settings_precedence_and_blank_uri(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text(
        "MLFLOW_TRACKING_URI=http://file\nMLFLOW_EXPERIMENT_NAME=file\n"
    )
    monkeypatch.setenv("MLFLOW_TRACKING_URI", "http://environment")
    assert tracing.TracingSettings().tracking_uri == "http://environment"
    assert (
        tracing.TracingSettings(tracking_uri="http://cli").tracking_uri == "http://cli"
    )
    assert tracing.TracingSettings(tracking_uri=" ").tracking_uri is None


@pytest.mark.parametrize(
    "uri,enabled",
    [(None, None), ("", True), ("http://server", False), ("http://server", None)],
)
def test_disabled_tracing_does_not_import_mlflow(
    monkeypatch: pytest.MonkeyPatch, uri: str | None, enabled: bool | None
) -> None:
    loader = MagicMock()
    monkeypatch.setattr(importlib, "import_module", loader)
    assert (
        tracing.configure_tracing(
            tracing.TracingSettings(tracking_uri=uri, enabled=enabled)
        )
        is False
    )
    loader.assert_not_called()


def test_tracing_enables_dspy_autolog(monkeypatch: pytest.MonkeyPatch) -> None:
    mlflow, integration = MagicMock(), MagicMock()
    loader = MagicMock(side_effect=[mlflow, integration])
    monkeypatch.setattr(importlib, "import_module", loader)
    assert (
        tracing.configure_tracing(
            tracing.TracingSettings(
                tracking_uri="http://server", experiment_name="test", enabled=True
            )
        )
        is True
    )
    mlflow.set_tracking_uri.assert_called_once_with("http://server")
    mlflow.set_experiment.assert_called_once_with("test")
    integration.autolog.assert_called_once_with()


@pytest.mark.parametrize("stage", ["import", "experiment", "autolog"])
def test_tracing_failure_warns_and_continues(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, stage: str
) -> None:
    mlflow, integration = MagicMock(), MagicMock()
    loader = MagicMock(side_effect=[mlflow, integration])
    if stage == "import":
        loader.side_effect = ImportError("missing")
    elif stage == "experiment":
        mlflow.set_experiment.side_effect = ConnectionError("offline")
    else:
        integration.autolog.side_effect = RuntimeError("failure")
    monkeypatch.setattr(importlib, "import_module", loader)
    assert (
        tracing.configure_tracing(
            tracing.TracingSettings(tracking_uri="http://server", enabled=True)
        )
        is False
    )
    assert "MLflow tracing setup failed" in caplog.text


def test_disabled_assessment_suppresses_previous_tracing() -> None:
    import dspy
    from dspy.utils.callback import BaseCallback

    callback = BaseCallback()
    with dspy.context(callbacks=[callback]):
        with tracing.trace_assessment(
            tracing.TracingSettings(tracking_uri="http://server", enabled=False)
        ):
            assert dspy.settings.callbacks == []
        assert dspy.settings.callbacks == [callback]
