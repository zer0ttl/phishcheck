"""Configuration and provider construction contract."""

from pathlib import Path
from unittest.mock import MagicMock

import dspy
import pytest
from pydantic import ValidationError

from emailscan import config


def test_configuration_precedence_and_blank_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text(
        'DSPY_MODEL=openai/file\nDSPY_API_KEY=\nDSPY_API_BASE=\nDSPY_LM_KWARGS={"temperature":0.2}\n'
    )
    monkeypatch.setenv("DSPY_MODEL", "anthropic/environment")
    assert config.Settings().model == "anthropic/environment"
    settings = config.Settings(model="ollama_chat/override")
    assert settings.model == "ollama_chat/override"
    assert settings.api_key is None
    assert settings.api_base is None
    assert settings.lm_kwargs == {"temperature": 0.2}
    monkeypatch.delenv("DSPY_MODEL")
    assert config.Settings().model == "openai/file"
    (tmp_path / ".env").unlink()
    assert config.Settings().model == "typesafe:jev-latest"


def test_configure_preserves_provider_options(monkeypatch: pytest.MonkeyPatch) -> None:
    lm = MagicMock()
    configure = MagicMock()
    monkeypatch.setattr(dspy, "LM", lm)
    monkeypatch.setattr(dspy, "configure", configure)
    settings = config.Settings(
        model="openai/proxy",
        api_base="http://proxy/v1",
        api_key="secret",
        lm_kwargs={"temperature": 0.3},
    )
    assert config.configure(settings) is lm.return_value
    lm.assert_called_once_with(
        model="openai/proxy",
        api_key="secret",
        api_base="http://proxy/v1",
        temperature=0.3,
    )
    configure.assert_called_once_with(lm=lm.return_value, track_usage=True)


def test_optional_credentials_and_managed_options(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lm = MagicMock()
    monkeypatch.setattr(dspy, "LM", lm)
    monkeypatch.setattr(dspy, "configure", MagicMock())
    config.configure(
        config.Settings(model="ollama_chat/local", api_key="", api_base="")
    )
    lm.assert_called_once_with(model="ollama_chat/local")
    with pytest.raises(ValidationError, match="managed options"):
        config.Settings(lm_kwargs={"model": "bad"})
