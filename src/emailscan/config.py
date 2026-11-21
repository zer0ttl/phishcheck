"""Environment-backed provider configuration, independent of the example."""

from typing import Any

import dspy
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Load DSPY_* variables; explicit constructor values take precedence."""

    model_config = SettingsConfigDict(
        env_prefix="DSPY_", env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )
    model: str = "typesafe:jev-latest"
    api_key: str | None = Field(default=None, repr=False)
    api_base: str | None = None
    lm_kwargs: dict[str, Any] = Field(default_factory=dict)
    track_usage: bool = True

    @field_validator("api_key", "api_base", mode="before")
    @classmethod
    def blank_to_none(cls, value: object) -> object:
        """Treat empty optional environment variables as absent."""
        return None if isinstance(value, str) and not value.strip() else value

    @field_validator("lm_kwargs")
    @classmethod
    def validate_options(cls, value: dict[str, Any]) -> dict[str, Any]:
        """Keep managed provider settings out of the extra options."""
        if {"model", "api_key", "api_base"}.intersection(value):
            raise ValueError(
                "Use DSPY_MODEL, DSPY_API_KEY or DSPY_API_BASE for managed options"
            )
        return value


def configure(settings: Settings) -> Any:
    """Construct an LM and configure DSPy usage tracking.

    Args:
        settings: Effective provider settings, including CLI overrides.

    Returns:
        The configured DSPy language model.
    """
    options: dict[str, Any] = {"model": settings.model, **settings.lm_kwargs}
    if settings.api_key is not None:
        options["api_key"] = settings.api_key
    if settings.api_base is not None:
        options["api_base"] = settings.api_base
    lm = dspy.LM(**options)
    dspy.configure(lm=lm, track_usage=settings.track_usage)
    return lm
