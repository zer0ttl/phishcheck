"""Optional MLflow DSPy tracing."""

import importlib
import logging

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)


class TracingSettings(BaseSettings):
    """Load standard MLFLOW_* variables and the explicit enable switch."""

    model_config = SettingsConfigDict(
        env_prefix="MLFLOW_", env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )
    tracking_uri: str | None = None
    experiment_name: str = "emailscan"
    enabled: bool | None = None

    @field_validator("tracking_uri", mode="before")
    @classmethod
    def blank_to_none(cls, value: object) -> object:
        """Treat an empty tracking URI as absent."""
        return None if isinstance(value, str) and not value.strip() else value


def configure_tracing(settings: TracingSettings) -> bool:
    """Enable DSPy autologging when a tracking URI is configured.

    Args:
        settings: Effective tracing configuration.

    Returns:
        Whether tracing was successfully enabled.
    """
    if settings.enabled is False or not settings.tracking_uri:
        return False
    try:
        mlflow = importlib.import_module("mlflow")
        integration = importlib.import_module("mlflow.dspy")
        mlflow.set_tracking_uri(settings.tracking_uri)
        mlflow.set_experiment(settings.experiment_name)
        integration.autolog()
        return True
    except Exception:
        logger.warning(
            "MLflow tracing setup failed; continuing without tracing", exc_info=True
        )
        return False
