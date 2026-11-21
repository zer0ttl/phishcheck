"""Optional MLflow DSPy tracing."""

import importlib
import logging
from collections.abc import Iterator
from contextlib import contextmanager
from threading import Lock

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)
_setup_lock = Lock()
_configured_target: tuple[str, str] | None = None


class TracingSettings(BaseSettings):
    """Load standard MLFLOW_* variables and the explicit enable switch."""

    model_config = SettingsConfigDict(
        env_prefix="MLFLOW_", env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )
    tracking_uri: str | None = None
    experiment_name: str = "phishcheck"
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
    if settings.enabled is not True or not settings.tracking_uri:
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


@contextmanager
def trace_assessment(settings: TracingSettings) -> Iterator[None]:
    """Limit DSPy tracing to assessments with explicit, successful opt-in."""
    from dspy import context

    global _configured_target
    if settings.enabled is True and settings.tracking_uri:
        target = (settings.tracking_uri, settings.experiment_name)
        with _setup_lock:
            if _configured_target != target:
                _configured_target = target if configure_tracing(settings) else None
            enabled = _configured_target == target
        if enabled:
            yield
            return

    # MLflow autolog installs a process-wide callback. A previous assessment
    # may have enabled it, so suppress it in this DSPy execution context.
    with context(callbacks=[]):
        yield
