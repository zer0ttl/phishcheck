"""Consistent command-line entry point."""

import argparse
import logging
from collections.abc import Sequence
from typing import Any

from .config import Settings, configure
from .models import Category, EventAssessment, Investigation, Risk
from .modules import EventAssessor
from .tracing import TracingSettings, configure_tracing


def main(argv: Sequence[str] | None = None) -> int:
    """Run the example and emit JSON.

    Args:
        argv: Command-line arguments, or None to use the process arguments.

    Returns:
        Zero on success, one on runtime failure. Argument errors exit with two.
    """
    parser = argparse.ArgumentParser(description="Assess a security event with Jev")
    parser.add_argument("--text", required=True, help="Security event description")
    parser.add_argument("--model")
    parser.add_argument("--api-key", help="Prefer DSPY_API_KEY to avoid shell history")
    parser.add_argument("--api-base")
    parser.add_argument("--tracking-uri")
    parser.add_argument("--experiment-name")
    parser.add_argument(
        "--tracing", action=argparse.BooleanOptionalAction, default=None
    )
    parser.add_argument(
        "--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR"], default="WARNING"
    )
    args = parser.parse_args(argv)
    if not args.text.strip():
        parser.error("--text must contain a security event description")
    logging.basicConfig(level=args.log_level)
    try:
        provider: dict[str, Any] = {
            key: getattr(args, key)
            for key in ("model", "api_key", "api_base")
            if getattr(args, key) is not None
        }
        tracing: dict[str, Any] = {
            key: getattr(args, key)
            for key in ("tracking_uri", "experiment_name")
            if getattr(args, key) is not None
        }
        if args.tracing is not None:
            tracing["enabled"] = args.tracing
        settings = Settings(**provider)
        trace_settings = TracingSettings(**tracing)
        configure(settings)
        configure_tracing(trace_settings)
        result = EventAssessor()(event=args.text)
        output = EventAssessment(
            investigate=Investigation(
                value=result.investigate.value,
                probability=result.investigate.probability,
            ),
            risk=Risk(value=result.risk.value, level=result.risk.level),
            category=Category(value=result.category.value),
            usage=result.get_lm_usage() or None,
        )
        print(output.model_dump_json(exclude_none=True))
        return 0
    except Exception:
        logging.getLogger(__name__).exception("Project execution failed")
        return 1
