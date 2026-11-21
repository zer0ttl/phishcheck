"""Command-line interface for Phishcheck."""

import argparse
import errno
import json
import os
import socket
import sys
from pathlib import Path
from typing import Any

DEFAULT_PORT = 8000


def terminal_text(value: str) -> str:
    """Escape control characters that can change terminal state."""
    return "".join(
        char if char in "\n\t" or char.isprintable() else ascii(char)[1:-1]
        for char in value
    )


def bind_socket(host: str, port: int | None = None) -> socket.socket:
    """Reserve the selected address until Uvicorn takes ownership."""
    candidates = (port,) if port is not None else range(DEFAULT_PORT, 65536)
    for candidate in candidates:
        server_socket = socket.socket(
            socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_STREAM
        )
        try:
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((host, candidate))
            server_socket.listen()
            return server_socket
        except OSError as exc:
            server_socket.close()
            if port is not None or exc.errno != errno.EADDRINUSE:
                raise
    raise OSError(errno.EADDRINUSE, f"No available port from {DEFAULT_PORT} to 65535")


def _port(value: str) -> int:
    port = int(value)
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return port


def _serve(host: str, port: int | None) -> int:
    import uvicorn
    from pydantic import ValidationError

    from .web import create_app

    try:
        with bind_socket(host, port) as server_socket:
            server = uvicorn.Server(uvicorn.Config(create_app(), log_level="info"))
            address = f"[{host}]" if ":" in host else host
            print(
                f"Phishcheck at http://{address}:{server_socket.getsockname()[1]}",
                flush=True,
            )
            server.run(sockets=[server_socket])
            return 0 if server.started else 1
    except ValidationError:
        print(
            "Could not start Phishcheck: invalid application settings", file=sys.stderr
        )
        return 1
    except (OSError, RuntimeError) as exc:
        print(f"Could not start Phishcheck: {terminal_text(str(exc))}", file=sys.stderr)
        return 1


def _process(args: argparse.Namespace) -> int:
    from pydantic import ValidationError

    from . import service
    from .config import Settings
    from .tracing import TracingSettings

    try:
        if args.command == "parse":
            run = service.run_file("parse", args.file)
        else:
            provider_options = {
                key: value
                for key in ("model", "api_key", "api_base")
                if (value := getattr(args, key)) is not None
            }
            tracing_options: dict[str, Any] = {
                key: value
                for key in ("tracking_uri", "experiment_name")
                if (value := getattr(args, key)) is not None
            }
            if args.no_tracing:
                tracing_options["enabled"] = False
            run = service.run_file(
                "triage",
                args.file,
                provider_settings=lambda: Settings(**provider_options),
                tracing_settings=lambda: TracingSettings(**tracing_options),
            )
    except ValidationError:
        message = (
            "Invalid Phishcheck configuration. Check the environment and CLI options."
        )
        print(json.dumps({"error": message}) if args.json else message, file=sys.stderr)
        return 1

    if run.parsed is not None:
        if args.json:
            if run.verdict is not None:
                print(
                    json.dumps(
                        {
                            "triage": run.verdict.model_dump(mode="json"),
                            "parse": run.parsed.model_dump(mode="json"),
                        }
                    )
                )
            else:
                print(run.parsed.model_dump_json())
        else:
            if run.verdict is not None:
                verdict = run.verdict
                print(f"Verdict: {verdict.label}")
                print(terminal_text("\n".join(verdict.summary_lines())))
                print(terminal_text(verdict.model_dump_json(indent=2)))
            report = run.parsed
            lines = [
                f"File: {report.filename}",
                f"SHA-256: {report.sha256}",
                "Headers:",
            ]
            lines.extend(f"  {key}: {value}" for key, value in report.headers.items())
            lines.extend(["", "Body:", report.body or "(no body)", "", "URLs:"])
            lines.extend(f"  {link['text']} -> {link['url']}" for link in report.urls)
            lines.append("Attachments:")
            lines.extend(f"  {item.model_dump_json()}" for item in report.attachments)
            lines.append(f"Body extraction: {report.body_status}")
            lines.extend(f"Warning: {warning}" for warning in report.warnings)
            print(terminal_text("\n".join(lines)))

    if run.diagnostic or run.persistence_error:
        if args.json:
            print(
                json.dumps(
                    {
                        "error": run.diagnostic or run.persistence_error,
                        "status": run.status,
                        "persistence_error": run.persistence_error,
                        **(
                            {"detection": run.detection.model_dump(mode="json")}
                            if run.detection is not None
                            else {}
                        ),
                    }
                ),
                file=sys.stderr,
            )
        else:
            for diagnostic in (run.diagnostic, run.persistence_error):
                if diagnostic:
                    print(terminal_text(diagnostic), file=sys.stderr)
    if run.persistence_error:
        return 1
    return {"success": 0, "invalid_input": 2, "oversized": 2}.get(run.status, 1)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="phishcheck")
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("parse", "triage"):
        child = subparsers.add_parser(command)
        child.add_argument("file", type=Path)
        child.add_argument("--json", action="store_true")
        if command == "triage":
            for option in (
                "model",
                "api-key",
                "api-base",
                "tracking-uri",
                "experiment-name",
            ):
                child.add_argument(f"--{option}")
            child.add_argument("--no-tracing", action="store_true")
    serve = subparsers.add_parser("serve")
    serve.add_argument("-p", "--port", type=_port)
    serve.add_argument("--host", default=os.getenv("PHISHCHECK_HOST", "127.0.0.1"))
    args = parser.parse_args(argv)
    if args.command == "serve":
        return _serve(args.host, args.port)
    return _process(args)
