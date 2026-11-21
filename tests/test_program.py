"""Exercise the Jev adapter and native provider with a stubbed HTTP transport."""

import json
from importlib import import_module
from unittest.mock import MagicMock

import pytest

from emailscan.cli import main


@pytest.mark.parametrize("track_usage", [True, False])
def test_jev_round_trip(
    track_usage: bool,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Verify one Jev request and decode its three probability-backed answers."""
    event = "Multiple failed logins preceded a successful login."
    monkeypatch.setenv("DSPY_MODEL", "typesafe:jev-latest")
    monkeypatch.delenv("DSPY_API_BASE", raising=False)
    monkeypatch.delenv("DSPY_API_KEY", raising=False)
    monkeypatch.setenv("TYPESAFE_API_KEY", "fixture-key")
    monkeypatch.setenv("DSPY_LM_KWARGS", '{"cache": false}')
    monkeypatch.setenv("DSPY_TRACK_USAGE", str(track_usage))
    fixture = {
        "answers": {
            "investigate": {"type": "noul", "noul": 0.9},
            "risk": {
                "type": "score",
                "confidence": 0.75,
                "probabilities": {"0": 0, "1": 0, "2": 0.25, "3": 0.75, "4": 0},
            },
            "category": {
                "type": "choice",
                "choice": "credential_attack",
                "confidence": 0.9,
                "probabilities": {
                    "credential_attack": 0.9,
                    "malware": 0,
                    "lateral_movement": 0,
                    "benign": 0.1,
                },
            },
        },
        "usage": {"input_tokens": 17, "output_tokens": 3},
    }
    transports = import_module("dspy._vendor.lm15.transports")
    transport = MagicMock(
        return_value=transports.TransportResponse(
            status=200,
            reason="OK",
            headers=[("Content-Type", "application/json")],
            http_version="HTTP/1.1",
            chunks=iter([json.dumps(fixture).encode()]),
            release=MagicMock(),
        )
    )
    monkeypatch.setattr(transports.StdlibTransport, "stream", transport)

    assert main(["--text", event, "--no-tracing"]) == 0
    transport.assert_called_once()
    request = transport.call_args.args[0]
    assert request.method == "POST"
    assert request.url == "https://api.typesafe.ai/v1/systemone"
    assert dict(request.headers)["Authorization"] == "Bearer fixture-key"
    payload = json.loads(request.body)
    assert payload["model"] == "jev-latest"
    assert payload["state"]["inputs"] == {"event": event}
    question_types = {
        name: question["type"] for name, question in payload["questions"].items()
    }
    assert question_types == {
        "investigate": "noul",
        "risk": "score",
        "category": "choice",
    }

    output = json.loads(capsys.readouterr().out)
    if track_usage:
        assert output.pop("usage")["typesafe:jev-latest"]["prompt_tokens"] == 17
    assert output == {
        "investigate": {"value": True, "probability": 0.9},
        "risk": {"value": 2.75, "level": 3},
        "category": {"value": "credential_attack"},
    }
