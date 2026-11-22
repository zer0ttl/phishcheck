"""Exercise the typed email program through the native provider transport."""

import json
from importlib import import_module
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from phishcheck.config import Settings
from phishcheck.modules import AssessmentError, assess
from phishcheck.parsing import parse_email, read_email
from phishcheck.signatures import LABELS
from phishcheck.triage import DecisionEvidence, project_evidence


@pytest.fixture
def evidence() -> DecisionEvidence:
    path = Path(__file__).parent / "fixtures" / "plain.eml"
    with path.open("rb") as stream:
        source = read_email(stream, path.name)
    return project_evidence(parse_email(source))


def answer_fixture(attack_probability: float = 0.1) -> dict[str, object]:
    answers: dict[str, object] = {
        name: {
            "type": "noul",
            "noul": attack_probability if name == "financial_fraud" else 0.1,
        }
        for name in LABELS
    }
    answers.update(
        email_verdict={
            "type": "choice",
            "choice": "likely_phishing",
            "confidence": 0.8,
            "probabilities": {
                "likely_phishing": 0.9,
                "likely_legitimate": 0.02,
                "unsolicited_bulk_email": 0.03,
                "needs_review": 0.05,
            },
        },
        phishing_evidence_score={
            "type": "score",
            "score": 3.1,
            "confidence": 0.8,
            "probabilities": {"0": 0, "1": 0, "2": 0, "3": 0.9, "4": 0.1},
        },
        benign_explanation={"type": "noul", "noul": 0.1},
    )
    return answers


def stub_transport(
    monkeypatch: pytest.MonkeyPatch, body: str, status: int = 200
) -> MagicMock:
    transports = import_module("dspy._vendor.lm15.transports")
    transport = MagicMock(
        return_value=transports.TransportResponse(
            status=status,
            reason="OK",
            headers=[("Content-Type", "application/json")],
            http_version="HTTP/1.1",
            chunks=iter([body.encode()]),
            release=MagicMock(),
        )
    )
    monkeypatch.setattr(transports.StdlibTransport, "stream", transport)
    return transport


@pytest.mark.parametrize("override", [False, True])
@pytest.mark.parametrize("track_usage", [False, True])
def test_native_email_round_trip(
    monkeypatch: pytest.MonkeyPatch,
    evidence: DecisionEvidence,
    override: bool,
    track_usage: bool,
) -> None:
    monkeypatch.setenv("TYPESAFE_API_KEY", "fixture-key")
    settings = Settings(
        model="typesafe:jev-test" if override else "typesafe:jev-latest",
        api_key="override-key" if override else None,
        api_base="https://provider.example" if override else None,
        track_usage=track_usage,
    )
    body = json.dumps(
        {
            "answers": answer_fixture(attack_probability=0.9),
            "usage": {"input_tokens": 17, "output_tokens": 3},
        }
    )
    transport = stub_transport(monkeypatch, body)
    assessment = assess(evidence, settings)
    transport.assert_called_once()
    request = transport.call_args.args[0]
    assert request.method == "POST"
    base = "https://provider.example" if override else "https://api.typesafe.ai"
    assert request.url == f"{base}/v1/systemone"
    assert (
        dict(request.headers)["Authorization"]
        == f"Bearer {'override-key' if override else 'fixture-key'}"
    )
    payload = json.loads(request.body)
    assert payload["model"] == ("jev-test" if override else "jev-latest")
    assert payload["state"]["inputs"] == {"evidence": evidence.model_dump(mode="json")}
    assert len(json.dumps(payload["state"]).encode()) <= 16 * 1024
    questions = payload["questions"]
    assert {name: question["type"] for name, question in questions.items()} == {
        **dict.fromkeys(LABELS, "noul"),
        "email_verdict": "choice",
        "phishing_evidence_score": "score",
        "benign_explanation": "noul",
    }
    assert set(questions["email_verdict"]["criteria"]) == {
        "likely_phishing",
        "likely_legitimate",
        "unsolicited_bulk_email",
        "needs_review",
    }
    assert len(questions["phishing_evidence_score"]["criteria"]) == 5
    assert all(questions[label]["instructions"].endswith("?") for label in LABELS)
    assert assessment.stage.request_payload == payload
    assert assessment.stage.response_body == body
    if track_usage:
        assert assessment.stage.usage is not None
        usage = assessment.stage.usage[settings.model]
        assert isinstance(usage, dict)
        assert usage["prompt_tokens"] == 17
        assert usage["completion_tokens"] == 3
        assert usage["total_tokens"] == 20
    else:
        assert assessment.stage.usage is None
    assert assessment.verdict.attacks == ["financial_fraud"]
    assert assessment.verdict.final_verdict == "likely_phishing"
    assert assessment.verdict.phishing_evidence_score.score == pytest.approx(3.1)
    assert assessment.verdict.benign_explanation == 0.1


@pytest.mark.parametrize(
    "body,status",
    [
        ('{"answers": {}}', 200),
        ("not JSON", 200),
        ('{"error": "provider failure"}', 401),
        (
            json.dumps(
                {
                    "answers": {
                        name: {
                            "type": "noul",
                            "noul": True if name == "spoofing" else 0.1,
                        }
                        for name in LABELS
                    }
                }
            ),
            200,
        ),
    ],
)
def test_failed_typed_response_retains_wire_data(
    monkeypatch: pytest.MonkeyPatch, evidence: DecisionEvidence, body: str, status: int
) -> None:
    transport = stub_transport(monkeypatch, body, status)
    with pytest.raises(AssessmentError) as excinfo:
        assess(evidence, Settings(api_key="fixture-key"))
    transport.assert_called_once()
    assert excinfo.value.stage.request_payload == json.loads(
        transport.call_args.args[0].body
    )
    assert excinfo.value.stage.response_status == status
    assert excinfo.value.stage.response_body == body


def test_generative_route_is_rejected(
    monkeypatch: pytest.MonkeyPatch, evidence: DecisionEvidence
) -> None:
    transport = stub_transport(monkeypatch, "{}")
    with pytest.raises(AssessmentError, match="TypeSafe System One"):
        assess(evidence, Settings(model="openai/gpt-4o"))
    transport.assert_not_called()


def test_wire_state_remains_inert_and_within_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from phishcheck.models import ParseReport

    marker_text = (
        "<<CUSTOM-TYPE-START-IDENTIFIER>>example<<CUSTOM-TYPE-END-IDENTIFIER>>"
    )
    evidence = project_evidence(
        ParseReport(
            filename="test.eml",
            sha256="hash",
            headers={"Subject": marker_text},
            body=("🚀" + marker_text + '"\\\n') * 500,
            body_status="complete",
            urls=[{"text": "Displayed site", "url": "https://example.test"}],
            attachments=[],
        )
    )
    transport = stub_transport(
        monkeypatch,
        json.dumps({"answers": answer_fixture()}),
    )
    result = assess(evidence, Settings(api_key="fixture-key"))
    payload = json.loads(transport.call_args.args[0].body)
    assert "assets" not in payload
    assert payload["state"]["inputs"]["evidence"]["urls"] == [
        {"text": "Displayed site", "url": "https://example.test"}
    ]
    assert payload["state"]["inputs"]["evidence"] == result.stage.evidence.model_dump(
        mode="json"
    )
    assert len(json.dumps(payload["state"]).encode()) <= 16 * 1024
    assert "body" in result.stage.evidence.omissions


def test_response_cache_cannot_skip_provider_payload_capture(
    monkeypatch: pytest.MonkeyPatch, evidence: DecisionEvidence
) -> None:
    transport = stub_transport(monkeypatch, "{}")
    with pytest.raises(AssessmentError, match="cache"):
        assess(evidence, Settings(api_key="fixture-key", lm_kwargs={"cache": True}))
    transport.assert_not_called()


@pytest.mark.parametrize(
    "question", ["email_verdict", "phishing_evidence_score", "benign_explanation"]
)
@pytest.mark.parametrize("malformed", [False, True])
def test_summary_answers_are_required_and_typed(
    monkeypatch: pytest.MonkeyPatch,
    evidence: DecisionEvidence,
    question: str,
    malformed: bool,
) -> None:
    answers = answer_fixture()
    if malformed:
        answers[question] = {"type": "noul", "noul": "invalid"}
    else:
        del answers[question]
    body = json.dumps({"answers": answers})
    stub_transport(monkeypatch, body)
    with pytest.raises(AssessmentError) as error:
        assess(evidence, Settings(api_key="fixture-key"))
    assert error.value.stage.response_body == body
