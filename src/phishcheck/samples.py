"""Curated message previews with recorded workshop verdicts."""

import json
from pathlib import Path

from pydantic import BaseModel, TypeAdapter

from .models import ParseReport
from .triage import Verdict


class SampleReport(BaseModel):
    title: str
    description: str
    source_path: str
    source_revision: str
    model: str
    parsed: ParseReport
    verdict: Verdict


def load_sample_reports() -> dict[str, SampleReport]:
    data = json.loads(
        Path(__file__).with_name("sample_reports.json").read_text(encoding="utf-8")
    )
    for sample in data.values():
        score = sample["verdict"]["phishing_evidence_score"]
        # JSON object keys are strings, while Verdict uses integer score levels.
        score["probabilities"] = {
            int(level): probability
            for level, probability in score["probabilities"].items()
        }
    return TypeAdapter(dict[str, SampleReport]).validate_python(data)
