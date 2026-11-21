"""Validated example outputs."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue


class Investigation(BaseModel):
    """Investigation judgment and probability that it is warranted."""

    model_config = ConfigDict(strict=True)

    value: bool
    probability: float = Field(ge=0, le=1)


class Risk(BaseModel):
    """Continuous risk score and its zero-based rubric level."""

    model_config = ConfigDict(strict=True)

    value: float = Field(ge=0, le=4)
    level: int = Field(ge=0, le=4)


class Category(BaseModel):
    """The classification selected from the declared activity categories."""

    value: Literal["credential_attack", "malware", "lateral_movement", "benign"]


class EventAssessment(BaseModel):
    """Public JSON output for one assessed event."""

    investigate: Investigation
    risk: Risk
    category: Category
    usage: dict[str, JsonValue] | None = None
