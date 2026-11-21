"""Validated public report models."""

from typing import Literal, TypedDict

from pydantic import BaseModel, ConfigDict, Field


class EmailLink(TypedDict):
    text: str
    url: str


class FormatDetection(BaseModel):
    status: str = "unavailable"
    label: str = "unknown"
    mime_type: str | None = None
    score: float | None = None


class EmailInput(BaseModel):
    data: bytes
    filename: str
    sha256: str
    detected_type: str = "unknown"
    detection_score: float | None = None
    detection: FormatDetection = Field(default_factory=FormatDetection)


class Header(BaseModel):
    name: str
    value: str


class MimeContainer(BaseModel):
    content_type: str
    mime_path: tuple[int, ...]
    headers: list[Header]


class BodyPart(BaseModel):
    content_type: str
    content: str | None
    status: Literal["complete", "unavailable", "truncated"]
    headers: list[Header] = Field(default_factory=list)
    mime_path: tuple[int, ...] = ()


class ExtractionRecord(BaseModel):
    text: str | None
    metadata: dict[str, object]


class ExtractedContent(BaseModel):
    status: Literal["complete", "unavailable", "truncated"]
    text: str | None
    metadata: dict[str, object]
    records: list[ExtractionRecord] = Field(default_factory=list)


class Attachment(BaseModel):
    name: str | None = None
    content_type: str | None = None
    status: Literal["not_extracted", "complete", "unavailable", "truncated"] = (
        "not_extracted"
    )
    text: str | None = None
    detection: FormatDetection | None = None
    extraction: ExtractedContent | None = None
    size_bytes: int | None = None
    headers: list[Header] = Field(default_factory=list)
    mime_path: tuple[int, ...] = ()


class ParseReport(BaseModel):
    model_config = ConfigDict(extra="forbid")
    filename: str
    sha256: str
    headers: dict[str, str]
    body: str | None
    body_status: Literal["complete", "absent", "unavailable", "truncated"]
    urls: list[EmailLink]
    attachments: list[Attachment]
    warnings: list[str] = Field(default_factory=list)
    detection: FormatDetection = Field(default_factory=FormatDetection)
    headers_all: list[Header] = Field(default_factory=list)
    body_parts: list[BodyPart] = Field(default_factory=list)
    mime_containers: list[MimeContainer] = Field(default_factory=list)
    body_extraction: ExtractedContent | None = None
