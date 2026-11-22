"""Bounded email intake and safe RFC 822 parsing."""

import hashlib
import re
import subprocess
import tempfile
import time
from email import policy
from email.errors import (
    InvalidBase64CharactersDefect,
    InvalidBase64LengthDefect,
    InvalidBase64PaddingDefect,
    MessageError,
    MissingHeaderBodySeparatorDefect,
)
from email.message import Message
from email.parser import BytesParser
from functools import lru_cache
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, BinaryIO, Literal, cast

from bs4 import BeautifulSoup
from eml_parser import EmlParser
from eml_parser.attachments import embedded_message_bytes
from eml_parser.decode import decode_body
from eml_parser.headers import header_items
from eml_parser.mime import filename as mime_filename
from magika import Magika

from .extraction import TikaClient
from .models import (
    Attachment,
    BodyPart,
    EmailInput,
    EmailLink,
    ExtractedContent,
    FormatDetection,
    Header,
    MimeContainer,
    ParseReport,
)

MAX_INPUT = 25 * 1024 * 1024
MAX_ATTACHMENT = 10 * 1024 * 1024
MAX_ATTACHMENTS = 20
COMPOUND_FILE_MAGIC = bytes.fromhex("d0cf11e0a1b11ae1")
EMAIL_HEADERS = (
    "From",
    "To",
    "Subject",
    "Date",
    "Message-ID",
    "Return-Path",
    "Authentication-Results",
)
URL = re.compile(r"""https?://[^\s<>"']+""", re.IGNORECASE)
BASE64_RUN = re.compile("[a-zA-Z0-9+/]+")
DECODE_DEFECTS = (
    InvalidBase64CharactersDefect,
    InvalidBase64LengthDefect,
    InvalidBase64PaddingDefect,
)


class InvalidEmail(ValueError):
    """Input is not a structurally valid email."""

    def __init__(
        self, message: str, source: EmailInput | None = None, *, oversized: bool = False
    ) -> None:
        super().__init__(message)
        self.source = source
        self.oversized = oversized


class EmailConversionError(RuntimeError):
    """Outlook conversion could not run to completion."""


class _Markup(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.text: list[str] = []
        self.hidden: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"script", "style", "head"} and self.hidden is None:
            self.hidden = tag
        if not self.hidden and tag in {"p", "br", "li", "div", "tr", "blockquote"}:
            self.text.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag == self.hidden:
            self.hidden = None
        if not self.hidden and tag in {"p", "li", "div", "tr", "blockquote"}:
            self.text.append("\n")

    def handle_data(self, data: str) -> None:
        if not self.hidden:
            self.text.append(data)


def _anchor_links(html: str) -> list[EmailLink]:
    links: list[EmailLink] = []
    soup = BeautifulSoup(html, "html.parser")
    for anchor in soup.find_all("a", href=True):
        href = anchor.get("href")
        if isinstance(href, str) and (url := href.strip()):
            links.append({"text": " ".join(anchor.get_text().split()), "url": url})
    return links


@lru_cache(maxsize=1)
def _magika() -> Magika:
    return Magika()


def _detect(data: bytes) -> FormatDetection:
    try:
        result = _magika().identify_bytes(data)
        if not result.ok:
            return FormatDetection(status=str(result.status))
        return FormatDetection(
            status=str(result.status),
            label=str(result.output.label),
            mime_type=result.output.mime_type,
            score=float(result.score),
        )
    except Exception:
        # Structure and conversion can still establish format if the detector fails.
        return FormatDetection()


def _read_bounded(stream: BinaryIO, limit: int) -> bytes:
    result = bytearray()
    while len(result) <= limit:
        chunk = stream.read(min(64 * 1024, limit + 1 - len(result)))
        if not chunk:
            break
        result.extend(chunk)
    if len(result) > limit:
        raise InvalidEmail("Email exceeds the configured size limit", oversized=True)
    return bytes(result)


def _valid_eml(data: bytes, *, require_sender: bool = False) -> bool:
    # Only parse the top-level headers here. The MIME parser runs after normalization.
    try:
        msg = BytesParser(policy=policy.default).parsebytes(data, headersonly=True)
    except (MessageError, ValueError, RecursionError):
        return False
    if any(
        isinstance(defect, MissingHeaderBodySeparatorDefect) for defect in msg.defects
    ):
        return False
    present = [
        (key.casefold(), value) for key, value in msg.raw_items() if value.strip()
    ]
    if any(name == "from" and "@" in value for name, value in present):
        return True
    if require_sender:
        return False
    known = {name for name, _ in present}
    return (
        len(
            known.intersection(
                {"from", "to", "subject", "date", "message-id", "received"}
            )
        )
        >= 2
    )


def _is_outlook(source: EmailInput) -> bool:
    return source.filename.lower().endswith(".msg") or source.detected_type == "outlook"


def read_email(stream: BinaryIO, filename: str, settings: Any = None) -> EmailInput:
    data = _read_bounded(stream, getattr(settings, "max_input_bytes", MAX_INPUT))
    detection = _detect(data)
    source = EmailInput(
        data=data,
        filename=filename,
        sha256=hashlib.sha256(data).hexdigest(),
        detected_type=detection.label,
        detection_score=detection.score,
        detection=detection,
    )
    if not data:
        raise InvalidEmail(f"Email file is empty (Magika: {detection.label})", source)
    if _is_outlook(source):
        valid = data.startswith(COMPOUND_FILE_MAGIC)
    elif detection.label == "mht":
        # Web archives and RFC 822 messages share MIME syntax. A sender mailbox
        # distinguishes ordinary messages when Magika reports the archive type.
        valid = _valid_eml(data, require_sender=True)
    else:
        valid = _valid_eml(data) and detection.label in {
            "eml",
            "txt",
            "unknown",
            "undefined",
        }
    if not valid:
        raise InvalidEmail(
            f"Not a recognizable email (Magika: {detection.label})", source
        )
    return source


def normalize_email(source: EmailInput, settings: Any = None) -> bytes:
    if not _is_outlook(source):
        return source.data
    limit = getattr(settings, "max_converted_bytes", MAX_INPUT)
    timeout = getattr(settings, "conversion_timeout", 15)
    with tempfile.TemporaryDirectory(prefix="phishcheck-") as workspace:
        original = Path(workspace) / "input.msg"
        converted = Path(workspace) / "output.eml"
        original.write_bytes(source.data)
        try:
            subprocess.run(
                ["msgconvert", "--outfile", str(converted), str(original)],
                check=True,
                timeout=timeout,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except FileNotFoundError:
            raise EmailConversionError(
                "Install msgconvert to open Outlook email files"
            ) from None
        except subprocess.TimeoutExpired:
            raise EmailConversionError("Outlook email conversion timed out") from None
        except subprocess.CalledProcessError:
            raise InvalidEmail("Outlook email could not be converted", source) from None
        try:
            with converted.open("rb") as stream:
                data = _read_bounded(stream, limit)
        except FileNotFoundError:
            raise InvalidEmail(
                "Outlook conversion did not produce an email", source
            ) from None
        except InvalidEmail:
            raise InvalidEmail(
                "Converted email exceeds the configured size limit", source
            ) from None
    if not _valid_eml(data):
        raise InvalidEmail(
            "Outlook conversion did not produce a recognizable email", source
        )
    return data


def _headers(message: Message) -> list[Header]:
    return [
        Header(name=name, value=str(value).encode("utf-8", "replace").decode())
        for name, value in header_items(message)
    ]


def _extract(tika: TikaClient | None, data: bytes, deadline: float) -> ExtractedContent:
    if time.monotonic() >= deadline:
        return ExtractedContent(status="truncated", text=None, metadata={})
    if isinstance(tika, TikaClient):
        return tika.extract(data, deadline=deadline)
    if tika is not None:
        return tika.extract(data)
    return ExtractedContent(status="unavailable", text=None, metadata={})


def _body_content(part: Message, payload: bytes) -> str | None:
    encoding = str(part.get("Content-Transfer-Encoding", "")).strip().casefold()
    if not payload and (encoding == "base64" and part.get_payload()):
        return None
    charset = part.get_content_charset()
    try:
        content = payload.decode(charset or "utf-8")
        content.encode("utf-8")
    except (LookupError, ValueError):
        content = decode_body(payload, charset)
    if payload and (not content or "\x00" in content):
        return None
    return content


def _attachment_payload(part: Message, limit: int) -> tuple[bytes | None, int]:
    if part.is_multipart():
        payload = (
            embedded_message_bytes(part)
            if part.get_content_type() == "message/rfc822"
            else part.as_bytes(policy=policy.compat32)
        )
    else:
        encoding = str(part.get("Content-Transfer-Encoding", "")).strip().casefold()
        if encoding == "base64":
            raw = cast(str, part.get_payload())
            if len(raw) > limit:
                symbols = sum(
                    match.end() - match.start() for match in BASE64_RUN.finditer(raw)
                )
                size = symbols * 6 // 8
                if size > limit:
                    return None, size
        payload = cast(bytes, part.get_payload(decode=True)) or b""
    size = len(payload)
    return (payload if size <= limit else None), size


def parse_email(
    source: EmailInput, settings: Any = None, tika: TikaClient | None = None
) -> ParseReport:
    normalized = normalize_email(source, settings)
    # Use eml-parser's MIME repair. Read attachments from
    # the resulting MIME tree so we can stop extraction at the configured limits.
    parser = EmlParser(include_raw_body=True, parse_attachments=False)
    try:
        parser.decode_email_bytes(normalized)
    except RecursionError:
        raise InvalidEmail(
            "Email MIME structure exceeds the nesting limit", source
        ) from None
    msg = parser.msg
    headers_all = _headers(msg)
    headers: dict[str, str] = {}
    canonical = {name.casefold(): name for name in EMAIL_HEADERS}
    for header in headers_all:
        headers.setdefault(
            canonical.get(header.name.casefold(), header.name), header.value
        )
    plain: list[str] = []
    html: list[str] = []
    body_parts: list[BodyPart] = []
    mime_containers: list[MimeContainer] = []
    urls: list[EmailLink] = []
    attachments: list[Attachment] = []
    warnings: list[str] = []
    deadline = time.monotonic() + getattr(settings, "extraction_budget_seconds", 30)
    max_attachments = getattr(settings, "max_attachments", MAX_ATTACHMENTS)
    max_attachment_bytes = getattr(settings, "max_attachment_bytes", MAX_ATTACHMENT)
    stack: list[tuple[Message, tuple[int, ...]]] = [(msg, ())]
    while stack:
        part, mime_path = stack.pop()
        content_type = part.get_content_type()
        name = mime_filename(part) or None
        if (
            part.is_multipart()
            and part.get_content_maintype() == "multipart"
            and not name
            and part.get_content_disposition() != "attachment"
        ):
            mime_containers.append(
                MimeContainer(
                    content_type=content_type,
                    mime_path=mime_path,
                    headers=_headers(part),
                )
            )
            children = cast(list[Message], part.get_payload())
            stack.extend(
                (children[i], (*mime_path, i)) for i in range(len(children) - 1, -1, -1)
            )
            continue
        is_attachment = (
            bool(name)
            or part.get_content_disposition() == "attachment"
            or part.get_content_maintype() != "text"
        )
        if is_attachment:
            if len(attachments) >= max_attachments:
                if (
                    "Additional attachments omitted: count limit reached"
                    not in warnings
                ):
                    warnings.append(
                        "Additional attachments omitted: count limit reached"
                    )
                continue
            payload, size = _attachment_payload(part, max_attachment_bytes)
            detection = None
            if payload is None:
                warnings.append(
                    f"Attachment omitted by size limit: {name or '(unnamed)'}"
                )
                result = ExtractedContent(status="truncated", text=None, metadata={})
            else:
                detection = _detect(payload)
                if any(isinstance(defect, DECODE_DEFECTS) for defect in part.defects):
                    warnings.append(
                        f"Attachment transfer encoding is damaged: {name or '(unnamed)'}"
                    )
                    result = ExtractedContent(
                        status="unavailable", text=None, metadata={}
                    )
                else:
                    result = _extract(tika, payload, deadline)
            text = "\n".join(
                record.text for record in result.records if record.text is not None
            )
            attachments.append(
                Attachment(
                    name=name,
                    content_type=content_type,
                    status=result.status,
                    text=text or result.text,
                    detection=detection,
                    extraction=result,
                    size_bytes=size,
                    headers=_headers(part),
                    mime_path=mime_path,
                )
            )
            continue

        payload = cast(bytes, part.get_payload(decode=True)) or b""
        body_content = _body_content(part, payload)
        damaged = any(isinstance(defect, DECODE_DEFECTS) for defect in part.defects)
        body_parts.append(
            BodyPart(
                content_type=content_type,
                content=body_content,
                status="unavailable"
                if body_content is None
                else ("truncated" if damaged else "complete"),
                headers=_headers(part),
                mime_path=mime_path,
            )
        )
        if body_content is None:
            continue
        if content_type == "text/html":
            markup = _Markup()
            markup.feed(body_content)
            markup.close()
            urls.extend(_anchor_links(body_content))
            html.append("".join(markup.text))
        else:
            plain.append(body_content)

    body = "\n".join(plain).strip() or "\n".join(html).strip() or None
    body_status: Literal["complete", "absent", "unavailable", "truncated"]
    body_status = "complete" if body else "absent"
    fallback = None
    if any(part.status != "complete" for part in body_parts):
        body_status = "truncated" if body else "unavailable"
        warnings.append("Some message body text could not be decoded")
        if not body:
            fallback = _extract(tika, normalized, deadline)
            body = fallback.text
            body_status = fallback.status
            if not body and body_status == "complete":
                body_status = "unavailable"
    if not html and body:
        urls = [{"text": url, "url": url} for url in dict.fromkeys(URL.findall(body))]
    return ParseReport(
        filename=source.filename,
        sha256=source.sha256,
        headers=headers,
        body=body,
        body_status=body_status,
        urls=urls,
        attachments=attachments,
        warnings=warnings,
        detection=source.detection,
        headers_all=headers_all,
        body_parts=body_parts,
        mime_containers=mime_containers,
        body_extraction=fallback,
    )
