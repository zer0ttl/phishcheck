import hashlib
import io
import subprocess
from email.message import EmailMessage
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from phishcheck.extraction import TikaClient
from phishcheck.parsing import InvalidEmail, parse_email, read_email

PLAIN = Path(__file__).with_name("fixtures").joinpath("plain.eml").read_bytes()


def test_intake_preserves_complete_invalid_upload() -> None:
    data = b"not an email"
    with pytest.raises(InvalidEmail) as caught:
        read_email(io.BytesIO(data), "spoof.eml")
    assert caught.value.source is not None
    assert caught.value.source.data == data
    assert caught.value.source.sha256 == hashlib.sha256(data).hexdigest()
    assert caught.value.source.detection.label == "txt"


def test_oversized_intake_keeps_no_partial_file() -> None:
    with pytest.raises(InvalidEmail) as caught:
        read_email(io.BytesIO(PLAIN), "plain.eml", SimpleNamespace(max_input_bytes=16))
    assert caught.value.oversized
    assert caught.value.source is None


def test_alternatives_and_repeated_headers_are_retained() -> None:
    message = EmailMessage()
    message["Subject"] = "Synthetic alternatives"
    message["From"] = "analyst@example.com"
    message["Received"] = "from first.example.org"
    message["Received"] = "from second.example.org"
    message.set_content("Plain view https://example.com/plain")
    message.add_alternative(
        '<a href="https://example.com/target">HTML view</a>', subtype="html"
    )
    report = parse_email(read_email(io.BytesIO(message.as_bytes()), "test.eml"))
    assert report.body == "Plain view https://example.com/plain"
    assert [(part.content_type, part.content) for part in report.body_parts] == [
        ("text/plain", "Plain view https://example.com/plain\n"),
        ("text/html", '<a href="https://example.com/target">HTML view</a>\n'),
    ]
    assert [h.value for h in report.headers_all if h.name == "Received"] == [
        "from first.example.org",
        "from second.example.org",
    ]
    assert report.urls == [{"text": "HTML view", "url": "https://example.com/target"}]


def test_outlook_uses_private_paths_and_preserves_input(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data = bytes.fromhex("d0cf11e0a1b11ae1") + b"sample"
    source = read_email(io.BytesIO(data), "../../upload.msg")
    paths: list[Path] = []

    def convert(argv: list[str], **kwargs: object) -> None:
        executable, option, output, original = argv
        assert (executable, option) == ("msgconvert", "--outfile")
        assert kwargs["timeout"] == 15
        paths.extend((Path(output), Path(original)))
        assert Path(original).read_bytes() == data
        Path(output).write_bytes(PLAIN)

    monkeypatch.setattr(subprocess, "run", convert)
    report = parse_email(source)
    assert report.headers["Subject"] == "Example message"
    assert report.sha256 == hashlib.sha256(data).hexdigest()
    assert all(not path.exists() for path in paths)


@pytest.mark.parametrize(
    ("failure", "error_type", "diagnostic"),
    [
        (FileNotFoundError(), RuntimeError, "Install msgconvert"),
        (subprocess.TimeoutExpired("msgconvert", 15), RuntimeError, "timed out"),
        (
            subprocess.CalledProcessError(1, "msgconvert", stderr=b"private"),
            InvalidEmail,
            "could not be converted",
        ),
        (b"not a message", InvalidEmail, "recognizable email"),
    ],
)
def test_conversion_failures_are_distinguished(
    monkeypatch: pytest.MonkeyPatch,
    failure: Exception | bytes,
    error_type: type[Exception],
    diagnostic: str,
) -> None:
    paths: list[Path] = []

    def convert(argv: list[str], **kwargs: object) -> None:
        paths.extend((Path(argv[2]), Path(argv[3])))
        if isinstance(failure, Exception):
            raise failure
        paths[0].write_bytes(failure)

    monkeypatch.setattr(subprocess, "run", convert)
    original = Path(__file__).with_name("fixtures").joinpath("outlook.msg").read_bytes()
    source = read_email(io.BytesIO(original), "outlook.msg")
    assert source.detection.label == "outlook"
    with pytest.raises(error_type, match=diagnostic) as caught:
        parse_email(source)
    assert "private" not in str(caught.value)
    assert all(not path.exists() for path in paths)


def test_html_only_message_yields_readable_text() -> None:
    message = EmailMessage()
    message["From"] = "analyst@example.com"
    message["Subject"] = "HTML sample"
    message.set_content(
        "<html><head><title>HTML sample</title></head><body><p>Hello &amp; welcome</p>"
        '<a href="https://example.com/details">Read more</a></body></html>',
        subtype="html",
    )
    report = parse_email(read_email(io.BytesIO(message.as_bytes()), "html.eml"))
    assert report.body == "Hello & welcome\nRead more"
    assert report.body_status == "complete"
    assert report.urls == [{"text": "Read more", "url": "https://example.com/details"}]


def test_malformed_body_uses_only_root_tika_text() -> None:
    data = b"From: analyst@example.com\r\nSubject: Test\r\nContent-Transfer-Encoding: base64\r\n\r\n!!!!"
    source = read_email(io.BytesIO(data), "bad-body.eml")
    unavailable = parse_email(source)
    assert unavailable.body_status == "unavailable"
    assert unavailable.body is None

    def extract(request: httpx.Request) -> httpx.Response:
        assert request.content == data
        return httpx.Response(
            200,
            json=[
                {"X-TIKA:content": "Recovered body"},
                {"X-TIKA:content": "Embedded file"},
            ],
        )

    report = parse_email(
        source,
        tika=TikaClient(
            "http://tika.example.net", transport=httpx.MockTransport(extract)
        ),
    )
    assert report.body == "Recovered body"
    assert report.body_status == "complete"
    assert report.body_extraction is not None
    assert report.body_extraction.records[1].text == "Embedded file"


def test_attachment_only_extraction_continues_after_a_failure() -> None:
    message = EmailMessage()
    message["From"] = "analyst@example.com"
    message["Subject"] = "Sample attachments"
    message.add_attachment(
        b"Content One",
        maintype="application",
        subtype="octet-stream",
        filename="first.txt",
    )
    message.add_attachment(
        b"Content Two",
        maintype="application",
        subtype="octet-stream",
        filename="second.txt",
    )
    calls: list[bytes] = []

    def extract(request: httpx.Request) -> httpx.Response:
        calls.append(request.content)
        if request.content == b"Content One":
            return httpx.Response(500)
        return httpx.Response(
            200, json=[{"X-TIKA:content": "Content Two", "Content-Type": "text/plain"}]
        )

    source = read_email(io.BytesIO(message.as_bytes()), "attachments.eml")
    tika = TikaClient("http://tika.example.net", transport=httpx.MockTransport(extract))
    report = parse_email(source, tika=tika)
    assert report.body_status == "absent"
    assert report.body_extraction is None
    assert calls == [b"Content One", b"Content Two"]
    assert [(part.name, part.status, part.text) for part in report.attachments] == [
        ("first.txt", "unavailable", None),
        ("second.txt", "complete", "Content Two"),
    ]
    second = report.attachments[1]
    assert second.content_type == "application/octet-stream"
    assert second.detection is not None
    assert second.detection.mime_type == "text/plain"
    assert second.extraction is not None
    assert second.extraction.metadata == {"Content-Type": "text/plain"}


def test_intact_plain_body_needs_no_tika_request() -> None:
    def extract(request: httpx.Request) -> httpx.Response:
        pytest.fail(f"Unexpected extraction request to {request.url}")

    source = read_email(io.BytesIO(PLAIN), "plain.eml")
    tika = TikaClient("http://tika.example.net", transport=httpx.MockTransport(extract))
    report = parse_email(source, tika=tika)
    assert report.body_status == "complete"
    assert report.body_extraction is None
    assert report.urls == [
        {"text": "https://example.com/info", "url": "https://example.com/info"}
    ]


def test_attachment_limits_show_skipped_evidence() -> None:
    message = EmailMessage()
    message["From"] = "analyst@example.com"
    message["Subject"] = "Samples"
    message.set_content("Please see attachments")
    message.add_attachment(
        b"large attachment",
        maintype="application",
        subtype="octet-stream",
        filename="large.txt",
    )
    message.add_attachment(
        b"second attachment",
        maintype="application",
        subtype="octet-stream",
        filename="second.txt",
    )

    def extract(request: httpx.Request) -> httpx.Response:
        pytest.fail(f"Unexpected extraction request to {request.url}")

    settings = SimpleNamespace(max_attachments=1, max_attachment_bytes=8)
    source = read_email(io.BytesIO(message.as_bytes()), "attachments.eml")
    tika = TikaClient("http://tika.example.net", transport=httpx.MockTransport(extract))
    report = parse_email(source, settings, tika)
    assert [(part.name, part.status) for part in report.attachments] == [
        ("large.txt", "truncated")
    ]
    assert report.warnings == [
        "Attachment omitted by size limit: large.txt",
        "Additional attachments omitted: count limit reached",
    ]


def test_recovered_body_is_kept_in_full() -> None:
    body = ("an ordinary line\n" * 4096) + "end of the message"
    message = EmailMessage()
    message["From"] = "analyst@example.com"
    message["Subject"] = "Long body"
    message.set_content(body)
    source = read_email(io.BytesIO(message.as_bytes()), "long.eml")
    report = parse_email(source)
    assert report.body_status == "complete"
    assert report.body == body
    assert report.body_parts[0].content == body + "\n"


def test_nested_mime_container_headers_are_preserved() -> None:
    message = EmailMessage()
    message["From"] = "analyst@example.com"
    message["Subject"] = "Nested messages"
    message.set_content("Plain view")
    message.add_alternative("<p>HTML view</p>", subtype="html")
    message.add_attachment(
        b"Attachment", maintype="application", subtype="octet-stream"
    )
    alternative = message.get_payload(0)
    assert isinstance(alternative, EmailMessage)
    alternative["X-Sample"] = "alternative container"

    report = parse_email(read_email(io.BytesIO(message.as_bytes()), "nested.eml"))
    assert [(part.content_type, part.mime_path) for part in report.mime_containers] == [
        ("multipart/mixed", ()),
        ("multipart/alternative", (0,)),
    ]
    assert "alternative container" in [
        h.value for h in report.mime_containers[1].headers
    ]
    assert [part.mime_path for part in report.body_parts] == [(0, 0), (0, 1)]
    assert report.attachments[0].mime_path == (1,)


def test_html_links_keep_anchor_text_and_destination_in_message_order() -> None:
    message = EmailMessage()
    message["From"] = "analyst@example.com"
    message["Subject"] = "Synthetic links"
    message.set_content(
        '<a href="https://example.net/go?x=1&amp;y=2">Visit <b>example.org</b></a>'
        '<a href="https://example.net/go?x=1&amp;y=2">Other label</a>'
        '<a href="/profile"><img src="/photo"></a>'
        '<a href=" ">Empty destination</a><a>Missing destination</a>'
        '<img src="https://example.net/photo"><form action="/submit"></form>',
        subtype="html",
    )
    report = parse_email(read_email(io.BytesIO(message.as_bytes()), "links.eml"))
    assert report.urls == [
        {"text": "Visit example.org", "url": "https://example.net/go?x=1&y=2"},
        {"text": "Other label", "url": "https://example.net/go?x=1&y=2"},
        {"text": "", "url": "/profile"},
    ]


def test_html_without_anchors_still_takes_precedence_over_plain_urls() -> None:
    message = EmailMessage()
    message["From"] = "analyst@example.com"
    message["Subject"] = "Anchorless HTML"
    message.set_content("https://example.net/plain")
    message.add_alternative("<p>https://example.net/html</p>", subtype="html")
    report = parse_email(read_email(io.BytesIO(message.as_bytes()), "no-links.eml"))
    assert report.urls == []
