import asyncio
from collections.abc import AsyncIterator

import httpx
import pytest

from phishcheck.extraction import TikaClient


@pytest.mark.parametrize("content_key", ["X-TIKA:content", "tk:content"])
def test_recovers_root_and_embedded_records(content_key: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "PUT"
        assert str(request.url) == "http://tika.example.net:9998/rmeta/text"
        assert request.content == b"decoded attachment bytes"
        return httpx.Response(
            200,
            json=[
                {content_key: "outer", "Content-Type": "application/pdf"},
                {
                    content_key: "inner",
                    "X-TIKA:embedded_resource_path": "/inner.txt",
                },
            ],
        )

    client = TikaClient(
        "http://tika.example.net:9998/", transport=httpx.MockTransport(handler)
    )
    result = client.extract(b"decoded attachment bytes")
    assert result.status == "complete"
    assert result.text == "outer"
    assert result.metadata == {"Content-Type": "application/pdf"}
    assert [record.text for record in result.records] == ["outer", "inner"]
    assert result.records[1].metadata == {"X-TIKA:embedded_resource_path": "/inner.txt"}


@pytest.mark.parametrize(
    ("response", "status"),
    [
        (
            httpx.Response(302, headers={"Location": "http://other.example.com/"}),
            "unavailable",
        ),
        (httpx.Response(500), "unavailable"),
        (httpx.Response(200, content=b"bad json"), "unavailable"),
        (httpx.Response(200, json=[{"X-TIKA:content": None}, {}]), "unavailable"),
        (httpx.Response(200, json=[{"X-TIKA:content": 5}]), "unavailable"),
        (httpx.Response(200, content=b"x" * 65), "truncated"),
    ],
)
def test_extraction_failures_produce_status(
    response: httpx.Response, status: str
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "tika.example.net"
        return response

    client = TikaClient(
        "http://tika.example.net",
        max_response_bytes=64,
        transport=httpx.MockTransport(handler),
    )
    assert client.extract(b"test").status == status


def test_timeout_is_reported() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("synthetic timeout", request=request)

    client = TikaClient(
        "http://tika.example.net", transport=httpx.MockTransport(handler)
    )
    assert client.extract(b"test").status == "unavailable"


def test_response_stream_respects_wall_clock_budget() -> None:
    class SlowResponse(httpx.AsyncByteStream):
        async def __aiter__(self) -> AsyncIterator[bytes]:
            await asyncio.sleep(0.1)
            yield b'[{"tk:content": "too late"}]'

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=SlowResponse())

    client = TikaClient(
        "http://tika.example.net", timeout=0.01, transport=httpx.MockTransport(handler)
    )
    assert client.extract(b"test").status == "truncated"
