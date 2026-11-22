"""Bounded Apache Tika text extraction."""

import asyncio
import json
import time

import httpx

from .models import ExtractedContent, ExtractionRecord


class TikaClient:
    def __init__(
        self,
        base_url: str | None,
        timeout: float = 10,
        max_response_bytes: int = 1024 * 1024,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/") if base_url else None
        self.timeout = timeout
        self.max_response_bytes = max_response_bytes
        self.transport = transport

    def extract(
        self, data: bytes, *, deadline: float | None = None
    ) -> ExtractedContent:
        if not self.base_url:
            return ExtractedContent(status="unavailable", text=None, metadata={})
        now = time.monotonic()
        end = (
            min(now + self.timeout, deadline)
            if deadline is not None
            else now + self.timeout
        )
        if end <= now:
            return ExtractedContent(status="truncated", text=None, metadata={})
        return asyncio.run(self._extract(data, end))

    async def _extract(self, data: bytes, deadline: float) -> ExtractedContent:
        remaining = max(0.0, deadline - time.monotonic())
        try:
            async with (
                asyncio.timeout(remaining),
                httpx.AsyncClient(
                    timeout=remaining,
                    follow_redirects=False,
                    transport=self.transport,
                    trust_env=False,
                ) as client,
            ):
                async with client.stream(
                    "PUT",
                    f"{self.base_url}/rmeta/text",
                    content=data,
                    headers={
                        "Accept": "application/json",
                        "Accept-Encoding": "identity",
                    },
                ) as response:
                    response.raise_for_status()
                    # Avoid an unbounded decompression allocation from an encoded response.
                    if (
                        response.headers.get("Content-Encoding", "identity").lower()
                        != "identity"
                    ):
                        return ExtractedContent(
                            status="unavailable", text=None, metadata={}
                        )
                    payload = bytearray()
                    async for chunk in response.aiter_bytes():
                        if len(payload) + len(chunk) > self.max_response_bytes:
                            return ExtractedContent(
                                status="truncated", text=None, metadata={}
                            )
                        payload.extend(chunk)
            raw = json.loads(payload)
            if (
                not isinstance(raw, list)
                or not raw
                or not all(isinstance(item, dict) for item in raw)
            ):
                return ExtractedContent(status="unavailable", text=None, metadata={})
            records: list[ExtractionRecord] = []
            for item in raw:
                content_key = "tk:content" if "tk:content" in item else "X-TIKA:content"
                text = item.pop(content_key, None)
                if text is not None and not isinstance(text, str):
                    return ExtractedContent(
                        status="unavailable", text=None, metadata={}
                    )
                records.append(ExtractionRecord(text=text, metadata=item))
            root = records[0]
            truncated = any(
                any(
                    key.casefold() == "x-tika:exception:write_limit_reached"
                    for key in record.metadata
                )
                for record in records
            )
            return ExtractedContent(
                status=(
                    "truncated"
                    if truncated
                    else "complete"
                    if any(record.text is not None for record in records)
                    else "unavailable"
                ),
                text=root.text,
                metadata=root.metadata,
                records=records,
            )
        except TimeoutError:
            return ExtractedContent(status="truncated", text=None, metadata={})
        except (httpx.HTTPError, httpx.InvalidURL, ValueError, RecursionError):
            return ExtractedContent(status="unavailable", text=None, metadata={})
