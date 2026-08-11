"""Tests for pipeline parsing helpers."""

import base64

from fns.collectors.base import RawContent
from fns.pipeline import _split_parse_chunks


def test_split_parse_chunks_splits_large_uri_subscription():
    lines = [f"vmess://node-{i}" for i in range(45_000)]
    raw = RawContent(
        text="\n".join(lines),
        source_url="https://example.com/sub.txt",
        collector_name="api",
    )

    chunks = _split_parse_chunks(raw)
    assert len(chunks) == 3
    assert all(chunk.startswith("vmess://") for chunk in chunks)
    assert sum(chunk.count("\n") + 1 for chunk in chunks) == 45_000


def test_split_parse_chunks_decodes_base64_subscription():
    lines = [f"vmess://node-{i}" for i in range(25_000)]
    payload = base64.b64encode("\n".join(lines).encode()).decode()
    raw = RawContent(
        text=payload,
        source_url="https://example.com/sub.txt",
        collector_name="api",
    )

    chunks = _split_parse_chunks(raw)
    assert len(chunks) == 2
    assert chunks[0].startswith("vmess://")


def test_split_parse_chunks_skips_non_uri_content():
    raw = RawContent(
        text="proxies:\n  - name: test\n    type: ss\n",
        source_url="https://example.com/config.yaml",
        collector_name="github",
    )
    assert _split_parse_chunks(raw) == []
