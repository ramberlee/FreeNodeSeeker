"""Tests for validation cache versioning."""

import base64
import json

import pytest

from fns.collectors.base import RawContent
from fns.config import FnsConfig, OutputConfig
from fns.pipeline import _load_validation_cache, _save_validation_cache, run_pipeline


class _FakeCollector:
    name = "fake"

    async def collect(self):
        payload = base64.b64encode(
            json.dumps(
                {
                    "v": "2",
                    "ps": "SkipValidation",
                    "add": "1.2.3.4",
                    "port": "443",
                    "id": "b831381d-6324-4d53-ad4f-8cda48b30811",
                    "net": "tcp",
                }
            ).encode()
        ).decode()
        return [
            RawContent(
                text=f"vmess://{payload}",
                source_url="https://example.com/sub",
                collector_name=self.name,
            )
        ]


def test_validation_cache_ignores_old_format(tmp_path):
    cache_file = tmp_path / "fns.cache.json"
    cache_file.write_text(
        json.dumps({"host.example.com|443|vless": [True, 123.0, 999.0]}),
        encoding="utf-8",
    )

    assert _load_validation_cache(tmp_path) == {}


def test_validation_cache_roundtrip_with_version(tmp_path):
    cache = {
        ("host.example.com", 443, "vless"): (True, 123.0, 999.0),
    }

    _save_validation_cache(tmp_path, cache)

    assert _load_validation_cache(tmp_path) == cache


@pytest.mark.asyncio
async def test_skip_validation_does_not_pollute_cache(tmp_path, monkeypatch):
    cfg = FnsConfig(output=OutputConfig(dir=str(tmp_path)))
    monkeypatch.setattr(
        "fns.pipeline._build_collectors", lambda cfg: [_FakeCollector()]
    )

    result = await run_pipeline(cfg, skip_validation=True)

    assert len(result.nodes) == 1
    assert result.nodes[0].is_alive is True
    assert not (tmp_path / "fns.cache.json").exists()
