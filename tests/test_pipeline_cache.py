"""Tests for validation cache versioning."""

import json

from fns.pipeline import _load_validation_cache, _save_validation_cache


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
