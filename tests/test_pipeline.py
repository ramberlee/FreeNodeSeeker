"""Tests for pipeline parsing helpers."""

import base64
import json

from fns.collectors.base import RawContent
from fns.models import ProxyNode, ProxyType
from fns.pipeline import (
    _split_parse_chunks,
    _write_collected_nodes,
    _write_validation_report,
    load_existing_nodes,
)


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


def test_write_collected_nodes_creates_jsonl_snapshot(tmp_path):
    nodes = {
        "api": [
            ProxyNode(
                node_type=ProxyType.VLESS,
                address="example.com",
                port=443,
                uuid="u",
                source="https://example.com/sub",
                remark="测试节点",
            )
        ]
    }

    _write_collected_nodes(tmp_path, nodes)

    lines = (tmp_path / "fns.collected.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["address"] == "example.com"
    assert record["collector"] == "api"
    assert record["remark"] == "测试节点"
    assert "collected_at" in record


def test_write_validation_report_counts_reasons(tmp_path):
    dead = ProxyNode(
        node_type=ProxyType.VLESS,
        address="dead.example.com",
        port=443,
        uuid="u",
    )
    dead.is_alive = False
    dead.validation_error = "tcp_unreachable"
    alive = ProxyNode(
        node_type=ProxyType.HTTP,
        address="alive.example.com",
        port=8080,
    )
    alive.is_alive = True

    _write_validation_report(
        tmp_path,
        collected_total=2,
        unique_candidates=2,
        validated_nodes=[dead, alive],
        alive_new=1,
        alive_final=1,
        errors=[],
    )

    report = json.loads((tmp_path / "fns.validation_report.json").read_text(encoding="utf-8"))
    assert report["collected_total"] == 2
    assert report["alive_final"] == 1
    assert report["dead_by_reason"] == {"tcp_unreachable": 1}


def test_load_existing_nodes_prefers_state_file(tmp_path):
    state = [
        {
            "node_type": "vless",
            "address": "state.example.com",
            "port": 443,
            "uuid": "u",
            "source": "state",
            "remark": "state",
        }
    ]
    legacy = [
        {
            "node_type": "vless",
            "address": "legacy.example.com",
            "port": 443,
            "uuid": "u",
            "source": "legacy",
            "remark": "legacy",
        }
    ]
    (tmp_path / "fns.state.json").write_text(
        json.dumps(state), encoding="utf-8"
    )
    (tmp_path / "fns.json").write_text(
        json.dumps(legacy), encoding="utf-8"
    )

    nodes = load_existing_nodes(tmp_path)

    assert len(nodes) == 1
    assert nodes[0].address == "state.example.com"
