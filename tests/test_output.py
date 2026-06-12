"""Test output formatters."""

import json

import yaml

from fns.config import ClashOutputConfig
from fns.output.base64_sub import format_base64_sub
from fns.output.clash import format_clash
from fns.output.json_output import format_json
from fns.utils.crypto import safe_b64decode


class TestClashOutput:
    def test_generates_valid_yaml(self, sample_vmess_node, sample_ss_node):
        cfg = ClashOutputConfig()
        output = format_clash([sample_vmess_node, sample_ss_node], cfg)
        data = yaml.safe_load(output)
        assert "proxies" in data
        assert len(data["proxies"]) == 2
        assert data["port"] == 7890
        assert "proxy-groups" in data

    def test_empty_nodes(self):
        cfg = ClashOutputConfig()
        output = format_clash([], cfg)
        data = yaml.safe_load(output)
        assert len(data["proxies"]) == 0


class TestBase64Output:
    def test_encodes_valid_base64(self, sample_vmess_node, sample_ss_node):
        output = format_base64_sub([sample_vmess_node, sample_ss_node])
        decoded = safe_b64decode(output).decode("utf-8")
        assert decoded.startswith("vmess://")
        assert "ss://" in decoded

    def test_empty_nodes(self):
        output = format_base64_sub([])
        assert output == ""


class TestJsonOutput:
    def test_valid_json(self, sample_vmess_node, sample_ss_node):
        output = format_json([sample_vmess_node, sample_ss_node])
        data = json.loads(output)
        assert isinstance(data, list)
        assert len(data) == 2
        assert "node_type" in data[0]
        assert data[0]["address"] == "1.2.3.4"

    def test_empty_nodes(self):
        output = format_json([])
        assert json.loads(output) == []
