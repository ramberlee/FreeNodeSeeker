"""Test output formatters."""

import json
import re

import yaml

from fns.config import ClashOutputConfig
from fns.formatters import clash as clash_module
from fns.formatters.base64_sub import format_base64_sub
from fns.formatters.clash import format_clash
from fns.formatters.json_output import format_json
from fns.models import ProxyNode, ProxyType
from fns.utils.crypto import safe_b64decode


class TestClashOutput:
    def test_generates_valid_yaml(self, sample_vmess_node, sample_ss_node, monkeypatch):
        monkeypatch.setattr(clash_module, "detect_country_code", lambda node: None)
        cfg = ClashOutputConfig()
        output = format_clash([sample_vmess_node, sample_ss_node], cfg)
        data = yaml.safe_load(output)
        assert "proxies" in data
        assert len(data["proxies"]) == 2
        assert "port" not in data
        assert "socks-port" not in data
        assert data["rules"][-1] == "MATCH,\U0001f680 \u8282\u70b9\u9009\u62e9"
        assert "proxy-groups" in data
        groups = {g["name"]: g for g in data["proxy-groups"]}
        auto = groups["\u26a1 \u81ea\u52a8\u6700\u5feb"]
        assert auto["interval"] == 300
        assert auto["url"] == "https://www.youtube.com/generate_204"
        assert auto["proxies"] == ["Test VMess", "Test SS"]
        score = groups["综合打分"]
        assert score["type"] == "select"
        assert score["proxies"] == ["Test VMess", "Test SS"]
        unknown = groups["\U0001f3f3\ufe0f \u672a\u6807\u6ce8"]
        assert unknown["proxies"] == ["Test VMess", "Test SS"]

    def test_country_groups(self, monkeypatch):
        def fake_detect(node):
            m = re.search(r"\[([A-Z]{2}|-)\]", node.remark or "")
            if not m:
                return None
            code = m.group(1)
            return None if code == "-" else code

        monkeypatch.setattr(clash_module, "detect_country_code", fake_detect)
        nodes = []
        for i in range(4):
            nodes.append(
                ProxyNode(
                    node_type=ProxyType.SS,
                    address=f"203.0.113.{i + 1}",
                    port=8388,
                    remark=f"[JP] Tokyo {i}",
                )
            )
        for i in range(2):
            nodes.append(
                ProxyNode(
                    node_type=ProxyType.SS,
                    address=f"203.0.113.{i + 10}",
                    port=8388,
                    remark=f"[US] LA {i}",
                )
            )
        for i in range(2):
            nodes.append(
                ProxyNode(
                    node_type=ProxyType.SS,
                    address=f"203.0.113.{i + 20}",
                    port=8388,
                    remark=f"[-] No name {i}",
                )
            )

        data = yaml.safe_load(format_clash(nodes, ClashOutputConfig()))
        groups = {g["name"]: g for g in data["proxy-groups"]}
        jp = groups["\U0001f1ef\U0001f1f5 日本·4"]
        assert jp["type"] == "url-test"
        assert jp["interval"] == 60
        assert len(jp["proxies"]) == 4
        assert len(groups["\U0001f30d 其他"]["proxies"]) == 2
        assert len(groups["\U0001f3f3\ufe0f 未标注"]["proxies"]) == 2
        master = groups["\U0001f680 \u8282\u70b9\u9009\u62e9"]
        assert "DIRECT" in master["proxies"]
        assert "综合打分" in master["proxies"]
        assert "\U0001f1ef\U0001f1f5 日本·4" in master["proxies"]

    def test_group_interval_threshold(self):
        assert clash_module._group_interval(99) == 60
        assert clash_module._group_interval(100) == 120

    def test_vless_reality_requires_public_key(self, sample_vless_node):
        proxy = clash_module.node_to_clash_proxy(sample_vless_node)
        assert proxy["reality-opts"] == {
            "public-key": "qwerty123",
            "short-id": "abcd",
        }

    def test_vless_without_public_key_omits_reality_opts(self):
        node = ProxyNode(
            node_type=ProxyType.VLESS,
            address="vless.example.com",
            port=443,
            uuid="b831381d-6324-4d53-ad4f-8cda48b30811",
            tls=True,
            sni="vless.example.com",
            fingerprint="chrome",
            flow="xtls-rprx-vision",
        )
        proxy = clash_module.node_to_clash_proxy(node)
        assert "reality-opts" not in proxy

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
