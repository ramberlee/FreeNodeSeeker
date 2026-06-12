"""Test all parsers against fixtures."""

from fns.models import ProxyType
from fns.parsers.base64_sub import Base64SubParser
from fns.parsers.clash_yaml import ClashYamlParser
from fns.parsers.detector import detect_format, parse_auto
from fns.parsers.proxy_uri import ProxyUriParser
from fns.parsers.sip008 import Sip008Parser

SAMPLE_MULTI_URI = """vmess://ewogICJ2IjogIjIiLAogICJwcyI6ICJUZXN0LVZNZXNzIiwKICAiYWRkIjogIjEuMi4zLjQiLAogICJwb3J0IjogNDQzLAogICJpZCI6ICJiODMxMzgxZC02MzI0LTRkNTMtYWQ0Zi04Y2RhNDhiMzA4MTEiLAogICJhaWQiOiAiMCIsCiAgInNjeSI6ICJhdXRvIiwKICAibmV0IjogIndzIiwKICAidHlwZSI6ICJub25lIiwKICAiaG9zdCI6ICJleGFtcGxlLmNvbSIsCiAgInBhdGgiOiAiL3BhdGgiLAogICJ0bHMiOiAidGxzIiwKICAic25pIjogImV4YW1wbGUuY29tIiwKICAiYWxwbiI6ICIiLAogICJmcCI6ICIiCn0=
ss://YWVzLTI1Ni1nY206dGVzdDEyMw==@5.6.7.8:8388#Test-SS
trojan://trojan-password@trojan.example.com:443?security=tls&type=tcp&sni=trojan.example.com#Test-Trojan"""


class TestProxyUriParser:
    def test_vmess(self):
        uri = "vmess://ewogICJ2IjogIjIiLAogICJwcyI6ICJUZXN0LVZNZXNzIiwKICAiYWRkIjogIjEuMi4zLjQiLAogICJwb3J0IjogNDQzLAogICJpZCI6ICJiODMxMzgxZC02MzI0LTRkNTMtYWQ0Zi04Y2RhNDhiMzA4MTEiLAogICJhaWQiOiAiMCIsCiAgInNjeSI6ICJhdXRvIiwKICAibmV0IjogIndzIiwKICAidHlwZSI6ICJub25lIiwKICAiaG9zdCI6ICJleGFtcGxlLmNvbSIsCiAgInBhdGgiOiAiL3BhdGgiLAogICJ0bHMiOiAidGxzIiwKICAic25pIjogImV4YW1wbGUuY29tIiwKICAiYWxwbiI6ICIiLAogICJmcCI6ICIiCn0="
        parser = ProxyUriParser()
        result = parser.parse(uri, "test")

        assert len(result.nodes) == 1
        n = result.nodes[0]
        assert n.node_type == ProxyType.VMESS
        assert n.address == "1.2.3.4"
        assert n.port == 443
        assert n.uuid == "b831381d-6324-4d53-ad4f-8cda48b30811"
        assert n.transport == "ws"
        assert n.ws_path == "/path"
        assert n.ws_host == "example.com"
        assert n.tls is True
        assert n.sni == "example.com"
        assert n.remark == "Test-VMess"

    def test_ss(self):
        uri = "ss://YWVzLTI1Ni1nY206dGVzdDEyMw==@5.6.7.8:8388#Test-SS"
        parser = ProxyUriParser()
        result = parser.parse(uri, "test")

        assert len(result.nodes) == 1
        n = result.nodes[0]
        assert n.node_type == ProxyType.SS
        assert n.address == "5.6.7.8"
        assert n.port == 8388
        assert n.password == "test123"
        assert n.method == "aes-256-gcm"
        assert n.remark == "Test-SS"

    def test_trojan(self):
        uri = "trojan://trojan-password@trojan.example.com:443?security=tls&type=tcp&sni=trojan.example.com#Test-Trojan"
        parser = ProxyUriParser()
        result = parser.parse(uri, "test")

        assert len(result.nodes) == 1
        n = result.nodes[0]
        assert n.node_type == ProxyType.TROJAN
        assert n.address == "trojan.example.com"
        assert n.port == 443
        assert n.password == "trojan-password"
        assert n.tls is True
        assert n.sni == "trojan.example.com"

    def test_multi_uri(self):
        parser = ProxyUriParser()
        result = parser.parse(SAMPLE_MULTI_URI, "test")
        assert len(result.nodes) == 3

    def test_can_parse(self):
        assert ProxyUriParser.can_parse(SAMPLE_MULTI_URI) is True
        assert ProxyUriParser.can_parse("not a uri") is False


class TestClashYamlParser:
    def test_parse(self):
        text = """proxies:
  - name: Test
    type: vmess
    server: 1.1.1.1
    port: 443
    uuid: test-uuid
    cipher: auto
    network: ws
"""
        parser = ClashYamlParser()
        result = parser.parse(text, "test")

        assert len(result.nodes) == 1
        n = result.nodes[0]
        assert n.node_type == ProxyType.VMESS
        assert n.address == "1.1.1.1"
        assert n.port == 443
        assert n.uuid == "test-uuid"

    def test_can_parse(self):
        assert ClashYamlParser.can_parse("proxies:\n  - name: x\n    type: ss\n    server: x\n    port: 1\n") is True
        assert ClashYamlParser.can_parse("not yaml proxies:") is False


class TestBase64SubParser:
    def test_can_parse(self):
        assert Base64SubParser.can_parse("dm1lc3M6Ly8=") is True

    def test_can_parse_non_b64(self):
        assert Base64SubParser.can_parse("hello world") is False


class TestSip008Parser:
    def test_can_parse(self):
        json_str = '[{"server": "1.1.1.1", "server_port": 8388, "method": "aes-256-gcm", "password": "pwd"}]'
        assert Sip008Parser.can_parse(json_str) is True

    def test_can_parse_non_sip(self):
        assert Sip008Parser.can_parse('[{"key": "value"}]') is False

    def test_parse(self):
        json_str = '[{"server": "1.1.1.1", "server_port": 8388, "method": "aes-256-gcm", "password": "pwd", "remarks": "Test"}]'
        parser = Sip008Parser()
        result = parser.parse(json_str, "test")

        assert len(result.nodes) == 1
        n = result.nodes[0]
        assert n.node_type == ProxyType.SS
        assert n.address == "1.1.1.1"
        assert n.port == 8388
        assert n.password == "pwd"
        assert n.method == "aes-256-gcm"


class TestDetector:
    def test_detect_proxy_uri(self):
        fmt, pre = detect_format(SAMPLE_MULTI_URI)
        assert fmt == "proxy_uri"

    def test_detect_clash_yaml(self):
        text = "port: 7890\nproxies:\n  - name: x\n    type: ss\n    server: x\n    port: 1\n"
        fmt, pre = detect_format(text)
        assert fmt == "clash_yaml"
        assert pre is not None  # pre-parsed YAML data should be returned

    def test_detect_sip008(self):
        json_str = '[{"server": "1.1.1.1", "server_port": 8388, "method": "aes-256-gcm", "password": "pwd"}]'
        fmt, pre = detect_format(json_str)
        assert fmt == "sip008"

    def test_parse_auto(self):
        result = parse_auto(SAMPLE_MULTI_URI, "test")
        assert len(result.nodes) == 3
