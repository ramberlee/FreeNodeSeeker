"""Test all parsers against fixtures."""

import base64
import json

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

    def test_vmess_with_remark_fragment(self):
        payload = base64.b64encode(
            json.dumps(
                {
                    "v": "2",
                    "ps": "",
                    "add": "1.2.3.4",
                    "port": "443",
                    "id": "b831381d-6324-4d53-ad4f-8cda48b30811",
                    "aid": "0",
                    "scy": "auto",
                    "net": "tcp",
                }
            ).encode()
        ).decode()
        uri = (
            f"vmess://{payload}#Remark"
        )
        parser = ProxyUriParser()
        result = parser.parse(uri, "test")

        assert len(result.nodes) == 1
        n = result.nodes[0]
        assert n.address == "1.2.3.4"
        assert n.port == 443
        assert n.remark == "Remark"

    def test_vless_trailing_slash(self):
        uri = (
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@vless.example.com:443/"
            "?type=ws&security=tls&sni=vless.example.com#Test-VLESS"
        )
        parser = ProxyUriParser()
        result = parser.parse(uri, "test")

        assert len(result.nodes) == 1
        n = result.nodes[0]
        assert n.node_type == ProxyType.VLESS
        assert n.address == "vless.example.com"
        assert n.port == 443
        assert n.transport == "ws"
        assert n.remark == "Test-VLESS"

    def test_hysteria2_trailing_slash(self):
        uri = (
            "hysteria2://hysteria-pass@hysteria.example.com:8443/"
            "?sni=hysteria.example.com&insecure=1#Test-Hysteria2"
        )
        parser = ProxyUriParser()
        result = parser.parse(uri, "test")

        assert len(result.nodes) == 1
        n = result.nodes[0]
        assert n.node_type == ProxyType.HYSTERIA2
        assert n.address == "hysteria.example.com"
        assert n.port == 8443
        assert n.skip_cert_verify is True
        assert n.remark == "Test-Hysteria2"

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

    def test_ss_plugin(self):
        uri = (
            "ss://YWVzLTI1Ni1nY206dGVzdDEyMw==@5.6.7.8:8388/"
            "?plugin=v2ray-plugin%3Btls%3Bmode%3Dwebsocket"
            "%3Bhost%3Dexample.com%3Bpath%3D%2Fws#Test-SS-Plugin"
        )
        parser = ProxyUriParser()
        result = parser.parse(uri, "test")

        assert len(result.nodes) == 1
        n = result.nodes[0]
        assert n.node_type == ProxyType.SS
        assert n.address == "5.6.7.8"
        assert n.port == 8388
        assert n.password == "test123"
        assert n.method == "aes-256-gcm"
        assert n.plugin == "v2ray-plugin"
        assert n.plugin_opts == {
            "tls": True,
            "mode": "websocket",
            "host": "example.com",
            "path": "/ws",
        }
        assert n.remark == "Test-SS-Plugin"

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

    def test_trojan_grpc_insecure(self):
        uri = (
            "trojan://trojan-password@trojan.example.com:443?"
            "security=tls&type=grpc&serviceName=example-service"
            "&allowInsecure=1&sni=trojan.example.com#Test-Trojan-GRPC"
        )
        parser = ProxyUriParser()
        result = parser.parse(uri, "test")

        assert len(result.nodes) == 1
        n = result.nodes[0]
        assert n.node_type == ProxyType.TROJAN
        assert n.transport == "grpc"
        assert n.grpc_service_name == "example-service"
        assert n.tls is True
        assert n.skip_cert_verify is True
        assert n.sni == "trojan.example.com"

    def test_trojan_ws(self):
        uri = (
            "trojan://trojan-password@trojan.example.com:443?"
            "security=tls&type=ws&path=%2Fws&host=ws.example.com#Test-Trojan-WS"
        )
        parser = ProxyUriParser()
        result = parser.parse(uri, "test")

        assert len(result.nodes) == 1
        n = result.nodes[0]
        assert n.node_type == ProxyType.TROJAN
        assert n.transport == "ws"
        assert n.ws_path == "/ws"
        assert n.ws_host == "ws.example.com"
        assert n.tls is True

    def test_tuic_insecure(self):
        uri = (
            "tuic://b831381d-6324-4d53-ad4f-8cda48b30811:tuic-pass@"
            "tuic.example.com:443?sni=tuic.example.com&insecure=1"
            "&congestion_control=bbr#Test-TUIC-Insecure"
        )
        parser = ProxyUriParser()
        result = parser.parse(uri, "test")

        assert len(result.nodes) == 1
        n = result.nodes[0]
        assert n.node_type == ProxyType.TUIC
        assert n.uuid == "b831381d-6324-4d53-ad4f-8cda48b30811"
        assert n.password == "tuic-pass"
        assert n.tls is False
        assert n.skip_cert_verify is True
        assert n.sni == "tuic.example.com"
        assert n.congestion_control == "bbr"

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

    def test_parse_extra_fields(self):
        text = """proxies:
  - name: SS Plugin
    type: ss
    server: 1.1.1.1
    port: 8388
    cipher: aes-256-gcm
    password: pwd
    plugin: v2ray-plugin
    plugin-opts:
      mode: websocket
      tls: true
      host: example.com
      path: /ws
  - name: HTTP Auth
    type: http
    server: 2.2.2.2
    port: 8080
    username: user
    password: pass
  - name: Trojan GRPC
    type: trojan
    server: 3.3.3.3
    port: 443
    password: pw
    network: grpc
    grpc-opts:
      grpc-service-name: svc
    skip-cert-verify: true
"""
        parser = ClashYamlParser()
        result = parser.parse(text, "test")

        assert len(result.nodes) == 3
        ss = result.nodes[0]
        assert ss.plugin == "v2ray-plugin"
        assert ss.plugin_opts == {
            "mode": "websocket",
            "tls": True,
            "host": "example.com",
            "path": "/ws",
        }
        http = result.nodes[1]
        assert http.username == "user"
        assert http.password == "pass"
        trojan = result.nodes[2]
        assert trojan.transport == "grpc"
        assert trojan.grpc_service_name == "svc"
        assert trojan.skip_cert_verify is True

    def test_can_parse(self):
        assert ClashYamlParser.can_parse(
            "proxies:\n  - name: x\n    type: ss\n    server: x\n    port: 1\n"
        ) is True
        assert ClashYamlParser.can_parse("not yaml proxies:") is False


class TestBase64SubParser:
    def test_can_parse(self):
        assert Base64SubParser.can_parse("dm1lc3M6Ly8=") is True

    def test_can_parse_non_b64(self):
        assert Base64SubParser.can_parse("hello world") is False

    def test_parse_clash_yaml_in_base64(self):
        yaml_text = (
            "proxies:\n"
            "  - name: Test\n"
            "    type: ss\n"
            "    server: 1.1.1.1\n"
            "    port: 8388\n"
            "    cipher: aes-256-gcm\n"
            "    password: pwd\n"
        )
        payload = base64.b64encode(yaml_text.encode()).decode()
        result = Base64SubParser().parse(payload, "test")
        assert len(result.nodes) == 1
        assert result.nodes[0].node_type == ProxyType.SS


class TestSip008Parser:
    def test_can_parse(self):
        json_str = (
            '[{"server": "1.1.1.1", "server_port": 8388, '
            '"method": "aes-256-gcm", "password": "pwd"}]'
        )
        assert Sip008Parser.can_parse(json_str) is True

    def test_can_parse_non_sip(self):
        assert Sip008Parser.can_parse('[{"key": "value"}]') is False

    def test_parse(self):
        json_str = (
            '[{"server": "1.1.1.1", "server_port": 8388, '
            '"method": "aes-256-gcm", "password": "pwd", "remarks": "Test"}]'
        )
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
        json_str = (
            '[{"server": "1.1.1.1", "server_port": 8388, '
            '"method": "aes-256-gcm", "password": "pwd"}]'
        )
        fmt, pre = detect_format(json_str)
        assert fmt == "sip008"

    def test_parse_auto(self):
        result = parse_auto(SAMPLE_MULTI_URI, "test")
        assert len(result.nodes) == 3

    def test_detect_base64_reuses_decoded_text(self):
        payload = base64.b64encode(SAMPLE_MULTI_URI.encode()).decode()
        fmt, pre = detect_format(payload)
        assert fmt == "base64_sub"
        assert pre == SAMPLE_MULTI_URI
        assert len(parse_auto(payload, "test").nodes) == 3
