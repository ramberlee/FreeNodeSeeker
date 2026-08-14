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

    def test_vmess_raw_json(self):
        payload = json.dumps(
            {
                "v": "2",
                "ps": "Raw-JSON",
                "add": "1.2.3.4",
                "port": "443",
                "id": "b831381d-6324-4d53-ad4f-8cda48b30811",
                "aid": "0",
                "scy": "auto",
                "net": "ws",
                "host": "example.com",
                "path": "/ws",
                "tls": "tls",
            }
        )
        uri = f"vmess://{payload}"
        parser = ProxyUriParser()
        result = parser.parse(uri, "test")

        assert len(result.nodes) == 1
        n = result.nodes[0]
        assert n.node_type == ProxyType.VMESS
        assert n.address == "1.2.3.4"
        assert n.port == 443
        assert n.transport == "ws"
        assert n.ws_path == "/ws"

    def test_vmess_raw_json_compact(self):
        # Some subscriptions emit vmess://{json} without base64 and without
        # spaces; safe_b64decode raises on these payloads, so the raw JSON
        # fallback must be reached.
        uri = (
            'vmess://{"v":"2","ps":"Compact","add":"67.220.95.3",'
            '"port":"18000","id":"f8c8dc3d-0d37-4"}'
        )
        parser = ProxyUriParser()
        result = parser.parse(uri, "test")

        assert len(result.nodes) == 1
        n = result.nodes[0]
        assert n.node_type == ProxyType.VMESS
        assert n.address == "67.220.95.3"
        assert n.port == 18000
        assert n.remark == "Compact"

    def test_vmess_json_boolean_tls_and_sni_fallback(self):
        payload = base64.b64encode(
            json.dumps(
                {
                    "v": "2",
                    "ps": "TLS-Bool",
                    "add": "1.2.3.4",
                    "port": "443",
                    "id": "b831381d-6324-4d53-ad4f-8cda48b30811",
                    "scy": "auto",
                    "net": "ws",
                    "host": "cdn.example.com",
                    "path": "/ws",
                    "tls": True,
                }
            ).encode()
        ).decode()
        parser = ProxyUriParser()
        result = parser.parse(f"vmess://{payload}", "test")

        assert len(result.nodes) == 1
        n = result.nodes[0]
        assert n.node_type == ProxyType.VMESS
        assert n.tls is True
        assert n.sni == "cdn.example.com"

    def test_vmess_raw_transport_normalized_to_tcp(self):
        payload = base64.b64encode(
            json.dumps(
                {
                    "v": "2",
                    "ps": "Raw",
                    "add": "1.2.3.4",
                    "port": "443",
                    "id": "b831381d-6324-4d53-ad4f-8cda48b30811",
                    "net": "raw",
                }
            ).encode()
        ).decode()
        parser = ProxyUriParser()
        result = parser.parse(f"vmess://{payload}", "test")

        assert len(result.nodes) == 1
        assert result.nodes[0].transport == "tcp"

    def test_vmess_mislabeled_vless(self):
        uri = (
            "vmess://b831381d-6324-4d53-ad4f-8cda48b30811@vless.example.com:443/"
            "?type=ws&amp;security=tls&amp;sni=vless.example.com#Mislabeled"
        )
        parser = ProxyUriParser()
        result = parser.parse(uri, "test")

        assert len(result.nodes) == 1
        n = result.nodes[0]
        assert n.node_type == ProxyType.VLESS
        assert n.address == "vless.example.com"
        assert n.port == 443
        assert n.transport == "ws"
        assert n.sni == "vless.example.com"
        assert n.remark == "Mislabeled"

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

    def test_vless_sni_implies_tls(self):
        uri = (
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443"
            "?type=ws&sni=cdn.example.com&host=cdn.example.com&path=/ws"
        )
        parser = ProxyUriParser()
        result = parser.parse(uri, "test")

        assert len(result.nodes) == 1
        n = result.nodes[0]
        assert n.node_type == ProxyType.VLESS
        assert n.tls is True
        assert n.sni == "cdn.example.com"

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

    def test_ss_legacy_with_fragment(self):
        payload = base64.b64encode(
            b"aes-256-gcm:test123@5.6.7.8:8388"
        ).decode()
        uri = f"ss://{payload}#Legacy-Remark"
        parser = ProxyUriParser()
        result = parser.parse(uri, "test")

        assert len(result.nodes) == 1
        n = result.nodes[0]
        assert n.address == "5.6.7.8"
        assert n.port == 8388
        assert n.method == "aes-256-gcm"
        assert n.remark == "Legacy-Remark"

    def test_ss_plaintext_userinfo(self):
        uri = "ss://aes-128-gcm%3A6601fb90e9b3@192.0.2.1:1#Plain"
        parser = ProxyUriParser()
        result = parser.parse(uri, "test")

        assert len(result.nodes) == 1
        n = result.nodes[0]
        assert n.node_type == ProxyType.SS
        assert n.address == "192.0.2.1"
        assert n.port == 1
        assert n.method == "aes-128-gcm"
        assert n.password == "6601fb90e9b3"

    def test_ss_plaintext_userinfo_without_method(self):
        uri = "ss://InternetAzadRobot@151.101.1.57:80?mode=auto"
        parser = ProxyUriParser()
        result = parser.parse(uri, "test")

        assert len(result.nodes) == 1
        n = result.nodes[0]
        assert n.node_type == ProxyType.SS
        assert n.method == "aes-256-gcm"
        assert n.password == "InternetAzadRobot"

    def test_ss_uuid_userinfo_not_mangled(self):
        # UUID-like userinfo is not valid base64 for method:password and must
        # be kept verbatim instead of being decoded into garbage bytes.
        uuid = "04c808e2-0b59-47b0-a54b-32fc7ef1c902"
        uri = (
            f"ss://{uuid}@japan.com:443?sni=example.com"
            "&type=ws&host=example.com&path=/"
        )
        parser = ProxyUriParser()
        result = parser.parse(uri, "test")

        assert len(result.nodes) == 1
        n = result.nodes[0]
        assert n.node_type == ProxyType.SS
        assert n.address == "japan.com"
        assert n.port == 443
        assert n.password == uuid

    def test_ss_vmess_json_userinfo(self):
        payload = base64.b64encode(
            json.dumps(
                {
                    "v": "2",
                    "ps": "JSON-in-SS",
                    "add": "1.2.3.4",
                    "port": "443",
                    "id": "b831381d-6324-4d53-ad4f-8cda48b30811",
                    "net": "ws",
                    "host": "example.com",
                    "path": "/ws",
                }
            ).encode()
        ).decode()
        parser = ProxyUriParser()
        result = parser.parse(f"ss://{payload}@1.2.3.4:443#X", "test")

        assert len(result.nodes) == 1
        n = result.nodes[0]
        assert n.node_type == ProxyType.VMESS
        assert n.address == "1.2.3.4"
        assert n.port == 443
        assert n.transport == "ws"
        assert n.ws_path == "/ws"
        assert n.remark == "JSON-in-SS"

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

    def test_trojan_password_with_hash(self):
        uri = (
            "trojan://8r<[9'l6hAO#8ZQi@104.16.7.70:443"
            "?path=/tr&security=tls&insecure=1&host="
        )
        parser = ProxyUriParser()
        result = parser.parse(uri, "test")

        assert len(result.nodes) == 1
        n = result.nodes[0]
        assert n.node_type == ProxyType.TROJAN
        assert n.address == "104.16.7.70"
        assert n.port == 443
        assert n.password == "8r<[9'l6hAO#8ZQi"
        assert n.tls is True

    def test_ipv6_bracketed_addresses(self):
        parser = ProxyUriParser()
        cases = [
            (
                "vless://b831381d-6324-4d53-ad4f-8cda48b30811@[2001:db8::1]:443#R",
                ProxyType.VLESS,
                443,
            ),
            ("ss://YWVzLTI1Ni1nY206dGVzdDEyMw==@[2001:db8::2]:8388#R", ProxyType.SS, 8388),
            ("trojan://pw@[2001:db8::3]:443#R", ProxyType.TROJAN, 443),
            ("hysteria2://pass@[2001:db8::4]:8443?sni=x#R", ProxyType.HYSTERIA2, 8443),
            ("tuic://uuid:pass@[2001:db8::5]:443?sni=x#R", ProxyType.TUIC, 443),
        ]
        for uri, expected_type, expected_port in cases:
            result = parser.parse(uri, "test")
            assert len(result.nodes) == 1, uri
            n = result.nodes[0]
            assert n.node_type == expected_type
            assert n.address.startswith("2001:db8::")
            assert "[" not in n.address
            assert n.port == expected_port

    def test_hysteria_v1_uri(self):
        uri = (
            "hysteria://1.2.3.4:443?auth=pass&upmbps=50&downmbps=150"
            "&obfs=salamander&obfsparam=x&sni=example.com&insecure=1#H1"
        )
        parser = ProxyUriParser()
        result = parser.parse(uri, "test")

        assert len(result.nodes) == 1
        n = result.nodes[0]
        assert n.node_type == ProxyType.HYSTERIA
        assert n.password == "pass"
        assert n.up_speed == 50
        assert n.down_speed == 150
        assert n.obfs == "salamander"
        assert n.obfs_password == "x"
        assert n.sni == "example.com"
        assert n.skip_cert_verify is True

    def test_ssr_uri(self):
        payload = base64.b64encode(
            b"aes-256-cfb:pwd@2.2.2.2:8388/?protocol=auth_sha1_v4"
            b"&protoparam=a:b&obfs=http_simple&obfsparam=c&remarks=SSR1"
        ).decode()
        parser = ProxyUriParser()
        result = parser.parse(f"ssr://{payload}", "test")

        assert len(result.nodes) == 1
        n = result.nodes[0]
        assert n.node_type == ProxyType.SSR
        assert n.method == "aes-256-cfb"
        assert n.password == "pwd"
        assert n.protocol == "auth_sha1_v4"
        assert n.protocol_param == "a:b"
        assert n.obfs == "http_simple"
        assert n.obfs_param == "c"
        assert n.remark == "SSR1"

    def test_anytls_uri(self):
        uri = "anytls://pw@3.3.3.3:443?sni=example.com&fp=chrome#AT"
        parser = ProxyUriParser()
        result = parser.parse(uri, "test")

        assert len(result.nodes) == 1
        n = result.nodes[0]
        assert n.node_type == ProxyType.ANYTLS
        assert n.password == "pw"
        assert n.sni == "example.com"
        assert n.fingerprint == "chrome"
        assert n.tls is True

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

    def test_http_proxy_line(self):
        parser = ProxyUriParser()
        result = parser.parse("http://user:pass@1.2.3.4:8080", "test")

        assert len(result.nodes) == 1
        n = result.nodes[0]
        assert n.node_type == ProxyType.HTTP
        assert n.address == "1.2.3.4"
        assert n.port == 8080
        assert n.username == "user"
        assert n.password == "pass"

    def test_socks5_proxy_line(self):
        parser = ProxyUriParser()
        result = parser.parse("socks5://5.6.7.8:1080", "test")

        assert len(result.nodes) == 1
        n = result.nodes[0]
        assert n.node_type == ProxyType.SOCKS5
        assert n.address == "5.6.7.8"
        assert n.port == 1080

    def test_http_link_with_path_rejected(self):
        parser = ProxyUriParser()
        result = parser.parse("http://example.com/path?q=1", "test")

        assert len(result.nodes) == 0
        assert result.errors == []


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

    def test_trojan_defaults_to_tls(self):
        text = """proxies:
  - name: Trojan No TLS Key
    type: trojan
    server: 1.1.1.1
    port: 443
    password: pw
    sni: example.com
  - name: Hysteria2 No TLS Key
    type: hysteria2
    server: 2.2.2.2
    port: 443
    password: pw
"""
        parser = ClashYamlParser()
        result = parser.parse(text, "test")

        assert len(result.nodes) == 2
        trojan = result.nodes[0]
        assert trojan.node_type == ProxyType.TROJAN
        assert trojan.tls is True
        hy2 = result.nodes[1]
        assert hy2.node_type == ProxyType.HYSTERIA2
        assert hy2.tls is True

    def test_trojan_explicit_tls_false_is_respected(self):
        text = """proxies:
  - name: Trojan No TLS
    type: trojan
    server: 1.1.1.1
    port: 443
    password: pw
    tls: false
"""
        parser = ClashYamlParser()
        result = parser.parse(text, "test")

        assert len(result.nodes) == 1
        assert result.nodes[0].tls is False

    def test_parse_extra_protocol_types(self):
        text = """proxies:
  - name: H
    type: hysteria
    server: 1.2.3.4
    port: 443
    auth-str: pass
    up: 50
    down: 150
  - name: R
    type: ssr
    server: 2.2.2.2
    port: 8388
    cipher: aes-256-cfb
    password: pwd
    protocol: auth_sha1_v4
    protocol-param: a
    obfs: http_simple
    obfs-param: b
  - name: A
    type: anytls
    server: 3.3.3.3
    port: 443
    password: pw
    sni: example.com
  - name: M
    type: mieru
    server: 4.4.4.4
    port: 443
    username: user
    password: pass
    transport: TCP
"""
        parser = ClashYamlParser()
        result = parser.parse(text, "test")

        assert len(result.nodes) == 4
        h, r, a, m = result.nodes
        assert h.node_type == ProxyType.HYSTERIA
        assert h.password == "pass"
        assert h.tls is True
        assert r.node_type == ProxyType.SSR
        assert r.protocol == "auth_sha1_v4"
        assert r.obfs_param == "b"
        assert a.node_type == ProxyType.ANYTLS
        assert a.tls is True
        assert m.node_type == ProxyType.MIERU
        assert m.username == "user"
        assert m.mieru_transport == "TCP"


class TestSingBoxParser:
    def test_parse_vless_ws(self):
        text = json.dumps(
            {
                "outbounds": [
                    {
                        "type": "vless",
                        "tag": "Test-VLESS",
                        "server": "1.2.3.4",
                        "server_port": 443,
                        "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
                        "tls": {
                            "enabled": True,
                            "server_name": "example.com",
                        },
                        "transport": {
                            "type": "ws",
                            "path": "/ws",
                            "headers": {"Host": "ws.example.com"},
                        },
                    }
                ]
            }
        )
        result = parse_auto(text, "test")

        assert len(result.nodes) == 1
        n = result.nodes[0]
        assert n.node_type == ProxyType.VLESS
        assert n.address == "1.2.3.4"
        assert n.port == 443
        assert n.transport == "ws"
        assert n.ws_path == "/ws"
        assert n.ws_host == "ws.example.com"
        assert n.tls is True
        assert n.sni == "example.com"
        assert n.remark == "Test-VLESS"

    def test_parse_trojan_grpc(self):
        text = json.dumps(
            {
                "outbounds": [
                    {
                        "type": "trojan",
                        "tag": "Test-Trojan",
                        "server": "trojan.example.com",
                        "server_port": 443,
                        "password": "pw",
                        "tls": {"enabled": True, "insecure": True},
                        "transport": {
                            "type": "grpc",
                            "service_name": "example-service",
                        },
                    }
                ]
            }
        )
        result = parse_auto(text, "test")

        assert len(result.nodes) == 1
        n = result.nodes[0]
        assert n.node_type == ProxyType.TROJAN
        assert n.transport == "grpc"
        assert n.grpc_service_name == "example-service"
        assert n.skip_cert_verify is True

    def test_parse_trojan_tls_block_without_enabled(self):
        text = json.dumps(
            {
                "outbounds": [
                    {
                        "type": "trojan",
                        "tag": "Test-Trojan",
                        "server": "1.2.3.4",
                        "server_port": 443,
                        "password": "pw",
                        "tls": {"insecure": True},
                    }
                ]
            }
        )
        result = parse_auto(text, "test")

        assert len(result.nodes) == 1
        n = result.nodes[0]
        assert n.node_type == ProxyType.TROJAN
        assert n.tls is True
        assert n.skip_cert_verify is True

    def test_parse_ssr_and_mieru(self):
        text = json.dumps(
            {
                "outbounds": [
                    {
                        "type": "shadowsocksr",
                        "tag": "R",
                        "server": "1.2.3.4",
                        "server_port": 8388,
                        "method": "aes-256-cfb",
                        "password": "pwd",
                        "protocol": "auth_sha1_v4",
                        "protocol_param": "a",
                        "obfs": "http_simple",
                        "obfs_param": "b",
                    },
                    {
                        "type": "mieru",
                        "tag": "M",
                        "server": "4.4.4.4",
                        "server_port": 443,
                        "username": "user",
                        "password": "pass",
                        "transport": "tcp",
                    },
                ]
            }
        )
        result = parse_auto(text, "test")

        assert len(result.nodes) == 2
        r, m = result.nodes
        assert r.node_type == ProxyType.SSR
        assert r.protocol == "auth_sha1_v4"
        assert r.obfs_param == "b"
        assert m.node_type == ProxyType.MIERU
        assert m.username == "user"
        assert m.mieru_transport == "tcp"


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

    def test_detect_mixed_proxy_list_with_tg_prefix(self):
        text = (
            "tg://proxy?server=1.2.3.4&port=443&secret=abc\n"
            "trojan://pw@1.2.3.4:443#TR\n"
            "ss://YWVzLTI1Ni1nY206dGVzdDEyMw==@5.6.7.8:8388#SS\n"
            "http://user:pass@9.9.9.9:8080\n"
        )
        fmt, pre = detect_format(text)
        assert fmt == "proxy_uri"

        result = parse_auto(text, "test")
        assert len(result.nodes) == 3
        assert {n.node_type for n in result.nodes} == {
            ProxyType.TROJAN,
            ProxyType.SS,
            ProxyType.HTTP,
        }

    def test_parse_base64_plain_proxy_list(self):
        text = "http://1.2.3.4:8080\nsocks5://5.6.7.8:1080\n"
        payload = base64.b64encode(text.encode()).decode()
        fmt, pre = detect_format(payload)
        assert fmt == "base64_sub"

        result = parse_auto(payload, "test")
        assert len(result.nodes) == 2
        assert result.nodes[0].node_type == ProxyType.HTTP
        assert result.nodes[1].node_type == ProxyType.SOCKS5
