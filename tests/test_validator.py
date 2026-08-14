"""Test multi-protocol validator."""

import asyncio
import base64
import json

import aiohttp
import pytest

from fns.config import ValidatorConfig
from fns.models import ProxyNode, ProxyType
from fns.validators.tcp_validator import (
    TcpValidator,
    _build_mihomo_config,
    _is_success_status,
    _validate_via_mihomo,
    _write_mihomo_config,
)


class TestTcpValidator:
    """Negative tests — verify unreachable nodes are correctly marked dead."""

    @pytest.mark.asyncio
    async def test_unreachable_http(self):
        cfg = ValidatorConfig(
            concurrency=1, timeout=2.0, retries=0, test_url="http://www.google.com/"
        )
        validator = TcpValidator(cfg)
        node = ProxyNode(node_type=ProxyType.HTTP, address="192.0.2.1", port=9999)
        result = await validator.validate_one(node)
        assert result.is_alive is False
        assert result.latency_ms is None

    @pytest.mark.asyncio
    async def test_unreachable_socks5(self):
        cfg = ValidatorConfig(
            concurrency=1, timeout=2.0, retries=0, test_url="http://www.google.com/"
        )
        validator = TcpValidator(cfg)
        node = ProxyNode(node_type=ProxyType.SOCKS5, address="192.0.2.2", port=9999)
        result = await validator.validate_one(node)
        assert result.is_alive is False

    @pytest.mark.asyncio
    async def test_unreachable_trojan(self, monkeypatch):
        cfg = ValidatorConfig(
            concurrency=1, timeout=2.0, retries=0, test_url="http://www.google.com/"
        )
        validator = TcpValidator(cfg)
        monkeypatch.setattr(
            "fns.validators.tcp_validator._find_mihomo", lambda: None
        )
        node = ProxyNode(
            node_type=ProxyType.TROJAN,
            address="192.0.2.3",
            port=9999,
            password="test",
        )
        result = await validator.validate_one(node)
        assert result.is_alive is False

    @pytest.mark.asyncio
    async def test_unreachable_ss(self, monkeypatch):
        cfg = ValidatorConfig(
            concurrency=1, timeout=2.0, retries=0, test_url="http://www.google.com/"
        )
        validator = TcpValidator(cfg)
        monkeypatch.setattr(
            "fns.validators.tcp_validator._find_mihomo", lambda: None
        )
        node = ProxyNode(
            node_type=ProxyType.SS,
            address="192.0.2.4",
            port=9999,
            method="aes-256-gcm",
            password="test",
        )
        result = await validator.validate_one(node)
        assert result.is_alive is False

    @pytest.mark.asyncio
    async def test_unreachable_vmess_without_mihomo(self, monkeypatch):
        """VMess without mihomo should be marked dead, not TCP-only alive."""
        cfg = ValidatorConfig(
            concurrency=1, timeout=2.0, retries=0, test_url="http://www.google.com/"
        )
        validator = TcpValidator(cfg)
        monkeypatch.setattr(
            "fns.validators.tcp_validator._find_mihomo", lambda: None
        )
        node = ProxyNode(
            node_type=ProxyType.VMESS,
            address="192.0.2.5",
            port=9999,
            uuid="b831381d-6324-4d53-ad4f-8cda48b30811",
        )
        result = await validator.validate_one(node)
        assert result.is_alive is False

    @pytest.mark.asyncio
    @pytest.mark.parametrize("node_type", [ProxyType.SS, ProxyType.TROJAN, ProxyType.TUIC])
    async def test_dispatch_to_mihomo_when_available(self, monkeypatch, node_type):
        cfg = ValidatorConfig(
            concurrency=1, timeout=2.0, retries=0, test_url="http://www.google.com/"
        )
        validator = TcpValidator(cfg)
        seen = []

        async def fake_mihomo(node):
            seen.append(node)
            node.is_alive = True
            node.latency_ms = 12.3
            return node

        monkeypatch.setattr(
            "fns.validators.tcp_validator._find_mihomo", lambda: "mihomo.exe"
        )
        monkeypatch.setattr(validator, "_try_mihomo", fake_mihomo)

        node = ProxyNode(
            node_type=node_type,
            address="192.0.2.7",
            port=443,
            password="secret",
        )
        result = await validator.validate_one(node)
        assert seen == [node]
        assert result.is_alive is True

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("node_type", "handler_name"),
        [(ProxyType.SS, "_try_ss"), (ProxyType.TROJAN, "_try_trojan")],
    )
    async def test_pproxy_fallback_without_mihomo(self, monkeypatch, node_type, handler_name):
        cfg = ValidatorConfig(
            concurrency=1, timeout=2.0, retries=0, test_url="http://www.google.com/"
        )
        validator = TcpValidator(cfg)
        seen = []

        async def fake_handler(node):
            seen.append(node)
            node.is_alive = False
            return node

        async def fail_mihomo(node):
            raise AssertionError("mihomo must not be used when unavailable")

        monkeypatch.setattr(
            "fns.validators.tcp_validator._find_mihomo", lambda: None
        )
        monkeypatch.setattr(validator, handler_name, fake_handler)
        monkeypatch.setattr(validator, "_try_mihomo", fail_mihomo)

        node = ProxyNode(
            node_type=node_type,
            address="192.0.2.8",
            port=9999,
            password="secret",
        )
        result = await validator.validate_one(node)
        assert seen == [node]
        assert result.is_alive is False

    @pytest.mark.asyncio
    async def test_mihomo_keeps_detailed_failure_reason(self, monkeypatch):
        cfg = ValidatorConfig(
            concurrency=1, timeout=2.0, retries=0, test_url="http://www.google.com/"
        )
        validator = TcpValidator(cfg)

        async def fake_validate(node, test_url, timeout, session=None):
            node.validation_error = "proxy_status_403"
            return False, None

        monkeypatch.setattr(
            "fns.validators.tcp_validator._find_mihomo", lambda: "mihomo.exe"
        )
        monkeypatch.setattr(
            "fns.validators.tcp_validator._validate_via_mihomo", fake_validate
        )

        node = ProxyNode(
            node_type=ProxyType.VLESS,
            address="192.0.2.7",
            port=443,
            uuid="b831381d-6324-4d53-ad4f-8cda48b30811",
        )
        result = await validator.validate_one(node)

        assert result.is_alive is False
        assert result.validation_error == "proxy_status_403"

    @pytest.mark.asyncio
    async def test_http_proxy_auth_handling(self, monkeypatch):
        cfg = ValidatorConfig(
            concurrency=1, timeout=2.0, retries=0, test_url="http://www.google.com/"
        )
        validator = TcpValidator(cfg)
        calls = []

        class FakeResponse:
            status = 200

            async def read(self):
                return b""

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

        class FakeSession:
            def get(self, *args, **kwargs):
                calls.append((args, kwargs))
                return FakeResponse()

        async def fake_get_session():
            return FakeSession()

        monkeypatch.setattr(validator, "_get_session", fake_get_session)

        node = ProxyNode(node_type=ProxyType.HTTP, address="127.0.0.1", port=8080)
        node.username = "alice"
        node.password = "secret"
        result = await validator.validate_one(node)
        assert result.is_alive is True
        kwargs = calls[0][1]
        assert kwargs["proxy"] == "http://127.0.0.1:8080"
        assert isinstance(kwargs["proxy_auth"], aiohttp.BasicAuth)
        assert kwargs["proxy_auth"].login == "alice"
        assert kwargs["proxy_auth"].password == "secret"

        no_auth_node = ProxyNode(
            node_type=ProxyType.HTTP, address="127.0.0.1", port=8081
        )
        result = await validator.validate_one(no_auth_node)
        assert result.is_alive is True
        assert calls[1][1]["proxy_auth"] is None

    def test_build_mihomo_config(self, sample_vmess_node):
        config = _build_mihomo_config(sample_vmess_node, 12345)
        assert config["port"] == 12345
        assert config["mode"] == "rule"
        assert len(config["proxies"]) == 1
        assert config["proxies"][0]["type"] == "vmess"
        assert config["proxies"][0]["server"] == "1.2.3.4"
        assert config["proxy-groups"][0]["proxies"] == [config["proxies"][0]["name"]]
        assert config["rules"] == ["MATCH,TEST"]

    def test_is_success_status_accepts_only_2xx(self):
        assert _is_success_status(200) is True
        assert _is_success_status(204) is True
        assert _is_success_status(302) is False
        assert _is_success_status(404) is False

    def test_write_mihomo_config_preserves_unicode_names(self, tmp_path, sample_vless_node):
        sample_vless_node.remark = "🟠🟢 测试节点"
        config = _build_mihomo_config(sample_vless_node, 12345)
        config_path = tmp_path / "config.json"

        _write_mihomo_config(config, str(config_path))

        raw = config_path.read_text(encoding="utf-8")
        assert "🟠🟢 测试节点" in raw
        assert "\\u" not in raw
        assert json.loads(raw)["proxies"][0]["name"] == sample_vless_node.remark

    def test_build_mihomo_config_vmess_grpc(self):
        node = ProxyNode(
            node_type=ProxyType.VMESS,
            address="1.2.3.4",
            port=443,
            uuid="b831381d-6324-4d53-ad4f-8cda48b30811",
            transport="grpc",
            grpc_service_name="my-service",
        )
        config = _build_mihomo_config(node, 12345)
        assert config["proxies"][0]["network"] == "grpc"
        assert config["proxies"][0]["grpc-opts"] == {
            "grpc-service-name": "my-service"
        }

    @pytest.mark.asyncio
    async def test_non_2xx_http_clears_stale_alive_state(self, monkeypatch):
        cfg = ValidatorConfig(
            concurrency=1,
            timeout=2.0,
            retries=0,
            test_url="https://www.gstatic.com/generate_204",
        )
        validator = TcpValidator(cfg)

        class FakeResponse:
            status = 403

            async def read(self):
                return b""

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

        class FakeSession:
            def get(self, *args, **kwargs):
                return FakeResponse()

        async def fake_get_session():
            return FakeSession()

        monkeypatch.setattr(validator, "_get_session", fake_get_session)

        node = ProxyNode(node_type=ProxyType.HTTP, address="127.0.0.1", port=8080)
        node.is_alive = True
        node.latency_ms = 55.0
        result = await validator.validate_one(node)
        assert result.is_alive is False
        assert result.latency_ms is None
        assert result.validation_error == "http_status_403"

    @pytest.mark.asyncio
    async def test_socks5_uses_username_field(self, monkeypatch):
        cfg = ValidatorConfig(
            concurrency=1,
            timeout=2.0,
            retries=0,
            test_url="https://www.gstatic.com/generate_204",
        )
        validator = TcpValidator(cfg)
        captured = {}

        class FakeConnector:
            def __init__(self, **kwargs):
                captured.update(kwargs)

        class FakeResponse:
            status = 200

            async def read(self):
                return b""

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

        class FakeSession:
            def __init__(self, *args, **kwargs):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            def get(self, *args, **kwargs):
                return FakeResponse()

        monkeypatch.setattr("aiohttp_socks.ProxyConnector", FakeConnector)
        monkeypatch.setattr("aiohttp.ClientSession", FakeSession)

        node = ProxyNode(
            node_type=ProxyType.SOCKS5,
            address="127.0.0.1",
            port=1080,
            username="alice",
            password="secret",
        )
        result = await validator.validate_one(node)
        assert result.is_alive is True
        assert captured["username"] == "alice"
        assert captured["password"] == "secret"

    @pytest.mark.asyncio
    async def test_non_2xx_socks5_clears_stale_alive_state(self, monkeypatch):
        cfg = ValidatorConfig(
            concurrency=1,
            timeout=2.0,
            retries=0,
            test_url="https://www.gstatic.com/generate_204",
        )
        validator = TcpValidator(cfg)

        class FakeResponse:
            status = 407

            async def read(self):
                return b""

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

        class FakeSession:
            def __init__(self, *args, **kwargs):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            def get(self, *args, **kwargs):
                return FakeResponse()

        monkeypatch.setattr("aiohttp_socks.ProxyConnector", lambda **kwargs: None)
        monkeypatch.setattr("aiohttp.ClientSession", FakeSession)

        node = ProxyNode(
            node_type=ProxyType.SOCKS5,
            address="127.0.0.1",
            port=1080,
            username="alice",
            password="secret",
        )
        node.is_alive = True
        node.latency_ms = 55.0
        result = await validator.validate_one(node)
        assert result.is_alive is False
        assert result.latency_ms is None
        assert result.validation_error == "socks5_status_407"

    @pytest.mark.asyncio
    async def test_unexpected_validation_error_marks_node_dead(self, monkeypatch):
        cfg = ValidatorConfig(
            concurrency=1,
            timeout=2.0,
            retries=0,
            test_url="https://www.gstatic.com/generate_204",
        )
        validator = TcpValidator(cfg)

        async def boom(node):
            raise RuntimeError("boom")

        monkeypatch.setattr(validator, "_validate_node", boom)

        node = ProxyNode(node_type=ProxyType.HTTP, address="192.0.2.1", port=9999)
        result = await validator.validate_one(node)
        assert result.is_alive is False
        assert result.latency_ms is None
        assert "boom" in result.validation_error

    @pytest.mark.asyncio
    async def test_ss_uri_uses_standard_base64(self, monkeypatch):
        cfg = ValidatorConfig(
            concurrency=1,
            timeout=2.0,
            retries=0,
            test_url="https://www.gstatic.com/generate_204",
        )
        validator = TcpValidator(cfg)
        seen = []

        class FakeWriter:
            def close(self):
                pass

            async def wait_closed(self):
                pass

        class FakeConnection:
            def __init__(self, uri):
                seen.append(uri)

            async def tcp_connect(self, host, port):
                return None, FakeWriter()

        async def ok_http(reader, writer, test_url, timeout):
            return True

        monkeypatch.setattr("pproxy.Connection", FakeConnection)
        monkeypatch.setattr(
            "fns.validators.tcp_validator._find_mihomo", lambda: None
        )
        monkeypatch.setattr(
            "fns.validators.tcp_validator._send_http_get", ok_http
        )

        password = "p@ssw0rd+/-"
        node = ProxyNode(
            node_type=ProxyType.SS,
            address="1.2.3.4",
            port=8388,
            method="aes-256-gcm",
            password=password,
        )
        result = await validator.validate_one(node)
        assert result.is_alive is True
        expected = base64.b64encode(f"aes-256-gcm:{password}".encode()).decode()
        assert seen[0] == f"ss://{expected}@1.2.3.4:8388"

    @pytest.mark.asyncio
    async def test_trojan_uri_uses_pproxy_fragment_format(self, monkeypatch):
        cfg = ValidatorConfig(
            concurrency=1,
            timeout=2.0,
            retries=0,
            test_url="https://www.gstatic.com/generate_204",
        )
        validator = TcpValidator(cfg)
        seen = []

        class FakeWriter:
            def close(self):
                pass

            async def wait_closed(self):
                pass

        class FakeConnection:
            def __init__(self, uri):
                seen.append(uri)

            async def tcp_connect(self, host, port):
                return None, FakeWriter()

        async def ok_http(reader, writer, test_url, timeout):
            return True

        monkeypatch.setattr("pproxy.Connection", FakeConnection)
        monkeypatch.setattr(
            "fns.validators.tcp_validator._find_mihomo", lambda: None
        )
        monkeypatch.setattr(
            "fns.validators.tcp_validator._send_http_get", ok_http
        )

        node = ProxyNode(
            node_type=ProxyType.TROJAN,
            address="trojan.example.com",
            port=443,
            password="p@ss/word",
            tls=True,
        )
        result = await validator.validate_one(node)
        assert result.is_alive is True
        assert seen[0] == "trojan+ssl://trojan.example.com:443#p@ss/word"

    @pytest.mark.asyncio
    async def test_mihomo_kills_process_on_wait_timeout(self, monkeypatch):
        class FakeResponse:
            status = 200

            async def read(self):
                return b""

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

        class FakeSession:
            closed = False

            def get(self, *args, **kwargs):
                return FakeResponse()

        class FakeProc:
            def __init__(self):
                self.stderr = None
                self.terminated = False
                self.killed = False
                self.wait_calls = 0

            def terminate(self):
                self.terminated = True

            def kill(self):
                self.killed = True

            async def wait(self):
                self.wait_calls += 1
                if self.wait_calls == 1:
                    raise asyncio.TimeoutError
                return 0

        proc = FakeProc()

        async def fake_wait_for_port(port, timeout):
            return True

        async def fake_create_subprocess_exec(*args, **kwargs):
            return proc

        monkeypatch.setattr(
            "fns.validators.tcp_validator._find_mihomo", lambda: "mihomo.exe"
        )
        monkeypatch.setattr(
            "fns.validators.tcp_validator._free_port", lambda: 12345
        )
        monkeypatch.setattr(
            "fns.validators.tcp_validator._wait_for_port", fake_wait_for_port
        )
        monkeypatch.setattr(
            "asyncio.create_subprocess_exec", fake_create_subprocess_exec
        )

        node = ProxyNode(
            node_type=ProxyType.VLESS,
            address="1.2.3.4",
            port=443,
            uuid="b831381d-6324-4d53-ad4f-8cda48b30811",
        )
        ok, _ = await _validate_via_mihomo(
            node,
            "https://www.gstatic.com/generate_204",
            2.0,
            session=FakeSession(),
        )
        assert ok is True
        assert proc.killed is True

    @pytest.mark.asyncio
    async def test_mihomo_spawn_failure_returns_false(self, monkeypatch):
        def fail_write(config, config_path):
            raise OSError("disk full")

        monkeypatch.setattr(
            "fns.validators.tcp_validator._find_mihomo", lambda: "mihomo.exe"
        )
        monkeypatch.setattr(
            "fns.validators.tcp_validator._write_mihomo_config", fail_write
        )

        node = ProxyNode(
            node_type=ProxyType.VLESS,
            address="1.2.3.4",
            port=443,
            uuid="b831381d-6324-4d53-ad4f-8cda48b30811",
        )
        ok, _ = await _validate_via_mihomo(
            node, "https://www.gstatic.com/generate_204", 2.0
        )
        assert ok is False
        assert "mihomo_spawn_failed" in node.validation_error

    @pytest.mark.asyncio
    async def test_validate_all(self):
        cfg = ValidatorConfig(
            concurrency=5, timeout=2.0, retries=0, test_url="http://www.google.com/"
        )
        validator = TcpValidator(cfg)
        nodes = [
            ProxyNode(node_type=ProxyType.HTTP, address="192.0.2.1", port=9999),
            ProxyNode(node_type=ProxyType.SOCKS5, address="192.0.2.2", port=9999),
            ProxyNode(node_type=ProxyType.VMESS, address="192.0.2.3", port=9999, uuid="x"),
        ]
        result = await validator.validate_all(nodes)
        assert len(result) == 3
        alive = [n for n in result if n.is_alive]
        assert len(alive) == 0

    @pytest.mark.asyncio
    async def test_validate_all_logs_dead_reasons(self, caplog):
        cfg = ValidatorConfig(
            concurrency=1, timeout=2.0, retries=0, test_url="http://www.google.com/"
        )
        validator = TcpValidator(cfg)
        node = ProxyNode(node_type=ProxyType.HTTP, address="192.0.2.10", port=9999)

        with caplog.at_level("DEBUG", logger="fns"):
            await validator.validate_all([node])

        assert any(
            "Validation failed" in record.message
            and "tcp_unreachable" in record.message
            for record in caplog.records
        )

    @pytest.mark.asyncio
    async def test_validate_all_prefilters_every_node(self, monkeypatch):
        cfg = ValidatorConfig(
            concurrency=2, timeout=2.0, retries=0, test_url="http://www.google.com/"
        )
        validator = TcpValidator(cfg)
        seen_types = []

        async def fake_prefilter(nodes):
            seen_types.extend(n.node_type for n in nodes)
            return nodes

        async def fake_validate(node):
            node.is_alive = True
            node.latency_ms = 10.0
            return node

        monkeypatch.setattr(validator, "_tcp_prefilter_batch", fake_prefilter)
        monkeypatch.setattr(validator, "_validate_node", fake_validate)

        nodes = [
            ProxyNode(node_type=ProxyType.HTTP, address="192.0.2.1", port=8080),
            ProxyNode(
                node_type=ProxyType.VMESS,
                address="192.0.2.2",
                port=443,
                uuid="x",
            ),
        ]
        await validator.validate_all(nodes)
        assert seen_types == [ProxyType.HTTP, ProxyType.VMESS]
        assert all(n.is_alive for n in nodes)
