"""Test multi-protocol validator."""

import pytest

from fns.config import ValidatorConfig
from fns.models import ProxyNode, ProxyType
from fns.validators.tcp_validator import (
    TcpValidator,
    _build_mihomo_config,
    _is_success_status,
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
    async def test_unreachable_trojan(self):
        cfg = ValidatorConfig(
            concurrency=1, timeout=2.0, retries=0, test_url="http://www.google.com/"
        )
        validator = TcpValidator(cfg)
        node = ProxyNode(
            node_type=ProxyType.TROJAN,
            address="192.0.2.3",
            port=9999,
            password="test",
        )
        result = await validator.validate_one(node)
        assert result.is_alive is False

    @pytest.mark.asyncio
    async def test_unreachable_ss(self):
        cfg = ValidatorConfig(
            concurrency=1, timeout=2.0, retries=0, test_url="http://www.google.com/"
        )
        validator = TcpValidator(cfg)
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
    async def test_unreachable_vmess_without_mihomo(self):
        """VMess without mihomo should be marked dead, not TCP-only alive."""
        cfg = ValidatorConfig(
            concurrency=1, timeout=2.0, retries=0, test_url="http://www.google.com/"
        )
        validator = TcpValidator(cfg)
        node = ProxyNode(
            node_type=ProxyType.VMESS,
            address="192.0.2.5",
            port=9999,
            uuid="b831381d-6324-4d53-ad4f-8cda48b30811",
        )
        result = await validator.validate_one(node)
        assert result.is_alive is False

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
