"""Test multi-protocol validator."""

import pytest

from fns.config import ValidatorConfig
from fns.models import ProxyNode, ProxyType
from fns.validators.tcp_validator import TcpValidator


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
    async def test_unreachable_vmess_tcp_fallback(self):
        """VMess without sing-box should fall back to TCP check and fail."""
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
