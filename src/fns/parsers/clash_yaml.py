"""
Parse Clash / Clash Meta YAML configurations into ProxyNode objects.
"""

from __future__ import annotations

import logging

import yaml

from fns.models import ProxyNode, ProxyType
from fns.parsers.base import BaseParser, ParseResult

logger = logging.getLogger("fns")

# Map Clash proxy type → ProxyType
_CLASH_TYPE_MAP = {
    "vmess": ProxyType.VMESS,
    "vless": ProxyType.VLESS,
    "ss": ProxyType.SS,
    "shadowsocks": ProxyType.SS,
    "trojan": ProxyType.TROJAN,
    "hysteria2": ProxyType.HYSTERIA2,
    "tuic": ProxyType.TUIC,
    "http": ProxyType.HTTP,
    "socks5": ProxyType.SOCKS5,
}


class ClashYamlParser(BaseParser):
    """Parse Clash / Clash Meta YAML proxy configurations."""

    @staticmethod
    def can_parse(text: str) -> bool:
        try:
            data = yaml.safe_load(text)
            if isinstance(data, dict):
                return "proxies" in data or "port" in data
            return False
        except yaml.YAMLError:
            return False

    def parse(self, text: str, source: str = "") -> ParseResult:
        result = ParseResult(format_detected="clash_yaml")

        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as e:
            result.errors.append(f"YAML parse error: {e}")
            return result

        if not isinstance(data, dict):
            result.errors.append("YAML root is not a dict")
            return result

        proxies = data.get("proxies", data.get("Proxy", []))
        if not proxies:
            return result

        for proxy in proxies:
            try:
                node = self._parse_clash_proxy(proxy, source)
                if node:
                    result.nodes.append(node)
            except Exception as e:
                result.errors.append(f"Clash proxy parse error: {e}")

        return result

    def _parse_clash_proxy(self, proxy: dict, source: str) -> ProxyNode | None:
        if not isinstance(proxy, dict):
            return None

        proxy_type_str = str(proxy.get("type", "")).lower()
        proxy_type = _CLASH_TYPE_MAP.get(proxy_type_str)
        if proxy_type is None:
            logger.debug(f"Unknown Clash proxy type: {proxy_type_str}")
            return None

        node = ProxyNode(
            node_type=proxy_type,
            address=str(proxy.get("server", "")),
            port=int(proxy.get("port", 0)),
            uuid=proxy.get("uuid", ""),
            password=proxy.get("password", ""),
            method=proxy.get("cipher", proxy.get("method", "")),
            encryption=proxy.get("cipher", proxy.get("encryption", "")),
            flow=proxy.get("flow", ""),
            transport=proxy.get("network", "tcp"),
            ws_path=_get_ws_opts_path(proxy),
            ws_host=_get_ws_opts_host(proxy),
            tls=proxy.get("tls", False) is True or str(proxy.get("tls", "")).lower() == "true",
            sni=proxy.get("servername", proxy.get("sni", "")),
            fingerprint=proxy.get("client-fingerprint", proxy.get("fp", "")),
            public_key=proxy.get("reality-opts", {}).get("public-key", "") if isinstance(proxy.get("reality-opts"), dict) else "",
            short_id=proxy.get("reality-opts", {}).get("short-id", "") if isinstance(proxy.get("reality-opts"), dict) else "",
            obfs=proxy.get("obfs", ""),
            obfs_password=proxy.get("obfs-password", ""),
            up_speed=proxy.get("up", proxy.get("up-speed")),
            down_speed=proxy.get("down", proxy.get("down-speed")),
            source=source,
            remark=proxy.get("name", ""),
        )
        return node


def _get_ws_opts_path(proxy: dict) -> str | None:
    opts = proxy.get("ws-opts", proxy.get("ws-path"))
    if isinstance(opts, dict):
        return opts.get("path")
    if isinstance(opts, str):
        return opts
    return None


def _get_ws_opts_host(proxy: dict) -> str | None:
    opts = proxy.get("ws-opts")
    if isinstance(opts, dict):
        hdrs = opts.get("headers", {})
        if isinstance(hdrs, dict):
            return hdrs.get("Host")
    return None
