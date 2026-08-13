"""Parse sing-box JSON configurations into ProxyNode objects."""

from __future__ import annotations

import json
import logging

from fns.models import ProxyNode, ProxyType
from fns.parsers.base import BaseParser, ParseResult

logger = logging.getLogger("fns")

_TYPE_MAP = {
    "vless": ProxyType.VLESS,
    "vmess": ProxyType.VMESS,
    "shadowsocks": ProxyType.SS,
    "ss": ProxyType.SS,
    "trojan": ProxyType.TROJAN,
    "hysteria2": ProxyType.HYSTERIA2,
    "hysteria": ProxyType.HYSTERIA2,
    "tuic": ProxyType.TUIC,
    "http": ProxyType.HTTP,
    "socks": ProxyType.SOCKS5,
}


def _as_bool(value: object) -> bool:
    return value is True or str(value).lower() in ("true", "1", "yes")


def _as_dict(value: object) -> dict:
    return value if isinstance(value, dict) else {}


class SingBoxParser(BaseParser):
    """Parse a sing-box config containing an ``outbounds`` list."""

    @staticmethod
    def can_parse(text: str) -> bool:
        try:
            data = json.loads(text)
        except Exception:
            return False
        return isinstance(data, dict) and "outbounds" in data

    def parse(self, text: str, source: str = "", pre_parsed: object = None) -> ParseResult:
        result = ParseResult(format_detected="singbox")

        try:
            data = pre_parsed if pre_parsed is not None else json.loads(text)
        except json.JSONDecodeError as e:
            result.errors.append(f"sing-box JSON parse error: {e}")
            return result

        if not isinstance(data, dict):
            result.errors.append("sing-box JSON root is not a dict")
            return result

        outbounds = data.get("outbounds")
        if not isinstance(outbounds, list):
            return result

        for outbound in outbounds:
            try:
                node = self._parse_outbound(outbound, source)
                if node:
                    result.nodes.append(node)
            except Exception as e:
                result.errors.append(f"sing-box outbound parse error: {e}")

        return result

    def _parse_outbound(self, outbound: object, source: str) -> ProxyNode | None:
        if not isinstance(outbound, dict):
            return None

        type_str = str(outbound.get("type", "")).lower()
        node_type = _TYPE_MAP.get(type_str)
        if node_type is None:
            return None

        address = str(outbound.get("server", "") or outbound.get("address", ""))
        port = int(outbound.get("server_port") or outbound.get("port") or 0)

        tls = _as_dict(outbound.get("tls"))
        tls_enabled = _as_bool(tls.get("enabled")) or outbound.get("tls") is True
        utls = _as_dict(tls.get("utls"))
        reality = _as_dict(tls.get("reality"))
        transport = _as_dict(outbound.get("transport"))
        headers = _as_dict(transport.get("headers"))

        return ProxyNode(
            node_type=node_type,
            address=address,
            port=port,
            uuid=outbound.get("uuid", ""),
            password=(
                outbound.get("password")
                or outbound.get("auth")
                or ""
            ),
            username=outbound.get("username", ""),
            method=outbound.get("method") or outbound.get("cipher") or "",
            encryption=outbound.get("security") or outbound.get("cipher") or "",
            flow=outbound.get("flow", ""),
            transport=str(transport.get("type", "tcp")),
            ws_path=transport.get("path", ""),
            ws_host=headers.get("Host") or transport.get("host", ""),
            tls=tls_enabled,
            sni=tls.get("server_name") or tls.get("sni") or "",
            skip_cert_verify=_as_bool(tls.get("insecure")),
            fingerprint=utls.get("fingerprint") or tls.get("fingerprint", ""),
            public_key=reality.get("public_key", ""),
            short_id=reality.get("short_id", ""),
            grpc_service_name=(
                transport.get("service_name")
                or transport.get("serviceName")
                or ""
            ),
            obfs=outbound.get("obfs", ""),
            obfs_password=outbound.get("obfs-password", ""),
            up_speed=outbound.get("up_mbps"),
            down_speed=outbound.get("down_mbps"),
            congestion_control=outbound.get("congestion_control", ""),
            udp_relay_mode=outbound.get("udp_relay_mode", ""),
            source=source,
            remark=str(outbound.get("tag") or outbound.get("name") or f"{address}:{port}"),
        )
