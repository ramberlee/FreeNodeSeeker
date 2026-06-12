"""
Parse individual proxy URIs: vmess://, vless://, ss://, trojan://, hysteria2://, tuic://
"""

from __future__ import annotations

import json
import re
from urllib.parse import parse_qs, unquote, urlparse

from fns.models import ProxyNode, ProxyType
from fns.parsers.base import BaseParser, ParseResult
from fns.utils.crypto import safe_b64decode

# Regex to match protocol:// prefix
PROTO_RE = re.compile(
    r"^(vmess|vless|ss|trojan|hysteria2?|hy2|tuic)://",
    re.IGNORECASE,
)

# Query param map for common parameters across protocols
_QS_MAP = {
    "encryption": "encryption",
    "security": "tls",  # handled specially
    "type": "transport",
    "path": "ws_path",
    "host": "ws_host",
    "sni": "sni",
    "fp": "fingerprint",
    "flow": "flow",
    "pbk": "public_key",
    "sid": "short_id",
    "insecure": None,  # handled specially
    "obfs": "obfs",
    "obfs-password": "obfs_password",
    "up": "up_speed",
    "down": "down_speed",
    "congestion_control": "congestion_control",
    "udp_relay_mode": "udp_relay_mode",
    "alpn": None,
    "allowInsecure": None,
    "headerType": None,
    "quicSecurity": None,
    "key": None,
    "serviceName": None,
    "mode": None,
    "scy": "encryption",
}


class ProxyUriParser(BaseParser):
    """Parse proxy protocol URIs into ProxyNode objects."""

    @staticmethod
    def can_parse(text: str) -> bool:
        return any(PROTO_RE.match(line.strip()) for line in text.strip().splitlines() if line.strip())

    def parse(self, text: str, source: str = "") -> ParseResult:
        result = ParseResult(format_detected="proxy_uri")
        for line in text.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                node = self._parse_line(line, source)
                if node:
                    result.nodes.append(node)
            except Exception as e:
                result.errors.append(f"URI parse error: {line[:80]} — {e}")
        return result

    def _parse_line(self, uri: str, source: str) -> ProxyNode | None:
        m = PROTO_RE.match(uri)
        if not m:
            return None
        proto = m.group(1).lower()

        if proto == "vmess":
            return self._parse_vmess(uri, source)
        elif proto == "vless":
            return self._parse_vless(uri, source)
        elif proto == "ss":
            return self._parse_ss(uri, source)
        elif proto == "trojan":
            return self._parse_trojan(uri, source)
        elif proto in ("hysteria2", "hy2"):
            return self._parse_hysteria2(uri, source)
        elif proto == "tuic":
            return self._parse_tuic(uri, source)
        return None

    # ── VMess ───────────────────────────────────────────────────────────────

    def _parse_vmess(self, uri: str, source: str) -> ProxyNode | None:
        encoded = uri[len("vmess://"):]
        decoded = safe_b64decode(encoded).decode("utf-8", errors="replace")
        data = json.loads(decoded)

        node = ProxyNode(
            node_type=ProxyType.VMESS,
            address=data.get("add", ""),
            port=int(data.get("port", 0)),
            uuid=data.get("id", ""),
            encryption=data.get("scy", "auto"),
            method=data.get("scy", "auto"),
            transport=data.get("net", "tcp"),
            ws_path=data.get("path", ""),
            ws_host=data.get("host", ""),
            tls=data.get("tls", "") == "tls",
            sni=data.get("sni", ""),
            fingerprint=data.get("fp", ""),
            source=source,
            remark=data.get("ps", ""),
        )
        return node

    # ── VLESS ───────────────────────────────────────────────────────────────

    def _parse_vless(self, uri: str, source: str) -> ProxyNode | None:
        inner = uri[len("vless://"):]
        # vless://uuid@host:port?params#remark
        if "#" in inner:
            inner, remark = inner.split("#", 1)
            remark = unquote(remark)
        else:
            remark = ""

        # split at first @
        userinfo, rest = inner.split("@", 1)
        uuid = userinfo

        host_port, _, qs = rest.partition("?")
        if ":" in host_port:
            host, port_str = host_port.rsplit(":", 1)
            port = int(port_str)
        else:
            host, port = host_port, 443

        params = parse_qs(qs) if qs else {}
        security = _first(params, "security", "")
        tls = security in ("tls", "reality")

        node = ProxyNode(
            node_type=ProxyType.VLESS,
            address=host,
            port=port,
            uuid=uuid,
            encryption=_first(params, "encryption", "none"),
            flow=_first(params, "flow", ""),
            transport=_first(params, "type", "tcp"),
            ws_path=_first(params, "path", ""),
            ws_host=_first(params, "host", ""),
            tls=tls,
            sni=_first(params, "sni", ""),
            fingerprint=_first(params, "fp", ""),
            public_key=_first(params, "pbk", ""),
            short_id=_first(params, "sid", ""),
            source=source,
            remark=remark,
        )
        return node

    # ── Shadowsocks ─────────────────────────────────────────────────────────

    def _parse_ss(self, uri: str, source: str) -> ProxyNode | None:
        inner = uri[len("ss://"):]

        # SIP002: ss://base64(method:password)@host:port#remark
        if "@" in inner:
            userinfo_b64, rest = inner.split("@", 1)
            userinfo = safe_b64decode(userinfo_b64).decode("utf-8", errors="replace")
            if ":" in userinfo:
                method, password = userinfo.split(":", 1)
            else:
                method, password = "aes-256-gcm", userinfo

            if "#" in rest:
                host_port, remark = rest.split("#", 1)
                remark = unquote(remark)
            else:
                host_port = rest
                remark = ""

            host_port = host_port.rstrip("/")
            if ":" in host_port:
                host, port_str = host_port.rsplit(":", 1)
                port = int(port_str)
            else:
                host, port = host_port, 8388
        else:
            # Legacy: ss://base64(method:password@host:port)
            decoded = safe_b64decode(inner).decode("utf-8", errors="replace")
            userinfo, hpp = decoded.rsplit("@", 1)
            method, password = userinfo.split(":", 1)
            host, port_str = hpp.rsplit(":", 1)
            host, port, remark = host, int(port_str), ""

        return ProxyNode(
            node_type=ProxyType.SS,
            address=host,
            port=port,
            password=password,
            method=method,
            source=source,
            remark=remark,
        )

    # ── Trojan ──────────────────────────────────────────────────────────────

    def _parse_trojan(self, uri: str, source: str) -> ProxyNode | None:
        inner = uri[len("trojan://"):]

        if "#" in inner:
            inner, remark = inner.split("#", 1)
            remark = unquote(remark)
        else:
            remark = ""

        password, rest = inner.split("@", 1)
        host_port, _, qs = rest.partition("?")

        if ":" in host_port:
            host, port_str = host_port.rsplit(":", 1)
            port = int(port_str)
        else:
            host, port = host_port, 443

        params = parse_qs(qs) if qs else {}
        security = _first(params, "security", "tls")

        return ProxyNode(
            node_type=ProxyType.TROJAN,
            address=host,
            port=port,
            password=password,
            transport=_first(params, "type", "tcp"),
            ws_path=_first(params, "path", ""),
            ws_host=_first(params, "host", ""),
            tls=security == "tls",
            sni=_first(params, "sni", ""),
            fingerprint=_first(params, "fp", ""),
            source=source,
            remark=remark,
        )

    # ── Hysteria2 ───────────────────────────────────────────────────────────

    def _parse_hysteria2(self, uri: str, source: str) -> ProxyNode | None:
        inner = re.sub(r"^(hysteria2|hy2)://", "", uri, flags=re.IGNORECASE)

        if "#" in inner:
            inner, remark = inner.split("#", 1)
            remark = unquote(remark)
        else:
            remark = ""

        if "@" in inner:
            # hysteria2://password@host:port?params
            password, rest = inner.split("@", 1)
        else:
            # hysteria2://host:port?auth=password&...
            rest = inner
            password = ""

        host_port, _, qs = rest.partition("?")
        if ":" in host_port:
            host, port_str = host_port.rsplit(":", 1)
            port = int(port_str)
        else:
            host, port = host_port, 443

        params = parse_qs(qs) if qs else {}
        if not password:
            password = _first(params, "auth", "")
        insecure = _first(params, "insecure", "")
        tls = insecure != "1"

        return ProxyNode(
            node_type=ProxyType.HYSTERIA2,
            address=host,
            port=port,
            password=password,
            tls=tls,
            sni=_first(params, "sni", ""),
            obfs=_first(params, "obfs", ""),
            obfs_password=_first(params, "obfs-password", ""),
            up_speed=_int_or_none(_first(params, "up", "")),
            down_speed=_int_or_none(_first(params, "down", "")),
            source=source,
            remark=remark,
        )

    # ── TUIC ────────────────────────────────────────────────────────────────

    def _parse_tuic(self, uri: str, source: str) -> ProxyNode | None:
        inner = uri[len("tuic://"):]

        if "#" in inner:
            inner, remark = inner.split("#", 1)
            remark = unquote(remark)
        else:
            remark = ""

        userinfo, rest = inner.split("@", 1)
        if ":" in userinfo:
            uuid, password = userinfo.split(":", 1)
        else:
            uuid, password = userinfo, ""

        host_port, _, qs = rest.partition("?")
        if ":" in host_port:
            host, port_str = host_port.rsplit(":", 1)
            port = int(port_str)
        else:
            host, port = host_port, 443

        params = parse_qs(qs) if qs else {}

        return ProxyNode(
            node_type=ProxyType.TUIC,
            address=host,
            port=port,
            uuid=uuid,
            password=password,
            tls=True,
            sni=_first(params, "sni", ""),
            congestion_control=_first(params, "congestion_control", ""),
            udp_relay_mode=_first(params, "udp_relay_mode", ""),
            source=source,
            remark=remark,
        )


def _first(params: dict, key: str, default: str = "") -> str:
    vals = params.get(key, [])
    return vals[0] if vals else default


def _int_or_none(s: str) -> int | None:
    try:
        return int(s)
    except (ValueError, TypeError):
        return None
