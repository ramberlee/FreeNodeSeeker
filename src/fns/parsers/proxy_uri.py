"""
Parse individual proxy URIs: vmess://, vless://, ss://, trojan://, hysteria2://, tuic://
"""

from __future__ import annotations

import html
import json
import re
from urllib.parse import parse_qs, unquote, urlsplit

from fns.models import ProxyNode, ProxyType, normalize_address, normalize_transport
from fns.parsers.base import BaseParser, ParseResult
from fns.utils.crypto import safe_b64decode

# Regex to match protocol:// prefix (http/socks5 lines come from plain proxy lists)
PROTO_RE = re.compile(
    r"^(vmess|vless|ssr|ss|trojan|hysteria2|hy2|hysteria|tuic|anytls|http|socks5?|socks)://",
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
        return any(
            PROTO_RE.match(line.strip())
            for line in text.strip().splitlines()
            if line.strip()
        )

    def parse(self, text: str, source: str = "", pre_parsed: object = None) -> ParseResult:
        result = ParseResult(format_detected="proxy_uri")
        for line in text.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            line = html.unescape(line)
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
        elif proto == "hysteria":
            return self._parse_hysteria(uri, source)
        elif proto == "ssr":
            return self._parse_ssr(uri, source)
        elif proto == "anytls":
            return self._parse_anytls(uri, source)
        elif proto == "tuic":
            return self._parse_tuic(uri, source)
        elif proto in ("http", "socks", "socks5"):
            return self._parse_plain_proxy(uri, source, proto)
        return None

    def _parse_plain_proxy(self, uri: str, source: str, proto: str) -> ProxyNode | None:
        """Parse plain http:// or socks5:// proxy list entries."""
        parsed = urlsplit(uri)
        if not parsed.hostname or parsed.port is None:
            return None
        # Reject URL-style lines that carry paths/queries (e.g. README links).
        if parsed.path not in ("", "/") or parsed.query:
            return None
        node_type = ProxyType.SOCKS5 if proto in ("socks", "socks5") else ProxyType.HTTP
        return ProxyNode(
            node_type=node_type,
            address=normalize_address(parsed.hostname),
            port=parsed.port,
            username=unquote(parsed.username) if parsed.username else None,
            password=unquote(parsed.password) if parsed.password else None,
            source=source,
            remark=unquote(parsed.fragment) if parsed.fragment else "",
        )

    # ── VMess ───────────────────────────────────────────────────────────────

    def _parse_vmess(self, uri: str, source: str) -> ProxyNode | None:
        raw_encoded = uri[len("vmess://"):]
        fragment = ""
        if "#" in raw_encoded:
            raw_encoded, fragment = raw_encoded.split("#", 1)
        encoded = raw_encoded
        if "?" in encoded:
            encoded = encoded.split("?", 1)[0]
        try:
            data = json.loads(safe_b64decode(encoded).decode("utf-8", errors="replace"))
        except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
            try:
                data = json.loads(encoded)
            except (json.JSONDecodeError, UnicodeDecodeError):
                fallback_uri = f"vless://{raw_encoded}"
                if fragment:
                    fallback_uri += f"#{fragment}"
                return self._parse_vless(fallback_uri, source)
        return _vmess_from_json(data, source, fragment)

    # ── VLESS ───────────────────────────────────────────────────────────────

    def _parse_vless(self, uri: str, source: str) -> ProxyNode | None:
        inner = uri[len("vless://"):]
        # Split userinfo from the host part first so a # in the userinfo is
        # not mistaken for the remark fragment.
        userinfo, rest = inner.rsplit("@", 1)
        uuid = unquote(userinfo)

        remark = ""
        if "#" in rest:
            rest, _, remark = rest.partition("#")
            remark = unquote(remark)

        host_port, _, qs = rest.partition("?")
        host, port = _split_host_port(host_port, 443)

        params = parse_qs(qs) if qs else {}
        security = _first(params, "security", "")
        # Some subscriptions omit security= while still setting sni; sni is
        # only meaningful for TLS, so treat that as an implicit TLS marker.
        tls = security in ("tls", "reality") or (
            not security and bool(_first(params, "sni", ""))
        )

        return ProxyNode(
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
            skip_cert_verify=_truthy(_first(params, "allowInsecure", "")) or _truthy(
                _first(params, "insecure", "")
            ),
            grpc_service_name=_first(params, "serviceName", "") or _first(
                params, "grpc-service-name", ""
            ),
            sni=_first(params, "sni", ""),
            fingerprint=_first(params, "fp", ""),
            public_key=_first(params, "pbk", ""),
            short_id=_first(params, "sid", ""),
            source=source,
            remark=remark,
        )

    # ── Shadowsocks ─────────────────────────────────────────────────────────

    def _parse_ss(self, uri: str, source: str) -> ProxyNode | None:
        inner = uri[len("ss://"):]
        qs = ""

        # SIP002: ss://base64(method:password)@host:port?plugin=...#remark
        if "@" in inner:
            userinfo_b64, rest = inner.split("@", 1)
            vmess_node = _vmess_from_ss_userinfo(userinfo_b64, source)
            if vmess_node is not None:
                return vmess_node
            userinfo = _decode_ss_userinfo(userinfo_b64)
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

            host_port, qs = _split_ss_query(host_port)
            host, port = _split_host_port(host_port, 8388)
        else:
            # Legacy: ss://base64(method:password@host:port)
            legacy = inner
            fragment = ""
            if "#" in legacy:
                legacy, fragment = legacy.split("#", 1)
            legacy = legacy.split("?", 1)[0]
            vmess_node = _vmess_from_ss_userinfo(legacy, source)
            if vmess_node is not None:
                return vmess_node
            decoded = _decode_ss_userinfo(legacy)
            userinfo, hpp = decoded.rsplit("@", 1)
            method, password = userinfo.split(":", 1)
            host, port = _split_host_port(hpp, 8388)
            remark = unquote(fragment)

        params = parse_qs(qs) if qs else {}
        plugin, plugin_opts = _parse_ss_plugin(_first(params, "plugin", ""))

        return ProxyNode(
            node_type=ProxyType.SS,
            address=host,
            port=port,
            password=password,
            method=method,
            plugin=plugin,
            plugin_opts=plugin_opts,
            source=source,
            remark=remark,
        )

    # ── Trojan ──────────────────────────────────────────────────────────────

    def _parse_trojan(self, uri: str, source: str) -> ProxyNode | None:
        inner = uri[len("trojan://"):]

        # Passwords can contain #, so split on @ first and only then take the
        # remark fragment from the remaining host/query part.
        password, rest = inner.rsplit("@", 1)
        password = unquote(password)

        remark = ""
        if "#" in rest:
            rest, _, remark = rest.partition("#")
            remark = unquote(remark)

        host_port, _, qs = rest.partition("?")
        host, port = _split_host_port(host_port, 443)

        params = parse_qs(qs) if qs else {}
        security = _first(params, "security", "tls")
        insecure = _truthy(_first(params, "allowInsecure", "")) or _truthy(
            _first(params, "insecure", "")
        )

        return ProxyNode(
            node_type=ProxyType.TROJAN,
            address=host,
            port=port,
            password=password,
            transport=_first(params, "type", "tcp"),
            ws_path=_first(params, "path", ""),
            ws_host=_first(params, "host", ""),
            grpc_service_name=_first(params, "serviceName", "") or _first(
                params, "grpc-service-name", ""
            ),
            tls=security == "tls",
            skip_cert_verify=insecure or security != "tls",
            sni=_first(params, "sni", ""),
            fingerprint=_first(params, "fp", ""),
            source=source,
            remark=remark,
        )

    # ── Hysteria2 ───────────────────────────────────────────────────────────

    def _parse_hysteria2(self, uri: str, source: str) -> ProxyNode | None:
        inner = re.sub(r"^(hysteria2|hy2)://", "", uri, flags=re.IGNORECASE)

        if "@" in inner:
            # hysteria2://password@host:port?params
            password, rest = inner.rsplit("@", 1)
            password = unquote(password)
        else:
            # hysteria2://host:port?auth=password&...
            rest = inner
            password = ""

        remark = ""
        if "#" in rest:
            rest, _, remark = rest.partition("#")
            remark = unquote(remark)

        host_port, _, qs = rest.partition("?")
        host, port = _split_host_port(host_port, 443)

        params = parse_qs(qs) if qs else {}
        if not password:
            password = _first(params, "auth", "")
        insecure = _truthy(_first(params, "insecure", "")) or _truthy(
            _first(params, "allowInsecure", "")
        )
        tls = not insecure

        return ProxyNode(
            node_type=ProxyType.HYSTERIA2,
            address=host,
            port=port,
            password=password,
            tls=tls,
            skip_cert_verify=insecure,
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

        userinfo, rest = inner.rsplit("@", 1)
        if ":" in userinfo:
            uuid, password = userinfo.split(":", 1)
        else:
            uuid, password = userinfo, ""
        uuid = unquote(uuid)
        password = unquote(password)

        remark = ""
        if "#" in rest:
            rest, _, remark = rest.partition("#")
            remark = unquote(remark)

        host_port, _, qs = rest.partition("?")
        host, port = _split_host_port(host_port, 443)

        params = parse_qs(qs) if qs else {}
        insecure = _truthy(_first(params, "insecure", "")) or _truthy(
            _first(params, "allowInsecure", "")
        )

        return ProxyNode(
            node_type=ProxyType.TUIC,
            address=host,
            port=port,
            uuid=uuid,
            password=password,
            tls=not insecure,
            skip_cert_verify=insecure,
            sni=_first(params, "sni", ""),
            congestion_control=_first(params, "congestion_control", ""),
            udp_relay_mode=_first(params, "udp_relay_mode", ""),
            source=source,
            remark=remark,
        )

    # ── Hysteria (v1) ────────────────────────────────────────────────────────

    def _parse_hysteria(self, uri: str, source: str) -> ProxyNode | None:
        inner = uri[len("hysteria://"):]

        remark = ""
        if "#" in inner:
            inner, _, remark = inner.partition("#")
            remark = unquote(remark)

        host_port, _, qs = inner.partition("?")
        host, port = _split_host_port(host_port, 443)
        params = parse_qs(qs) if qs else {}
        insecure = _truthy(_first(params, "insecure", ""))

        return ProxyNode(
            node_type=ProxyType.HYSTERIA,
            address=host,
            port=port,
            password=_first(params, "auth", ""),
            up_speed=_int_or_none(_first(params, "upmbps", "")),
            down_speed=_int_or_none(_first(params, "downmbps", "")),
            obfs=_first(params, "obfs", ""),
            obfs_password=_first(params, "obfsparam", ""),
            sni=_first(params, "sni", ""),
            tls=not insecure,
            skip_cert_verify=insecure,
            source=source,
            remark=remark,
        )

    # ── SSR ──────────────────────────────────────────────────────────────────

    def _parse_ssr(self, uri: str, source: str) -> ProxyNode | None:
        inner = uri[len("ssr://"):]
        decoded = safe_b64decode(inner).decode("utf-8", errors="replace")
        userinfo, rest = decoded.rsplit("@", 1)
        method, password = userinfo.split(":", 1)

        host_port, _, qs = rest.partition("?")
        host, port = _split_host_port(host_port, 8388)
        params = parse_qs(qs) if qs else {}

        return ProxyNode(
            node_type=ProxyType.SSR,
            address=host,
            port=port,
            method=method,
            password=password,
            protocol=_first(params, "protocol", ""),
            protocol_param=_first(params, "protoparam", ""),
            obfs=_first(params, "obfs", ""),
            obfs_param=_first(params, "obfsparam", ""),
            source=source,
            remark=unquote(_first(params, "remarks", "")),
        )

    # ── AnyTLS ───────────────────────────────────────────────────────────────

    def _parse_anytls(self, uri: str, source: str) -> ProxyNode | None:
        inner = uri[len("anytls://"):]
        password, rest = inner.rsplit("@", 1)
        password = unquote(password)

        remark = ""
        if "#" in rest:
            rest, _, remark = rest.partition("#")
            remark = unquote(remark)

        host_port, _, qs = rest.partition("?")
        host, port = _split_host_port(host_port, 443)
        params = parse_qs(qs) if qs else {}
        insecure = _truthy(_first(params, "insecure", "")) or _truthy(
            _first(params, "allowInsecure", "")
        )

        return ProxyNode(
            node_type=ProxyType.ANYTLS,
            address=host,
            port=port,
            password=password,
            tls=not insecure,
            skip_cert_verify=insecure,
            sni=_first(params, "sni", ""),
            fingerprint=_first(params, "fp", ""),
            source=source,
            remark=remark,
        )


def _first(params: dict, key: str, default: str = "") -> str:
    vals = params.get(key, [])
    return vals[0] if vals else default


def _vmess_from_json(data: object, source: str, fragment: str) -> ProxyNode | None:
    """Build a VMess node from a decoded vmess JSON config."""
    if not isinstance(data, dict):
        return None
    try:
        port = int(data.get("port", 0))
    except (TypeError, ValueError):
        port = 0
    transport = normalize_transport(data.get("net", "tcp")) or "tcp"
    tls = str(data.get("tls", "")).strip().lower() in ("tls", "true", "1", "yes")
    ws_host = str(data.get("host", ""))
    sni = str(data.get("sni", "")).strip()
    if not sni and tls and ws_host and transport in ("ws", "http", "httpupgrade", "h2"):
        sni = ws_host
    return ProxyNode(
        node_type=ProxyType.VMESS,
        address=normalize_address(str(data.get("add", ""))),
        port=port,
        uuid=data.get("id", ""),
        encryption=data.get("scy", "auto"),
        method=data.get("scy", "auto"),
        transport=transport,
        ws_path=data.get("path", ""),
        ws_host=ws_host,
        tls=tls,
        sni=sni,
        fingerprint=data.get("fp", ""),
        source=source,
        remark=data.get("ps") or unquote(fragment),
    )


def _vmess_from_ss_userinfo(userinfo: str, source: str) -> ProxyNode | None:
    """Some subscriptions wrap a vmess JSON payload in an ss:// prefix."""
    try:
        decoded = safe_b64decode(userinfo).decode("utf-8", errors="replace")
    except ValueError:
        return None
    if not decoded.lstrip().startswith("{"):
        return None
    try:
        data = json.loads(decoded)
    except json.JSONDecodeError:
        return None
    return _vmess_from_json(data, source, "")


def _decode_ss_userinfo(raw: str) -> str:
    """Decode SIP002 userinfo, falling back to plaintext when not base64."""
    plain = unquote(raw)
    if ":" in plain or "@" in plain:
        return plain
    try:
        decoded = safe_b64decode(plain).decode("utf-8", errors="replace")
    except ValueError:
        return plain
    # Lenient base64 decoding can silently "decode" plaintext strings, so only
    # trust it when the result looks like method:password or a JSON payload.
    if ":" in decoded or decoded.lstrip().startswith("{"):
        return decoded
    return plain


def _split_host_port(host_port: str, default_port: int) -> tuple[str, int]:
    """Split host:port, tolerating bracketed or bare IPv6 addresses."""
    host_port = host_port.strip().rstrip("/")
    if host_port.startswith("["):
        end = host_port.find("]")
        if end != -1:
            host = host_port[1:end]
            rest = host_port[end + 1:]
            if rest.startswith(":"):
                try:
                    return normalize_address(host), int(rest[1:])
                except ValueError:
                    return normalize_address(host), default_port
            return normalize_address(host), default_port
    if host_port.count(":") == 1:
        host, port_str = host_port.rsplit(":", 1)
        try:
            return normalize_address(host), int(port_str)
        except ValueError:
            return normalize_address(host), default_port
    # Bare hostname, bare IPv6, or default port.
    return normalize_address(host_port), default_port


def _int_or_none(s: str) -> int | None:
    try:
        return int(s)
    except (ValueError, TypeError):
        return None


def _split_ss_query(host_port: str) -> tuple[str, str]:
    """Split a SIP002 host:port into (host_port, query), tolerating `/?`."""
    if "/?" in host_port:
        host_port, _, qs = host_port.partition("/?")
    else:
        host_port, _, qs = host_port.partition("?")
    return host_port, qs


def _parse_ss_plugin(plugin_param: str) -> tuple[str | None, dict | None]:
    """Parse a SIP002 plugin value into a plugin name and option dict."""
    parts = [p for p in plugin_param.split(";") if p.strip()]
    if not parts:
        return None, None
    opts: dict = {}
    for part in parts[1:]:
        if "=" in part:
            key, _, value = part.partition("=")
            opts[key.strip()] = value
        else:
            opts[part.strip()] = True
    return parts[0].strip(), opts or None


def _truthy(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}
