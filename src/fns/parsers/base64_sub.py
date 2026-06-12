"""
Parse base64-encoded V2Ray/Clash subscription content.
Handles:
  - Line-based: each line after decode is a proxy URI
  - JSON-array after decode (V2Ray server list format)
  - Clash YAML within base64
"""

from __future__ import annotations

import json
import logging

from fns.models import ProxyNode
from fns.parsers.base import BaseParser, ParseResult
from fns.parsers.proxy_uri import ProxyUriParser
from fns.parsers.sip008 import Sip008Parser
from fns.utils.crypto import safe_b64decode

logger = logging.getLogger("fns")

URI_PREFIXES = ("vmess://", "vless://", "ss://", "trojan://", "hysteria2://", "hy2://", "tuic://")


class Base64SubParser(BaseParser):
    """Parse base64-encoded subscription content."""

    @staticmethod
    def can_parse(text: str) -> bool:
        clean = text.strip()
        if not clean:
            return False
        try:
            decoded = safe_b64decode(clean)
            decoded_str = decoded.decode("utf-8", errors="ignore").strip()
            return any(
                decoded_str.startswith(p) or decoded_str.startswith("[") or "proxies" in decoded_str
                for p in URI_PREFIXES + ("{",)
            )
        except Exception:
            return False

    def parse(self, text: str, source: str = "", pre_parsed: object = None) -> ParseResult:
        result = ParseResult(format_detected="base64_sub")
        uri_parser = ProxyUriParser()

        try:
            decoded = safe_b64decode(text.strip()).decode("utf-8", errors="replace")
        except Exception as e:
            result.errors.append(f"Base64 decode failed: {e}")
            return result

        decoded = decoded.strip()

        # Case 1: Lines of proxy URIs
        if any(decoded.startswith(p) for p in URI_PREFIXES):
            sub_result = uri_parser.parse(decoded, source)
            result.nodes = sub_result.nodes
            result.errors = sub_result.errors
            return result

        # Case 2: JSON array (V2Ray server list)
        if decoded.startswith("["):
            return self._parse_json_array(decoded, source, result)

        # Case 3: JSON object with add/port keys
        if decoded.startswith("{"):
            try:
                data = json.loads(decoded)
                node = self._parse_json_node(data, source)
                if node:
                    result.nodes.append(node)
            except json.JSONDecodeError:
                result.errors.append("JSON parse failed for base64 content")
            return result

        # Case 4: Fallback — try URI parser anyway
        sub_result = uri_parser.parse(decoded, source)
        result.nodes = sub_result.nodes
        result.errors = sub_result.errors
        return result

    def _parse_json_array(self, text: str, source: str, result: ParseResult) -> ParseResult:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as e:
            result.errors.append(f"JSON decode failed: {e}")
            return result

        if not isinstance(data, list):
            result.errors.append("Expected JSON array")
            return result

        # Check if it's SIP008 format
        if data and isinstance(data[0], dict) and "server" in data[0]:
            sip = Sip008Parser()
            sip_result = sip.parse(text, source)
            result.nodes = sip_result.nodes
            return result

        # Generic V2Ray server list
        for item in data:
            if isinstance(item, dict):
                node = self._parse_json_node(item, source)
                if node:
                    result.nodes.append(node)
        return result

    def _parse_json_node(self, data: dict, source: str) -> ProxyNode | None:
        """Parse a single V2Ray JSON server object."""
        proto = data.get("protocol", "vmess").lower()
        if proto not in ("vmess", "vless", "ss", "trojan", "http", "socks"):
            proto = "vmess"

        from fns.models import ProxyType

        node = ProxyNode(
            node_type=ProxyType(proto),
            address=data.get("add", data.get("address", "")),
            port=int(data.get("port", 0)),
            uuid=data.get("id", data.get("uuid", "")),
            password=data.get("password", ""),
            encryption=data.get("scy", data.get("encryption", data.get("method", ""))),
            method=data.get("method", data.get("scy", "")),
            transport=data.get("net", data.get("transport", data.get("type", "tcp"))),
            ws_path=data.get("path", ""),
            ws_host=data.get("host", ""),
            tls=str(data.get("tls", "")).lower() in ("tls", "true", "1"),
            sni=data.get("sni", ""),
            fingerprint=data.get("fp", ""),
            source=source,
            remark=data.get("ps", data.get("remark", data.get("name", ""))),
        )
        return node
