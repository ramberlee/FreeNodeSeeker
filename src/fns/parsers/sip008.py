"""
Parse Shadowsocks SIP008 JSON format:
[{"server": "...", "server_port": ..., "method": "...", "password": "...", "remarks": "...", ...}]
"""

from __future__ import annotations

import json
import logging

from fns.models import ProxyNode, ProxyType
from fns.parsers.base import BaseParser, ParseResult
from fns.utils.crypto import safe_b64decode

logger = logging.getLogger("fns")


class Sip008Parser(BaseParser):
    """Parse SIP008 Shadowsocks node list."""

    @staticmethod
    def can_parse(text: str) -> bool:
        clean = text.strip()
        if not clean:
            return False
        # Try direct JSON
        try:
            data = json.loads(clean)
            if isinstance(data, list) and data and isinstance(data[0], dict):
                return "server" in data[0]
        except json.JSONDecodeError:
            pass
        # Try base64-decoded
        try:
            decoded = safe_b64decode(clean)
            data = json.loads(decoded)
            if isinstance(data, list) and data and isinstance(data[0], dict):
                return "server" in data[0]
        except Exception:
            pass
        return False

    def parse(self, text: str, source: str = "", pre_parsed: object = None) -> ParseResult:
        result = ParseResult(format_detected="sip008")
        data = self._load_json(text, result)
        if data is None:
            return result

        for item in data:
            try:
                node = ProxyNode(
                    node_type=ProxyType.SS,
                    address=str(item.get("server", "")),
                    port=int(item.get("server_port", 0)),
                    password=str(item.get("password", "")),
                    method=str(item.get("method", "aes-256-gcm")),
                    source=source,
                    remark=str(item.get("remarks", "")),
                )
                result.nodes.append(node)
            except Exception as e:
                result.errors.append(f"SIP008 entry error: {e}")

        return result

    def _load_json(self, text: str, result: ParseResult) -> list | None:
        clean = text.strip()
        # Try direct
        try:
            data = json.loads(clean)
            if isinstance(data, list):
                return data
        except json.JSONDecodeError:
            pass
        # Try base64
        try:
            decoded = safe_b64decode(clean)
            data = json.loads(decoded)
            if isinstance(data, list):
                return data
        except Exception:
            pass
        result.errors.append("Could not parse SIP008 JSON")
        return None
