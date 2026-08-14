"""
Format detector — sniff RawContent format and route to the correct parser.
"""

from __future__ import annotations

import logging
from urllib.parse import urlsplit

import yaml

from fns.parsers.base import ParseResult
from fns.parsers.base64_sub import Base64SubParser
from fns.parsers.clash_yaml import ClashYamlParser
from fns.parsers.proxy_uri import ProxyUriParser
from fns.parsers.singbox import SingBoxParser
from fns.parsers.sip008 import Sip008Parser

logger = logging.getLogger("fns")

URI_PREFIXES = (
    "vmess://",
    "vless://",
    "ss://",
    "ssr://",
    "trojan://",
    "hysteria://",
    "hysteria2://",
    "hy2://",
    "tuic://",
    "anytls://",
    "http://",
    "socks5://",
    "socks://",
)

_STRONG_PROXY_PREFIXES = (
    "vmess://",
    "vless://",
    "ss://",
    "ssr://",
    "trojan://",
    "hysteria://",
    "hysteria2://",
    "hy2://",
    "tuic://",
    "anytls://",
)


def _is_strict_http_proxy_line(line: str) -> bool:
    """True for http://host:port proxy-list lines (no path/query)."""
    if not line.lower().startswith("http://"):
        return False
    try:
        parsed = urlsplit(line)
    except ValueError:
        return False
    return (
        bool(parsed.hostname)
        and parsed.port is not None
        and parsed.path in ("", "/")
        and not parsed.query
    )


def _looks_like_proxy_list(clean: str) -> bool:
    """Detect proxy lists that start with comments/tg:// or mix schemes."""
    lines = [line.strip() for line in clean.splitlines() if line.strip()][:50]
    if not lines:
        return False
    if any(line.lower().startswith(_STRONG_PROXY_PREFIXES) for line in lines):
        return True
    return sum(1 for line in lines if _is_strict_http_proxy_line(line)) >= 3


def detect_format(text: str) -> tuple[str, object]:
    """Sniff format of raw content. Returns (parser_name, pre_parsed_data).

    pre_parsed_data is returned so parsers can avoid re-parsing (e.g. YAML).
    """
    clean = text.strip()
    if not clean:
        return "unknown", None

    # 1. Proxy URI lines
    if any(clean.startswith(p) for p in URI_PREFIXES):
        return "proxy_uri", None

    # 2. Clash YAML — parse once, reuse result
    decoded_b64 = Base64SubParser.try_decode(clean)
    if decoded_b64 is not None and Base64SubParser.is_subscription_text(decoded_b64):
        return "base64_sub", decoded_b64

    try:
        data = yaml.safe_load(clean)
        if isinstance(data, dict) and "outbounds" in data:
            return "singbox", data
        if isinstance(data, dict) and ("proxies" in data or "port" in data):
            return "clash_yaml", data
    except yaml.YAMLError:
        pass

    # 4. SIP008
    if Sip008Parser.can_parse(clean):
        return "sip008", None

    # 5. Check for proxy URI lines mixed in text (e.g. leading tg:// lines)
    if _looks_like_proxy_list(clean):
        return "proxy_uri", None

    return "unknown", None


_PARSERS = {
    "proxy_uri": ProxyUriParser(),
    "base64_sub": Base64SubParser(),
    "clash_yaml": ClashYamlParser(),
    "sip008": Sip008Parser(),
    "singbox": SingBoxParser(),
}


def parse_auto(text: str, source: str = "") -> ParseResult:
    """Detect format and parse with the correct parser."""
    fmt, pre_parsed = detect_format(text)
    parser = _PARSERS.get(fmt)
    if parser is None:
        return ParseResult(errors=[f"Unknown format for content from {source}"])
    logger.debug(f"Detected format: {fmt} for {source}")
    return parser.parse(text, source, pre_parsed=pre_parsed)
