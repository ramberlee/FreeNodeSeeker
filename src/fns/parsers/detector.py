"""
Format detector — sniff RawContent format and route to the correct parser.
"""

from __future__ import annotations

import logging

import yaml

from fns.parsers.base import ParseResult
from fns.parsers.base64_sub import Base64SubParser
from fns.parsers.clash_yaml import ClashYamlParser
from fns.parsers.proxy_uri import ProxyUriParser
from fns.parsers.sip008 import Sip008Parser

logger = logging.getLogger("fns")

URI_PREFIXES = ("vmess://", "vless://", "ss://", "trojan://", "hysteria2://", "hy2://", "tuic://")


def detect_format(text: str) -> str:
    """Sniff format of raw content. Returns parser name string."""
    clean = text.strip()
    if not clean:
        return "unknown"

    # 1. Proxy URI lines
    if any(clean.startswith(p) for p in URI_PREFIXES):
        return "proxy_uri"

    # 2. Clash YAML
    try:
        data = yaml.safe_load(clean)
        if isinstance(data, dict) and ("proxies" in data or "port" in data):
            return "clash_yaml"
    except yaml.YAMLError:
        pass

    # 3. Base64 subscription
    if Base64SubParser.can_parse(clean):
        return "base64_sub"

    # 4. SIP008
    if Sip008Parser.can_parse(clean):
        return "sip008"

    # 5. Check for URI lines mixed in text
    for line in clean.splitlines()[:5]:
        if line.strip().startswith(URI_PREFIXES):
            return "proxy_uri"

    return "unknown"


_PARSERS = {
    "proxy_uri": ProxyUriParser(),
    "base64_sub": Base64SubParser(),
    "clash_yaml": ClashYamlParser(),
    "sip008": Sip008Parser(),
}


def parse_auto(text: str, source: str = "") -> ParseResult:
    """Detect format and parse with the correct parser."""
    fmt = detect_format(text)
    parser = _PARSERS.get(fmt)
    if parser is None:
        return ParseResult(errors=[f"Unknown format for content from {source}"])
    logger.debug(f"Detected format: {fmt} for {source}")
    return parser.parse(text, source)
