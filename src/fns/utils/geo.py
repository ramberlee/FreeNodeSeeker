"""Country detection for proxy nodes.

Node remarks are parsed first (flag emoji, Chinese country names, ISO codes,
common English aliases). When that fails, the server IP is looked up with a
local GeoLite2 Country database when one is available.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from pathlib import Path

logger = logging.getLogger("fns")

# ISO 3166-1 alpha-2 -> Chinese display name
COUNTRY_CN = {
    "CN": "中国",
    "HK": "香港",
    "MO": "澳门",
    "TW": "台湾",
    "JP": "日本",
    "KR": "韩国",
    "KP": "朝鲜",
    "SG": "新加坡",
    "MY": "马来西亚",
    "TH": "泰国",
    "VN": "越南",
    "PH": "菲律宾",
    "ID": "印度尼西亚",
    "IN": "印度",
    "PK": "巴基斯坦",
    "BD": "孟加拉国",
    "LK": "斯里兰卡",
    "NP": "尼泊尔",
    "MM": "缅甸",
    "KH": "柬埔寨",
    "LA": "老挝",
    "BN": "文莱",
    "TL": "东帝汶",
    "MN": "蒙古",
    "US": "美国",
    "CA": "加拿大",
    "MX": "墨西哥",
    "BR": "巴西",
    "AR": "阿根廷",
    "CL": "智利",
    "PE": "秘鲁",
    "CO": "哥伦比亚",
    "VE": "委内瑞拉",
    "UY": "乌拉圭",
    "EC": "厄瓜多尔",
    "BO": "玻利维亚",
    "GB": "英国",
    "FR": "法国",
    "DE": "德国",
    "IT": "意大利",
    "ES": "西班牙",
    "PT": "葡萄牙",
    "NL": "荷兰",
    "BE": "比利时",
    "CH": "瑞士",
    "AT": "奥地利",
    "SE": "瑞典",
    "NO": "挪威",
    "DK": "丹麦",
    "FI": "芬兰",
    "IE": "爱尔兰",
    "PL": "波兰",
    "CZ": "捷克",
    "SK": "斯洛伐克",
    "HU": "匈牙利",
    "RO": "罗马尼亚",
    "BG": "保加利亚",
    "GR": "希腊",
    "HR": "克罗地亚",
    "RS": "塞尔维亚",
    "SI": "斯洛文尼亚",
    "TR": "土耳其",
    "RU": "俄罗斯",
    "UA": "乌克兰",
    "BY": "白俄罗斯",
    "EE": "爱沙尼亚",
    "LV": "拉脱维亚",
    "LT": "立陶宛",
    "AU": "澳大利亚",
    "NZ": "新西兰",
    "SA": "沙特阿拉伯",
    "AE": "阿联酋",
    "QA": "卡塔尔",
    "KW": "科威特",
    "IL": "以色列",
    "IR": "伊朗",
    "IQ": "伊拉克",
    "OM": "阿曼",
    "JO": "约旦",
    "LB": "黎巴嫩",
    "AZ": "阿塞拜疆",
    "GE": "格鲁吉亚",
    "KZ": "哈萨克斯坦",
    "UZ": "乌兹别克斯坦",
    "AM": "亚美尼亚",
    "EG": "埃及",
    "ZA": "南非",
    "NG": "尼日利亚",
    "KE": "肯尼亚",
    "MA": "摩洛哥",
    "DZ": "阿尔及利亚",
    "ET": "埃塞俄比亚",
    "GH": "加纳",
    "TZ": "坦桑尼亚",
    "UG": "乌干达",
    "ZW": "津巴布韦",
    "FJ": "斐济",
}

CN_TO_CODE = {name: code for code, name in COUNTRY_CN.items()}

# Common English aliases found in node remarks, mapped to ISO codes
EN_ALIASES = {
    "hongkong": "HK",
    "hong kong": "HK",
    "taiwan": "TW",
    "japan": "JP",
    "korea": "KR",
    "singapore": "SG",
    "malaysia": "MY",
    "thailand": "TH",
    "vietnam": "VN",
    "philippines": "PH",
    "indonesia": "ID",
    "india": "IN",
    "russia": "RU",
    "germany": "DE",
    "france": "FR",
    "united kingdom": "GB",
    "uk": "GB",
    "usa": "US",
    "united states": "US",
    "canada": "CA",
    "australia": "AU",
    "new zealand": "NZ",
    "netherlands": "NL",
    "italy": "IT",
    "spain": "ES",
    "brazil": "BR",
    "turkey": "TR",
    "ukraine": "UA",
    "poland": "PL",
    "sweden": "SE",
    "norway": "NO",
    "denmark": "DK",
    "finland": "FI",
    "switzerland": "CH",
    "austria": "AT",
    "belgium": "BE",
    "portugal": "PT",
    "ireland": "IE",
    "greece": "GR",
    "czech": "CZ",
    "hungary": "HU",
    "romania": "RO",
    "bulgaria": "BG",
    "south africa": "ZA",
    "egypt": "EG",
    "israel": "IL",
    "saudi arabia": "SA",
    "uae": "AE",
    "emirates": "AE",
    "kazakhstan": "KZ",
    "mongolia": "MN",
    "mexico": "MX",
    "argentina": "AR",
    "chile": "CL",
    "colombia": "CO",
    "peru": "PE",
}

_FLAG_RE = re.compile("[\U0001F1E6-\U0001F1FF]{2}")
_ISO_RE = re.compile(r"\b([A-Za-z]{2})\b")

_DB_PATH = Path(__file__).resolve().parent.parent.parent.parent / "bin" / "geolite2-country.mmdb"
_reader = None
_geoip_cache: dict[str, str | None] = {}
_geoip_warned = False


def country_flag(code: str) -> str:
    """Return the flag emoji for a two-letter ISO country code."""
    return "".join(chr(0x1F1E6 + ord(c.upper()) - ord("A")) for c in code)


def country_cn_name(code: str) -> str:
    """Return the Chinese display name for a country code."""
    return COUNTRY_CN.get(code.upper(), code.upper())


def country_code_from_name(remark: str) -> str | None:
    """Detect a country code from a node remark."""
    if not remark:
        return None

    for flag in _FLAG_RE.findall(remark):
        code = "".join(chr(ord(c) - 0x1F1E6 + ord("A")) for c in flag)
        if code in COUNTRY_CN:
            return code

    for code, name in COUNTRY_CN.items():
        if name in remark:
            return code

    for token in _ISO_RE.findall(remark):
        code = token.upper()
        if code in COUNTRY_CN:
            return code

    low = remark.lower()
    for alias, code in EN_ALIASES.items():
        if re.search(rf"\b{re.escape(alias)}\b", low):
            return code
    return None


def geoip_country_code(address: str) -> str | None:
    """Look up a country code for an IP using a local GeoLite2 database."""
    global _reader, _geoip_warned

    if address in _geoip_cache:
        return _geoip_cache[address]

    try:
        ipaddress.ip_address(address)
    except ValueError:
        _geoip_cache[address] = None
        return None

    if _reader is None:
        try:
            import maxminddb
        except ImportError:
            if not _geoip_warned:
                logger.warning("maxminddb not installed; GeoIP fallback disabled")
                _geoip_warned = True
            return None
        if not _DB_PATH.exists():
            if not _geoip_warned:
                logger.warning(
                    "GeoLite2 Country DB not found at %s; GeoIP fallback disabled",
                    _DB_PATH,
                )
                _geoip_warned = True
            return None
        try:
            _reader = maxminddb.open_database(str(_DB_PATH))
        except Exception as e:
            if not _geoip_warned:
                logger.warning("Failed to open GeoLite2 Country DB: %s", e)
                _geoip_warned = True
            return None

    try:
        result = _reader.get(address)
        code = (result or {}).get("country", {}).get("iso_code")
    except Exception:
        code = None
    _geoip_cache[address] = code
    return code


def detect_country_code(node) -> str | None:
    """Detect a node's country code: remark first, GeoIP as fallback."""
    code = country_code_from_name(node.remark or "")
    if code:
        return code
    return geoip_country_code(node.address)
