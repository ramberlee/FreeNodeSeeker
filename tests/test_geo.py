"""Test country detection for Clash policy grouping."""

from fns.models import ProxyNode, ProxyType
from fns.utils import geo


class TestCountryCodeFromName:
    def test_flag_emoji(self):
        assert geo.country_code_from_name("\U0001f1ef\U0001f1f5 东京") == "JP"
        assert geo.country_code_from_name("\U0001f1f0\U0001f1f7 首尔") == "KR"

    def test_chinese_name(self):
        assert geo.country_code_from_name("美国节点 01") == "US"
        assert geo.country_code_from_name("香港 - HKT") == "HK"

    def test_iso_code(self):
        assert geo.country_code_from_name("HK 01") == "HK"
        assert geo.country_code_from_name("SG - 新加坡") == "SG"

    def test_english_alias(self):
        assert geo.country_code_from_name("hongkong") == "HK"
        assert geo.country_code_from_name("Singapore 02") == "SG"

    def test_unknown(self):
        assert geo.country_code_from_name("Free Node 001") is None
        assert geo.country_code_from_name("") is None


class TestDetectCountryCode:
    def test_name_takes_priority(self, monkeypatch):
        node = ProxyNode(
            node_type=ProxyType.SS,
            address="1.1.1.1",
            port=8388,
            remark="\U0001f1ef\U0001f1f5 东京",
        )
        monkeypatch.setattr(geo, "geoip_country_code", lambda ip: "US")
        assert geo.detect_country_code(node) == "JP"

    def test_geoip_fallback(self, monkeypatch):
        node = ProxyNode(
            node_type=ProxyType.SS,
            address="1.2.3.4",
            port=8388,
            remark="No Country Info",
        )
        monkeypatch.setattr(geo, "country_code_from_name", lambda remark: None)
        monkeypatch.setattr(geo, "geoip_country_code", lambda ip: "DE")
        assert geo.detect_country_code(node) == "DE"

    def test_geoip_skips_domains(self):
        assert geo.geoip_country_code("example.com") is None


class TestDisplay:
    def test_country_flag(self):
        assert geo.country_flag("JP") == "\U0001f1ef\U0001f1f5"

    def test_country_cn_name(self):
        assert geo.country_cn_name("US") == "美国"
        assert geo.country_cn_name("XX") == "XX"
