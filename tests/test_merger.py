"""Test merger deduplication and merging logic."""

from fns.merger import deduplicate, merge_sources
from fns.models import ProxyType


class TestDeduplicate:
    def test_no_dupes(self, sample_vmess_node, sample_ss_node):
        result = deduplicate([sample_vmess_node, sample_ss_node])
        assert len(result) == 2

    def test_dedupe_same_addr_port_type(self, sample_ss_node, sample_ss_node_2):
        # These have same address:port:type but different password
        result = deduplicate([sample_ss_node, sample_ss_node_2])
        assert len(result) == 1
        # First one wins
        assert result[0].password == "test123"

    def test_no_dedupe_different_type(self, sample_vmess_node):
        other = sample_vmess_node
        other2 = type(other)(
            node_type=ProxyType.VLESS,
            address=other.address,
            port=other.port,
            uuid=other.uuid,
        )
        result = deduplicate([other, other2])
        assert len(result) == 2

    def test_no_dedupe_different_port(self, sample_vmess_node):
        other = type(sample_vmess_node)(
            node_type=sample_vmess_node.node_type,
            address=sample_vmess_node.address,
            port=8443,
            uuid=sample_vmess_node.uuid,
        )
        result = deduplicate([sample_vmess_node, other])
        assert len(result) == 2


class TestMergeSources:
    def test_merge_basic(self, sample_vmess_node, sample_ss_node, sample_trojan_node):
        sources = {
            "src_a": [sample_vmess_node],
            "src_b": [sample_ss_node, sample_trojan_node],
        }
        result = merge_sources(sources)
        assert len(result) == 3

    def test_merge_dedupe_across_sources(self, sample_ss_node, sample_ss_node_2):
        sources = {
            "src_a": [sample_ss_node],
            "src_b": [sample_ss_node_2],  # Same addr:port:type
        }
        result = merge_sources(sources)
        assert len(result) == 1

    def test_merge_alive_preferred(self, sample_vmess_node, sample_ss_node):
        sample_vmess_node.is_alive = True
        sample_vmess_node.latency_ms = 50
        sample_ss_node.is_alive = False
        sample_ss_node.latency_ms = None

        sources = {"src": [sample_ss_node, sample_vmess_node]}
        result = merge_sources(sources, prefer_alive=True)
        assert result[0].is_alive is True

    def test_merge_max_total(self, sample_vmess_node, sample_ss_node, sample_trojan_node):
        sources = {"src": [sample_vmess_node, sample_ss_node, sample_trojan_node]}
        result = merge_sources(sources, max_total=2)
        assert len(result) == 2
