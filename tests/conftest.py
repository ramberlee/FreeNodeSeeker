import pytest
from fns.models import ProxyNode, ProxyType


@pytest.fixture
def sample_vmess_node():
    return ProxyNode(
        node_type=ProxyType.VMESS,
        address="1.2.3.4",
        port=443,
        uuid="b831381d-6324-4d53-ad4f-8cda48b30811",
        encryption="auto",
        transport="ws",
        ws_path="/path",
        ws_host="example.com",
        tls=True,
        sni="example.com",
        remark="Test VMess",
    )


@pytest.fixture
def sample_ss_node():
    return ProxyNode(
        node_type=ProxyType.SS,
        address="5.6.7.8",
        port=8388,
        password="test123",
        method="aes-256-gcm",
        remark="Test SS",
    )


@pytest.fixture
def sample_ss_node_2():
    return ProxyNode(
        node_type=ProxyType.SS,
        address="5.6.7.8",
        port=8388,
        password="test456",
        method="chacha20-ietf-poly1305",
        remark="Test SS Duplicate",
    )


@pytest.fixture
def sample_trojan_node():
    return ProxyNode(
        node_type=ProxyType.TROJAN,
        address="trojan.example.com",
        port=443,
        password="trojan-password",
        transport="tcp",
        tls=True,
        sni="trojan.example.com",
        remark="Test Trojan",
    )


@pytest.fixture
def sample_vless_node():
    return ProxyNode(
        node_type=ProxyType.VLESS,
        address="vless.example.com",
        port=443,
        uuid="b831381d-6324-4d53-ad4f-8cda48b30811",
        encryption="none",
        flow="xtls-rprx-vision",
        transport="tcp",
        tls=True,
        sni="vless.example.com",
        public_key="qwerty123",
        short_id="abcd",
        remark="Test VLESS Reality",
    )


@pytest.fixture
def sample_hysteria2_node():
    return ProxyNode(
        node_type=ProxyType.HYSTERIA2,
        address="hy2.example.com",
        port=443,
        password="hy2-pass",
        tls=True,
        sni="hy2.example.com",
        obfs="salamander",
        obfs_password="obfs-pass",
        up_speed=50,
        down_speed=200,
        remark="Test Hysteria2",
    )


@pytest.fixture
def sample_tuic_node():
    return ProxyNode(
        node_type=ProxyType.TUIC,
        address="tuic.example.com",
        port=443,
        uuid="b831381d-6324-4d53-ad4f-8cda48b30811",
        password="tuic-pass",
        tls=True,
        sni="tuic.example.com",
        congestion_control="bbr",
        udp_relay_mode="native",
        remark="Test TUIC",
    )


@pytest.fixture
def all_sample_nodes(
    sample_vmess_node, sample_ss_node, sample_ss_node_2,
    sample_trojan_node, sample_vless_node, sample_hysteria2_node, sample_tuic_node,
):
    return [
        sample_vmess_node, sample_ss_node, sample_ss_node_2,
        sample_trojan_node, sample_vless_node, sample_hysteria2_node, sample_tuic_node,
    ]


@pytest.fixture
def dead_node():
    return ProxyNode(
        node_type=ProxyType.VMESS,
        address="192.0.2.1",
        port=9999,
        uuid="dead-dead-dead-dead-dead",
        remark="Dead Node",
    )
