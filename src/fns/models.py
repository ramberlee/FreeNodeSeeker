from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


def normalize_address(address: str) -> str:
    """Return a bare host/IP, stripping IPv6 brackets (``[::1]`` -> ``::1``)."""
    if address.startswith("[") and address.endswith("]"):
        return address[1:-1]
    return address


def format_host_port(host: str, port: int) -> str:
    """Build host:port, bracketing IPv6 addresses for use in URLs and URIs."""
    host = normalize_address(host)
    if ":" in host:
        return f"[{host}]:{port}"
    return f"{host}:{port}"


def normalize_transport(transport: str | None) -> str | None:
    """Normalize transport names; v2ray's raw transport means plain TCP."""
    if transport is None:
        return None
    normalized = transport.strip().lower()
    return "tcp" if normalized == "raw" else normalized


class ProxyType(str, Enum):
    VMESS = "vmess"
    VLESS = "vless"
    SS = "ss"
    SSR = "ssr"
    TROJAN = "trojan"
    HYSTERIA = "hysteria"
    HYSTERIA2 = "hysteria2"
    TUIC = "tuic"
    ANYTLS = "anytls"
    MIERU = "mieru"
    HTTP = "http"
    SOCKS5 = "socks5"


@dataclass
class ProxyNode:
    node_type: ProxyType
    address: str
    port: int

    # Auth
    uuid: str | None = None
    password: str | None = None
    username: str | None = None

    # Protocol params
    method: str | None = None
    encryption: str | None = None
    flow: str | None = None
    plugin: str | None = None
    plugin_opts: dict | None = None
    grpc_service_name: str | None = None

    # Transport
    transport: str | None = None  # tcp, ws, grpc, quic, h2
    ws_path: str | None = None
    ws_host: str | None = None

    # TLS / Reality
    tls: bool = False
    sni: str | None = None
    skip_cert_verify: bool = False
    fingerprint: str | None = None
    public_key: str | None = None
    short_id: str | None = None

    # Hysteria2 / TUIC specific
    obfs: str | None = None
    obfs_password: str | None = None
    up_speed: int | None = None
    down_speed: int | None = None
    congestion_control: str | None = None
    udp_relay_mode: str | None = None

    # SSR specific
    protocol: str | None = None
    protocol_param: str | None = None
    obfs_param: str | None = None

    # Mieru specific
    mieru_transport: str | None = None

    # Quality
    latency_ms: float | None = None
    is_alive: bool = False
    validation_error: str | None = None

    # Metadata
    source: str | None = None
    remark: str | None = None

    @property
    def key(self) -> tuple[str, int, str]:
        return (self.address, self.port, self.node_type.value)


def effective_sni(node: ProxyNode) -> str:
    """Return the TLS SNI, falling back to the WS Host header for TLS+WS nodes."""
    if node.sni:
        return node.sni
    if (
        node.tls
        and node.transport in ("ws", "http", "httpupgrade", "h2")
        and node.ws_host
    ):
        return node.ws_host
    return ""


@dataclass
class PipelineResult:
    nodes: list[ProxyNode]
    sources_used: int
    parse_errors: list[str] = field(default_factory=list)
    alive_count: int = 0
