from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class ProxyType(str, Enum):
    VMESS = "vmess"
    VLESS = "vless"
    SS = "ss"
    TROJAN = "trojan"
    HYSTERIA2 = "hysteria2"
    TUIC = "tuic"
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

    # Protocol params
    method: str | None = None
    encryption: str | None = None
    flow: str | None = None

    # Transport
    transport: str | None = None  # tcp, ws, grpc, quic, h2
    ws_path: str | None = None
    ws_host: str | None = None

    # TLS / Reality
    tls: bool = False
    sni: str | None = None
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

    # Quality
    latency_ms: float | None = None
    is_alive: bool = False

    # Metadata
    source: str | None = None
    remark: str | None = None

    @property
    def key(self) -> tuple[str, int, str]:
        return (self.address, self.port, self.node_type.value)


@dataclass
class PipelineResult:
    nodes: list[ProxyNode]
    sources_used: int
    parse_errors: list[str] = field(default_factory=list)
    alive_count: int = 0
