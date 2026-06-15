"""
Format proxy nodes into Clash Meta (Mihomo) YAML configuration.
"""

from __future__ import annotations

import yaml

from fns.config import ClashOutputConfig
from fns.models import ProxyNode, ProxyType

_CLASH_TYPE = {
    ProxyType.VMESS: "vmess",
    ProxyType.VLESS: "vless",
    ProxyType.SS: "ss",
    ProxyType.TROJAN: "trojan",
    ProxyType.HYSTERIA2: "hysteria2",
    ProxyType.TUIC: "tuic",
    ProxyType.HTTP: "http",
    ProxyType.SOCKS5: "socks5",
}


def _node_to_clash_proxy(node: ProxyNode) -> dict:
    """Convert a ProxyNode to a Clash proxy dict."""
    proxy = {
        "name": node.remark or f"{node.address}:{node.port}",
        "type": _CLASH_TYPE.get(node.node_type, "vmess"),
        "server": node.address,
        "port": node.port,
    }

    if node.node_type == ProxyType.VMESS:
        proxy["uuid"] = node.uuid or ""
        proxy["alterId"] = 0
        proxy["cipher"] = node.encryption or "auto"
        proxy["tls"] = node.tls
        proxy["sni"] = node.sni or ""
        proxy["fingerprint"] = node.fingerprint or ""
        proxy["network"] = node.transport or "tcp"
        if node.transport == "ws":
            proxy["ws-opts"] = {
                "path": node.ws_path or "/",
                "headers": {"Host": node.ws_host or node.address},
            }

    elif node.node_type == ProxyType.VLESS:
        proxy["uuid"] = node.uuid or ""
        proxy["tls"] = node.tls
        proxy["sni"] = node.sni or ""
        proxy["fingerprint"] = node.fingerprint or ""
        proxy["network"] = node.transport or "tcp"
        proxy["servername"] = node.sni or ""
        proxy["flow"] = node.flow or ""
        proxy["reality-opts"] = {}
        if node.public_key:
            proxy["reality-opts"]["public-key"] = node.public_key
        if node.short_id:
            proxy["reality-opts"]["short-id"] = node.short_id
        if node.fingerprint:
            proxy["reality-opts"]["fingerprint"] = node.fingerprint
        if node.transport == "ws":
            proxy["ws-opts"] = {
                "path": node.ws_path or "/",
                "headers": {"Host": node.ws_host or node.address},
            }
        if not proxy["reality-opts"]:
            del proxy["reality-opts"]

    elif node.node_type == ProxyType.SS:
        proxy["cipher"] = node.method or "aes-256-gcm"
        proxy["password"] = node.password or ""
        proxy["plugin"] = ""
        proxy["plugin-opts"] = {}

    elif node.node_type == ProxyType.TROJAN:
        proxy["password"] = node.password or ""
        proxy["tls"] = node.tls
        proxy["sni"] = node.sni or ""
        proxy["fingerprint"] = node.fingerprint or ""
        proxy["network"] = node.transport or "tcp"
        if node.transport == "ws":
            proxy["ws-opts"] = {
                "path": node.ws_path or "/",
                "headers": {"Host": node.ws_host or node.address},
            }

    elif node.node_type == ProxyType.HYSTERIA2:
        proxy["password"] = node.password or ""
        proxy["sni"] = node.sni or ""
        proxy["skip-cert-verify"] = not node.tls
        if node.obfs:
            proxy["obfs"] = node.obfs
        if node.obfs_password:
            proxy["obfs-password"] = node.obfs_password
        if node.up_speed is not None:
            proxy["up"] = node.up_speed
        if node.down_speed is not None:
            proxy["down"] = node.down_speed

    elif node.node_type == ProxyType.TUIC:
        proxy["uuid"] = node.uuid or ""
        proxy["password"] = node.password or ""
        proxy["sni"] = node.sni or ""
        proxy["skip-cert-verify"] = not node.tls
        if node.congestion_control:
            proxy["congestion-controller"] = node.congestion_control
        if node.udp_relay_mode:
            proxy["udp-relay-mode"] = node.udp_relay_mode

    return proxy


def format_clash(nodes: list[ProxyNode], cfg: ClashOutputConfig) -> str:
    """Generate a Clash Meta YAML config string."""
    proxies = [_node_to_clash_proxy(n) for n in nodes]
    proxy_names = [p["name"] for p in proxies]

    config = {
        "port": cfg.port,
        "socks-port": cfg.socks_port,
        "allow-lan": cfg.allow_lan,
        "mode": cfg.mode,
        "log-level": cfg.log_level,
        "proxies": proxies,
        "proxy-groups": [
            {
                "name": "\U0001f680 自动选择",
                "type": "url-test",
                "proxies": proxy_names,
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300,
            },
            {
                "name": "\U0001f3af 手动选择",
                "type": "select",
                "proxies": ["\U0001f680 自动选择"] + proxy_names,
            },
        ],
    }

    return yaml.dump(config, allow_unicode=True, default_flow_style=False, sort_keys=False)
