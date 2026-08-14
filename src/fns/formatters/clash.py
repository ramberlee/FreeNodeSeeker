"""
Format proxy nodes into Clash Meta (Mihomo) YAML configuration.
"""

from __future__ import annotations

import yaml

from fns.config import ClashOutputConfig
from fns.models import ProxyNode, ProxyType
from fns.utils.geo import country_cn_name, country_flag, detect_country_code

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

_MASTER_GROUP = "\U0001f680 节点选择"
_AUTO_GROUP = "\u26a1 自动最快"
_SCORE_GROUP = "综合打分"
_OTHER_GROUP = "\U0001f30d 其他"
_UNKNOWN_GROUP = "\U0001f3f3\ufe0f 未标注"
_TEST_URL = "https://www.youtube.com/generate_204"


def _group_interval(member_count: int) -> int:
    """Use 120s for large groups and 60s otherwise."""
    return 120 if member_count >= 100 else 60


def _url_test_group(name: str, members: list[str], interval: int) -> dict:
    return {
        "name": name,
        "type": "url-test",
        "proxies": members,
        "url": _TEST_URL,
        "interval": interval,
    }


def node_to_clash_proxy(node: ProxyNode) -> dict:
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
        if node.transport == "grpc" and node.grpc_service_name:
            proxy["grpc-opts"] = {"grpc-service-name": node.grpc_service_name}

    elif node.node_type == ProxyType.VLESS:
        proxy["uuid"] = node.uuid or ""
        proxy["tls"] = node.tls
        proxy["sni"] = node.sni or ""
        proxy["fingerprint"] = node.fingerprint or ""
        proxy["network"] = node.transport or "tcp"
        proxy["servername"] = node.sni or ""
        proxy["flow"] = node.flow or ""
        if node.skip_cert_verify:
            proxy["skip-cert-verify"] = True
        if node.public_key:
            reality_opts = {"public-key": node.public_key}
            if node.short_id:
                reality_opts["short-id"] = node.short_id
            if node.fingerprint:
                reality_opts["fingerprint"] = node.fingerprint
            proxy["reality-opts"] = reality_opts
        if node.transport == "ws":
            proxy["ws-opts"] = {
                "path": node.ws_path or "/",
                "headers": {"Host": node.ws_host or node.address},
            }
        if node.transport == "grpc" and node.grpc_service_name:
            proxy["grpc-opts"] = {"grpc-service-name": node.grpc_service_name}

    elif node.node_type == ProxyType.SS:
        proxy["cipher"] = node.method or "aes-256-gcm"
        proxy["password"] = node.password or ""
        proxy["plugin"] = node.plugin or ""
        proxy["plugin-opts"] = node.plugin_opts or {}

    elif node.node_type == ProxyType.TROJAN:
        proxy["password"] = node.password or ""
        proxy["tls"] = node.tls
        proxy["sni"] = node.sni or ""
        proxy["fingerprint"] = node.fingerprint or ""
        proxy["network"] = node.transport or "tcp"
        if node.skip_cert_verify or not node.tls:
            proxy["skip-cert-verify"] = True
        if node.transport == "ws":
            proxy["ws-opts"] = {
                "path": node.ws_path or "/",
                "headers": {"Host": node.ws_host or node.address},
            }
        if node.transport == "grpc" and node.grpc_service_name:
            proxy["grpc-opts"] = {"grpc-service-name": node.grpc_service_name}

    elif node.node_type == ProxyType.HYSTERIA2:
        proxy["password"] = node.password or ""
        proxy["sni"] = node.sni or ""
        proxy["skip-cert-verify"] = node.skip_cert_verify or not node.tls
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
        proxy["skip-cert-verify"] = node.skip_cert_verify or not node.tls
        if node.congestion_control:
            proxy["congestion-controller"] = node.congestion_control
        if node.udp_relay_mode:
            proxy["udp-relay-mode"] = node.udp_relay_mode

    elif node.node_type in (ProxyType.HTTP, ProxyType.SOCKS5):
        if node.username:
            proxy["username"] = node.username
        if node.password:
            proxy["password"] = node.password

    return proxy


def format_clash(nodes: list[ProxyNode], cfg: ClashOutputConfig) -> str:
    """Generate a Clash Meta YAML config string."""
    proxies = [node_to_clash_proxy(n) for n in nodes]
    proxy_names = [p["name"] for p in proxies]

    country_of: dict[str, str | None] = {}
    counts: dict[str | None, int] = {}
    for node, name in zip(nodes, proxy_names):
        code = detect_country_code(node)
        country_of[name] = code
        counts[code] = counts.get(code, 0) + 1

    members_by_country: dict[str, list[str]] = {}
    other_members: list[str] = []
    unknown_members: list[str] = []
    for name in proxy_names:
        code = country_of[name]
        if code is None:
            unknown_members.append(name)
        elif counts[code] >= 3:
            members_by_country.setdefault(code, []).append(name)
        else:
            other_members.append(name)

    groups = [
        _url_test_group(_AUTO_GROUP, proxy_names, 300),
        {"name": _SCORE_GROUP, "type": "select", "proxies": proxy_names},
    ]
    group_names = [_AUTO_GROUP, _SCORE_GROUP]
    for code in sorted(members_by_country):
        members = members_by_country[code]
        name = f"{country_flag(code)} {country_cn_name(code)}·{len(members)}"
        groups.append(_url_test_group(name, members, _group_interval(len(members))))
        group_names.append(name)
    if other_members:
        groups.append(
            _url_test_group(_OTHER_GROUP, other_members, _group_interval(len(other_members)))
        )
        group_names.append(_OTHER_GROUP)
    if unknown_members:
        groups.append(
            _url_test_group(_UNKNOWN_GROUP, unknown_members, _group_interval(len(unknown_members)))
        )
        group_names.append(_UNKNOWN_GROUP)

    master = {
        "name": _MASTER_GROUP,
        "type": "select",
        "proxies": [_AUTO_GROUP, _SCORE_GROUP, "DIRECT"] + group_names[2:] + proxy_names,
    }

    config = {
        "allow-lan": cfg.allow_lan,
        "mode": cfg.mode,
        "log-level": cfg.log_level,
        "geodata-mode": True,
        "proxies": proxies,
        "proxy-groups": [master] + groups,
        "rules": [
            "IP-CIDR,127.0.0.0/8,DIRECT",
            "IP-CIDR,10.0.0.0/8,DIRECT",
            "IP-CIDR,172.16.0.0/12,DIRECT",
            "IP-CIDR,192.168.0.0/16,DIRECT",
            "IP-CIDR6,::1/128,DIRECT",
            "IP-CIDR6,fc00::/7,DIRECT",
            "IP-CIDR6,fe80::/10,DIRECT",
            "GEOIP,CN,DIRECT",
            f"MATCH,{_MASTER_GROUP}",
        ],
    }

    return yaml.dump(config, allow_unicode=True, default_flow_style=False, sort_keys=False)
