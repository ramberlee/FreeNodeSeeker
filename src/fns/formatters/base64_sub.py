"""
Format proxy nodes into base64-encoded subscription URI strings.
"""

from __future__ import annotations

import base64
import json
from urllib.parse import quote

from fns.models import ProxyNode, ProxyType
from fns.utils.crypto import safe_b64encode


def _node_to_uri(node: ProxyNode) -> str:
    """Convert a ProxyNode to a proxy URI string."""
    if node.node_type == ProxyType.VMESS:
        return _to_vmess_uri(node)
    elif node.node_type == ProxyType.VLESS:
        return _to_vless_uri(node)
    elif node.node_type == ProxyType.SS:
        return _to_ss_uri(node)
    elif node.node_type == ProxyType.TROJAN:
        return _to_trojan_uri(node)
    elif node.node_type == ProxyType.HYSTERIA2:
        return _to_hysteria2_uri(node)
    elif node.node_type == ProxyType.TUIC:
        return _to_tuic_uri(node)
    return ""


def _to_vmess_uri(node: ProxyNode) -> str:
    cfg = {
        "v": "2",
        "ps": node.remark or f"{node.address}:{node.port}",
        "add": node.address,
        "port": str(node.port),
        "id": node.uuid or "",
        "aid": "0",
        "scy": node.encryption or "auto",
        "net": node.transport or "tcp",
        "type": "none",
        "host": node.ws_host or "",
        "path": node.ws_path or "",
        "tls": "tls" if node.tls else "",
        "sni": node.sni or "",
        "fp": node.fingerprint or "",
    }
    encoded = safe_b64encode(json.dumps(cfg, separators=(",", ":")).encode("utf-8"))
    return f"vmess://{encoded}"


def _to_vless_uri(node: ProxyNode) -> str:
    params = []
    if node.encryption and node.encryption != "none":
        params.append(f"encryption={quote(node.encryption)}")
    if node.flow:
        params.append(f"flow={quote(node.flow)}")
    if node.transport and node.transport != "tcp":
        params.append(f"type={quote(node.transport)}")
    if node.ws_path:
        params.append(f"path={quote(node.ws_path)}")
    if node.ws_host:
        params.append(f"host={quote(node.ws_host)}")
    if node.tls:
        security = "reality" if node.public_key else "tls"
        params.append(f"security={security}")
    if node.sni:
        params.append(f"sni={quote(node.sni)}")
    if node.fingerprint:
        params.append(f"fp={quote(node.fingerprint)}")
    if node.public_key:
        params.append(f"pbk={quote(node.public_key)}")
    if node.short_id:
        params.append(f"sid={quote(node.short_id)}")

    qs = "&".join(params)
    base = f"vless://{node.uuid or ''}@{node.address}:{node.port}"
    if qs:
        base += f"?{qs}"
    if node.remark:
        base += f"#{quote(node.remark)}"
    return base


def _to_ss_uri(node: ProxyNode) -> str:
    userinfo = safe_b64encode(
        f"{node.method or 'aes-256-gcm'}:{node.password or ''}".encode("utf-8")
    )
    uri = f"ss://{userinfo}@{node.address}:{node.port}"
    if node.remark:
        uri += f"#{quote(node.remark)}"
    return uri


def _to_trojan_uri(node: ProxyNode) -> str:
    params = []
    if node.transport and node.transport != "tcp":
        params.append(f"type={quote(node.transport)}")
    if node.ws_path:
        params.append(f"path={quote(node.ws_path)}")
    if node.ws_host:
        params.append(f"host={quote(node.ws_host)}")
    if node.tls:
        params.append("security=tls")
    if node.sni:
        params.append(f"sni={quote(node.sni)}")
    if node.fingerprint:
        params.append(f"fp={quote(node.fingerprint)}")

    qs = "&".join(params)
    base = f"trojan://{node.password or ''}@{node.address}:{node.port}"
    if qs:
        base += f"?{qs}"
    if node.remark:
        base += f"#{quote(node.remark)}"
    return base


def _to_hysteria2_uri(node: ProxyNode) -> str:
    params = []
    if not node.tls:
        params.append("insecure=1")
    if node.sni:
        params.append(f"sni={quote(node.sni)}")
    if node.obfs:
        params.append(f"obfs={quote(node.obfs)}")
    if node.obfs_password:
        params.append(f"obfs-password={quote(node.obfs_password)}")
    if node.up_speed is not None:
        params.append(f"up={node.up_speed}")
    if node.down_speed is not None:
        params.append(f"down={node.down_speed}")

    qs = "&".join(params)
    base = f"hysteria2://{node.password or ''}@{node.address}:{node.port}"
    if qs:
        base += f"?{qs}"
    if node.remark:
        base += f"#{quote(node.remark)}"
    return base


def _to_tuic_uri(node: ProxyNode) -> str:
    userinfo = f"{node.uuid or ''}"
    if node.password:
        userinfo += f":{node.password}"

    params = []
    if node.sni:
        params.append(f"sni={quote(node.sni)}")
    if not node.tls:
        params.append("insecure=1")
    if node.congestion_control:
        params.append(f"congestion_control={quote(node.congestion_control)}")
    if node.udp_relay_mode:
        params.append(f"udp_relay_mode={quote(node.udp_relay_mode)}")

    qs = "&".join(params)
    base = f"tuic://{userinfo}@{node.address}:{node.port}"
    if qs:
        base += f"?{qs}"
    if node.remark:
        base += f"#{quote(node.remark)}"
    return base


def format_base64_sub(nodes: list[ProxyNode]) -> str:
    """Generate a base64-encoded subscription string (one URI per line)."""
    if not nodes:
        return ""
    lines = [_node_to_uri(n) for n in nodes]
    lines = [l for l in lines if l]
    if not lines:
        return ""
    content = "\n".join(lines)
    return base64.b64encode(content.encode("utf-8")).decode("ascii")
