"""
Format proxy nodes into JSON output.
"""

from __future__ import annotations

import json

from fns.models import ProxyNode


def _node_to_dict(node: ProxyNode) -> dict:
    """Convert a ProxyNode to a serializable dict."""
    return {
        "node_type": node.node_type.value,
        "address": node.address,
        "port": node.port,
        "uuid": node.uuid,
        "password": node.password,
        "method": node.method,
        "encryption": node.encryption,
        "flow": node.flow,
        "transport": node.transport,
        "ws_path": node.ws_path,
        "ws_host": node.ws_host,
        "tls": node.tls,
        "sni": node.sni,
        "fingerprint": node.fingerprint,
        "public_key": node.public_key,
        "short_id": node.short_id,
        "obfs": node.obfs,
        "obfs_password": node.obfs_password,
        "up_speed": node.up_speed,
        "down_speed": node.down_speed,
        "congestion_control": node.congestion_control,
        "udp_relay_mode": node.udp_relay_mode,
        "latency_ms": node.latency_ms,
        "is_alive": node.is_alive,
        "source": node.source,
        "remark": node.remark,
    }


def format_json(nodes: list[ProxyNode]) -> str:
    """Generate a JSON string representation of nodes."""
    return json.dumps(
        [_node_to_dict(n) for n in nodes],
        ensure_ascii=False,
        indent=2,
    )
