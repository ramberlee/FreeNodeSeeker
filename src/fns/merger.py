from __future__ import annotations

import logging

from fns.models import ProxyNode

logger = logging.getLogger("fns")


def deduplicate(
    nodes: list[ProxyNode],
    key_fn: callable = None,
) -> list[ProxyNode]:
    """Deduplicate nodes by (address, port, node_type). First occurrence wins."""
    if key_fn is None:
        key_fn = lambda n: (n.address, n.port, n.node_type.value)
    seen: dict[tuple, ProxyNode] = {}
    for node in nodes:
        k = key_fn(node)
        if k not in seen:
            seen[k] = node
    return list(seen.values())


def merge_sources(
    source_nodes: dict[str, list[ProxyNode]],
    source_priority: list[str] | None = None,
    max_total: int | None = None,
    prefer_alive: bool = True,
) -> list[ProxyNode]:
    """Merge nodes from multiple sources with deduplication.

    Args:
        source_nodes: {source_name: [nodes]}
        source_priority: Source names in priority order (first = highest). None = insertion order.
        max_total: Max total nodes in output; None or <=0 means no cap.
        prefer_alive: Sort alive nodes first.
    """
    if source_priority is None:
        source_priority = list(source_nodes.keys())

    # Collect in priority order
    all_nodes: list[ProxyNode] = []
    for src in source_priority:
        nodes = source_nodes.get(src, [])
        all_nodes.extend(nodes)

    # Deduplicate
    unique = deduplicate(all_nodes)

    # Sort: alive first, then by latency
    if prefer_alive:
        unique.sort(key=lambda n: (not n.is_alive, n.latency_ms if n.latency_ms is not None else 99999))

    # Cap
    if max_total is not None and max_total > 0 and len(unique) > max_total:
        unique = unique[:max_total]

    return unique
