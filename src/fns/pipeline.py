"""
Pipeline orchestration: collect -> parse -> validate -> merge -> output.
Supports incremental update: resume existing alive nodes, only collect if short.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from pathlib import Path

from fns.collectors.api_collector import ApiCollector
from fns.collectors.base import RawContent
from fns.collectors.github import GithubCollector
from fns.collectors.web_scraper import WebScraperCollector
from fns.config import FnsConfig
from fns.merger import merge_sources
from fns.models import PipelineResult, ProxyNode, ProxyType
from fns.parsers.detector import parse_auto
from fns.parsers.base import ParseResult
from fns.validators.tcp_validator import TcpValidator

logger = logging.getLogger("fns")

# Validation cache TTL: skip re-validating nodes checked within this window (seconds)
_VALIDATION_CACHE_TTL = 1800  # 30 minutes
_VALIDATION_CACHE_FILE = "fns.cache.json"


def _load_validation_cache(output_dir: Path) -> dict[tuple, tuple[bool, float, float]]:
    """Load validation cache: {(address, port, node_type): (is_alive, latency_ms, timestamp)}."""
    cache_path = output_dir / _VALIDATION_CACHE_FILE
    if not cache_path.exists():
        return {}
    try:
        raw = json.loads(cache_path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    cache: dict[tuple, tuple[bool, float, float]] = {}
    for key_str, val in raw.items():
        parts = key_str.split("|", 2)
        if len(parts) == 3:
            cache[(parts[0], int(parts[1]), parts[2])] = (val[0], val[1], val[2])
    return cache


def _save_validation_cache(
    output_dir: Path, cache: dict[tuple, tuple[bool, float, float]]
) -> None:
    cache_path = output_dir / _VALIDATION_CACHE_FILE
    raw: dict[str, list] = {}
    for (addr, port, ptype), (alive, lat, ts) in cache.items():
        raw[f"{addr}|{port}|{ptype}"] = [alive, lat, ts]
    cache_path.write_text(json.dumps(raw, indent=2), encoding="utf-8")


def load_existing_nodes(output_dir: Path) -> list[ProxyNode]:
    """Load previously saved nodes from fns.json."""
    json_path = output_dir / "fns.json"
    if not json_path.exists():
        logger.info("No existing nodes found")
        return []

    try:
        data = json.loads(json_path.read_text(encoding="utf-8"))
    except Exception as e:
        logger.warning(f"Failed to read existing nodes: {e}")
        return []

    nodes = []
    for item in data:
        try:
            node = ProxyNode(
                node_type=ProxyType(item.get("node_type", "vmess")),
                address=item.get("address", ""),
                port=item.get("port", 0),
                uuid=item.get("uuid", ""),
                password=item.get("password", ""),
                method=item.get("method", ""),
                encryption=item.get("encryption", ""),
                flow=item.get("flow", ""),
                transport=item.get("transport", ""),
                ws_path=item.get("ws_path", ""),
                ws_host=item.get("ws_host", ""),
                tls=item.get("tls", False),
                sni=item.get("sni", ""),
                fingerprint=item.get("fingerprint", ""),
                public_key=item.get("public_key", ""),
                short_id=item.get("short_id", ""),
                obfs=item.get("obfs", ""),
                obfs_password=item.get("obfs_password", ""),
                up_speed=item.get("up_speed"),
                down_speed=item.get("down_speed"),
                congestion_control=item.get("congestion_control", ""),
                udp_relay_mode=item.get("udp_relay_mode", ""),
                source=item.get("source", ""),
                remark=item.get("remark", ""),
            )
            nodes.append(node)
        except Exception:
            pass

    logger.info(f"Loaded {len(nodes)} existing nodes from {json_path}")
    return nodes


def _build_collectors(cfg: FnsConfig) -> list:
    collectors = []
    if cfg.sources.github.enabled:
        collectors.append(GithubCollector(cfg.sources.github))
    if cfg.sources.web_scrape.enabled:
        collectors.append(WebScraperCollector(cfg.sources.web_scrape))
    if cfg.sources.api.enabled:
        collectors.append(ApiCollector(cfg.sources.api))
    return collectors


async def run_pipeline(
    cfg: FnsConfig,
    skip_validation: bool = False,
    max_nodes: int | None = None,
) -> PipelineResult:
    """Execute the full collection pipeline.

    If max_nodes > 0:
      1. Load & validate existing output nodes
      2. If enough alive, skip collection
      3. Otherwise collect only enough to reach max_nodes
    """
    errors: list[str] = []
    output_dir = Path(cfg.output.dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    effective_max = max_nodes if max_nodes is not None else cfg.max_alive_nodes

    # ── 0. Resume existing nodes (if max_nodes mode) ────────────────────────
    # 同时更新验证缓存

    existing_alive: list[ProxyNode] = []
    validation_cache = _load_validation_cache(output_dir) if not skip_validation else {}

    if effective_max > 0 and not skip_validation:
        existing = load_existing_nodes(output_dir)
        if existing:
            now = time.time()
            fresh_nodes: list[ProxyNode] = []   # 需要重新验证
            cached_alive: list[ProxyNode] = []  # 缓存中仍存活且未过期

            for n in existing:
                cache_entry = validation_cache.get((n.address, n.port, n.node_type.value))
                if cache_entry and (now - cache_entry[2]) < _VALIDATION_CACHE_TTL:
                    # 使用缓存结果
                    n.is_alive = cache_entry[0]
                    n.latency_ms = cache_entry[1]
                    if n.is_alive:
                        cached_alive.append(n)
                else:
                    fresh_nodes.append(n)

            if cached_alive:
                logger.info(
                    f"Reused cached results: {len(cached_alive)} alive, "
                    f"need to validate {len(fresh_nodes)} fresh"
                )

            if fresh_nodes:
                logger.info(f"Validating {len(fresh_nodes)} existing nodes...")
                validator = TcpValidator(cfg.validator)
                await validator.validate_all(fresh_nodes)
                # 更新缓存
                for n in fresh_nodes:
                    validation_cache[(n.address, n.port, n.node_type.value)] = (
                        n.is_alive, n.latency_ms, now,
                    )

            existing_alive = cached_alive + [n for n in fresh_nodes if n.is_alive]
            logger.info(f"Existing nodes: {len(existing_alive)}/{len(existing)} alive")

            if len(existing_alive) >= effective_max:
                # Already enough — just write and return
                logger.info(f"Already have {len(existing_alive)} alive nodes (target={effective_max}), skipping collection")
                existing_alive = existing_alive[:effective_max]
                _save_validation_cache(output_dir, validation_cache)
                _write_outputs(existing_alive, cfg, output_dir, errors)
                return PipelineResult(
                    nodes=existing_alive,
                    sources_used=0,
                    parse_errors=errors,
                    alive_count=len(existing_alive),
                )

    # ── 1. Collect ─────────────────────────────────────────────────────────

    collectors = _build_collectors(cfg)
    if not collectors:
        logger.warning("No collectors enabled")
        # Still output existing alive nodes
        if existing_alive:
            _save_validation_cache(output_dir, validation_cache)
            _write_outputs(existing_alive, cfg, output_dir, errors)
        return PipelineResult(nodes=existing_alive, sources_used=0, parse_errors=errors)

    shortage = effective_max - len(existing_alive) if effective_max > 0 else 0

    # Run all collectors concurrently
    async def _collect_one(collector):
        try:
            raw = await collector.collect()
            logger.info(f"Collector '{collector.name}' got {len(raw)} items")
            return raw, collector.name, None
        except Exception as e:
            msg = f"Collector '{collector.name}' failed: {e}"
            logger.error(msg)
            return [], collector.name, msg

    collector_results = await asyncio.gather(
        *[_collect_one(c) for c in collectors], return_exceptions=False
    )

    all_raw: list[RawContent] = []
    for raw_list, cname, err_msg in collector_results:
        if err_msg:
            errors.append(err_msg)
        all_raw.extend(raw_list)

    if not all_raw:
        logger.warning("No content collected")
        if existing_alive:
            _save_validation_cache(output_dir, validation_cache)
            _write_outputs(existing_alive, cfg, output_dir, errors)
        return PipelineResult(
            nodes=existing_alive,
            sources_used=0,
            parse_errors=errors,
            alive_count=len(existing_alive),
        )

    # ── 2. Parse ───────────────────────────────────────────────────────────

    async def _parse_one(raw: RawContent):
        """Parse a single raw content item in a thread (CPU-bound)."""
        try:
            return await asyncio.to_thread(parse_auto, raw.text, raw.source_url), raw.collector_name
        except Exception as e:
            return ParseResult(errors=[f"Parse error for {raw.source_url}: {e}"]), raw.collector_name

    source_nodes: dict[str, list] = {}
    parse_tasks = [_parse_one(raw) for raw in all_raw]
    parse_results = await asyncio.gather(*parse_tasks)
    for result, collector_name in parse_results:
        if result.nodes:
            source_nodes.setdefault(collector_name, []).extend(result.nodes)
        if result.errors:
            errors.extend(result.errors)

    total_parsed = sum(len(v) for v in source_nodes.values())
    logger.info(f"Parsed {total_parsed} nodes from {len(source_nodes)} sources")

    # ── 3. Merge ───────────────────────────────────────────────────────────

    source_priority = [c.name for c in collectors if c.name in source_nodes]
    new_nodes = merge_sources(source_nodes, source_priority=source_priority)
    logger.info(f"Merged to {len(new_nodes)} unique new nodes")

    # ── 4. Validate new nodes ──────────────────────────────────────────────

    if skip_validation:
        for n in new_nodes:
            n.is_alive = True
    else:
        validator = TcpValidator(cfg.validator)

        if effective_max > 0:
            # Validate in concurrent batches. Over-collect 3x target pool so
            # we can pick the lowest-latency nodes, not just the first alive.
            new_alive: list[ProxyNode] = []
            remaining = effective_max - len(existing_alive)
            pool_target = min(remaining * 3, len(new_nodes))
            batch_size = cfg.validator.concurrency
            for i in range(0, len(new_nodes), batch_size):
                if len(new_alive) >= pool_target:
                    break
                batch = new_nodes[i:i + batch_size]
                await validator.validate_all(batch)
                for node in batch:
                    if node.is_alive:
                        new_alive.append(node)
                logger.info(f"  Batch {i // batch_size + 1}: {len(new_alive)}/{pool_target} alive found so far")

            # Sort by lowest latency, take exactly remaining
            new_alive.sort(key=lambda n: n.latency_ms if n.latency_ms is not None else 99999)
            new_nodes = new_alive[:remaining]
            logger.info(
                f"Selected {len(new_nodes)} lowest-latency nodes from {len(new_alive)} alive candidates"
            )
        else:
            await validator.validate_all(new_nodes)

    alive_new = sum(1 for n in new_nodes if n.is_alive)
    logger.info(f"New nodes validation: {alive_new}/{len(new_nodes)} alive")

    # 更新验证缓存（新节点）
    now = time.time()
    for n in new_nodes:
        validation_cache[(n.address, n.port, n.node_type.value)] = (
            n.is_alive, n.latency_ms, now,
        )
    _save_validation_cache(output_dir, validation_cache)

    # ── 5. Merge existing + new ────────────────────────────────────────────

    new_alive_nodes = [n for n in new_nodes if n.is_alive]
    all_nodes = existing_alive + new_alive_nodes
    all_nodes = merge_sources(
        {"merged": all_nodes},
        max_total=effective_max if effective_max > 0 else None,
    )
    alive_count = len(all_nodes)
    logger.info(f"Final: {alive_count} alive nodes (from {len(existing_alive)} existing + {len(new_alive_nodes)} new)")

    # ── 6. Output ──────────────────────────────────────────────────────────

    _write_outputs(all_nodes, cfg, output_dir, errors)

    return PipelineResult(
        nodes=all_nodes,
        sources_used=len(source_nodes),
        parse_errors=errors,
        alive_count=alive_count,
    )


def _write_outputs(
    nodes: list[ProxyNode],
    cfg: FnsConfig,
    output_dir: Path,
    errors: list[str],
) -> None:
    nodes = [n for n in nodes if n.is_alive]  # Only write alive nodes
    for fmt in cfg.output.formats:
        try:
            if fmt == "clash":
                from fns.output.clash import format_clash
                content = format_clash(nodes, cfg.output.clash)
                (output_dir / "fns.yaml").write_text(content, encoding="utf-8")
                logger.info(f"Wrote clash config to {output_dir / 'fns.yaml'}")

            elif fmt == "base64":
                from fns.output.base64_sub import format_base64_sub
                content = format_base64_sub(nodes)
                (output_dir / "fns.txt").write_text(content, encoding="utf-8")
                logger.info(f"Wrote base64 subscription to {output_dir / 'fns.txt'}")

            elif fmt == "json":
                from fns.output.json_output import format_json
                content = format_json(nodes)
                (output_dir / "fns.json").write_text(content, encoding="utf-8")
                logger.info(f"Wrote JSON to {output_dir / 'fns.json'}")

        except Exception as e:
            msg = f"Output error for format '{fmt}': {e}"
            logger.error(msg)
            errors.append(msg)
