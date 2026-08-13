"""
Pipeline orchestration: collect -> parse -> validate -> merge -> output.
Supports incremental update: resume existing alive nodes, only collect if short.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from fns.collectors.api_collector import ApiCollector
from fns.collectors.base import RawContent
from fns.collectors.github import GithubCollector
from fns.collectors.web_scraper import WebScraperCollector
from fns.config import FnsConfig
from fns.merger import merge_sources
from fns.models import PipelineResult, ProxyNode, ProxyType
from fns.parsers.base import ParseResult
from fns.parsers.base64_sub import Base64SubParser
from fns.parsers.detector import parse_auto
from fns.validators.tcp_validator import TcpValidator

logger = logging.getLogger("fns")

# Validation cache TTL: skip re-validating nodes checked within this window (seconds)
_VALIDATION_CACHE_TTL = 1800  # 30 minutes
_VALIDATION_CACHE_FILE = "fns.cache.json"
_VALIDATION_CACHE_VERSION = 2
_COLLECTED_NODES_FILE = "fns.collected.jsonl"
_VALIDATION_REPORT_FILE = "fns.validation_report.json"
_STATE_FILE = "fns.state.json"

_PARSE_CHUNK_LINES = 20_000
_URI_PREFIXES = ("vmess://", "vless://", "ss://", "trojan://", "hysteria2://", "hy2://", "tuic://")


def _split_parse_chunks(raw: RawContent) -> list[str]:
    """Split large URI-line subscriptions into independently parseable chunks."""
    text = raw.text
    if raw.format_hint != "proxy_uri":
        decoded = Base64SubParser.try_decode(text)
        if decoded is not None and decoded.lstrip().startswith(_URI_PREFIXES):
            text = decoded
    if not text.lstrip().startswith(_URI_PREFIXES):
        return []
    lines = text.splitlines()
    if len(lines) < _PARSE_CHUNK_LINES:
        return []
    return [
        "\n".join(lines[i : i + _PARSE_CHUNK_LINES])
        for i in range(0, len(lines), _PARSE_CHUNK_LINES)
    ]


def _node_to_record(node: ProxyNode, collector: str | None = None) -> dict:
    """Convert a node to a flat, JSON-serializable diagnostic record."""
    return {
        "node_type": node.node_type.value,
        "address": node.address,
        "port": node.port,
        "uuid": node.uuid,
        "password": node.password,
        "username": node.username,
        "method": node.method,
        "encryption": node.encryption,
        "flow": node.flow,
        "plugin": node.plugin,
        "plugin_opts": node.plugin_opts,
        "grpc_service_name": node.grpc_service_name,
        "transport": node.transport,
        "ws_path": node.ws_path,
        "ws_host": node.ws_host,
        "tls": node.tls,
        "skip_cert_verify": node.skip_cert_verify,
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
        "validation_error": node.validation_error,
        "source": node.source,
        "collector": collector,
        "remark": node.remark,
    }


def _write_collected_nodes(output_dir: Path, source_nodes: dict[str, list]) -> None:
    """Persist every parsed node before dedup/validation for later analysis."""
    path = output_dir / _COLLECTED_NODES_FILE
    collected_at = time.time()
    try:
        with path.open("w", encoding="utf-8") as f:
            for collector_name, nodes in source_nodes.items():
                for node in nodes:
                    record = _node_to_record(node, collector_name)
                    record["collected_at"] = collected_at
                    f.write(json.dumps(record, ensure_ascii=False) + "\n")
        logger.info(f"Wrote collected node snapshot to {path}")
    except Exception as e:
        logger.warning(f"Failed to write collected node snapshot: {e}")


def _write_validation_report(
    output_dir: Path,
    *,
    collected_total: int,
    unique_candidates: int,
    validated_nodes: list[ProxyNode],
    alive_new: int,
    alive_final: int,
    errors: list[str],
) -> None:
    """Write a human-readable summary plus per-reason dead-node counts."""
    path = output_dir / _VALIDATION_REPORT_FILE
    alive_validated = sum(1 for n in validated_nodes if n.is_alive)
    dead_validated = len(validated_nodes) - alive_validated
    by_protocol: dict[str, dict[str, int]] = {}
    for n in validated_nodes:
        bucket = by_protocol.setdefault(
            n.node_type.value, {"alive": 0, "dead": 0}
        )
        if n.is_alive:
            bucket["alive"] += 1
        else:
            bucket["dead"] += 1

    error_counts = Counter(
        n.validation_error or "unknown" for n in validated_nodes if not n.is_alive
    )
    report = {
        "generated_at": time.time(),
        "collected_total": collected_total,
        "unique_candidates": unique_candidates,
        "validated_total": len(validated_nodes),
        "alive_validated": alive_validated,
        "dead_validated": dead_validated,
        "alive_new": alive_new,
        "alive_final": alive_final,
        "by_protocol": by_protocol,
        "dead_by_reason": dict(error_counts),
        "errors": errors,
    }
    try:
        path.write_text(
            json.dumps(report, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        logger.info(f"Wrote validation report to {path}")
    except Exception as e:
        logger.warning(f"Failed to write validation report: {e}")


def _load_validation_cache(output_dir: Path) -> dict[tuple, tuple[bool, float, float]]:
    """Load validation cache: {(address, port, node_type): (is_alive, latency_ms, timestamp)}."""
    cache_path = output_dir / _VALIDATION_CACHE_FILE
    if not cache_path.exists():
        return {}
    try:
        raw = json.loads(cache_path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    if not isinstance(raw, dict) or raw.get("_version") != _VALIDATION_CACHE_VERSION:
        logger.warning(
            "Ignoring stale validation cache (version mismatch or missing version)"
        )
        return {}
    cache: dict[tuple, tuple[bool, float, float]] = {}
    for key_str, val in raw.items():
        if key_str == "_version":
            continue
        parts = key_str.split("|", 2)
        if len(parts) == 3 and isinstance(val, list) and len(val) == 3:
            cache[(parts[0], int(parts[1]), parts[2])] = (val[0], val[1], val[2])
    return cache


def _save_validation_cache(
    output_dir: Path, cache: dict[tuple, tuple[bool, float, float]]
) -> None:
    cache_path = output_dir / _VALIDATION_CACHE_FILE
    raw: dict[str, object] = {"_version": _VALIDATION_CACHE_VERSION}
    for (addr, port, ptype), (alive, lat, ts) in cache.items():
        raw[f"{addr}|{port}|{ptype}"] = [alive, lat, ts]
    cache_path.write_text(json.dumps(raw, indent=2), encoding="utf-8")


def load_existing_nodes(output_dir: Path) -> list[ProxyNode]:
    """Load previously saved nodes from the internal state file."""
    json_path = output_dir / _STATE_FILE
    if not json_path.exists():
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
                username=item.get("username"),
                method=item.get("method", ""),
                encryption=item.get("encryption", ""),
                flow=item.get("flow", ""),
                plugin=item.get("plugin"),
                plugin_opts=item.get("plugin_opts"),
                grpc_service_name=item.get("grpc_service_name"),
                transport=item.get("transport", ""),
                ws_path=item.get("ws_path", ""),
                ws_host=item.get("ws_host", ""),
                tls=item.get("tls", False),
                skip_cert_verify=bool(item.get("skip_cert_verify", False)),
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
                latency_ms=item.get("latency_ms"),
                is_alive=bool(item.get("is_alive", False)),
                validation_error=item.get("validation_error"),
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
                logger.info(
                    f"Already have {len(existing_alive)} alive nodes "
                    f"(target={effective_max}), skipping collection"
                )
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

    # Parse with a dedicated thread pool. Large URI-line subscriptions are
    # split into chunks so one huge source does not serialize all parsing.
    loop = asyncio.get_running_loop()
    parse_workers = min(64, max(1, len(all_raw)))
    parse_sem = asyncio.Semaphore(parse_workers)
    parse_executor = ThreadPoolExecutor(
        max_workers=parse_workers, thread_name_prefix="fns-parse"
    )

    async def _run_parse(text: str, source: str) -> ParseResult:
        async with parse_sem:
            return await loop.run_in_executor(parse_executor, parse_auto, text, source)

    async def _parse_one(raw: RawContent):
        try:
            chunks = await loop.run_in_executor(
                parse_executor, _split_parse_chunks, raw
            )
        except Exception:
            chunks = []
        if not chunks:
            chunks = [raw.text]

        try:
            results = await asyncio.gather(
                *(_run_parse(chunk, raw.source_url) for chunk in chunks),
                return_exceptions=True,
            )
        except Exception as e:
            return (
                ParseResult(errors=[f"Parse error for {raw.source_url}: {e}"]),
                raw.collector_name,
            )

        nodes: list[ProxyNode] = []
        parse_errors: list[str] = []
        for result in results:
            if isinstance(result, Exception):
                parse_errors.append(f"Parse error for {raw.source_url}: {result}")
            else:
                nodes.extend(result.nodes)
                parse_errors.extend(result.errors)
        return ParseResult(nodes=nodes, errors=parse_errors), raw.collector_name

    source_nodes: dict[str, list] = {}
    try:
        parse_tasks = [_parse_one(raw) for raw in all_raw]
        parse_results = await asyncio.gather(*parse_tasks)
    finally:
        parse_executor.shutdown(wait=True)

    for result, collector_name in parse_results:
        if result.nodes:
            valid_nodes = [n for n in result.nodes if n.address and n.port > 0]
            source_nodes.setdefault(collector_name, []).extend(valid_nodes)
        if result.errors:
            errors.extend(result.errors)

    github_nodes = source_nodes.get("github")
    if github_nodes and len(github_nodes) > cfg.sources.github.max_collect_nodes:
        logger.info(
            f"Capping parsed GitHub nodes from {len(github_nodes)} "
            f"to {cfg.sources.github.max_collect_nodes}"
        )
        source_nodes["github"] = github_nodes[: cfg.sources.github.max_collect_nodes]

    total_parsed = sum(len(v) for v in source_nodes.values())
    logger.info(f"Parsed {total_parsed} nodes from {len(source_nodes)} sources")
    _write_collected_nodes(output_dir, source_nodes)

    # ── 3. Merge ───────────────────────────────────────────────────────────

    source_priority = [c.name for c in collectors if c.name in source_nodes]
    new_nodes = merge_sources(source_nodes, source_priority=source_priority)
    unique_candidate_count = len(new_nodes)
    logger.info(f"Merged to {len(new_nodes)} unique new nodes")

    # ── 4. Validate new nodes ──────────────────────────────────────────────

    validated_nodes: list[ProxyNode] = []
    if skip_validation:
        for n in new_nodes:
            n.is_alive = True
            n.validation_error = None
        validated_nodes = list(new_nodes)
    else:
        validator = TcpValidator(cfg.validator)

        if effective_max > 0:
            # Validate in concurrent batches, stopping as soon as the target
            # is reached. The first usable candidates are good enough when the
            # pool contains tens of thousands of nodes.
            new_alive: list[ProxyNode] = []
            remaining = effective_max - len(existing_alive)
            pool_target = min(remaining, len(new_nodes))
            batch_size = cfg.validator.concurrency
            for i in range(0, len(new_nodes), batch_size):
                if len(new_alive) >= pool_target:
                    break
                batch = new_nodes[i:i + batch_size]
                await validator.validate_all(batch)
                validated_nodes.extend(batch)
                for node in batch:
                    if node.is_alive:
                        new_alive.append(node)
                logger.info(
                    f"  Batch {i // batch_size + 1}: "
                    f"{len(new_alive)}/{pool_target} alive found so far"
                )

            # Sort by lowest latency, take exactly remaining
            new_alive.sort(key=lambda n: n.latency_ms if n.latency_ms is not None else 99999)
            new_nodes = new_alive[:remaining]
            logger.info(
                f"Selected {len(new_nodes)} lowest-latency nodes "
                f"from {len(new_alive)} alive candidates"
            )
        else:
            await validator.validate_all(new_nodes)
            validated_nodes = list(new_nodes)

    alive_new = sum(1 for n in new_nodes if n.is_alive)
    logger.info(f"New nodes validation: {alive_new}/{len(new_nodes)} alive")

    # 更新验证缓存（新节点）
    now = time.time()
    for n in validated_nodes:
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
    logger.info(
        f"Final: {alive_count} alive nodes "
        f"(from {len(existing_alive)} existing + {len(new_alive_nodes)} new)"
    )
    _write_validation_report(
        output_dir,
        collected_total=total_parsed,
        unique_candidates=unique_candidate_count,
        validated_nodes=validated_nodes,
        alive_new=len(new_alive_nodes),
        alive_final=alive_count,
        errors=errors,
    )

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
                from fns.formatters.clash import format_clash
                content = format_clash(nodes, cfg.output.clash)
                (output_dir / "fns.yaml").write_text(content, encoding="utf-8")
                logger.info(f"Wrote clash config to {output_dir / 'fns.yaml'}")

            elif fmt == "base64":
                from fns.formatters.base64_sub import format_base64_sub
                content = format_base64_sub(nodes)
                (output_dir / "fns.txt").write_text(content, encoding="utf-8")
                logger.info(f"Wrote base64 subscription to {output_dir / 'fns.txt'}")

            elif fmt == "json":
                from fns.formatters.json_output import format_json
                content = format_json(nodes)
                (output_dir / "fns.json").write_text(content, encoding="utf-8")
                logger.info(f"Wrote JSON to {output_dir / 'fns.json'}")

        except Exception as e:
            msg = f"Output error for format '{fmt}': {e}"
            logger.error(msg)
            errors.append(msg)

    try:
        from fns.formatters.json_output import format_json
        (output_dir / _STATE_FILE).write_text(
            format_json(nodes), encoding="utf-8"
        )
        logger.info(f"Wrote internal state to {output_dir / _STATE_FILE}")
    except Exception as e:
        msg = f"Output error for internal state: {e}"
        logger.error(msg)
        errors.append(msg)
