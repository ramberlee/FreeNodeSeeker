"""
Daemon mode — run the pipeline on a periodic loop with optional HTTP server.
"""

from __future__ import annotations

import asyncio
import logging
import signal
from pathlib import Path

from fns.config import FnsConfig
from fns.pipeline import run_pipeline
from fns.server import run_server

logger = logging.getLogger("fns")

_server_runner = None  # Keep a reference for graceful shutdown


def start_daemon(cfg: FnsConfig) -> None:
    """Start the periodic pipeline loop. Blocks until interrupted."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    stop_event = asyncio.Event()

    # Global cleanup reference for signal handlers
    global _server_runner

    def _signal_handler():
        logger.info("Shutting down daemon...")
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _signal_handler)
        except NotImplementedError:
            # Windows doesn't support add_signal_handler
            pass

    try:
        loop.run_until_complete(_scheduled_pipeline(cfg, stop_event))
    except KeyboardInterrupt:
        logger.info("Daemon stopped")
    finally:
        if _server_runner is not None:
            loop.run_until_complete(_server_runner.cleanup())
            _server_runner = None
        loop.close()


async def _scheduled_pipeline(cfg: FnsConfig, stop_event: asyncio.Event) -> None:
    global _server_runner

    interval = cfg.scheduler.interval_hours * 3600

    # ── Start HTTP server (if enabled) ─────────────────────────────────────
    if cfg.server.enabled:
        output_dir = Path(cfg.output.dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        try:
            _server_runner = await run_server(cfg.server, output_dir)
            logger.info(f"HTTP server running at http://{cfg.server.host}:{cfg.server.port}/")
        except Exception as e:
            logger.warning(f"Failed to start HTTP server: {e}")

    # ── First run immediately ─────────────────────────────────────────────
    logger.info("Starting initial collection...")
    try:
        await run_pipeline(cfg)
    except Exception as e:
        logger.error(f"Pipeline failed: {e}", exc_info=True)

    # ── Scheduled loop ────────────────────────────────────────────────────
    while not stop_event.is_set():
        logger.info(f"Sleeping {cfg.scheduler.interval_hours}h until next run...")
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval)
            break  # stop was set
        except asyncio.TimeoutError:
            pass  # interval elapsed, run again

        logger.info(f"Starting scheduled collection (interval={cfg.scheduler.interval_hours}h)...")
        try:
            await run_pipeline(cfg)
        except Exception as e:
            logger.error(f"Pipeline failed: {e}", exc_info=True)

    # ── Stop HTTP server ──────────────────────────────────────────────────
    if _server_runner is not None:
        await _server_runner.cleanup()
        _server_runner = None
        logger.info("HTTP server stopped")
