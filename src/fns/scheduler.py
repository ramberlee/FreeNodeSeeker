"""
Daemon mode — run the pipeline on a periodic loop.
"""

from __future__ import annotations

import asyncio
import logging
import signal

from fns.config import FnsConfig
from fns.pipeline import run_pipeline

logger = logging.getLogger("fns")


def start_daemon(cfg: FnsConfig) -> None:
    """Start the periodic pipeline loop. Blocks until interrupted."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    stop_event = asyncio.Event()

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
        loop.close()


async def _scheduled_pipeline(cfg: FnsConfig, stop_event: asyncio.Event) -> None:
    interval = cfg.scheduler.interval_hours * 3600

    while not stop_event.is_set():
        logger.info(f"Starting scheduled collection (interval={cfg.scheduler.interval_hours}h)...")
        try:
            await run_pipeline(cfg)
        except Exception as e:
            logger.error(f"Pipeline failed: {e}", exc_info=True)

        logger.info(f"Sleeping {cfg.scheduler.interval_hours}h until next run...")
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval)
            break  # stop was set
        except asyncio.TimeoutError:
            pass  # interval elapsed, run again
