from __future__ import annotations

import asyncio
import logging

import aiohttp

from fns.collectors.base import BaseCollector, RawContent
from fns.config import ApiSourceConfig
from fns.utils.network import make_session

logger = logging.getLogger("fns")


class ApiCollector(BaseCollector):
    """Fetch subscription content from direct API endpoints."""

    name = "api"

    def __init__(self, config: ApiSourceConfig):
        super().__init__(self.name)
        self.config = config

    async def collect(self) -> list[RawContent]:
        results: list[RawContent] = []
        async with make_session() as sess:
            for url in self.config.urls:
                try:
                    content = await self._fetch(sess, url)
                    if content:
                        results.append(content)
                except asyncio.TimeoutError:
                    logger.warning(f"Timeout fetching API: {url}")
                except aiohttp.ClientError as e:
                    logger.warning(f"HTTP error for {url}: {e}")
                except Exception as e:
                    logger.warning(f"Failed to fetch {url}: {e}")
        return results

    async def _fetch(self, sess: aiohttp.ClientSession, url: str) -> RawContent | None:
        logger.debug(f"Fetching API: {url}")
        async with sess.get(url, allow_redirects=True) as resp:
            if resp.status != 200:
                logger.warning(f"API {url} returned {resp.status}")
                return None
            text = await resp.text()
            if not text or len(text) < 20:
                return None
            return RawContent(
                text=text,
                source_url=url,
                collector_name=self.name,
                format_hint=None,
            )
