from __future__ import annotations

import asyncio
import logging
import re

import aiohttp
from bs4 import BeautifulSoup

from fns.collectors.base import BaseCollector, RawContent
from fns.config import WebScrapeSourceConfig
from fns.utils.network import make_session

logger = logging.getLogger("fns")

# Patterns to find proxy-related content in HTML
BASE64_RE = re.compile(r"[A-Za-z0-9+/=]{40,}")
URI_LINE_RE = re.compile(r"^(vmess|vless|ss|trojan|hysteria2|hy2|tuic)://", re.MULTILINE)
SUB_LINK_RE = re.compile(r"https?://[^\s\"'<>]+\.(yaml|yml|txt)[^\s\"'<>]*", re.IGNORECASE)


async def fetch_linked_content(
    sess: aiohttp.ClientSession,
    href: str,
    base_url: str = "",
    collector_name: str = "",
) -> RawContent | None:
    from urllib.parse import urljoin

    full_url = urljoin(base_url, href) if base_url else href
    async with sess.get(full_url, allow_redirects=True) as resp:
        if resp.status == 200:
            text = await resp.text()
            if text and len(text) > 40:
                return RawContent(
                    text=text,
                    source_url=full_url,
                    collector_name=collector_name,
                )
    return None


class WebScraperCollector(BaseCollector):
    """Scrape known web pages for proxy subscription content."""

    name = "web_scrape"

    def __init__(self, config: WebScrapeSourceConfig):
        super().__init__(self.name)
        self.config = config

    async def collect(self) -> list[RawContent]:
        results: list[RawContent] = []
        proxy = self.config.proxy if self.config.proxy else None
        async with make_session(proxy=proxy) as sess:
            for url in self.config.urls:
                try:
                    contents = await self._scrape(sess, url)
                    results.extend(contents)
                except asyncio.TimeoutError:
                    logger.warning(f"Timeout scraping: {url}")
                except aiohttp.ClientError as e:
                    logger.warning(f"HTTP error scraping {url}: {e}")
                except Exception as e:
                    logger.warning(f"Failed to scrape {url}: {e}")
                if self.config.request_delay > 0:
                    await asyncio.sleep(self.config.request_delay)
        return results

    async def _scrape(self, sess: aiohttp.ClientSession, url: str) -> list[RawContent]:
        logger.debug(f"Scraping: {url}")
        async with sess.get(url, allow_redirects=True) as resp:
            if resp.status != 200:
                return []
            html = await resp.text()

        soup = BeautifulSoup(html, "lxml")
        results: list[RawContent] = []

        # 1. <pre> and <code> blocks — common for base64 subscription
        for tag in soup.find_all(["pre", "code"]):
            text = tag.get_text(strip=True)
            if len(text) > 40 and (BASE64_RE.match(text) or URI_LINE_RE.search(text)):
                results.append(
                    RawContent(
                        text=text,
                        source_url=url,
                        collector_name=self.name,
                    )
                )

        # 2. Links to .yaml/.yml/.txt files
        for a in soup.find_all("a", href=True):
            href = a.get("href")
            if not isinstance(href, str) or not href:
                continue
            if SUB_LINK_RE.search(href):
                try:
                    sub_content = await self._fetch_linked(sess, href, url)
                    if sub_content:
                        results.append(sub_content)
                except Exception:
                    pass

        # 3. Embedded proxy URIs in page text
        page_text = soup.get_text()
        if URI_LINE_RE.search(page_text):
            lines = [
                line.strip()
                for line in page_text.splitlines()
                if URI_LINE_RE.match(line.strip())
            ]
            if lines:
                results.append(
                    RawContent(
                        text="\n".join(lines),
                        source_url=url,
                        collector_name=self.name,
                        format_hint="proxy_uri",
                    )
                )

        return results

    async def _fetch_linked(
        self, sess: aiohttp.ClientSession, href: str, base_url: str
    ) -> RawContent | None:
        return await fetch_linked_content(sess, href, base_url, self.name)
