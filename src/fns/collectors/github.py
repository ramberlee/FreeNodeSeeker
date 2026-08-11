from __future__ import annotations

import asyncio
import base64
import logging
import re

import aiohttp

from fns.collectors.base import BaseCollector, RawContent
from fns.collectors.web_scraper import BASE64_RE, SUB_LINK_RE, URI_LINE_RE, fetch_linked_content
from fns.config import GithubSourceConfig

logger = logging.getLogger("fns")

GITHUB_API = "https://api.github.com"
CODE_SEARCH = f"{GITHUB_API}/search/code"

# Generic URL regex — find all http/https links in markdown text
LINK_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)


def _clean_url(url: str) -> str:
    """Strip trailing punctuation captured from markdown link syntax."""
    return url.rstrip(")>\"';,")


class GithubCollector(BaseCollector):
    """Search GitHub for proxy subscription repositories and files."""

    name = "github"

    def __init__(self, config: GithubSourceConfig):
        super().__init__(self.name)
        self.config = config

    async def collect(self) -> list[RawContent]:
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "FreeNodeSeeker/0.1",
        }
        if self.config.token:
            headers["Authorization"] = f"token {self.config.token}"

        n_queries = len(self.config.search_queries)
        timeout = aiohttp.ClientTimeout(total=30, connect=10)
        connector = aiohttp.TCPConnector(limit=0, ttl_dns_cache=300)

        async with aiohttp.ClientSession(
            headers=headers, timeout=timeout, connector=connector
        ) as sess:
            # Concurrent search with semaphore to respect rate limits
            # GitHub: 10 req/min unauthenticated, 30 req/min authenticated
            search_sem = asyncio.Semaphore(3 if self.config.token else 2)
            seen_items: set[str] = set()

            async def _search_one(idx: int, query: str) -> list[dict]:
                async with search_sem:
                    logger.info(f"[{idx+1}/{n_queries}] Searching GitHub: {query}")
                    try:
                        items = await self._search(sess, query)
                        logger.info(f"  -> {len(items)} matching files found")
                        # The same README often matches multiple queries; download it once.
                        unique_items = []
                        for item in items:
                            key = item.get("url") or item.get("html_url")
                            if key:
                                key = str(key)
                                if key in seen_items:
                                    continue
                                seen_items.add(key)
                            unique_items.append(item)
                        return unique_items
                    except asyncio.TimeoutError:
                        logger.warning(f"GitHub search timeout for: {query}")
                    except aiohttp.ClientError as e:
                        logger.warning(f"GitHub API error: {e}")
                    except Exception as e:
                        logger.warning(f"GitHub error for '{query}': {e}")
                    return []

            tasks = [_search_one(i, q) for i, q in enumerate(self.config.search_queries)]
            batch_results = await asyncio.gather(*tasks)
            unique_items = [item for items in batch_results for item in items]
            logger.info(f"GitHub: {len(unique_items)} unique files to download")

            results: list[RawContent] = []
            if unique_items:
                results = await self._fetch_contents(sess, unique_items)

        return results

    async def _search(self, sess: aiohttp.ClientSession, query: str) -> list[dict]:
        per_page = min(self.config.max_results, 100)
        params = {
            "q": f"{query} filename:README.md",
            "per_page": per_page,
            "sort": "updated",
            "order": "desc",
        }
        async with sess.get(CODE_SEARCH, params=params) as resp:
            if resp.status == 401:
                logger.warning(
                    "GitHub API requires authentication. Set a token in fns.yaml "
                    "(sources.github.token). Create one at "
                    "https://github.com/settings/tokens "
                    "(no scopes needed for public repos)."
                )
                return []
            if resp.status == 403:
                logger.warning(
                    "GitHub API returned 403 (rate limit or access denied). "
                    "If you have a token, check it is still valid."
                )
                return []
            if resp.status != 200:
                err_body = await resp.text()
                logger.warning(f"GitHub search returned HTTP {resp.status}: {err_body}")
                return []
            data = await resp.json()
        logger.debug(data)
        items = data.get("items", [])
        return items

    async def _fetch_contents(
        self,
        sess: aiohttp.ClientSession,
        items: list[dict],
        seen_urls: set[str] | None = None,
    ) -> list[RawContent]:
        results: list[RawContent] = []
        sem = asyncio.Semaphore(30)  # Concurrent README downloads
        link_sem = asyncio.Semaphore(80)
        if seen_urls is None:
            seen_urls = set()

        async def process_readme(item: dict):
            async with sem:
                # Use GitHub Contents API (api.github.com) instead of raw.githubusercontent.com
                # which is often unreachable from some regions.
                api_url = item.get("url", "")
                html_url = item.get("html_url", "")
                try:
                    async with sess.get(api_url) as resp:
                        if resp.status != 200:
                            return
                        data = await resp.json()
                        text = base64.b64decode(data.get("content", "")).decode("utf-8")
                        if not text or len(text) <= 40:
                            return
                except Exception:
                    return

            local_results: list[RawContent] = []

            # 1. Extract subscription links from README (raw links + .yaml/.yml/.txt URLs)
            links = set()
            for match in LINK_RE.finditer(text):
                link = _clean_url(match.group(0))
                if "raw" in link.lower() or SUB_LINK_RE.match(link):
                    links.add(link)

            if links:
                async def _fetch_one_link(url: str) -> RawContent | None:
                    async with link_sem:
                        if url in seen_urls:
                            return None
                        seen_urls.add(url)
                        try:
                            return await fetch_linked_content(
                                sess, url, collector_name=self.name
                            )
                        except Exception:
                            return None

                fetched = await asyncio.gather(*[_fetch_one_link(url) for url in links])
                for result in fetched:
                    if isinstance(result, RawContent):
                        local_results.append(result)

            # 2. Extract embedded proxy URI lines (vmess://, ss://, etc.)
            if URI_LINE_RE.search(text):
                lines = [
                    line.strip()
                    for line in text.splitlines()
                    if URI_LINE_RE.match(line.strip())
                ]
                if lines:
                    local_results.append(RawContent(
                        text="\n".join(lines),
                        source_url=html_url,
                        collector_name=self.name,
                        format_hint="proxy_uri",
                    ))

            # 3. Extract base64 blobs embedded in README text
            for match in BASE64_RE.finditer(text):
                b64 = match.group(0)
                if len(b64) >= 40:
                    local_results.append(RawContent(
                        text=b64,
                        source_url=html_url,
                        collector_name=self.name,
                        format_hint="base64",
                    ))

            results.extend(local_results)

        tasks = [process_readme(item) for item in items]
        await asyncio.gather(*tasks)
        return results
