"""Collector speed and deduplication behavior tests."""

import asyncio
import base64

import pytest

import fns.collectors.github as github_module
from fns.collectors.api_collector import ApiCollector
from fns.collectors.base import RawContent
from fns.collectors.github import GithubCollector
from fns.collectors.web_scraper import WebScraperCollector
from fns.config import ApiSourceConfig, GithubSourceConfig, WebScrapeSourceConfig


class _FakeJsonResp:
    status = 200

    def __init__(self, content: str):
        self._content = content

    async def json(self):
        return {"content": base64.b64encode(self._content.encode()).decode()}


class _FakeTextResp:
    status = 200

    def __init__(self, text: str):
        self._text = text

    async def text(self):
        return self._text


class _FakeRequest:
    def __init__(self, resp):
        self._resp = resp

    async def __aenter__(self):
        return self._resp

    async def __aexit__(self, *args):
        return False


class _FakeSession:
    def __init__(self, body: str = ""):
        self._body = body

    def get(self, url: str, **kwargs):
        if "api.github.com" in url:
            return _FakeRequest(_FakeJsonResp(self._body))
        return _FakeRequest(_FakeTextResp(self._body))


@pytest.mark.asyncio
async def test_api_collector_fetches_urls_concurrently(monkeypatch):
    collector = ApiCollector(
        ApiSourceConfig(urls=[f"https://e{i}.example/sub" for i in range(6)])
    )
    active = 0
    max_active = 0

    async def fake_fetch(sess, url):
        nonlocal active, max_active
        active += 1
        max_active = max(max_active, active)
        await asyncio.sleep(0.05)
        active -= 1
        return RawContent(text="vmess://x", source_url=url, collector_name="api")

    class FakeSession:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

    monkeypatch.setattr(
        "fns.collectors.api_collector.make_session", lambda: FakeSession()
    )
    monkeypatch.setattr(collector, "_fetch", fake_fetch)

    results = await collector.collect()
    assert len(results) == 6
    assert max_active > 1


@pytest.mark.asyncio
async def test_github_downloads_each_file_once(monkeypatch):
    cfg = GithubSourceConfig(search_queries=["free v2ray", "v2ray config"], max_results=5)
    collector = GithubCollector(cfg)
    item = {
        "url": "https://api.github.com/repos/owner/repo/contents/README.md",
        "html_url": "https://github.com/owner/repo/blob/main/README.md",
    }
    fetched = []

    async def fake_search(sess, query):
        return [item]

    async def fake_fetch(sess, items, seen_urls=None):
        fetched.append(items)
        return []

    monkeypatch.setattr(collector, "_search", fake_search)
    monkeypatch.setattr(collector, "_fetch_contents", fake_fetch)

    await collector.collect()
    assert len(fetched) == 1
    assert len(fetched[0]) == 1


@pytest.mark.asyncio
async def test_github_deduplicates_linked_urls(monkeypatch):
    collector = GithubCollector(GithubSourceConfig(search_queries=["x"], max_results=5))
    readme = (
        "This repository README links to a subscription file: "
        "https://example.com/sub.txt\nMore useful text follows here.\n"
    )
    items = [
        {
            "url": "https://api.github.com/repos/a/contents/README.md",
            "html_url": "https://github.com/a",
        },
        {
            "url": "https://api.github.com/repos/b/contents/README.md",
            "html_url": "https://github.com/b",
        },
    ]
    calls = []

    async def fake_fetch_linked(sess, href, base_url="", collector_name=""):
        calls.append(href)
        return RawContent(text="vmess://x", source_url=href, collector_name=collector_name)

    monkeypatch.setattr(github_module, "fetch_linked_content", fake_fetch_linked)

    results = await collector._fetch_contents(_FakeSession(readme), items)
    assert len(calls) == 1
    assert len(results) == 1


@pytest.mark.asyncio
async def test_web_scraper_fetches_unique_links_once(monkeypatch):
    cfg = WebScrapeSourceConfig(urls=["https://example.com/page"], request_delay=0)
    collector = WebScraperCollector(cfg)
    html = (
        '<a href="https://example.com/sub.txt">one</a>'
        '<a href="https://example.com/sub.txt">two</a>'
        '<a href="https://example.com/other.yaml">three</a>'
    )
    calls = []

    async def fake_fetch_linked(sess, href, base_url=""):
        calls.append(href)
        return RawContent(text="vmess://x", source_url=href, collector_name="web_scrape")

    monkeypatch.setattr(collector, "_fetch_linked", fake_fetch_linked)

    results = await collector._scrape(_FakeSession(html), "https://example.com/page")
    assert len(calls) == 2
    assert len(results) == 2
