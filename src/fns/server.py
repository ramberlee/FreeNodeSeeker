"""
Built-in HTTP server for sharing output files (fns.txt, fns.yaml, fns.json)
over HTTP, so they can be used as subscription URLs in proxy clients.

Integrated into the pipeline: starts together with run --serve or daemon.
"""

from __future__ import annotations

import logging
from pathlib import Path

from aiohttp import web

from fns.config import ServerConfig

logger = logging.getLogger("fns")

routes = web.RouteTableDef()


def _build_app(output_dir: Path) -> web.Application:
    """Build aiohttp web application serving files from output_dir."""

    @routes.get("/")
    async def index(request: web.Request) -> web.Response:
        """Status page."""
        files = []
        for name in ("fns.txt", "fns.yaml", "fns.json", "fns.cache.json"):
            fp = output_dir / name
            if fp.exists():
                files.append(f"{name} ({fp.stat().st_size} bytes)")
        html = (
            "<html><body>"
            "<h2>FreeNodeSeeker Server</h2>"
            "<ul>"
            + "".join(f"<li>{f}</li>" for f in files)
            + "</ul>"
            "<hr><pre>"
            "GET /fns.txt   — Base64 subscription\n"
            "GET /fns.yaml   — Clash YAML config\n"
            "GET /fns.json   — JSON node data\n"
            "GET /           — this page"
            "</pre></body></html>"
        )
        return web.Response(text=html, content_type="text/html")

    @routes.get("/fns.txt")
    async def serve_txt(request: web.Request) -> web.Response:
        return _file_response(output_dir / "fns.txt", "text/plain", "utf-8")

    @routes.get("/fns.yaml")
    async def serve_yaml(request: web.Request) -> web.Response:
        return _file_response(output_dir / "fns.yaml", "text/yaml", "utf-8")

    @routes.get("/fns.json")
    async def serve_json(request: web.Request) -> web.Response:
        return _file_response(output_dir / "fns.json", "application/json", "utf-8")

    app = web.Application()
    app.add_routes(routes)
    return app


def _file_response(path: Path, content_type: str, charset: str | None = None) -> web.Response:
    if not path.exists():
        return web.Response(status=404, text="File not found")
    try:
        data = path.read_bytes()
    except OSError as e:
        return web.Response(status=500, text=f"Error reading file: {e}")
    return web.Response(
        body=data,
        status=200,
        content_type=content_type,
        charset=charset,
        headers={"Access-Control-Allow-Origin": "*"},
    )


async def run_server(cfg: ServerConfig, output_dir: Path) -> web.AppRunner:
    """Start the HTTP server and return the runner (for lifecycle management).

    Caller should ``await runner.cleanup()`` on shutdown.
    """
    app = _build_app(output_dir)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, cfg.host, cfg.port)
    await site.start()
    logger.info(f"HTTP server started at http://{cfg.host}:{cfg.port}/")
    return runner
