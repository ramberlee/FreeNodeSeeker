"""
FreeNodeSeeker CLI — auto-collect free V2Ray/Clash subscription nodes.
"""

from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from fns import __version__
from fns.config import FnsConfig, find_config, load_config, write_example_config
from fns.utils.log import setup_logging

app = typer.Typer(
    name="fns",
    help="Auto-collect free V2Ray/Clash subscription nodes.",
    no_args_is_help=True,
)
console = Console()
logger = logging.getLogger("fns")
sources_app = typer.Typer()
app.add_typer(sources_app, name="sources", help="Manage sources.")
config_app = typer.Typer()
app.add_typer(config_app, name="config", help="Manage configuration.")

# Global config path override (set by app-level callback)
_global_config_path: Path | None = None


@app.callback()
def _global_config(
    config_path: Optional[Path] = typer.Option(None, "--config", "-c", help="Config file path"),
) -> None:
    """FreeNodeSeeker — auto-collect free V2Ray/Clash subscription nodes."""
    global _global_config_path
    _global_config_path = config_path


# ── Helpers ──────────────────────────────────────────────────────────────────

def _resolve_config(path: Optional[Path]) -> FnsConfig:
    cfg = load_config(path or _global_config_path)
    setup_logging(cfg.logging.level, cfg.logging.file)
    return cfg


# ── Core Commands ────────────────────────────────────────────────────────────

@app.command()
def run(
    output_dir: Optional[Path] = typer.Option(None, "--output-dir", "-o", help="Output directory"),
    formats: Optional[str] = typer.Option(None, "--formats", "-f", help="Comma-separated: clash,base64,json"),
    skip_validation: bool = typer.Option(False, "--skip-validation", help="Skip connectivity test"),
    max_nodes: int | None = typer.Option(None, "--max-nodes", "-n", help="Alive nodes to output (default from config, 0=no limit)"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    serve: bool = typer.Option(False, "--serve", "-s", help="Start HTTP server after pipeline"),
    no_serve: bool = typer.Option(False, "--no-serve", help="Disable HTTP server (override config)"),
) -> None:
    """Full pipeline: collect -> parse -> validate -> merge -> output.

    With --max-nodes, existing output nodes are re-validated first.
    Only collects new nodes if not enough alive ones remain.

    With --serve, starts the built-in HTTP server after pipeline completes
    to share output files over HTTP (useful as subscription URL).
    """
    cfg = _resolve_config(None)
    if verbose:
        cfg.logging.level = "DEBUG"
        setup_logging(cfg.logging.level, cfg.logging.file)
    if output_dir:
        cfg.output.dir = str(output_dir)
    if formats:
        cfg.output.formats = [f.strip() for f in formats.split(",")]

    console.print(f"[bold]FreeNodeSeeker v{__version__}[/]")
    if max_nodes:
        console.print(f"Target: {max_nodes} alive nodes")
    elif max_nodes == 0:
        console.print("Target: all alive nodes (no limit)")
    else:
        console.print(f"Target: {cfg.max_alive_nodes} alive nodes (from config)")
    console.print(f"Output dir: {cfg.output.dir}")
    console.print(f"Formats: {', '.join(cfg.output.formats)}")

    from fns.pipeline import run_pipeline

    result = asyncio.run(run_pipeline(
        cfg,
        skip_validation=skip_validation,
        max_nodes=max_nodes,
    ))
    _print_result(result)

    # ── Serve ────────────────────────────────────────────────────
    start_server = serve or (cfg.server.enabled and not no_serve)
    if start_server:
        _start_http_server(cfg)


def _start_http_server(cfg: FnsConfig) -> None:
    """Start the built-in HTTP server and block until Ctrl+C."""
    from fns.server import run_server

    output_dir = Path(cfg.output.dir)
    console.print(f"[bold]Starting HTTP server on {cfg.server.host}:{cfg.server.port}...[/]")

    async def _serve():
        runner = await run_server(cfg.server, output_dir)
        console.print(f"[green]HTTP server running at http://{cfg.server.host}:{cfg.server.port}/[/]")
        console.print("[dim]Press Ctrl+C to stop[/]")
        try:
            await asyncio.Event().wait()  # sleep forever
        finally:
            await runner.cleanup()
            console.print("[yellow]HTTP server stopped[/]")

    try:
        asyncio.run(_serve())
    except KeyboardInterrupt:
        console.print("\n[yellow]Shutting down...[/]")


@app.command()
def daemon(
    interval: Optional[int] = typer.Option(None, "--interval", "-i", help="Hours between runs"),
    no_serve: bool = typer.Option(False, "--no-serve", help="Disable HTTP server"),
) -> None:
    """Start periodic collection daemon with built-in HTTP server.

    The HTTP server runs alongside the collection loop, serving the
    latest output files over HTTP for use as subscription URLs.
    """
    cfg = _resolve_config(None)
    if interval:
        cfg.scheduler.interval_hours = interval
    if no_serve:
        cfg.server.enabled = False

    console.print(f"[bold]Starting daemon — every {cfg.scheduler.interval_hours}h[/]")
    if cfg.server.enabled:
        console.print(f"[bold]HTTP server on {cfg.server.host}:{cfg.server.port}[/]")
    else:
        console.print("[dim]HTTP server disabled[/]")
    from fns.scheduler import start_daemon

    start_daemon(cfg)


@app.command()
def validate(
    url: str = typer.Argument(..., help="Proxy URI or subscription URL/file"),
    timeout: float = typer.Option(5.0, "--timeout", "-t", help="Request timeout (seconds)"),
) -> None:
    """Validate a single subscription URL or local file."""
    cfg = FnsConfig()
    cfg.validator.timeout = timeout
    setup_logging()

    from fns.parsers.detector import parse_auto
    from fns.utils.network import make_session
    from fns.validators.tcp_validator import TcpValidator

    async def _validate():
        async with make_session() as sess:
            async with sess.get(url) as resp:
                text = await resp.text()
        result = parse_auto(text, url)
        console.print(f"Parsed {len(result.nodes)} nodes from {url}")

        validator = TcpValidator(cfg.validator)
        validated = await validator.validate_all(result.nodes)
        return validated

    nodes = asyncio.run(_validate())
    _print_node_table(nodes)


@app.command()
def check(
    address: str = typer.Argument(..., help="IP or domain"),
    port: int = typer.Argument(..., help="Port number"),
    timeout: float = typer.Option(5.0, "--timeout", "-t", help="Request timeout"),
    test_url: str = typer.Option(
        "http://www.google.com/", "--url", "-u", help="URL to request through the proxy"
    ),
    proxy_type: str = typer.Option(
        "http", "--type", "-T", help="Proxy protocol: http, socks5, ss, trojan, vmess, vless, hysteria2, tuic"
    ),
) -> None:
    """Check if an endpoint can proxy HTTP requests to a test URL."""
    setup_logging()
    from fns.validators.tcp_validator import TcpValidator
    from fns.config import ValidatorConfig
    from fns.models import ProxyNode, ProxyType

    try:
        pt = ProxyType(proxy_type.lower())
    except ValueError:
        valid = ", ".join(t.value for t in ProxyType)
        console.print(f"[red]Unknown proxy type '{proxy_type}'. Valid: {valid}[/]")
        raise typer.Exit(1)

    vcfg = ValidatorConfig(timeout=timeout, test_url=test_url)
    validator = TcpValidator(vcfg)
    node = ProxyNode(node_type=pt, address=address, port=port)
    result = asyncio.run(validator.validate_one(node))
    if result.is_alive:
        console.print(f"[green][OK] {pt.value}://{address}:{port} proxies {test_url} — {result.latency_ms:.0f}ms[/]")
    else:
        console.print(f"[red][FAIL] {pt.value}://{address}:{port} — cannot proxy {test_url}[/]")


# ── Config Subcommands ──────────────────────────────────────────────────────

@config_app.command("show")
def config_show() -> None:
    """Print current config."""
    path = find_config()
    if path:
        console.print(f"Config: {path}")
        cfg = load_config(path)
    else:
        console.print("No config found, using defaults")
        cfg = FnsConfig()
    # Pretty print via model_dump
    import json
    console.print_json(json.dumps(cfg.model_dump(), indent=2, default=str))


@config_app.command("init")
def config_init(
    path: Optional[Path] = typer.Option(None, "--path", "-p", help="Output path"),
    force: bool = typer.Option(False, "--force", help="Overwrite existing"),
) -> None:
    """Generate example config."""
    target = path or Path("fns.yaml")
    if target.exists() and not force:
        console.print(f"[red]{target} exists. Use --force to overwrite.[/]")
        raise typer.Exit(1)
    write_example_config(target)
    console.print(f"[green]Example config written to {target}[/]")


@config_app.command("path")
def config_path() -> None:
    """Show resolved config path."""
    path = find_config()
    if path:
        console.print(str(path))
    else:
        console.print("[dim]No config found[/]")


# ── Sources Subcommands ─────────────────────────────────────────────────────

@sources_app.command("list")
def sources_list(
    all_sources: bool = typer.Option(False, "--all", "-a", help="Show all, including disabled"),
) -> None:
    """List configured sources."""
    cfg = _resolve_config(None)
    table = Table(title="Sources")
    table.add_column("Category")
    table.add_column("Source")
    table.add_column("Status")

    for cat, cat_cfg, get_items in [
        ("github", cfg.sources.github, lambda c: c.search_queries),
        ("web_scrape", cfg.sources.web_scrape, lambda c: c.urls),
        ("api", cfg.sources.api, lambda c: c.urls),
    ]:
        if not cat_cfg.enabled and not all_sources:
            continue
        status = "[green]enabled[/]" if cat_cfg.enabled else "[dim]disabled[/]"
        items = get_items(cat_cfg)
        if items:
            for item in items:
                table.add_row(cat, str(item)[:80], status)
        else:
            table.add_row(cat, "[dim](empty)[/]", status)

    console.print(table)


# ── Output Helpers ───────────────────────────────────────────────────────────

def _print_result(result) -> None:
    """Print pipeline result summary."""
    from fns.models import PipelineResult
    r: PipelineResult = result
    console.print()
    console.print(f"[bold]Results:[/] {len(r.nodes)} nodes from {r.sources_used} sources, "
                  f"[green]{r.alive_count} alive[/]")
    if r.parse_errors:
        console.print(f"[yellow]{len(r.parse_errors)} parse errors[/]")


def _print_node_table(nodes) -> None:
    table = Table(title="Nodes")
    table.add_column("Type")
    table.add_column("Address")
    table.add_column("Port")
    table.add_column("Latency")
    table.add_column("Status")
    table.add_column("Remark")

    for n in sorted(nodes, key=lambda x: (not x.is_alive, x.latency_ms or 9999)):
        status = "[green]alive[/]" if n.is_alive else "[red]dead[/]"
        lat = f"{n.latency_ms:.0f}ms" if n.latency_ms else "-"
        table.add_row(n.node_type.value, n.address, str(n.port), lat, status, n.remark or "-")

    console.print(table)
