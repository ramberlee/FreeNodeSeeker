from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import shutil
import socket
import subprocess
import tempfile
import time
from urllib.parse import urlparse

import aiohttp

from fns.config import ValidatorConfig
from fns.models import ProxyNode, ProxyType

logger = logging.getLogger("fns")

# ── sing-box binary discovery ────────────────────────────────────────────────

_SINGBOX_PATH: str | None = None


def _find_singbox() -> str | None:
    """Locate sing-box binary on the system."""
    global _SINGBOX_PATH
    if _SINGBOX_PATH is not None:
        return _SINGBOX_PATH

    candidates = [
        "sing-box",
        "sing-box.exe",
        shutil.which("sing-box"),
        shutil.which("sing-box.exe"),
    ]
    # Check venv Scripts directory (4 levels up from validators/)
    from pathlib import Path
    venv_scripts = str(Path(__file__).parent.parent.parent.parent / ".venv" / "Scripts")
    for name in ["sing-box.exe", "sing-box"]:
        p = os.path.join(venv_scripts, name)
        if os.path.exists(p):
            candidates.insert(0, p)

    for candidate in candidates:
        if candidate and os.path.exists(candidate):
            _SINGBOX_PATH = candidate
            logger.info(f"Found sing-box at {candidate}")
            return candidate

    logger.warning("sing-box not found — VMess/VLESS/Hysteria2/TUIC will use TCP fallback (port check only, NOT real proxy validation!)")
    _SINGBOX_PATH = ""
    return None


# ── Helpers ──────────────────────────────────────────────────────────────────


def _free_port() -> int:
    """Find a free local TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


def _parse_host_port(url: str) -> tuple[str, int]:
    """Extract hostname and port from a URL."""
    parsed = urlparse(url)
    return parsed.hostname or "www.google.com", parsed.port or (443 if parsed.scheme == "https" else 80)


_SUCCESS_CODES = {b"200", b"301", b"302", b"303", b"307", b"308"}


async def _send_http_get(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    test_url: str,
    timeout: float,
) -> bool:
    """Send an HTTP GET through an established tunnel and check the response."""
    parsed = urlparse(test_url)
    host = parsed.hostname or "www.google.com"
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    req = (
        f"GET {path} HTTP/1.0\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: Mozilla/5.0\r\n"
        f"Accept: */*\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    )
    writer.write(req.encode())
    await writer.drain()
    try:
        data = await asyncio.wait_for(reader.read(4096), timeout=timeout)
    except asyncio.TimeoutError:
        return False
    if not data or len(data) < 12:
        return False
    # Parse HTTP status line: "HTTP/1.x NNN ..."
    parts = data[:32].split(b" ")
    if len(parts) < 2:
        return False
    return parts[1] in _SUCCESS_CODES


# ── sing-box subprocess validator ─────────────────────────────────────────────


def _build_singbox_config(node: ProxyNode, listen_port: int) -> dict:
    """Generate a minimal sing-box config that routes through *node*."""
    outbound: dict = {"type": node.node_type.value, "server": node.address, "server_port": node.port}

    if node.node_type == ProxyType.VMESS:
        outbound["uuid"] = node.uuid or ""
        outbound["security"] = node.encryption or "auto"
        outbound["alter_id"] = 0
        t = node.transport or "tcp"
        if t == "ws":
            outbound["transport"] = {"type": "ws", "path": node.ws_path or "/"}
            if node.ws_host:
                outbound["transport"]["headers"] = {"Host": node.ws_host}
        if node.tls:
            outbound["tls"] = {"enabled": True, "server_name": node.sni or node.address}
            if node.fingerprint:
                outbound["tls"]["utls"] = {"enabled": True, "fingerprint": node.fingerprint}

    elif node.node_type == ProxyType.VLESS:
        outbound["uuid"] = node.uuid or ""
        outbound["flow"] = node.flow or ""
        t = node.transport or "tcp"
        if t == "ws":
            outbound["transport"] = {"type": "ws", "path": node.ws_path or "/"}
            if node.ws_host:
                outbound["transport"]["headers"] = {"Host": node.ws_host}
        if node.tls:
            outbound["tls"] = {"enabled": True, "server_name": node.sni or node.address}
            if node.fingerprint:
                outbound["tls"]["utls"] = {"enabled": True, "fingerprint": node.fingerprint}
        if node.public_key:
            outbound.setdefault("tls", {})["reality"] = {
                "enabled": True,
                "public_key": node.public_key,
                "short_id": node.short_id or "",
            }

    elif node.node_type == ProxyType.HYSTERIA2:
        outbound["password"] = node.password or ""
        outbound["tls"] = {"enabled": True, "server_name": node.sni or node.address}
        if node.obfs:
            outbound["obfs"] = {"type": node.obfs, "password": node.obfs_password or ""}

    elif node.node_type == ProxyType.TUIC:
        outbound["uuid"] = node.uuid or ""
        outbound["password"] = node.password or ""
        outbound["tls"] = {"enabled": True, "server_name": node.sni or node.address}
        outbound["congestion_control"] = node.congestion_control or "bbr"

    elif node.node_type == ProxyType.TROJAN:
        outbound["password"] = node.password or ""
        outbound["tls"] = {"enabled": True, "server_name": node.sni or node.address}
        if node.fingerprint:
            outbound["tls"]["utls"] = {"enabled": True, "fingerprint": node.fingerprint}
        t = node.transport or "tcp"
        if t == "ws":
            outbound["transport"] = {"type": "ws", "path": node.ws_path or "/"}
            if node.ws_host:
                outbound["transport"]["headers"] = {"Host": node.ws_host}

    elif node.node_type == ProxyType.SS:
        outbound["method"] = node.method or "aes-256-gcm"
        outbound["password"] = node.password or ""

    return {
        "log": {"level": "error"},
        "inbounds": [{"type": "http", "listen": "127.0.0.1", "listen_port": listen_port}],
        "outbounds": [outbound],
    }


async def _wait_for_port(port: int, timeout: float) -> bool:
    """Poll a local TCP port until it accepts connections."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", port),
                timeout=min(1.0, deadline - time.monotonic()),
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return True
        except Exception:
            await asyncio.sleep(0.1)
    return False


async def _validate_via_singbox(
    node: ProxyNode, test_url: str, timeout: float
) -> tuple[bool, float | None]:
    """Test a node by starting sing-box and routing a request through it.

    Returns (is_alive, latency_ms).
    """
    binary = _find_singbox()
    if not binary:
        return False, None

    port = _free_port()
    config = _build_singbox_config(node, port)

    # Write temp config
    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, encoding="utf-8"
    )
    try:
        json.dump(config, tmp, indent=2)
        tmp.close()

        proc = await asyncio.create_subprocess_exec(
            binary,
            "run",
            "-c",
            tmp.name,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )

        try:
            if not await _wait_for_port(port, min(timeout * 0.3, 2.0)):
                return False, None

            start = time.monotonic()
            proxy_url = f"http://127.0.0.1:{port}"
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=timeout)
            ) as session:
                async with session.get(test_url, proxy=proxy_url) as resp:
                    if resp.status >= 400:
                        return False, None  # 502 = sing-box outbound failed
                    await resp.read()
            elapsed = (time.monotonic() - start) * 1000
            return True, round(elapsed, 1)
        except Exception:
            return False, None
        finally:
            try:
                proc.terminate()
            except ProcessLookupError:
                pass
            try:
                await asyncio.wait_for(proc.wait(), timeout=5.0)
            except (ProcessLookupError, TimeoutError, asyncio.TimeoutError):
                pass
            except Exception:
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass

    return False, None


# ── TcpValidator ─────────────────────────────────────────────────────────────


class TcpValidator:
    """Validates proxy nodes by accessing test_url through them.

    Routes to the appropriate protocol handler:
      HTTP    → aiohttp native proxy
      SOCKS5  → aiohttp-socks ProxyConnector
      SS      → pproxy Connection
      Trojan  → pproxy Connection (pure Python), sing-box (subprocess)
      VMess/VLESS/Hysteria2/TUIC → sing-box subprocess (TCP fallback if unavailable)
    """

    def __init__(self, config: ValidatorConfig):
        self.concurrency = config.concurrency
        self.timeout = config.timeout
        self.retries = config.retries
        self.test_url = config.test_url
        self._semaphore = asyncio.Semaphore(config.concurrency)
        self._singbox_sem = asyncio.Semaphore(max(1, config.concurrency // 10))

    # ── Public API ──────────────────────────────────────────────────────

    async def validate_all(self, nodes: list[ProxyNode]) -> list[ProxyNode]:
        if not nodes:
            return nodes

        logger.info(
            f"Validating {len(nodes)} nodes via {self.test_url} "
            f"(concurrency={self.concurrency}, timeout={self.timeout}s)..."
        )
        done = 0
        total = len(nodes)
        log_every = max(1, total // 10)  # Log ~10 times

        async def _validate_one_count(node: ProxyNode) -> ProxyNode:
            nonlocal done
            result = await self._validate_with_sem(node)
            done += 1
            if done % log_every == 0 or done == total:
                alive_so_far = sum(1 for n in nodes[:done] if n.is_alive)
                logger.info(f"  Progress: {done}/{total} checked, {alive_so_far} alive so far")
            return result

        tasks = [_validate_one_count(node) for node in nodes]
        await asyncio.gather(*tasks)
        alive = sum(1 for n in nodes if n.is_alive)
        logger.info(f"Validation done: {alive}/{len(nodes)} alive")
        return nodes

    async def validate_one(self, node: ProxyNode) -> ProxyNode:
        return await self._validate_node(node)

    # ── Internal dispatch ───────────────────────────────────────────────

    async def _validate_with_sem(self, node: ProxyNode) -> ProxyNode:
        async with self._semaphore:
            return await self._validate_node(node)

    async def _validate_node(self, node: ProxyNode) -> ProxyNode:
        handlers = {
            ProxyType.HTTP: self._try_http,
            ProxyType.SOCKS5: self._try_socks5,
            ProxyType.SS: self._try_ss,
            ProxyType.TROJAN: self._try_trojan,
        }
        handler = handlers.get(node.node_type)
        if handler:
            return await handler(node)

        # VMess, VLESS, Hysteria2, TUIC → TCP pre-filter first
        if not await self._quick_tcp_check(node):
            node.is_alive = False
            node.latency_ms = None
            return node

        if _find_singbox():
            return await self._try_singbox(node)
        return await self._try_tcp_fallback(node)

    async def _quick_tcp_check(self, node: ProxyNode) -> bool:
        """Fast TCP port check to filter out dead nodes before expensive validation."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(node.address, node.port),
                timeout=min(self.timeout * 0.3, 2.0),
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return True
        except Exception:
            return False

    # ── HTTP ────────────────────────────────────────────────────────────

    async def _try_http(self, node: ProxyNode) -> ProxyNode:
        proxy_url = f"http://{node.address}:{node.port}"
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.timeout)
        ) as session:
            for attempt in range(self.retries + 1):
                try:
                    start = time.monotonic()
                    async with session.get(
                        self.test_url,
                        proxy=proxy_url,
                        timeout=aiohttp.ClientTimeout(total=self.timeout),
                    ) as resp:
                        if resp.status >= 400:
                            return node  # proxy returned error
                        await resp.read()
                    elapsed = (time.monotonic() - start) * 1000
                    node.latency_ms = round(elapsed, 1)
                    node.is_alive = True
                    return node
                except (asyncio.TimeoutError, aiohttp.ClientError, OSError) as e:
                    logger.debug(
                        f"HTTP error via {node.address}:{node.port}: {e} "
                        f"(attempt {attempt + 1})"
                    )
                except Exception as e:
                    logger.debug(
                        f"Error via {node.address}:{node.port}: {e} "
                        f"(attempt {attempt + 1})"
                    )

        node.is_alive = False
        node.latency_ms = None
        return node

    # ── SOCKS5 ──────────────────────────────────────────────────────────

    async def _try_socks5(self, node: ProxyNode) -> ProxyNode:
        from aiohttp_socks import ProxyConnector, ProxyType as SocksProxyType

        username = node.uuid or None
        password = node.password or None
        connector = ProxyConnector(
            proxy_type=SocksProxyType.SOCKS5,
            host=node.address,
            port=node.port,
            username=username,
            password=password,
            rdns=True,
        )
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=self.timeout),
        ) as session:
            for attempt in range(self.retries + 1):
                try:
                    start = time.monotonic()
                    async with session.get(
                        self.test_url,
                        timeout=aiohttp.ClientTimeout(total=self.timeout),
                    ) as resp:
                        if resp.status >= 400:
                            return node  # proxy returned error
                        await resp.read()
                    elapsed = (time.monotonic() - start) * 1000
                    node.latency_ms = round(elapsed, 1)
                    node.is_alive = True
                    return node
                except (asyncio.TimeoutError, aiohttp.ClientError, OSError) as e:
                    logger.debug(
                        f"SOCKS5 error via {node.address}:{node.port}: {e} "
                        f"(attempt {attempt + 1})"
                    )
                except Exception as e:
                    logger.debug(
                        f"Error via {node.address}:{node.port}: {e} "
                        f"(attempt {attempt + 1})"
                    )

        node.is_alive = False
        node.latency_ms = None
        return node

    # ── Shadowsocks ─────────────────────────────────────────────────────

    async def _try_ss(self, node: ProxyNode) -> ProxyNode:
        import pproxy

        method = node.method or "aes-256-gcm"
        password = node.password or ""
        userinfo = (
            base64.urlsafe_b64encode(f"{method}:{password}".encode())
            .decode()
            .rstrip("=")
        )
        ss_uri = f"ss://{userinfo}@{node.address}:{node.port}"

        target_host, target_port = _parse_host_port(self.test_url)

        for attempt in range(self.retries + 1):
            try:
                start = time.monotonic()
                conn = pproxy.Connection(ss_uri)
                reader, writer = await asyncio.wait_for(
                    conn.tcp_connect(target_host, target_port),
                    timeout=self.timeout,
                )
                ok = await _send_http_get(reader, writer, self.test_url, self.timeout)
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                if ok:
                    elapsed = (time.monotonic() - start) * 1000
                    node.latency_ms = round(elapsed, 1)
                    node.is_alive = True
                    return node
            except (asyncio.TimeoutError, OSError, ConnectionError) as e:
                logger.debug(
                    f"SS error via {node.address}:{node.port}: {e} "
                    f"(attempt {attempt + 1})"
                )
            except Exception as e:
                logger.debug(
                    f"Error via {node.address}:{node.port}: {e} "
                    f"(attempt {attempt + 1})"
                )

        node.is_alive = False
        node.latency_ms = None
        return node

    # ── Trojan ──────────────────────────────────────────────────────────

    async def _try_trojan(self, node: ProxyNode) -> ProxyNode:
        # Prefer pproxy for Trojan (pure Python)
        import pproxy

        password = node.password or ""
        trojan_uri = f"trojan://{password}@{node.address}:{node.port}"
        if node.sni:
            trojan_uri += f"?sni={node.sni}"

        target_host, target_port = _parse_host_port(self.test_url)

        for attempt in range(self.retries + 1):
            try:
                start = time.monotonic()
                conn = pproxy.Connection(trojan_uri)
                reader, writer = await asyncio.wait_for(
                    conn.tcp_connect(target_host, target_port),
                    timeout=self.timeout,
                )
                ok = await _send_http_get(reader, writer, self.test_url, self.timeout)
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                if ok:
                    elapsed = (time.monotonic() - start) * 1000
                    node.latency_ms = round(elapsed, 1)
                    node.is_alive = True
                    return node
            except (asyncio.TimeoutError, OSError, ConnectionError) as e:
                logger.debug(
                    f"Trojan error via {node.address}:{node.port}: {e} "
                    f"(attempt {attempt + 1})"
                )
            except Exception as e:
                logger.debug(
                    f"Error via {node.address}:{node.port}: {e} "
                    f"(attempt {attempt + 1})"
                )

        node.is_alive = False
        node.latency_ms = None
        return node

    # ── sing-box (VMess / VLESS / Hysteria2 / TUIC) ─────────────────────

    async def _try_singbox(self, node: ProxyNode) -> ProxyNode:
        async with self._singbox_sem:
            for attempt in range(self.retries + 1):
                ok, lat = await _validate_via_singbox(
                    node, self.test_url, self.timeout
                )
                if ok:
                    node.is_alive = True
                    node.latency_ms = lat
                    return node

        node.is_alive = False
        node.latency_ms = None
        return node

    # ── TCP fallback ────────────────────────────────────────────────────

    async def _try_tcp_fallback(self, node: ProxyNode) -> ProxyNode:
        """Basic TCP port check — used when sing-box is unavailable.

        WARNING: This only checks if the TCP port is reachable. It does NOT
        verify that the node actually proxies traffic. False positives are expected.
        """
        for attempt in range(self.retries + 1):
            try:
                start = time.monotonic()
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(node.address, node.port),
                    timeout=self.timeout,
                )
                elapsed = (time.monotonic() - start) * 1000
                node.latency_ms = round(elapsed, 1)
                node.is_alive = True
                if attempt == 0:
                    logger.warning(
                        f"TCP-only validation for {node.node_type.value}://{node.address}:{node.port} "
                        f"— NOT a real proxy test! Install sing-box for accurate validation."
                    )
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                return node
            except asyncio.TimeoutError:
                logger.debug(
                    f"TCP timeout: {node.address}:{node.port} (attempt {attempt + 1})"
                )
            except OSError as e:
                logger.debug(
                    f"TCP OS error: {node.address}:{node.port}: {e} (attempt {attempt + 1})"
                )
            except Exception as e:
                logger.debug(
                    f"TCP error: {node.address}:{node.port}: {e} (attempt {attempt + 1})"
                )

        node.is_alive = False
        node.latency_ms = None
        return node
