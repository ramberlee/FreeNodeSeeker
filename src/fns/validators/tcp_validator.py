from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import shutil
import socket
import tempfile
import time
from pathlib import Path
from urllib.parse import urlparse

import aiohttp

from fns.config import ValidatorConfig
from fns.formatters.clash import node_to_clash_proxy
from fns.models import ProxyNode, ProxyType, format_host_port

logger = logging.getLogger("fns")

# ── mihomo binary discovery ──────────────────────────────────────────────────

_MIHOMO_PATH: str | None = None


def _find_mihomo() -> str | None:
    """Locate mihomo binary on the system."""
    global _MIHOMO_PATH
    if _MIHOMO_PATH is not None:
        return _MIHOMO_PATH

    root = Path(__file__).resolve().parent.parent.parent.parent
    candidates = [
        str(root / "bin" / "mihomo.exe"),
        str(root / "bin" / "mihomo"),
        str(root / ".venv" / "Scripts" / "mihomo.exe"),
        shutil.which("mihomo"),
        shutil.which("mihomo.exe"),
    ]

    for candidate in candidates:
        if candidate and os.path.exists(candidate):
            _MIHOMO_PATH = candidate
            logger.info(f"Found mihomo at {candidate}")
            return candidate

    logger.warning(
        "mihomo not found — VMess/VLESS/Hysteria2/TUIC will be "
        "marked dead (no real proxy validation)"
    )
    _MIHOMO_PATH = ""
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
    return (
        parsed.hostname or "www.google.com",
        parsed.port or (443 if parsed.scheme == "https" else 80),
    )


def _plain_host(host: str) -> str:
    """Strip IPv6 brackets for APIs that expect a bare address."""
    if host.startswith("[") and host.endswith("]"):
        return host[1:-1]
    return host


def _is_success_status(status: int) -> bool:
    """Return True only for 2xx HTTP status codes."""
    return 200 <= status < 300


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

    if parsed.scheme == "https":
        import ssl

        # pproxy exposes the same TLS wrapper it uses for its own test_url.
        from pproxy import proto

        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        reader, writer = proto.sslwrap(reader, writer, ctx, False, host)

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
        status_line = await asyncio.wait_for(reader.readline(), timeout=timeout)
    except (asyncio.TimeoutError, TimeoutError):
        return False
    if not status_line:
        return False
    # Parse HTTP status line: "HTTP/1.x NNN ..."
    parts = status_line.split(b" ", 2)
    if len(parts) < 2:
        return False
    try:
        status = int(parts[1])
    except ValueError:
        return False
    return _is_success_status(status)


# ── mihomo subprocess validator ──────────────────────────────────────────────


def _build_mihomo_config(node: ProxyNode, listen_port: int) -> dict:
    """Generate a minimal mihomo config that routes through *node*."""
    proxy = node_to_clash_proxy(node)
    name = proxy["name"]
    return {
        "log-level": "error",
        "port": listen_port,
        "mode": "rule",
        "proxies": [proxy],
        "proxy-groups": [{"name": "TEST", "type": "select", "proxies": [name]}],
        "rules": ["MATCH,TEST"],
    }


def _write_mihomo_config(config: dict, config_path: str) -> None:
    """Write mihomo config as UTF-8 JSON without escaping non-ASCII names."""
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)


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


async def _validate_via_mihomo(
    node: ProxyNode,
    test_url: str,
    timeout: float,
    session: aiohttp.ClientSession | None = None,
) -> tuple[bool, float | None]:
    """Test a node by starting mihomo and routing a request through it.

    Returns (is_alive, latency_ms).
    """
    binary = _find_mihomo()
    if not binary:
        node.validation_error = "mihomo_not_available"
        return False, None

    port = _free_port()
    config = _build_mihomo_config(node, port)
    work_dir = tempfile.mkdtemp(prefix="fns-mihomo-")
    config_path = os.path.join(work_dir, "config.json")
    stderr_tail = b""
    try:
        _write_mihomo_config(config, config_path)

        proc = await asyncio.create_subprocess_exec(
            binary,
            "-f",
            config_path,
            "-d",
            work_dir,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            if not await _wait_for_port(port, min(timeout, 5.0)):
                node.validation_error = "mihomo_startup_failed"
                return False, None

            start = time.monotonic()
            proxy_url = f"http://127.0.0.1:{port}"

            if session is not None and not session.closed:
                async with session.get(
                    test_url, proxy=proxy_url, allow_redirects=False
                ) as resp:
                    if not _is_success_status(resp.status):
                        node.validation_error = f"proxy_status_{resp.status}"
                        return False, None
                    await resp.read()
            else:
                async with aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=timeout)
                ) as sess:
                    async with sess.get(
                        test_url, proxy=proxy_url, allow_redirects=False
                    ) as resp:
                        if not _is_success_status(resp.status):
                            node.validation_error = f"proxy_status_{resp.status}"
                            return False, None
                        await resp.read()

            elapsed = (time.monotonic() - start) * 1000
            return True, round(elapsed, 1)
        except Exception as e:
            if isinstance(e, (asyncio.TimeoutError, TimeoutError)) and not str(e):
                detail = f"{type(e).__name__} (after {timeout:.1f}s)"
            else:
                detail = f"{type(e).__name__}: {e}"[:200]
            node.validation_error = f"mihomo_request_failed: {detail}"
            return False, None
        finally:
            try:
                proc.terminate()
            except Exception:
                pass
            try:
                await asyncio.wait_for(proc.wait(), timeout=5.0)
            except (ProcessLookupError, TimeoutError, asyncio.TimeoutError):
                try:
                    proc.kill()
                except Exception:
                    pass
                try:
                    await asyncio.wait_for(proc.wait(), timeout=5.0)
                except Exception:
                    pass
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
            if proc.stderr is not None:
                try:
                    stderr_tail = (
                        await asyncio.wait_for(proc.stderr.read(), timeout=1.0)
                    )[-1000:]
                except Exception:
                    pass
    except Exception as e:
        node.validation_error = f"mihomo_spawn_failed: {type(e).__name__}: {e}"
        return False, None
    finally:
        if stderr_tail:
            if node.validation_error is None or node.validation_error.startswith(
                ("mihomo_request_failed", "mihomo_startup_failed")
            ):
                node.validation_error = (
                    "mihomo_error: "
                    + stderr_tail[-200:].decode("utf-8", errors="replace")
                )
        logger.debug(
            f"mihomo stderr for {node.node_type.value}://{node.address}:{node.port}: "
            f"{stderr_tail[-500:]!r}"
        )
        shutil.rmtree(work_dir, ignore_errors=True)
    return False, None


# ── TcpValidator ─────────────────────────────────────────────────────────────


class TcpValidator:
    """Validates proxy nodes by accessing test_url through them.

    Routes to the appropriate protocol handler:
      HTTP    → aiohttp native proxy
      SOCKS5  → aiohttp-socks ProxyConnector
      SS/Trojan → mihomo subprocess (pproxy fallback without mihomo)
      VMess/VLESS/Hysteria2/TUIC → mihomo subprocess (no TCP fallback)
    """

    def __init__(self, config: ValidatorConfig):
        self.concurrency = config.concurrency
        self.timeout = config.timeout
        self.retries = config.retries
        self.test_url = config.test_url
        self._semaphore = asyncio.Semaphore(config.concurrency)
        # mihomo 进程启动是主要开销，提高并发比限制更合理
        self._mihomo_sem = asyncio.Semaphore(max(1, config.concurrency // 2))
        self._shared_session: aiohttp.ClientSession | None = None
        self._session_owner: bool = False

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create a shared aiohttp session for the validation batch."""
        if self._shared_session is None or self._shared_session.closed:
            connector = aiohttp.TCPConnector(
                limit=0,          # 不限连接数
                force_close=True, # 每次用完立即关闭，因为代理端口每次不同
                enable_cleanup_closed=True,
            )
            timeout_obj = aiohttp.ClientTimeout(total=self.timeout)
            self._shared_session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout_obj,
            )
            self._session_owner = True
        return self._shared_session

    async def _close_session(self) -> None:
        if self._session_owner and self._shared_session and not self._shared_session.closed:
            await self._shared_session.close()
            self._shared_session = None
            self._session_owner = False

    # ── Public API ──────────────────────────────────────────────────────

    async def validate_all(self, nodes: list[ProxyNode]) -> list[ProxyNode]:
        if not nodes:
            return nodes

        # Separate nodes into simple (direct handler) and complex (TCP pre-filter → mihomo)
        simple_nodes: list[ProxyNode] = []
        complex_nodes: list[ProxyNode] = []

        for n in nodes:
            if n.node_type in (ProxyType.HTTP, ProxyType.SOCKS5):
                simple_nodes.append(n)
            else:
                complex_nodes.append(n)

        # Phase 1: TCP pre-filter every node at high concurrency. This is much
        # cheaper than a full protocol handshake and skips dead endpoints quickly.
        prefilter_nodes = simple_nodes + complex_nodes
        tcp_alive = (
            await self._tcp_prefilter_batch(prefilter_nodes) if prefilter_nodes else []
        )
        logger.info(
            f"TCP pre-filter: {len(tcp_alive)}/{len(nodes)} nodes reachable"
        )

        # Phase 2: Full validation on reachable candidates
        all_candidates = tcp_alive
        total = len(all_candidates)

        logger.info(
            f"Full validation: {len(simple_nodes)} simple + {len(complex_nodes)} "
            f"complex, {total} reachable "
            f"(concurrency={self.concurrency}, timeout={self.timeout}s)..."
        )
        done = 0
        alive_count = 0
        log_every = max(1, total // 10) if total else 1

        async def _validate_one_count(node: ProxyNode) -> ProxyNode:
            nonlocal done, alive_count
            result = await self._validate_with_sem(node)
            done += 1
            if result.is_alive:
                alive_count += 1
            if done % log_every == 0 or done == total:
                logger.info(f"  Progress: {done}/{total} checked, {alive_count} alive so far")
            return result

        try:
            if all_candidates:
                tasks = [_validate_one_count(node) for node in all_candidates]
                await asyncio.gather(*tasks)
        finally:
            try:
                await self._close_session()
            except Exception:
                logger.debug("Failed to close shared aiohttp session", exc_info=True)

        alive = sum(1 for n in nodes if n.is_alive)
        logger.info(f"Validation done: {alive}/{len(nodes)} alive")
        if logger.isEnabledFor(logging.DEBUG):
            for n in nodes:
                if not n.is_alive:
                    logger.debug(
                        f"Validation failed: {n.node_type.value}://{n.address}:{n.port} "
                        f"-> {n.validation_error}"
                    )
        return nodes

    async def _tcp_prefilter_batch(self, nodes: list[ProxyNode]) -> list[ProxyNode]:
        """Fast TCP port check for all complex nodes at high concurrency.

        Uses a dedicated high-concurrency semaphore since TCP connects are cheap.
        """
        tcp_sem = asyncio.Semaphore(min(len(nodes), max(self.concurrency * 3, 100)))

        async def _check_one(node: ProxyNode) -> ProxyNode | None:
            async with tcp_sem:
                if await self._quick_tcp_check(node):
                    node.validation_error = None
                    return node
                node.is_alive = False
                node.latency_ms = None
                node.validation_error = "tcp_unreachable"
                return None

        results = await asyncio.gather(*[_check_one(n) for n in nodes])
        return [r for r in results if r is not None]

    async def validate_one(self, node: ProxyNode) -> ProxyNode:
        try:
            return await self._validate_with_sem(node)
        finally:
            try:
                await self._close_session()
            except Exception:
                logger.debug("Failed to close shared aiohttp session", exc_info=True)

    # ── Internal dispatch ───────────────────────────────────────────────

    async def _validate_with_sem(self, node: ProxyNode) -> ProxyNode:
        async with self._semaphore:
            try:
                return await self._validate_node(node)
            except Exception as e:
                logger.warning(
                    f"Unexpected validation error for {node.node_type.value}://"
                    f"{node.address}:{node.port}: {type(e).__name__}: {e}"
                )
                node.is_alive = False
                node.latency_ms = None
                node.validation_error = f"validation_error: {type(e).__name__}: {e}"
                return node

    async def _validate_node(self, node: ProxyNode) -> ProxyNode:
        # SS/Trojan get full protocol validation through mihomo when available;
        # fall back to pproxy only when mihomo is missing.
        if _find_mihomo():
            if node.node_type in (ProxyType.SS, ProxyType.TROJAN):
                return await self._try_mihomo(node)
            handlers = {
                ProxyType.HTTP: self._try_http,
                ProxyType.SOCKS5: self._try_socks5,
            }
            handler = handlers.get(node.node_type)
            if handler:
                return await handler(node)

            # VMess, VLESS, Hysteria2, TUIC: TCP pre-filter already done in validate_all,
            # go straight to full protocol validation.
            return await self._try_mihomo(node)

        handlers = {
            ProxyType.HTTP: self._try_http,
            ProxyType.SOCKS5: self._try_socks5,
            ProxyType.SS: self._try_ss,
            ProxyType.TROJAN: self._try_trojan,
        }
        handler = handlers.get(node.node_type)
        if handler:
            return await handler(node)

        logger.warning(
            f"No mihomo available; marking {node.node_type.value}://"
            f"{node.address}:{node.port} dead instead of using a TCP-only check"
        )
        node.is_alive = False
        node.latency_ms = None
        node.validation_error = "mihomo_not_available"
        return node

    async def _quick_tcp_check(self, node: ProxyNode) -> bool:
        """Fast TCP port check to filter out dead nodes before expensive validation."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(_plain_host(node.address), node.port),
                timeout=min(self.timeout * 0.5, 3.0),
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
        proxy_url = f"http://{format_host_port(node.address, node.port)}"
        session = await self._get_session()
        username = getattr(node, "username", None)
        proxy_auth = None
        if username or node.password:
            proxy_auth = aiohttp.BasicAuth(username or "", node.password or "")
        for attempt in range(self.retries + 1):
            try:
                start = time.monotonic()
                async with session.get(
                    self.test_url,
                    proxy=proxy_url,
                    proxy_auth=proxy_auth,
                    allow_redirects=False,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                ) as resp:
                    if not _is_success_status(resp.status):
                        node.validation_error = f"http_status_{resp.status}"
                        node.is_alive = False
                        node.latency_ms = None
                        return node
                    await resp.read()
                elapsed = (time.monotonic() - start) * 1000
                node.latency_ms = round(elapsed, 1)
                node.is_alive = True
                node.validation_error = None
                return node
            except (asyncio.TimeoutError, aiohttp.ClientError, OSError) as e:
                logger.debug(
                    f"HTTP error via {node.address}:{node.port}: "
                    f"{type(e).__name__}: {e} "
                    f"(attempt {attempt + 1})"
                )
            except Exception as e:
                logger.debug(
                    f"Error via {node.address}:{node.port}: "
                    f"{type(e).__name__}: {e} "
                    f"(attempt {attempt + 1})"
                )

        node.is_alive = False
        node.latency_ms = None
        node.validation_error = "http_request_failed"
        return node

    # ── SOCKS5 ──────────────────────────────────────────────────────────

    async def _try_socks5(self, node: ProxyNode) -> ProxyNode:
        from aiohttp_socks import ProxyConnector
        from aiohttp_socks import ProxyType as SocksProxyType

        username = node.username or node.uuid or None
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
                        allow_redirects=False,
                        timeout=aiohttp.ClientTimeout(total=self.timeout),
                    ) as resp:
                        if not _is_success_status(resp.status):
                            node.validation_error = f"socks5_status_{resp.status}"
                            node.is_alive = False
                            node.latency_ms = None
                            return node  # proxy returned error
                        await resp.read()
                    elapsed = (time.monotonic() - start) * 1000
                    node.latency_ms = round(elapsed, 1)
                    node.is_alive = True
                    node.validation_error = None
                    return node
                except (asyncio.TimeoutError, aiohttp.ClientError, OSError) as e:
                    logger.debug(
                        f"SOCKS5 error via {node.address}:{node.port}: "
                        f"{type(e).__name__}: {e} "
                        f"(attempt {attempt + 1})"
                    )
                except Exception as e:
                    logger.debug(
                        f"Error via {node.address}:{node.port}: "
                        f"{type(e).__name__}: {e} "
                        f"(attempt {attempt + 1})"
                    )

        node.is_alive = False
        node.latency_ms = None
        node.validation_error = "socks5_request_failed"
        return node

    # ── Shadowsocks ─────────────────────────────────────────────────────

    async def _try_ss(self, node: ProxyNode) -> ProxyNode:
        import pproxy

        method = node.method or "aes-256-gcm"
        password = node.password or ""
        # pproxy requires the base64 padding, otherwise short userinfo strings
        # cannot be decoded back to "method:password".
        userinfo = base64.b64encode(f"{method}:{password}".encode()).decode()
        ss_uri = f"ss://{userinfo}@{format_host_port(node.address, node.port)}"

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
                    node.validation_error = None
                    return node
            except (asyncio.TimeoutError, OSError, ConnectionError) as e:
                logger.debug(
                    f"SS error via {node.address}:{node.port}: "
                    f"{type(e).__name__}: {e} "
                    f"(attempt {attempt + 1})"
                )
            except Exception as e:
                logger.debug(
                    f"Error via {node.address}:{node.port}: "
                    f"{type(e).__name__}: {e} "
                    f"(attempt {attempt + 1})"
                )

        node.is_alive = False
        node.latency_ms = None
        node.validation_error = "ss_request_failed"
        return node

    # ── Trojan ──────────────────────────────────────────────────────────

    async def _try_trojan(self, node: ProxyNode) -> ProxyNode:
        # Prefer pproxy for Trojan (pure Python)
        import pproxy

        password = node.password or ""
        # pproxy uses the URI fragment for the Trojan password and +ssl for TLS.
        scheme = "trojan+ssl" if node.tls else "trojan"
        # pproxy keeps the raw fragment as the Trojan password, so do not
        # percent-encode it (raw #/@ inside the fragment survive URL parsing).
        trojan_uri = (
            f"{scheme}://{format_host_port(node.address, node.port)}"
            f"#{password}"
        )

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
                    node.validation_error = None
                    return node
            except (asyncio.TimeoutError, OSError, ConnectionError) as e:
                logger.debug(
                    f"Trojan error via {node.address}:{node.port}: "
                    f"{type(e).__name__}: {e} "
                    f"(attempt {attempt + 1})"
                )
            except Exception as e:
                logger.debug(
                    f"Error via {node.address}:{node.port}: "
                    f"{type(e).__name__}: {e} "
                    f"(attempt {attempt + 1})"
                )

        node.is_alive = False
        node.latency_ms = None
        node.validation_error = "trojan_request_failed"
        return node

    # ── mihomo (SS / Trojan / VMess / VLESS / Hysteria2 / TUIC) ────────

    async def _try_mihomo(self, node: ProxyNode) -> ProxyNode:
        async with self._mihomo_sem:
            session = await self._get_session()
            for attempt in range(self.retries + 1):
                ok, lat = await _validate_via_mihomo(
                    node, self.test_url, self.timeout, session=session
                )
                if ok:
                    node.is_alive = True
                    node.latency_ms = lat
                    node.validation_error = None
                    return node
                if node.validation_error and node.validation_error.startswith(
                    "proxy_status_"
                ):
                    # A non-2xx response from the proxy is definitive; retrying
                    # with another mihomo instance would just overwrite the reason.
                    break

        node.is_alive = False
        node.latency_ms = None
        if not node.validation_error:
            node.validation_error = "proxy_request_failed"
        return node

    # ── TCP fallback ────────────────────────────────────────────────────

    async def _try_tcp_fallback(self, node: ProxyNode) -> ProxyNode:
        """Basic TCP port check — used when mihomo is unavailable.

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
                node.validation_error = None
                if attempt == 0:
                    logger.warning(
                        f"TCP-only validation for {node.node_type.value}://"
                        f"{node.address}:{node.port} "
                        f"— NOT a real proxy test! Install mihomo for accurate validation."
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
