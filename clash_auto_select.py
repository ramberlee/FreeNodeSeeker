#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Clash Verge Rev —— 延迟 + 带宽综合自动选线工具
================================================
原理:
  1. 通过 Clash External Controller API 递归展开目标分组下的所有叶子节点
  2. 用 /proxies/{name}/delay 接口测每个节点的延迟(ms)
  3. 经 Clash 的 mixed 代理端口下载测试文件, 测每个节点的带宽(MB/s)
  4. 综合延迟与带宽打分, 自动把目标 select 分组切到最优节点
  5. 每 INTERVAL 秒循环一次(INTERVAL<=0 则只跑一轮)
  6. 每轮评估前重新获取节点列表, 订阅更新后无需重启

与 Clash 原生 url-test 的区别:
  原生 url-test 只看延迟; 本脚本额外考虑带宽, 更适合"既要稳又要快"。

依赖: pip install requests (并发带宽模式另需 PyYAML 与 bin/mihomo, 缺失时自动回退到串行测速)
运行: python clash_auto_select.py
全部参数可用环境变量覆盖(见下方 CONFIG)。
"""

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import requests
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote

if sys.platform == "win32":
    import ctypes

    ctypes.windll.kernel32.SetConsoleOutputCP(65001)
    ctypes.windll.kernel32.SetConsoleCP(65001)

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
    sys.stderr.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)

LOG_FILE = os.getenv(
    "CLASH_LOG",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs", "clash_auto_select.log"),
)


class Tee:
    """把输出同时写到控制台和日志文件。"""

    def __init__(self, *streams):
        self.streams = streams

    def write(self, data):
        for stream in self.streams:
            stream.write(data)

    def flush(self):
        for stream in self.streams:
            stream.flush()


def setup_log_file():
    path = os.path.abspath(LOG_FILE)
    log_dir = os.path.dirname(path)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)
    log = open(path, "a", encoding="utf-8", buffering=1)
    sys.stdout = Tee(sys.__stdout__, log)
    sys.stderr = Tee(sys.__stderr__, log)


setup_log_file()

# ============================ 配置(可用环境变量覆盖) ============================
CTRL      = os.getenv("CLASH_CTRL", "http://127.0.0.1:9097")   # External Controller 地址
SECRET    = os.getenv("CLASH_SECRET", "set-your-secret")      # Clash Verge Rev 里设置的 secret
PROXY     = os.getenv("CLASH_PROXY", "http://127.0.0.1:7897")  # Clash mixed 端口(用作下载代理)
GROUP     = os.getenv("CLASH_GROUP", "综合打分")                # 要管理的顶层 select 分组名
DELAY_URL = os.getenv("CLASH_DELAY_URL", "https://cp.cloudflare.com/generate_204")  # 延迟测试 URL
TEST_URL  = os.getenv("CLASH_TEST_URL", "https://speed.cloudflare.com/__down?bytes=1000000")   # 1MB
TIMEOUT   = int(os.getenv("CLASH_TEST_TIMEOUT", "40"))         # 单节点测速超时(秒)
INTERVAL  = int(os.getenv("CLASH_INTERVAL", "300"))            # 自动选线间隔(秒); <=0 只跑一轮
LAT_THRESH = int(os.getenv("CLASH_LAT_THRESH", "3000"))        # 延迟超过此值(ms)直接淘汰
DELAY_TIMEOUT = int(os.getenv("CLASH_DELAY_TIMEOUT", "5000"))   # 单节点延迟测试超时(ms), 越低越快判死节点
W_LAT     = float(os.getenv("CLASH_W_LAT", "5.0"))             # 延迟惩罚权重: 每 1000ms 扣 W_LAT MB/s
MAX_WORKERS = min(int(os.getenv("CLASH_MAX_WORKERS", "100")), 100)   # 测试最高并发数(上限100)
MIHOMO_LIMIT = min(int(os.getenv("CLASH_MIHOMO_LIMIT", str(MAX_WORKERS))), MAX_WORKERS)  # 同时运行的独立 mihomo 实例上限(默认=MAX_WORKERS)
NODE_CONFIG = os.getenv("CLASH_NODE_CONFIG", os.path.join(os.path.dirname(os.path.abspath(__file__)), "output", "fns.yaml"))  # 含完整节点参数的 Clash 配置
MIHOMO_BIN = os.getenv("CLASH_MIHOMO", "")  # mihomo 可执行文件路径, 留空自动查找
TOPK      = int(os.getenv("CLASH_TOPK", "0"))                 # 仅对延迟最低的 TOPK 个节点测带宽(0=全部)
# =============================================================================

GROUP_TYPES = {"Selector", "URLTest", "Fallback", "LoadBalance", "Relay"}

_SPEED_LOCK = threading.Lock()          # 回退到 Clash 分组切换时, 串行保护选中节点
_MIHOMO_SEM = threading.Semaphore(MIHOMO_LIMIT)


def find_mihomo() -> str | None:
    """Locate the mihomo binary used for per-node bandwidth tests."""
    if MIHOMO_BIN and os.path.exists(MIHOMO_BIN):
        return MIHOMO_BIN
    root = os.path.dirname(os.path.abspath(__file__))
    for cand in (
        os.path.join(root, "bin", "mihomo.exe"),
        os.path.join(root, "bin", "mihomo"),
        os.path.join(root, ".venv", "Scripts", "mihomo.exe"),
        shutil.which("mihomo"),
        shutil.which("mihomo.exe"),
    ):
        if cand and os.path.exists(cand):
            return cand
    return None


def load_node_configs() -> dict | None:
    """Load {proxy name: proxy dict} from the generated Clash config."""
    try:
        import yaml
        with open(NODE_CONFIG, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return {p["name"]: p for p in data.get("proxies", [])
                if isinstance(p, dict) and p.get("name")}
    except Exception:
        return None


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


def _wait_port(port: int, timeout: float = 8.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def api() -> requests.Session:
    s = requests.Session()
    if SECRET:
        s.headers.update({"Authorization": f"Bearer {SECRET}"})
    return s


def get_proxies(s: requests.Session) -> dict:
    return s.get(f"{CTRL}/proxies", timeout=10).json()["proxies"]


def walk(pname: str, proxies: dict, path: list, out: list):
    """递归展开分组, out 收集 (叶子节点名, [祖先分组路径...])"""
    # 跳过 Clash 内置伪节点: DIRECT(直连)/REJECT(拒绝), 它们不是真实服务器
    if pname in ("DIRECT", "REJECT") or proxies.get(pname, {}).get("type") in ("Direct", "Reject"):
        return
    info = proxies.get(pname, {})
    if info.get("type") in GROUP_TYPES and info.get("all"):
        for child in info["all"]:
            walk(child, proxies, path + [pname], out)
    else:
        out.append((pname, path))


def collect_leaves(s: requests.Session) -> list:
    """重新拉取 /proxies, 递归展开目标分组并去重, 返回本轮要评估的叶子节点"""
    proxies = get_proxies(s)
    if GROUP not in proxies:
        avail = [k for k, v in proxies.items() if v.get("type") in GROUP_TYPES]
        raise ValueError(f"找不到分组 '{GROUP}', 可用分组: {avail}")
    leaves = []
    walk(GROUP, proxies, [], leaves)
    seen, uniq = set(), []
    for n, p in leaves:
        if n not in seen:
            seen.add(n)
            uniq.append((n, p))
    return uniq


def select_path(s: requests.Session, full_path: list):
    """把 full_path=[GROUP, mid, ..., leaf] 上的每个分组依次选到下一个节点"""
    for i in range(len(full_path) - 1):
        parent, child = full_path[i], full_path[i + 1]
        s.put(f"{CTRL}/proxies/{parent}", json={"name": child}, timeout=10)


def measure_latency(s: requests.Session, name: str):
    try:
        r = s.get(f"{CTRL}/proxies/{quote(name, safe='')}/delay",
                  params={"url": DELAY_URL, "timeout": DELAY_TIMEOUT}, timeout=10).json()
        d = r.get("delay", 0)
        return d if d and d > 0 else None
    except Exception:
        return None


def measure_speed(proxy_url: str | None = None) -> float:
    proxy = proxy_url or PROXY
    try:
        t = time.time()
        r = requests.get(TEST_URL,
                         proxies={"http": proxy, "https": proxy},
                         timeout=TIMEOUT, stream=True)
        n = sum(len(c) for c in r.iter_content(8192))
        dt = time.time() - t
        return n / 1024 / 1024 / dt if dt > 0 else 0.0
    except Exception:
        return 0.0


def speed_via_mihomo(binary: str, proxy_cfg: dict, name: str) -> float:
    """Start an isolated mihomo for one node and measure bandwidth through it."""
    port = _free_port()
    config = {
        "mixed-port": port,
        "mode": "rule",
        "log-level": "error",
        "proxies": [proxy_cfg],
        "proxy-groups": [{"name": "TEST", "type": "select", "proxies": [name]}],
        "rules": ["MATCH,TEST"],
    }
    work = tempfile.mkdtemp(prefix="cas-mihomo-")
    cfg_path = os.path.join(work, "config.json")
    proc = None
    try:
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(config, f, ensure_ascii=False)
        kwargs = {}
        if sys.platform == "win32":
            kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        proc = subprocess.Popen(
            [binary, "-f", cfg_path, "-d", work],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            **kwargs,
        )
        if not _wait_port(port, min(TIMEOUT, 8.0)):
            return 0.0
        return measure_speed(f"http://127.0.0.1:{port}")
    except Exception:
        return 0.0
    finally:
        if proc is not None:
            try:
                proc.terminate()
            except Exception:
                pass
            try:
                proc.wait(timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        shutil.rmtree(work, ignore_errors=True)


def evaluate(s: requests.Session, leaves: list):
    # 每个节点一个并行任务: 先测延迟, 合格后立即测带宽。
    # 带宽优先用独立 mihomo 实例, 避免 Clash 全局分组被并发覆盖;
    # 找不到节点配置时回退到 Clash 分组切换, 并用锁串行执行。
    print(f"[*] 并行评估 {len(leaves)} 个节点 (workers={MAX_WORKERS}, mihomo={MIHOMO_LIMIT}) ...\n")
    binary = find_mihomo()
    node_cfgs = load_node_configs() if binary else None

    def _bandwidth(name, path, lat):
        if binary is not None and node_cfgs and name in node_cfgs:
            with _MIHOMO_SEM:
                return speed_via_mihomo(binary, node_cfgs[name], name)
        with _SPEED_LOCK:
            try:
                select_path(s, path + [name])   # 切到该节点再经代理端口下载
                time.sleep(0.15)
                return measure_speed()
            except Exception:
                return 0.0

    def _finish(name, path, lat):
        spd = _bandwidth(name, path, lat)
        ok = spd > 0.0001                       # 带宽测速成功才算有效候选
        score = spd - (lat / 1000.0) * W_LAT
        tag = "" if ok else "  (带宽测速失败)"
        print(f"  {name:30s} 延迟={lat:5d}ms 带宽={spd:5.2f}MB/s 得分={score:6.2f}{tag}")
        return name, path, lat, spd, score, ok

    def _test(item):
        name, path = item
        lat = measure_latency(s, name)
        if lat is None or lat > LAT_THRESH:
            print(f"  {name:30s} 延迟={'超时' if lat is None else str(lat)+'ms':>7}  -> 淘汰(延迟)")
            return name, path, lat, 0.0, -1.0, False
        return _finish(name, path, lat)

    if TOPK > 0:
        # TOPK 需要先知道全量延迟, 再对延迟最低的前 N 个节点测带宽
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            meta = {}
            for name, path, lat in ex.map(
                lambda it: (it[0], it[1], measure_latency(s, it[0])), leaves
            ):
                meta[name] = (path, lat)
        survivors = [(n, p, lat) for n, (p, lat) in meta.items()
                     if lat is not None and lat <= LAT_THRESH]
        survivors.sort(key=lambda x: x[2])
        survivors = survivors[:TOPK]
        print(f"[*] 延迟最低的 TOPK={TOPK} 个节点开始测带宽 ...\n")
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            results = list(ex.map(lambda it: _finish(it[0], it[1], it[2]), survivors))
        for name, path, lat in [(n, p, lat) for n, (p, lat) in meta.items()
                                if not (lat is not None and lat <= LAT_THRESH)]:
            print(f"  {name:30s} 延迟={'超时' if lat is None else str(lat)+'ms':>7}  -> 淘汰(延迟)")
            results.append((name, path, lat, 0.0, -1.0, False))
        return results

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        results = list(ex.map(_test, leaves))
    return results


def main():
    s = api()
    while True:
        try:
            uniq = collect_leaves(s)
        except Exception as e:
            if isinstance(e, requests.RequestException):
                print(f"[!] 无法连接 Clash Controller ({CTRL}): {e}")
                print("    请确认 Clash Verge Rev 已开启 External Controller 并填写正确的地址/secret。")
            else:
                print(f"[!] 获取节点列表失败: {e}")
            if INTERVAL <= 0:
                sys.exit(1)
            print(f"[*] {INTERVAL}s 后重试 ...\n")
            time.sleep(INTERVAL)
            continue

        results = evaluate(s, uniq)
        cands = [r for r in results if r[5]]   # 带宽测速成功的真实节点
        if cands:
            best = max(cands, key=lambda r: r[4])
            print(f"\n[+] 最优节点: {best[0]}  (延迟={best[2]}ms, "
                  f"带宽={best[3]:.2f}MB/s, 得分={best[4]:.2f})\n")
            select_path(s, best[1] + [best[0]])
            print(f"[✓] 已将分组 '{GROUP}' 切换到 '{best[0]}'\n")
        else:
            # 退而求其次: 延迟合格但带宽测速失败的, 选延迟最低的真实节点(绝不会是 DIRECT/REJECT)
            real = [r for r in results if r[2] is not None and r[2] <= LAT_THRESH]
            if real:
                best = min(real, key=lambda r: r[2])
                print(f"\n[!] 无节点带宽测速成功, 退而选延迟最低的可用节点: "
                      f"{best[0]} (延迟={best[2]}ms)\n")
                select_path(s, best[1] + [best[0]])
                print(f"[✓] 已将分组 '{GROUP}' 切换到 '{best[0]}' (仅按延迟)\n")
            else:
                none_cnt = sum(1 for r in results if r[2] is None)
                total = len(results)
                print("\n[!] 没有可用节点(全部超时或超过延迟阈值), 跳过本次切换。")
                if total > 0 and none_cnt == total:
                    print(f"    [诊断] 全部 {total} 个节点延迟都为 None, 极可能是延迟测试 URL "
                          f"({DELAY_URL}) 在节点侧不可达(如被墙)。请换一个可达的测试 URL, 例如:")
                    print("    export CLASH_DELAY_URL=http://connect.rom.miui.com/generate_204")
                    print("    export CLASH_DELAY_URL=https://cp.cloudflare.com/generate_204")
                print()
        if INTERVAL <= 0:
            break
        print(f"[*] {INTERVAL}s 后重新评估 ... (Ctrl+C 退出)\n")
        time.sleep(INTERVAL)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[退出] 已停止自动选线。")
        sys.exit(0)
