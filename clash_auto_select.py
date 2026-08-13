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

与 Clash 原生 url-test 的区别:
  原生 url-test 只看延迟; 本脚本额外考虑带宽, 更适合"既要稳又要快"。

依赖: pip install requests
运行: python clash_auto_select.py
全部参数可用环境变量覆盖(见下方 CONFIG)。
"""

import os
import sys
import time
import requests
from concurrent.futures import ThreadPoolExecutor

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(errors="replace")
    sys.stderr.reconfigure(errors="replace")

# ============================ 配置(可用环境变量覆盖) ============================
CTRL      = os.getenv("CLASH_CTRL", "http://127.0.0.1:9097")   # External Controller 地址
SECRET    = os.getenv("CLASH_SECRET", "set-your-secret")      # Clash Verge Rev 里设置的 secret
PROXY     = os.getenv("CLASH_PROXY", "http://127.0.0.1:7897")  # Clash mixed 端口(用作下载代理)
GROUP     = os.getenv("CLASH_GROUP", "综合打分")                # 要管理的顶层 select 分组名
DELAY_URL = os.getenv("CLASH_DELAY_URL", "https://www.google.com/generate_204")  # 延迟测试 URL
TEST_URL  = os.getenv("CLASH_TEST_URL", "https://speed.cloudflare.com/__down?bytes=3000000")   # 3MB
TIMEOUT   = int(os.getenv("CLASH_TEST_TIMEOUT", "40"))         # 单节点测速超时(秒)
INTERVAL  = int(os.getenv("CLASH_INTERVAL", "300"))            # 自动选线间隔(秒); <=0 只跑一轮
LAT_THRESH = int(os.getenv("CLASH_LAT_THRESH", "1500"))        # 延迟超过此值(ms)直接淘汰
DELAY_TIMEOUT = int(os.getenv("CLASH_DELAY_TIMEOUT", "2000"))   # 单节点延迟测试超时(ms), 越低越快判死节点
W_LAT     = float(os.getenv("CLASH_W_LAT", "5.0"))             # 延迟惩罚权重: 每 1000ms 扣 W_LAT MB/s
LAT_WORKERS = int(os.getenv("CLASH_LAT_WORKERS", "16"))        # 延迟测试的并发线程数
TOPK      = int(os.getenv("CLASH_TOPK", "0"))                 # 仅对延迟最低的 TOPK 个节点测带宽(0=全部)
# =============================================================================

GROUP_TYPES = {"Selector", "URLTest", "Fallback", "LoadBalance", "Relay"}


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


def select_path(s: requests.Session, full_path: list):
    """把 full_path=[GROUP, mid, ..., leaf] 上的每个分组依次选到下一个节点"""
    for i in range(len(full_path) - 1):
        parent, child = full_path[i], full_path[i + 1]
        s.put(f"{CTRL}/proxies/{parent}", json={"name": child}, timeout=10)


def measure_latency(s: requests.Session, name: str):
    try:
        r = s.get(f"{CTRL}/proxies/{name}/delay",
                  params={"url": DELAY_URL, "timeout": DELAY_TIMEOUT}, timeout=10).json()
        d = r.get("delay", 0)
        return d if d and d > 0 else None
    except Exception:
        return None


def measure_speed() -> float:
    try:
        t = time.time()
        r = requests.get(TEST_URL,
                         proxies={"http": PROXY, "https": PROXY},
                         timeout=TIMEOUT, stream=True)
        n = sum(len(c) for c in r.iter_content(8192))
        dt = time.time() - t
        return n / 1024 / 1024 / dt if dt > 0 else 0.0
    except Exception:
        return 0.0


def evaluate(s: requests.Session, leaves: list):
    # 1) 并行测延迟: /delay 直接测节点本身, 不需要切换分组, 可安全并发
    print(f"[*] 并行测延迟: {len(leaves)} 个节点 (workers={LAT_WORKERS}) ...\n")
    meta = {}
    def _lat(item):
        name, path = item
        return name, path, measure_latency(s, name)
    with ThreadPoolExecutor(max_workers=LAT_WORKERS) as ex:
        for name, path, lat in ex.map(_lat, leaves):
            meta[name] = (path, lat)

    # 2) 按延迟过滤, 取最低的 TOPK 做带宽测速(减少下载次数=主要提速点)
    survivors = [(n, p, lat) for n, (p, lat) in meta.items()
                 if lat is not None and lat <= LAT_THRESH]
    survivors.sort(key=lambda x: x[2])
    if TOPK > 0:
        survivors = survivors[:TOPK]
    print(f"[*] 通过延迟筛选 {len(survivors)} 个节点"
          + (f" (TOPK={TOPK})" if TOPK else "") + "，开始测带宽 ...\n")

    results = []
    for name, path, lat in survivors:
        select_path(s, path + [name])          # 切到该节点再经代理端口下载
        time.sleep(0.15)
        spd = measure_speed()
        ok = spd > 0.0001                       # 带宽测速成功才算有效候选
        score = spd - (lat / 1000.0) * W_LAT
        tag = "" if ok else "  (带宽测速失败)"
        print(f"  {name:30s} 延迟={lat:5d}ms 带宽={spd:5.2f}MB/s 得分={score:6.2f}{tag}")
        results.append((name, path, lat, spd, score, ok))

    dropped = [(n, p, lat) for n, (p, lat) in meta.items()
               if not (lat is not None and lat <= LAT_THRESH)]
    for name, path, lat in dropped:
        print(f"  {name:30s} 延迟={'超时' if lat is None else str(lat)+'ms':>7}  -> 淘汰(延迟)")
        results.append((name, path, lat, 0.0, -1.0, False))
    return results


def main():
    s = api()
    try:
        proxies = get_proxies(s)
    except Exception as e:
        print(f"[!] 无法连接 Clash Controller ({CTRL}): {e}")
        print("    请确认 Clash Verge Rev 已开启 External Controller 并填写正确的地址/secret。")
        sys.exit(1)

    if GROUP not in proxies:
        avail = [k for k, v in proxies.items() if v.get("type") in GROUP_TYPES]
        print(f"[!] 找不到分组 '{GROUP}'。可用的分组有:")
        print("   ", avail)
        sys.exit(1)

    leaves = []
    walk(GROUP, proxies, [], leaves)
    seen, uniq = set(), []
    for n, p in leaves:
        if n not in seen:
            seen.add(n)
            uniq.append((n, p))

    while True:
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
                    print(f"    export CLASH_DELAY_URL=http://connect.rom.miui.com/generate_204")
                    print(f"    export CLASH_DELAY_URL=https://www.gstatic.com/generate_204")
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
