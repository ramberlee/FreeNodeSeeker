# FreeNodeSeeker 使用手册

FreeNodeSeeker 自动从多个公开源收集免费的 V2Ray / Clash 订阅节点，经过解析、合并和连通性验证后，输出 Clash、Base64、JSON 格式的订阅文件，并可通过内置 HTTP 服务直接分享。

## 目录

- [项目简介](#项目简介)
- [快速开始](#快速开始)
- [安装](#安装)
- [命令行](#命令行)
- [Clash 自动选线](#clash-自动选线)
- [Windows 一键启动](#windows-一键启动)
- [配置说明](#配置说明)
- [采集与验证流程](#采集与验证流程)
- [输出与 HTTP 服务](#输出与-http-服务)
- [性能优化说明](#性能优化说明)
- [开发与测试](#开发与测试)
- [故障排除](#故障排除)

## 项目简介

完整管线为：

```text
collect → parse → validate → merge → output
```

主要能力：

- 多源采集：GitHub 代码搜索、API / 订阅 URL、网页抓取
- 多格式解析：Base64 订阅、Clash YAML、SIP008 JSON、sing-box JSON、单条代理 URI
- 多协议验证：HTTP、SOCKS5、SS、Trojan、VMess、VLESS、Hysteria2、TUIC
- 增量更新：已有存活节点足够时跳过采集，只补充差额
- 验证缓存：30 分钟内复用已验证结果，避免重复检查
- 多格式输出：Clash Meta YAML、Base64 订阅、JSON
- 内置 HTTP 服务：把输出文件作为订阅 URL 提供给客户端
- 守护进程：按固定间隔定时采集
- Clash 自动选线：经 External Controller API 综合延迟与带宽，自动把 select 分组切到最优节点

## 快速开始

```powershell
cd D:\agents\FreeNodeSeeker
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .

# 初始化配置
fns config init

# 编辑 fns.yaml，至少配置 api.urls 或 github.search_queries

# 采集 10 个存活节点
fns run -n 10
```

输出文件位于 `output/`：

| 文件 | 说明 |
|------|------|
| `output/fns.yaml` | Clash Meta 配置，可直接导入 Clash Verge Rev / Mihomo |
| `output/fns.txt` | Base64 通用订阅 |
| `output/fns.json` | JSON 节点元数据（需在配置中启用） |
| `output/fns.cache.json` | 验证缓存，自动生成 |
| `output/fns.collected.jsonl` | 本次运行采集到的全部解析节点快照 |
| `output/fns.validation_report.json` | 节点去重、验证和死亡原因汇总 |
| `output/fns.state.json` | 增量更新使用的内部节点状态 |

Windows 也可以直接运行 `start_daemon.bat 2` 一键启动 Clash Verge、自动选线和定时采集，详见 [Windows 一键启动](#windows-一键启动)。

## 安装

### 环境要求

- Windows 10+ / Linux / macOS
- Python 3.10+
- 可选：mihomo（用于 VMess / VLESS / Hysteria2 / TUIC 的真实代理验证）

### 安装步骤

```powershell
git clone <repo-url>
cd FreeNodeSeeker
python -m venv .venv
.\.venv\Scripts\Activate.ps1      # Windows
# source .venv/bin/activate       # Linux / macOS
pip install -e .
```

### 安装 mihomo（推荐）

mihomo 用于 VMess / VLESS / Hysteria2 / TUIC 协议的真实代理验证。未安装时，这些协议会直接标记为不可用，而不是做 TCP 端口假验证。

从 [mihomo releases](https://github.com/MetaCubeX/mihomo/releases) 下载对应平台的二进制文件，放到以下任一位置：

- `bin/mihomo.exe`（项目目录，Windows）
- `.venv/Scripts/mihomo.exe`（Windows）
- 系统 PATH 中的任意目录

验证安装：

```powershell
mihomo -v
```

### GeoIP 数据库（可选）

国别识别的 GeoIP 兜底需要 `maxminddb` 依赖和本地 GeoLite2 Country 数据库。先安装依赖：

```powershell
.\.venv\Scripts\python.exe -m pip install maxminddb
```

再把 [P3TERX/GeoLite.mmdb](https://github.com/P3TERX/GeoLite.mmdb/releases/latest) 的 `GeoLite2-Country.mmdb` 放到 `bin/geolite2-country.mmdb`。缺少依赖或数据库时，无法从节点名识别的节点会归入 `🏳️ 未标注`。

## 命令行

所有命令都支持全局参数 `-c / --config` 指定配置文件。

### `fns run`

执行完整采集管线。

```powershell
fns run                           # 采集所有可用节点，不限数量
fns run -n 10                     # 采集 10 个存活节点
fns run -n 20 -o ./my_output      # 指定输出目录
fns run --skip-validation         # 跳过连通性验证，全部标记为存活
fns run --formats clash,json      # 指定输出格式
fns run -v                        # 详细日志
fns run -n 10 --serve             # 采集后启动 HTTP 服务器
fns run --no-serve                # 即使配置启用了 server，也不启动
```

参数：

| 参数 | 说明 |
|------|------|
| `-o, --output-dir` | 输出目录 |
| `-f, --formats` | 逗号分隔的输出格式：`clash,base64,json` |
| `--skip-validation` | 跳过验证 |
| `-n, --max-nodes` | 输出存活节点数，`0` 表示不限制 |
| `-v, --verbose` | 输出 DEBUG 日志 |
| `-s, --serve` | 采集完成后启动 HTTP 服务器 |
| `--no-serve` | 覆盖配置，禁用 HTTP 服务器 |

### `fns daemon`

启动定时采集守护进程，同时按配置启动 HTTP 服务器。

```powershell
fns daemon                  # 每 6 小时采集一次（按配置）
fns daemon -i 2             # 每 2 小时采集一次
fns daemon --no-serve       # 只定时采集，不启动 HTTP 服务器
```

守护进程行为：

1. 启动后立即执行一次采集
2. 之后按 `scheduler.interval_hours` 定时采集
3. HTTP 服务器持续运行，始终提供最新的订阅文件

### `fns validate`

验证单个订阅 URL，并打印解析出的节点表格。

```powershell
fns validate https://example.com/sub.txt
fns validate https://example.com/sub.txt -t 10
```

### `fns check`

检查单个代理端点是否能通过指定的测试 URL。

```powershell
fns check 1.2.3.4 443                          # HTTP 代理
fns check 1.2.3.4 8443 -T vless                # VLESS
fns check 1.2.3.4 1080 -T socks5               # SOCKS5
fns check 1.2.3.4 8388 -T ss                   # Shadowsocks
fns check proxy.com 443 -T http -u http://example.com/
```

### `fns sources`

```powershell
fns sources list           # 列出已启用源
fns sources list -a        # 列出全部源（含禁用）
```

### `fns config`

```powershell
fns config init            # 生成 ./fns.yaml
fns config init -p my.yaml # 生成到指定路径
fns config show            # 显示当前配置
fns config path            # 显示配置文件路径
```

## Clash 自动选线

`clash_auto_select.py` 是独立的自动选线守护脚本，与 FreeNodeSeeker 采集管线解耦。它通过 Clash 的 External Controller API 管理客户端，每轮评估前都会重新拉取节点列表，订阅更新后无需重启。

工作原理：

1. 递归展开目标 select 分组，收集分组下所有叶子节点
2. 并行调用 `/proxies/{name}/delay` 测延迟（默认 16 线程）
3. 按延迟阈值筛选，对延迟最低的 `CLASH_TOPK` 个节点经 mixed 代理端口下载测试文件测带宽
4. 按 `带宽 - 延迟/1000 × CLASH_W_LAT` 打分，把目标分组切到得分最高的节点
5. 每 `CLASH_INTERVAL` 秒循环一次；`CLASH_INTERVAL <= 0` 时只跑一轮

与 Clash 原生 `url-test` 的区别：`url-test` 只看延迟，本工具额外考虑带宽，更适合“既要稳又要快”的场景。

### 准备

- 使用 Clash Verge Rev（或其他支持 External Controller 的 Clash 内核客户端）导入 `output/fns.yaml`
- 在 Clash Verge Rev 中开启 External Controller，记下地址、secret 和 mixed 端口
- 确认要管理的顶层 select 分组存在，默认是 `综合打分`
- 依赖 `requests`，执行 `pip install -e .` 后已包含

### 运行

```powershell
python clash_auto_select.py
```

Windows 可直接运行 `clash_auto_select.bat`，Git Bash / Linux / macOS 可运行 `./clash_auto_select.sh`。输出同时写入控制台和 `logs/clash_auto_select.log`。

### 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `CLASH_CTRL` | `http://127.0.0.1:9097` | External Controller 地址 |
| `CLASH_SECRET` | `set-your-secret` | External Controller secret |
| `CLASH_PROXY` | `http://127.0.0.1:7897` | mixed 代理端口，用于带宽测速下载 |
| `CLASH_GROUP` | `综合打分` | 要管理的顶层 select 分组名 |
| `CLASH_DELAY_URL` | `https://cp.cloudflare.com/generate_204` | 延迟测试 URL |
| `CLASH_TEST_URL` | `https://speed.cloudflare.com/__down?bytes=1000000` | 带宽测试下载 URL（约 1 MB） |
| `CLASH_TEST_TIMEOUT` | `40` | 单节点测速超时（秒） |
| `CLASH_INTERVAL` | `300` | 自动选线间隔（秒），`<=0` 只跑一轮 |
| `CLASH_LAT_THRESH` | `3000` | 延迟超过该值（ms）直接淘汰 |
| `CLASH_DELAY_TIMEOUT` | `5000` | 单节点延迟测试超时（ms） |
| `CLASH_W_LAT` | `5.0` | 延迟惩罚权重，每 1000 ms 扣对应 MB/s |
| `CLASH_MAX_WORKERS` | `100` | 延迟+带宽统一并行任务数（上限 100） |
| `CLASH_MIHOMO_LIMIT` | `100` | 同时运行的独立 mihomo 实例上限，默认等于 `CLASH_MAX_WORKERS` |
| `CLASH_NODE_CONFIG` | `output/fns.yaml` | 含完整节点参数的 Clash 配置，用于独立 mihomo 测速 |
| `CLASH_MIHOMO` | 自动查找 | mihomo 可执行文件路径，优先使用 `bin/mihomo.exe` |
| `CLASH_TOPK` | `0` | 只对延迟最低的前 N 个节点测带宽，`0` 为全部 |
| `CLASH_LOG` | `logs/clash_auto_select.log` | 日志文件路径 |

Windows 示例：

```powershell
set CLASH_SECRET=your-secret
set CLASH_GROUP=节点选择
set CLASH_INTERVAL=120
clash_auto_select.bat
```

Git Bash / Linux 示例：

```bash
CLASH_SECRET=your-secret CLASH_GROUP=节点选择 CLASH_INTERVAL=120 ./clash_auto_select.sh
```

## Windows 一键启动

`start_daemon.bat` 一次启动完整运行环境：

```powershell
start_daemon.bat 2
```

参数为 `fns daemon` 的采集间隔（小时）。脚本会：

1. 启动 Clash Verge Rev（默认路径 `D:\Program Files\Clash Verge\clash-verge.exe`，安装位置不同时请修改批处理文件）
2. 等待 5 秒让客户端初始化
3. 启动自动选线：优先用 Git Bash 运行 `clash_auto_select.sh`，没有 Git Bash 时回退到 `clash_auto_select.bat`，日志写入 `logs/clash_auto_select.log`
4. 运行 `fns.bat daemon -i <interval>` 定时采集

## 配置说明

配置文件按以下优先级查找：

1. 命令行 `--config` 指定的路径
2. 当前目录 `fns.yaml`
3. 当前目录 `config.yaml`
4. `~/.fns/config.yaml`

### 完整示例

```yaml
sources:
  github:
    enabled: true
    search_queries:
      - free v2ray subscription
      - v2ray config
      - clash node free
      - vless free
    max_results: 30
    max_collect_nodes: 5000
    token: null          # GitHub 代码搜索需要 token

  web_scrape:
    enabled: false
    urls: []
    request_delay: 0.3
    proxy: null          # 抓取时使用的代理

  api:
    enabled: true
    urls:
      - https://example.com/sub.txt
      - https://example.com/sub.yaml

validator:
  concurrency: 50        # 并发验证数，范围 1-200
  timeout: 5.0           # 单次验证超时（秒）
  retries: 1             # 失败重试次数
  test_url: "https://www.gstatic.com/generate_204"

output:
  dir: ./output
  formats:
    - clash
    - base64
  clash:
    # 监听端口由客户端决定，订阅中不写死
    allow_lan: false
    mode: Rule
    log_level: info

max_alive_nodes: 0       # 0 = 不限制数量

scheduler:
  interval_hours: 6

server:
  enabled: true
  host: "0.0.0.0"
  port: 5000

logging:
  level: INFO            # DEBUG / INFO / WARNING / ERROR
  file: ./logs/fns.log   # 日志文件路径
```

### 字段参考

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `sources.github.enabled` | bool | `true` | 启用 GitHub 代码搜索 |
| `sources.github.search_queries` | list | 4 条英文默认词 | 搜索关键词 |
| `sources.github.max_results` | int | `30` | 每个关键词最多返回的 README 数 |
| `sources.github.max_collect_nodes` | int | `5000` | GitHub 采集/解析后保留的节点上限 |
| `sources.github.token` | str / null | `null` | GitHub 经典 token，解除搜索速率限制 |
| `sources.web_scrape.enabled` | bool | `true` | 启用网页抓取 |
| `sources.web_scrape.urls` | list | `[]` | 要抓取的 HTML 页面 |
| `sources.web_scrape.request_delay` | float | `0.3` | 页面间延迟（秒） |
| `sources.web_scrape.proxy` | str / null | `null` | 抓取代理，如 `http://127.0.0.1:7890` |
| `sources.api.enabled` | bool | `true` | 启用 API / 订阅 URL 拉取 |
| `sources.api.urls` | list | `[]` | 订阅 URL 列表 |
| `validator.concurrency` | int | `50` | 验证并发数，自动限制在 1-200 |
| `validator.timeout` | float | `5.0` | 单次验证超时（秒） |
| `validator.retries` | int | `1` | 失败重试次数 |
| `validator.test_url` | str | `https://www.gstatic.com/generate_204` | 验证时请求的目标 URL |
| `output.dir` | str | `./output` | 输出目录 |
| `output.formats` | list | `["clash", "base64"]` | 支持 `clash` / `base64` / `json` |
| `output.clash.allow_lan` | bool | `false` | 是否允许局域网访问 |
| `output.clash.mode` | str | `Rule` | Clash 模式 |
| `output.clash.log_level` | str | `info` | Clash 日志级别 |
| `max_alive_nodes` | int | `0` | 输出存活节点目标数，`0` 为不限 |
| `scheduler.interval_hours` | int | `6` | daemon 采集间隔（小时） |
| `server.enabled` | bool | `true` | 是否在 run/daemon 时启动 HTTP 服务 |
| `server.host` | str | `0.0.0.0` | HTTP 监听地址 |
| `server.port` | int | `5000` | HTTP 监听端口 |
| `logging.level` | str | `INFO` | 日志级别 |
| `logging.file` | str / null | `logs/fns.log` | 日志文件路径 |

注意：配置文件使用 snake_case 字段名，例如 `allow_lan`、`log_level`。写成 `allow-lan` 或 `log-level` 会被忽略，保持默认值。

## 采集与验证流程

### 采集

- API 源并发拉取所有订阅 URL（最多 10 路）
- GitHub 源并发搜索关键词，去重后只下载一次 README；README 中的订阅链接也全局去重
- 网页源对同页链接并发下载，并跳过重复链接

### 解析

- 自动检测格式：Base64、Clash YAML、SIP008、sing-box JSON、代理 URI
- Base64 内容只解码一次，解码结果直接传给解析器
- 支持 base64 包裹的 Clash YAML
- 解析在线程池中执行，避免大量内容时阻塞事件循环

### 合并

- 按 `(address, port, node_type)` 去重，先出现的源优先
- 存活节点排在前面，并按延迟排序

### 验证

- 所有节点先做快速 TCP 预筛，不可达节点直接跳过完整协议测试
- HTTP / SOCKS5 使用 aiohttp 做真实代理请求
- SS / Trojan / VMess / VLESS / Hysteria2 / TUIC 使用 mihomo 子进程验证；未安装 mihomo 时 SS / Trojan 回退 pproxy，其余标记为不可用
- 验证结果写入 `output/fns.cache.json`，30 分钟内复用

### 增量更新

当 `max_alive_nodes > 0` 时：

1. 加载上次输出并读取验证缓存
2. 存活节点足够时直接输出，跳过采集
3. 不足时继续采集并验证新节点，达到目标数量后立即停止

## 输出与 HTTP 服务

### 输出文件

| 格式 | 文件 | 用途 |
|------|------|------|
| Clash | `output/fns.yaml` | Clash Verge Rev / Mihomo 等客户端 |
| Base64 | `output/fns.txt` | V2Ray / Clash 通用订阅 |
| JSON | `output/fns.json` | 完整节点元数据 |

### Clash 策略组

生成的 `output/fns.yaml` 内置以下策略组：

- `🚀 节点选择`：总开关，可切换各组、DIRECT 或单个节点
- `⚡ 自动最快`：包含全部节点的 url-test 组，每 5 分钟用 `https://www.youtube.com/generate_204` 测速
- `综合打分`：包含全部节点的 select 手动选择组
- 国家/地区组：节点数 ≥3 的国家单独成组（如 `🇯🇵 日本·141`），测速间隔按节点数自动调整，≥100 节点每 2 分钟，否则每 1 分钟
- `🌍 其他`：节点数少于 3 的国家合并
- `🏳️ 未标注`：无法识别归属的节点

国别识别优先解析节点名（国旗 emoji、中文国名、ISO 代码、常见英文别名），失败后使用 `bin/geolite2-country.mmdb` 按服务器 IP 补识别。

分流规则：内网 IP 直连 → `GEOIP,CN,DIRECT` → 其余走 `🚀 节点选择`。配置使用 `geodata-mode: true`，客户端需提供 `geoip.dat`（Clash Verge Rev 自带）。

### HTTP 端点

启动 HTTP 服务后（`run --serve` 或 `daemon`），提供：

| 路由 | 说明 |
|------|------|
| `GET /` | 状态页 |
| `GET /fns.txt` | Base64 订阅 |
| `GET /fns.yaml` | Clash Meta 配置 |
| `GET /fns.json` | JSON 节点数据 |

订阅 URL 示例：`http://你的IP:5000/fns.txt`

## 性能优化说明

- 采集、下载、解析、验证各阶段均采用并发模型
- GitHub 跨关键词去重，避免同一 README 和订阅链接被重复下载
- 所有节点在完整协议测试前先做 TCP 预筛，显著减少死节点等待时间
- 验证缓存避免 30 分钟内重复检查同一节点
- Base64 检测与解析只解码一次，减少大订阅内容上的 CPU 消耗

## 开发与测试

```powershell
pip install -e ".[dev]"
pytest tests/ -v
ruff check src tests
```

项目布局：

```text
项目根目录/
├── src/fns/
│   ├── collectors/       # 采集器：API / GitHub / 网页
│   ├── parsers/          # 订阅格式解析
│   ├── validators/       # 节点连通性验证
│   ├── formatters/       # 输出格式化
│   ├── pipeline.py       # 管线编排
│   ├── scheduler.py      # daemon 定时任务
│   ├── server.py         # HTTP 订阅服务
│   └── config.py         # 配置模型
├── clash_auto_select.py  # Clash 自动选线守护脚本
├── clash_auto_select.bat / .sh  # 自动选线启动脚本
└── start_daemon.bat      # Windows 一键启动
```

## 故障排除

### mihomo 未找到

日志提示：

```text
mihomo not found — VMess/VLESS/Hysteria2/TUIC will be marked dead
```

安装 mihomo 到项目 `bin/`、PATH 或 `.venv/Scripts/` 后重新运行。未安装时，VMess / VLESS / Hysteria2 / TUIC 不会进入 TCP 假验证，而是直接标记为不可用。

### GitHub 搜索 401 / 403

GitHub 代码搜索现在要求认证。创建无权限范围的 classic token，填入 `sources.github.token`。403 也可能是速率限制，token 可将限额从每分钟 10 次提升到 30 次。

### GitHub SSL 证书错误

Windows 常见问题：

```text
WARNING  GitHub API error: SSLCertVerificationError
```

解决方案：

1. 在 `fns.yaml` 中禁用 GitHub 源：`github.enabled: false`
2. 安装系统根证书：`pip install pip-system-certs`

### 采集不到新节点

1. 检查源是否可访问：`fns sources list -a`
2. 更新 API URL（免费节点源经常变更）
3. 检查网络是否需要代理，并配置 `web_scrape.proxy` 或系统代理
4. 确认 GitHub token 有效且未被速率限制

### 所有节点验证失败

1. 确认 mihomo 已安装：`mihomo -v`
2. 确认测试 URL 可访问：`fns check 1.1.1.1 80`
3. 免费节点时效短，定期重新采集
4. 调高 `validator.timeout`，例如 `10.0`

### 自动选线无法连接 Controller

```text
[!] 无法连接 Clash Controller (http://127.0.0.1:9097)
```

排查：

1. 在 Clash Verge Rev 中开启 External Controller，并确认地址和端口
2. 用 `CLASH_CTRL`、`CLASH_SECRET` 覆盖默认地址和 secret
3. 确认 `CLASH_PROXY` 与客户端的 mixed 端口一致

### 全部节点延迟为 None

延迟测试 URL 在节点侧不可达（例如被墙）时会出现。换一个可达的测试 URL：

```powershell
set CLASH_DELAY_URL=https://www.gstatic.com/generate_204
clash_auto_select.bat
```

### 输出为空

确认 `output.formats` 至少包含 `clash` 或 `base64`，并检查 `output/fns.cache.json` 是否因版本升级被判定为过期缓存而重建。
