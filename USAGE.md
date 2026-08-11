# FreeNodeSeeker 使用手册

FreeNodeSeeker 自动从多个公开源收集免费的 V2Ray / Clash 订阅节点，经过解析、合并和连通性验证后，输出 Clash、Base64、JSON 格式的订阅文件，并可通过内置 HTTP 服务直接分享。

## 目录

- [项目简介](#项目简介)
- [快速开始](#快速开始)
- [安装](#安装)
- [命令行](#命令行)
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
- 多格式解析：Base64 订阅、Clash YAML、SIP008 JSON、单条代理 URI
- 多协议验证：HTTP、SOCKS5、SS、Trojan、VMess、VLESS、Hysteria2、TUIC
- 增量更新：已有存活节点足够时跳过采集，只补充差额
- 验证缓存：30 分钟内复用已验证结果，避免重复检查
- 多格式输出：Clash Meta YAML、Base64 订阅、JSON
- 内置 HTTP 服务：把输出文件作为订阅 URL 提供给客户端
- 守护进程：按固定间隔定时采集

## 快速开始

```powershell
cd E:\agents\FreeNodeSeeker
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
| `output/fns.yaml` | Clash Meta 配置，可直接导入 Clash Verge / Mihomo |
| `output/fns.txt` | Base64 通用订阅 |
| `output/fns.json` | JSON 节点元数据（需在配置中启用） |
| `output/fns.cache.json` | 验证缓存，自动生成 |

## 安装

### 环境要求

- Windows 10+ / Linux / macOS
- Python 3.10+
- 可选：sing-box（用于 VMess / VLESS / Hysteria2 / TUIC 的真实代理验证）

### 安装步骤

```powershell
git clone <repo-url>
cd FreeNodeSeeker
python -m venv .venv
.\.venv\Scripts\Activate.ps1      # Windows
# source .venv/bin/activate       # Linux / macOS
pip install -e .
```

### 安装 sing-box（推荐）

sing-box 用于 VMess / VLESS / Hysteria2 / TUIC 协议的真实代理验证。未安装时，这些协议会直接标记为不可用，而不是做 TCP 端口假验证。

从 [sing-box releases](https://github.com/SagerNet/sing-box/releases) 下载对应平台的二进制文件，放到以下任一位置：

- `.venv/Scripts/sing-box.exe`（Windows）
- 系统 PATH 中的任意目录

验证安装：

```powershell
sing-box version
```

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
  test_url: "http://www.google.com/"

output:
  dir: ./output
  formats:
    - clash
    - base64
  clash:
    port: 7890
    socks_port: 7891
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
  file: null             # null = 输出到控制台
```

### 字段参考

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `sources.github.enabled` | bool | `true` | 启用 GitHub 代码搜索 |
| `sources.github.search_queries` | list | 4 条英文默认词 | 搜索关键词 |
| `sources.github.max_results` | int | `30` | 每个关键词最多返回的 README 数 |
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
| `validator.test_url` | str | `http://www.google.com/` | 验证时请求的目标 URL |
| `output.dir` | str | `./output` | 输出目录 |
| `output.formats` | list | `["clash", "base64"]` | 支持 `clash` / `base64` / `json` |
| `output.clash.port` | int | `7890` | Clash 混合代理端口 |
| `output.clash.socks_port` | int | `7891` | Clash SOCKS 端口 |
| `output.clash.allow_lan` | bool | `false` | 是否允许局域网访问 |
| `output.clash.mode` | str | `Rule` | Clash 模式 |
| `output.clash.log_level` | str | `info` | Clash 日志级别 |
| `max_alive_nodes` | int | `0` | 输出存活节点目标数，`0` 为不限 |
| `scheduler.interval_hours` | int | `6` | daemon 采集间隔（小时） |
| `server.enabled` | bool | `true` | 是否在 run/daemon 时启动 HTTP 服务 |
| `server.host` | str | `0.0.0.0` | HTTP 监听地址 |
| `server.port` | int | `5000` | HTTP 监听端口 |
| `logging.level` | str | `INFO` | 日志级别 |
| `logging.file` | str / null | `null` | 日志文件路径 |

注意：配置文件使用 snake_case 字段名，例如 `socks_port`、`log_level`。写成 `socks-port` 或 `log-level` 会被忽略，保持默认值。

## 采集与验证流程

### 采集

- API 源并发拉取所有订阅 URL（最多 10 路）
- GitHub 源并发搜索关键词，去重后只下载一次 README；README 中的订阅链接也全局去重
- 网页源对同页链接并发下载，并跳过重复链接

### 解析

- 自动检测格式：Base64、Clash YAML、SIP008、代理 URI
- Base64 内容只解码一次，解码结果直接传给解析器
- 支持 base64 包裹的 Clash YAML
- 解析在线程池中执行，避免大量内容时阻塞事件循环

### 合并

- 按 `(address, port, node_type)` 去重，先出现的源优先
- 存活节点排在前面，并按延迟排序

### 验证

- 所有节点先做快速 TCP 预筛，不可达节点直接跳过完整协议测试
- HTTP / SOCKS5 / SS / Trojan 使用 aiohttp / pproxy 做真实代理请求
- VMess / VLESS / Hysteria2 / TUIC 使用 sing-box 子进程验证；未安装 sing-box 时标记为不可用
- 验证结果写入 `output/fns.cache.json`，30 分钟内复用

### 增量更新

当 `max_alive_nodes > 0` 时：

1. 加载上次输出并读取验证缓存
2. 存活节点足够时直接输出，跳过采集
3. 不足时按 3 倍差额收集候选池，验证后选择延迟最低的节点补足

## 输出与 HTTP 服务

### 输出文件

| 格式 | 文件 | 用途 |
|------|------|------|
| Clash | `output/fns.yaml` | Clash Verge / Mihomo 等客户端 |
| Base64 | `output/fns.txt` | V2Ray / Clash 通用订阅 |
| JSON | `output/fns.json` | 完整节点元数据 |

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
src/fns/
├── collectors/       # 采集器：API / GitHub / 网页
├── parsers/          # 订阅格式解析
├── validators/       # 节点连通性验证
├── formatters/       # 输出格式化
├── pipeline.py       # 管线编排
├── scheduler.py      # daemon 定时任务
├── server.py         # HTTP 订阅服务
└── config.py         # 配置模型
```

## 故障排除

### sing-box 未找到

日志提示：

```text
sing-box not found — VMess/VLESS/Hysteria2/TUIC will be marked dead
```

安装 sing-box 到 PATH 或 `.venv/Scripts/` 后重新运行。未安装时，VMess / VLESS / Hysteria2 / TUIC 不会进入 TCP 假验证，而是直接标记为不可用。

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

1. 确认 sing-box 已安装：`sing-box version`
2. 确认测试 URL 可访问：`fns check 1.1.1.1 80`
3. 免费节点时效短，定期重新采集
4. 调高 `validator.timeout`，例如 `10.0`

### 输出为空

确认 `output.formats` 至少包含 `clash` 或 `base64`，并检查 `output/fns.cache.json` 是否因版本升级被判定为过期缓存而重建。
