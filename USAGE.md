# FreeNodeSeeker 使用手册

Auto-collect free V2Ray/Clash subscription nodes.

## 目录
- [快速开始](#快速开始)
- [安装](#安装)
- [配置文件](#配置文件)
- [命令参考](#命令参考)
- [协议支持](#协议支持)
- [输出格式](#输出格式)
- [故障排除](#故障排除)

## 快速开始

```powershell
# 1. 安装
cd E:\agents\FreeNodeSeeker
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .

# 2. 初始化配置（首次使用）
fns config init

# 3. 编辑 fns.yaml，填入订阅源 URL（api.urls）

# 4. 运行采集
fns run -n 10

# 5. 输出在 output/ 目录下
#    output/fns.yaml  — Clash Meta 配置
#    output/fns.txt   — Base64 订阅
#    output/fns.json  — JSON（需在配置中启用）
```

导入 Clash Verge / Mihomo 等客户端时，使用 `output/fns.yaml`。

## 安装

### 环境要求
- Windows 10+ / Linux / macOS
- Python 3.10+
- sing-box（可选，用于 VMess/VLESS/Hysteria2/TUIC 验证）

### 安装步骤

```powershell
git clone <repo-url>
cd FreeNodeSeeker
python -m venv .venv
.\.venv\Scripts\Activate.ps1      # Windows
# source .venv/bin/activate       # Linux/macOS
pip install -e .
```

### 安装 sing-box（推荐）

sing-box 用于 VMess/VLESS/Hysteria2/TUIC 协议的真实代理验证。不安装时，这些协议回退为 TCP 端口检查。

从 [sing-box releases](https://github.com/SagerNet/sing-box/releases) 下载对应平台的二进制文件，放到以下任一位置：
- `.venv/Scripts/sing-box.exe`（Windows）
- 系统 PATH 中的任意目录

```powershell
# Windows 一键安装示例
$url = "https://github.com/SagerNet/sing-box/releases/latest/download/sing-box-windows-amd64.zip"
# 下载并解压 sing-box.exe 到 .venv/Scripts/
```

验证安装：
```powershell
sing-box version
```

## 配置文件

程序按以下优先级查找配置文件：
1. 命令行 `--config` 指定的路径
2. 当前目录 `fns.yaml`
3. 当前目录 `config.yaml`
4. `~/.fns/config.yaml`

### 生成示例配置
```powershell
fns config init              # 生成到 ./fns.yaml
fns config init -p my.yaml   # 生成到指定路径
```

### 配置结构

```yaml
sources:
  github:              # GitHub 代码搜索
    enabled: false
    search_queries:
      - "free v2ray subscription"
      - "v2ray config"
    max_results: 30
    token: null         # GitHub Token（解除速率限制）

  web_scrape:           # 网页抓取
    enabled: false
    urls: []
    request_delay: 1.0
    proxy: null         # 抓取时使用的代理

  api:                  # 直接 API/订阅 URL（最常用）
    enabled: true
    urls:
      - https://example.com/sub.txt
      - https://example.com/sub.yaml

validator:
  concurrency: 50       # 并发验证数（1-200）
  timeout: 5.0          # 单次验证超时（秒）
  retries: 1            # 失败重试次数
  test_url: http://www.google.com/  # 验证目标 URL

output:
  dir: ./output         # 输出目录
  formats:              # 输出格式：clash, base64, json
    - clash
    - base64
  clash:
    port: 7890
    socks_port: 7891
    allow_lan: false
    mode: Rule

scheduler:
  interval_hours: 6     # 守护进程模式采集间隔

logging:
  level: INFO           # DEBUG / INFO / WARNING / ERROR
  file: null            # 日志文件路径（null=控制台）
```

### 查看配置
```powershell
fns config show      # 打印当前完整配置
fns config path      # 显示配置文件路径
fns sources list     # 列出所有采集源
fns sources list -a  # 包括已禁用的源
```

## 命令参考

### fns run — 执行完整管线

```
collect → parse → validate → merge → output
```

```powershell
fns run                           # 采集所有可用节点，不限数量
fns run -n 10                     # 采集 10 个存活节点
fns run -n 10 --serve             # 采集后启动 HTTP 服务器（订阅 URL）
fns run -n 20 -o ./my_output      # 指定输出目录
fns run --skip-validation         # 跳过验证（全部标记为存活）
fns run --formats clash,json      # 指定输出格式
fns run -v                        # 详细日志
fns run -c my_config.yaml         # 使用自定义配置
```

**增量更新模式**（`--max-nodes` / `-n`）：
1. 加载上次保存的节点，重新验证
2. 存活节点足够 → 直接输出，跳过采集
3. 存活节点不足 → 从源采集新节点补足差额

### fns daemon — 后台定时采集 + HTTP 服务器

```powershell
fns daemon                  # 启动 HTTP 服务器 + 每 6 小时采集一次
fns daemon -i 2             # 每 2 小时采集一次
fns daemon --no-serve       # 仅定时采集，不启动 HTTP 服务器
```

daemon 模式下，HTTP 服务器与采集循环在同一个进程中运行：
- 首次启动立即执行一次采集
- 之后按 `scheduler.interval_hours` 定时采集
- HTTP 服务器持续运行，提供最新的节点数据
- 订阅 URL：`http://你的IP:5000/fns.txt`

### fns serve — 启动 HTTP 服务器（仅服务模式）

```powershell
fns run -n 10 --serve       # 采集并启动服务器
# 或者直接用 daemon 模式（自动启动服务器）
fns daemon
```

HTTP 服务器提供以下端点：

| 路由 | 说明 |
|------|------|
| `GET /` | 状态页面 |
| `GET /fns.txt` | Base64 订阅（通用） |
| `GET /fns.yaml` | Clash Meta YAML 配置 |
| `GET /fns.json` | JSON 节点元数据 |

### fns check — 单节点检查

```powershell
fns check 1.2.3.4 443                           # HTTP 代理检查
fns check 1.2.3.4 8443 -T vless                 # VLESS 节点检查
fns check 1.2.3.4 1080 -T socks5                # SOCKS5 节点检查
fns check 1.2.3.4 8388 -T ss                    # Shadowsocks 节点检查
fns check 1.2.3.4 443 -T trojan                 # Trojan 节点检查
fns check 1.2.3.4 443 -T vmess                  # VMess 节点检查
fns check proxy.com 8443 -T vless -t 10         # 10 秒超时
fns check proxy.com 443 -T http -u http://example.com/  # 自定义测试 URL
```

### fns validate — 验证订阅 URL

```powershell
fns validate https://example.com/sub.txt        # 验证远程订阅
fns validate ./local_sub.txt                    # 验证本地文件
fns validate https://example.com/sub.txt -t 10  # 10 秒超时
```

### fns config — 配置管理

```powershell
fns config init            # 生成示例配置
fns config show            # 显示当前配置
fns config path            # 显示配置路径
```

### fns sources — 采集源管理

```powershell
fns sources list           # 列出已启用的源
fns sources list -a        # 列出所有源（含禁用）
```

## 协议支持

### 支持的代理协议

| 协议 | URI 格式 | 验证方式 |
|------|---------|---------|
| HTTP | — | aiohttp 代理请求 |
| SOCKS5 | — | aiohttp-socks |
| Shadowsocks | `ss://` | pproxy |
| Trojan | `trojan://` | pproxy / sing-box |
| VMess | `vmess://` | sing-box（需安装） |
| VLESS | `vless://` | sing-box（需安装） |
| Hysteria2 | `hysteria2://` | sing-box（需安装） |
| TUIC | `tuic://` | sing-box（需安装） |

### 支持的订阅格式
- Base64 编码订阅（V2Ray/Clash 通用）
- Clash / Clash Meta YAML
- SIP008 Shadowsocks JSON
- 单条代理 URI（vmess://、vless://、ss://、trojan:// 等）

### 采集源类型
- **API** — 直接 URL 拉取订阅内容
- **GitHub** — 搜索 GitHub 代码仓库中的代理配置
- **网页抓取** — 从 HTML 页面提取代理内容

## 输出格式

### Clash YAML（`output/fns.yaml`）
可直接导入 Clash Verge、Mihomo 等客户端。
```yaml
port: 7890
proxies:
  - name: "节点名称"
    type: vless
    server: 1.2.3.4
    port: 443
    ...
proxy-groups:
  - name: Auto
    type: url-test
    url: http://www.google.com/
    interval: 300
```

### Base64 订阅（`output/fns.txt`）
通用订阅格式，可导入 V2Ray、Clash 等客户端。

### JSON（`output/fns.json`）
需在 `output.formats` 中添加 `json`。包含完整的节点元数据。

## 故障排除

### sing-box 未找到
```
INFO: sing-box not found — VMess/VLESS/Hysteria2/TUIC will use TCP fallback
```
安装 sing-box 以获得准确的协议验证。不安装时，上述协议仅做 TCP 端口检查。

### GitHub SSL 证书错误
```
WARNING  GitHub API error: SSLCertVerificationError
```
Windows 环境常见问题。解决方案：
1. 在 fns.yaml 中禁用 GitHub 源：`github.enabled: false`
2. 或安装系统根证书：`pip install pip-system-certs`

### 采集不到新节点
1. 检查 API 源是否可访问：`fns sources list`
2. 更新 API URL（免费节点源经常变更）
3. 检查网络是否需要代理

### 所有节点验证失败
1. 确认 sing-box 已安装：`sing-box version`
2. 检查测试 URL 是否可访问
3. 免费节点时效性短，定期重新采集
4. 调高 timeout：在 `fns.yaml` 中 `validator.timeout: 10.0`

### 运行测试
```powershell
pip install -e ".[dev]"
pytest tests/ -v
```
