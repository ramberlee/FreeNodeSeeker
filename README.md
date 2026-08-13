# FreeNodeSeeker

自动收集免费 V2Ray / Clash 订阅节点，并进行解析、验证、去重和格式化输出。内置 HTTP 订阅服务和定时采集守护进程。

## 功能

- 多源采集：GitHub 代码搜索、API / 订阅 URL、网页抓取
- 多格式解析：Base64、Clash YAML、SIP008、sing-box JSON、代理 URI
- 多协议验证：HTTP、SOCKS5、SS、Trojan、VMess、VLESS、Hysteria2、TUIC
- 完整协议选项：SS plugin、Trojan WS/GRPC、TUIC insecure、HTTP 代理认证
- 增量更新与验证缓存，缩短每次采集时间
- 输出 Clash Meta YAML、Base64 订阅、JSON
- Clash 输出内置策略组：节点选择、自动最快、综合打分、国家/地区分组
- 内置 HTTP 服务，可直接作为客户端订阅 URL
- `daemon` 定时采集，支持 Windows 批处理启动
- Clash 自动选线：配合 Clash Verge Rev，综合延迟与带宽自动切换最优节点

## 快速开始

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .

fns config init
# 编辑 fns.yaml，配置 api.urls 或 github.search_queries

fns run -n 10

# Windows 一键启动：Clash Verge + 自动选线 + 每 2 小时采集
start_daemon.bat 2
```

运行完成后，输出文件在 `output/`：

- `output/fns.yaml`：Clash Meta 配置
- `output/fns.txt`：Base64 订阅
- `output/fns.json`：JSON 节点数据（需在配置中启用）
- `output/fns.collected.jsonl`：本次运行采集到的全部解析节点快照
- `output/fns.validation_report.json`：节点去重、验证和死亡原因汇总
- `output/fns.state.json`：增量更新使用的内部节点状态

导入 Clash Verge Rev / Mihomo 时使用 `output/fns.yaml`，其他客户端可使用 `output/fns.txt`。

## 常用命令

| 命令 | 说明 |
|------|------|
| `fns run` | 执行一次完整采集管线 |
| `fns run -n 10 --serve` | 采集 10 个存活节点并启动 HTTP 服务 |
| `fns daemon -i 2` | 每 2 小时定时采集 |
| `start_daemon.bat 2` | Windows 一键启动：Clash Verge + 自动选线 + 定时采集 |
| `fns validate <url>` | 验证单个订阅 URL |
| `fns check <host> <port> -T <type>` | 检查单个代理节点 |
| `fns sources list -a` | 查看全部采集源 |
| `fns config init / show / path` | 配置管理 |

## 配置

完整配置说明见 [USAGE.md](USAGE.md)。

```yaml
sources:
  api:
    enabled: true
    urls:
      - https://example.com/sub.txt

validator:
  concurrency: 50
  timeout: 5.0
  retries: 1

output:
  dir: ./output
  formats:
    - clash
    - base64

max_alive_nodes: 10
```

配置文件使用 snake_case 字段名，例如 `allow_lan`、`log_level`。

## 文档

- [USAGE.md](USAGE.md)：完整使用手册
- `fns.example.yaml`：可复制的示例配置

## 开发与测试

```powershell
pip install -e ".[dev]"
pytest tests/ -v
ruff check src tests
```

## 许可证

MIT
