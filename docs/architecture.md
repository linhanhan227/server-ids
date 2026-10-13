# IRTrace 架构设计

## 1. 设计目标

| 目标 | 落地方式 |
| --- | --- |
| **只读取证** | 所有目标访问收敛到 `RunContext`，禁止 shell 重定向与破坏性命令 |
| **证据可验证** | 每份证据落盘并计算 SHA256，写入哈希链账本 `evidence-ledger.jsonl` |
| **可扩展** | 采集/分析/报告三类插件 + `@register` 装饰器 + `--plugin-dir` |
| **单一时间轴** | 所有事件归一化为 UTC，支持跨源关联与攻击窗口识别 |
| **现场可用** | 运行期零第三方依赖，纯标准库，离线可直接运行 |

## 2. 分层结构

```
┌─────────────────────────────────────────────────────────────┐
│                         CLI (cli.py)                        │
│      run / collect / analyze / list / verify / doctor       │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│                  Orchestrator (core/pipeline.py)            │
│         collect() ──► analyze() ──► report()                │
└───────┬──────────────────┬──────────────────────┬───────────┘
        │                  │                      │
┌───────▼────────┐ ┌───────▼────────┐  ┌──────────▼──────────┐
│  Collectors    │ │   Analyzers    │  │     Reporters       │
│ process        │ │ timeline       │  │ json                │
│ network        │ │ ioc            │  │ markdown            │
│ auth_log       │ │ correlation    │  │ html                │
│ persistence    │ │                │  │                     │
│ account        │ │                │  │                     │
│ filesystem     │ │ intrusion      │  │                     │
│ kernel         │ │ ai_assist      │  │                     │
│ web_log        │ │                │  │                     │
└───────┬────────┘ └───────┬────────┘  └──────────┬──────────┘
        └──────────────────┼──────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│              core: RunContext / Registry / Models            │
│  Event · Evidence · Finding   |   hash-ledger   |   audit    │
└─────────────────────────────────────────────────────────────┘
```

## 3. 数据流

1. **采集阶段** — 各 `Collector` 只读访问 `/proc`、`/etc`、`/var/log`，产出 `Event`（归一化动作）与 `Evidence`（原始素材）。证据经 `ctx.store_evidence()` 落盘并登记哈希链。
2. **分析阶段** — `Analyzer` 消费 `ctx.events` / `ctx.evidence`，产出 `Finding`（结论）。分析器包括时间线、IOC、跨源关联、场景级失陷判定与 AI 辅助判定。
3. **报告阶段** — `Reporter` 渲染 `Finding` + `Event` + `Evidence` 为 JSON / Markdown / HTML。

## 4. 核心抽象

### Event（归一化事件）
统一字段：`timestamp(UTC)` `category` `source` `action` `user` `pid/ppid` `src_ip/dst_ip/dst_port` `path` `tags` `raw`。
`tags` 是关联分析的关键——分析器与关联规则均基于标签匹配。

### Evidence（证据）
`source` `kind` `path` `sha256` `size` `mtime` `collected_at`。
哈希链：`entry_hash = SHA256(prev_hash | seq | evidence_id | sha256)`，任意条目被篡改都会导致 `verify` 失败。

### Finding（结论）
`title` `severity` `confidence` `category` `mitre` `event_ids` `evidence_ids` `details`。
通过 `event_ids` / `evidence_ids` 可回溯到原始证据，形成完整证据链。

## 5. 关联规则（correlation）

| 规则 | 信号组合 | ATT&CK |
| --- | --- | --- |
| R1 爆破成功 | `ssh_failed ×N` → `ssh_login`（同 IP，1h 内） | T1110 / T1078 |
| R2 登录后提权 | `ssh_login` → `sudo`/`user_added`（30min 内） | T1078 / T1548 |
| R3 落地执行 | 可写目录可执行文件 + 同路径进程 | T1059 / T1204 |
| R4 持久化闭环 | 可疑进程/账号 + 持久化点变更 | T1547 / T1053 |
| R5 外联回连 | 反弹 shell 特征 + 外部连接 | T1071 / T1571 |
| R6 无文件/Rootkit | 已删除 exe 进程 + 内核模块异常 | T1014 / T1027 |
| R7 webshell | Web 目录中的 webshell 文件 + 访问日志命中同一路径 | T1505.003 / T1105 |
| R8 中转沦陷 | 中转或端口转发进程 + 公网连入 + 对外连接 | T1090 / T1572 |
| R9 模型中转 | 对外模型接口且配置上游地址 + 外部流量 | T1090 |
| R10 模型爆破/打野 | 模型登录大量失败后成功；或中转进程在线时补全接口被同一来源打满 | T1110 / T1496 |
| R11 密钥泄露 | 同一密钥指纹被至少两个来源用来调用模型接口 | T1552 |
| R12 清痕后落地 | 命令历史被清空，且随后出现落地、反弹或 memfd | T1070.003 |
| R13 隐藏进程 | `ps` 不可见的进程，同时有已删除可执行文件或 rootkit 模块 | T1014 |
| R14 无文件执行 | memfd 或解释器从标准输入执行，且伴随外联或落地 | T1620 |
| R15 挖矿驻留 | 挖矿命令行同时有矿池外联，或在可写目录落地 | T1496 |
| R16 伪装内核 | 用户态进程伪装成内核线程，且有挖矿、落地或外联 | T1036.005 |

场景级判定在 `intrusion`。中转进程（frp、gost、chisel、ssh -L/-R/-D 等）单独存在不跨过阈值；同一场景同时看到入站和出站才记为中转站沦陷。模型中转站要同时有对外监听和上游模型地址，再加一条入站或出站连接；只配置了上游地址、没有对外监听的进程是调用方，不算中转。模型登录失败但没有成功、以及没有中转进程的补全高频，都不单独判失陷。查询串里的密钥和反代附加的 `keyfp:` 只换成 SHA256 前 12 位，写入证据前再把原文替换成 `[redacted]`；同一指纹只出现在一个来源时不判泄露。可写目录中的 SUID、`/etc/ld.so.preload` 有内容、家目录落在 `/tmp` 或 `/dev/shm`，各自单独构成失陷。可疑端口监听要配合已有攻击阶段才加分。系统账号可登录 shell、近期改口令、特权组成员和 sysctl 偏离仍只作基线，不进失陷分。Web 日志里状态码为 2xx 或 5xx 的 webshell 请求记为执行（T1505.003）；404 探测和同一来源的路径扫描只作为侦察噪声，单独不跨过失陷阈值。磁盘上的 webshell 文件只有和一次成功访问指向同一路径时才追加落地分，单独存放不判失陷。挖矿命令行（矿池协议、xmrig 的 `donate-level` / `rx/0`，以及这些参数的 base64 片段）单独 +7（T1496）。进程名是 `[kworker…]`、`[kthreadd]` 这类内核线程，但 `/proc/PID/exe` 指向用户态文件，单独 +7（T1036.005）；exe 为空的是真内核线程，不报。`wget`/`curl` 把响应交给 `sh`/`bash`/`perl`，且同一场景已有可写目录落地文件时 +6（T1059.004）；单独一条管道不跨过阈值。

## 6. 威胁情报层（intel）

IOC 分析器不直接访问外部平台，而是通过 **聚合器** 统一查询，便于替换与测试。

```
IOCAnalyzer ──► IntelAggregator ──┬── local_rules   (离线, 本地规则库)
                                  ├── csv_feed      (离线, data/intel/*.csv|json)
                                  └── local_db      (离线, 手动拉取落地的威胁库)
在线源只在 `irtrace intel pull` 或 AI 交叉验证开关打开时使用。
                     │
                     ├── IntelCache    磁盘 TTL 缓存 (避免重复消耗配额)
                     ├── RateLimiter   按平台最小间隔限速
                     └── Evidence      原始响应落盘 → 纳入 SHA256 哈希链
```

### 关键机制

| 机制 | 说明 |
| --- | --- |
| **只读本地库** | 检测不请求在线情报。在线结果先手动拉取进 `threat_indicators` |
| **交叉验证默认关闭** | `ai.cross_validate` 打开后，AI 判定才查询已配置的在线接口 |
| **Key 在 SQLite** | 明文放在 `data/secrets.db`，接口只回掩码；不再读 TOML |
| **多源聚合** | 综合评分 = Σ(评分×置信度)/Σ(置信度)；级别取最高危；多源命中提升聚合置信度 |
| **指标级去重** | 同一指标只产出一条 Finding（`details.verdicts` 保留各平台明细） |
| **失败隔离** | 单平台异常仅记录 `error` 判定，不参与聚合、不中断分析 |
| **并发查询** | 在线源经 `ThreadPoolExecutor` 并发执行，离线源同步执行 |

聚合判定公式与各平台申请地址详见 [`threat-intel.md`](threat-intel.md)。

## 7. Web 控制台（web）

只读可视化层，基于标准库 `http.server`，零依赖、可离线。

```
浏览器 ──► ThreadingHTTPServer ──┬── /api/runs                    运行列表
                                 ├── /api/runs/<id>               完整结果 (result.json)
                                 ├── /api/runs/<id>/ledger        哈希链重放校验
                                 ├── /api/runs/<id>/audit         审计日志
                                 ├── /api/runs/<id>/report.html   原始 HTML 报告
                                 └── /api/overview                跨运行汇总
                    │
                    └── RunStore   只读数据访问层 (runs/ 目录)
```

### 安全约束

| 约束 | 实现 |
| --- | --- |
| 不对外暴露 | 默认绑定 `127.0.0.1`，需显式 `--host` 才能改 |
| 防目录穿越 | 静态资源必须落在 `static/` 内；`runs/` 访问经 `Path.relative_to()` 校验 |
| run_id 白名单 | `^[A-Za-z0-9][A-Za-z0-9_\-]{0,63}$` |
| 只读 | 仅实现 `GET`/`HEAD`，无任何写接口 |
| 响应头加固 | `X-Content-Type-Options: nosniff`、`Cache-Control: no-store` |

前端为原生 JS 单页应用，无 CDN 依赖，图表以 CSS/SVG 绘制（严重级别条形图、事件时间密度图）。

## 8. 扩展方式

新增采集器（放入 `--plugin-dir` 或 `src/irtrace/collectors/`）：

```python
from irtrace.core.plugin import CollectResult
from irtrace.core.registry import register
from irtrace.collectors.base import BaseCollector

@register
class WebLogCollector(BaseCollector):
    name = "weblog"
    description = "解析 nginx/apache 访问日志, 识别 webshell 特征"
    requires_paths = ["/var/log/nginx"]

    def collect(self, ctx) -> CollectResult:
        res = CollectResult()
        # ... 使用 ctx.read_file / ctx.run_command / ctx.store_evidence
        return res
```

## 9. 安全约束

- `RunContext.run_command()` 仅接受参数序列（不经 shell），并拦截 `rm` `dd` `mkfs` `chown` `systemctl stop` 等破坏性前缀。
- 所有外部命令强制超时（默认 30s），单插件异常隔离，不中断整轮分析。
- 运行全程写入 `audit.log`，记录每一条命令与证据登记动作。
- 报告不包含明文口令（`/etc/shadow` 仅采集元信息与风险标记）。
