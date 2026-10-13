# IRTrace — Linux 服务器入侵溯源检测框架

一套面向**应急响应 / 入侵溯源**的模块化取证框架：只读采集目标主机痕迹 → 归一化为统一时间轴 → 跨源关联分析 → 输出多格式溯源报告。

> 运行期零第三方依赖（纯 Python 标准库），可在离线应急现场直接运行。

## 快速开始

```bash
# 1. 环境自检（确认权限、依赖命令、可用采集器）
python -m irtrace doctor

# 2. 完整溯源分析（采集 → 分析 → 报告）
sudo python -m irtrace run --format json markdown html

# 3. 常用子命令
python -m irtrace list                 # 列出全部插件
python -m irtrace collect --only process network
python -m irtrace analyze --run-dir runs/<run_id>   # 用已有报告重跑分析
python -m irtrace verify runs/<run_id> # 校验证据哈希链完整性

# 4. 离线演练（不采集本机，合成一条爆破→落地→外联攻击链）
PYTHONPATH=src python scripts/replay.py
```

开发期测试（pytest 只在开发环境安装，运行期仍零依赖）：

```bash
python3 -m venv .venv && .venv/bin/pip install pytest
.venv/bin/python -m pytest
```

安装为命令（可选）：

```bash
pip install -e .
irtrace run
```

## Web 可视化控制台

零依赖的只读控制台（标准库 `http.server`，可离线运行），用于浏览 `runs/` 下的分析结果。

```bash
python -m irtrace web                  # 默认 http://127.0.0.1:8787
python -m irtrace web --port 9000 --open
```

| 视图 | 内容 |
| --- | --- |
| **概览** | 事件 / 结论 / 严重级别分布 / 事件时间密度图（红色柱 = 含高危事件） |
| **发现项** | 按严重级别筛选 + 全文搜索，可展开查看 `details` 明细与 MITRE 编号 |
| **时间线** | 全量事件表，高危事件高亮，支持「仅高危」筛选 |
| **威胁情报** | 情报源状态、查询/缓存统计、各源命中指标清单、IOC 提取汇总 |
| **证据链** | 证据清单 + SHA256，并实时校验哈希链完整性（✓ 完整 / ✗ 被篡改） |
| **审计日志** | 运行期每条命令与返回码 |

安全设计：默认仅绑定 `127.0.0.1`；静态资源与 `runs/` 之外的文件一律拒绝（防目录穿越）；`run_id` 经白名单校验；控制台**只读**，不提供任何修改目标系统的操作。

## 输出结构

```
runs/<run_id>/
├── audit.log                  # 全流程审计（每条命令与证据登记）
├── evidence-ledger.jsonl      # 证据哈希链账本（防篡改）
├── summary.json               # 运行摘要
├── evidence/                  # 原始证据（按采集器分目录）
│   ├── process/process-snapshot.tsv
│   ├── auth_log/auth.log
│   └── ...
└── reports/
    ├── result.json            # 结构化全量结果
    ├── report.md              # 可读溯源报告
    └── report.html            # 单文件可视化报告
```

## 能力矩阵

**采集器（10 个）**

| 采集器 | 取证对象 |
| --- | --- |
| `process` | 进程树；已删除可执行文件、可写目录启动、反弹 shell、中转/端口转发、memfd、挖矿命令行、伪装内核线程、下载后执行 |
| `network` | 连接/监听端口/外联 IP（`ss` 优先，`/proc/net` 兜底） |
| `auth_log` | `auth.log`/`secure`/`wtmp`/`btmp`；登录、sudo、暴力破解 |
| `persistence` | cron、systemd、rc.local、`ld.so.preload`、`authorized_keys`、profile |
| `account` | `passwd`/`shadow`/`group`/`sudoers`；UID=0 后门账号、空口令 |
| `filesystem` | 可写目录可执行文件、SUID、近期变更文件、已知恶意样本名、Web 目录中的脚本型 webshell |
| `kernel` | 内核模块、rootkit 特征、关键 sysctl 偏离 |
| `web_log` | nginx/apache 访问日志；已响应的 webshell、路径扫描、模型登录撞库、补全接口打满 |
| `command_history` | shell 历史被截断，或启动脚本把 `HISTFILE` 指到 `/dev/null`（T1070.003） |
| `hidden_proc` | `/proc` 里有、`ps` 列不出的进程（chkrootkit chkproc，T1014） |

**分析器（4 个）**

| 分析器 | 职责 |
| --- | --- |
| `timeline` | 统一时间轴 + 攻击窗口（事件密度异常）识别 |
| `ioc` | IOC 提取（IP/域名/URL/哈希）+ 威胁情报比对 + 外联画像 |
| `correlation` | 16 条跨源关联规则，组合弱信号形成攻击链结论 |
| `intrusion` | 场景级失陷判定：多阶段加权，抑制正常运维与单纯扫描误报 |
| `ai_assist` | 真实调用 AI 模型，只依据本次情报查询结果判定；未接上在线源时会标明 |

**报告器（3 个）**：`json` / `markdown` / `html`

## 威胁情报对接

检测只查本地库：本地规则、CSV，以及手动拉取落地的威胁数据库。不会因为分析自己去请求在线情报，避免额度用完后无法检测。

在线 Key 放在 Web 控制台「情报源 Key」。明文写在 `data/secrets.db`，不加密，也没有单独的主密钥文件。接口只回掩码。环境变量仍可作为 Key 的后备，但不触发自动查询。

| 平台 | 申请 / 管理地址 | 免费额度 | 环境变量 |
| --- | --- | --- | --- |
| 微步在线 ThreatBook | <https://x.threatbook.com/v5/serviceCenter?tab=myKey> | 付费为主 | `THREATBOOK_API_KEY` |
| VirusTotal | <https://www.virustotal.com/gui/my-apikey> | 4 次/分、500 次/天 | `VT_API_KEY` |
| AbuseIPDB | <https://www.abuseipdb.com/account/api> | 1,000 次/天 | `ABUSEIPDB_API_KEY` |
| AlienVault OTX | <https://otx.alienvault.com/settings> | 免费 | `OTX_API_KEY` |
| MISP（自建） | 实例内「用户设置 → Auth keys」 | 取决于实例 | `MISP_API_KEY` |
| `local_rules` / `csv_feed` | 本地 `data/rules/`、`data/intel/` | 无限制 | — |

启用方式与各平台详细申请步骤见 **[docs/threat-intel.md](docs/threat-intel.md)**。

```bash
python -m irtrace intel list                              # 查看平台与本地库状态
python -m irtrace intel pull                              # 手动拉取并写入本地库
python -m irtrace intel check 45.155.205.233 --type ip    # 只查本地库
```

## AI 辅助判定

模型只读本次事件摘要和情报查询原文，不读取其它文件，也不执行任何删除。返回里如果出现删除动作，整段结论丢弃。

协议支持 OpenAI 兼容接口和本机 `codex` CLI。Key 与 `base_url`、模型名一起放在明文 `data/secrets.db` 的 `ai_model` 条目，接口只回掩码。环境变量 `IRTRACE_AI_BASE_URL` / `IRTRACE_AI_API_KEY` / `IRTRACE_AI_MODEL` 优先于库。

```bash
python -m irtrace ai set --base-url https://host/v1 --model <name> --api-key <key>
python -m irtrace ai status
python -m irtrace ai check 45.155.205.233
```

默认只把本地库的查询结果交给模型。Web「设置」里的「在线交叉验证」默认关闭；打开后，AI 判定才会用已配置的在线接口核对。没有在线命中时，结论带「仅有本地情报，不是在线高精度判定」。

## 配置

不再使用 TOML。运行配置、情报源 Key 和本地威胁库都在 `data/secrets.db`，通过 Web 控制台「设置」修改。`--config` 会被拒绝。

## 架构与扩展

设计细节见 [`docs/architecture.md`](docs/architecture.md)，威胁情报对接见 [`docs/threat-intel.md`](docs/threat-intel.md)。新增采集器只需继承 `BaseCollector` 并加 `@register` 装饰器：

```python
@register
class WebLogCollector(BaseCollector):
    name = "weblog"
    description = "解析 Web 访问日志, 识别 webshell 特征"
    requires_paths = ["/var/log/nginx"]

    def collect(self, ctx) -> CollectResult:
        ...
```

外部插件目录：`python -m irtrace run --plugin-dir ./my_plugins`

## 安全声明

- 本工具**只读**运行，不修改目标系统任何状态；所有目标访问经 `RunContext` 收敛并拦截破坏性命令。
- 建议以 `root` 运行以获得完整可见性（`/etc/shadow`、`/proc/*/exe`、`lastb` 等），并在**取证副本**或已隔离主机上执行。
- 证据采用 SHA256 哈希链，`irtrace verify` 可验证未被篡改。
