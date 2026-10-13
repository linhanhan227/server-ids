# 威胁情报平台对接说明

本文档说明 IRTrace 支持的在线威胁情报平台、**API Key 申请地址**、免费额度、配置方法与排查手段。

---

## 一、设计原则（先读这段）

| 原则 | 说明 |
| --- | --- |
| **离线优先** | 默认 `mode = "offline"`，只使用本地情报源。**取证现场不会产生任何外联**，避免污染证据、暴露调查意图。 |
| **显式开启** | 在线平台必须同时满足 `enabled = true` 且 `mode = "online"` 才会被调用。 |
| **Key 不入库** | API Key 只从**环境变量**读取，不写入配置文件、不进入日志、不进入报告。 |
| **可审计** | 每次情报查询的原始响应落盘为证据（`evidence/intel/`），纳入 SHA256 哈希链。 |
| **优雅降级** | 单平台超时/配额耗尽/鉴权失败不影响整体分析，仅记录为 `error` 判定。 |

> ⚠️ **合规提示**：向第三方平台提交内网 IP、域名、文件哈希属于**数据外传**行为。生产环境启用前请确认符合单位的数据安全与保密制度。

---

## 二、平台清单与申请地址

| 平台 | 类型 | 申请 / 管理地址 | 免费额度 | 环境变量 | 支持指标 | 默认权重 |
| --- | --- | --- | --- | --- | --- | --- |
| **微步在线 ThreatBook** | 商业 | [我的 API KEY](https://x.threatbook.com/v5/serviceCenter?tab=myKey) ｜ [申请文档](https://x.threatbook.com/apiDocs/start/get_api_key) ｜ [产品页](https://threatbook.cn/prod/api) | 付费为主，部分接口有试用额度 | `THREATBOOK_API_KEY` | IP / 域名 / 哈希 | 1.2 |
| **VirusTotal** | 免费+商业 | [我的 API Key](https://www.virustotal.com/gui/my-apikey) ｜ [注册](https://www.virustotal.com/gui/join-us) | 4 次/分钟、500 次/天 | `VT_API_KEY` | IP / 域名 / 哈希 | 1.0 |
| **AbuseIPDB** | 免费+商业 | [API 管理](https://www.abuseipdb.com/account/api) ｜ [注册](https://www.abuseipdb.com/register) ｜ [文档](https://www.abuseipdb.com/api.html) | 1,000 次/天 | `ABUSEIPDB_API_KEY` | IP | 1.0 |
| **AlienVault OTX** | 免费 | [设置页](https://otx.alienvault.com/settings) ｜ [注册](https://otx.alienvault.com/) | 免费（有软性速率限制） | `OTX_API_KEY` | IP / 域名 / 哈希 | 0.9 |
| **MISP** | 自建 | 需自建或订阅实例；Key 在 **用户设置 → Auth keys** 生成，参考 [官方 OpenAPI](https://www.misp-project.org/openapi/) | 取决于实例 | `MISP_API_KEY` | IP / 域名 / 哈希 / URL | 1.1 |
| **local_rules** | 离线 | 本地文件 `data/rules/ioc_rules.json` | 无限制 | — | IP / 域名 / 哈希 / URL | 1.0 |
| **csv_feed** | 离线 | 本地目录 `data/intel/` | 无限制 | — | IP / 域名 / 哈希 / URL | 1.0 |

---

## 三、各平台申请步骤

### 3.1 微步在线 ThreatBook

1. 访问 <https://x.threatbook.com/> 注册账号（企业用户建议完成企业认证以获得更高接口权限）。
2. 登录后进入 **服务中心 → 我的 API KEY**：<https://x.threatbook.com/v5/serviceCenter?tab=myKey>
3. 复制 API KEY；如需开通具体接口（`scene/ip_reputation` 等），在 **服务中心** 中确认已订阅对应 API 服务。
4. 写入环境变量：

```bash
export THREATBOOK_API_KEY="你的_apikey"
```

> 本框架调用的是 **云 API v3**（`https://api.threatbook.cn/v3`）。若为私有化部署，请在配置中改写 `base_url`。
> API KEY 拥有你账号下的全部调用权限，请勿共享或提交到代码仓库。

### 3.2 VirusTotal

1. 注册账号：<https://www.virustotal.com/gui/join-us>
2. 登录后打开 <https://www.virustotal.com/gui/my-apikey>，页面顶部即为你的 API Key。
3. 写入环境变量：

```bash
export VT_API_KEY="你的_apikey"
```

> 免费版配额为 **4 请求/分钟、500 请求/天**。框架默认对 VT 设置 `min_interval = 15`（秒）以避免触发限流；批量分析大量主机时建议提高该值或改用商业版。
> VirusTotal 明确禁止将其用于商业用途的自动化批量查询，请遵守其服务条款。

### 3.3 AbuseIPDB

1. 注册账号：<https://www.abuseipdb.com/register>
2. 登录后打开 <https://www.abuseipdb.com/account/api>，点击 **Create API Key**。
3. 写入环境变量：

```bash
export ABUSEIPDB_API_KEY="你的_apikey"
```

> 免费账号 **1,000 次查询/天**。仅支持 IP 指标。
> 判定逻辑：`abuseConfidenceScore ≥ 25` 或 `totalReports ≥ 5` 视为恶意；若目标 IP 被标记 `isWhitelisted` 则强制置为正常。

### 3.4 AlienVault OTX

1. 注册 / 登录：<https://otx.alienvault.com/>
2. 打开 **Settings** 页：<https://otx.alienvault.com/settings>，页面中 **OTX Key** 即为 API Key。
3. 写入环境变量：

```bash
export OTX_API_KEY="你的_apikey"
```

> 完全免费，基于社区 Pulse 订阅量判定：命中 ≥ 3 个 Pulse 视为恶意。
> 该平台由 AT&T Cybersecurity（LevelBlue）运营。

### 3.5 MISP（自建 / 订阅实例）

MISP 是开源情报共享平台，没有统一的"申请地址"，Key 由**你自己的实例**签发：

1. 部署实例（Docker 一键部署见 <https://github.com/MISP/misp-docker>）或使用上级/行业共享的 MISP 实例。
2. 登录 MISP Web 界面 → 右上角用户菜单 → **Auth keys** → **Add authentication key**。
3. 勾选所需权限（至少需 `attributes/restSearch` 的读权限），生成并复制 Key。
4. 配置实例地址与 Key：

```bash
export MISP_API_KEY="你的_authkey"
```

```toml
[intel.platforms.misp]
url = "https://misp.example.com"    # 必填，缺失则平台不可用
api_key_env = "MISP_API_KEY"
weight = 1.1
```

> 本框架通过 `POST /attributes/restSearch` 查询属性命中，返回关联事件数、IDS 标记数与标签。

---

## 四、配置

不再使用配置文件。Key、运行配置和本地威胁库都在 `data/secrets.db`。

- Web 控制台「情报源 Key」写入各平台 Key。检测不会因此自动查询。
- 「设置」里的「在线交叉验证」默认关闭。打开后，只有 AI 辅助判定会用已配置的在线接口核对。
- 「拉取最新」或 `irtrace intel pull` 才请求在线源，并把结果覆盖进本地威胁库。之后的检测只读这份库。

---

## 五、验证与排查

```bash
# 1. 查看所有平台及其可用状态 (会提示缺少哪个环境变量)
python -m irtrace intel list

# 2. 手动拉取在线情报，写入本地库
python -m irtrace intel pull

# 3. 查询单个指标（只查本地库，不消耗在线额度）
python -m irtrace intel check 45.155.205.233 --type ip

# 4. 查看 / 清空情报缓存
python -m irtrace intel cache
python -m irtrace intel cache --clear
```

`intel list` 输出示例：

```
名称            类型      状态        说明
------------------------------------------------------------------------------
threatbook    在线      不可用       微步在线 ThreatBook (IP/域名/文件信誉)
                                └─ 未配置 API Key (环境变量 THREATBOOK_API_KEY)
virustotal    在线      已启用       VirusTotal v3 (多引擎检测 + 社区信誉)
csv_feed      离线      已启用       本地批量情报源 (data/intel/*.csv|*.json)
local_rules   离线      已启用       本地 IOC 规则库 (data/rules/ioc_rules.json)
```

`intel check` 输出示例：

```
指标      : 45.155.205.233 (IP)
判定      : 恶意
综合评分  : 87.6/100　置信度: 0.97
级别      : critical
命中来源  : csv_feed, local_rules
标签      : local-rule, ioc-ip, local-feed, mining-pool

各平台结果:
  [!] local_rules  恶意 评分=90.0   置信=0.9
      命中本地规则库 (ioc_rules.json)
  [!] csv_feed     恶意 评分=85.0   置信=0.85
      命中本地情报源 threat-feed.csv
```

### 常见问题

| 现象 | 原因 | 处理 |
| --- | --- | --- |
| 平台显示"未配置 API Key" | 环境变量未生效 | 确认 `export` 后在**同一 shell** 中运行；Windows 用 `setx` 后需重开终端 |
| 平台显示"未启用" | 未开启在线模式 | 设置 `enabled = true` 且 `mode = "online"`，并把平台名加入 `providers` |
| MISP 显示"未配置 url" | 缺少实例地址 | 补上 `[intel.platforms.misp] url = "..."` |
| 判定结果里出现 `HTTP 429` | 触发平台限流 | 提高该平台 `min_interval`，或依赖缓存（`cache_ttl_hours`） |
| 判定结果里出现 `HTTP 401/403` | Key 无效或无接口权限 | 重新核对 Key；微步需确认已订阅对应 API 服务 |
| 查询很慢 | 多个在线平台串行/限速 | 在线平台已并发执行；主要瓶颈是 `min_interval`，可适当下调 |
| 想复用已有查询结果 | 缓存被清理 | 缓存位于 `data/intel-cache/`，保留该目录即可 |

---

## 六、离线情报源

无网络环境下仍可保持情报能力：

| 来源 | 路径 | 用途 |
| --- | --- | --- |
| 本地规则库 | `data/rules/ioc_rules.json` | 长期通用的 IOC 与关键词规则 |
| 本地批量情报 | `data/intel/*.csv`、`data/intel/*.json` | 从微步/VT/MISP/SOC **导出的 IOC 清单** |

格式说明见 [`data/intel/README.md`](../data/intel/README.md)。

---

## 七、聚合判定逻辑

多平台结果按以下规则合并（实现见 `src/irtrace/intel/models.py`）：

1. **综合评分** = Σ(平台评分 × 平台置信度) / Σ(平台置信度)，取值范围 0~100。
2. **严重级别** = 取所有"恶意"判定中最高的一档（任一平台判定 CRITICAL 则整体为 CRITICAL）。
3. **聚合置信度** = 各平台置信度均值 + 每多一个命中平台 +0.1（上限 0.99）——即**多源交叉验证会显著提升置信度**。
4. **平台置信度** = 平台自身给出的置信度 × 配置权重 `weight`（上限 1.0）。
5. 查询失败的平台（`error != None`）不参与聚合，仅在报告中列为不可用。

IOC 分析器对**每个指标只产出一条结论**（不会因同一 IP 出现在 20 条日志里就报 20 次），并在结论 `details.verdicts` 中保留各平台的判定明细，便于人工复核。

---

## 八、扩展新平台

新增平台只需实现 `ThreatIntelProvider`（见 `src/irtrace/intel/providers/` 下的现有实现）：

```python
from irtrace.core.models import Severity
from irtrace.intel.base import ThreatIntelProvider
from irtrace.intel.http import request_json
from irtrace.intel.models import IndicatorType, IntelVerdict
from irtrace.intel.registry import register_provider

@register_provider
class MyProvider(ThreatIntelProvider):
    name = "myintel"
    description = "自建情报平台"
    supports = (IndicatorType.IP,)
    requires_api_key = True
    api_key_env = "MYINTEL_API_KEY"
    offline = False
    weight = 1.0

    def _lookup(self, indicator: str, itype: IndicatorType) -> IntelVerdict:
        status, data, err = request_json(
            "https://intel.example.com/api/v1/lookup",
            params={"q": indicator, "key": self.api_key},
            timeout=self.timeout,
        )
        if err:
            return self.error_verdict(indicator, itype, err)
        bad = bool((data or {}).get("malicious"))
        return self.verdict(
            indicator, itype, malicious=bad,
            score=90.0 if bad else 0.0,
            severity=Severity.CRITICAL if bad else Severity.INFO,
            confidence=0.8,
            tags=["myintel"],
            description=f"自建平台判定: {'恶意' if bad else '正常'}",
            raw=data,
        )
```

放在 `src/irtrace/intel/providers/` 下会自动发现；放入外部目录后手动 `import` 亦可。
