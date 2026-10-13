"""威胁情报对接层。

统一对接外部威胁情报平台 (微步在线 ThreatBook / VirusTotal / AbuseIPDB /
AlienVault OTX / MISP / 本地情报源), 为分析器提供一致的查询接口。

设计原则
--------
1. **离线优先** —— 默认 ``mode = "offline"``, 仅使用本地情报源; 联网查询需显式开启,
   避免取证现场意外外联。
2. **多源聚合** —— 同一指标可并发查询多个平台, 按权重合并为统一结论。
3. **可审计** —— 每次外部查询的原始响应落盘为证据, 保留完整证据链。
4. **优雅降级** —— 单平台失败/超时/配额耗尽不影响整体分析, 仅记录告警。
5. **零依赖** —— 基于标准库 ``urllib`` 实现 HTTP, 无需 requests。

快速使用::

    from irtrace.intel import IntelAggregator, IndicatorType

    agg = IntelAggregator.from_config(ctx.config.get("intel", {}), ctx=ctx)
    report = agg.lookup("45.155.205.233", IndicatorType.IP)
    if report.is_malicious:
        print(report.severity, report.sources, report.tags)
"""

from irtrace.intel.models import (
    IndicatorType,
    IntelVerdict,
    IntelReport,
)
from irtrace.intel.base import ThreatIntelProvider
from irtrace.intel.aggregator import IntelAggregator
from irtrace.intel.registry import intel_registry, register_provider

__all__ = [
    "IndicatorType",
    "IntelVerdict",
    "IntelReport",
    "ThreatIntelProvider",
    "IntelAggregator",
    "intel_registry",
    "register_provider",
]
