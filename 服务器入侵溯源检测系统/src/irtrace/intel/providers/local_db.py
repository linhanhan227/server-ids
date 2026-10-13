"""本地威胁数据库情报源（离线）。

只读 ``data/secrets.db`` 里手动拉取落地的指标。检测过程不联网。
来源名保持 ``local_db``，原始记录里的在线平台名留在 ``raw``，
供需要区分来源时查看。
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from irtrace.core.models import Severity
from irtrace.intel.base import ThreatIntelProvider
from irtrace.intel.models import IndicatorType, IntelVerdict
from irtrace.intel.registry import register_provider

_SEVERITY = {item.value: item for item in Severity}


@register_provider
class LocalDBProvider(ThreatIntelProvider):
    name = "local_db"
    description = "本地威胁数据库 (手动拉取的在线情报)"
    homepage = ""
    supports = (IndicatorType.IP, IndicatorType.DOMAIN,
                IndicatorType.HASH, IndicatorType.URL)
    requires_api_key = False
    offline = True
    weight = 1.0
    min_interval = 0.0

    def _lookup(self, indicator: str, itype: IndicatorType) -> IntelVerdict:
        rows = self._rows(indicator, itype)
        if not rows:
            return self.verdict(
                indicator, itype, malicious=False, score=0.0,
                severity=Severity.INFO, confidence=0.3,
                tags=["local-db"],
                description="本地威胁数据库未收录",
            )

        best = max(rows, key=lambda item: float(item.get("score") or 0))
        providers = sorted({item["provider"] for item in rows})
        return self.verdict(
            indicator, itype, malicious=True,
            score=float(best.get("score") or 0),
            severity=_SEVERITY.get(str(best.get("severity")), Severity.HIGH),
            confidence=max(float(item.get("confidence") or 0) for item in rows),
            tags=["local-db", *[f"from:{name}" for name in providers]],
            description="本地威胁数据库命中: " + "；".join(
                f"{item['provider']} {item.get('description') or ''}".strip() for item in rows
            ),
            raw={"hits": rows},
        )

    def _rows(self, indicator: str, itype: IndicatorType):
        workspace = self.config.get("workspace")
        if not workspace:
            return []
        try:
            from irtrace.intel.localdb import ThreatDB
            return ThreatDB(workspace).lookup(indicator.strip(), itype.value)
        except (OSError, ValueError):
            return []


__all__ = ["LocalDBProvider"]
