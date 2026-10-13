"""AlienVault OTX 情报源。

API 文档: https://otx.alienvault.com/api
支持: IP / 域名 / 文件哈希 —— 基于社区 Pulse 订阅量判定。

配置::

    [intel.platforms.otx]
    api_key_env = "OTX_API_KEY"
    weight = 0.9
"""

from __future__ import annotations

from typing import Any, Dict, List

from irtrace.core.models import Severity
from irtrace.intel.base import ThreatIntelProvider
from irtrace.intel.http import request_json
from irtrace.intel.models import IndicatorType, IntelVerdict
from irtrace.intel.registry import register_provider

_SECTIONS = {
    IndicatorType.IP: "IPv4",
    IndicatorType.DOMAIN: "domain",
    IndicatorType.HASH: "file",
}


@register_provider
class OTXProvider(ThreatIntelProvider):
    name = "otx"
    description = "AlienVault OTX (社区 Pulse 情报)"
    homepage = "https://otx.alienvault.com/"
    supports = (IndicatorType.IP, IndicatorType.DOMAIN, IndicatorType.HASH)
    requires_api_key = True
    api_key_env = "OTX_API_KEY"
    offline = False
    weight = 0.9
    min_interval = 1.0
    timeout = 15

    @property
    def base_url(self) -> str:
        return str(self.config.get("base_url", "https://otx.alienvault.com/api/v1")).rstrip("/")

    # ------------------------------------------------------------------ #
    def _lookup(self, indicator: str, itype: IndicatorType) -> IntelVerdict:
        section = _SECTIONS.get(itype)
        if section is None:
            return self.error_verdict(indicator, itype, f"不支持 {itype.value}")

        status, payload, err = request_json(
            f"{self.base_url}/indicators/{section}/{indicator}/general",
            headers={"X-OTX-API-KEY": self.api_key or ""},
            timeout=self.timeout,
        )
        if err:
            return self.error_verdict(indicator, itype, err)
        if not isinstance(payload, dict):
            return self.error_verdict(indicator, itype, "响应格式异常")

        pulse_info: Dict[str, Any] = payload.get("pulse_info") or {}
        count = int(pulse_info.get("count", 0))
        pulses = pulse_info.get("pulses") or []

        tags: List[str] = []
        for p in pulses[:10]:
            if isinstance(p, dict):
                for t in (p.get("tags") or [])[:4]:
                    if t and t not in tags:
                        tags.append(str(t))

        malicious = count >= 3
        score = min(95.0, count * 12.0)
        desc = f"OTX: 命中 {count} 个情报 Pulse"
        if payload.get("reputation") is not None:
            desc += f"; 信誉: {payload['reputation']}"
        if pulses and isinstance(pulses[0], dict) and pulses[0].get("name"):
            desc += f"; 首个 Pulse: {pulses[0]['name']}"

        return self.verdict(
            indicator, itype,
            malicious=malicious,
            score=score if malicious else min(score, 15.0),
            severity=self.severity_from_score(score) if malicious else Severity.INFO,
            confidence=0.8 if count >= 5 else 0.6,
            tags=sorted(set(tags + ["otx"])),
            description=desc,
            raw={"pulse_count": count,
                 "reputation": payload.get("reputation"),
                 "tags": tags[:20]},
        )


__all__ = ["OTXProvider"]
