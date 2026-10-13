"""VirusTotal v3 情报源。

API 文档: https://docs.virustotal.com/reference/overview
支持: IP / 域名 / 文件哈希

配置::

    [intel.platforms.virustotal]
    api_key_env = "VT_API_KEY"
    weight = 1.0
    min_interval = 15          # 免费版限速 (4 req/min)
"""

from __future__ import annotations

from typing import Any, Dict, List

from irtrace.core.models import Severity
from irtrace.intel.base import ThreatIntelProvider
from irtrace.intel.http import request_json
from irtrace.intel.models import IndicatorType, IntelVerdict
from irtrace.intel.registry import register_provider

_PATHS = {
    IndicatorType.IP: "ip_addresses",
    IndicatorType.DOMAIN: "domains",
    IndicatorType.HASH: "files",
}


@register_provider
class VirusTotalProvider(ThreatIntelProvider):
    name = "virustotal"
    description = "VirusTotal v3 (多引擎检测 + 社区信誉)"
    homepage = "https://www.virustotal.com/"
    supports = (IndicatorType.IP, IndicatorType.DOMAIN, IndicatorType.HASH)
    requires_api_key = True
    api_key_env = "VT_API_KEY"
    offline = False
    weight = 1.0
    min_interval = 15.0     # 免费配额 4 次/分钟
    timeout = 15

    @property
    def base_url(self) -> str:
        return str(self.config.get("base_url", "https://www.virustotal.com/api/v3")).rstrip("/")

    # ------------------------------------------------------------------ #
    def _lookup(self, indicator: str, itype: IndicatorType) -> IntelVerdict:
        path = _PATHS.get(itype)
        if path is None:
            return self.error_verdict(indicator, itype, f"不支持 {itype.value}")

        status, payload, err = request_json(
            f"{self.base_url}/{path}/{indicator}",
            headers={"x-apikey": self.api_key or ""},
            timeout=self.timeout,
        )
        if err:
            return self.error_verdict(indicator, itype, err)
        if not isinstance(payload, dict):
            return self.error_verdict(indicator, itype, "响应格式异常")

        attrs = ((payload.get("data") or {}).get("attributes") or {})
        if not attrs:
            return self.error_verdict(indicator, itype, "响应缺少 attributes")

        stats: Dict[str, int] = attrs.get("last_analysis_stats") or {}
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        harmless = int(stats.get("harmless", 0))
        undetected = int(stats.get("undetected", 0))
        total = malicious + suspicious + harmless + undetected
        weighted = malicious + suspicious * 0.5
        score = round(weighted / total * 100, 1) if total else 0.0
        is_bad = malicious >= 3 or (malicious >= 1 and total and malicious / total > 0.1)

        tags: List[str] = [str(t) for t in (attrs.get("tags") or [])]
        if is_bad:
            tags.append("vt-detection")

        desc = (f"VirusTotal: {malicious}/{total} 引擎判定恶意"
                f" (可疑 {suspicious})")
        if attrs.get("as_owner"):
            desc += f"; AS: {attrs['as_owner']}"
        if attrs.get("country"):
            desc += f"; 国家: {attrs['country']}"
        if attrs.get("reputation") is not None:
            desc += f"; 社区信誉: {attrs['reputation']}"

        return self.verdict(
            indicator, itype,
            malicious=bool(is_bad),
            score=score,
            severity=self.severity_from_score(score) if is_bad else Severity.INFO,
            confidence=0.9 if malicious >= 5 else 0.75,
            tags=sorted(set(tags)),
            description=desc,
            raw={"last_analysis_stats": stats,
                 "reputation": attrs.get("reputation"),
                 "as_owner": attrs.get("as_owner"),
                 "country": attrs.get("country"),
                 "tags": attrs.get("tags")},
        )


__all__ = ["VirusTotalProvider"]
