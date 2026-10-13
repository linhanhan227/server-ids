"""AbuseIPDB v2 情报源 (仅 IP)。

API 文档: https://docs.abuseipdb.com/
配置::

    [intel.platforms.abuseipdb]
    api_key_env = "ABUSEIPDB_API_KEY"
    max_age_days = 90
    weight = 1.0
"""

from __future__ import annotations

from typing import Any, Dict

from irtrace.core.models import Severity
from irtrace.intel.base import ThreatIntelProvider
from irtrace.intel.http import request_json
from irtrace.intel.models import IndicatorType, IntelVerdict
from irtrace.intel.registry import register_provider


@register_provider
class AbuseIPDBProvider(ThreatIntelProvider):
    name = "abuseipdb"
    description = "AbuseIPDB (IP 滥用举报库)"
    homepage = "https://www.abuseipdb.com/"
    supports = (IndicatorType.IP,)
    requires_api_key = True
    api_key_env = "ABUSEIPDB_API_KEY"
    offline = False
    weight = 1.0
    min_interval = 1.0
    timeout = 10

    @property
    def base_url(self) -> str:
        return str(self.config.get("base_url", "https://api.abuseipdb.com/api/v2")).rstrip("/")

    # ------------------------------------------------------------------ #
    def _lookup(self, indicator: str, itype: IndicatorType) -> IntelVerdict:
        status, payload, err = request_json(
            f"{self.base_url}/check",
            headers={"Key": self.api_key or "", "Accept": "application/json"},
            params={"ipAddress": indicator,
                    "maxAgeInDays": int(self.config.get("max_age_days", 90))},
            timeout=self.timeout,
        )
        if err:
            return self.error_verdict(indicator, itype, err)
        if not isinstance(payload, dict):
            return self.error_verdict(indicator, itype, "响应格式异常")

        data: Dict[str, Any] = payload.get("data") or {}
        if not data:
            return self.error_verdict(indicator, itype,
                                      f"响应缺少 data: {payload.get('errors')}")

        confidence = float(data.get("abuseConfidenceScore", 0))
        reports = int(data.get("totalReports", 0))
        malicious = confidence >= 25 or reports >= 5

        tags = ["abuseipdb"]
        if data.get("isWhitelisted"):
            tags.append("whitelisted")
            malicious = False
        if data.get("usageType"):
            tags.append(str(data["usageType"]))

        desc = (f"AbuseIPDB: 滥用置信度 {confidence:.0f}%, "
                f"举报 {reports} 次 / {data.get('numDistinctUsers', 0)} 个来源")
        if data.get("countryCode"):
            desc += f"; 国家: {data['countryCode']}"
        if data.get("isp"):
            desc += f"; ISP: {data['isp']}"

        return self.verdict(
            indicator, itype,
            malicious=malicious,
            score=confidence,
            severity=self.severity_from_score(confidence) if malicious else Severity.INFO,
            confidence=0.85 if reports >= 5 else 0.65,
            tags=sorted(set(tags)),
            description=desc,
            raw={k: data.get(k) for k in
                 ("abuseConfidenceScore", "totalReports", "numDistinctUsers",
                  "lastReportedAt", "countryCode", "isp", "usageType", "isWhitelisted")},
        )


__all__ = ["AbuseIPDBProvider"]
