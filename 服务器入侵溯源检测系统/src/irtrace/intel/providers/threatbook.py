"""微步在线 (ThreatBook) 情报源。

API 文档: https://api.threatbook.cn/v3/
支持: IP 信誉 / 域名信誉 / 文件报告 (SHA256)

配置::

    [intel.platforms.threatbook]
    api_key_env = "THREATBOOK_API_KEY"
    weight = 1.2
    base_url = "https://api.threatbook.cn/v3"   # 可指向私有化部署
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from irtrace.core.models import Severity
from irtrace.intel.base import ThreatIntelProvider
from irtrace.intel.http import request_json
from irtrace.intel.models import IndicatorType, IntelVerdict
from irtrace.intel.registry import register_provider

_SEVERITY_MAP = {
    "high": Severity.CRITICAL,
    "medium": Severity.HIGH,
    "low": Severity.MEDIUM,
    "info": Severity.INFO,
}
_CONF_MAP = {"high": 0.95, "medium": 0.8, "low": 0.6}

_ENDPOINTS = {
    IndicatorType.IP: ("scene/ip_reputation", "resource"),
    IndicatorType.DOMAIN: ("scene/domain_reputation", "resource"),
    IndicatorType.HASH: ("scene/file/report", "resource"),
}


@register_provider
class ThreatBookProvider(ThreatIntelProvider):
    name = "threatbook"
    description = "微步在线 ThreatBook (IP/域名/文件信誉)"
    homepage = "https://x.threatbook.com/"
    supports = (IndicatorType.IP, IndicatorType.DOMAIN, IndicatorType.HASH)
    requires_api_key = True
    api_key_env = "THREATBOOK_API_KEY"
    offline = False
    weight = 1.2
    min_interval = 1.0
    timeout = 10

    @property
    def base_url(self) -> str:
        return str(self.config.get("base_url", "https://api.threatbook.cn/v3")).rstrip("/")

    # ------------------------------------------------------------------ #
    def _lookup(self, indicator: str, itype: IndicatorType) -> IntelVerdict:
        endpoint = _ENDPOINTS.get(itype)
        if endpoint is None:
            return self.error_verdict(indicator, itype, f"不支持 {itype.value}")

        path, param = endpoint
        status, payload, err = request_json(
            f"{self.base_url}/{path}",
            params={"apikey": self.api_key, param: indicator},
            timeout=self.timeout,
        )
        if err:
            return self.error_verdict(indicator, itype, err)
        if not isinstance(payload, dict):
            return self.error_verdict(indicator, itype, "响应格式异常")

        code = payload.get("response_code")
        if code != 0:
            return self.error_verdict(
                indicator, itype,
                f"API 返回错误 (code={code}): {payload.get('verbose_msg', '')}")

        data = (payload.get("data") or {})
        entry = data.get(indicator) or (next(iter(data.values()), {}) if data else {})
        if not isinstance(entry, dict):
            return self.error_verdict(indicator, itype, "响应 data 结构异常")

        if itype == IndicatorType.HASH:
            return self._parse_file(indicator, itype, entry, payload)
        return self._parse_scene(indicator, itype, entry, payload)

    # ------------------------------------------------------------------ #
    def _parse_scene(self, indicator: str, itype: IndicatorType,
                     entry: Dict[str, Any], payload: Dict[str, Any]) -> IntelVerdict:
        malicious = bool(entry.get("is_malicious"))
        severity_raw = str(entry.get("severity", "info")).lower()
        confidence = _CONF_MAP.get(str(entry.get("confidence_level", "")).lower(), 0.75)

        judgments: List[str] = [str(j) for j in entry.get("judgments", []) if j]
        tags = list(judgments)

        # tags_classes: [{tags_type, tags:[{tag, confidence}]}]
        for cls in entry.get("tags_classes", []) or []:
            if not isinstance(cls, dict):
                continue
            if cls.get("tags_type"):
                tags.append(str(cls["tags_type"]))
            for t in cls.get("tags", []) or []:
                if isinstance(t, dict) and t.get("tag"):
                    tags.append(str(t["tag"]))

        score = {"high": 95.0, "medium": 70.0, "low": 45.0}.get(severity_raw, 0.0)
        if not malicious:
            score = min(score, 20.0)

        desc_bits = [f"微步判定: {'恶意' if malicious else '未发现恶意'}"
                     f" (severity={severity_raw or 'info'})"]
        if judgments:
            desc_bits.append("标签: " + ", ".join(judgments[:6]))
        basic = entry.get("basic") or {}
        if isinstance(basic, dict):
            loc = basic.get("location") or {}
            if isinstance(loc, dict) and loc.get("country"):
                desc_bits.append(f"归属: {loc.get('country')}"
                                 + (f"/{loc.get('province')}" if loc.get("province") else ""))
            if basic.get("carrier"):
                desc_bits.append(f"运营商: {basic['carrier']}")

        return self.verdict(
            indicator, itype,
            malicious=malicious,
            score=score,
            severity=_SEVERITY_MAP.get(severity_raw, Severity.INFO) if malicious
            else Severity.INFO,
            confidence=confidence,
            tags=sorted(set(tags)),
            description="; ".join(desc_bits),
            raw=entry,
        )

    def _parse_file(self, indicator: str, itype: IndicatorType,
                    entry: Dict[str, Any], payload: Dict[str, Any]) -> IntelVerdict:
        threat_level = str(entry.get("threat_level", "")).lower()
        malicious = threat_level in ("malicious", "suspicious")
        severity_raw = {"malicious": "high", "suspicious": "medium"}.get(threat_level, "info")

        families: List[str] = []
        for fam in entry.get("family", []) or []:
            if isinstance(fam, dict) and fam.get("family"):
                families.append(str(fam["family"]))
            elif isinstance(fam, str):
                families.append(fam)

        score = {"high": 95.0, "medium": 65.0}.get(severity_raw, 0.0)
        return self.verdict(
            indicator, itype,
            malicious=malicious, score=score,
            severity=_SEVERITY_MAP.get(severity_raw, Severity.INFO) if malicious
            else Severity.INFO,
            confidence=0.9 if malicious else 0.6,
            tags=["threatbook", f"file-{threat_level}"] + families,
            description=f"微步文件报告: threat_level={threat_level or 'unknown'}"
                        + (f", 家族: {', '.join(families)}" if families else ""),
            raw=entry,
        )


__all__ = ["ThreatBookProvider"]
