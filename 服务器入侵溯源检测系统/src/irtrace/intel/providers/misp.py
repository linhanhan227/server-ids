"""MISP 情报源 (自建 / 订阅实例)。

通过 MISP 的 ``attributes/restSearch`` 接口查询属性命中情况。
支持机构内部情报共享平台对接。

配置::

    [intel.platforms.misp]
    url = "https://misp.example.com"
    api_key_env = "MISP_API_KEY"
    verify_tls = true
    weight = 1.1
"""

from __future__ import annotations

from typing import Any, Dict, List

from irtrace.core.models import Severity
from irtrace.intel.base import ThreatIntelProvider
from irtrace.intel.http import request_json
from irtrace.intel.models import IndicatorType, IntelVerdict
from irtrace.intel.registry import register_provider

_MISP_TYPES = {
    IndicatorType.IP: ["ip-dst", "ip-src"],
    IndicatorType.DOMAIN: ["domain", "hostname"],
    IndicatorType.HASH: ["sha256", "sha1", "md5"],
    IndicatorType.URL: ["url", "uri"],
}


@register_provider
class MISPProvider(ThreatIntelProvider):
    name = "misp"
    description = "MISP 情报共享平台 (自建 / 订阅实例)"
    homepage = "https://www.misp-project.org/"
    supports = (IndicatorType.IP, IndicatorType.DOMAIN,
                IndicatorType.HASH, IndicatorType.URL)
    requires_api_key = True
    api_key_env = "MISP_API_KEY"
    offline = False
    weight = 1.1
    min_interval = 1.0
    timeout = 15

    @property
    def base_url(self) -> str:
        return str(self.config.get("url", "")).rstrip("/")

    def unavailable_reason(self) -> str | None:
        if not self.base_url:
            return "未配置 [intel.platforms.misp] url"
        return super().unavailable_reason()

    @property
    def available(self) -> bool:
        return bool(self.base_url) and super().available

    # ------------------------------------------------------------------ #
    def _lookup(self, indicator: str, itype: IndicatorType) -> IntelVerdict:
        misp_types = _MISP_TYPES.get(itype)
        if not misp_types:
            return self.error_verdict(indicator, itype, f"不支持 {itype.value}")

        status, payload, err = request_json(
            f"{self.base_url}/attributes/restSearch",
            method="POST",
            headers={"Authorization": self.api_key or "",
                     "Accept": "application/json"},
            json_body={"returnFormat": "json", "value": indicator,
                       "type": misp_types, "limit": 30,
                       "includeEventTags": True},
            timeout=self.timeout,
        )
        if err:
            return self.error_verdict(indicator, itype, err)
        if not isinstance(payload, dict):
            return self.error_verdict(indicator, itype, "响应格式异常")

        attrs: List[Dict[str, Any]] = ((payload.get("response") or {}).get("Attribute")
                                       or [])
        if not attrs:
            return self.verdict(
                indicator, itype, malicious=False, score=0.0,
                severity=Severity.INFO, confidence=0.4,
                tags=["misp"], description="MISP 无命中",
            )

        tags: List[str] = []
        for a in attrs:
            for t in (a.get("Tag") or []):
                if isinstance(t, dict) and t.get("name") and t["name"] not in tags:
                    tags.append(str(t["name"]))
            cat = a.get("category")
            if cat and cat not in tags:
                tags.append(str(cat))

        to_ids = sum(1 for a in attrs if a.get("to_ids"))
        events = {a.get("event_id") for a in attrs if a.get("event_id")}
        score = min(95.0, 40.0 + len(attrs) * 8.0)
        malicious = to_ids >= 1 or len(attrs) >= 2

        return self.verdict(
            indicator, itype,
            malicious=malicious,
            score=score if malicious else 20.0,
            severity=self.severity_from_score(score) if malicious else Severity.LOW,
            confidence=0.9 if to_ids else 0.7,
            tags=sorted(set(tags + ["misp"])),
            description=(f"MISP: 命中 {len(attrs)} 条属性 "
                         f"(关联 {len(events)} 个事件, IDS 标记 {to_ids} 条)"),
            raw={"attributes": [{k: a.get(k) for k in
                                 ("id", "event_id", "type", "value", "category",
                                  "to_ids", "comment")} for a in attrs[:20]]},
        )


__all__ = ["MISPProvider"]
