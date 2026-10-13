"""公开在线封禁列表。不需要 API Key。

只使用从当前环境实际拉到的三份列表：

- Spamhaus DROP：被列入的网段
- Emerging Threats compromised-ips：失陷主机 IP
- IPsum：多个公开黑名单交叉出现的 IP，附出现次数

拉不到的列表记为错误，不当成「未命中」。命中时保留来源 URL 和原文行，
供 AI 引用。结果缓存 6 小时，避免每次检测都重新下载。
"""

from __future__ import annotations

import ipaddress
import json
import time
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

from irtrace.core.models import Severity
from irtrace.intel.base import ThreatIntelProvider
from irtrace.intel.http import USER_AGENT
from irtrace.intel.models import IndicatorType, IntelVerdict
from irtrace.intel.registry import register_provider

_FEEDS = (
    {
        "name": "spamhaus-drop",
        "url": "https://www.spamhaus.org/drop/drop.txt",
        "kind": "cidr",
    },
    {
        "name": "et-compromised",
        "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "kind": "ip",
    },
    {
        "name": "ipsum",
        "url": "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
        "kind": "scored-ip",
    },
)
_CACHE_TTL = 6 * 3600
_MAX_BYTES = 8 * 1024 * 1024


@register_provider
class PublicFeedProvider(ThreatIntelProvider):
    name = "public_feeds"
    description = "公开封禁列表 (Spamhaus DROP / ET compromised / IPsum)，无需 Key"
    homepage = "https://www.spamhaus.org/drop/"
    supports = (IndicatorType.IP,)
    requires_api_key = False
    offline = False
    weight = 1.0
    min_interval = 0.0

    def _lookup(self, indicator: str, itype: IndicatorType) -> IntelVerdict:
        try:
            ip = ipaddress.ip_address(indicator.strip())
        except ValueError:
            return self.verdict(
                indicator, itype, malicious=False, score=0.0,
                severity=Severity.INFO, confidence=0.2,
                tags=["public-feed"], description="不是可查询的 IP",
            )
        if not isinstance(ip, ipaddress.IPv4Address):
            return self.verdict(
                indicator, itype, malicious=False, score=0.0,
                severity=Severity.INFO, confidence=0.2,
                tags=["public-feed"], description="公开列表仅覆盖 IPv4",
            )

        hits: List[Dict[str, Any]] = []
        errors: List[str] = []
        for feed in _FEEDS:
            try:
                rows = self._rows(feed)
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{feed['name']}: {exc}")
                continue
            hit = _match(ip, rows, feed["kind"])
            if hit:
                hits.append({
                    "feed": feed["name"],
                    "url": feed["url"],
                    "line": hit,
                })

        if errors and not hits and len(errors) == len(_FEEDS):
            return self.error_verdict(indicator, itype, "; ".join(errors))

        if not hits:
            return self.verdict(
                indicator, itype, malicious=False, score=0.0,
                severity=Severity.INFO, confidence=0.4,
                tags=["public-feed"],
                description="三份公开列表均未收录" + (f"；拉取失败 {errors}" if errors else ""),
                raw={"errors": errors},
            )

        score = min(95.0, 55.0 + 15.0 * (len(hits) - 1))
        return self.verdict(
            indicator, itype, malicious=True, score=score,
            severity=Severity.HIGH, confidence=min(0.9, 0.55 + 0.15 * len(hits)),
            tags=["public-feed", *[item["feed"] for item in hits]],
            description="；".join(f"{item['feed']} 收录" for item in hits),
            raw={"hits": hits, "errors": errors},
        )

    def _rows(self, feed: Dict[str, str]) -> List[str]:
        cache = self._cache_path(feed["name"])
        if cache and cache.exists() and time.time() - cache.stat().st_mtime < _CACHE_TTL:
            return cache.read_text(encoding="utf-8", errors="replace").splitlines()
        req = urllib.request.Request(feed["url"], headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310
            text = resp.read(_MAX_BYTES).decode("utf-8", "replace")
        if cache:
            cache.parent.mkdir(parents=True, exist_ok=True)
            cache.write_text(text, encoding="utf-8")
        return text.splitlines()

    def export_indicators(self) -> tuple:
        """整份下载三份列表，返回 (指标行, 错误)。只在手动拉取时调用。"""
        rows: List[Dict[str, Any]] = []
        errors: List[str] = []
        for feed in _FEEDS:
            try:
                lines = self._rows(feed)
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{feed['name']}: {exc}")
                continue
            for raw in lines:
                line = raw.split(";", 1)[0].strip()
                if not line or line.startswith("#"):
                    continue
                token = line.split()[0]
                if "/" in token:
                    continue
                try:
                    ipaddress.ip_address(token)
                except ValueError:
                    continue
                rows.append({
                    "indicator": token,
                    "indicator_type": IndicatorType.IP.value,
                    "provider": self.name,
                    "malicious": True,
                    "score": 70.0,
                    "confidence": 0.7,
                    "severity": Severity.HIGH.value,
                    "tags": ["public-feed", feed["name"]],
                    "description": f"{feed['name']} 收录",
                    "raw": {"feed": feed["name"], "url": feed["url"], "line": raw.strip()[:180]},
                })
        return rows, errors

    def _cache_path(self, name: str) -> Optional[Path]:
        workspace = self.config.get("workspace")
        if not workspace:
            return None
        return Path(workspace) / "data" / "intel-cache" / f"public-{name}.txt"


def _match(ip: ipaddress.IPv4Address, rows: List[str], kind: str) -> str:
    for raw in rows:
        line = raw.split(";", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        try:
            if kind == "cidr" and "/" in line:
                if ip in ipaddress.ip_network(line, strict=False):
                    return raw.strip()[:180]
            elif kind == "ip" and line == str(ip):
                return raw.strip()[:180]
            elif kind == "scored-ip":
                token = line.split()[0]
                if token == str(ip):
                    return raw.strip()[:180]
        except ValueError:
            continue
    return ""


__all__ = ["PublicFeedProvider"]
