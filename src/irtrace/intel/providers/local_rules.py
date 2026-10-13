"""本地规则库情报源 (离线)。

读取 ``data/rules/ioc_rules.json``, 与内置规则库保持一致。
这是默认启用的离线源, 保证取证现场无网络时仍有情报能力。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from irtrace.core.models import Severity
from irtrace.intel.base import ThreatIntelProvider
from irtrace.intel.models import IndicatorType, IntelVerdict
from irtrace.intel.registry import register_provider


@register_provider
class LocalRulesProvider(ThreatIntelProvider):
    name = "local_rules"
    description = "本地 IOC 规则库 (data/rules/ioc_rules.json)"
    homepage = ""
    supports = (IndicatorType.IP, IndicatorType.DOMAIN,
                IndicatorType.HASH, IndicatorType.URL)
    requires_api_key = False
    offline = True
    weight = 1.0
    min_interval = 0.0

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(config)
        self._cache: Optional[Dict[str, Set[str]]] = None

    # ------------------------------------------------------------------ #
    @property
    def rules_path(self) -> Path:
        if self.config.get("rules_path"):
            return Path(self.config["rules_path"])
        ws = self.config.get("workspace")
        if ws:
            return Path(ws) / "data" / "rules" / "ioc_rules.json"
        return Path.cwd() / "data" / "rules" / "ioc_rules.json"

    def _rules(self) -> Dict[str, Set[str]]:
        if self._cache is not None:
            return self._cache
        data: Dict[str, Any] = {}
        try:
            data = json.loads(self.rules_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            data = {}
        self._cache = {
            "ip": {str(x).strip() for x in data.get("malicious_ips", []) if x},
            "domain": {str(x).strip().lower() for x in data.get("malicious_domains", []) if x},
            "hash": {str(x).strip().lower() for x in data.get("malicious_hashes", []) if x},
            "keyword": {str(x).strip().lower() for x in data.get("suspicious_keywords", []) if x},
            "port": {int(p) for p in data.get("suspicious_ports", []) if str(p).isdigit()},
        }
        return self._cache

    # ------------------------------------------------------------------ #
    def _lookup(self, indicator: str, itype: IndicatorType) -> IntelVerdict:
        rules = self._rules()
        probe = indicator.strip().lower()
        bucket = rules.get(itype.value, set())

        if probe in bucket:
            return self.verdict(
                indicator, itype, malicious=True, score=90.0,
                severity=Severity.CRITICAL, confidence=0.9,
                tags=["local-rule", f"ioc-{itype.value}"],
                description=f"命中本地规则库 ({self.rules_path.name})",
                raw={"source": str(self.rules_path), "bucket": itype.value},
            )

        # 关键词型匹配 (用于 URL / 哈希前缀等)
        hits = [k for k in rules.get("keyword", set()) if k and k in probe]
        if hits:
            return self.verdict(
                indicator, itype, malicious=True, score=60.0,
                severity=Severity.MEDIUM, confidence=0.6,
                tags=["local-rule", "keyword-match"] + hits,
                description=f"命中本地关键词规则: {', '.join(hits)}",
                raw={"keywords": hits},
            )

        # IP 指标额外看目标端口 (规则库 suspicious_ports)
        if itype == IndicatorType.IP:
            port_hit = self._port_hit(indicator, rules.get("port", set()))
            if port_hit is not None:
                return self.verdict(
                    indicator, itype, malicious=True, score=50.0,
                    severity=Severity.MEDIUM, confidence=0.55,
                    tags=["local-rule", "suspicious-port"],
                    description=f"命中本地可疑端口规则: {port_hit}",
                    raw={"port": port_hit},
                )

        return self.verdict(
            indicator, itype, malicious=False, score=0.0,
            severity=Severity.INFO, confidence=0.3,
            tags=["local-rule"], description="本地规则库无命中",
        )

    @staticmethod
    def _port_hit(indicator: str, ports: set) -> Optional[int]:
        """指标形如 ``1.2.3.4:4444`` 或 ``[::1]:1337`` 时取出端口。"""
        text = indicator.strip()
        if text.startswith("["):
            end = text.rfind("]:")
            port_s = text[end + 2:] if end != -1 else ""
        elif text.count(":") == 1:
            port_s = text.rsplit(":", 1)[1]
        else:
            return None
        try:
            port = int(port_s)
        except ValueError:
            return None
        return port if port in ports else None


__all__ = ["LocalRulesProvider"]
