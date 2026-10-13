"""情报数据模型。"""

from __future__ import annotations

import dataclasses
import enum
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from irtrace.core.models import Severity


class IndicatorType(str, enum.Enum):
    """可查询的指标类型。"""

    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"
    EMAIL = "email"

    @property
    def label(self) -> str:
        return {"ip": "IP", "domain": "域名", "url": "URL",
                "hash": "文件哈希", "email": "邮箱"}[self.value]


@dataclass
class IntelVerdict:
    """单一情报平台对某个指标的判定结果。"""

    indicator: str
    indicator_type: IndicatorType
    provider: str
    malicious: bool = False
    #: 恶意评分 0~100
    score: float = 0.0
    #: 该判定的置信度 0~1 (平台可靠度 × 命中强度)
    confidence: float = 0.5
    severity: Severity = Severity.INFO
    tags: List[str] = field(default_factory=list)
    description: str = ""
    #: 平台原始响应 (落盘为证据)
    raw: Dict[str, Any] = field(default_factory=dict)
    queried_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    cached: bool = False
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error is None

    def to_dict(self) -> Dict[str, Any]:
        d = dataclasses.asdict(self)
        d["indicator_type"] = self.indicator_type.value
        d["severity"] = self.severity.value
        d["queried_at"] = self.queried_at.isoformat()
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, default=str)


@dataclass
class IntelReport:
    """多源聚合后的指标结论。"""

    indicator: str
    indicator_type: IndicatorType
    verdicts: List[IntelVerdict] = field(default_factory=list)

    # -- 聚合视图 ---------------------------------------------------------- #
    @property
    def valid_verdicts(self) -> List[IntelVerdict]:
        return [v for v in self.verdicts if v.ok]

    @property
    def errors(self) -> List[IntelVerdict]:
        return [v for v in self.verdicts if not v.ok]

    @property
    def sources(self) -> List[str]:
        return sorted({v.provider for v in self.valid_verdicts})

    @property
    def malicious_sources(self) -> List[str]:
        return sorted({v.provider for v in self.valid_verdicts if v.malicious})

    @property
    def is_malicious(self) -> bool:
        return bool(self.malicious_sources)

    @property
    def score(self) -> float:
        """加权综合评分 (0~100): 各平台 score × confidence 的置信加权均值。"""
        vals = [v for v in self.valid_verdicts if v.score > 0 or v.malicious]
        if not vals:
            return 0.0
        num = sum(v.score * v.confidence for v in vals)
        den = sum(v.confidence for v in vals) or 1.0
        return round(num / den, 1)

    @property
    def severity(self) -> Severity:
        """按最高危的判定定级。"""
        if not self.is_malicious:
            return Severity.INFO
        ranks = {Severity.CRITICAL: 5, Severity.HIGH: 4, Severity.MEDIUM: 3,
                 Severity.LOW: 2, Severity.INFO: 1}
        worst = max(self.valid_verdicts, key=lambda v: ranks.get(v.severity, 0))
        return worst.severity

    @property
    def tags(self) -> List[str]:
        out: List[str] = []
        for v in self.valid_verdicts:
            for t in v.tags:
                if t not in out:
                    out.append(t)
        return out

    @property
    def confidence(self) -> float:
        """聚合置信度: 命中平台越多、权重越高, 置信度越高 (上限 0.99)。"""
        if not self.is_malicious:
            return 0.0
        hits = self.valid_verdicts
        conf = sum(v.confidence for v in hits if v.malicious)
        return round(min(0.99, conf / max(1, len(hits)) + 0.1 * (len(hits) - 1)), 2)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "indicator": self.indicator,
            "indicator_type": self.indicator_type.value,
            "is_malicious": self.is_malicious,
            "score": self.score,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "sources": self.sources,
            "malicious_sources": self.malicious_sources,
            "tags": self.tags,
            "verdicts": [v.to_dict() for v in self.verdicts],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2, default=str)


__all__ = ["IndicatorType", "IntelVerdict", "IntelReport"]
