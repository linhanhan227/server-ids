"""分析器公共基类。"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from irtrace.core.models import (
    Category,
    Confidence,
    Event,
    Finding,
    Severity,
)
from irtrace.core.plugin import Analyzer


class BaseAnalyzer(Analyzer):
    """分析器基类。"""

    #: 分析器读取的规则文件 (相对工程 data/rules/)
    rules_file: Optional[str] = None

    def preflight(self, ctx) -> Optional[str]:  # type: ignore[override]
        reason = super().preflight(ctx)
        if reason:
            return reason
        if not ctx.events and not ctx.evidence:
            return "无事件与证据可分析"
        return None

    # -- 辅助 -------------------------------------------------------------- #
    def load_rules(self, ctx) -> Dict[str, Any]:
        if not self.rules_file:
            return {}
        path = Path(ctx.workspace) / "data" / "rules" / self.rules_file
        if not path.exists():
            ctx.warn(f"[analyzer:{self.name}] 规则文件缺失: {path}")
            return {}
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            ctx.warn(f"[analyzer:{self.name}] 规则文件解析失败: {exc}")
            return {}

    def finding(
        self,
        *,
        title: str,
        severity: Severity,
        description: str = "",
        confidence: Confidence = Confidence.MEDIUM,
        category: Category = Category.OTHER,
        mitre: Optional[List[str]] = None,
        events: Optional[List[Event]] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> Finding:
        evs = events or []
        return Finding(
            title=title,
            severity=severity,
            analyzer=self.name,
            description=description,
            confidence=confidence,
            category=category,
            mitre=mitre or [],
            event_ids=[e.event_id for e in evs],
            details=details or {},
        )

    @staticmethod
    def events_by_tag(ctx, *tags: str) -> List[Event]:
        wanted = set(tags)
        return [e for e in ctx.events if wanted & set(e.tags)]


__all__ = ["BaseAnalyzer"]
