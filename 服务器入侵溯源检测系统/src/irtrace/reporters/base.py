"""报告器公共基类。"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from irtrace.core.models import Finding
from irtrace.core.plugin import Reporter


class BaseReporter(Reporter):
    """报告器基类。"""

    def out_path(self, ctx, filename: str) -> Path:
        p = Path(ctx.report_dir) / filename
        p.parent.mkdir(parents=True, exist_ok=True)
        return p

    @staticmethod
    def sorted_findings(ctx) -> List[Finding]:
        """按严重级别降序, 同级按置信度降序排列。"""
        conf_rank = {"high": 3, "medium": 2, "low": 1}
        return sorted(
            ctx.findings,
            key=lambda f: (f.severity.weight, conf_rank.get(f.confidence.value, 0)),
            reverse=True,
        )

    @staticmethod
    def severity_counts(ctx) -> Dict[str, int]:
        counts = {s: 0 for s in ("critical", "high", "medium", "low", "info")}
        for f in ctx.findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return counts

    @staticmethod
    def risk_level(ctx) -> str:
        counts = BaseReporter.severity_counts(ctx)
        if counts["critical"]:
            return "严重 (CRITICAL)"
        if counts["high"]:
            return "高危 (HIGH)"
        if counts["medium"]:
            return "中危 (MEDIUM)"
        if counts["low"]:
            return "低危 (LOW)"
        return "未见明显异常 (INFO)"


__all__ = ["BaseReporter"]
