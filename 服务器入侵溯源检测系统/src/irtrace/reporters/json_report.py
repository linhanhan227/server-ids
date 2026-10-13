"""JSON 报告器: 输出结构化全量结果, 便于 SIEM / 自动化消费。"""

from __future__ import annotations

import json

from irtrace.core.registry import register
from irtrace.reporters.base import BaseReporter


@register
class JsonReporter(BaseReporter):
    name = "json"
    description = "结构化 JSON 报告 (事件/证据/结论/统计全量导出)"
    extension = "json"

    def render(self, ctx):
        payload = {
            "meta": {
                "tool": "irtrace",
                "run_id": ctx.run_id,
                "host": ctx.hostname,
                "operator": ctx.operator,
                "is_linux": ctx.is_linux,
                "generated_at": ctx.summary()["generated_at"],
                "risk_level": self.risk_level(ctx),
                "severity_counts": self.severity_counts(ctx),
            },
            "summary": ctx.summary(),
            "stats": ctx.stats,
            "warnings": ctx.warnings,
            "findings": [f.to_dict() for f in self.sorted_findings(ctx)],
            "events": [e.to_dict() for e in sorted(ctx.events, key=lambda x: x.sort_key)],
            "evidence": [e.to_dict() for e in ctx.evidence],
        }
        path = self.out_path(ctx, "result.json")
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, default=str),
                        encoding="utf-8")
        return path


__all__ = ["JsonReporter"]
