"""时间线分析器。

职责:
1. 把全量事件按时间排序, 输出统一时间线文件 (timeline.json / timeline.txt)。
2. 识别"攻击窗口"—— 短时间内事件密度显著高于基线的时段。
3. 输出首末事件、跨度、时间来源分布等溯源元信息。
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

from irtrace.analyzers.base import BaseAnalyzer
from irtrace.core.models import Category, Confidence, Event, Finding, Severity
from irtrace.core.registry import register
from irtrace.utils.timeutil import fmt_local

#: 窗口大小 (分钟) 与 触发阈值 (事件数)
WINDOW_MINUTES = 5
CLUSTER_THRESHOLD = 8


@register
class TimelineAnalyzer(BaseAnalyzer):
    name = "timeline"
    description = "构建统一时间轴, 识别事件密度异常的攻击窗口"

    def analyze(self, ctx) -> List[Finding]:
        findings: List[Finding] = []
        events = [e for e in ctx.events if e.timestamp is not None]
        if not events:
            return findings

        events.sort(key=lambda e: e.sort_key)
        self._dump_timeline(ctx, events)
        findings.extend(self._detect_clusters(ctx, events))
        return findings

    # ------------------------------------------------------------------ #
    def _dump_timeline(self, ctx, events: List[Event]) -> None:
        lines = [
            "时间(UTC)\t类别\t来源\t动作\t主体\t详情",
            "-" * 100,
        ]
        for e in events:
            lines.append(
                f"{e.timestamp.strftime('%Y-%m-%d %H:%M:%S')}\t{e.category.value}\t"
                f"{e.source}\t{e.action}\t{e.user or e.path or '-'}\t{e.message[:200]}"
            )
        body = "\n".join(lines)
        ctx.store_evidence(source=self.name, kind="timeline",
                           name="timeline.txt", data=body, note="统一时间轴")

        ctx.stats["timeline"] = {
            "total_events": len(events),
            "first": events[0].timestamp.isoformat(),
            "last": events[-1].timestamp.isoformat(),
            "span_hours": round(
                (events[-1].timestamp - events[0].timestamp).total_seconds() / 3600, 2),
            "by_source": dict(Counter(e.source for e in events)),
            "by_category": dict(Counter(e.category.value for e in events)),
        }

    def _detect_clusters(self, ctx, events: List[Event]) -> List[Finding]:
        """滑动窗口统计事件密度, 找出显著聚集的时段。"""
        findings: List[Finding] = []
        window = timedelta(minutes=WINDOW_MINUTES)

        buckets: Dict[datetime, List[Event]] = defaultdict(list)
        for e in events:
            key = e.timestamp.replace(second=0, microsecond=0) - timedelta(
                minutes=e.timestamp.minute % WINDOW_MINUTES)
            buckets[key].append(e)

        # 只保留含"高关注度"事件的窗口
        interesting = {"auth-failure", "bruteforce", "privilege-escalation",
                       "backdoor-account", "suspicious-process", "reverse_shell_pattern",
                       "suspicious-persistence", "rootkit"}

        for start, evs in sorted(buckets.items()):
            if len(evs) < CLUSTER_THRESHOLD:
                continue
            hot = [e for e in evs if interesting & set(e.tags)]
            if not hot:
                continue
            sev = Severity.HIGH if any(
                {"backdoor-account", "reverse_shell_pattern", "rootkit"} & set(e.tags)
                for e in hot) else Severity.MEDIUM
            findings.append(self.finding(
                title=f"事件聚集窗口 {fmt_local(start, '%m-%d %H:%M')} "
                      f"(UTC+8) 共 {len(evs)} 事件",
                severity=sev,
                category=Category.OTHER,
                confidence=Confidence.MEDIUM,
                description=(
                    f"该 {WINDOW_MINUTES} 分钟窗口内事件密度异常 ({len(evs)} 条, "
                    f"其中高关注事件 {len(hot)} 条), 可能对应攻击时间窗。"
                ),
                events=hot[:20],
                details={
                    "window_start": start.isoformat(),
                    "total": len(evs),
                    "hot_events": len(hot),
                    "actions": dict(Counter(e.action for e in hot)),
                },
            ))
        return findings


__all__ = ["TimelineAnalyzer"]
