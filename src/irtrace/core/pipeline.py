"""编排引擎。

流程::

    prepare()  -> 发现插件 + 过滤 (enable_only / disable) + preflight
    collect()  -> 顺序执行采集器, 聚合 Event / Evidence
    analyze()  -> 顺序执行分析器, 聚合 Finding
    report()   -> 执行报告生成器

每个阶段独立容错: 单个插件抛异常只记录告警, 不中断整轮分析。
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional, Sequence

from irtrace.core.context import RunContext
from irtrace.core.plugin import Analyzer, Collector, CollectResult, Reporter
from irtrace.core.registry import registry

logger = logging.getLogger("irtrace")


class Orchestrator:
    """分析流水线编排器。"""

    def __init__(self, ctx: RunContext) -> None:
        self.ctx = ctx
        self.timings: Dict[str, float] = {}

    # ------------------------------------------------------------------ #
    def _select(self, kind: str, enable_only: Sequence[str], disable: Sequence[str]):
        plugins = registry.by_kind(kind)
        if enable_only:
            plugins = [p for p in plugins if p.name in enable_only]
        if disable:
            plugins = [p for p in plugins if p.name not in disable]
        plugins = [p for p in plugins if p.enabled_by_default or p.name in enable_only]
        return plugins

    # ------------------------------------------------------------------ #
    def collect(self) -> CollectResult:
        cfg = self.ctx.config.get("collectors", {})
        plugins = self._select("collector", cfg.get("enable_only", []), cfg.get("disable", []))
        agg = CollectResult()

        for plugin in plugins:
            assert isinstance(plugin, Collector)
            reason = plugin.preflight(self.ctx)
            if reason:
                self.ctx.warn(f"[collector:{plugin.name}] 跳过 — {reason}")
                continue
            start = time.perf_counter()
            try:
                result = plugin.collect(self.ctx) or CollectResult()
            except Exception as exc:  # noqa: BLE001
                self.ctx.warn(f"[collector:{plugin.name}] 采集失败: {exc}")
                logger.exception("采集器异常: %s", plugin.name)
                continue
            finally:
                self.timings[f"collect.{plugin.name}"] = round(time.perf_counter() - start, 3)

            agg.extend(result)
            self.ctx.add_events(result.events)
            self.ctx.evidence.extend(
                [e for e in result.evidence if e not in self.ctx.evidence]
            )
            logger.info("采集器 %-18s 事件=%-5d 证据=%-5d",
                        plugin.name, len(result.events), len(result.evidence))

        self.ctx.stats["collect"] = {
            "plugins": [p.name for p in plugins],
            "events": len(agg.events),
            "evidence": len(agg.evidence),
        }
        return agg

    # ------------------------------------------------------------------ #
    def analyze(self) -> int:
        cfg = self.ctx.config.get("analyzers", {})
        plugins = self._select("analyzer", cfg.get("enable_only", []), cfg.get("disable", []))
        total = 0

        for plugin in plugins:
            assert isinstance(plugin, Analyzer)
            reason = plugin.preflight(self.ctx)
            if reason:
                self.ctx.warn(f"[analyzer:{plugin.name}] 跳过 — {reason}")
                continue
            start = time.perf_counter()
            try:
                findings = plugin.analyze(self.ctx) or []
            except Exception as exc:  # noqa: BLE001
                self.ctx.warn(f"[analyzer:{plugin.name}] 分析失败: {exc}")
                logger.exception("分析器异常: %s", plugin.name)
                continue
            finally:
                self.timings[f"analyze.{plugin.name}"] = round(time.perf_counter() - start, 3)

            for f in findings:
                self.ctx.add_finding(f)
            total += len(findings)
            logger.info("分析器 %-18s 结论=%d", plugin.name, len(findings))

        self.ctx.stats["analyze"] = {"findings": total}
        return total

    # ------------------------------------------------------------------ #
    def report(self, formats: Optional[Sequence[str]] = None) -> List[str]:
        cfg = self.ctx.config.get("reporters", {})
        wanted = set(formats or cfg.get("formats", ["json"]))
        disable = set(cfg.get("disable", []))
        outputs: List[str] = []

        for plugin in registry.by_kind("reporter"):
            assert isinstance(plugin, Reporter)
            if plugin.name in disable:
                continue
            if wanted and plugin.name not in wanted and plugin.extension not in wanted:
                continue
            reason = plugin.preflight(self.ctx)
            if reason:
                self.ctx.warn(f"[reporter:{plugin.name}] 跳过 — {reason}")
                continue
            start = time.perf_counter()
            try:
                out = plugin.render(self.ctx)
            except Exception as exc:  # noqa: BLE001
                self.ctx.warn(f"[reporter:{plugin.name}] 报告生成失败: {exc}")
                logger.exception("报告器异常: %s", plugin.name)
                continue
            finally:
                self.timings[f"report.{plugin.name}"] = round(time.perf_counter() - start, 3)
            if out:
                outputs.append(str(out))
                logger.info("报告器 %-18s -> %s", plugin.name, out)

        self.ctx.stats["report"] = {"outputs": outputs}
        return outputs

    # ------------------------------------------------------------------ #
    def run(
        self,
        *,
        skip_collect: bool = False,
        skip_analyze: bool = False,
        formats: Optional[Sequence[str]] = None,
    ) -> Dict[str, Any]:
        """完整跑一遍流水线。"""
        if not skip_collect:
            self.collect()
        if not skip_analyze:
            self.analyze()
        outputs = self.report(formats)
        self.ctx.stats["timings"] = self.timings
        return {"outputs": outputs, "summary": self.ctx.summary()}


__all__ = ["Orchestrator"]
