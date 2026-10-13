"""IOC 分析器。

职责:
1. 从全量事件中提取 IOC: 外联 IP、域名、URL、文件哈希。
2. 调用威胁情报聚合器 (微步 / VT / AbuseIPDB / OTX / MISP / 本地源) 判定恶意性。
3. 汇总"外联画像"—— 每个远程 IP 的关联事件、首次/末次出现、进程。
4. 落盘 IOC 清单与情报原始响应 (证据链完整)。

检测只查本地规则、CSV 与手动拉取落地的本地威胁库，不请求在线情报。
"""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, List, Set

from irtrace.analyzers.base import BaseAnalyzer
from irtrace.core.models import Category, Confidence, Event, Finding, Severity
from irtrace.core.registry import register
from irtrace.intel import IndicatorType, IntelAggregator
from irtrace.utils.textutil import (
    extract_domains,
    extract_hashes,
    extract_ips,
    extract_urls,
    is_private_ip,
)


@register
class IOCAnalyzer(BaseAnalyzer):
    name = "ioc"
    description = "提取 IOC 并调用威胁情报平台判定, 生成外联画像"
    rules_file = "ioc_rules.json"

    #: 单轮分析最多查询的指标数 (防止超长日志导致 API 配额爆炸)
    max_indicators = 200

    def analyze(self, ctx) -> List[Finding]:
        findings: List[Finding] = []

        # 1) 提取指标
        all_ips: Set[str] = set()
        all_domains: Set[str] = set()
        all_hashes: Set[str] = set()
        all_urls: Set[str] = set()
        external_map: Dict[str, List[Event]] = defaultdict(list)
        indicator_events: Dict[tuple, List[Event]] = defaultdict(list)

        for e in ctx.events:
            blob = " ".join([e.message, e.path or "", str(e.raw)])
            ips = set(extract_ips(blob))
            domains = set(extract_domains(blob))
            hashes = set(extract_hashes(blob))
            urls = set(extract_urls(blob))

            all_ips |= ips
            all_domains |= domains
            all_hashes |= hashes
            all_urls |= urls

            for ip in ips:
                indicator_events[(ip, IndicatorType.IP)].append(e)
                if not is_private_ip(ip):
                    external_map[ip].append(e)
            for d in domains:
                indicator_events[(d, IndicatorType.DOMAIN)].append(e)
            for h in hashes:
                indicator_events[(h, IndicatorType.HASH)].append(e)

        # 2) 查询威胁情报
        aggregator = IntelAggregator.from_config(ctx.config.get("intel", {}), ctx=ctx)

        targets = sorted(indicator_events.items(),
                         key=lambda kv: -len(kv[1]))[: self.max_indicators]
        findings += self._query_and_judge(ctx, aggregator, targets, indicator_events)
        # 查询完成后快照统计 (含实际查询次数与缓存命中)
        ctx.stats["intel_providers"] = aggregator.describe()

        # 3) 可疑外联 (基于事件标签, 不依赖情报)
        findings += self._risky_external(ctx, external_map)

        # 4) 落盘
        self._dump_iocs(ctx, all_ips, all_domains, all_hashes, all_urls,
                        external_map, aggregator)
        ctx.stats["ioc"] = {
            "ips": len(all_ips), "domains": len(all_domains),
            "hashes": len(all_hashes), "urls": len(all_urls),
            "external_peers": len(external_map),
            "queries": aggregator.queries,
            "cache_hits": aggregator.cache_hits,
        }
        return findings

    # ------------------------------------------------------------------ #
    def _query_and_judge(self, ctx, aggregator: IntelAggregator,
                         targets, indicator_events) -> List[Finding]:
        """对每个指标执行情报查询, 命中即产出结论 (按指标聚合, 避免重复)。"""
        findings: List[Finding] = []
        by_provider_hits: Dict[str, List[dict]] = defaultdict(list)

        for (indicator, itype), _evs in targets:
            report = aggregator.lookup(indicator, itype)
            if not report.is_malicious:
                continue
            evs = indicator_events.get((indicator, itype), [])[:20]
            srcs = report.malicious_sources

            findings.append(self.finding(
                title=f"威胁情报判定恶意 {itype.label}: {indicator}",
                severity=report.severity,
                category=(Category.NETWORK if itype in
                          (IndicatorType.IP, IndicatorType.DOMAIN) else Category.FILE),
                confidence=(Confidence.HIGH if len(srcs) >= 2 else Confidence.MEDIUM),
                mitre=["T1071"] if itype != IndicatorType.HASH else ["T1204"],
                events=evs,
                description=(
                    f"{itype.label} {indicator} 被 {len(srcs)} 个情报源判定为恶意"
                    f" (综合评分 {report.score}/100, 置信度 {report.confidence})。"
                    f"命中来源: {', '.join(srcs)}。"
                    + (f" 标签: {', '.join(report.tags[:8])}。" if report.tags else "")
                ),
                details={
                    "indicator": indicator,
                    "indicator_type": itype.value,
                    "score": report.score,
                    "malicious_sources": srcs,
                    "all_sources": report.sources,
                    "tags": report.tags,
                    "verdicts": [
                        {"provider": v.provider, "malicious": v.malicious,
                         "score": v.score, "severity": v.severity.value,
                         "description": v.description}
                        for v in report.valid_verdicts
                    ],
                    "event_count": len(evs),
                },
            ))

            for src in srcs:
                by_provider_hits[src].append({"indicator": indicator,
                                              "type": itype.value,
                                              "score": report.score})

        if by_provider_hits:
            ctx.stats["intel_hits"] = {k: v for k, v in by_provider_hits.items()}
        return findings

    def _risky_external(self, ctx, external_map) -> List[Finding]:
        """高危事件关联的外部地址 (即使情报无命中也要提示)。"""
        findings: List[Finding] = []
        risky_tags = {"reverse_shell_pattern", "suspicious-process",
                      "known_malware_name", "suspicious-listen"}
        for ip, evs in external_map.items():
            if any(risky_tags & set(e.tags) for e in evs):
                findings.append(self.finding(
                    title=f"高危事件关联的外部地址: {ip}",
                    severity=Severity.HIGH,
                    category=Category.NETWORK,
                    confidence=Confidence.MEDIUM,
                    mitre=["T1071", "T1571"],
                    events=evs[:20],
                    description=f"外部地址 {ip} 出现在 {len(evs)} 条高危事件中, "
                                f"疑似 C2 或数据外传目标。",
                    details={"occurrences": len(evs),
                             "actions": sorted({e.action for e in evs})},
                ))
        return findings

    # ------------------------------------------------------------------ #
    def _dump_iocs(self, ctx, ips, domains, hashes, urls, external_map, aggregator) -> None:
        lines = ["# 提取到的 IOC", "",
                 f"- IP: {len(ips)}　域名: {len(domains)}　URL: {len(urls)}　哈希: {len(hashes)}",
                 f"- 情报查询: {aggregator.queries} 次　缓存命中: {aggregator.cache_hits} 次",
                 f"- 启用情报源: {', '.join(p.name for p in aggregator.providers) or '无'}", ""]

        for title, items in (("IP", ips), ("域名", domains),
                             ("URL", urls), ("哈希", hashes)):
            lines.append(f"## {title} ({len(items)})")
            lines += [f"- `{i}`" for i in sorted(items)] or ["- (无)"]
            lines.append("")

        lines.append(f"## 外联地址画像 ({len(external_map)})")
        for ip, evs in sorted(external_map.items()):
            times = [e.timestamp for e in evs if e.timestamp]
            span = ""
            if times:
                span = (f"　首次 {min(times).strftime('%m-%d %H:%M')} "
                        f"末次 {max(times).strftime('%m-%d %H:%M')}")
            lines.append(f"- `{ip}`: {len(evs)} 次 "
                         f"[{', '.join(sorted({e.action for e in evs}))}]{span}")

        ctx.store_evidence(source=self.name, kind="ioc", name="iocs.md",
                           data="\n".join(lines), note="IOC 汇总与外联画像")


__all__ = ["IOCAnalyzer"]
