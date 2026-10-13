"""Markdown 报告器: 生成人类可读的溯源分析报告。"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone

from irtrace.core.registry import register
from irtrace.reporters.base import BaseReporter
from irtrace.utils.timeutil import fmt_local

_SEV_ICON = {
    "critical": "[严重]", "high": "[高危]", "medium": "[中危]",
    "low": "[低危]", "info": "[信息]",
}


@register
class MarkdownReporter(BaseReporter):
    name = "markdown"
    description = "Markdown 溯源报告"
    extension = "md"

    def render(self, ctx):
        s = ctx.summary()
        counts = self.severity_counts(ctx)
        L: list[str] = []

        L.append("# Linux 服务器入侵溯源报告\n")
        L.append(f"> 生成时间: {fmt_local(datetime.now(timezone.utc), '%Y-%m-%d %H:%M:%S %Z')}")
        L.append(f"> 分析主机: `{s['host']}`　|　执行人: `{s['operator']}`")
        L.append(f"> 运行 ID: `{s['run_id']}`　|　结论级别: **{self.risk_level(ctx)}**\n")

        # 摘要
        L.append("## 一、结论摘要\n")
        L.append("| 严重级别 | 数量 |")
        L.append("| --- | ---: |")
        for sev in ("critical", "high", "medium", "low", "info"):
            L.append(f"| {_SEV_ICON[sev]} {sev} | {counts[sev]} |")
        L.append("")
        L.append(f"- 归一化事件总数: **{s['events']}**")
        L.append(f"- 采集证据条目: **{s['evidence']}**")
        L.append(f"- 分析结论总数: **{s['findings']}**")
        L.append(f"- 采集告警: {s['warnings']}\n")

        # 结论明细
        L.append("## 二、发现项明细\n")
        findings = self.sorted_findings(ctx)
        if not findings:
            L.append("_未发现明显异常。_\n")
        for i, f in enumerate(findings, 1):
            L.append(f"### {i}. {_SEV_ICON[f.severity.value]} {f.title}\n")
            L.append(f"- **严重级别**: `{f.severity.value}`　"
                     f"**置信度**: `{f.confidence.value}`　"
                     f"**分类**: `{f.category.value}`")
            L.append(f"- **检出分析器**: `{f.analyzer}`")
            if f.mitre:
                L.append(f"- **ATT&CK**: {', '.join(f'`{m}`' for m in f.mitre)}")
            if f.description:
                L.append(f"\n{f.description}\n")
            if f.details:
                L.append("```json")
                import json
                L.append(json.dumps(f.details, ensure_ascii=False, indent=2, default=str))
                L.append("```\n")
            L.append("")

        # 威胁情报
        L.append("## 三、威胁情报命中\n")
        intel = ctx.stats.get("intel_providers") or {}
        providers = intel.get("providers", [])
        if providers:
            L.append("| 情报平台 | 类型 | 状态 | 权重 |")
            L.append("| --- | --- | --- | ---: |")
            for p in providers:
                kind = "离线" if p.get("offline") else "在线"
                status = "可用" if p.get("available") else f"不可用 ({p.get('reason') or '-'})"
                L.append(f"| `{p['name']}` | {kind} | {status} | {p.get('weight', 1.0)} |")
            L.append("")
            L.append(f"- 情报查询次数: **{intel.get('queries', 0)}**　"
                     f"缓存命中: **{intel.get('cache_hits', 0)}**")
            L.append("")

        hits = ctx.stats.get("intel_hits") or {}
        if hits:
            L.append("**情报源命中统计**\n")
            for name, items in hits.items():
                inds = ", ".join(f"`{i['indicator']}`" for i in items[:8])
                L.append(f"- `{name}`: {len(items)} 个指标 — {inds}")
            L.append("")
        else:
            L.append("_无情报命中 (或未启用情报源)。_\n")

        # 时间线
        L.append("## 四、关键时间线\n")
        tl = ctx.stats.get("timeline", {})
        if tl:
            L.append(f"- 时间跨度: {tl.get('first', '-')} ~ {tl.get('last', '-')} "
                     f"({tl.get('span_hours', 0)} 小时)")
            L.append(f"- 事件来源分布: {tl.get('by_source', {})}")
            L.append(f"- 事件类别分布: {tl.get('by_category', {})}\n")
        hot = [e for e in sorted(ctx.events, key=lambda x: x.sort_key)
               if e.tags and {"critical", "suspicious-process", "reverse_shell_pattern",
                              "backdoor-account", "rootkit", "bruteforce",
                              "privilege-escalation"} & set(e.tags)]
        if hot:
            L.append("| 时间 (本地) | 类别 | 动作 | 主体 | 描述 |")
            L.append("| --- | --- | --- | --- | --- |")
            for e in hot[:60]:
                L.append(f"| {fmt_local(e.timestamp)} | {e.category.value} | "
                         f"{e.action} | `{e.user or e.path or '-'}` | "
                         f"{e.message[:120].replace('|', '/')} |")
        else:
            L.append("_无高危事件。_")
        L.append("")

        # 证据链
        L.append("## 五、证据清单\n")
        L.append("| # | 来源 | 类型 | 目标 | SHA256 |")
        L.append("| ---: | --- | --- | --- | --- |")
        for i, ev in enumerate(ctx.evidence, 1):
            sha = (ev.sha256 or "-")[:16] + "…" if ev.sha256 else "-"
            L.append(f"| {i} | {ev.source} | {ev.kind} | `{ev.path or ev.content or '-'}` | `{sha}` |")
        L.append("")
        L.append(f"> 证据哈希链账本: `{ctx.run_dir / 'evidence-ledger.jsonl'}` "
                 f"(可用 `irtrace verify` 校验完整性)\n")

        # 处置建议
        L.append("## 六、处置建议\n")
        L.extend(self._recommendations(ctx, counts))
        L.append("")

        if ctx.warnings:
            L.append("## 七、采集告警\n")
            for w in ctx.warnings:
                L.append(f"- {w}")
            L.append("")

        path = self.out_path(ctx, "report.md")
        path.write_text("\n".join(L), encoding="utf-8")
        return path

    # ------------------------------------------------------------------ #
    @staticmethod
    def _recommendations(ctx, counts) -> list[str]:
        tips: list[str] = []
        actions = {e.action for e in ctx.events}
        if counts["critical"] or counts["high"]:
            tips.append("1. **立即隔离**: 对主机进行网络隔离, 阻断已识别的外联 IP, "
                        "避免横向移动与数据外传。")
        if "bruteforce_suspected" in actions or "ssh_failed" in actions:
            tips.append("2. **账号安全**: 强制重置所有可登录账号口令, 部署 fail2ban / "
                        "密钥登录, 关闭口令认证, 限制 SSH 来源 IP。")
        if {"uid0_account", "user_added"} & actions:
            tips.append("3. **后门账号**: 核查并删除 UID=0 的非 root 账号及新增可疑账号。")
        if any(e.category.value == "persistence" for e in ctx.events):
            tips.append("4. **清除持久化**: 逐项核查 cron / systemd / rc.local / "
                        "authorized_keys / ld.so.preload, 删除非授权条目。")
        if {"rootkit_module", "ld_preload", "exe_deleted"} & actions:
            tips.append("5. **深度查杀**: 存在 rootkit/无文件攻击迹象, 建议离线取证, "
                        "使用 rkhunter/chkrootkit 交叉验证, 必要时重装系统。")
        if any(e.action == "external_connection" for e in ctx.events):
            tips.append("6. **流量审计**: 将外联 IP 加入黑名单, 回溯边界设备日志确认入侵入口。")
        if not tips:
            tips.append("未发现需要立即处置的高危项; 建议保持日常日志审计与基线核查。")
        tips.append(f"\n> 完整证据与时间线位于: `{ctx.run_dir}`")
        return tips


__all__ = ["MarkdownReporter"]
