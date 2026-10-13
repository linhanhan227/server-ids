"""HTML 报告器: 生成单文件、离线可看的可视化溯源报告。"""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone

from irtrace.core.registry import register
from irtrace.reporters.base import BaseReporter
from irtrace.utils.timeutil import fmt_local

_SEV_COLOR = {
    "critical": "#c0392b", "high": "#e67e22", "medium": "#d4a017",
    "low": "#2e86c1", "info": "#7f8c8d",
}
_SEV_LABEL = {
    "critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "info": "信息",
}

_TEMPLATE = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>入侵溯源报告 - {host}</title>
<style>
  :root {{
    --bg: #f5f7fa; --card: #ffffff; --text: #1f2933; --muted: #6b7280;
    --border: #e3e8ee; --accent: #2c5f8d;
  }}
  * {{ box-sizing: border-box; }}
  body {{ margin: 0; background: var(--bg); color: var(--text);
    font-family: -apple-system, "Segoe UI", "Microsoft YaHei", Roboto, sans-serif;
    line-height: 1.6; font-size: 14px; }}
  .wrap {{ max-width: 1180px; margin: 0 auto; padding: 28px 20px 60px; }}
  header {{ background: var(--card); border: 1px solid var(--border); border-radius: 10px;
    padding: 24px 28px; margin-bottom: 20px; }}
  h1 {{ margin: 0 0 8px; font-size: 22px; color: var(--accent); }}
  .meta {{ color: var(--muted); font-size: 13px; }}
  .meta code {{ background: #eef2f6; padding: 1px 6px; border-radius: 4px; }}
  .risk {{ display: inline-block; margin-top: 12px; padding: 6px 14px; border-radius: 20px;
    font-weight: 600; color: #fff; font-size: 13px; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 14px; margin-bottom: 20px; }}
  .stat {{ background: var(--card); border: 1px solid var(--border); border-radius: 10px;
    padding: 16px 18px; }}
  .stat .n {{ font-size: 26px; font-weight: 700; }}
  .stat .l {{ color: var(--muted); font-size: 12px; margin-top: 2px; }}
  section {{ background: var(--card); border: 1px solid var(--border); border-radius: 10px;
    padding: 20px 24px; margin-bottom: 20px; }}
  h2 {{ font-size: 16px; margin: 0 0 14px; padding-bottom: 10px;
    border-bottom: 1px solid var(--border); color: var(--accent); }}
  .finding {{ border-left: 4px solid var(--muted); padding: 12px 16px; margin-bottom: 12px;
    background: #fbfcfe; border-radius: 0 6px 6px 0; }}
  .finding .t {{ font-weight: 600; margin-bottom: 4px; }}
  .chip {{ display: inline-block; font-size: 11px; padding: 2px 8px; border-radius: 10px;
    background: #eef2f6; color: var(--muted); margin-right: 6px; }}
  .finding p {{ margin: 6px 0 0; color: #374151; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th, td {{ text-align: left; padding: 7px 10px; border-bottom: 1px solid var(--border);
    vertical-align: top; }}
  th {{ background: #f0f4f8; font-weight: 600; color: #475569; position: sticky; top: 0; }}
  td code {{ background: #eef2f6; padding: 1px 5px; border-radius: 4px; font-size: 12px; }}
  .scroll {{ max-height: 460px; overflow: auto; border: 1px solid var(--border); border-radius: 6px; }}
  .muted {{ color: var(--muted); }}
  ul {{ margin: 6px 0; padding-left: 20px; }}
  .warn {{ background: #fff8e6; border-color: #f0d68a; }}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>Linux 服务器入侵溯源报告</h1>
    <div class="meta">
      主机 <code>{host}</code> ｜ 执行人 <code>{operator}</code> ｜
      运行 ID <code>{run_id}</code><br>
      生成时间 {generated_at}
    </div>
    <div class="risk" style="background:{risk_color}">结论级别：{risk_level}</div>
  </header>

  <div class="grid">
    <div class="stat"><div class="n">{n_events}</div><div class="l">归一化事件</div></div>
    <div class="stat"><div class="n">{n_evidence}</div><div class="l">证据条目</div></div>
    <div class="stat"><div class="n">{n_findings}</div><div class="l">分析结论</div></div>
    <div class="stat"><div class="n" style="color:{critical_color}">{n_critical}</div>
      <div class="l">严重 / 高危</div></div>
  </div>

  <section>
    <h2>一、严重级别分布</h2>
    <table>
      <tr><th>级别</th><th>数量</th><th>占比</th></tr>
      {sev_rows}
    </table>
  </section>

  <section>
    <h2>二、发现项明细</h2>
    {findings_html}
  </section>

  {intel_section}

  <section>
    <h2>四、关键时间线</h2>
    <div class="scroll"><table>
      <tr><th>时间 (本地)</th><th>类别</th><th>动作</th><th>主体</th><th>描述</th></tr>
      {timeline_rows}
    </table></div>
  </section>

  <section>
    <h2>五、证据清单 (SHA256 防篡改)</h2>
    <div class="scroll"><table>
      <tr><th>#</th><th>来源</th><th>类型</th><th>目标</th><th>SHA256</th></tr>
      {evidence_rows}
    </table></div>
  </section>

  <section>
    <h2>六、处置建议</h2>
    {recommendations}
  </section>

  {warnings_section}
</div>
</body>
</html>
"""


@register
class HtmlReporter(BaseReporter):
    name = "html"
    description = "单文件可视化 HTML 报告"
    extension = "html"

    def render(self, ctx):
        s = ctx.summary()
        counts = self.severity_counts(ctx)
        total = max(1, sum(counts.values()))
        risk = self.risk_level(ctx)
        risk_color = _SEV_COLOR["critical"] if counts["critical"] else (
            _SEV_COLOR["high"] if counts["high"] else (
                _SEV_COLOR["medium"] if counts["medium"] else _SEV_COLOR["info"]))

        # 严重级别分布
        sev_rows = []
        for sev in ("critical", "high", "medium", "low", "info"):
            n = counts[sev]
            pct = f"{n / total * 100:.1f}%"
            sev_rows.append(
                f"<tr><td><span class='chip' style='background:{_SEV_COLOR[sev]};"
                f"color:#fff'>{_SEV_LABEL[sev]}</span></td><td>{n}</td><td>{pct}</td></tr>"
            )

        # 发现项
        findings_html = []
        for f in self.sorted_findings(ctx):
            chips = "".join(f"<span class='chip'>{html.escape(m)}</span>" for m in f.mitre)
            desc = html.escape(f.description or "")
            details = ""
            if f.details:
                details = (f"<details><summary class='muted'>查看详情</summary><pre>"
                           f"{html.escape(json.dumps(f.details, ensure_ascii=False, indent=2, default=str))}"
                           f"</pre></details>")
            findings_html.append(
                f"<div class='finding' style='border-left-color:{_SEV_COLOR[f.severity.value]}'>"
                f"<div class='t'>{html.escape(f.title)}</div>"
                f"<span class='chip' style='background:{_SEV_COLOR[f.severity.value]};color:#fff'>"
                f"{_SEV_LABEL[f.severity.value]}</span>"
                f"<span class='chip'>置信度 {f.confidence.value}</span>"
                f"<span class='chip'>{f.category.value}</span>"
                f"<span class='chip'>{html.escape(f.analyzer)}</span>{chips}"
                f"<p>{desc}</p>{details}</div>"
            )
        if not findings_html:
            findings_html.append("<p class='muted'>未发现明显异常。</p>")

        # 时间线
        hot = [e for e in sorted(ctx.events, key=lambda x: x.sort_key)
               if e.tags and {"critical", "suspicious-process", "reverse_shell_pattern",
                              "backdoor-account", "rootkit", "bruteforce",
                              "privilege-escalation", "suspicious-file"} & set(e.tags)]
        if not hot:
            hot = sorted(ctx.events, key=lambda x: x.sort_key)[:80]
        timeline_rows = "".join(
            f"<tr><td>{fmt_local(e.timestamp)}</td><td>{e.category.value}</td>"
            f"<td>{html.escape(e.action)}</td>"
            f"<td><code>{html.escape(e.user or e.path or '-')}</code></td>"
            f"<td>{html.escape(e.message[:200])}</td></tr>"
            for e in hot[:120]
        ) or "<tr><td colspan='5' class='muted'>无事件</td></tr>"

        # 证据
        evidence_rows = "".join(
            f"<tr><td>{i}</td><td>{html.escape(ev.source)}</td><td>{ev.kind}</td>"
            f"<td><code>{html.escape(ev.path or ev.content or '-')}</code></td>"
            f"<td><code>{html.escape((ev.sha256 or '-'))}</code></td></tr>"
            for i, ev in enumerate(ctx.evidence, 1)
        ) or "<tr><td colspan='5' class='muted'>无证据</td></tr>"

        # 威胁情报
        intel_section = self._intel_section(ctx)

        # 处置建议
        from irtrace.reporters.markdown_report import MarkdownReporter
        recs = MarkdownReporter._recommendations(ctx, counts)
        rec_html = "<ul>" + "".join(
            f"<li>{self._md_inline(r)}</li>" for r in recs if not r.startswith("\n>")) + "</ul>"

        warnings_section = ""
        if ctx.warnings:
            warnings_section = (
                "<section class='warn'><h2>七、采集告警</h2><ul>"
                + "".join(f"<li>{html.escape(w)}</li>" for w in ctx.warnings)
                + "</ul></section>"
            )

        body = _TEMPLATE.format(
            host=html.escape(s["host"]), operator=html.escape(s["operator"]),
            run_id=html.escape(s["run_id"]),
            generated_at=fmt_local(datetime.now(timezone.utc), "%Y-%m-%d %H:%M:%S"),
            risk_level=risk, risk_color=risk_color,
            n_events=s["events"], n_evidence=s["evidence"], n_findings=s["findings"],
            n_critical=counts["critical"] + counts["high"],
            critical_color=_SEV_COLOR["critical"],
            sev_rows="".join(sev_rows),
            findings_html="".join(findings_html),
            intel_section=intel_section,
            timeline_rows=timeline_rows, evidence_rows=evidence_rows,
            recommendations=rec_html, warnings_section=warnings_section,
        )
        path = self.out_path(ctx, "report.html")
        path.write_text(body, encoding="utf-8")
        return path

    # ------------------------------------------------------------------ #
    def _intel_section(self, ctx) -> str:
        """威胁情报命中章节。"""
        intel = ctx.stats.get("intel_providers") or {}
        providers = intel.get("providers", [])
        hits = ctx.stats.get("intel_hits") or {}

        rows = []
        for p in providers:
            kind = "离线" if p.get("offline") else "在线"
            ok = p.get("available")
            badge = (f"<span class='chip' style='background:#2e7d32;color:#fff'>可用</span>"
                     if ok else
                     f"<span class='chip' style='background:#9aa5b1;color:#fff'>不可用</span>")
            reason = "" if ok else html.escape(p.get("reason") or "")
            rows.append(
                f"<tr><td><code>{html.escape(p['name'])}</code></td><td>{kind}</td>"
                f"<td>{badge}</td><td>{p.get('weight', 1.0)}</td>"
                f"<td class='muted'>{reason}</td></tr>"
            )

        hit_rows = []
        for name, items in hits.items():
            inds = ", ".join(f"<code>{html.escape(str(i['indicator']))}</code>"
                             for i in items[:10])
            hit_rows.append(f"<tr><td><code>{html.escape(name)}</code></td>"
                            f"<td>{len(items)}</td><td>{inds}</td></tr>")

        body = ["<section><h2>三、威胁情报命中</h2>"]
        if providers:
            body.append(
                f"<p class='muted'>查询 {intel.get('queries', 0)} 次　"
                f"缓存命中 {intel.get('cache_hits', 0)} 次</p>"
                "<table><tr><th>情报平台</th><th>类型</th><th>状态</th>"
                "<th>权重</th><th>说明</th></tr>" + "".join(rows) + "</table>")
        else:
            body.append("<p class='muted'>未启用情报源。</p>")

        if hit_rows:
            body.append("<h3 style='font-size:14px;margin:16px 0 8px'>情报源命中统计</h3>"
                        "<table><tr><th>情报平台</th><th>命中指标数</th><th>指标</th></tr>"
                        + "".join(hit_rows) + "</table>")
        body.append("</section>")
        return "".join(body)

    @staticmethod
    def _md_inline(text: str) -> str:
        """极简 markdown 内联转换 (加粗 + 行内代码)。"""
        import re
        text = html.escape(text)
        text = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", text)
        text = re.sub(r"`(.+?)`", r"<code>\1</code>", text)
        return text


__all__ = ["HtmlReporter"]
