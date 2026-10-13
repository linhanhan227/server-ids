"""AI 辅助入侵检测。

流程：

1. 从事件里抽出 IP / 域名 / 哈希。
2. 默认只查本地威胁库。``ai.cross_validate`` 打开后，才会用已配置的
   在线情报接口做交叉验证；没有 Key 的源不参与。开关默认关闭。
3. 只把带编号的事件和情报原文交给模型。模型只写论点并引用编号，
   不决定是否失陷、也不决定沦陷程度。
4. 是否失陷和 stage 由本模块按材料计算。模型没配、返回无法解析、
   或引用了材料里没有的证据时，不产出结论。

材料里没有在线源命中时，结论会标明「仅有本地情报」，不会被说成在线高精度判定。
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List

from irtrace.ai.client import ModelClient, ModelError, load_model_config
from irtrace.analyzers.base import BaseAnalyzer
from irtrace.core.models import Category, Confidence, Finding, Severity
from irtrace.core.registry import register
from irtrace.intel import IndicatorType, IntelAggregator
from irtrace.utils.textutil import extract_domains, extract_hashes, extract_ips

_SYSTEM = """你是 Linux 入侵检测分析员，只有只读权限。
只能依据用户给出的带编号材料作答。每条论点必须引用材料中的 id。
不得补充材料里没有的情报源、评分、IOC、漏洞编号或攻击手法。
不得要求读取材料以外的文件。禁止删除、移动、覆盖任何文件，也禁止给出删除命令。
不要判断是否失陷，也不要给出沦陷程度：这两项由调用方按材料计算。
malicious=false 或 error 非空的情报条目只能写「未收录」或「查询失败」，不得当作恶意依据。
只输出一个 JSON 对象，不要 Markdown。字段：
{
  "intrusion_points": [{"claim": "一句话", "evidence_ids": ["E1"]}],
  "summary": "两三句中文，只复述已引用的材料",
  "sources": ["材料里出现过的 provider"],
  "readonly": true
}
"""

# 模型没有文件工具。这里再拦一层：返回里一旦出现删除动作就整段丢弃。
_DELETE = re.compile(
    r"(\brm\s+-[rf]|\bunlink\s*\(|\bos\.remove\b|\bshutil\.rmtree\b|删除文件|删掉文件)",
    re.I,
)
_MALICIOUS_CLAIM = re.compile(r"(恶意|失陷|沦陷|命中|收录|木马|后门|回连)")
_OFFLINE_PROVIDERS = {"local_rules", "csv_feed", "local_db"}

# 沦陷程度只看材料里的动作和情报，不看模型自己的判断。
_ACCESS_ACTIONS = {"ssh_login", "ssh_failed"}
_EXEC_ACTIONS = {"process_suspicious", "suspicious_file"}
_PERSIST_ACTIONS = {
    "cron", "systemd", "rc_local", "ld_preload", "authorized_keys",
    "user_added", "uid0_account", "sudo_rule", "empty_password",
}
_STRONG_TAGS = {
    "reverse_shell_pattern", "known_malware_name", "backdoor-account",
    "exe_deleted", "rootkit", "suspicious-content", "cron-persistence",
    "systemd-persistence", "boot-persistence",
}

_MAX_INDICATORS = 8
_MAX_EVENTS = 30


@register
class AIAssistAnalyzer(BaseAnalyzer):
    name = "ai_assist"
    description = "调用真实 AI 模型，结合在线威胁情报做失陷判定"

    def analyze(self, ctx) -> List[Finding]:
        cfg = ctx.config.get("ai", {}) if isinstance(ctx.config, dict) else {}
        if cfg.get("enabled") is False:
            return []

        model_cfg = load_model_config(
            ctx.workspace,
            protocol=cfg.get("protocol"),
            model=cfg.get("model"),
        )
        if cfg.get("base_url"):
            model_cfg.base_url = str(cfg["base_url"])
        if cfg.get("timeout"):
            model_cfg.timeout = int(cfg["timeout"])
        if not model_cfg.configured:
            ctx.stats["ai_assist"] = {"status": "skipped", "reason": "模型未配置或不可用"}
            ctx.warn("[analyzer:ai_assist] 跳过 — 未配置可用的 AI 模型")
            return []

        indicators = _indicators(ctx)
        intel_cfg = _intel_for_assist(ctx)
        aggregator = IntelAggregator.from_config(intel_cfg, ctx=ctx)
        reports = []
        for indicator, itype in indicators:
            report = aggregator.lookup(indicator, itype)
            reports.append(report.to_dict())

        material = _material(ctx, reports)
        online_sources = sorted({
            item["provider"] for item in material["intel"] if item["online"] and item["ok"]
        })
        user = (
            "以下是本次全部材料。evidence_ids 和 sources 只能使用这里出现的 id 与 provider。"
            "不要复述没有给出的字段。\n"
            + json.dumps(material, ensure_ascii=False)
        )
        try:
            answer = ModelClient(model_cfg).complete_json(_SYSTEM, user)
        except ModelError as exc:
            ctx.stats["ai_assist"] = {"status": "error", "reason": str(exc)}
            ctx.warn(f"[analyzer:ai_assist] 模型调用失败: {exc}")
            return []

        rejected = _reject_reason(answer, material)
        if rejected:
            ctx.stats["ai_assist"] = {"status": "rejected", "reason": rejected}
            ctx.warn(f"[analyzer:ai_assist] 丢弃模型返回: {rejected}")
            return []

        finding = _to_finding(self, answer, reports, online_sources, indicators, material)
        ctx.stats["ai_assist"] = {
            "status": "ok",
            "protocol": model_cfg.protocol,
            "model": model_cfg.model,
            "indicators": len(indicators),
            "online_sources": online_sources,
            "compromised": finding.details.get("compromised"),
            "stage": finding.details.get("stage"),
        }
        return [finding]


def _intel_for_assist(ctx) -> Dict[str, Any]:
    """默认只查本地库。交叉验证开关打开后才带上已配置的在线源。"""
    from irtrace.intel.aggregator import DEFAULT_OFFLINE_PROVIDERS, _enabled_secret_names

    cfg = dict(ctx.config.get("intel", {}) or {})
    ai_cfg = ctx.config.get("ai", {}) if isinstance(ctx.config, dict) else {}
    if not ai_cfg.get("cross_validate"):
        cfg["providers"] = list(DEFAULT_OFFLINE_PROVIDERS)
        return cfg
    online = _enabled_secret_names(ctx.workspace)
    cfg["providers"] = list(DEFAULT_OFFLINE_PROVIDERS) + online
    return cfg


def _reject_reason(answer: Dict[str, Any], material: Dict[str, Any]) -> str:
    """返回非空表示这份模型结果不能用。

    丢弃条件：删除动作、引用了不存在的证据或情报源、把未收录写成恶意命中、
    写出材料里没有的 IOC。
    """
    if not isinstance(answer, dict):
        return "返回不是对象"
    if answer.get("readonly") is False:
        return "模型声明了非只读"
    blob = json.dumps(answer, ensure_ascii=False)
    if _DELETE.search(blob):
        return "模型返回包含删除文件动作"

    known_ids = {item["id"] for item in material["events"]}
    known_ids.update(item["id"] for item in material["intel"])
    points = answer.get("intrusion_points") or []
    if not isinstance(points, list):
        return "intrusion_points 不是数组"
    cited = []
    for point in points:
        if not isinstance(point, dict):
            return "入侵点不是对象"
        ids = point.get("evidence_ids") or []
        if not ids:
            return "入侵点缺少 evidence_ids"
        missing = [item for item in ids if item not in known_ids]
        if missing:
            return "引用了材料中不存在的证据 " + ",".join(map(str, missing))
        cited.extend(ids)

    known_providers = {item["provider"] for item in material["intel"]}
    sources = [str(item) for item in answer.get("sources") or [] if item]
    unknown = [item for item in sources if item not in known_providers]
    if unknown:
        return "引用了材料中不存在的情报源 " + ",".join(unknown)

    if "compromised" in answer or "stage" in answer or "online" in answer:
        return "模型自行给出了失陷或沦陷程度，这两项只能由材料计算"

    malicious_ids = {item["id"] for item in material["intel"] if item["malicious"]}
    for point in points:
        claim = str(point.get("claim") or "")
        if not _MALICIOUS_CLAIM.search(claim):
            continue
        ids = [str(item) for item in point.get("evidence_ids") or []]
        intel_ids = [item for item in ids if item.startswith("I")]
        if intel_ids and not any(item in malicious_ids for item in intel_ids):
            return "把未收录的情报当作恶意依据"

    allowed = set(material["indicators"])
    for token in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", blob):
        if token not in allowed:
            return f"写出了材料中没有的 IP {token}"
    return ""


def _material(ctx, reports: List[Dict[str, Any]]) -> Dict[str, Any]:
    """只保留判定需要的字段，并给每条证据一个 id。原始响应整包不进模型。"""
    events = []
    for index, event in enumerate(list(ctx.events)[:_MAX_EVENTS], 1):
        events.append({
            "id": f"E{index}",
            "action": event.action,
            "category": event.category.value,
            "message": (event.message or "")[:180],
            "src_ip": event.src_ip,
            "dst_ip": event.dst_ip,
            "path": event.path,
            "tags": list(event.tags or [])[:6],
        })
    intel = []
    indicators = []
    seq = 1
    for report in reports:
        indicator = str(report.get("indicator") or "")
        if indicator and indicator not in indicators:
            indicators.append(indicator)
        for verdict in report.get("verdicts") or []:
            provider = str(verdict.get("provider") or "")
            raw = verdict.get("raw") or {}
            hits = raw.get("hits") if isinstance(raw, dict) else None
            intel.append({
                "id": f"I{seq}",
                "indicator": indicator,
                "provider": provider,
                "online": provider not in _OFFLINE_PROVIDERS,
                "ok": not bool(verdict.get("error")),
                "malicious": bool(verdict.get("malicious")),
                "score": verdict.get("score"),
                "description": str(verdict.get("description") or "")[:240],
                "cited_lines": [item.get("line") for item in (hits or [])][:3],
                "source_urls": [item.get("url") for item in (hits or [])][:3],
                "error": (str(verdict.get("error"))[:120] if verdict.get("error") else ""),
            })
            seq += 1
    return {"events": events, "intel": intel, "indicators": indicators}


def _indicators(ctx) -> List[tuple]:
    found: List[tuple] = []
    seen = set()
    for event in ctx.events:
        blob = " ".join([
            event.message or "", event.path or "", event.src_ip or "",
            event.dst_ip or "", str(event.raw or ""),
        ])
        for value, itype in (
            *[(ip, IndicatorType.IP) for ip in extract_ips(blob)],
            *[(domain, IndicatorType.DOMAIN) for domain in extract_domains(blob)],
            *[(digest, IndicatorType.HASH) for digest in extract_hashes(blob)],
        ):
            key = (value, itype)
            if key in seen:
                continue
            seen.add(key)
            found.append(key)
            if len(found) >= _MAX_INDICATORS:
                return found
    return found


def _event_view(event) -> Dict[str, Any]:
    return {
        "action": event.action,
        "category": event.category.value,
        "message": (event.message or "")[:180],
        "src_ip": event.src_ip,
        "dst_ip": event.dst_ip,
        "path": event.path,
        "tags": list(event.tags or []),
    }


def _assess(material: Dict[str, Any], cited: List[str]) -> Dict[str, Any]:
    """按材料计算沦陷程度。模型的 compromised / stage 不参与。

    情报是否恶意只看查询结果，不看模型有没有引用。
    事件阶段只计入模型实际引用的条目，避免模型没有说明的动作被算进入侵链。

    none：没有可引用的攻击动作，也没有情报命中。
    suspicious：只有弱迹象，或情报命中但本机没有对应动作。
    partial：看到入侵动作，但没有驻留或恶意回连。
    compromised：至少两个阶段闭合，或入侵动作与在线情报命中同时成立。
    """
    events = {
        item["id"]: item for item in material["events"]
        if item["id"] in cited
    }
    intel = {
        item["id"]: item for item in material["intel"]
        if item["malicious"] and item["ok"]
    }
    stages = set()
    for event in events.values():
        tags = set(event.get("tags") or [])
        action = event.get("action") or ""
        if action in _ACCESS_ACTIONS or "brute" in tags:
            stages.add("access")
        if action in _EXEC_ACTIONS or tags & {"reverse_shell_pattern", "known_malware_name", "exe_deleted"}:
            stages.add("execution")
        if action in _PERSIST_ACTIONS or tags & {
            "suspicious-content", "cron-persistence", "systemd-persistence",
            "boot-persistence", "backdoor-account", "rootkit",
        }:
            stages.add("persistence")
    online_hits = [item for item in intel.values() if item["online"]]
    local_hits = [item for item in intel.values() if not item["online"]]
    if online_hits or local_hits:
        stages.add("intel")

    host_stages = stages & {"access", "execution", "persistence"}
    if "execution" in stages and (online_hits or len(host_stages) >= 2):
        stage = "compromised"
    elif online_hits and host_stages:
        stage = "compromised"
    elif host_stages:
        stage = "partial"
    elif online_hits or local_hits:
        stage = "suspicious"
    else:
        stage = "none"
    return {
        "stage": stage,
        "compromised": stage == "compromised",
        "online": bool(online_hits),
        "stages": sorted(stages),
    }


def _to_finding(analyzer, answer: Dict[str, Any], reports, online_sources,
                indicators, material) -> Finding:
    cited: List[str] = []
    for point in answer.get("intrusion_points") or []:
        cited.extend(str(item) for item in point.get("evidence_ids") or [])
    verdict = _assess(material, cited)
    compromised = verdict["compromised"]
    online = verdict["online"]
    claimed = [str(item) for item in answer.get("sources") or [] if item]
    known = {
        verdict_item.get("provider")
        for report in reports
        for verdict_item in report.get("verdicts", [])
        if verdict_item.get("provider")
    }
    sources = [item for item in claimed if item in known]
    summary = str(answer.get("summary") or "").strip() or "模型未给出摘要"
    if not online:
        summary = "仅有本地情报，不是在线高精度判定。" + summary

    if compromised and online:
        severity, confidence = Severity.CRITICAL, Confidence.HIGH
    elif compromised:
        severity, confidence = Severity.HIGH, Confidence.MEDIUM
    elif verdict["stage"] == "partial":
        severity, confidence = Severity.MEDIUM, Confidence.MEDIUM
    else:
        severity, confidence = Severity.INFO, Confidence.LOW

    labels = {
        "none": "未见入侵",
        "suspicious": "可疑",
        "partial": "部分沦陷",
        "compromised": "判定失陷",
    }
    title = "AI " + labels[verdict["stage"]]
    if online:
        title += "（含在线情报）"
    return analyzer.finding(
        title=title,
        severity=severity,
        category=Category.OTHER,
        confidence=confidence,
        description=summary,
        details={
            "compromised": compromised,
            "stage": verdict["stage"],
            "stages": verdict["stages"],
            "online": online,
            "sources": sources,
            "online_sources": online_sources,
            "intrusion_points": answer.get("intrusion_points") or [],
            "indicators": [f"{itype.value}:{value}" for value, itype in indicators],
            "intel_reports": reports,
        },
    )


__all__ = ["AIAssistAnalyzer"]
