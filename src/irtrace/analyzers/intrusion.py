"""入侵判定器 —— 在关联规则之上做场景级失陷判定。

关联规则（correlation）是「有这条链就报一条结论」，正常运维里的
sudo、合法外联、单独的 SSH 公钥也会被单独点名。本分析器把同一主机上的
事件收成一个场景，按攻击阶段加权，并用反例抑制误报：

- 正信号按阶段计分（爆破成功、落地执行、反弹 shell、rootkit、已被访问的 webshell 等）。
- 反信号只在没有对应攻击阶段时扣分（管理员 sudo、合法外联、单独公钥、单纯的 Web 扫描）。
- 总分达到阈值才产出一条失陷结论；否则不报。

评测口径是「这个场景是不是失陷主机」，不是「每一条规则有没有命中」。
"""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from typing import Dict, Iterable, List, Optional, Set

from irtrace.analyzers.base import BaseAnalyzer
from irtrace.collectors.web_shell import same_web_file
from irtrace.core.models import Category, Confidence, Event, Finding, Severity
from irtrace.core.registry import register

#: 判定为失陷的最低分。单条弱信号（sudo、外联、公钥）到不了这个分。
INTRUSION_THRESHOLD = 6.0

_WINDOW = timedelta(hours=1)
_PRIV_ACTIONS = {
    "sudo", "user_added", "uid0_account", "sudo_rule",
    "empty_password", "privileged_group_members",
}
_PERSIST_TAGS = {
    "suspicious-content", "cron-persistence", "systemd-persistence",
    "boot-persistence",
}
_STRONG_TAGS = {
    "reverse_shell_pattern", "known_malware_name", "backdoor-account",
    "exe_deleted", "rootkit", "memfd_exec", "fileless_exec",
}


def _tags(event: Event) -> Set[str]:
    return set(event.tags or [])


def _is_model_relay(event: Event) -> bool:
    """专用网关，或同时标了对外监听和上游地址。"""
    tags = _tags(event)
    if any(tag.startswith("model_gateway:") for tag in tags):
        return True
    return "model_listen" in tags and "model_upstream" in tags


def _http_status(event: Event) -> Optional[int]:
    raw = event.raw if isinstance(event.raw, dict) else {}
    status = raw.get("status")
    return status if isinstance(status, int) else None


def _shell_responded(event: Event) -> bool:
    """2xx 表示页面返回，5xx 表示脚本已执行后出错。没有状态时保留原事件语义。"""
    status = _http_status(event)
    if status is None:
        return True
    return (200 <= status < 300) or status >= 500


def _in_window(earlier: Event, later: Event, window: timedelta = _WINDOW) -> bool:
    if earlier.timestamp is None or later.timestamp is None:
        return False
    delta = later.timestamp - earlier.timestamp
    return timedelta(0) <= delta <= window


@register
class IntrusionAnalyzer(BaseAnalyzer):
    name = "intrusion"
    description = "场景级入侵判定：多阶段加权并抑制正常运维误报"

    def analyze(self, ctx) -> List[Finding]:
        events = list(ctx.events)
        if not events:
            return []
        verdict = judge_intrusion(events)
        ctx.stats["intrusion"] = {
            "compromised": verdict.compromised,
            "score": verdict.score,
            "threshold": INTRUSION_THRESHOLD,
            "signals": verdict.signals,
            "suppressors": verdict.suppressors,
        }
        if not verdict.compromised:
            return []
        confidence = Confidence.HIGH if verdict.score >= 9 else Confidence.MEDIUM
        severity = Severity.CRITICAL if verdict.score >= 9 else Severity.HIGH
        return [self.finding(
            title=verdict.title,
            severity=severity,
            category=Category.OTHER,
            confidence=confidence,
            mitre=verdict.mitre,
            events=verdict.evidence[:20],
            description=verdict.summary,
            details={
                "score": verdict.score,
                "threshold": INTRUSION_THRESHOLD,
                "signals": verdict.signals,
                "suppressors": verdict.suppressors,
            },
        )]


class IntrusionVerdict:
    """一次场景判定的结果，供分析器与评测共用。"""

    def __init__(
        self,
        compromised: bool,
        score: float,
        signals: List[str],
        suppressors: List[str],
        evidence: List[Event],
        mitre: List[str],
    ) -> None:
        self.compromised = compromised
        self.score = round(score, 2)
        self.signals = signals
        self.suppressors = suppressors
        self.evidence = evidence
        self.mitre = mitre

    @property
    def title(self) -> str:
        head = "判定失陷" if self.compromised else "未达失陷阈值"
        return f"{head}（评分 {self.score} / 阈值 {INTRUSION_THRESHOLD}）"

    @property
    def summary(self) -> str:
        parts = []
        if self.signals:
            parts.append("命中：" + "、".join(self.signals))
        if self.suppressors:
            parts.append("抑制：" + "、".join(self.suppressors))
        return "；".join(parts) or "无可判定信号"


def judge_intrusion(events: Iterable[Event]) -> IntrusionVerdict:
    """对一组事件做失陷判定。纯函数，不依赖流水线。"""
    events = list(events)
    score = 0.0
    signals: List[str] = []
    suppressors: List[str] = []
    evidence: List[Event] = []
    mitre: List[str] = []
    stages: Set[str] = set()

    def hit(name: str, points: float, stage: str, evs: List[Event],
            technique: Optional[str] = None) -> None:
        nonlocal score
        score += points
        stages.add(stage)
        signals.append(f"{name}(+{points:g})")
        evidence.extend(evs)
        if technique and technique not in mitre:
            mitre.append(technique)

    def damp(name: str, points: float) -> None:
        nonlocal score
        score -= points
        suppressors.append(f"{name}(-{points:g})")

    failed: Dict[str, List[Event]] = defaultdict(list)
    for event in events:
        if event.action == "ssh_failed" and event.src_ip:
            failed[event.src_ip].append(event)

    # --- 认证：爆破成功是强信号；单次失败或合法登录不加分 ---
    brute_ips: Set[str] = set()
    for event in events:
        if event.action != "ssh_login" or not event.src_ip:
            continue
        prior = [
            item for item in failed.get(event.src_ip, [])
            if _in_window(item, event)
        ]
        if len(prior) >= 5:
            brute_ips.add(event.src_ip)
            # 失败后成功就是账号失陷，单独足以跨过阈值；
            # 没有后续的失败爆破仍然只给低分，避免扫描噪声误报。
            hit("爆破后登录成功", 7, "initial_access", [*prior[-3:], event], "T1110")

    burst_ips = {
        ip for ip, items in failed.items()
        if len(items) >= 10 and ip not in brute_ips
    }
    if burst_ips:
        samples = [item for ip in burst_ips for item in failed[ip][:2]]
        hit("口令爆破未成功", 2, "recon", samples, "T1110")

    # --- 落地并执行 ---
    dropped = [
        event for event in events
        if event.action == "suspicious_file" and event.path
        and event.path.startswith(("/tmp", "/dev/shm", "/var/tmp", "/run/shm"))
    ]
    running = [
        event for event in events
        if event.action == "process_suspicious" and event.path
    ]
    executed = False
    for proc in running:
        for drop in dropped:
            if proc.path == drop.path or (drop.path and drop.path in (proc.path or "")):
                executed = True
                hit("载荷落地并执行", 6, "execution", [drop, proc], "T1204")
                break
        if executed:
            break

    # --- 进程侧强特征（反弹 shell / 已删除可执行 / 已知恶意名）---
    strong_proc = [
        event for event in events
        if _STRONG_TAGS & _tags(event) and event.category in
        (Category.PROCESS, Category.FILE)
        and not ({"memfd_exec", "fileless_exec"} & _tags(event))
    ]
    if strong_proc and "execution" not in stages:
        hit("进程或文件强恶意特征", 5, "execution", strong_proc[:3], "T1059")

    # --- Web：2xx/5xx 才说明脚本被执行；404 只是探测 ---
    shells = [event for event in events if event.action == "web_shell_request"]
    live_shells = [event for event in shells if _shell_responded(event)]
    missed_shells = [event for event in shells if event not in live_shells]
    if live_shells:
        hit("webshell 被访问", 7, "execution", live_shells[:3], "T1505.003")

    # 磁盘文件单独不够。它和一次成功访问指向同一路径时, 说明外壳已经落地。
    shell_files = [event for event in events if event.action == "web_shell_file" and event.path]
    confirmed_files = [
        event for event in shell_files
        if any(same_web_file(req.path or "", event.path or "") for req in live_shells)
    ]
    if confirmed_files and "execution" in stages:
        hit("webshell 文件落地", 3, "persistence", confirmed_files[:2], "T1505.003")
    elif shell_files and not stages:
        damp("未被访问的 webshell 文件", 1)

    # --- 提权：必须跟在爆破成功或落地之后，单独 sudo 不算 ---
    privesc = [event for event in events if event.action in _PRIV_ACTIONS]
    # UID=0 非 root、空口令本身就是后门账号，不能和普通 sudo 一起抑制。
    backdoor_accounts = [
        event for event in privesc
        if event.action in ("uid0_account", "empty_password")
        or "backdoor-account" in _tags(event)
    ]
    routine_priv = [event for event in privesc if event not in backdoor_accounts]
    attack_anchors = [
        event for event in events
        if event.action == "ssh_login" and event.src_ip in brute_ips
    ] + dropped + strong_proc + live_shells
    chained_priv = [
        event for event in routine_priv
        if any(_in_window(anchor, event) for anchor in attack_anchors)
    ]
    if backdoor_accounts:
        hit("后门账号", 6, "privilege", backdoor_accounts[:2], "T1136")
    if chained_priv:
        hit("攻击后提权或建号", 3, "privilege", chained_priv[:2], "T1548")
    elif routine_priv and not stages:
        damp("孤立的提权/账号变更", 2)

    # --- 持久化：可疑内容才算；单独的 authorized_keys 是基线 ---
    persist = [
        event for event in events
        if event.category == Category.PERSISTENCE and (_PERSIST_TAGS & _tags(event))
    ]
    keys_only = [
        event for event in events
        if "ssh-key" in _tags(event) and not (_PERSIST_TAGS & _tags(event))
    ]
    if persist and stages:
        hit("攻击后写入持久化", 3, "persistence", persist[:3], "T1053")
    elif persist:
        hit("可疑持久化内容", 4, "persistence", persist[:3], "T1053")
    elif keys_only and not stages:
        damp("仅有 SSH 公钥", 1)

    # 模型中转站先挑出来。它带 relay 标签，但不能再走普通端口转发的双向要求。
    abused = [event for event in events if event.action == "model_abuse"]
    model_relays = [
        event for event in events
        if event.action == "relay_process" and _is_model_relay(event)
    ]

    # --- 中转：工具本身不够，必须同时有连入和连出 ---
    relays = [
        event for event in events
        if event not in model_relays and (
            event.action == "relay_process"
            or {"relay", "port_forward"} & _tags(event)
        )
    ]
    inbound = [
        event for event in events
        if event.action == "external_connection" and "inbound" in _tags(event)
    ]
    outbound = [
        event for event in events
        if event.action == "external_connection" and "outbound" in _tags(event)
    ]
    if relays and inbound and outbound:
        hit("中转站：入站经本机转到出站", 7, "c2",
            relays[:2] + inbound[:1] + outbound[:1], "T1090")
    elif relays and not stages:
        damp("仅有转发进程，没有双向流量", 2)

    # 模型中转站：对外提供接口，并且命令行里有上游模型地址。
    # 只有上游地址没有对外监听的，是本机调用方，不进这个列表。
    if model_relays and (inbound or outbound):
        hit("模型中转站：对外接口转发到上游模型", 7, "c2",
            model_relays[:2] + (inbound[:1] or outbound[:1]), "T1090")
    elif model_relays and not stages and not abused:
        damp("模型网关进程但没有外部流量", 2)

    # 模型中转站被爆破：同一来源先大量登录失败，再出现成功。
    # 只打满补全接口是薅配额，要有网关进程才算这台机器在被利用。
    auth_fail = [event for event in events if event.action == "model_auth_failure"]
    auth_ok = [event for event in events if event.action == "model_auth_success"]
    cracked = [
        event for event in auth_ok
        if any(event.src_ip and event.src_ip == fail.src_ip for fail in auth_fail)
    ]
    if cracked:
        hit("模型中转站登录被爆破", 7, "initial_access",
            auth_fail[:2] + cracked[:1], "T1110")
    elif auth_fail and not stages:
        damp("模型登录失败但没有成功", 1)
    if abused and (model_relays or cracked):
        hit("模型中转站配额被打野", 7, "impact", abused[:2], "T1496")
    elif abused and not stages:
        damp("补全接口高频但未见中转进程", 1)

    # 同一把密钥被多个来源调用。指纹相同就说明钥匙已经流出，
    # 不要求先看到网关进程，也不把密钥原文放进结论。
    reused = [event for event in events if event.action == "model_key_reuse"]
    shared = [
        event for event in reused
        if len((event.raw or {}).get("sources") or []) >= 2
    ]
    if shared:
        hit("泄露的模型密钥被多个来源使用", 7, "credential_access",
            shared[:2], "T1552")
    elif reused and not stages:
        damp("密钥复用但来源不足", 1)

    # --- 外联：恶意名 / 反弹 / 情报命中 / 可疑端口才加分 ---
    risky_conn = [
        event for event in events
        if event.action in ("external_connection", "external_conn")
        and (
            {"suspicious_port", "suspicious-port", "known_malware_name",
             "reverse_shell_pattern"} & _tags(event)
            or "恶意" in (event.message or "")
        )
    ]
    plain_conn = [
        event for event in events
        if event.action in ("external_connection", "external_conn")
        and event not in risky_conn
    ]
    if risky_conn and (stages or any(_STRONG_TAGS & _tags(event) for event in events)):
        hit("可疑外联或回连", 3, "c2", risky_conn[:3], "T1071")
    elif risky_conn:
        hit("可疑端口外联", 3, "c2", risky_conn[:2], "T1071")
    elif plain_conn and not stages and not relays and not model_relays:
        damp("仅有合法外联", 2)

    # --- 内核：rootkit 模块本身足够；未知模块要配合其它阶段 ---
    rootkit = [event for event in events if event.action == "rootkit_module"]
    unknown_mod = [event for event in events if event.action == "unknown_module"]
    deleted = [event for event in events if "exe_deleted" in _tags(event)]
    if rootkit:
        hit("已知 rootkit 模块", 7, "defense_evasion", rootkit[:2], "T1014")
    elif unknown_mod and deleted:
        hit("无文件进程配合异常内核模块", 6, "defense_evasion",
            deleted[:2] + unknown_mod[:2], "T1014")
    elif unknown_mod and not stages:
        damp("孤立的非常规内核模块", 2)

    # 采集器已经报出、但此前没进场景分的强信号。
    # 基线类（系统账号可登录、近期改口令、特权组成员、sysctl 偏离）仍不加分。
    suid = [event for event in events if event.action == "suid_in_writable"]
    preload = [event for event in events if event.action == "ld_preload"]
    homes = [event for event in events if event.action == "suspicious_home"]
    listens = [event for event in events if event.action == "suspicious_listen"]
    if suid:
        hit("可写目录中的 SUID 文件", 7, "privilege", suid[:2], "T1548.001")
    if preload:
        hit("动态链接器预加载劫持", 7, "defense_evasion", preload[:2], "T1574.006")
    if homes:
        hit("账号家目录位于可写目录", 6, "persistence", homes[:2], "T1078")
    if listens and (stages or relays or model_relays):
        hit("可疑端口正在监听", 3, "c2", listens[:2], "T1571")
    elif listens and not stages:
        damp("仅有可疑监听", 1)

    # 清痕本身是善后动作。它跟着落地、反弹、memfd 或隐藏进程才加分；
    # 单独清空历史只扣分，避免运维误删 .bash_history 被判失陷。
    wipes = [event for event in events if event.action == "history_wiped"]
    hidden = [event for event in events if event.action == "hidden_process"]
    fileless = [
        event for event in events
        if {"memfd_exec", "fileless_exec"} & _tags(event)
    ]
    if hidden:
        hit("ps 不可见的隐藏进程", 7, "defense_evasion", hidden[:3], "T1014")
    if fileless and "execution" not in stages:
        hit("memfd 或标准输入无文件执行", 7, "execution", fileless[:3], "T1620")
    if wipes and (stages or hidden):
        hit("命令历史被清理", 3, "defense_evasion", wipes[:2], "T1070.003")
    elif wipes and not stages:
        damp("仅清空命令历史", 1)

    # Sigma proc_creation_lnx_crypto_mining：矿池协议或 xmrig 参数单独即失陷。
    # 伪装成内核线程但 exe 非空，对照 Elastic kthreadd masquerading，同样单独即失陷。
    # 下载管道本身只是投递。可写目录已经有落地文件时，管道就是这次执行，单独跨过阈值。
    miners = [
        event for event in events
        if "crypto_miner" in _tags(event)
    ]
    masquerade = [
        event for event in events
        if "kthread_masquerade" in _tags(event)
    ]
    downloads = [
        event for event in events
        if "download_exec" in _tags(event)
    ]
    if miners and "impact" not in stages:
        hit("挖矿进程", 7, "impact", miners[:3], "T1496")
    if masquerade:
        hit("伪装成内核线程的用户态进程", 7, "defense_evasion",
            masquerade[:3], "T1036.005")
    if downloads and (dropped or "execution" in stages):
        hit("下载后直接执行", 6, "execution", downloads[:2], "T1059.004")
    elif downloads and not stages:
        damp("仅有下载管道，没有落地", 1)

    # 没有执行成功的 webshell 与纯扫描都不单独构成失陷。
    scans = [event for event in events if event.action == "web_scan"]
    if missed_shells and "execution" not in stages:
        if len(missed_shells) >= 8:
            hit("webshell 路径探测未命中", 2, "recon", missed_shells[:3], "T1190")
        else:
            damp("未命中的 webshell 探测", 1)
    if scans and not stages:
        damp("仅有 Web 扫描", 2)

    # 多阶段叠加：两条以上不同阶段再加分，避免单点噪声跨过阈值
    if len(stages) >= 2:
        bonus = 2.0
        score += bonus
        signals.append(f"多阶段叠加(+{bonus:g})")

    return IntrusionVerdict(
        compromised=score >= INTRUSION_THRESHOLD,
        score=max(score, 0.0),
        signals=signals,
        suppressors=suppressors,
        evidence=evidence,
        mitre=mitre,
    )


__all__ = ["IntrusionAnalyzer", "judge_intrusion", "INTRUSION_THRESHOLD"]
