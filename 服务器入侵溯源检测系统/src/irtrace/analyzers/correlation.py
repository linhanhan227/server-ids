"""跨源关联分析器 —— 把多个弱信号组合成强结论。

内置关联规则 (每条对应一个真实攻击链片段):

============  ==============================================================
规则            逻辑
============  ==============================================================
R1 爆破成功     同一 IP 大量认证失败后出现登录成功 → 账号被爆破攻破
R2 登录后提权   可疑登录后短时间内出现 sudo/新建账号 → 权限提升
R3 落地执行     可写目录出现可执行文件 + 该路径进程运行 → 载荷落地并执行
R4 持久化闭环   可疑进程 + 持久化点被修改 → 攻击者建立驻留
R5 外联回连     高危进程 + 外部连接 → 反弹 shell / C2 通道
R6 隐藏痕迹     已删除可执行文件 + 内核模块异常 → 无文件攻击 / rootkit
R7 webshell     Web 目录出现 webshell 文件 + 访问日志命中同一文件 → 已落地并被访问
R8 中转沦陷     中转/端口转发进程 + 入站与出站同时存在 → 本机被当作跳板
R9 模型中转     模型网关对外提供接口并配置上游地址 + 存在外部流量 → 模型中转站
R10 模型爆破    模型登录大量失败后成功, 或中转进程在线时补全接口被打满
R11 密钥泄露    同一密钥指纹被多个来源用来调用模型接口
R12 清痕后落地  命令历史被清空/关闭, 且随后出现落地、反弹或 memfd 执行
R13 隐藏进程    ps 不可见的进程同时有已删除可执行文件或 rootkit 模块
R14 无文件执行  memfd 或解释器从标准输入执行, 且伴随外联或落地
R15 挖矿驻留    挖矿命令行同时有矿池外联, 或在可写目录落地
R16 伪装内核    用户态进程伪装成内核线程, 且有挖矿、落地或外联
============  ==============================================================
"""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from typing import Dict, List

from irtrace.analyzers.base import BaseAnalyzer
from irtrace.collectors.web_shell import same_web_file
from irtrace.core.models import Category, Confidence, Event, Finding, Severity
from irtrace.core.registry import register

#: 关联时间窗 (事件间隔超过该值则不关联)
CORRELATE_WINDOW = timedelta(minutes=30)


def _tags(event: Event) -> set:
    return set(event.tags or [])


def _model_relay(event: Event) -> bool:
    """专用网关, 或同时标了对外监听和上游地址。"""
    tags = _tags(event)
    if any(tag.startswith("model_gateway:") for tag in tags):
        return True
    return "model_listen" in tags and "model_upstream" in tags


@register
class CorrelationAnalyzer(BaseAnalyzer):
    name = "correlation"
    description = "跨源关联多信号形成攻击链结论 (爆破→登录→提权→持久化→回连)"

    def analyze(self, ctx) -> List[Finding]:
        findings: List[Finding] = []
        findings += self._r1_bruteforce_success(ctx)
        findings += self._r2_login_to_privesc(ctx)
        findings += self._r3_dropped_and_executed(ctx)
        findings += self._r4_persistence_chain(ctx)
        findings += self._r5_outbound_callback(ctx)
        findings += self._r6_fileless_rootkit(ctx)
        findings += self._r7_webshell_file_and_request(ctx)
        findings += self._r8_relay_pivot(ctx)
        findings += self._r9_model_relay(ctx)
        findings += self._r10_model_gateway_abuse(ctx)
        findings += self._r11_leaked_model_key(ctx)
        findings += self._r12_history_then_payload(ctx)
        findings += self._r13_hidden_process(ctx)
        findings += self._r14_fileless_exec(ctx)
        findings += self._r15_crypto_miner(ctx)
        findings += self._r16_kthread_masquerade(ctx)
        return findings

    # ------------------------------------------------------------------ #
    def _r1_bruteforce_success(self, ctx) -> List[Finding]:
        """R1: 同 IP 先大量失败后成功登录。"""
        out: List[Finding] = []
        failed: Dict[str, List[Event]] = defaultdict(list)
        for e in ctx.events:
            if e.action == "ssh_failed" and e.src_ip:
                failed[e.src_ip].append(e)

        for e in ctx.events:
            if e.action != "ssh_login" or not e.src_ip:
                continue
            fails = failed.get(e.src_ip, [])
            prior = [f for f in fails if e.timestamp and f.timestamp
                     and f.timestamp <= e.timestamp
                     and (e.timestamp - f.timestamp) <= timedelta(hours=1)]
            if len(prior) >= 5:
                out.append(self.finding(
                    title=f"疑似爆破成功: {e.src_ip} → {e.user}",
                    severity=Severity.CRITICAL,
                    category=Category.AUTH,
                    confidence=Confidence.HIGH,
                    mitre=["T1110", "T1078"],  # Brute Force / Valid Accounts
                    events=[*prior[-10:], e],
                    description=(
                        f"来自 {e.src_ip} 的地址在成功登录前 1 小时内有 {len(prior)} "
                        f"次失败记录, 高度疑似口令爆破成功并取得 {e.user} 账号。"
                    ),
                    details={"src_ip": e.src_ip, "user": e.user,
                             "failed_count": len(prior)},
                ))
        return out

    def _r2_login_to_privesc(self, ctx) -> List[Finding]:
        """R2: 可疑登录后紧接提权/建号。"""
        out: List[Finding] = []
        logins = [e for e in ctx.events if e.action in ("ssh_login", "session_active")]
        privesc = [e for e in ctx.events if e.action in
                   ("sudo", "user_added", "uid0_account", "sudo_rule",
                    "empty_password", "privileged_group_members")]
        for lg in logins:
            for pv in privesc:
                if not (lg.timestamp and pv.timestamp):
                    continue
                delta = pv.timestamp - lg.timestamp
                if timedelta(0) <= delta <= CORRELATE_WINDOW:
                    out.append(self.finding(
                        title=f"登录后提权: {lg.user or lg.src_ip} → {pv.action}",
                        severity=Severity.HIGH,
                        category=Category.ACCOUNT,
                        confidence=Confidence.MEDIUM,
                        mitre=["T1078", "T1548"],  # Valid Accounts / Abuse Elevation
                        events=[lg, pv],
                        description=(
                            f"登录事件 ({lg.action}, user={lg.user or '?'}) 之后 "
                            f"{int(delta.total_seconds() // 60)} 分钟内出现提权/账号变更行为 "
                            f"({pv.action}), 需核实是否为管理员正常操作。"
                        ),
                        details={"delta_seconds": int(delta.total_seconds())},
                    ))
        return out

    def _r3_dropped_and_executed(self, ctx) -> List[Finding]:
        """R3: 可写目录落地文件 + 同路径进程运行。"""
        out: List[Finding] = []
        dropped = {e.path: e for e in ctx.events
                   if e.action == "suspicious_file" and e.path
                   and e.path.startswith(("/tmp", "/dev/shm", "/var/tmp"))}
        running = [e for e in ctx.events if e.action == "process_suspicious" and e.path]

        for proc in running:
            for path, drop in dropped.items():
                if proc.path and (proc.path == path or path in proc.path):
                    out.append(self.finding(
                        title=f"载荷落地并执行: {path}",
                        severity=Severity.CRITICAL,
                        category=Category.PROCESS,
                        confidence=Confidence.HIGH,
                        mitre=["T1059", "T1204"],  # Command and Scripting / User Execution
                        events=[drop, proc],
                        description=(
                            f"文件 {path} 在可写目录落地, 且存在以该路径启动的进程 "
                            f"(PID={proc.pid}), 构成完整的「落地-执行」链路。"
                        ),
                        details={"path": path, "pid": proc.pid, "user": proc.user},
                    ))
        return out

    def _r4_persistence_chain(self, ctx) -> List[Finding]:
        """R4: 可疑进程/账号 + 持久化点变更。"""
        out: List[Finding] = []
        persist = [e for e in ctx.events if e.category == Category.PERSISTENCE
                   and ({"suspicious-content", "ssh-key", "cron-persistence",
                         "systemd-persistence", "boot-persistence"} & set(e.tags))]
        triggers = [e for e in ctx.events if {"suspicious-process", "backdoor-account",
                                              "uid0_account", "reverse_shell_pattern"}
                    & set(e.tags)]
        if triggers and persist:
            out.append(self.finding(
                title="疑似建立持久化驻留",
                severity=Severity.HIGH,
                category=Category.PERSISTENCE,
                confidence=Confidence.MEDIUM,
                mitre=["T1547", "T1053"],  # Boot/Logon Autostart, Scheduled Task
                events=[*triggers[:5], *persist[:10]],
                description=(
                    f"检测到 {len(triggers)} 个可疑进程/账号信号与 {len(persist)} 处"
                    f"持久化点变更同时出现, 疑似攻击者建立长期驻留。"
                ),
                details={"persistence_points": sorted({e.path for e in persist if e.path})},
            ))
        return out

    def _r5_outbound_callback(self, ctx) -> List[Finding]:
        """R5: 高危进程 + 外部连接。"""
        out: List[Finding] = []
        risky = [e for e in ctx.events if {"reverse_shell_pattern", "suspicious-process",
                                           "known_malware_name"} & set(e.tags)]
        conns = [e for e in ctx.events if e.action == "external_connection"]
        if risky and conns:
            peers = sorted({e.dst_ip for e in conns if e.dst_ip})
            out.append(self.finding(
                title=f"疑似反弹 Shell / C2 回连 ({len(peers)} 个外联目标)",
                severity=Severity.CRITICAL,
                category=Category.NETWORK,
                confidence=Confidence.MEDIUM,
                mitre=["T1071", "T1571", "T1059"],
                events=[*risky[:5], *conns[:15]],
                description=(
                    "存在反弹 shell 特征进程, 同时检测到外部连接, "
                    "疑似被控主机与 C2 建立通道。"
                ),
                details={"peers": peers,
                         "risky_processes": sorted({e.path for e in risky if e.path})},
            ))
        return out

    def _r6_fileless_rootkit(self, ctx) -> List[Finding]:
        """R6: 已删除可执行文件 + 内核异常。"""
        out: List[Finding] = []
        deleted = self.events_by_tag(ctx, "exe_deleted")
        kernel_anom = [e for e in ctx.events
                       if e.action in ("rootkit_module", "unknown_module", "ld_preload")]
        if deleted and kernel_anom:
            out.append(self.finding(
                title="疑似无文件攻击 / Rootkit",
                severity=Severity.CRITICAL,
                category=Category.KERNEL,
                confidence=Confidence.MEDIUM,
                mitre=["T1014", "T1027"],  # Rootkit / Obfuscated Files
                events=[*deleted[:5], *kernel_anom[:5]],
                description=(
                    "存在可执行文件已被删除但仍在运行的进程, 且内核模块存在异常, "
                    "符合无文件攻击或 rootkit 特征。"
                ),
                details={"deleted_exe_processes": [e.pid for e in deleted],
                         "kernel_anomalies": [e.message for e in kernel_anom]},
            ))
        return out

    def _r7_webshell_file_and_request(self, ctx) -> List[Finding]:
        """R7: 磁盘上的 webshell 文件与访问日志命中同一路径。"""
        out: List[Finding] = []
        files = [e for e in ctx.events if e.action == "web_shell_file" and e.path]
        requests = [e for e in ctx.events if e.action == "web_shell_request" and e.path]
        seen = set()
        for script in files:
            matched = [
                event for event in requests
                if same_web_file(event.path or "", script.path or "")
            ]
            if not matched or script.path in seen:
                continue
            seen.add(script.path)
            live = [
                event for event in matched
                if isinstance(event.raw, dict)
                and isinstance(event.raw.get("status"), int)
                and (200 <= event.raw["status"] < 300 or event.raw["status"] >= 500)
            ]
            used = live or matched
            out.append(self.finding(
                title=f"webshell 落地并被访问: {script.path}",
                severity=Severity.CRITICAL if live else Severity.HIGH,
                category=Category.FILE,
                confidence=Confidence.HIGH if live else Confidence.MEDIUM,
                mitre=["T1505.003", "T1105"],
                events=[script, *used[:5]],
                description=(
                    f"Web 目录文件 {script.path} 具有 webshell 特征, 且访问日志中"
                    f"有 {len(matched)} 次指向该文件的请求"
                    f"（其中 {len(live)} 次返回 2xx/5xx）。"
                ),
                details={
                    "path": script.path,
                    "request_count": len(matched),
                    "responded_count": len(live),
                    "src_ips": sorted({event.src_ip for event in used if event.src_ip}),
                },
            ))
        return out

    def _r8_relay_pivot(self, ctx) -> List[Finding]:
        """R8: 中转进程同时看到连入和连出, 说明流量经过本机。"""
        relays = [
            event for event in ctx.events
            if "relay" in _tags(event) or "port_forward" in _tags(event)
            or event.action == "relay_process"
        ]
        inbound = [
            event for event in ctx.events
            if event.action == "external_connection" and "inbound" in _tags(event)
        ]
        outbound = [
            event for event in ctx.events
            if event.action == "external_connection" and "outbound" in _tags(event)
        ]
        if not relays or not inbound or not outbound:
            return []
        clients = sorted({event.src_ip for event in inbound if event.src_ip})
        peers = sorted({event.dst_ip for event in outbound if event.dst_ip})
        return [self.finding(
            title="主机被用作中转/跳板",
            severity=Severity.CRITICAL,
            category=Category.NETWORK,
            confidence=Confidence.HIGH,
            mitre=["T1572", "T1090"],
            events=[*relays[:3], *inbound[:5], *outbound[:5]],
            description=(
                "存在端口转发或内网穿透进程, 同时有公网连入和对外连接, "
                "符合被控中转站特征。"
            ),
            details={
                "relay_processes": sorted({event.path or event.message for event in relays}),
                "clients": clients,
                "peers": peers,
            },
        )]

    def _r9_model_relay(self, ctx) -> List[Finding]:
        """R9: 对外模型接口 + 上游地址 + 外部流量。"""
        relays = [event for event in ctx.events if _model_relay(event)]
        traffic = [
            event for event in ctx.events
            if event.action == "external_connection"
            and ({"inbound", "outbound"} & _tags(event))
        ]
        if not relays or not traffic:
            return []
        peers = sorted({
            event.dst_ip or event.src_ip for event in traffic
            if event.dst_ip or event.src_ip
        })
        return [self.finding(
            title="模型中转站",
            severity=Severity.CRITICAL,
            category=Category.NETWORK,
            confidence=Confidence.HIGH,
            mitre=["T1090"],
            events=[*relays[:3], *traffic[:5]],
            description=(
                "进程对外提供模型接口并配置了上游地址, 同时存在外部连接, "
                "符合模型请求中转站特征。"
            ),
            details={
                "processes": sorted({event.path or event.message for event in relays}),
                "peers": peers,
            },
        )]

    def _r10_model_gateway_abuse(self, ctx) -> List[Finding]:
        """R10: 登录撞库成功, 或网关在线时补全接口被打满。"""
        out: List[Finding] = []
        fails = {event.src_ip: event for event in ctx.events
                 if event.action == "model_auth_failure" and event.src_ip}
        for event in ctx.events:
            if event.action != "model_auth_success" or event.src_ip not in fails:
                continue
            out.append(self.finding(
                title=f"模型中转站登录被爆破: {event.src_ip}",
                severity=Severity.CRITICAL,
                category=Category.AUTH,
                confidence=Confidence.HIGH,
                mitre=["T1110"],
                events=[fails[event.src_ip], event],
                description=(
                    f"{event.src_ip} 对模型登录接口大量失败后出现成功响应, "
                    "疑似撞库进入中转站。"
                ),
                details={"src_ip": event.src_ip},
            ))
        relays = [event for event in ctx.events if _model_relay(event)]
        abuse = [event for event in ctx.events if event.action == "model_abuse"]
        if relays and abuse:
            sources = sorted({event.src_ip for event in abuse if event.src_ip})
            out.append(self.finding(
                title="模型中转站配额被打野",
                severity=Severity.HIGH,
                category=Category.NETWORK,
                confidence=Confidence.MEDIUM,
                mitre=["T1496"],
                events=[*relays[:2], *abuse[:3]],
                description="中转站进程在线, 同时有来源把模型补全接口打满。",
                details={"sources": sources},
            ))
        return out

    def _r11_leaked_model_key(self, ctx) -> List[Finding]:
        """R11: 同一指纹出现在多个来源。结论里不回显密钥。"""
        out: List[Finding] = []
        for event in ctx.events:
            if event.action != "model_key_reuse":
                continue
            sources = list((event.raw or {}).get("sources") or [])
            if len(sources) < 2:
                continue
            fingerprint = (event.raw or {}).get("key_fp") or ""
            out.append(self.finding(
                title=f"模型密钥被多个来源使用: {fingerprint}",
                severity=Severity.CRITICAL,
                category=Category.AUTH,
                confidence=Confidence.HIGH,
                mitre=["T1552"],
                events=[event],
                description=(
                    f"密钥指纹 {fingerprint} 出现在 {len(sources)} 个来源的模型接口调用中, "
                    "符合密钥泄露后被他人使用。日志只保留指纹。"
                ),
                details={"key_fp": fingerprint, "sources": sources},
            ))
        return out

    def _r12_history_then_payload(self, ctx) -> List[Finding]:
        """R12: 清痕之后出现落地、反弹 shell 或 memfd。单独清空不报。"""
        wipes = [event for event in ctx.events if event.action == "history_wiped"]
        if not wipes:
            return []
        payloads = [
            event for event in ctx.events
            if event.action in ("suspicious_file", "process_suspicious", "relay_process")
            and (
                {"reverse_shell_pattern", "memfd_exec", "fileless_exec",
                 "exe_deleted", "known_malware_name"} & _tags(event)
                or (event.path or "").startswith(("/tmp", "/dev/shm", "/var/tmp"))
            )
        ]
        if not payloads:
            return []
        return [self.finding(
            title="清痕后出现落地或无文件执行",
            severity=Severity.HIGH,
            category=Category.FILE,
            confidence=Confidence.MEDIUM,
            mitre=["T1070.003", "T1059"],
            events=[*wipes[:3], *payloads[:5]],
            description=(
                "命令历史被清空或关闭, 同时存在落地文件、反弹 shell 或 memfd 执行。"
            ),
            details={"wiped": [event.path for event in wipes if event.path]},
        )]

    def _r13_hidden_process(self, ctx) -> List[Finding]:
        """R13: ps 看不到的进程, 再配上已删除可执行文件或 rootkit 模块。"""
        hidden = [event for event in ctx.events if event.action == "hidden_process"]
        if not hidden:
            return []
        support = [
            event for event in ctx.events
            if event.action in ("rootkit_module", "unknown_module", "ld_preload")
            or "exe_deleted" in _tags(event)
            or "memfd_exec" in _tags(event)
        ]
        if not support:
            return []
        return [self.finding(
            title="隐藏进程配合 rootkit 或无文件痕迹",
            severity=Severity.CRITICAL,
            category=Category.PROCESS,
            confidence=Confidence.HIGH,
            mitre=["T1014", "T1564.001"],
            events=[*hidden[:5], *support[:5]],
            description=(
                f"{len(hidden)} 个进程在 /proc 中存在但 ps 不可见, "
                "同时有已删除可执行文件、memfd 或异常内核模块。"
            ),
            details={"pids": [event.pid for event in hidden]},
        )]

    def _r14_fileless_exec(self, ctx) -> List[Finding]:
        """R14: memfd 或 stdin 执行, 且有外联或可写目录落地。"""
        fileless = [
            event for event in ctx.events
            if {"memfd_exec", "fileless_exec"} & _tags(event)
        ]
        if not fileless:
            return []
        support = [
            event for event in ctx.events
            if event.action == "external_connection"
            or (
                event.action == "suspicious_file"
                and (event.path or "").startswith(("/tmp", "/dev/shm", "/var/tmp"))
            )
        ]
        if not support:
            return []
        return [self.finding(
            title="无文件执行并伴随外联或落地",
            severity=Severity.CRITICAL,
            category=Category.PROCESS,
            confidence=Confidence.HIGH,
            mitre=["T1620", "T1059"],
            events=[*fileless[:3], *support[:5]],
            description="进程从 memfd 或标准输入执行, 同时存在外部连接或可写目录文件。",
            details={"paths": sorted({event.path for event in fileless if event.path})},
        )]


    def _r15_crypto_miner(self, ctx) -> List[Finding]:
        """R15: 挖矿命令行再配上矿池连接或可写目录落地。单独命令行不报。"""
        miners = [
            event for event in ctx.events
            if "crypto_miner" in _tags(event)
        ]
        if not miners:
            return []
        support = [
            event for event in ctx.events
            if event.action == "external_connection"
            or (
                event.action == "suspicious_file"
                and (event.path or "").startswith(("/tmp", "/dev/shm", "/var/tmp"))
            )
        ]
        if not support:
            return []
        return [self.finding(
            title="挖矿进程配合矿池连接或落地文件",
            severity=Severity.CRITICAL,
            category=Category.PROCESS,
            confidence=Confidence.HIGH,
            mitre=["T1496"],
            events=[*miners[:3], *support[:5]],
            description="进程命令行含矿池协议或 xmrig 参数, 同时存在外部连接或可写目录文件。",
            details={"paths": sorted({event.path for event in miners if event.path})},
        )]

    def _r16_kthread_masquerade(self, ctx) -> List[Finding]:
        """R16: 伪装内核线程, 再配上挖矿、落地或外联。单独伪装由失陷分覆盖。"""
        fake = [
            event for event in ctx.events
            if "kthread_masquerade" in _tags(event)
        ]
        if not fake:
            return []
        fake_ids = {id(event) for event in fake}
        support = [
            event for event in ctx.events
            if id(event) not in fake_ids and (
                "crypto_miner" in _tags(event)
                or event.action == "external_connection"
                or (
                    event.action == "suspicious_file"
                    and (event.path or "").startswith(("/tmp", "/dev/shm", "/var/tmp"))
                )
            )
        ]
        if not support:
            return []
        return [self.finding(
            title="伪装内核线程并伴随挖矿、落地或外联",
            severity=Severity.CRITICAL,
            category=Category.PROCESS,
            confidence=Confidence.HIGH,
            mitre=["T1036.005", "T1036"],
            events=[*fake[:3], *support[:5]],
            description="进程名伪装成内核线程但可执行文件非空, 同时存在挖矿、落地或外部连接。",
            details={"pids": [event.pid for event in fake]},
        )]


__all__ = ["CorrelationAnalyzer"]
