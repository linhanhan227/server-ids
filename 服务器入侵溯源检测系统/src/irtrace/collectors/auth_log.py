"""认证日志采集器。

覆盖:
- ``/var/log/auth.log`` (Debian/Ubuntu) 或 ``/var/log/secure`` (RHEL/CentOS)
- ``/var/log/wtmp`` / ``btmp`` / ``lastlog`` (经 ``last`` / ``lastb``)
- SSH 暴力破解特征 (短时间内大量 Failed password)
- 成功登录、sudo 提权、新建用户、会话开启
"""

from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Optional

from irtrace.collectors.base import BaseCollector
from irtrace.core.models import Category, Event
from irtrace.core.plugin import CollectResult
from irtrace.core.registry import register
from irtrace.utils.timeutil import parse_timestamp

# 当前日志在前, 轮转日志在后; 历史日志决定能否还原跨天的爆破与登录链。
_LOG_CANDIDATES = (
    "/var/log/auth.log", "/var/log/secure",
    "/var/log/auth.log.1", "/var/log/secure.1",
    "/var/log/auth.log.2", "/var/log/secure.2",
)

# 关键行模式
_PATTERNS = {
    "ssh_failed": re.compile(r"Failed password for (?:invalid user )?(\S+) from ([\d.]+)"),
    "ssh_accepted": re.compile(r"Accepted (\S+) for (\S+) from ([\d.]+)"),
    "invalid_user": re.compile(r"Invalid user (\S+) from ([\d.]+)"),
    "sudo": re.compile(r"sudo:\s+(\S+)\s*:.*?COMMAND=(.*)"),
    "su": re.compile(r"su(?:do)?:\s+.*?session opened for user (\S+)"),
    "new_user": re.compile(r"useradd.*?: new user: name=(\S+)"),
    "session_open": re.compile(r"session opened for user (\S+)"),
}


@register
class AuthLogCollector(BaseCollector):
    name = "auth_log"
    description = "解析认证日志 (auth.log/secure/wtmp/btmp), 提取登录、sudo、暴力破解"
    category = Category.AUTH
    requires_paths = list(_LOG_CANDIDATES) + ["/var/log"]

    def collect(self, ctx) -> CollectResult:
        res = CollectResult()
        parsed_logs = 0
        for log_path in _LOG_CANDIDATES:
            if not ctx.exists(log_path):
                continue
            raw = ctx.read_file(log_path)
            if not raw:
                continue
            parsed_logs += 1
            safe_name = log_path.strip("/").replace("/", "__")
            res.evidence.append(
                self.evidence_from_text(ctx, f"{safe_name}.txt", raw, path=log_path,
                                        note="认证日志原始内容")
            )
            self._parse_auth_log(ctx, res, raw)
        res.stats["auth_logs"] = parsed_logs

        # wtmp / btmp 通过 last / lastb 采集
        if ctx.which("last"):
            out = ctx.run_command(["last", "-Faiw"])
            if out:
                res.evidence.append(self.evidence_from_text(ctx, "last.txt", out,
                                                            note="登录会话记录"))
                self._parse_last(ctx, res, out)
        if ctx.which("lastb"):
            out = ctx.run_command(["lastb", "-Faiw"])
            if out:
                res.evidence.append(self.evidence_from_text(ctx, "lastb.txt", out,
                                                            note="失败登录记录"))
                self._detect_bruteforce(ctx, res, out)

        return res

    # ------------------------------------------------------------------ #
    def _parse_auth_log(self, ctx, res: CollectResult, raw: str) -> None:
        failed_by_ip: Dict[str, List[datetime]] = defaultdict(list)

        for line in raw.splitlines():
            ts = parse_timestamp(line[:15])  # syslog 前缀 "Oct 12 19:59:55"
            for key, pattern in _PATTERNS.items():
                m = pattern.search(line)
                if not m:
                    continue
                if key == "ssh_failed":
                    user, ip = m.group(1), m.group(2)
                    res.events.append(self.event(
                        ctx, action="ssh_failed", timestamp=ts, user=user, src_ip=ip,
                        message=f"SSH 登录失败 user={user} from {ip}",
                        tags=["auth-failure"],
                    ))
                    if ts:
                        failed_by_ip[ip].append(ts)
                elif key == "ssh_accepted":
                    method, user, ip = m.group(1), m.group(2), m.group(3)
                    res.events.append(self.event(
                        ctx, action="ssh_login", timestamp=ts, user=user, src_ip=ip,
                        message=f"SSH 登录成功 user={user} from {ip} ({method})",
                        tags=["auth-success"],
                    ))
                elif key == "invalid_user":
                    res.events.append(self.event(
                        ctx, action="invalid_user", timestamp=ts, user=m.group(1),
                        src_ip=m.group(2),
                        message=f"无效用户尝试 user={m.group(1)} from {m.group(2)}",
                        tags=["auth-failure", "user-enum"],
                    ))
                elif key == "sudo":
                    res.events.append(self.event(
                        ctx, action="sudo", timestamp=ts, user=m.group(1),
                        message=f"sudo 提权 {m.group(1)}: {m.group(2).strip()}",
                        tags=["privilege-escalation"],
                        raw={"command": m.group(2).strip()},
                    ))
                elif key == "new_user":
                    res.events.append(self.event(
                        ctx, action="user_added", timestamp=ts, user=m.group(1),
                        message=f"新建系统账号 {m.group(1)}",
                        tags=["account-created"],
                    ))
                break

        # 暴力破解: 同一 IP 短时间内 >= 10 次失败
        for ip, times in failed_by_ip.items():
            times.sort()
            if len(times) >= 10:
                res.events.append(self.event(
                    ctx, action="bruteforce_suspected",
                    timestamp=times[-1], src_ip=ip,
                    message=f"疑似暴力破解: {ip} 共 {len(times)} 次失败登录",
                    tags=["bruteforce"],
                    raw={"count": len(times), "first": times[0].isoformat(),
                         "last": times[-1].isoformat()},
                ))

    def _parse_last(self, ctx, res: CollectResult, out: str) -> None:
        for line in out.splitlines():
            if not line.strip() or line.startswith(("wtmp", "btmp")):
                continue
            parts = line.split()
            if len(parts) < 3:
                continue
            user = parts[0]
            # 采集 still logged in 的会话
            if "still" in line and "logged in" in line:
                res.events.append(self.event(
                    ctx, action="session_active", user=user,
                    message=f"当前活动会话 user={user} ({line.strip()})",
                    tags=["active-session"],
                ))

    def _detect_bruteforce(self, ctx, res: CollectResult, out: str) -> None:
        count = sum(1 for ln in out.splitlines() if ln.strip() and not ln.startswith("btmp"))
        if count:
            res.stats["failed_logins"] = count


__all__ = ["AuthLogCollector"]
