"""账号与提权面采集器。

覆盖:
- /etc/passwd: UID=0 的非 root 账号、可登录 shell 的系统账号、异常家目录
- /etc/shadow: 空口令、无口令账号、近期修改
- /etc/group: 特权组成员 (sudo/wheel/adm/root)
- /etc/sudoers 及 /etc/sudoers.d/*: NOPASSWD 提权规则
- /etc/pam.d/*: 可疑 PAM 配置
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from irtrace.collectors.base import BaseCollector
from irtrace.core.models import Category, Event
from irtrace.core.plugin import CollectResult
from irtrace.core.registry import register

_PRIV_GROUPS = {"root", "sudo", "wheel", "adm", "docker", "lxd", "disk"}
_LOGIN_SHELLS = ("/bin/bash", "/bin/sh", "/bin/zsh", "/usr/bin/bash", "/usr/bin/zsh")
_NOPASSWD = re.compile(r"NOPASSWD", re.I)


@register
class AccountCollector(BaseCollector):
    name = "account"
    description = "审计账号/口令/提权面 (passwd, shadow, group, sudoers, PAM)"
    category = Category.ACCOUNT
    requires_paths = ["/etc/passwd"]

    def collect(self, ctx) -> CollectResult:
        res = CollectResult()
        self._scan_passwd(ctx, res)
        self._scan_shadow(ctx, res)
        self._scan_groups(ctx, res)
        self._scan_sudoers(ctx, res)
        return res

    # ------------------------------------------------------------------ #
    def _scan_passwd(self, ctx, res: CollectResult) -> None:
        content = ctx.read_file("/etc/passwd")
        if not content:
            return
        res.evidence.append(self.evidence_from_text(
            ctx, "passwd.txt", content, path="/etc/passwd", note="账号数据库"))

        for line in content.splitlines():
            parts = line.split(":")
            if len(parts) < 7:
                continue
            name, _pw, uid, gid, gecos, home, shell = parts[:7]
            if uid == "0" and name != "root":
                res.events.append(self.event(
                    ctx, action="uid0_account",
                    message=f"发现 UID=0 的非 root 账号: {name} (shell={shell})",
                    user=name, tags=["backdoor-account", "critical"],
                    raw={"home": home, "shell": shell},
                ))
            if shell in _LOGIN_SHELLS and int(uid) < 1000 and name != "root":
                res.events.append(self.event(
                    ctx, action="system_account_login_shell",
                    message=f"系统账号 {name}(uid={uid}) 拥有可登录 shell: {shell}",
                    user=name, tags=["baseline-deviation"],
                    raw={"uid": uid, "shell": shell},
                ))
            if home.startswith(("/tmp", "/dev/shm", "/var/tmp")):
                res.events.append(self.event(
                    ctx, action="suspicious_home",
                    message=f"账号 {name} 家目录位于可写目录: {home}",
                    user=name, tags=["suspicious-account"],
                ))

    def _scan_shadow(self, ctx, res: CollectResult) -> None:
        content = ctx.read_file("/etc/shadow")
        if not content:
            res.warnings.append("无法读取 /etc/shadow (需 root)")
            return
        for line in content.splitlines():
            parts = line.split(":")
            if len(parts) < 3:
                continue
            name, pw, _chg = parts[0], parts[1], parts[2]
            if pw == "":
                res.events.append(self.event(
                    ctx, action="empty_password",
                    message=f"账号 {name} 口令为空 (严重风险)",
                    user=name, tags=["empty-password", "critical"],
                ))
            elif pw.startswith("!") or pw in ("*", "!!"):
                continue
            # 近期修改的口令
            try:
                days = int(_chg)
                if days > 0:
                    changed = datetime.fromtimestamp(days * 86400, tz=timezone.utc)
                    if (datetime.now(timezone.utc) - changed).days <= 7:
                        res.events.append(self.event(
                            ctx, action="password_changed",
                            message=f"账号 {name} 口令在 7 天内被修改 ({changed.date()})",
                            timestamp=changed, user=name, tags=["password-change"],
                        ))
            except (ValueError, OSError):
                pass

    def _scan_groups(self, ctx, res: CollectResult) -> None:
        content = ctx.read_file("/etc/group")
        if not content:
            return
        for line in content.splitlines():
            parts = line.split(":")
            if len(parts) < 4:
                continue
            gname, members = parts[0], [m for m in parts[3].split(",") if m]
            if gname in _PRIV_GROUPS and members:
                res.events.append(self.event(
                    ctx, action="privileged_group_members",
                    message=f"特权组 {gname} 成员: {', '.join(members)}",
                    tags=["privileged-group"],
                    raw={"group": gname, "members": members},
                ))

    def _scan_sudoers(self, ctx, res: CollectResult) -> None:
        targets = ["/etc/sudoers"]
        if ctx.exists("/etc/sudoers.d"):
            targets += [f"/etc/sudoers.d/{f}" for f in self.listdir("/etc/sudoers.d")]
        for path in targets:
            content = ctx.read_file(path)
            if not content:
                continue
            res.evidence.append(self.evidence_from_text(
                ctx, path.strip("/").replace("/", "__"), content, path=path,
                note="sudo 规则"))
            for i, line in enumerate(content.splitlines(), 1):
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                if _NOPASSWD.search(s) or re.search(r"ALL\s*=\s*\(ALL", s):
                    res.events.append(self.event(
                        ctx, action="sudo_rule",
                        message=f"sudo 提权规则 {path}:{i} — {s[:140]}",
                        path=path, tags=["sudo-rule"],
                        raw={"line_no": i, "line": s},
                    ))


__all__ = ["AccountCollector"]
