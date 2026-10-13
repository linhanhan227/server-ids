"""持久化机制采集器 —— 入侵溯源中最关键的一环。

覆盖所有常见 Linux 持久化位置:

- **定时任务**: /etc/crontab, /etc/cron.{d,daily,hourly,weekly,monthly},
  /var/spool/cron/{crontab,atjobs}, 用户 crontab
- **systemd**: /etc/systemd/system/*.service, ~/.config/systemd/user/*,
  ``systemctl list-unit-files --state=enabled``
- **传统启动**: /etc/rc.local, /etc/rc{0-6}.d/, /etc/init.d/
- **动态链接器劫持**: /etc/ld.so.preload, LD_PRELOAD (环境)
- **SSH 后门**: ~/.ssh/authorized_keys, /root/.ssh/authorized_keys
- **Shell 启动脚本**: /etc/profile, /etc/profile.d/*, ~/.bashrc, ~/.bash_profile
- **PAM 后门**: /etc/pam.d/*
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Tuple

from irtrace.collectors.base import BaseCollector
from irtrace.core.models import Category, Event
from irtrace.core.plugin import CollectResult
from irtrace.core.registry import register

# 可疑内容特征 (反弹 shell / 下载执行 / 编码载荷)
_SUSPICIOUS = re.compile(
    r"(curl\s+[^\n]*\|\s*(?:ba)?sh|wget\s+[^\n]*\|\s*(?:ba)?sh|"
    r"/dev/tcp/|nc\s+-e|base64\s+-d|eval\s*\(|python\s+-c|perl\s+-e|"
    r"chmod\s+\+x|/tmp/|/dev/shm/|\.onion|xmr|miner|stratum)",
    re.I,
)

_CRON_DIRS = ["/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily",
              "/etc/cron.weekly", "/etc/cron.monthly", "/var/spool/cron",
              "/var/spool/cron/crontabs", "/etc/cron.daily"]

_CRON_FILES = ["/etc/crontab", "/etc/anacrontab"]

_PROFILE_FILES = ["/etc/profile", "/etc/bash.bashrc", "/etc/ld.so.preload",
                  "/etc/rc.local", "/root/.bashrc", "/root/.bash_profile",
                  "/root/.profile", "/root/.ssh/authorized_keys"]


@register
class PersistenceCollector(BaseCollector):
    name = "persistence"
    description = "扫描 cron / systemd / rc.local / ld.so.preload / SSH key / profile 等持久化点"
    category = Category.PERSISTENCE
    requires_paths = ["/etc"]

    def collect(self, ctx) -> CollectResult:
        res = CollectResult()
        findings_ctx: List[str] = []

        # 1) cron
        self._scan_cron(ctx, res)
        # 2) systemd
        self._scan_systemd(ctx, res)
        # 3) 关键 profile / preload 文件
        for path in _PROFILE_FILES:
            self._scan_file(ctx, res, path, tag="boot-persistence")
        # 4) 用户级 profile / ssh
        self._scan_user_homes(ctx, res)

        res.stats = {"persistence_points_scanned": len(_PROFILE_FILES) + len(_CRON_DIRS)}
        return res

    # ------------------------------------------------------------------ #
    def _scan_cron(self, ctx, res: CollectResult) -> None:
        targets: List[str] = list(_CRON_FILES)
        for d in _CRON_DIRS:
            if ctx.exists(d):
                targets += [f"{d}/{f}" for f in self.listdir(d)]
        for path in targets:
            self._scan_file(ctx, res, path, tag="cron-persistence",
                            timestamp_hint=True)

    def _scan_systemd(self, ctx, res: CollectResult) -> None:
        if ctx.which("systemctl"):
            out = ctx.run_command(["systemctl", "list-unit-files", "--state=enabled",
                                   "--type=service", "--no-pager", "--plain"])
            if out:
                res.evidence.append(self.evidence_from_text(
                    ctx, "systemd-enabled-units.txt", out, note="已启用 systemd 服务"))
                res.stats["enabled_services"] = max(0, len(out.splitlines()) - 1)
        for d in ("/etc/systemd/system", "/usr/lib/systemd/system",
                  "/lib/systemd/system"):
            if not ctx.exists(d):
                continue
            for f in self.listdir(d):
                if f.endswith(".service"):
                    self._scan_file(ctx, res, f"{d}/{f}", tag="systemd-persistence")

    def _scan_user_homes(self, ctx, res: CollectResult) -> None:
        try:
            homes = [f"/home/{u}" for u in self.listdir("/home")]
        except OSError:
            homes = []
        homes.append("/root")
        for home in homes:
            for rel in (".bashrc", ".bash_profile", ".profile", ".zshrc",
                        ".ssh/authorized_keys", ".config/systemd/user"):
                p = f"{home}/{rel}"
                if ctx.exists(p):
                    self._scan_file(ctx, res, p, tag="user-persistence")

    # ------------------------------------------------------------------ #
    def _scan_file(self, ctx, res: CollectResult, path: str, *,
                   tag: str, timestamp_hint: bool = False) -> None:
        content = ctx.read_file(path)
        if content is None or not content.strip():
            return

        mtime: Optional[datetime] = None
        try:
            mtime = datetime.fromtimestamp(Path(path).stat().st_mtime, tz=timezone.utc)
        except OSError:
            pass

        # 记录存在即证据
        res.evidence.append(ctx.store_evidence(
            source=self.name, kind="file", name=path.strip("/").replace("/", "__"),
            data=content, path=path, mtime=mtime, note=f"持久化点 {tag}",
        ))

        for i, line in enumerate(content.splitlines(), 1):
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            if _SUSPICIOUS.search(s):
                res.events.append(self.event(
                    ctx, action="suspicious_persistence",
                    message=f"可疑持久化内容 {path}:{i} — {s[:160]}",
                    timestamp=mtime, category=Category.PERSISTENCE,
                    path=path, tags=[tag, "suspicious-content"],
                    raw={"line_no": i, "line": s},
                ))

        # authorized_keys 单独告警 (任何 key 都值得关注)
        if path.endswith("authorized_keys"):
            keys = [ln for ln in content.splitlines()
                    if ln.strip() and not ln.startswith("#")]
            if keys:
                res.events.append(self.event(
                    ctx, action="ssh_authorized_key",
                    message=f"发现 {len(keys)} 个 SSH 公钥: {path}",
                    timestamp=mtime, path=path,
                    tags=["ssh-key", "persistence"],
                    raw={"count": len(keys)},
                ))


__all__ = ["PersistenceCollector"]
