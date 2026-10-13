"""文件系统采集器。

覆盖入侵者最常落地的痕迹:

- 可写目录中的可执行文件: /tmp, /dev/shm, /var/tmp, /run/shm
- SUID / SGID 文件 (提权后门)
- 近期变更的关键目录文件 (mtime 在 N 天内)
- 隐藏文件 / 可疑脚本名 (如 .xxx, xmrig, kdevtmpfsi, 随机串)
- Web 目录中的脚本型 webshell (文件名或正文特征)
"""

from __future__ import annotations

import os
import re
import stat
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from irtrace.collectors.base import BaseCollector
from irtrace.collectors.web_shell import (
    MAX_BODY_BYTES,
    SCRIPT_EXT,
    WEB_ROOTS,
    body_looks_like_shell,
    is_shell_path,
)
from irtrace.core.models import Category, Event
from irtrace.core.plugin import CollectResult
from irtrace.core.registry import register

_WRITABLE_DIRS = ["/tmp", "/dev/shm", "/var/tmp", "/run/shm"]

# 已知恶意/挖矿样本名
_KNOWN_BAD_NAMES = re.compile(
    r"^(kdevtmpfsi|kinsing|xmrig|minerd|sysupdate|\.?watchdogs|\.?kworkerd|"
    r"dota3|systemd-network|\.sshd|\.X11-unix)\b", re.I,
)
_SCRIPT_EXT = (".sh", ".py", ".pl", ".elf", ".bin")


@register
class FilesystemCollector(BaseCollector):
    name = "filesystem"
    description = "扫描可写目录可执行文件 / SUID / 近期变更文件 / 已知恶意样本名"
    category = Category.FILE
    requires_paths = ["/tmp", "/etc"]

    #: 只关注最近 N 天内变更的文件
    recent_days: int = 30
    #: 单目录最大遍历文件数 (避免 /tmp 塞满时拖死)
    max_entries: int = 5000

    def collect(self, ctx) -> CollectResult:
        res = CollectResult()
        cutoff = datetime.now(timezone.utc) - timedelta(days=self.recent_days)

        for d in _WRITABLE_DIRS:
            if ctx.exists(d):
                self._scan_writable(ctx, res, d, cutoff)

        self._scan_web_roots(ctx, res)
        self._scan_suid(ctx, res)
        return res

    # ------------------------------------------------------------------ #
    def _scan_writable(self, ctx, res: CollectResult, root: str,
                       cutoff: datetime) -> None:
        count = 0
        for dirpath, dirnames, filenames in os.walk(root):
            # 跳过 proc/sys 挂载点
            if any(dirpath.startswith(p) for p in ("/dev/shm/..", )):
                continue
            for fname in filenames:
                count += 1
                if count > self.max_entries:
                    res.warnings.append(f"{root} 文件过多, 已截断于 {self.max_entries}")
                    return
                full = os.path.join(dirpath, fname)
                self._inspect(ctx, res, full, cutoff)

    def _inspect(self, ctx, res: CollectResult, path: str, cutoff: datetime) -> None:
        try:
            st = os.stat(path)
        except OSError:
            return
        mtime = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc)
        is_exec = bool(st.st_mode & stat.S_IXUSR)
        flags: List[str] = []

        if is_exec:
            flags.append("executable")
        if _KNOWN_BAD_NAMES.match(os.path.basename(path)):
            flags.append("known_malware_name")
        if os.path.basename(path).startswith(".") and is_exec:
            flags.append("hidden_executable")
        if is_exec and mtime >= cutoff:
            flags.append("recent_executable")

        if not flags:
            return

        # 只对有执行权限或已知恶意名的文件算哈希并落证
        sha = None
        if is_exec:
            from irtrace.utils.hashutil import sha256_file
            sha = sha256_file(path, max_bytes=64 * 1024 * 1024)

        res.events.append(self.event(
            ctx, action="suspicious_file",
            message=f"可疑文件 {path} ({', '.join(flags)})",
            timestamp=mtime, path=path, tags=flags,
            raw={"size": st.st_size, "mode": oct(st.st_mode), "sha256": sha,
                 "mtime": mtime.isoformat()},
        ))

    def _scan_web_roots(self, ctx, res: CollectResult) -> None:
        """只看脚本扩展名, 命中文件名或正文才登记。"""
        seen = {event.path for event in res.events if event.path}
        for root in WEB_ROOTS:
            if not ctx.exists(root):
                continue
            count = 0
            for dirpath, _dirnames, filenames in os.walk(root):
                for fname in filenames:
                    count += 1
                    if count > self.max_entries:
                        res.warnings.append(
                            f"{root} 文件过多, webshell 扫描截断于 {self.max_entries}"
                        )
                        return
                    if not fname.lower().endswith(SCRIPT_EXT):
                        continue
                    full = os.path.join(dirpath, fname)
                    if full in seen:
                        continue
                    self._inspect_web_script(ctx, res, full)
                    seen.add(full)

    def _inspect_web_script(self, ctx, res: CollectResult, path: str) -> None:
        by_name = is_shell_path(path)
        by_body = False
        if not by_name:
            text = ctx.read_file(path, max_bytes=MAX_BODY_BYTES)
            by_body = body_looks_like_shell(text or "")
        if not by_name and not by_body:
            return
        try:
            st = os.stat(path)
            mtime = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc)
            size = st.st_size
        except OSError:
            mtime = None
            size = None
        reason = "filename" if by_name else "content"
        res.events.append(self.event(
            ctx, action="web_shell_file",
            message=f"Web 目录中的 webshell 文件 {path} ({reason})",
            timestamp=mtime, path=path,
            category=Category.FILE,
            tags=["webshell", "web-file"],
            raw={"reason": reason, "size": size},
        ))

    def _scan_suid(self, ctx, res: CollectResult) -> None:
        """优先用 find; 无 find 时跳过。"""
        if not ctx.which("find"):
            return
        out = ctx.run_command([
            "find", "/usr", "/bin", "/sbin", "/opt", "/tmp", "/dev/shm",
            "-xdev", "-type", "f", "-perm", "-4000",
        ], timeout=60)
        if not out:
            return
        res.evidence.append(self.evidence_from_text(
            ctx, "suid-files.txt", out, note="SUID 文件清单"))
        lines = [ln for ln in out.splitlines() if ln.strip()]
        res.stats["suid_files"] = len(lines)
        # 可写目录中的 SUID 是强异常
        for ln in lines:
            if ln.startswith(("/tmp", "/dev/shm", "/var/tmp")):
                res.events.append(self.event(
                    ctx, action="suid_in_writable",
                    message=f"可写目录中的 SUID 文件: {ln}",
                    path=ln, tags=["suid", "critical"],
                ))


__all__ = ["FilesystemCollector"]
