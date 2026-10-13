"""命令历史采集器 —— 只看攻击者事后清痕的痕迹。

对照 Sigma 的 T1070.003（Clear Command History）与 rkhunter 对
HISTFILE 的检查。正常的长历史不当成事件；只有下面三类才登记：

- ``.bash_history`` / ``.zsh_history`` 存在但没有命令，且 mtime 比同目录的 shell 启动脚本新
- 启动脚本里把 ``HISTFILE`` 指到 ``/dev/null``，或把 ``HISTSIZE`` 设成 0
- 启动脚本里有截断或删除历史文件的命令

单独一条清空不够跨过失陷阈值，要和登录、落地等阶段一起看。
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from irtrace.collectors.base import BaseCollector
from irtrace.core.models import Category
from irtrace.core.plugin import CollectResult
from irtrace.core.registry import register

_HISTORY_NAMES = (".bash_history", ".zsh_history", ".sh_history")
_PROFILE_NAMES = (".bashrc", ".bash_profile", ".profile", ".zshrc")

# 把历史关掉或写进黑洞。赋值两侧允许空格。
_DISABLE = re.compile(
    r"""(?ix)
    (?:^|\n)\s*(?:export\s+)?
    (?:
        HISTFILE\s*=\s*['\"]?/dev/null['\"]?
        | HISTSIZE\s*=\s*['\"]?0['\"]?\b
        | HISTFILESIZE\s*=\s*['\"]?0['\"]?\b
    )
    """
)

# 直接把历史文件截断。unset HISTFILE 太常见，不单独算。
_WIPE = re.compile(
    r"""(?ix)
    (?:history\s+-c\b)
    | (?:(?:^|[|&;])\s*>\s*~/?\.bash_history)
    | (?:rm\s+-f\s+[^\n]*\.bash_history)
    | (?:cat\s+/dev/null\s*>\s*[^\n]*history)
    | (?:truncate\s+-s\s*0\s+[^\n]*history)
    """
)


@register
class CommandHistoryCollector(BaseCollector):
    name = "command_history"
    description = "检查 shell 历史被清空或被启动脚本关闭（T1070.003）"
    category = Category.FILE
    requires_paths = ["/root", "/home", "/etc"]

    def collect(self, ctx) -> CollectResult:
        res = CollectResult()
        homes = self._homes(ctx)
        wiped = 0
        for home in homes:
            wiped += self._scan_home(ctx, res, home)
        wiped += self._scan_global(ctx, res)
        res.stats = {"homes": len(homes), "history_wiped": wiped}
        return res

    # ------------------------------------------------------------------ #
    def _homes(self, ctx) -> List[str]:
        homes = ["/root"] if ctx.exists("/root") else []
        if ctx.exists("/home"):
            homes += [f"/home/{name}" for name in self.listdir("/home")]
        return homes

    def _scan_home(self, ctx, res: CollectResult, home: str) -> int:
        wiped = 0
        history_files = [
            f"{home}/{name}" for name in _HISTORY_NAMES if ctx.exists(f"{home}/{name}")
        ]
        profile_mtime = self._newest_mtime(
            f"{home}/{name}" for name in _PROFILE_NAMES if ctx.exists(f"{home}/{name}")
        )
        for path in history_files:
            content = ctx.read_file(path, max_bytes=256 * 1024)
            if content is None:
                continue
            # 新账号的空历史比启动脚本更旧，不算清痕。
            mtime = _mtime(path)
            if _command_lines(content):
                continue
            if mtime is None or profile_mtime is None or mtime <= profile_mtime:
                continue
            self._emit(ctx, res, path, "truncated_after_profile", mtime, home)
            wiped += 1

        for name in _PROFILE_NAMES:
            path = f"{home}/{name}"
            content = ctx.read_file(path, max_bytes=64 * 1024)
            if content and _DISABLE.search(content):
                self._emit(ctx, res, path, "histfile_disabled", _mtime(path), home)
                wiped += 1
            if content and _WIPE.search(content):
                self._emit(ctx, res, path, "wipe_command", _mtime(path), home)
                wiped += 1
        return wiped

    def _scan_global(self, ctx, res: CollectResult) -> int:
        wiped = 0
        for path in ("/etc/bash.bashrc", "/etc/profile", "/etc/skel/.bashrc"):
            content = ctx.read_file(path, max_bytes=64 * 1024)
            if content and _DISABLE.search(content):
                self._emit(ctx, res, path, "histfile_disabled", _mtime(path), "")
                wiped += 1
        return wiped

    def _emit(self, ctx, res, path: str, reason: str, mtime, home: str) -> None:
        res.events.append(self.event(
            ctx, action="history_wiped",
            message=f"命令历史被清理或关闭: {path} ({reason})",
            timestamp=mtime, path=path,
            tags=["defense-evasion", "history-wipe", reason],
            raw={"reason": reason, "home": home},
        ))

    @staticmethod
    def _newest_mtime(paths) -> Optional[datetime]:
        newest: Optional[datetime] = None
        for path in paths:
            stamp = _mtime(path)
            if stamp and (newest is None or stamp > newest):
                newest = stamp
        return newest


def _command_lines(content: str) -> List[str]:
    """去掉空行、注释和 zsh 的时间戳行。"""
    lines = []
    for line in content.splitlines():
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        if re.match(r":\s*\d+:\d+;", text):
            continue
        lines.append(text)
    return lines


def _mtime(path: str) -> Optional[datetime]:
    try:
        return datetime.fromtimestamp(Path(path).stat().st_mtime, tz=timezone.utc)
    except OSError:
        return None


__all__ = ["CommandHistoryCollector"]
