"""隐藏进程采集器 —— chkrootkit 的 chkproc 思路。

``/proc`` 里有数字目录，但 ``ps`` 列不出来，常见于 LKM 把进程从
``readdir`` 或 ``ps`` 一侧藏掉。两边对不上才报 ``hidden_process``。

容器里没有 ``ps`` 时不猜，直接跳过。``ps`` 失败同样不报，避免把
采集失败当成 rootkit。
"""

from __future__ import annotations

import re

from irtrace.collectors.base import BaseCollector
from irtrace.core.models import Category
from irtrace.core.plugin import CollectResult
from irtrace.core.registry import register

_PS_PID = re.compile(r"^\s*(\d+)\b")


@register
class HiddenProcCollector(BaseCollector):
    name = "hidden_proc"
    description = "比对 /proc 与 ps，找出只存在于一侧的进程（T1014）"
    category = Category.PROCESS
    requires_paths = ["/proc"]

    def collect(self, ctx) -> CollectResult:
        res = CollectResult()
        proc_pids = {
            int(name) for name in self.listdir("/proc") if name.isdigit()
        }
        if not proc_pids:
            res.stats = {"proc": 0, "hidden": 0}
            return res
        if not ctx.which("ps"):
            res.warnings.append("没有 ps，跳过隐藏进程比对")
            res.stats = {"proc": len(proc_pids), "hidden": 0, "skipped": "no-ps"}
            return res

        out = ctx.run_command(["ps", "-e", "-o", "pid="])
        if out is None:
            res.warnings.append("ps 执行失败，跳过隐藏进程比对")
            res.stats = {"proc": len(proc_pids), "hidden": 0, "skipped": "ps-failed"}
            return res

        ps_pids = set()
        for line in out.splitlines():
            match = _PS_PID.match(line)
            if match:
                ps_pids.add(int(match.group(1)))

        # ps 自己和刚退出的进程会有短暂偏差。只保留 /proc 里仍能读到
        # comm 的 pid，减少采集窗口造成的误报。
        hidden = sorted(
            pid for pid in (proc_pids - ps_pids)
            if ctx.read_file(f"/proc/{pid}/comm")
        )
        for pid in hidden[:20]:
            comm = (ctx.read_file(f"/proc/{pid}/comm") or "").strip()
            res.events.append(self.event(
                ctx, action="hidden_process",
                message=f"进程 PID={pid} ({comm or '?'}) 在 /proc 中存在但 ps 不可见",
                pid=pid, tags=["rootkit", "hidden-process"],
                raw={"comm": comm},
            ))

        res.evidence.append(self.evidence_from_text(
            ctx, "hidden-proc.txt",
            f"proc={len(proc_pids)} ps={len(ps_pids)} hidden={len(hidden)}\n"
            + "\n".join(str(pid) for pid in hidden),
            note="proc 与 ps 的 PID 差集",
        ))
        res.stats = {
            "proc": len(proc_pids),
            "ps": len(ps_pids),
            "hidden": len(hidden),
        }
        return res


__all__ = ["HiddenProcCollector"]
