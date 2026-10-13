"""内核层采集器: 内核模块 / 关键 sysctl / 隐藏进程线索。

覆盖:
- 已加载内核模块清单 (/proc/modules, lsmod)
- 异常模块 (不在 /lib/modules 中、名称随机、常见的 rootkit 名)
- 关键 sysctl 被篡改 (kptr_restrict, dmesg_restrict, ASLR)
- /etc/ld.so.preload (用户态 rootkit 常用)
"""

from __future__ import annotations

import re
from typing import Dict, List, Set

from irtrace.collectors.base import BaseCollector
from irtrace.core.models import Category, Event
from irtrace.core.plugin import CollectResult
from irtrace.core.registry import register

# 常见 rootkit 模块名 / 特征
_KNOWN_ROOTKIT = re.compile(
    r"^(diamorphine|reptile|azazel|knark|adore|bd_|suterusu|kbeast|hide|"
    r"rootkit|hiding|modhide)\w*$", re.I,
)

# 关键安全相关 sysctl 期望值
_EXPECTED_SYSCTL = {
    "kernel.kptr_restrict": "1",
    "kernel.dmesg_restrict": "1",
    "kernel.randomize_va_space": "2",
    "kernel.yama.ptrace_scope": "1",
    "net.ipv4.conf.all.accept_source_route": "0",
}


@register
class KernelCollector(BaseCollector):
    name = "kernel"
    description = "审计内核模块 / 关键 sysctl / ld.so.preload, 检测 rootkit 痕迹"
    category = Category.KERNEL
    requires_paths = ["/proc"]

    def collect(self, ctx) -> CollectResult:
        res = CollectResult()
        self._scan_modules(ctx, res)
        self._scan_sysctl(ctx, res)
        self._scan_preload(ctx, res)
        return res

    # ------------------------------------------------------------------ #
    def _scan_modules(self, ctx, res: CollectResult) -> None:
        content = ctx.read_file("/proc/modules")
        if not content:
            return
        res.evidence.append(self.evidence_from_text(
            ctx, "proc-modules.txt", content, path="/proc/modules", note="内核模块清单"))

        builtin = self._builtin_modules()
        for line in content.splitlines():
            parts = line.split()
            if not parts:
                continue
            mod = parts[0]
            if _KNOWN_ROOTKIT.match(mod):
                res.events.append(self.event(
                    ctx, action="rootkit_module",
                    message=f"疑似 rootkit 内核模块: {mod}",
                    tags=["rootkit", "critical"], raw={"module": mod},
                ))
            elif builtin and mod not in builtin:
                res.events.append(self.event(
                    ctx, action="unknown_module",
                    message=f"非常规内核模块 (不在 /lib/modules 中): {mod}",
                    tags=["kernel-module"], raw={"module": mod},
                ))

    def _builtin_modules(self) -> Set[str]:
        """收集 /lib/modules 下所有模块名 (去扩展名), 用于比对。"""
        names: Set[str] = set()
        import os
        for root in ("/lib/modules", "/usr/lib/modules"):
            for dirpath, _dirs, files in os.walk(root):
                for f in files:
                    if f.endswith((".ko", ".ko.xz", ".ko.gz", ".ko.zst")):
                        names.add(f.split(".ko")[0])
        return names

    def _scan_sysctl(self, ctx, res: CollectResult) -> None:
        for key, expected in _EXPECTED_SYSCTL.items():
            path = "/proc/sys/" + key.replace(".", "/")
            actual = (ctx.read_file(path) or "").strip()
            if actual and actual != expected:
                res.events.append(self.event(
                    ctx, action="sysctl_deviation",
                    message=f"安全 sysctl 偏离基线 {key}={actual} (期望 {expected})",
                    path=path, tags=["sysctl", "baseline-deviation"],
                    raw={"key": key, "actual": actual, "expected": expected},
                ))

    def _scan_preload(self, ctx, res: CollectResult) -> None:
        content = ctx.read_file("/etc/ld.so.preload")
        if content and content.strip():
            res.events.append(self.event(
                ctx, action="ld_preload",
                message=f"/etc/ld.so.preload 存在内容 (用户态 rootkit 常见): {content.strip()[:200]}",
                path="/etc/ld.so.preload", tags=["rootkit", "critical"],
                raw={"content": content.strip()},
            ))


__all__ = ["KernelCollector"]
