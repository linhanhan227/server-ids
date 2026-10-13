"""进程采集器: 遍历 /proc 构建进程快照并标记可疑特征。

可疑特征:
- 可执行文件已删除 (``/proc/PID/exe`` 指向 ``(deleted)``) —— 常见于内存马/木马
- 进程名与可执行文件路径不一致
- 从 /tmp、/dev/shm、/var/tmp 等可写目录启动
- 父进程为 1 且非守护进程特征 (孤儿进程)
- cmdline 含反弹 shell 特征 (bash -i、nc -e、/dev/tcp)
- cmdline 含中转/端口转发工具 (frp、gost、ssh -L/-R/-D、chisel)
- 可执行文件指向 memfd: 或 /proc/pid/fd 下的匿名文件 (T1620)
- 解释器从标准输入执行脚本 (python - / perl - / bash 读管道)
- 挖矿命令行 (Sigma proc_creation_lnx_crypto_mining, T1496)
- 伪装成内核线程但 exe 不空 (Elastic kthreadd masquerading, T1036.005)
- 下载后立刻交给 shell 执行 (Sigma lnx_shell_susp_commands, T1059.004)
"""

from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from typing import List, Optional

from irtrace.collectors.base import BaseCollector
from irtrace.collectors.payload import download_exec, kthread_masquerade, miner_flags
from irtrace.collectors.relay import model_relay_flags, relay_flags
from irtrace.core.models import Category, Event
from irtrace.core.plugin import CollectResult
from irtrace.core.registry import register

# 可疑启动目录
_SUSPICIOUS_DIRS = ("/tmp/", "/dev/shm/", "/var/tmp/", "/run/shm/", "/.cache/")

# 反弹 shell / 后门特征
_REVERSE_SHELL = re.compile(
    r"(bash\s+-i|/dev/tcp/|nc\s+-e|ncat\s+-e|socat\s+.*exec|python.*socket.*connect|"
    r"perl\s+-e.*socket|mkfifo.*nc|sh\s+-i)",
    re.I,
)

# 常见伪装成内核线程的可疑名
_FAKE_KTHREAD = re.compile(r"^\[?[a-z0-9_\-]{1,16}\]?$")


@register
class ProcessCollector(BaseCollector):
    name = "process"
    description = "遍历 /proc 采集进程快照, 标记已删除可执行文件 / 可疑路径 / 反弹 shell"
    category = Category.PROCESS
    requires_paths = ["/proc"]

    def collect(self, ctx) -> CollectResult:
        res = CollectResult()
        proc_root = "/proc"
        snapshot_lines: List[str] = []
        suspicious = 0

        for entry in self.listdir(proc_root):
            if not entry.isdigit():
                continue
            pid = int(entry)
            info = self._read_proc(ctx, proc_root, pid)
            if info is None:
                continue
            snapshot_lines.append(
                f"{pid}\t{info['ppid']}\t{info['user']}\t{info['exe']}\t{info['cmdline']}"
            )

            flags = self._flag_suspicious(info)
            if not flags:
                continue
            suspicious += 1
            relay = [flag for flag in flags if flag == "port_forward"
                     or flag.startswith(("relay_", "model_"))]
            other = [flag for flag in flags if flag not in relay]
            if relay:
                res.events.append(self.event(
                    ctx,
                    action="relay_process",
                    message=f"中转进程 PID={pid} ({info['comm']}): {'; '.join(relay)}",
                    timestamp=info["start_time"],
                    pid=pid, ppid=info["ppid"], user=info["user"],
                    path=info["exe"],
                    tags=["relay"] + relay,
                    raw=info,
                ))
            if other:
                res.events.append(
                    self.event(
                        ctx,
                        action="process_suspicious",
                        message=f"可疑进程 PID={pid} ({info['comm']}): {'; '.join(other)}",
                        timestamp=info["start_time"],
                        pid=pid,
                        ppid=info["ppid"],
                        user=info["user"],
                        path=info["exe"],
                        tags=["suspicious-process"] + other,
                        raw=info,
                    )
                )

        if snapshot_lines:
            res.evidence.append(
                self.evidence_from_text(
                    ctx,
                    "process-snapshot.tsv",
                    "PID\tPPID\tUSER\tEXE\tCMDLINE\n" + "\n".join(snapshot_lines),
                    note="全量进程快照",
                )
            )

        res.stats = {"processes": len(snapshot_lines), "suspicious": suspicious}
        return res

    # ------------------------------------------------------------------ #
    def _read_proc(self, ctx, root: str, pid: int) -> Optional[dict]:
        stat = ctx.read_file(f"{root}/{pid}/stat")
        if not stat:
            return None
        try:
            # comm 可能含空格/括号, 取最后一个 ')' 之后的部分
            rparen = stat.rfind(")")
            comm = stat[stat.find("(") + 1: rparen]
            rest = stat[rparen + 2:].split()
            ppid = int(rest[1])
            state = rest[0]
        except (ValueError, IndexError):
            return None

        cmdline_raw = ctx.read_file(f"{root}/{pid}/cmdline", max_bytes=64 * 1024) or ""
        cmdline = cmdline_raw.replace("\x00", " ").strip()

        try:
            exe = os.readlink(f"{root}/{pid}/exe")
        except OSError:
            exe = ""

        user = self._owner(ctx, f"{root}/{pid}")

        try:
            st = os.stat(f"{root}/{pid}")
            start_time = datetime.fromtimestamp(st.st_ctime, tz=timezone.utc)
        except OSError:
            start_time = None

        return {
            "pid": pid, "ppid": ppid, "comm": comm, "state": state,
            "cmdline": cmdline or f"[{comm}]", "exe": exe, "user": user,
            "start_time": start_time,
        }

    @staticmethod
    def _owner(ctx, path: str) -> str:
        try:
            import pwd
            return pwd.getpwuid(os.stat(path).st_uid).pw_name
        except Exception:  # noqa: BLE001
            return "?"

    def _flag_suspicious(self, info: dict) -> List[str]:
        flags: List[str] = []
        exe = info.get("exe", "")
        cmd = info.get("cmdline", "")

        if exe.endswith("(deleted)"):
            flags.append("exe_deleted")
        if _is_memfd(exe):
            flags.append("memfd_exec")
        if _is_fileless(cmd):
            flags.append("fileless_exec")
        for d in _SUSPICIOUS_DIRS:
            if exe.startswith(d) or d in cmd:
                flags.append(f"exec_from_writable:{d.strip('/')}")
                break
        if _REVERSE_SHELL.search(cmd):
            flags.append("reverse_shell_pattern")
        flags.extend(miner_flags(cmd))
        if kthread_masquerade(info.get("comm", ""), exe):
            flags.append("kthread_masquerade")
        if download_exec(cmd):
            flags.append("download_exec")
        flags.extend(relay_flags(cmd))
        flags.extend(model_relay_flags(cmd))
        if info.get("ppid") == 1 and info.get("user") == "root" and exe.startswith("/tmp"):
            flags.append("orphan_root_from_tmp")
        return flags


def _is_memfd(exe: str) -> bool:
    """memfd_create 与从 /proc/self/fd 执行的匿名文件。"""
    text = exe.lower()
    if "memfd:" in text or "/memfd:" in text:
        return True
    return "/proc/" in text and "/fd/" in text


def _is_fileless(cmd: str) -> bool:
    """解释器把脚本从标准输入读进来执行。``python -c`` 与 ``python -m`` 不算。"""
    if re.search(r"\b(?:python|python3|perl)(?:\d\.\d+)?\s+-\s", cmd):
        return True
    return bool(re.search(r"(?:^|[|&;])\s*(?:ba)?sh\s*<\s*\S+", cmd))


__all__ = ["ProcessCollector", "_is_memfd", "_is_fileless"]
