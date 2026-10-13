"""进程命令行里的挖矿、内核线程伪装与下载后执行。

对照公开检测规则，不复制其规则全文：

- Sigma ``proc_creation_lnx_crypto_mining``（T1496）：矿池协议、xmrig 的
  donate-level / RandomX 参数，以及这些参数的 base64 片段。
- Elastic「Executable Masquerading as Kernel Process」：comm 像 ``[kworker/0:1]``，
  但 ``/proc/PID/exe`` 指向真实文件。真内核线程没有用户态 exe。
- Sigma ``lnx_shell_susp_commands``：``wget``/``curl`` 把响应交给 ``sh``/``bash``/``perl``。

单独的下载管道不够跨过失陷阈值，要和可写目录落地一起看。
"""

from __future__ import annotations

import re
from typing import List

# Sigma 规则里的矿池与 xmrig 参数。只认这些，不把普通 curl 算成挖矿。
_MINER = re.compile(
    r"""(?ix)
    stratum\+(?:tcp|udp|ssl)://
    | --donate-level=\d
    | --cpu-priority=
    | --algo=rx/0
    | \s-o\s+pool\.
    | --nicehash\b
    | \bxmrig\b
    | \bminerd\b
    | \bcpuminer\b
    | kdevtmpfsi
    | kinsing
    | LS1kb25hdGUtbGV2ZWw9
    | 0tZG9uYXRlLWxldmVsP
    | tLWRvbmF0ZS1sZXZlbD
    | c3RyYXR1bSt0Y3A6Ly
    | c3RyYXR1bSt1ZHA6Ly
    | c3RyYXR1bStzc2w6Ly
    | YXN0cmF0dW0rdGNwOi8v
    | YXN0cmF0dW0rdWRwOi8v
    | YWFzdHJhdHVtK3RjcDov
    | YWFzdHJhdHVtK3VkcDov
    """
)

# 真内核线程的 comm 是方括号短名，没有路径。
_KTHREAD = re.compile(r"^\[(?:kworker|kthreadd|ksoftirqd|migration|rcu_|watchdog)[^\]]{0,24}\]$")

# wget/curl 的输出直接进解释器。写到文件再执行不算这条，落地扫描会另记。
_DOWNLOAD_EXEC = re.compile(
    r"""(?ix)
    \b(?:wget|curl)\b[^\n|;]{0,240}\|\s*(?:ba)?sh\b
    | \b(?:wget|curl)\b[^\n|;]{0,240}\|\s*perl\b
    | \b(?:wget|curl)\b[^\n|;]{0,240}\|\s*python(?:3)?\b
    """
)


def miner_flags(cmd: str) -> List[str]:
    if not cmd or not _MINER.search(cmd):
        return []
    return ["crypto_miner"]


def kthread_masquerade(comm: str, exe: str) -> bool:
    """方括号内核线程名，但 exe 指向用户态文件。空 exe 是真内核线程。"""
    if not comm or not exe:
        return False
    if exe.endswith("(deleted)"):
        return False
    if not exe.startswith("/"):
        return False
    return bool(_KTHREAD.match(comm.strip()))


def download_exec(cmd: str) -> bool:
    return bool(cmd and _DOWNLOAD_EXEC.search(cmd))


__all__ = ["miner_flags", "kthread_masquerade", "download_exec"]
