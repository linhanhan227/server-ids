"""运行上下文与只读执行接口。

``RunContext`` 是插件与框架之间的唯一契约对象, 提供:

- 只读文件访问 (``read_file`` / ``glob`` / ``exists``)
- 只读命令执行 (``run_command``) —— 强制超时、禁止危险命令
- 证据登记 (``add_evidence``) —— 自动哈希并写入哈希链账本
- 事件登记 (``add_event``) / 结论登记 (``add_finding``)
- 运行审计日志 (``audit``)

**安全约束**: 所有采集动作必须经由本上下文, 以保证 (1) 不修改目标状态,
(2) 所有落盘证据可校验。
"""

from __future__ import annotations

import getpass
import hashlib
import json
import logging
import os
import platform
import shutil
import socket
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Union

from irtrace.core.errors import EvidenceIntegrityError
from irtrace.core.models import Event, Evidence, Finding

logger = logging.getLogger("irtrace")

#: 明令禁止执行的命令 (破坏性 / 会改变目标状态)。
# 按参数序列的前两个 token 匹配, 避免 "ps aux | grep rm" 这类误伤,
# 也避免 "find ... -exec rm" 这类藏在参数里的破坏性动作漏过。
_FORBIDDEN_HEADS = {
    "rm", "mv", "dd", "mkfs", "shred", "truncate", "chmod", "chown",
    "chgrp", "useradd", "userdel", "usermod", "groupadd", "passwd",
    "kill", "pkill", "killall", "reboot", "shutdown", "poweroff",
    "halt", "init", "telinit", "mkswap", "swapon", "swapoff",
}
_FORBIDDEN_PAIRS = {
    ("systemctl", "stop"), ("systemctl", "disable"), ("systemctl", "restart"),
    ("systemctl", "mask"), ("service", "stop"),
    ("iptables", "-f"), ("iptables", "--flush"), ("ip6tables", "-f"),
    ("nft", "flush"), ("nft", "delete"),
}


class RunContext:
    """一次溯源分析的运行上下文。"""

    def __init__(
        self,
        workspace: Union[str, Path],
        config: Optional[Dict[str, Any]] = None,
        *,
        dry_run: bool = False,
        command_timeout: int = 30,
        max_file_bytes: int = 8 * 1024 * 1024,
        persistent: bool = True,
    ) -> None:
        self.run_id: str = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:6]
        self.workspace = Path(workspace).resolve()
        if config is None:
            from irtrace.settings import load_settings
            config = load_settings(self.workspace)
        self.config: Dict[str, Any] = config
        self.dry_run = dry_run
        self.command_timeout = command_timeout
        self.max_file_bytes = max_file_bytes
        #: False 表示临时上下文 (只读命令使用), 产物写入系统临时目录, 不污染 runs/
        self.persistent = persistent

        # 目录布局
        if persistent:
            self.run_dir = self.workspace / "runs" / self.run_id
        else:
            import tempfile
            self.run_dir = Path(tempfile.mkdtemp(prefix="irtrace-ephemeral-"))
        self.evidence_dir = self.run_dir / "evidence"
        self.report_dir = self.run_dir / "reports"
        for d in (self.evidence_dir, self.report_dir):
            d.mkdir(parents=True, exist_ok=True)

        # 数据仓库
        self.events: List[Event] = []
        self.evidence: List[Evidence] = []
        self.findings: List[Finding] = []
        self.warnings: List[str] = []
        self.stats: Dict[str, Any] = {}

        # 哈希链账本
        self._ledger_path = self.run_dir / "evidence-ledger.jsonl"
        self._ledger_prev = "0" * 64
        self._ledger_seq = 0

        # 审计日志
        self._audit_path = self.run_dir / "audit.log"
        self.audit("run_start", run_id=self.run_id, host=self.hostname,
                   platform=f"{platform.system()} {platform.release()}",
                   operator=self.operator)

    # ------------------------------------------------------------------ #
    # 系统信息
    # ------------------------------------------------------------------ #
    @property
    def hostname(self) -> str:
        try:
            return socket.gethostname()
        except Exception:  # noqa: BLE001
            return "unknown"

    @property
    def operator(self) -> str:
        try:
            return getpass.getuser()
        except Exception:  # noqa: BLE001
            return "unknown"

    @property
    def is_linux(self) -> bool:
        return platform.system().lower() == "linux"

    def which(self, cmd: str) -> Optional[str]:
        return shutil.which(cmd)

    # ------------------------------------------------------------------ #
    # 只读文件访问
    # ------------------------------------------------------------------ #
    def exists(self, path: Union[str, Path]) -> bool:
        return Path(path).exists()

    def read_file(
        self,
        path: Union[str, Path],
        *,
        encoding: str = "utf-8",
        errors: str = "replace",
        max_bytes: Optional[int] = None,
    ) -> Optional[str]:
        """读取文本文件; 不存在或不可读时返回 None 并记录告警。"""
        p = Path(path)
        try:
            size = p.stat().st_size
            limit = max_bytes or self.max_file_bytes
            if size > limit:
                self.warn(f"文件过大, 仅读取前 {limit} 字节: {p}")
                with p.open("rb") as fh:
                    return fh.read(limit).decode(encoding, errors)
            return p.read_text(encoding=encoding, errors=errors)
        except (OSError, UnicodeError) as exc:
            logger.debug("read_file 失败 %s: %s", p, exc)
            return None

    def read_lines(self, path: Union[str, Path], **kw: Any) -> List[str]:
        content = self.read_file(path, **kw)
        return content.splitlines() if content else []

    def glob(self, pattern: str) -> List[Path]:
        import glob as _glob
        return [Path(p) for p in _glob.glob(pattern, recursive=True)]

    # ------------------------------------------------------------------ #
    # 只读命令执行
    # ------------------------------------------------------------------ #
    def run_command(
        self,
        args: Sequence[str],
        *,
        timeout: Optional[int] = None,
        check_forbidden: bool = True,
    ) -> Optional[str]:
        """执行只读命令并返回 stdout (失败返回 None)。

        - ``args`` 必须为序列, 不经 shell, 避免注入与重定向。
        - 命中 ``_FORBIDDEN`` 前缀的命令直接拒绝。
        """
        tokens = [str(a) for a in args]
        cmdline = " ".join(tokens)
        if check_forbidden and self._is_forbidden(tokens):
            self.warn(f"拒绝执行可能修改系统状态的命令: {cmdline}")
            return None
        if self.dry_run:
            self.audit("command_skipped(dry_run)", cmd=cmdline)
            return None
        try:
            proc = subprocess.run(  # noqa: S603 - 参数为序列, 无 shell
                [str(a) for a in args],
                capture_output=True,
                text=True,
                timeout=timeout or self.command_timeout,
                check=False,
            )
            self.audit("command", cmd=cmdline, rc=proc.returncode)
            if proc.returncode != 0 and not proc.stdout:
                logger.debug("命令非零退出 %s: %s", cmdline, proc.stderr.strip())
            return proc.stdout
        except FileNotFoundError:
            return None
        except subprocess.TimeoutExpired:
            self.warn(f"命令超时({timeout or self.command_timeout}s): {cmdline}")
            return None
        except Exception as exc:  # noqa: BLE001
            logger.debug("命令执行异常 %s: %s", cmdline, exc)
            return None

    @staticmethod
    def _is_forbidden(tokens: Sequence[str]) -> bool:
        """拒绝会改变目标状态的命令。重定向符、sudo 包装和 -exec 都算。"""
        if not tokens:
            return False
        low = [t.lower() for t in tokens]
        if any(t in {">", ">>", "<"} or t.startswith(">") for t in low):
            return True
        if any(t in {"rm", "shred", "mkfs"} or t.startswith("mkfs.") for t in low):
            return True
        head = low[0]
        if head in {"sudo", "doas", "pkexec"} and len(low) > 1:
            head = low[1]
            rest = low[2:3]
        else:
            rest = low[1:2]
        if head in _FORBIDDEN_HEADS or head.startswith("mkfs."):
            return True
        if rest and (head, rest[0]) in _FORBIDDEN_PAIRS:
            return True
        return False

    # ------------------------------------------------------------------ #
    # 证据登记 (含哈希链)
    # ------------------------------------------------------------------ #
    def store_evidence(
        self,
        *,
        source: str,
        kind: str,
        name: str,
        data: Union[bytes, str],
        note: str = "",
        mtime: Optional[datetime] = None,
        path: Optional[str] = None,
    ) -> Evidence:
        """把采集到的原始内容落盘到 evidence/ 并登记哈希链。"""
        if isinstance(data, str):
            raw = data.encode("utf-8", "replace")
        else:
            raw = data
        digest = hashlib.sha256(raw).hexdigest()

        rel = Path(source) / name
        dest = self.evidence_dir / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(raw)

        ev = Evidence(
            source=source, kind=kind, path=path or str(rel), content=str(dest),
            sha256=digest, size=len(raw), mtime=mtime, note=note,
        )
        self.evidence.append(ev)
        self._append_ledger(ev)
        return ev

    def _append_ledger(self, ev: Evidence) -> None:
        """把证据摘要追加进哈希链: entry_hash = H(prev || seq || id || sha256)。"""
        self._ledger_seq += 1
        payload = f"{self._ledger_prev}|{self._ledger_seq}|{ev.evidence_id}|{ev.sha256}"
        entry_hash = hashlib.sha256(payload.encode()).hexdigest()
        record = {
            "seq": self._ledger_seq,
            "evidence_id": ev.evidence_id,
            "source": ev.source,
            "path": ev.path,
            "sha256": ev.sha256,
            "prev_hash": self._ledger_prev,
            "entry_hash": entry_hash,
            "at": datetime.now(timezone.utc).isoformat(),
        }
        with self._ledger_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        self._ledger_prev = entry_hash

    def verify_ledger(self) -> bool:
        """重放哈希链, 校验证据账本未被篡改。"""
        prev = "0" * 64
        seq = 0
        if not self._ledger_path.exists():
            return True
        for line in self._ledger_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            rec = json.loads(line)
            seq += 1
            expect = hashlib.sha256(
                f"{prev}|{rec['seq']}|{rec['evidence_id']}|{rec['sha256']}".encode()
            ).hexdigest()
            if rec["prev_hash"] != prev or rec["entry_hash"] != expect or rec["seq"] != seq:
                raise EvidenceIntegrityError(f"证据账本在第 {rec['seq']} 条被篡改")
            prev = rec["entry_hash"]
        return True

    # ------------------------------------------------------------------ #
    # 事件 / 结论 / 告警
    # ------------------------------------------------------------------ #
    def add_event(self, event: Event) -> Event:
        self.events.append(event)
        return event

    def add_events(self, events: Sequence[Event]) -> None:
        self.events.extend(events)

    def add_finding(self, finding: Finding) -> Finding:
        self.findings.append(finding)
        return finding

    def warn(self, message: str) -> None:
        self.warnings.append(message)
        logger.warning(message)

    def audit(self, action: str, **fields: Any) -> None:
        rec = {"at": datetime.now(timezone.utc).isoformat(), "action": action, **fields}
        try:
            with self._audit_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
        except OSError:  # pragma: no cover
            pass

    # ------------------------------------------------------------------ #
    # 汇总
    # ------------------------------------------------------------------ #
    def summary(self) -> Dict[str, Any]:
        by_sev: Dict[str, int] = {}
        for f in self.findings:
            by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
        return {
            "run_id": self.run_id,
            "host": self.hostname,
            "operator": self.operator,
            "events": len(self.events),
            "evidence": len(self.evidence),
            "findings": len(self.findings),
            "findings_by_severity": by_sev,
            "warnings": len(self.warnings),
            "run_dir": str(self.run_dir),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    def close(self) -> None:
        self.audit("run_end", events=len(self.events),
                   evidence=len(self.evidence), findings=len(self.findings))
        if not self.persistent:
            return
        (self.run_dir / "summary.json").write_text(
            json.dumps(self.summary(), ensure_ascii=False, indent=2), encoding="utf-8"
        )


__all__ = ["RunContext"]
