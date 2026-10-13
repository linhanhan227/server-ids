"""核心模型、只读沙箱、哈希链与关联规则。"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from irtrace.core.context import RunContext
from irtrace.core.models import Category, Event, Severity
from irtrace.core.registry import registry


def _event(action: str, **kwargs) -> Event:
    kwargs.setdefault("timestamp", datetime(2026, 10, 12, 12, 0, tzinfo=timezone.utc))
    kwargs.setdefault("category", Category.AUTH)
    kwargs.setdefault("source", "test")
    return Event(action=action, **kwargs)


def test_event_roundtrip_keeps_timestamp_and_category():
    original = _event(
        "ssh_login", user="root", src_ip="1.2.3.4",
        tags=["ssh"], raw={"ok": True}, message="登录",
    )
    restored = Event.from_dict(original.to_dict())
    assert restored.action == "ssh_login"
    assert restored.user == "root"
    assert restored.src_ip == "1.2.3.4"
    assert restored.category is Category.AUTH
    assert restored.timestamp == original.timestamp
    assert restored.tags == ["ssh"]
    assert restored.raw == {"ok": True}


def test_event_from_dict_drops_unknown_fields():
    restored = Event.from_dict({
        "action": "note", "source": "t", "category": "no-such",
        "timestamp": "not-a-date", "extra": "ignored",
    })
    assert restored.category is Category.OTHER
    assert restored.timestamp is None


def test_run_command_rejects_destructive_invocations(workspace):
    ctx = RunContext(workspace, persistent=False)
    assert ctx.run_command(["rm", "-rf", "/tmp/x"]) is None
    assert ctx.run_command(["sudo", "chmod", "777", "/etc"]) is None
    assert ctx.run_command(["find", "/tmp", "-exec", "rm", "{}", ";"]) is None
    assert ctx.run_command(["systemctl", "stop", "sshd"]) is None
    assert any("拒绝执行" in w for w in ctx.warnings)


def test_run_command_allows_readonly_lookup(workspace):
    ctx = RunContext(workspace, persistent=False)
    out = ctx.run_command(["echo", "irtrace-ok"])
    assert out is not None and "irtrace-ok" in out
    assert ctx.warnings == []


def test_evidence_ledger_detects_tamper(workspace):
    ctx = RunContext(workspace)
    ctx.store_evidence(source="t", kind="note", name="a.txt", data="alpha")
    ctx.store_evidence(source="t", kind="note", name="b.txt", data="beta")
    ctx.verify_ledger()

    ledger = ctx.run_dir / "evidence-ledger.jsonl"
    lines = ledger.read_text(encoding="utf-8").splitlines()
    first = json.loads(lines[0])
    first["sha256"] = "0" * 64
    lines[0] = json.dumps(first, ensure_ascii=False)
    ledger.write_text("\n".join(lines) + "\n", encoding="utf-8")

    from irtrace.core.errors import EvidenceIntegrityError
    try:
        ctx.verify_ledger()
    except EvidenceIntegrityError:
        return
    raise AssertionError("篡改后的账本应当校验失败")


def test_correlation_bruteforce_then_login(workspace):
    registry.discover()
    base = datetime(2026, 10, 12, 8, 0, tzinfo=timezone.utc)
    ctx = RunContext(workspace)
    for i in range(6):
        ctx.add_event(_event(
            "ssh_failed", src_ip="203.0.113.9", user="root",
            timestamp=base + timedelta(minutes=i),
            category=Category.AUTH, message="失败",
        ))
    ctx.add_event(_event(
        "ssh_login", src_ip="203.0.113.9", user="root",
        timestamp=base + timedelta(minutes=10),
        category=Category.AUTH, message="成功",
    ))

    from irtrace.analyzers.correlation import CorrelationAnalyzer
    findings = CorrelationAnalyzer().analyze(ctx)
    titles = [f.title for f in findings]
    assert any("爆破成功" in t and "203.0.113.9" in t for t in titles)
    hit = next(f for f in findings if "爆破成功" in f.title)
    assert hit.severity is Severity.CRITICAL
    assert hit.details["failed_count"] == 6


def test_correlation_login_then_privilege(workspace):
    registry.discover()
    base = datetime(2026, 10, 12, 9, 0, tzinfo=timezone.utc)
    ctx = RunContext(workspace)
    ctx.add_event(_event(
        "ssh_login", user="alice", src_ip="198.51.100.8",
        timestamp=base, category=Category.AUTH,
    ))
    ctx.add_event(_event(
        "sudo", user="alice", timestamp=base + timedelta(minutes=4),
        category=Category.ACCOUNT, message="sudo visudo",
    ))
    from irtrace.analyzers.correlation import CorrelationAnalyzer
    findings = CorrelationAnalyzer().analyze(ctx)
    assert any(f.severity is Severity.HIGH and "提权" in f.title for f in findings)


def test_correlation_ignores_unrelated_failures(workspace):
    registry.discover()
    base = datetime(2026, 10, 12, 9, 0, tzinfo=timezone.utc)
    ctx = RunContext(workspace)
    for i in range(3):
        ctx.add_event(_event(
            "ssh_failed", src_ip="203.0.113.1",
            timestamp=base + timedelta(minutes=i),
        ))
    ctx.add_event(_event(
        "ssh_login", src_ip="198.51.100.2", user="bob",
        timestamp=base + timedelta(hours=3),
    ))
    from irtrace.analyzers.correlation import CorrelationAnalyzer
    assert CorrelationAnalyzer()._r1_bruteforce_success(ctx) == []
