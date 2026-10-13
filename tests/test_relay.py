"""中转站沦陷。

工具名或转发参数单独出现只记进程，不判失陷。
同一场景同时有中转进程、公网连入和对外连接，才算本机被当作跳板。
"""

from __future__ import annotations

from irtrace.analyzers.correlation import CorrelationAnalyzer
from irtrace.analyzers.intrusion import judge_intrusion
from irtrace.collectors.process import ProcessCollector
from irtrace.collectors.relay import (
    is_model_relay,
    is_relay_process,
    relay_flags,
)
from irtrace.core.context import RunContext
from irtrace.core.models import Category

from test_detection_accuracy import _ev


def test_relay_flags_known_tools_and_ssh_forward():
    assert "relay_tool:frpc" in relay_flags("/usr/bin/frpc -c /etc/frp/frpc.ini")
    assert is_relay_process("ssh -N -R 0.0.0.0:2222:10.0.0.8:22 user@203.0.113.9")
    assert "port_forward" in relay_flags("ssh -D 1080 jump")
    assert not is_relay_process("ssh user@10.0.0.8")
    assert not is_relay_process("/usr/bin/nginx -g daemon off")


def test_process_collector_emits_relay_event():
    collector = ProcessCollector()
    flags = collector._flag_suspicious({
        "exe": "/usr/local/bin/frpc",
        "cmdline": "/usr/local/bin/frpc -c /etc/frp/frpc.toml",
        "ppid": 1,
        "user": "root",
    })
    assert any(flag.startswith("relay_tool:") for flag in flags)


def test_relay_without_traffic_is_not_compromise():
    verdict = judge_intrusion([
        _ev("relay_process", minutes=1, category=Category.PROCESS,
            path="/usr/bin/frpc", tags=["relay", "relay_tool:frpc"],
            message="frpc -c /etc/frp/frpc.ini"),
    ])
    assert not verdict.compromised


def test_bidirectional_relay_is_compromise():
    verdict = judge_intrusion([
        _ev("relay_process", minutes=1, category=Category.PROCESS,
            path="/usr/bin/gost", tags=["relay", "relay_tool:gost", "port_forward"],
            message="gost -L socks5://:1080"),
        _ev("external_connection", minutes=2, category=Category.NETWORK,
            src_ip="203.0.113.8", dst_port=1080,
            tags=["external-conn", "inbound"],
            message="入站 203.0.113.8"),
        _ev("external_connection", minutes=3, category=Category.NETWORK,
            dst_ip="198.51.100.20", dst_port=443,
            tags=["external-conn", "outbound"],
            message="出站 198.51.100.20"),
    ])
    assert verdict.compromised
    assert any("中转" in item for item in verdict.signals)


def test_correlation_requires_both_directions(workspace):
    ctx = RunContext(workspace, dry_run=True)
    ctx.add_events([
        _ev("relay_process", minutes=1, category=Category.PROCESS,
            path="/usr/bin/frpc", tags=["relay", "relay_tool:frpc"]),
        _ev("external_connection", minutes=2, category=Category.NETWORK,
            src_ip="203.0.113.8", tags=["external-conn", "inbound"]),
        _ev("external_connection", minutes=3, category=Category.NETWORK,
            dst_ip="198.51.100.20", dst_port=22,
            tags=["external-conn", "outbound"]),
    ])
    findings = CorrelationAnalyzer()._r8_relay_pivot(ctx)
    assert len(findings) == 1
    assert findings[0].details["clients"] == ["203.0.113.8"]
    assert findings[0].details["peers"] == ["198.51.100.20"]

    ctx.events = [event for event in ctx.events if "outbound" not in event.tags]
    assert CorrelationAnalyzer()._r8_relay_pivot(ctx) == []


def test_model_gateway_needs_listen_and_upstream():
    gateway = "one-api --port 3000 OPENAI_API_BASE=https://api.example.com/v1"
    client = "python app.py OPENAI_API_BASE=https://api.example.com/v1"
    assert is_model_relay(gateway)
    assert not is_model_relay(client)
    assert not is_model_relay("nginx -g daemon off")


def test_model_relay_with_outbound_is_compromise():
    verdict = judge_intrusion([
        _ev("relay_process", minutes=1, category=Category.PROCESS,
            path="/usr/local/bin/one-api",
            tags=["relay", "model_gateway:one-api", "model_listen", "model_upstream"],
            message="one-api --port 3000"),
        _ev("external_connection", minutes=2, category=Category.NETWORK,
            dst_ip="203.0.113.50", dst_port=443,
            tags=["external-conn", "outbound"],
            message="上游模型"),
    ])
    assert verdict.compromised
    assert any("模型中转" in item for item in verdict.signals)


def test_model_client_without_listen_is_not_compromise():
    verdict = judge_intrusion([
        _ev("process_suspicious", minutes=1, category=Category.PROCESS,
            path="/usr/bin/python", tags=["suspicious-process"],
            message="OPENAI_API_BASE=https://api.example.com/v1"),
        _ev("external_connection", minutes=2, category=Category.NETWORK,
            dst_ip="203.0.113.50", dst_port=443,
            tags=["external-conn", "outbound"]),
    ])
    assert not verdict.compromised


def _access(ip: str, path: str, status: int, minute: int = 0) -> str:
    return (
        f"{ip} - - [13/Oct/2026:08:{minute % 60:02d}:00 +0000] "
        f"\"POST {path} HTTP/1.1\" {status} 20 \"-\" \"client\""
    )


def test_web_log_marks_model_bruteforce_and_abuse(workspace, monkeypatch):
    from irtrace.collectors.web_log import WebLogCollector

    log_path = workspace / "access.log"
    lines = [
        _access("203.0.113.9", "/api/user/login", 401, i) for i in range(8)
    ]
    lines.append(_access("203.0.113.9", "/api/user/login", 200, 9))
    lines += [
        _access("198.51.100.7", "/v1/chat/completions", 200, i)
        for i in range(30)
    ]
    lines.append(_access("10.0.0.4", "/login", 401, 1))
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    monkeypatch.setattr(
        "irtrace.collectors.web_log._LOG_CANDIDATES", (str(log_path),),
    )
    ctx = RunContext(workspace, dry_run=True)
    result = WebLogCollector().collect(ctx)
    actions = {event.action: event for event in result.events}
    assert actions["model_auth_failure"].src_ip == "203.0.113.9"
    assert actions["model_auth_success"].src_ip == "203.0.113.9"
    assert actions["model_abuse"].raw["hit_count"] == 30
    assert "10.0.0.4" not in {event.src_ip for event in result.events}


def test_failed_model_login_is_not_compromise():
    verdict = judge_intrusion([
        _ev("model_auth_failure", minutes=1, category=Category.AUTH,
            src_ip="203.0.113.9", tags=["model-auth", "model-gateway"],
            raw={"hit_count": 12}),
    ])
    assert not verdict.compromised


def test_cracked_model_login_is_compromise():
    verdict = judge_intrusion([
        _ev("model_auth_failure", minutes=1, category=Category.AUTH,
            src_ip="203.0.113.9", tags=["model-auth"], raw={"hit_count": 8}),
        _ev("model_auth_success", minutes=2, category=Category.AUTH,
            src_ip="203.0.113.9", tags=["model-auth"], raw={"hit_count": 1}),
    ])
    assert verdict.compromised
    assert any("爆破" in item for item in verdict.signals)


def test_abuse_without_gateway_is_not_compromise():
    verdict = judge_intrusion([
        _ev("model_abuse", minutes=1, category=Category.LOG,
            src_ip="198.51.100.7", tags=["model-abuse"],
            raw={"hit_count": 40}),
    ])
    assert not verdict.compromised


def test_abuse_on_gateway_is_compromise():
    verdict = judge_intrusion([
        _ev("relay_process", minutes=1, category=Category.PROCESS,
            path="/opt/new-api",
            tags=["relay", "model_gateway:new-api", "model_listen", "model_upstream"]),
        _ev("model_abuse", minutes=2, category=Category.LOG,
            src_ip="198.51.100.7", tags=["model-abuse"],
            raw={"hit_count": 40}),
    ])
    assert verdict.compromised
    assert any("打野" in item for item in verdict.signals)


def test_shared_key_fingerprint_is_compromise(workspace, monkeypatch):
    from irtrace.collectors.web_log import WebLogCollector

    secret = "sk-live-abcdefghijklmnopqrstuvwxyz"
    log_path = workspace / "keys.log"
    lines = [
        _access("203.0.113.9", f"/v1/chat/completions?api_key={secret}", 200, 1),
        _access("198.51.100.7", f"/v1/chat/completions?api_key={secret}", 200, 2),
        _access("203.0.113.9", "/v1/chat/completions?api_key=sk-other-zzzzzzzzzzzz", 200, 3),
    ]
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    monkeypatch.setattr(
        "irtrace.collectors.web_log._LOG_CANDIDATES", (str(log_path),),
    )
    ctx = RunContext(workspace, dry_run=True)
    result = WebLogCollector().collect(ctx)
    reused = [event for event in result.events if event.action == "model_key_reuse"]
    assert len(reused) == 1
    assert secret not in str(reused[0].raw)
    stored = (workspace / "runs").rglob("*.txt")
    assert stored
    assert all(secret not in item.read_text(encoding="utf-8") for item in stored)
    assert reused[0].raw["sources"] == ["198.51.100.7", "203.0.113.9"]

    verdict = judge_intrusion(result.events)
    assert verdict.compromised
    assert any("密钥" in item for item in verdict.signals)


def test_one_source_key_is_not_compromise():
    verdict = judge_intrusion([
        _ev("model_key_reuse", minutes=1, category=Category.AUTH,
            tags=["leaked-key"],
            raw={"key_fp": "abc123def456", "sources": ["203.0.113.9"],
                 "hit_count": 4}),
    ])
    assert not verdict.compromised


def test_correlation_reports_model_relay(workspace):
    ctx = RunContext(workspace, dry_run=True)
    ctx.add_events([
        _ev("relay_process", minutes=1, category=Category.PROCESS,
            path="/opt/new-api", tags=["relay", "model_listen", "model_upstream"]),
        _ev("external_connection", minutes=2, category=Category.NETWORK,
            src_ip="198.51.100.8", tags=["external-conn", "inbound"]),
    ])
    findings = CorrelationAnalyzer()._r9_model_relay(ctx)
    assert len(findings) == 1
    assert findings[0].details["peers"] == ["198.51.100.8"]
