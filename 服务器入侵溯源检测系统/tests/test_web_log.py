"""Web 访问日志解析与场景判定。

采集器用合成日志验证，不读本机 /var/log。
判定用例并入同一套失陷口径：访问成功才算执行，扫描不算失陷。
"""

from __future__ import annotations

from pathlib import Path

from irtrace.analyzers.correlation import CorrelationAnalyzer
from irtrace.analyzers.intrusion import judge_intrusion
from irtrace.collectors.filesystem import FilesystemCollector
from irtrace.collectors.web_log import classify_request, parse_access_line
from irtrace.collectors.web_log import WebLogCollector
from irtrace.collectors.web_shell import same_web_file
from irtrace.core.context import RunContext
from irtrace.core.models import Category, Event
from irtrace.core.registry import registry

from test_detection_accuracy import _ev


_LINE = (
    '{ip} - - [{time}] "{method} {target} HTTP/1.1" {status} 128 '
    '"-" "scanner"'
)


def _line(ip: str, target: str, status: int = 200, method: str = "GET",
          time: str = "13/Oct/2026:08:00:00 +0000") -> str:
    return _LINE.format(ip=ip, method=method, target=target,
                        status=status, time=time)


def test_parse_combined_line():
    record = parse_access_line(_line("203.0.113.8", "/app.php?id=1", 200))
    assert record is not None
    assert record["ip"] == "203.0.113.8"
    assert record["path"] == "/app.php"
    assert record["status"] == 200
    assert record["timestamp"] is not None
    assert parse_access_line("not a log line") is None


def test_classify_webshell_not_normal_php():
    shell = parse_access_line(_line("203.0.113.8", "/uploads/c99.php", 200))
    page = parse_access_line(_line("10.0.0.2", "/index.php", 200))
    assert shell is not None and classify_request(shell) == "webshell"
    assert page is not None and classify_request(page) is None


def test_classify_command_parameter():
    hit = parse_access_line(_line(
        "203.0.113.8", "/image.php?cmd=cat+/etc/passwd", 200,
    ))
    noise = parse_access_line(_line(
        "10.0.0.2", "/search?q=whoami", 200,
    ))
    assert hit is not None and classify_request(hit) == "webshell"
    assert noise is not None and classify_request(noise) is None


def test_classify_probe_requires_error_status():
    missing = parse_access_line(_line("198.51.100.4", "/.env", 404))
    present = parse_access_line(_line("198.51.100.4", "/.env", 200))
    assert missing is not None and classify_request(missing) == "probe"
    assert present is not None and classify_request(present) is None


def test_collector_emits_shell_and_scan(workspace: Path, monkeypatch):
    log_dir = workspace / "logs"
    log_dir.mkdir()
    log_path = log_dir / "access.log"
    lines = [_line("203.0.113.8", "/uploads/wso.php", 200)]
    lines += [
        _line("198.51.100.9", f"/.env?n={i}", 404,
              time=f"13/Oct/2026:08:{i % 60:02d}:00 +0000")
        for i in range(20)
    ]
    lines.append(_line("10.0.0.5", "/index.php", 200))
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ctx = RunContext(workspace, dry_run=True)
    monkeypatch.setattr(
        "irtrace.collectors.web_log._LOG_CANDIDATES", (str(log_path),),
    )

    result = WebLogCollector().collect(ctx)
    actions = [event.action for event in result.events]
    assert actions.count("web_shell_request") == 1
    assert actions.count("web_scan") == 1
    assert result.stats["web_logs"] == 1
    shell = next(event for event in result.events
                 if event.action == "web_shell_request")
    assert shell.raw["status"] == 200
    assert shell.path == "/uploads/wso.php"


def test_web_log_registered():
    registry.discover()
    assert "web_log" in registry.names()


def test_live_webshell_is_compromise():
    verdict = judge_intrusion([
        _ev("web_shell_request", minutes=1, category=Category.LOG,
            src_ip="203.0.113.8", path="/uploads/c99.php",
            tags=["webshell", "web"],
            message="webshell 请求",
            raw={"status": 200, "method": "GET"}),
    ])
    assert verdict.compromised
    assert any("webshell" in item for item in verdict.signals)


def test_not_found_shell_is_not_compromise():
    verdict = judge_intrusion([
        _ev("web_shell_request", minutes=i, category=Category.LOG,
            src_ip="198.51.100.4", path=f"/x{i}.php",
            tags=["webshell", "web"],
            raw={"status": 404, "method": "GET"})
        for i in range(3)
    ])
    assert not verdict.compromised


def test_scan_only_is_not_compromise():
    verdict = judge_intrusion([
        _ev("web_scan", minutes=1, category=Category.LOG,
            src_ip="198.51.100.9", tags=["web-scan", "web"],
            raw={"hit_count": 40}),
    ])
    assert not verdict.compromised


def test_same_web_file_matches_document_root():
    assert same_web_file("/uploads/c99.php", "/var/www/html/uploads/c99.php")
    assert not same_web_file("/uploads/c99.php", "/var/www/html/other/c99.php")
    assert same_web_file("/c99.php", "/var/www/html/c99.php")


def test_filesystem_flags_web_shell(workspace: Path, monkeypatch):
    root = workspace / "www"
    (root / "uploads").mkdir(parents=True)
    shell = root / "uploads" / "wso.php"
    page = root / "index.php"
    hidden = root / "img.php"
    shell.write_text("<?php echo 1; ?>", encoding="utf-8")
    page.write_text("<?php echo 'ok'; ?>", encoding="utf-8")
    hidden.write_text(
        "<?php eval(base64_decode($_POST['c'])); system($_GET['cmd']); ?>",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "irtrace.collectors.filesystem.WEB_ROOTS", (str(root),),
    )
    monkeypatch.setattr(
        "irtrace.collectors.filesystem._WRITABLE_DIRS", (),
    )
    ctx = RunContext(workspace, dry_run=True)
    result = FilesystemCollector().collect(ctx)
    found = {event.path: event.raw["reason"] for event in result.events
             if event.action == "web_shell_file"}
    assert found[str(shell)] == "filename"
    assert found[str(hidden)] == "content"
    assert str(page) not in found


def test_correlation_links_file_and_request(workspace: Path):
    ctx = RunContext(workspace, dry_run=True)
    ctx.add_events([
        _ev("web_shell_file", minutes=1, category=Category.FILE,
            path="/var/www/html/uploads/alfa.php", tags=["webshell", "web-file"]),
        _ev("web_shell_request", minutes=2, category=Category.LOG,
            src_ip="203.0.113.8", path="/uploads/alfa.php",
            tags=["webshell", "web"], raw={"status": 200, "method": "POST"}),
        _ev("web_shell_request", minutes=3, category=Category.LOG,
            src_ip="198.51.100.1", path="/other.php",
            tags=["webshell", "web"], raw={"status": 200, "method": "GET"}),
    ])
    findings = CorrelationAnalyzer()._r7_webshell_file_and_request(ctx)
    assert len(findings) == 1
    assert findings[0].details["path"] == "/var/www/html/uploads/alfa.php"
    assert findings[0].details["responded_count"] == 1
    assert findings[0].details["src_ips"] == ["203.0.113.8"]


def test_unvisited_shell_file_is_not_compromise():
    verdict = judge_intrusion([
        _ev("web_shell_file", minutes=1, category=Category.FILE,
            path="/var/www/html/uploads/c99.php", tags=["webshell", "web-file"]),
    ])
    assert not verdict.compromised


def test_visited_shell_file_adds_persistence():
    verdict = judge_intrusion([
        _ev("web_shell_file", minutes=1, category=Category.FILE,
            path="/var/www/html/uploads/c99.php", tags=["webshell", "web-file"]),
        _ev("web_shell_request", minutes=2, category=Category.LOG,
            src_ip="203.0.113.8", path="/uploads/c99.php",
            tags=["webshell", "web"], raw={"status": 200, "method": "GET"}),
    ])
    assert verdict.compromised
    assert any("落地" in item for item in verdict.signals)


def test_webshell_then_privilege_is_compromise():
    events: list[Event] = [
        _ev("web_shell_request", minutes=1, category=Category.LOG,
            src_ip="203.0.113.8", path="/uploads/alfa.php",
            tags=["webshell", "web"],
            raw={"status": 500, "method": "POST"}),
        _ev("sudo", minutes=4, user="www-data", category=Category.ACCOUNT,
            tags=["privilege-escalation"],
            message="COMMAND=/usr/sbin/useradd backdoor"),
    ]
    verdict = judge_intrusion(events)
    assert verdict.compromised
    assert any("提权" in item for item in verdict.signals)
