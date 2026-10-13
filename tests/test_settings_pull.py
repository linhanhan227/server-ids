"""配置进 SQLite，检测不主动拉在线情报，交叉验证默认关闭。"""

from __future__ import annotations

import json
from urllib.request import Request, urlopen

from irtrace.analyzers.ai_assist import _intel_for_assist
from irtrace.core.context import RunContext
from irtrace.intel.localdb import ThreatDB
from irtrace.intel.pull import pull_threats
from irtrace.settings import SettingsStore
from irtrace.web.server import create_server


def test_cross_validate_defaults_off_and_stays_local(workspace):
    ctx = RunContext(workspace, persistent=False)
    cfg = _intel_for_assist(ctx)
    assert ctx.config["ai"]["cross_validate"] is False
    assert cfg["providers"] == ["local_rules", "csv_feed", "local_db"]

    SettingsStore(workspace).update({"ai": {"cross_validate": True}})
    ctx.config = SettingsStore(workspace).load()
    opened = _intel_for_assist(ctx)
    assert "public_feeds" not in opened["providers"]
    assert opened["providers"] == ["local_rules", "csv_feed", "local_db"]


def test_manual_pull_stores_only_exported_rows(workspace, monkeypatch):
    class _Feed:
        name = "public_feeds"
        offline = False
        available = True

        def __init__(self, config=None):
            pass

        def export_indicators(self):
            return [{
                "indicator": "203.0.113.9",
                "indicator_type": "ip",
                "provider": "public_feeds",
                "malicious": True,
                "score": 70,
                "confidence": 0.7,
                "severity": "high",
                "tags": ["public-feed"],
                "description": "测试收录",
                "raw": {"line": "203.0.113.9"},
            }], []

        def unavailable_reason(self):
            return None

    monkeypatch.setattr(
        "irtrace.intel.registry.intel_registry.get",
        lambda name: _Feed if name == "public_feeds" else None,
    )
    summary = pull_threats(workspace, ["public_feeds"])
    assert summary["stored"] == 1
    rows = ThreatDB(workspace).lookup("203.0.113.9", "ip")
    assert rows[0]["provider"] == "public_feeds"
    assert rows[0]["malicious"] is True


def test_settings_api_defaults_cross_validate_off(workspace):
    server = create_server(workspace, "127.0.0.1", 0)
    port = server.server_address[1]
    import threading
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{port}"
        view = json.loads(urlopen(base + "/api/settings", timeout=5).read())
        assert view["ai"]["cross_validate"] is False
        body = json.dumps({"ai": {"enabled": True, "cross_validate": True}}).encode()
        req = Request(base + "/api/settings", data=body, method="POST",
                      headers={"Content-Type": "application/json"})
        saved = json.loads(urlopen(req, timeout=5).read())
        assert saved["ai"]["cross_validate"] is True
        again = json.loads(urlopen(base + "/api/settings", timeout=5).read())
        assert again["ai"]["cross_validate"] is True
    finally:
        server.shutdown()
