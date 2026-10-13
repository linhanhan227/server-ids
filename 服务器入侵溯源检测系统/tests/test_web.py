"""报告产物与 Web 只读接口。"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from urllib.request import urlopen

from irtrace.core.context import RunContext
from irtrace.core.models import Category, Event
from irtrace.core.pipeline import Orchestrator
from irtrace.core.registry import registry
from irtrace.web.server import RunStore, create_server


def _seed(ctx: RunContext) -> None:
    base = datetime(2026, 10, 12, 7, 0, tzinfo=timezone.utc)
    for i in range(8):
        ctx.add_event(Event(
            timestamp=base + timedelta(minutes=i),
            category=Category.AUTH, source="auth_log", action="ssh_failed",
            src_ip="45.155.205.233", user="root",
            message=f"Failed password from 45.155.205.233 #{i}",
            tags=["bruteforce"],
        ))
    ctx.add_event(Event(
        timestamp=base + timedelta(minutes=9),
        category=Category.AUTH, source="auth_log", action="ssh_login",
        src_ip="45.155.205.233", user="root",
        message="Accepted password for root from 45.155.205.233",
        tags=["ssh"],
    ))


def test_pipeline_writes_three_reports(workspace):
    registry.discover()
    ctx = RunContext(workspace)
    _seed(ctx)
    result = Orchestrator(ctx).run(skip_collect=True)
    ctx.close()

    names = {p.split("/")[-1] for p in result["outputs"]}
    assert {"result.json", "report.md", "report.html"} <= names
    payload = json.loads((ctx.report_dir / "result.json").read_text(encoding="utf-8"))
    assert payload["meta"]["run_id"] == ctx.run_id
    assert payload["findings"]
    assert "爆破成功" in payload["findings"][0]["title"] or any(
        "爆破成功" in f["title"] for f in payload["findings"]
    )
    ctx.verify_ledger()


def test_runstore_and_readonly_api(workspace):
    registry.discover()
    ctx = RunContext(workspace)
    _seed(ctx)
    Orchestrator(ctx).run(skip_collect=True)
    ctx.close()

    store = RunStore(workspace)
    runs = store.list_runs()
    assert [r["run_id"] for r in runs] == [ctx.run_id]
    detail = store.get_run(ctx.run_id)
    assert detail and detail["findings"]
    assert store.get_run("../etc") is None
    assert store.get_run("no-such-run") is None

    server = create_server(workspace, "127.0.0.1", 0)
    port = server.server_address[1]
    import threading
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{port}"
        health = json.loads(urlopen(base + "/api/health", timeout=5).read())
        assert health["status"] == "ok"
        listed = json.loads(urlopen(base + "/api/runs", timeout=5).read())
        assert listed["runs"][0]["run_id"] == ctx.run_id
        page = urlopen(base + "/", timeout=5).read().decode("utf-8")
        assert "入侵检测控制台" in page
        try:
            urlopen(base + "/api/runs/..%2F..%2Fetc", timeout=5)
        except Exception as exc:
            assert getattr(exc, "code", None) in {400, 404}
        else:
            raise AssertionError("目录穿越应当被拒绝")
    finally:
        server.shutdown()
        server.server_close()
