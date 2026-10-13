"""威胁情报：本地规则、CSV 情报源、聚合与 IOC 分析。"""

from __future__ import annotations

from datetime import datetime, timezone

from irtrace.analyzers.ioc import IOCAnalyzer
from irtrace.core.context import RunContext
from irtrace.core.models import Category, Event, Severity
from irtrace.core.registry import registry
from irtrace.intel import IndicatorType, IntelAggregator
from irtrace.intel.providers.local_rules import LocalRulesProvider
from irtrace.intel.registry import intel_registry


def test_local_rules_hit_known_ip(workspace):
    intel_registry.discover()
    provider = LocalRulesProvider({"workspace": str(workspace)})
    verdict = provider.lookup("45.155.205.233", IndicatorType.IP)
    assert verdict.malicious
    assert verdict.score >= 80
    assert "local-rule" in verdict.tags


def test_local_rules_keyword_and_port(workspace):
    intel_registry.discover()
    provider = LocalRulesProvider({"workspace": str(workspace)})
    keyword = provider.lookup("https://pool.example/xmrig", IndicatorType.URL)
    assert keyword.malicious
    assert "keyword-match" in keyword.tags

    port = provider.lookup("203.0.113.10:4444", IndicatorType.IP)
    assert port.malicious
    assert port.raw["port"] == 4444

    clean = provider.lookup("1.1.1.1", IndicatorType.IP)
    assert not clean.malicious


def test_csv_feed_and_aggregator(workspace):
    intel_registry.discover()
    ctx = RunContext(workspace, persistent=False)
    agg = IntelAggregator.from_config({"mode": "offline", "cache_enabled": False}, ctx=ctx)
    names = {p.name for p in agg.providers}
    assert {"local_rules", "csv_feed", "local_db"} <= names
    assert all(p.offline for p in agg.providers)

    report = agg.lookup("evil.example.com", IndicatorType.DOMAIN)
    assert report.is_malicious
    assert "csv_feed" in report.malicious_sources

    ip = agg.lookup("45.155.205.233", IndicatorType.IP)
    assert set(ip.malicious_sources) >= {"local_rules", "csv_feed"}
    assert ip.severity.weight >= Severity.HIGH.weight


def test_ioc_analyzer_emits_one_finding_per_indicator(workspace):
    registry.discover()
    intel_registry.discover()
    ctx = RunContext(workspace)
    ts = datetime(2026, 10, 12, 11, 0, tzinfo=timezone.utc)
    for _ in range(3):
        ctx.add_event(Event(
            timestamp=ts, category=Category.NETWORK, source="network",
            action="external_conn", dst_ip="45.155.205.233",
            message="外联 45.155.205.233:3333 进程=xmrig",
        ))
    findings = IOCAnalyzer().analyze(ctx)
    hits = [f for f in findings if "45.155.205.233" in f.title]
    assert len(hits) == 1
    assert hits[0].severity.weight >= Severity.HIGH.weight
    assert (ctx.evidence_dir / "ioc" / "iocs.md").exists()
