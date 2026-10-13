"""情报聚合器: 多源并发查询 + 缓存 + 限速 + 证据留痕。

检测默认只查本地源（规则、CSV、手动拉取落地的本地威胁库）。
在线平台只在调用方显式传入 ``providers`` 时参与查询，
用于手动拉取，以及 AI 交叉验证开关打开后的单次判定。
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from irtrace.intel.base import ThreatIntelProvider
from irtrace.intel.cache import IntelCache
from irtrace.intel.http import RateLimiter
from irtrace.intel.models import IndicatorType, IntelReport, IntelVerdict
from irtrace.intel.registry import intel_registry

logger = logging.getLogger("irtrace.intel")

#: 检测默认启用的离线情报源。local_db 是手动拉取落地的本地库。
DEFAULT_OFFLINE_PROVIDERS = ["local_rules", "csv_feed", "local_db"]
#: 不需要 API Key 的公开源。只在手动拉取或交叉验证时使用。
DEFAULT_PUBLIC_PROVIDERS = ["public_feeds"]


# 存在密钥库里、但不属于情报平台的条目。
_NON_INTEL_SECRETS = {"ai_model"}


def _enabled_secret_names(workspace) -> List[str]:
    try:
        from irtrace.secrets import SecretStore
        return [name for name in SecretStore(workspace).enabled_names()
                if name not in _NON_INTEL_SECRETS]
    except (OSError, ValueError):
        return []


def _apply_stored_secret(name: str, pcfg: Dict[str, Any]) -> None:
    """把密钥库里的 Key 与附加配置注入平台配置。库里没有则保持原样。"""
    workspace = pcfg.get("workspace")
    if not workspace:
        return
    try:
        from irtrace.secrets import SecretStore
        stored = SecretStore(workspace).get(name)
    except (OSError, ValueError):
        return
    if not stored or not stored.get("enabled"):
        return
    if stored.get("api_key") and not pcfg.get("api_key"):
        pcfg["api_key"] = stored["api_key"]
    for key, value in (stored.get("extra") or {}).items():
        pcfg.setdefault(key, value)


class IntelAggregator:
    """威胁情报聚合查询入口。"""

    def __init__(
        self,
        providers: Sequence[ThreatIntelProvider],
        *,
        ctx: Any = None,
        cache: Optional[IntelCache] = None,
        max_workers: int = 6,
    ) -> None:
        self.providers = list(providers)
        self.ctx = ctx
        self.cache = cache
        self.max_workers = max(1, max_workers)
        self.rate_limiter = RateLimiter(
            min_interval=max((p.min_interval for p in self.providers), default=0.0))
        self.queries = 0
        self.cache_hits = 0

    # ------------------------------------------------------------------ #
    # 构造
    # ------------------------------------------------------------------ #
    @classmethod
    def from_config(cls, cfg: Optional[Dict[str, Any]] = None,
                    ctx: Any = None, workspace: Any = None) -> "IntelAggregator":
        cfg = cfg or {}
        intel_registry.discover()

        # providers 由调用方显式给出时，在线源也参与查询（手动拉取、交叉验证）。
        # 没有给出时只用离线源，检测不会自己去请求在线情报。
        explicit = bool(cfg.get("providers"))
        wanted: List[str] = list(cfg.get("providers") or DEFAULT_OFFLINE_PROVIDERS)

        per_cfg: Dict[str, Dict[str, Any]] = cfg.get("platforms", {}) or {}

        instances: List[ThreatIntelProvider] = []
        for name in wanted:
            cls_ = intel_registry.get(name)
            if cls_ is None:
                logger.warning("未知情报平台, 已跳过: %s", name)
                continue
            pcfg = dict(per_cfg.get(name, {}))
            # 离线源需要知道工作区位置以定位 data/rules 与 data/intel
            ws = workspace or (ctx.workspace if ctx is not None else None)
            if ws is not None:
                pcfg.setdefault("workspace", str(ws))
                _apply_stored_secret(name, pcfg)
            provider = cls_(pcfg)
            # 离线源始终可用。在线源只有调用方点名要查时才启用。
            if not provider.offline:
                if not explicit:
                    continue
                if not provider.available:
                    logger.warning("情报源 %s 不可用: %s", name,
                                   provider.unavailable_reason())
                    continue
            instances.append(provider)

        cache = None
        if cfg.get("cache_enabled", True):
            cache_dir = cfg.get("cache_dir")
            if not cache_dir:
                base = Path(ctx.workspace) if ctx is not None else Path.cwd()
                cache_dir = base / "data" / "intel-cache"
            cache = IntelCache(cache_dir, float(cfg.get("cache_ttl_hours", 24)))

        return cls(instances, ctx=ctx, cache=cache)

    # ------------------------------------------------------------------ #
    # 查询
    # ------------------------------------------------------------------ #
    def lookup(self, indicator: str, itype: IndicatorType) -> IntelReport:
        """查询单个指标 (并发调用各平台)。"""
        report = IntelReport(indicator=indicator, indicator_type=itype)
        indicator = indicator.strip()
        if not indicator:
            return report

        verdicts: List[IntelVerdict] = []
        online = [p for p in self.providers if not p.offline]

        # 离线源同步执行 (快, 无网络)
        for p in self.providers:
            if p.offline:
                verdicts.append(self._query_one(p, indicator, itype))

        # 在线源并发执行
        if online:
            with ThreadPoolExecutor(max_workers=min(self.max_workers, len(online))) as pool:
                futures = {pool.submit(self._query_one, p, indicator, itype): p
                           for p in online}
                for fut in as_completed(futures):
                    try:
                        verdicts.append(fut.result())
                    except Exception as exc:  # noqa: BLE001
                        p = futures[fut]
                        verdicts.append(p.error_verdict(indicator, itype, str(exc)))

        report.verdicts = verdicts
        self._record_evidence(report)
        return report

    def lookup_many(
        self, indicators: Iterable[Tuple[str, IndicatorType]]
    ) -> Dict[Tuple[str, IndicatorType], IntelReport]:
        """批量查询 (自动去重)。"""
        unique: List[Tuple[str, IndicatorType]] = []
        seen = set()
        for ind, itype in indicators:
            ind = (ind or "").strip()
            key = (ind, itype)
            if ind and key not in seen:
                seen.add(key)
                unique.append(key)

        out: Dict[Tuple[str, IndicatorType], IntelReport] = {}
        for ind, itype in unique:
            out[(ind, itype)] = self.lookup(ind, itype)
        return out

    # ------------------------------------------------------------------ #
    def _query_one(self, provider: ThreatIntelProvider, indicator: str,
                   itype: IndicatorType) -> IntelVerdict:
        key = f"{provider.name}:{itype.value}:{indicator}"

        if self.cache is not None:
            cached = self.cache.get(key)
            if cached is not None:
                self.cache_hits += 1
                return self._verdict_from_cache(provider, indicator, itype, cached)

        self.queries += 1
        self.rate_limiter.acquire(provider.name)
        verdict = provider.lookup(indicator, itype)

        if self.cache is not None and verdict.ok:
            self.cache.set(key, verdict.to_dict())
        return verdict

    @staticmethod
    def _verdict_from_cache(provider: ThreatIntelProvider, indicator: str,
                            itype: IndicatorType, payload: Dict[str, Any]) -> IntelVerdict:
        from datetime import datetime, timezone
        from irtrace.core.models import Severity
        return IntelVerdict(
            indicator=indicator, indicator_type=itype, provider=provider.name,
            malicious=bool(payload.get("malicious")),
            score=float(payload.get("score", 0.0)),
            confidence=float(payload.get("confidence", 0.5)),
            severity=Severity(payload.get("severity", "info")),
            tags=list(payload.get("tags", [])),
            description=payload.get("description", ""),
            raw=payload.get("raw", {}),
            queried_at=datetime.now(timezone.utc),
            cached=True,
        )

    # ------------------------------------------------------------------ #
    def _record_evidence(self, report: IntelReport) -> None:
        """把情报查询结果落盘为证据 (保证证据链完整可审计)。"""
        if self.ctx is None:
            return
        try:
            self.ctx.store_evidence(
                source="intel",
                kind="intel_report",
                name=f"{report.indicator_type.value}__{report.indicator}".replace(
                    "/", "_").replace(":", "_"),
                data=report.to_json(),
                note=f"威胁情报查询: {report.indicator} ({len(report.valid_verdicts)} 源)",
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug("情报证据落盘失败: %s", exc)

    # ------------------------------------------------------------------ #
    def describe(self) -> Dict[str, Any]:
        return {
            "providers": [
                {"name": p.name, "offline": p.offline, "available": p.available,
                 "weight": p.weight, "supports": [t.value for t in p.supports],
                 "reason": p.unavailable_reason()}
                for p in self.providers
            ],
            "queries": self.queries,
            "cache_hits": self.cache_hits,
            "cache": self.cache.stats() if self.cache else None,
        }

    def stats(self) -> Dict[str, Any]:
        return {"queries": self.queries, "cache_hits": self.cache_hits,
                "providers": [p.name for p in self.providers]}


__all__ = ["IntelAggregator", "DEFAULT_OFFLINE_PROVIDERS"]
