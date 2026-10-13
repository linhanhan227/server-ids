"""威胁情报 Provider 基类。

新增平台只需继承 ``ThreatIntelProvider`` 并实现 ``_lookup``::

    @register_provider
    class MyProvider(ThreatIntelProvider):
        name = "myintel"
        requires_api_key = True
        api_key_env = "MYINTEL_API_KEY"
        supports = (IndicatorType.IP,)

        def _lookup(self, indicator, itype):
            status, data, err = request_json(...)
            if err:
                return self.error_verdict(indicator, itype, err)
            return self.verdict(indicator, itype, malicious=..., score=..., ...)
"""

from __future__ import annotations

import abc
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

from irtrace.core.models import Severity
from irtrace.intel.models import IndicatorType, IntelVerdict

logger = logging.getLogger("irtrace.intel")


class ThreatIntelProvider(abc.ABC):
    """威胁情报平台适配器基类。"""

    #: 平台标识 (用于配置与报告展示)
    name: str = ""
    description: str = ""
    version: str = "0.1.0"
    #: 平台主页 / API 文档
    homepage: str = ""
    #: 支持的指标类型
    supports: Sequence[IndicatorType] = (IndicatorType.IP,)
    #: 是否需要 API Key
    requires_api_key: bool = True
    #: 读取 API Key 的环境变量名
    api_key_env: str = ""
    #: 是否属于离线源 (离线源在 offline 模式下也启用)
    offline: bool = False
    #: 该平台在聚合时的可信权重 (0~2)
    weight: float = 1.0
    #: 建议的最小查询间隔 (秒), 用于限速
    min_interval: float = 1.0
    #: 单次查询超时
    timeout: int = 10

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        self.config: Dict[str, Any] = config or {}
        if not self.name:
            self.name = self.__class__.__name__.lower()
        # 配置覆盖
        self.weight = float(self.config.get("weight", self.weight))
        self.timeout = int(self.config.get("timeout", self.timeout))
        self.min_interval = float(self.config.get("min_interval", self.min_interval))
        self.api_key_env = self.config.get("api_key_env", self.api_key_env)
        self._api_key: Optional[str] = self.config.get("api_key")

    # ------------------------------------------------------------------ #
    # API Key
    # ------------------------------------------------------------------ #
    @property
    def api_key(self) -> Optional[str]:
        """显式配置 > 密钥库 > 环境变量。"""
        if self._api_key:
            return self._api_key
        stored = self._key_from_store()
        if stored:
            return stored
        if self.api_key_env:
            return os.environ.get(self.api_key_env) or None
        return None

    def _key_from_store(self) -> Optional[str]:
        workspace = self.config.get("workspace")
        if not workspace or not self.requires_api_key:
            return None
        try:
            from irtrace.secrets import SecretStore
            return SecretStore(workspace).api_key_for(self.name)
        except (OSError, ValueError):
            return None

    @property
    def available(self) -> bool:
        """该平台当前是否可用 (在线平台需已配置 API Key)。"""
        if self.offline:
            return True
        if self.requires_api_key and not self.api_key:
            return False
        return True

    def unavailable_reason(self) -> Optional[str]:
        if self.offline:
            return None
        if self.requires_api_key and not self.api_key:
            where = "Web 控制台「情报源」或环境变量 " + (self.api_key_env or "N/A")
            return f"未配置 API Key ({where})"
        return None

    # ------------------------------------------------------------------ #
    # 查询入口 (由聚合器调用, 负责类型校验)
    # ------------------------------------------------------------------ #
    def lookup(self, indicator: str, itype: IndicatorType) -> IntelVerdict:
        if itype not in self.supports:
            return self.error_verdict(indicator, itype, f"{self.name} 不支持 {itype.value} 查询")
        if not self.available:
            return self.error_verdict(indicator, itype,
                                      self.unavailable_reason() or "平台不可用")
        try:
            return self._lookup(indicator, itype)
        except Exception as exc:  # noqa: BLE001 - 单平台异常不影响整体
            logger.debug("情报查询异常 %s/%s: %s", self.name, indicator, exc)
            return self.error_verdict(indicator, itype, f"查询异常: {exc}")

    @abc.abstractmethod
    def _lookup(self, indicator: str, itype: IndicatorType) -> IntelVerdict:
        """子类实现实际查询逻辑。"""
        raise NotImplementedError

    def export_indicators(self):
        """手动拉取时导出可入库的指标。没有清单接口的源返回空列表。"""
        return [], [f"{self.name}: 没有可整份拉取的清单，请在交叉验证里按指标查询"]

    # ------------------------------------------------------------------ #
    # 构造结果
    # ------------------------------------------------------------------ #
    def verdict(
        self,
        indicator: str,
        itype: IndicatorType,
        *,
        malicious: bool,
        score: float,
        severity: Optional[Severity] = None,
        confidence: float = 0.8,
        tags: Optional[List[str]] = None,
        description: str = "",
        raw: Optional[Dict[str, Any]] = None,
        cached: bool = False,
    ) -> IntelVerdict:
        return IntelVerdict(
            indicator=indicator,
            indicator_type=itype,
            provider=self.name,
            malicious=malicious,
            score=round(float(score), 1),
            confidence=round(min(1.0, max(0.0, confidence * self.weight)), 3),
            severity=severity or self.severity_from_score(score),
            tags=tags or [],
            description=description,
            raw=raw or {},
            queried_at=datetime.now(timezone.utc),
            cached=cached,
        )

    def error_verdict(self, indicator: str, itype: IndicatorType,
                      error: str) -> IntelVerdict:
        return IntelVerdict(
            indicator=indicator, indicator_type=itype, provider=self.name,
            malicious=False, score=0.0, confidence=0.0,
            severity=Severity.INFO, error=error,
        )

    @staticmethod
    def severity_from_score(score: float) -> Severity:
        if score >= 80:
            return Severity.CRITICAL
        if score >= 60:
            return Severity.HIGH
        if score >= 40:
            return Severity.MEDIUM
        if score >= 20:
            return Severity.LOW
        return Severity.INFO

    def __repr__(self) -> str:  # pragma: no cover
        return f"<{self.__class__.__name__} name={self.name!r} available={self.available}>"


__all__ = ["ThreatIntelProvider"]
