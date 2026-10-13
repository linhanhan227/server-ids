"""核心层: 数据模型、插件基类、注册中心、编排引擎、运行上下文。"""

from irtrace.core.models import (
    Event,
    Evidence,
    Finding,
    Severity,
    Confidence,
    Category,
)
from irtrace.core.plugin import BasePlugin, Collector, Analyzer, Reporter
from irtrace.core.registry import registry, register
from irtrace.core.context import RunContext
from irtrace.core.pipeline import Orchestrator
from irtrace.core.errors import (
    IRTraceError,
    PluginError,
    CollectorError,
    AnalyzerError,
    ReporterError,
)

__all__ = [
    "Event",
    "Evidence",
    "Finding",
    "Severity",
    "Confidence",
    "Category",
    "BasePlugin",
    "Collector",
    "Analyzer",
    "Reporter",
    "registry",
    "register",
    "RunContext",
    "Orchestrator",
    "IRTraceError",
    "PluginError",
    "CollectorError",
    "AnalyzerError",
    "ReporterError",
]
