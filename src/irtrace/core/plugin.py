"""插件基类。

三类插件统一契约::

    Collector.collect(ctx)  -> CollectResult   (产出 Event / Evidence)
    Analyzer.analyze(ctx)   -> List[Finding]
    Reporter.render(ctx)    -> Path

插件通过 ``@register`` 装饰器登记到全局注册中心; 框架在启动时
自动发现 ``irtrace.collectors`` / ``irtrace.analyzers`` / ``irtrace.reporters``
包下的所有模块。
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from irtrace.core.models import Event, Evidence, Finding

if TYPE_CHECKING:  # pragma: no cover
    from irtrace.core.context import RunContext


@dataclass
class CollectResult:
    """采集结果聚合容器。"""

    events: List[Event] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    stats: Dict[str, Any] = field(default_factory=dict)

    def extend(self, other: "CollectResult") -> None:
        self.events.extend(other.events)
        self.evidence.extend(other.evidence)
        self.warnings.extend(other.warnings)
        self.stats.update(other.stats)


class BasePlugin(abc.ABC):
    """所有插件基类。"""

    #: 插件唯一名 (用于 CLI --only / --skip)
    name: str = ""
    #: 人类可读描述
    description: str = ""
    #: 插件版本
    version: str = "0.1.0"
    #: 依赖的外部命令 (缺失时跳过并告警, 不抛异常)
    requires_commands: List[str] = []
    #: 依赖的目标文件/目录 (不存在时跳过)
    requires_paths: List[str] = []
    #: 默认是否启用
    enabled_by_default: bool = True

    def __init__(self) -> None:
        if not self.name:
            self.name = self.__class__.__name__.lower()

    # -- 生命周期钩子 ------------------------------------------------------ #
    def preflight(self, ctx: "RunContext") -> Optional[str]:
        """返回非 None 字符串表示跳过原因; 返回 None 表示可执行。"""
        for cmd in self.requires_commands:
            if not ctx.which(cmd):
                return f"缺少外部命令: {cmd}"
        return None

    def __repr__(self) -> str:  # pragma: no cover
        return f"<{self.__class__.__name__} name={self.name!r}>"


class Collector(BasePlugin):
    """采集器基类。只读采集, 禁止修改目标状态。"""

    category: str = "other"

    @abc.abstractmethod
    def collect(self, ctx: "RunContext") -> CollectResult:
        """执行采集。实现中应使用 ctx.run_command / ctx.read_file 等只读接口。"""
        raise NotImplementedError


class Analyzer(BasePlugin):
    """分析器基类。消费 ctx 中的事件与证据, 产出 Finding。"""

    @abc.abstractmethod
    def analyze(self, ctx: "RunContext") -> List[Finding]:
        raise NotImplementedError


class Reporter(BasePlugin):
    """报告生成器基类。"""

    #: 输出文件扩展名
    extension: str = "txt"

    @abc.abstractmethod
    def render(self, ctx: "RunContext") -> Any:
        """生成报告, 返回输出文件路径 (str / Path)。"""
        raise NotImplementedError


__all__ = [
    "CollectResult",
    "BasePlugin",
    "Collector",
    "Analyzer",
    "Reporter",
]
