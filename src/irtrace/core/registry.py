"""插件注册中心。

用法::

    from irtrace.core import register, Collector

    @register
    class MyCollector(Collector):
        name = "my_collector"
        ...

框架通过 :func:`discover` 自动导入内置包, 通过 :func:`load_external`
支持 ``--plugin-dir`` 加载第三方插件目录。
"""

from __future__ import annotations

import importlib
import importlib.util
import pkgutil
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Type

from irtrace.core.errors import PluginError
from irtrace.core.plugin import Analyzer, BasePlugin, Collector, Reporter


class PluginRegistry:
    """全局插件注册表。"""

    _KINDS = {
        "collector": Collector,
        "analyzer": Analyzer,
        "reporter": Reporter,
    }

    def __init__(self) -> None:
        self._plugins: Dict[str, BasePlugin] = {}
        self._loaded_modules: set = set()

    # -- 注册 -------------------------------------------------------------- #
    def register(self, cls: Type[BasePlugin]) -> Type[BasePlugin]:
        if not issubclass(cls, BasePlugin):
            raise PluginError(f"{cls!r} 不是 BasePlugin 子类")
        instance = cls()
        if not instance.name:
            raise PluginError(f"{cls.__name__} 缺少 name 属性")
        if instance.name in self._plugins:
            raise PluginError(f"插件名重复: {instance.name}")
        self._plugins[instance.name] = instance
        return cls

    # -- 查询 -------------------------------------------------------------- #
    def get(self, name: str) -> BasePlugin:
        try:
            return self._plugins[name]
        except KeyError as exc:
            raise PluginError(f"未注册的插件: {name}") from exc

    def all(self) -> List[BasePlugin]:
        return list(self._plugins.values())

    def by_kind(self, kind: str) -> List[BasePlugin]:
        base = self._KINDS.get(kind)
        if base is None:
            raise PluginError(f"未知插件类别: {kind}")
        return [p for p in self._plugins.values() if isinstance(p, base)]

    def names(self) -> List[str]:
        return sorted(self._plugins)

    def clear(self) -> None:
        self._plugins.clear()
        self._loaded_modules.clear()

    # -- 发现 -------------------------------------------------------------- #
    def discover(self, packages: Iterable[str] = ("irtrace.collectors",
                                                  "irtrace.analyzers",
                                                  "irtrace.reporters")) -> None:
        """导入内置包下所有模块以触发 ``@register``。

        幂等: 模块一旦进过 ``sys.modules`` 就不再重载。重载会再次执行
        ``@register``, 在 ``clear()`` 之后造成「插件名重复」。
        """
        for pkg_name in packages:
            try:
                pkg = importlib.import_module(pkg_name)
            except ImportError:
                continue
            for mod in pkgutil.iter_modules(pkg.__path__):
                if mod.name.startswith("_"):
                    continue
                full = f"{pkg_name}.{mod.name}"
                if full in self._loaded_modules or full in sys.modules:
                    self._loaded_modules.add(full)
                    continue
                importlib.import_module(full)
                self._loaded_modules.add(full)

    def load_external(self, directory: str | Path) -> List[str]:
        """从目录加载第三方插件 (.py 文件)。返回已加载模块名列表。"""
        d = Path(directory)
        if not d.is_dir():
            raise PluginError(f"插件目录不存在: {d}")
        loaded: List[str] = []
        for py in sorted(d.glob("*.py")):
            if py.name.startswith("_"):
                continue
            mod_name = f"irtrace_external_{py.stem}"
            spec = importlib.util.spec_from_file_location(mod_name, py)
            if spec is None or spec.loader is None:
                continue
            module = importlib.util.module_from_spec(spec)
            sys.modules[mod_name] = module
            try:
                spec.loader.exec_module(module)
            except Exception as exc:  # noqa: BLE001 - 第三方插件错误不应中断主流程
                raise PluginError(f"加载插件 {py} 失败: {exc}") from exc
            loaded.append(mod_name)
        return loaded


#: 全局单例
registry = PluginRegistry()


def register(cls: Type[BasePlugin]) -> Type[BasePlugin]:
    """装饰器: 将插件类登记到全局注册中心。"""
    return registry.register(cls)


__all__ = ["PluginRegistry", "registry", "register"]
