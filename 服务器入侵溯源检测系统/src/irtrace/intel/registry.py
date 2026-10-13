"""情报 Provider 注册中心。"""

from __future__ import annotations

import importlib
import pkgutil
from typing import Dict, List, Optional, Type

from irtrace.intel.base import ThreatIntelProvider


class IntelProviderRegistry:
    """情报平台注册表。"""

    def __init__(self) -> None:
        self._providers: Dict[str, Type[ThreatIntelProvider]] = {}

    def register(self, cls: Type[ThreatIntelProvider]) -> Type[ThreatIntelProvider]:
        name = cls.name or cls.__name__.lower()
        if name in self._providers:
            raise ValueError(f"情报 Provider 名称重复: {name}")
        self._providers[name] = cls
        return cls

    def get(self, name: str) -> Optional[Type[ThreatIntelProvider]]:
        return self._providers.get(name)

    def names(self) -> List[str]:
        return sorted(self._providers)

    def all(self) -> Dict[str, Type[ThreatIntelProvider]]:
        return dict(self._providers)

    def clear(self) -> None:
        self._providers.clear()

    def discover(self, package: str = "irtrace.intel.providers") -> None:
        try:
            pkg = importlib.import_module(package)
        except ImportError:
            return
        for mod in pkgutil.iter_modules(pkg.__path__):
            if mod.name.startswith("_"):
                continue
            importlib.import_module(f"{package}.{mod.name}")


intel_registry = IntelProviderRegistry()


def register_provider(cls: Type[ThreatIntelProvider]) -> Type[ThreatIntelProvider]:
    """装饰器: 注册情报 Provider。"""
    return intel_registry.register(cls)


__all__ = ["IntelProviderRegistry", "intel_registry", "register_provider"]
