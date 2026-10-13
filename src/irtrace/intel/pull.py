"""手动拉取在线威胁情报，写入本地库。

检测不会调用这里。只有 CLI ``intel pull`` 和 Web「拉取最新」会进来。
每次拉取覆盖参与来源的旧记录，其它来源保持不动。
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from irtrace.intel.aggregator import DEFAULT_PUBLIC_PROVIDERS, _enabled_secret_names
from irtrace.intel.localdb import ThreatDB
from irtrace.intel.registry import intel_registry

logger = logging.getLogger("irtrace.intel")


def pull_threats(workspace, providers: Optional[List[str]] = None) -> Dict[str, Any]:
    """拉取并落地。未指定来源时，用已启用的 Key 源；一个都没有则拉公开列表。"""
    intel_registry.discover()
    names = [str(item).strip() for item in (providers or []) if str(item).strip()]
    if not names:
        names = _enabled_secret_names(workspace) or list(DEFAULT_PUBLIC_PROVIDERS)

    rows: List[Dict[str, Any]] = []
    errors: List[str] = []
    used: List[str] = []
    for name in names:
        cls_ = intel_registry.get(name)
        if cls_ is None:
            errors.append(f"{name}: 未知情报源")
            continue
        provider = cls_({"workspace": str(workspace)})
        if provider.offline:
            errors.append(f"{name}: 离线源不参与拉取")
            continue
        if not provider.available:
            errors.append(f"{name}: {provider.unavailable_reason() or '不可用'}")
            continue
        used.append(name)
        try:
            exported, feed_errors = provider.export_indicators()
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{name}: {exc}")
            continue
        errors.extend(feed_errors)
        rows.extend(exported)

    summary = ThreatDB(workspace).replace(rows, providers=used, queried=len(rows), errors=errors)
    logger.info("手动拉取完成: %s", summary)
    return summary


__all__ = ["pull_threats"]
