"""采集器公共基类与辅助函数。"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from irtrace.core.models import Category, Event, Evidence
from irtrace.core.plugin import CollectResult, Collector

logger = logging.getLogger("irtrace.collectors")


class BaseCollector(Collector):
    """采集器基类, 提供常用辅助方法。"""

    category: Category = Category.OTHER
    #: 采集器在 Linux 上才可用
    linux_only: bool = True

    def preflight(self, ctx) -> Optional[str]:  # type: ignore[override]
        reason = super().preflight(ctx)
        if reason:
            return reason
        if self.linux_only and not ctx.is_linux:
            return "非 Linux 环境"
        missing = [p for p in self.requires_paths if not ctx.exists(p)]
        if missing and len(missing) == len(self.requires_paths):
            return f"目标路径均不存在: {', '.join(missing)}"
        return None

    # -- 辅助 -------------------------------------------------------------- #
    def event(
        self,
        ctx,
        *,
        action: str,
        message: str,
        timestamp: Optional[datetime] = None,
        category: Optional[Category] = None,
        **kwargs,
    ) -> Event:
        return Event(
            timestamp=timestamp,
            category=category or self.category,
            source=self.name,
            action=action,
            message=message,
            host=ctx.hostname,
            **kwargs,
        )

    def evidence_from_file(
        self,
        ctx,
        path: str,
        *,
        kind: str = "file",
        note: str = "",
    ) -> Optional[Evidence]:
        """读取目标文件内容并登记为证据。"""
        content = ctx.read_file(path)
        if content is None:
            return None
        try:
            mtime = datetime.fromtimestamp(Path(path).stat().st_mtime, tz=timezone.utc)
        except OSError:
            mtime = None
        return ctx.store_evidence(
            source=self.name,
            kind=kind,
            name=path.strip("/").replace("/", "__"),
            data=content,
            path=path,
            note=note,
            mtime=mtime,
        )

    def evidence_from_text(
        self,
        ctx,
        name: str,
        text: str,
        *,
        kind: str = "command_output",
        note: str = "",
        target: str = "",
        path: str = "",
    ) -> Evidence:
        return ctx.store_evidence(
            source=self.name, kind=kind, name=name, data=text,
            path=path or target, note=note,
        )

    @staticmethod
    def listdir(path: str) -> List[str]:
        try:
            return sorted(os.listdir(path))
        except OSError:
            return []


__all__ = ["BaseCollector"]
