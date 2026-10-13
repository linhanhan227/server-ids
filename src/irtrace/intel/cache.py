"""情报查询结果本地缓存 (JSON 文件, 带 TTL)。

目的: 避免重复消耗 API 配额, 并支持离线复查 (缓存的原始响应即证据)。
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger("irtrace.intel")


class IntelCache:
    """按 ``provider:type:indicator`` 为键的磁盘缓存。"""

    def __init__(self, cache_dir: str | Path, ttl_hours: float = 24.0) -> None:
        self.dir = Path(cache_dir)
        # 目录惰性创建: 只读命令 (如 `irtrace intel list`) 不应产生任何文件
        self.ttl_seconds = max(0.0, ttl_hours * 3600)
        self._mem: Dict[str, Dict[str, Any]] = {}
        self.hits = 0
        self.misses = 0

    # ------------------------------------------------------------------ #
    def _key_path(self, key: str) -> Path:
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]
        return self.dir / f"{digest}.json"

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        """命中且未过期则返回 payload, 否则 None。"""
        entry = self._mem.get(key)
        if entry is None:
            path = self._key_path(key)
            if not path.exists():
                self.misses += 1
                return None
            try:
                entry = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                self.misses += 1
                return None
            self._mem[key] = entry

        if self.ttl_seconds and (time.time() - entry.get("at", 0)) > self.ttl_seconds:
            self.misses += 1
            return None
        self.hits += 1
        return entry.get("payload")

    def set(self, key: str, payload: Dict[str, Any]) -> None:
        entry = {"at": time.time(), "key": key, "payload": payload}
        self._mem[key] = entry
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
            self._key_path(key).write_text(
                json.dumps(entry, ensure_ascii=False), encoding="utf-8")
        except OSError as exc:  # pragma: no cover
            logger.debug("缓存写入失败: %s", exc)

    def clear(self) -> int:
        if not self.dir.is_dir():
            self._mem.clear()
            return 0
        n = 0
        for f in self.dir.glob("*.json"):
            try:
                f.unlink()
                n += 1
            except OSError:
                pass
        self._mem.clear()
        return n

    def stats(self) -> Dict[str, Any]:
        entries = len(list(self.dir.glob("*.json"))) if self.dir.is_dir() else 0
        return {"hits": self.hits, "misses": self.misses, "entries": entries}


__all__ = ["IntelCache"]
