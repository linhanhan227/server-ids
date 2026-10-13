"""运行配置。

全部放在 ``data/secrets.db`` 的 ``settings`` 表，不再读取 TOML / JSON。
界面和接口只回这份公开视图，不回情报源 Key。

约定：

- 检测只查本地库，不因为配置打开而自己去拉在线情报。
- ``ai_cross_validate`` 默认关闭。打开后，AI 辅助判定才会用已配置的
  在线情报接口做交叉验证。
"""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict

DEFAULTS: Dict[str, Any] = {
    "general": {
        "command_timeout": 30,
        "max_file_bytes": 8 * 1024 * 1024,
        "dry_run": False,
    },
    "collectors": {"disable": [], "enable_only": []},
    "analyzers": {"disable": [], "enable_only": []},
    "reporters": {"formats": ["json", "markdown", "html"], "disable": []},
    "intel": {
        "cache_enabled": True,
        "cache_ttl_hours": 24,
        "platforms": {},
    },
    "ai": {
        "enabled": True,
        "cross_validate": False,
    },
}

_DB_NAME = "secrets.db"


class SettingsStore:
    """工作区配置。与密钥库共用同一个明文 SQLite 文件。"""

    def __init__(self, workspace: str | Path) -> None:
        self.workspace = Path(workspace)
        self.dir = self.workspace / "data"
        self.db_path = self.dir / _DB_NAME
        self._lock = threading.Lock()
        self.dir.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS settings (
                    key   TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
                """
            )

    def get(self, key: str, default: Any = None) -> Any:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT value FROM settings WHERE key=?", (key,)
            ).fetchone()
        if row is None:
            return default
        try:
            return json.loads(row["value"])
        except json.JSONDecodeError:
            return default

    def set(self, key: str, value: Any) -> None:
        payload = json.dumps(value, ensure_ascii=False)
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO settings (key, value) VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value
                """,
                (key, payload),
            )

    def load(self) -> Dict[str, Any]:
        """返回带默认值的完整配置。库里没有的键保持默认。"""
        stored = self.get("config")
        if not isinstance(stored, dict):
            return _copy(DEFAULTS)
        return _deep_merge(DEFAULTS, stored)

    def update(self, patch: Dict[str, Any]) -> Dict[str, Any]:
        """按段合并。只接受已知顶层段，未知段丢弃。"""
        current = self.load()
        clean = {key: value for key, value in patch.items() if key in DEFAULTS}
        merged = _deep_merge(current, clean)
        merged["ai"]["cross_validate"] = bool(merged["ai"].get("cross_validate"))
        merged["ai"]["enabled"] = bool(merged["ai"].get("enabled", True))
        self.set("config", merged)
        return merged


def load_settings(workspace: str | Path) -> Dict[str, Any]:
    return SettingsStore(workspace).load()


def _copy(data: Dict[str, Any]) -> Dict[str, Any]:
    return json.loads(json.dumps(data))


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(base)
    for key, val in override.items():
        if isinstance(val, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], val)
        else:
            out[key] = val
    return out


__all__ = ["DEFAULTS", "SettingsStore", "load_settings"]
