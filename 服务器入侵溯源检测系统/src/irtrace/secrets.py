"""情报源密钥库。

SQLite 明文放在 ``data/secrets.db``，不加密，也没有单独的主密钥文件。
界面和接口只回掩码，不回明文。

库里的字段：

- ``api_key``  平台 Key
- ``extra``    平台附加配置（如 MISP 的 URL）
- ``enabled``  是否作为在线源启用
"""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

_DB_NAME = "secrets.db"


class SecretStore:
    """工作区级别的密钥库。"""

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
                CREATE TABLE IF NOT EXISTS provider_secrets (
                    name       TEXT PRIMARY KEY,
                    api_key    TEXT NOT NULL,
                    extra      TEXT NOT NULL DEFAULT '{}',
                    enabled    INTEGER NOT NULL DEFAULT 1,
                    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
                )
                """
            )

    def set(self, name: str, api_key: str, *, extra: Optional[Dict[str, Any]] = None,
            enabled: bool = True) -> None:
        """写入或覆盖一个平台的 Key。空 Key 会被拒绝。"""
        key = (api_key or "").strip()
        if not key:
            raise ValueError("API Key 不能为空")
        extra_json = json.dumps(extra or {}, ensure_ascii=False)
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO provider_secrets (name, api_key, extra, enabled, updated_at)
                VALUES (?, ?, ?, ?, datetime('now'))
                ON CONFLICT(name) DO UPDATE SET
                    api_key=excluded.api_key,
                    extra=excluded.extra,
                    enabled=excluded.enabled,
                    updated_at=datetime('now')
                """,
                (name, key, extra_json, 1 if enabled else 0),
            )

    def update(self, name: str, *, api_key: Optional[str] = None,
               extra: Optional[Dict[str, Any]] = None,
               enabled: Optional[bool] = None) -> bool:
        """局部更新。Key 传空字符串表示不改已有值。不存在返回 False。"""
        current = self.get(name)
        if current is None:
            return False
        new_key = current["api_key"] if not (api_key or "").strip() else api_key.strip()
        new_extra = current["extra"] if extra is None else extra
        new_enabled = current["enabled"] if enabled is None else enabled
        self.set(name, new_key, extra=new_extra, enabled=new_enabled)
        return True

    def get(self, name: str) -> Optional[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT api_key, extra, enabled FROM provider_secrets WHERE name=?",
                (name,),
            ).fetchone()
        if row is None:
            return None
        return {
            "name": name,
            "api_key": row["api_key"],
            "extra": _loads(row["extra"]),
            "enabled": bool(row["enabled"]),
        }

    def api_key_for(self, name: str) -> Optional[str]:
        item = self.get(name)
        if not item or not item["enabled"]:
            return None
        return item["api_key"] or None

    def delete(self, name: str) -> bool:
        with self._lock, self._connect() as conn:
            cur = conn.execute("DELETE FROM provider_secrets WHERE name=?", (name,))
            return cur.rowcount > 0

    def list_public(self) -> List[Dict[str, Any]]:
        """给界面用的视图：只有掩码，没有明文。"""
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT name, api_key, extra, enabled, updated_at "
                "FROM provider_secrets ORDER BY name"
            ).fetchall()
        return [{
            "name": row["name"],
            "configured": bool(row["api_key"]),
            "hint": mask_secret(row["api_key"]),
            "extra": _loads(row["extra"]),
            "enabled": bool(row["enabled"]),
            "updated_at": row["updated_at"],
        } for row in rows]

    def enabled_names(self) -> List[str]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT name FROM provider_secrets WHERE enabled=1 ORDER BY name"
            ).fetchall()
        return [r["name"] for r in rows]


def mask_secret(value: str) -> str:
    """保留首尾少量字符，中间打码。空值返回空串。"""
    text = value or ""
    if not text:
        return ""
    if len(text) <= 8:
        return text[:2] + "•" * max(2, len(text) - 2)
    return f"{text[:4]}{'•' * 6}{text[-4:]}"


def _loads(text: str) -> Dict[str, Any]:
    try:
        data = json.loads(text or "{}")
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


__all__ = ["SecretStore", "mask_secret"]
