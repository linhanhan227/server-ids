"""本地威胁数据库。

在线情报只在手动拉取时写入 ``data/secrets.db`` 的 ``threat_indicators``。
日常检测只读这张表，不再因为分析而请求在线接口。

每条记录保留来源、评分和原始响应。同一指标被多个来源命中时各留一行，
查询时按来源全部返回。
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_DB_NAME = "secrets.db"


class ThreatDB:
    """工作区级别的本地威胁库。与密钥、配置共用同一个明文 SQLite。"""

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
                CREATE TABLE IF NOT EXISTS threat_indicators (
                    indicator      TEXT NOT NULL,
                    indicator_type TEXT NOT NULL,
                    provider       TEXT NOT NULL,
                    malicious      INTEGER NOT NULL,
                    score          REAL NOT NULL DEFAULT 0,
                    confidence     REAL NOT NULL DEFAULT 0,
                    severity       TEXT NOT NULL DEFAULT 'info',
                    tags           TEXT NOT NULL DEFAULT '[]',
                    description    TEXT NOT NULL DEFAULT '',
                    raw            TEXT NOT NULL DEFAULT '{}',
                    pulled_at      TEXT NOT NULL,
                    PRIMARY KEY (indicator, indicator_type, provider)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS threat_pulls (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    pulled_at  TEXT NOT NULL,
                    providers  TEXT NOT NULL,
                    queried    INTEGER NOT NULL,
                    stored     INTEGER NOT NULL,
                    errors     TEXT NOT NULL DEFAULT '[]'
                )
                """
            )

    def replace(self, rows: List[Dict[str, Any]], *, providers: List[str],
                queried: int, errors: Optional[List[str]] = None) -> Dict[str, Any]:
        """用本次拉取结果覆盖这些来源的旧记录。未参与的来源保持不动。"""
        pulled_at = datetime.now(timezone.utc).isoformat()
        names = [str(name) for name in providers if name]
        with self._lock, self._connect() as conn:
            if names:
                marks = ",".join("?" for _ in names)
                conn.execute(
                    f"DELETE FROM threat_indicators WHERE provider IN ({marks})",
                    names,
                )
            stored = 0
            for row in rows:
                if not row.get("malicious"):
                    continue
                conn.execute(
                    """
                    INSERT INTO threat_indicators (
                        indicator, indicator_type, provider, malicious, score,
                        confidence, severity, tags, description, raw, pulled_at
                    ) VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(row["indicator"]).strip(),
                        str(row["indicator_type"]),
                        str(row["provider"]),
                        float(row.get("score") or 0),
                        float(row.get("confidence") or 0),
                        str(row.get("severity") or "info"),
                        json.dumps(list(row.get("tags") or []), ensure_ascii=False),
                        str(row.get("description") or ""),
                        json.dumps(row.get("raw") or {}, ensure_ascii=False, default=str),
                        pulled_at,
                    ),
                )
                stored += 1
            conn.execute(
                """
                INSERT INTO threat_pulls (pulled_at, providers, queried, stored, errors)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    pulled_at,
                    json.dumps(names, ensure_ascii=False),
                    int(queried),
                    stored,
                    json.dumps(list(errors or []), ensure_ascii=False),
                ),
            )
        return {"pulled_at": pulled_at, "providers": names,
                "queried": int(queried), "stored": stored, "errors": list(errors or [])}

    def lookup(self, indicator: str, indicator_type: str) -> List[Dict[str, Any]]:
        probe = (indicator or "").strip()
        if not probe:
            return []
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM threat_indicators
                WHERE indicator = ? AND indicator_type = ?
                ORDER BY provider
                """,
                (probe, indicator_type),
            ).fetchall()
        return [_row(row) for row in rows]

    def stats(self) -> Dict[str, Any]:
        with self._lock, self._connect() as conn:
            total = conn.execute(
                "SELECT COUNT(*) AS n FROM threat_indicators"
            ).fetchone()["n"]
            by_provider = {
                row["provider"]: row["n"]
                for row in conn.execute(
                    "SELECT provider, COUNT(*) AS n FROM threat_indicators "
                    "GROUP BY provider ORDER BY provider"
                )
            }
            last = conn.execute(
                "SELECT pulled_at, providers, queried, stored, errors "
                "FROM threat_pulls ORDER BY id DESC LIMIT 1"
            ).fetchone()
        return {
            "indicators": total,
            "by_provider": by_provider,
            "last_pull": _pull(last) if last else None,
        }


def _row(row: sqlite3.Row) -> Dict[str, Any]:
    return {
        "indicator": row["indicator"],
        "indicator_type": row["indicator_type"],
        "provider": row["provider"],
        "malicious": bool(row["malicious"]),
        "score": row["score"],
        "confidence": row["confidence"],
        "severity": row["severity"],
        "tags": _loads(row["tags"], []),
        "description": row["description"],
        "raw": _loads(row["raw"], {}),
        "pulled_at": row["pulled_at"],
    }


def _pull(row: sqlite3.Row) -> Dict[str, Any]:
    return {
        "pulled_at": row["pulled_at"],
        "providers": _loads(row["providers"], []),
        "queried": row["queried"],
        "stored": row["stored"],
        "errors": _loads(row["errors"], []),
    }


def _loads(text: str, fallback: Any) -> Any:
    try:
        return json.loads(text or "")
    except json.JSONDecodeError:
        return fallback


__all__ = ["ThreatDB"]
