"""Web 控制台 (可视化 UI)。

基于标准库 ``http.server`` 实现, 零第三方依赖, 可完全离线运行。

职责: 展示 ``runs/`` 目录下的溯源结果。分析记录只读。
配置、情报源 Key 和手动拉取写入 ``data/secrets.db``，不改目标系统。

安全约束:
- 默认仅绑定 ``127.0.0.1``, 不对外暴露。
- 所有文件访问限制在静态资源目录与 ``runs/`` 目录内, 防目录穿越。
- ``run_id`` 经白名单正则校验。

启动::

    python -m irtrace web --port 8787
"""

from __future__ import annotations

import json
import logging
import re
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import unquote, urlparse

logger = logging.getLogger("irtrace.web")

STATIC_DIR = Path(__file__).parent / "static"

#: run_id 白名单 (形如 20261012T122835Z-c725cc)
_RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_\-]{0,63}$")

_MIME = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
    ".png": "image/png",
}


# --------------------------------------------------------------------------- #
# 数据访问
# --------------------------------------------------------------------------- #
class RunStore:
    """runs/ 目录的只读数据访问层。"""

    def __init__(self, workspace: str | Path) -> None:
        self.workspace = Path(workspace).resolve()
        self.runs_dir = self.workspace / "runs"

    # ------------------------------------------------------------------ #
    def _safe_run_dir(self, run_id: str) -> Optional[Path]:
        if not _RUN_ID_RE.match(run_id):
            return None
        candidate = (self.runs_dir / run_id).resolve()
        # 防目录穿越: 必须位于 runs/ 之下
        try:
            candidate.relative_to(self.runs_dir.resolve())
        except ValueError:
            return None
        return candidate if candidate.is_dir() else None

    def list_runs(self) -> List[Dict[str, Any]]:
        """列出所有运行 (按时间倒序)。"""
        if not self.runs_dir.is_dir():
            return []
        out: List[Dict[str, Any]] = []
        for d in self.runs_dir.iterdir():
            if not d.is_dir() or not _RUN_ID_RE.match(d.name):
                continue
            # 忽略没有任何产物的空目录 (如被中断的运行)
            summary = self._read_json(d / "summary.json") or {}
            result_meta = self._read_json(d / "reports" / "result.json") or {}
            if not summary and not result_meta:
                continue
            meta = result_meta.get("meta") or {}
            out.append({
                "run_id": d.name,
                "host": summary.get("host") or meta.get("host") or "-",
                "operator": summary.get("operator") or meta.get("operator") or "-",
                "generated_at": summary.get("generated_at") or meta.get("generated_at"),
                "events": summary.get("events", 0),
                "evidence": summary.get("evidence", 0),
                "findings": summary.get("findings", 0),
                "severity_counts": (summary.get("findings_by_severity")
                                    or meta.get("severity_counts") or {}),
                "warnings": summary.get("warnings", 0),
                "risk_level": meta.get("risk_level", "-"),
                "has_report": bool(result_meta),
                "mtime": d.stat().st_mtime,
            })
        out.sort(key=lambda r: r.get("mtime") or 0, reverse=True)
        return out

    def get_run(self, run_id: str) -> Optional[Dict[str, Any]]:
        """返回某次运行的完整结果 (result.json 优先, 否则 summary.json)。"""
        d = self._safe_run_dir(run_id)
        if d is None:
            return None
        data = self._read_json(d / "reports" / "result.json")
        if data is None:
            summary = self._read_json(d / "summary.json")
            if summary is None:
                return None
            data = {"meta": {"run_id": run_id, "host": summary.get("host"),
                             "risk_level": "-", "severity_counts": {}},
                    "summary": summary, "stats": {}, "warnings": [],
                    "findings": [], "events": [], "evidence": []}
        data["run_id"] = run_id
        data["report_html"] = (d / "reports" / "report.html").exists()
        data["report_md"] = (d / "reports" / "report.md").exists()
        return data

    def overview(self) -> Dict[str, Any]:
        """跨运行汇总。"""
        runs = self.list_runs()
        total = {"events": 0, "evidence": 0, "findings": 0,
                 "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for r in runs:
            total["events"] += r.get("events", 0)
            total["evidence"] += r.get("evidence", 0)
            total["findings"] += r.get("findings", 0)
            for sev, n in (r.get("severity_counts") or {}).items():
                if sev in total:
                    total[sev] += n
        return {
            "workspace": str(self.workspace),
            "run_count": len(runs),
            "totals": total,
            "latest": runs[0] if runs else None,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    def ledger(self, run_id: str) -> Optional[Dict[str, Any]]:
        """读取证据哈希链账本并重放校验。"""
        d = self._safe_run_dir(run_id)
        if d is None:
            return None
        path = d / "evidence-ledger.jsonl"
        if not path.exists():
            return {"entries": [], "valid": True, "count": 0}

        import hashlib
        prev = "0" * 64
        seq = 0
        entries: List[Dict[str, Any]] = []
        valid = True
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            rec = json.loads(line)
            seq += 1
            expect = hashlib.sha256(
                f"{prev}|{rec['seq']}|{rec['evidence_id']}|{rec['sha256']}".encode()
            ).hexdigest()
            ok = (rec.get("prev_hash") == prev and rec.get("entry_hash") == expect
                  and rec.get("seq") == seq)
            rec["verified"] = ok
            if not ok:
                valid = False
            prev = rec.get("entry_hash", "")
            entries.append(rec)
        return {"entries": entries, "valid": valid, "count": seq}

    def audit(self, run_id: str, limit: int = 500) -> Optional[List[Dict[str, Any]]]:
        d = self._safe_run_dir(run_id)
        if d is None:
            return None
        path = d / "audit.log"
        if not path.exists():
            return []
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        out: List[Dict[str, Any]] = []
        for line in lines[-limit:]:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out

    @staticmethod
    def _read_json(path: Path) -> Optional[Dict[str, Any]]:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None


# --------------------------------------------------------------------------- #
# HTTP 处理
# --------------------------------------------------------------------------- #
class _Handler(BaseHTTPRequestHandler):
    server_version = "IRTraceWeb/0.1"
    protocol_version = "HTTP/1.1"

    # -- 基础设施 ---------------------------------------------------------- #
    @property
    def store(self) -> RunStore:
        return self.server.store  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
        logger.debug("%s - %s", self.address_string(), fmt % args)

    def _send(self, status: int, body: bytes, ctype: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, payload: Any, status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
        self._send(status, body, "application/json; charset=utf-8")

    def _error(self, status: int, message: str) -> None:
        self._json({"error": message, "status": status}, status)

    # -- 路由 -------------------------------------------------------------- #
    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = unquote(parsed.path)
        try:
            if path.startswith("/api/"):
                self._route_api(path)
            else:
                self._serve_static(path)
        except BrokenPipeError:
            pass
        except Exception as exc:  # noqa: BLE001
            logger.exception("请求处理失败: %s", path)
            self._error(500, f"内部错误: {exc}")

    do_HEAD = do_GET

    # -- API --------------------------------------------------------------- #
    def _route_api(self, path: str) -> None:
        parts = [p for p in path.split("/") if p]      # ['api', ...]
        store = self.store

        if parts == ["api", "health"]:
            self._json({"status": "ok", "workspace": str(store.workspace),
                        "runs_dir": str(store.runs_dir)})
            return

        if parts == ["api", "overview"]:
            self._json(store.overview())
            return

        if parts == ["api", "runs"]:
            self._json({"runs": store.list_runs()})
            return

        if parts == ["api", "intel", "keys"]:
            self._json(self._intel_catalog())
            return

        if parts == ["api", "settings"]:
            self._json(self._settings_view())
            return

        if parts == ["api", "intel", "db"]:
            from irtrace.intel.localdb import ThreatDB
            self._json(ThreatDB(store.workspace).stats())
            return

        if len(parts) >= 3 and parts[0] == "api" and parts[1] == "runs":
            run_id = parts[2]
            if len(parts) == 3:
                data = store.get_run(run_id)
                if data is None:
                    self._error(404, f"未找到运行: {run_id}")
                else:
                    self._json(data)
                return
            sub = parts[3]
            if sub == "ledger":
                data = store.ledger(run_id)
                if data is None:
                    self._error(404, f"未找到运行: {run_id}")
                else:
                    self._json(data)
                return
            if sub == "audit":
                data = store.audit(run_id)
                if data is None:
                    self._error(404, f"未找到运行: {run_id}")
                else:
                    self._json({"entries": data})
                return
            if sub == "report.html":
                d = store._safe_run_dir(run_id)
                f = d / "reports" / "report.html" if d else None
                if f and f.exists():
                    self._send(200, f.read_bytes(), _MIME[".html"])
                else:
                    self._error(404, "报告不存在")
                return

        self._error(404, f"未知接口: {path}")

    def do_POST(self) -> None:  # noqa: N802
        path = unquote(urlparse(self.path).path)
        try:
            if path == "/api/intel/keys":
                self._save_intel_key()
            elif path == "/api/settings":
                self._save_settings()
            elif path == "/api/intel/pull":
                self._pull_intel()
            else:
                self._error(404, f"未知接口: {path}")
        except ValueError as exc:
            self._error(400, str(exc))
        except Exception as exc:  # noqa: BLE001
            logger.exception("写入失败: %s", path)
            self._error(500, f"内部错误: {exc}")

    # -- 情报源密钥 -------------------------------------------------------- #
    def _secrets(self):
        from irtrace.secrets import SecretStore
        return SecretStore(self.store.workspace)

    def _intel_catalog(self) -> Dict[str, Any]:
        """平台清单。Key 只给掩码，明文不出接口。"""
        from irtrace.intel.registry import intel_registry

        intel_registry.discover()
        stored = {item["name"]: item for item in self._secrets().list_public()}
        providers = []
        for name in intel_registry.names():
            cls_ = intel_registry.get(name)
            inst = cls_() if cls_ is not None else None
            if inst is None or inst.offline or not inst.requires_api_key:
                continue
            item = stored.get(name, {})
            providers.append({
                "name": name,
                "description": inst.description,
                "homepage": inst.homepage,
                "api_key_env": inst.api_key_env,
                "needs_url": name == "misp",
                "configured": bool(item.get("configured")),
                "hint": item.get("hint") or "",
                "enabled": bool(item.get("enabled", False)) if item else False,
                "url": (item.get("extra") or {}).get("url", ""),
                "updated_at": item.get("updated_at", ""),
            })
        return {"providers": providers}

    def _save_intel_key(self) -> None:
        payload = self._read_json_body()

        from irtrace.intel.registry import intel_registry
        intel_registry.discover()
        name = str(payload.get("name") or "").strip()
        cls_ = intel_registry.get(name)
        if cls_ is None or cls_.offline or not cls_.requires_api_key:
            raise ValueError(f"不是可配置的在线情报源: {name or '(空)'}")

        store = self._secrets()
        action = str(payload.get("action") or "save")
        if action == "delete":
            store.delete(name)
            self._json({"ok": True, "providers": self._intel_catalog()["providers"]})
            return

        enabled = bool(payload.get("enabled", True))
        extra = {}
        if name == "misp":
            url = str(payload.get("url") or "").strip().rstrip("/")
            if url and not url.startswith(("http://", "https://")):
                raise ValueError("MISP 地址必须以 http:// 或 https:// 开头")
            if url:
                extra["url"] = url

        api_key = str(payload.get("api_key") or "")
        if store.get(name) is None:
            if not api_key.strip():
                raise ValueError("首次保存必须填写 API Key")
            store.set(name, api_key, extra=extra, enabled=enabled)
        else:
            current = store.get(name) or {}
            merged = dict(current.get("extra") or {})
            merged.update(extra)
            store.update(name, api_key=api_key, extra=merged, enabled=enabled)
        self._json({"ok": True, "providers": self._intel_catalog()["providers"]})

    def _settings_view(self) -> Dict[str, Any]:
        from irtrace.intel.localdb import ThreatDB
        from irtrace.settings import SettingsStore

        config = SettingsStore(self.store.workspace).load()
        ai = config.get("ai") or {}
        return {
            "ai": {
                "enabled": bool(ai.get("enabled", True)),
                "cross_validate": bool(ai.get("cross_validate", False)),
            },
            "threat_db": ThreatDB(self.store.workspace).stats(),
        }

    def _save_settings(self) -> None:
        payload = self._read_json_body()
        from irtrace.settings import SettingsStore

        ai = payload.get("ai") if isinstance(payload.get("ai"), dict) else {}
        stored = SettingsStore(self.store.workspace).update({"ai": {
            "enabled": bool(ai.get("enabled", True)),
            "cross_validate": bool(ai.get("cross_validate", False)),
        }})
        self._json({"ok": True, "ai": {
            "enabled": bool(stored["ai"]["enabled"]),
            "cross_validate": bool(stored["ai"]["cross_validate"]),
        }})

    def _pull_intel(self) -> None:
        payload = self._read_json_body(allow_empty=True)
        names = payload.get("providers") if isinstance(payload, dict) else None
        if names is not None and not isinstance(names, list):
            raise ValueError("providers 必须是数组")
        from irtrace.intel.pull import pull_threats
        summary = pull_threats(self.store.workspace, names)
        self._json({"ok": True, "pull": summary})

    def _read_json_body(self, *, allow_empty: bool = False) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            if allow_empty:
                return {}
            raise ValueError("请求体为空或过大")
        if length > 64 * 1024:
            raise ValueError("请求体为空或过大")
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError("JSON 无法解析") from exc
        if not isinstance(payload, dict):
            raise ValueError("请求体必须是对象")
        return payload

    # -- 静态资源 ---------------------------------------------------------- #
    def _serve_static(self, path: str) -> None:
        rel = "index.html" if path in ("/", "") else path.lstrip("/")
        target = (STATIC_DIR / rel).resolve()
        try:
            target.relative_to(STATIC_DIR.resolve())
        except ValueError:
            self._error(403, "禁止访问")
            return
        if not target.is_file():
            self._error(404, "资源不存在")
            return
        ctype = _MIME.get(target.suffix.lower(), "application/octet-stream")
        self._send(200, target.read_bytes(), ctype)


# --------------------------------------------------------------------------- #
# 启动
# --------------------------------------------------------------------------- #
def create_server(workspace: str | Path, host: str = "127.0.0.1",
                  port: int = 8787) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), _Handler)
    server.store = RunStore(workspace)  # type: ignore[attr-defined]
    server.daemon_threads = True
    return server


def serve(workspace: str | Path, host: str = "127.0.0.1", port: int = 8787,
          open_browser: bool = False) -> None:
    """阻塞式启动 Web 控制台。"""
    server = create_server(workspace, host, port)
    url = f"http://{host}:{server.server_address[1]}/"
    logger.info("=" * 58)
    logger.info("  IRT 入侵检测控制台已启动")
    logger.info("  访问地址: %s", url)
    logger.info("  工作区  : %s", Path(workspace).resolve())
    logger.info("  按 Ctrl+C 停止")
    logger.info("=" * 58)

    if open_browser:
        import webbrowser
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("正在停止控制台 ...")
    finally:
        server.shutdown()
        server.server_close()


__all__ = ["RunStore", "create_server", "serve"]
