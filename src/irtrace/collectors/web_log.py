"""Web 访问日志采集器。

覆盖 nginx / apache 的访问日志, 只读解析, 不改日志、不请求目标 URL。

两类信号分开报, 避免把扫描噪声当成已落地的 webshell:

- ``web_shell_request``: 请求了常见 webshell 文件名, 或参数里出现命令执行特征。
- ``web_scan``: 同一来源短时间内大量 404 / 探测路径, 没有落到具体文件。
- ``model_auth_failure`` / ``model_auth_success``: 模型接口的登录或鉴权失败与成功。
- ``model_abuse``: 同一来源把补全接口打满, 用来薅中转站配额。
- ``model_key_reuse``: 同一把密钥被多个来源用来调用模型接口。事件只留指纹。

时间戳能解析时写入事件, 供后续与进程、文件事件做时间窗关联。
"""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional
from urllib.parse import unquote

from irtrace.collectors.base import BaseCollector
from irtrace.collectors.web_shell import is_shell_path
from irtrace.core.models import Category, Event
from irtrace.core.plugin import CollectResult
from irtrace.core.registry import register
from irtrace.utils.timeutil import parse_timestamp

# 当前日志在前, 轮转日志在后。不读压缩归档, 避免在应急现场解包。
_LOG_CANDIDATES = (
    "/var/log/nginx/access.log",
    "/var/log/nginx/access.log.1",
    "/var/log/httpd/access_log",
    "/var/log/httpd/access_log.1",
    "/var/log/apache2/access.log",
    "/var/log/apache2/access.log.1",
)

# combined / common 格式。取不到字段的行直接跳过, 不猜。
# 末尾的附加字段用来接反代补上的密钥指纹, 标准 combined 行没有它也照常解析。
_COMBINED = re.compile(
    r"^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"
    r"\"(?P<method>[A-Z]+)\s+(?P<target>\S*)(?:\s+[^\"]*)?\"\s+"
    r"(?P<status>\d{3})"
    r"(?:\s+\S+\s+\"[^\"]*\"\s+\"[^\"]*\")?"
    r"(?:\s+keyfp:(?P<keyfp>[A-Za-z0-9_\-]{6,32}))?"
)

# 查询串里的密钥。日志行可能带明文, 解析后只留指纹。
_QUERY_KEY = re.compile(
    r"[?&](?:api_key|apikey|key|access_token|token)=([A-Za-z0-9_\-]{12,})",
    re.I,
)
_LEAKED_KEY_SOURCES = 2

# 参数里的命令执行。要同时看到执行入口和命令特征, 避免单个单词误报。
# 加号是访问日志里空格的常见写法, 分类前按空格还原。
_EXEC_PARAM = re.compile(
    r"(?:[?&](?:cmd|command|exec|shell|c|code)=|(?:system|passthru|eval|assert)\s*\()",
    re.I,
)
_CMD_HINT = re.compile(
    r"(?:/bin/(?:ba)?sh|cmd\.exe|whoami|\bid\b|uname\s+-a|cat\s+/etc/passwd|"
    r"wget\s+|curl\s+|base64\s+-d)",
    re.I,
)

# 模型网关的登录与补全接口。普通业务的 /login 不在这里。
_MODEL_AUTH = re.compile(
    r"/(?:api/)?(?:user/)?(?:login|signin|sign-in|token|oauth/token|session)(?:/|$)",
    re.I,
)
_MODEL_API = re.compile(
    r"/(?:v1|openai)/(?:chat/completions|completions|embeddings|images/generations|audio/transcriptions|responses)(?:/|$)",
    re.I,
)
_MODEL_AUTH_BURST = 8
_MODEL_ABUSE_HITS = 30

# 扫描器常用探测路径。命中次数要累积, 单次 404 不算。
_PROBE_PATH = re.compile(
    r"(?:/\.env(?:$|[?#])|/\.git/|/wp-login\.php|/phpmyadmin|"
    r"/admin(?:/|$)|/manager/html|/\.aws/|/actuator/|/vendor/phpunit|"
    r"/boaform/|/HNAP1|/\.DS_Store|/server-status)",
    re.I,
)

_SCAN_MIN_HITS = 20
_MAX_LINES = 200_000


def _path_of(target: str) -> str:
    """去掉 query, 并做一次 URL 解码。解码失败就用原文。"""
    raw = target.split("?", 1)[0]
    try:
        return unquote(raw)
    except ValueError:
        return raw


def parse_access_line(line: str) -> Optional[dict]:
    """解析一行 combined 日志。无法识别时返回 None。"""
    match = _COMBINED.match(line.strip())
    if not match:
        return None
    target = match.group("target") or "/"
    status_text = match.group("status")
    try:
        status = int(status_text)
    except ValueError:
        return None
    return {
        "ip": match.group("ip"),
        "timestamp": parse_timestamp(match.group("time")),
        "method": match.group("method"),
        "target": target,
        "path": _path_of(target),
        "status": status,
        "key_fp": _key_fingerprint(target, match.group("keyfp")),
        "raw": _redact_secrets(line.rstrip("\n")),
    }


def _redact_secrets(line: str) -> str:
    """证据里不留查询串中的密钥。指纹另行保存。"""
    return _QUERY_KEY.sub(
        lambda match: match.group(0).split("=", 1)[0] + "=[redacted]",
        line,
    )


def _key_fingerprint(target: str, explicit: Optional[str]) -> Optional[str]:
    """密钥不落事件。反代已经给了指纹就用它, 否则从查询串算 SHA256 前 12 位。"""
    if explicit:
        return explicit.lower()
    found = _QUERY_KEY.search(target or "")
    if not found:
        return None
    digest = hashlib.sha256(found.group(1).encode("utf-8")).hexdigest()
    return digest[:12]


def _first_time(records: List[dict]) -> Optional[datetime]:
    times = [item["timestamp"] for item in records if item.get("timestamp")]
    return min(times) if times else None


def classify_request(record: dict) -> Optional[str]:
    """返回 ``webshell`` / ``probe`` / ``model_auth`` / ``model_api`` / None。

    webshell 优先。模型接口按路径认, 不把普通页面算进来。
    """
    blob = unquote(f"{record['path']} {record['target']}").replace("+", " ")
    if is_shell_path(record["path"]) or (
        _EXEC_PARAM.search(blob) and _CMD_HINT.search(blob)
    ):
        return "webshell"
    if _MODEL_AUTH.search(record["path"]):
        return "model_auth"
    if _MODEL_API.search(record["path"]):
        return "model_api"
    if record["status"] in (401, 403, 404) and _PROBE_PATH.search(record["path"]):
        return "probe"
    return None


@register
class WebLogCollector(BaseCollector):
    name = "web_log"
    description = "解析 nginx/apache 访问日志, 识别 webshell 请求与扫描"
    category = Category.LOG
    requires_paths = [
        "/var/log/nginx", "/var/log/httpd", "/var/log/apache2",
    ]

    def preflight(self, ctx) -> Optional[str]:  # type: ignore[override]
        # 日志路径由调用方显式指定时, 不要求跑在 Linux 上。
        if _LOG_CANDIDATES and all(not path.startswith("/var/log/")
                                   for path in _LOG_CANDIDATES):
            return None
        return super().preflight(ctx)

    def collect(self, ctx) -> CollectResult:
        res = CollectResult()
        parsed_logs = 0
        for log_path in _LOG_CANDIDATES:
            if not ctx.exists(log_path):
                continue
            raw = ctx.read_file(log_path)
            if not raw:
                continue
            parsed_logs += 1
            safe_name = log_path.strip("/").replace("/", "__") + ".txt"
            res.evidence.append(self.evidence_from_text(
                ctx, safe_name, _redact_secrets(raw), path=log_path,
                note="Web 访问日志, 查询串密钥已替换",
            ))
            self._parse(ctx, res, raw)
        res.stats["web_logs"] = parsed_logs
        return res

    def _parse(self, ctx, res: CollectResult, raw: str) -> None:
        probes: Dict[str, List[dict]] = defaultdict(list)
        auth_fail: Dict[str, List[dict]] = defaultdict(list)
        auth_ok: Dict[str, List[dict]] = defaultdict(list)
        api_hits: Dict[str, List[dict]] = defaultdict(list)
        key_hits: Dict[str, List[dict]] = defaultdict(list)
        shell_events = 0
        lines = raw.splitlines()
        if len(lines) > _MAX_LINES:
            lines = lines[-_MAX_LINES:]
            res.warnings.append(f"Web 日志过长, 仅解析末尾 {_MAX_LINES} 行")

        for line in lines:
            record = parse_access_line(line)
            if record is None:
                continue
            kind = classify_request(record)
            if kind == "webshell":
                res.events.append(self._shell_event(ctx, record))
                shell_events += 1
            elif kind == "probe":
                probes[record["ip"]].append(record)
            elif kind == "model_auth":
                bucket = auth_ok if record["status"] < 400 else auth_fail
                bucket[record["ip"]].append(record)
            elif kind == "model_api" and record["status"] < 400:
                api_hits[record["ip"]].append(record)
                if record.get("key_fp"):
                    key_hits[record["key_fp"]].append(record)

        scan_events = 0
        for ip, hits in probes.items():
            if len(hits) < _SCAN_MIN_HITS:
                continue
            res.events.append(self._scan_event(ctx, ip, hits))
            scan_events += 1
        auth_events = self._emit_model_auth(ctx, res, auth_fail, auth_ok)
        abuse_events = self._emit_model_abuse(ctx, res, api_hits)
        reuse_events = self._emit_key_reuse(ctx, res, key_hits)
        res.stats["web_shell_requests"] = (
            res.stats.get("web_shell_requests", 0) + shell_events
        )
        res.stats["web_scans"] = res.stats.get("web_scans", 0) + scan_events
        res.stats["model_auth"] = res.stats.get("model_auth", 0) + auth_events
        res.stats["model_abuse"] = res.stats.get("model_abuse", 0) + abuse_events
        res.stats["model_key_reuse"] = (
            res.stats.get("model_key_reuse", 0) + reuse_events
        )

    def _shell_event(self, ctx, record: dict) -> Event:
        return self.event(
            ctx,
            action="web_shell_request",
            message=(
                f"webshell 请求 {record['ip']} {record['method']} "
                f"{record['target']} -> {record['status']}"
            ),
            timestamp=record["timestamp"],
            src_ip=record["ip"],
            path=record["path"],
            tags=["webshell", "web"],
            raw={
                "method": record["method"],
                "status": record["status"],
                "target": record["target"][:500],
            },
        )

    def _emit_model_auth(self, ctx, res: CollectResult,
                         failed: Dict[str, List[dict]],
                         succeeded: Dict[str, List[dict]]) -> int:
        """失败次数够了才记爆破。成功要落在这些失败之后。"""
        count = 0
        sources = set(failed) | set(succeeded)
        for ip in sources:
            fails = failed.get(ip, [])
            oks = succeeded.get(ip, [])
            if len(fails) < _MODEL_AUTH_BURST and not oks:
                continue
            if len(fails) >= _MODEL_AUTH_BURST:
                res.events.append(self._auth_event(
                    ctx, ip, fails, "model_auth_failure",
                ))
                count += 1
            first_fail = _first_time(fails)
            later = [
                item for item in oks
                if first_fail is None or item["timestamp"] is None
                or item["timestamp"] >= first_fail
            ]
            if later and len(fails) >= _MODEL_AUTH_BURST:
                res.events.append(self._auth_event(
                    ctx, ip, later, "model_auth_success",
                ))
                count += 1
        return count

    def _emit_model_abuse(self, ctx, res: CollectResult,
                          hits: Dict[str, List[dict]]) -> int:
        count = 0
        for ip, records in hits.items():
            if len(records) < _MODEL_ABUSE_HITS:
                continue
            res.events.append(self._abuse_event(ctx, ip, records))
            count += 1
        return count

    def _auth_event(self, ctx, ip: str, records: List[dict], action: str) -> Event:
        paths = sorted({item["path"] for item in records})[:4]
        return self.event(
            ctx,
            action=action,
            message=f"模型接口{('登录失败' if action.endswith('failure') else '登录成功')} "
                    f"{ip} {len(records)} 次",
            timestamp=_first_time(records),
            src_ip=ip,
            tags=["model-auth", "model-gateway"],
            raw={"hit_count": len(records), "paths": paths},
        )

    def _emit_key_reuse(self, ctx, res: CollectResult,
                        hits: Dict[str, List[dict]]) -> int:
        """同一指纹出现在多个来源才算泄露后被别人使用。"""
        count = 0
        for fingerprint, records in hits.items():
            sources = sorted({item["ip"] for item in records if item.get("ip")})
            if len(sources) < _LEAKED_KEY_SOURCES:
                continue
            res.events.append(self.event(
                ctx,
                action="model_key_reuse",
                message=f"模型密钥指纹 {fingerprint} 被 {len(sources)} 个来源使用",
                timestamp=_first_time(records),
                tags=["leaked-key", "model-gateway"],
                raw={
                    "key_fp": fingerprint,
                    "sources": sources[:8],
                    "hit_count": len(records),
                },
            ))
            count += 1
        return count

    def _abuse_event(self, ctx, ip: str, records: List[dict]) -> Event:
        paths = sorted({item["path"] for item in records})[:4]
        return self.event(
            ctx,
            action="model_abuse",
            message=f"模型补全接口被打满 {ip} {len(records)} 次",
            timestamp=_first_time(records),
            src_ip=ip,
            tags=["model-abuse", "model-gateway"],
            raw={"hit_count": len(records), "paths": paths},
        )

    def _scan_event(self, ctx, ip: str, hits: List[dict]) -> Event:
        timestamps = [item["timestamp"] for item in hits if item["timestamp"]]
        first: Optional[datetime] = min(timestamps) if timestamps else None
        paths = sorted({item["path"] for item in hits})[:8]
        return self.event(
            ctx,
            action="web_scan",
            message=f"Web 扫描 {ip} 命中探测路径 {len(hits)} 次",
            timestamp=first,
            src_ip=ip,
            tags=["web-scan", "web"],
            raw={"hit_count": len(hits), "sample_paths": paths},
        )


__all__ = [
    "WebLogCollector",
    "parse_access_line",
    "classify_request",
]
