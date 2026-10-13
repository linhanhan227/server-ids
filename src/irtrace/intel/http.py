"""HTTP 客户端 (标准库实现) 与限速器。

- 统一超时、重试、User-Agent
- 返回 ``(status, payload, error)``, 不抛异常, 由调用方决定降级策略
- HTTP 错误响应体一并返回 (多数情报平台在 4xx body 中给出错误原因)
"""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger("irtrace.intel")

USER_AGENT = "IRTrace/0.1 (+linux-intrusion-forensics)"

#: 单次请求最大响应体 (防止异常大响应拖垮内存)
MAX_BODY = 4 * 1024 * 1024


def request_json(
    url: str,
    *,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    params: Optional[Dict[str, Any]] = None,
    json_body: Optional[Dict[str, Any]] = None,
    form_body: Optional[Dict[str, Any]] = None,
    timeout: int = 10,
    retries: int = 1,
) -> Tuple[int, Optional[Any], Optional[str]]:
    """发起 HTTP 请求并解析 JSON。

    :return: ``(status_code, payload, error)``; 失败时 payload 为 None。
    """
    if params:
        url = f"{url}{'&' if '?' in url else '?'}{urllib.parse.urlencode(params)}"

    body: Optional[bytes] = None
    hdrs = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if headers:
        hdrs.update(headers)

    if json_body is not None:
        body = json.dumps(json_body).encode("utf-8")
        hdrs["Content-Type"] = "application/json"
    elif form_body is not None:
        body = urllib.parse.urlencode(form_body).encode("utf-8")
        hdrs["Content-Type"] = "application/x-www-form-urlencoded"

    last_err: Optional[str] = None
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
                raw = resp.read(MAX_BODY)
                try:
                    return resp.status, json.loads(raw.decode("utf-8", "replace")), None
                except json.JSONDecodeError:
                    return resp.status, {"_raw": raw.decode("utf-8", "replace")[:4096]}, None
        except urllib.error.HTTPError as exc:
            # 读取错误体, 情报平台通常在 body 中说明原因 (如配额耗尽)
            detail = ""
            try:
                detail = exc.read(4096).decode("utf-8", "replace")
            except Exception:  # noqa: BLE001
                pass
            last_err = f"HTTP {exc.code}: {detail[:300] or exc.reason}"
            if exc.code in (401, 403, 404, 429):  # 不重试
                return exc.code, None, last_err
        except urllib.error.URLError as exc:
            last_err = f"网络错误: {exc.reason}"
        except TimeoutError:
            last_err = f"请求超时 ({timeout}s)"
        except Exception as exc:  # noqa: BLE001
            last_err = f"未知错误: {exc}"

        if attempt < retries:
            time.sleep(1.0 * (attempt + 1))

    return 0, None, last_err


class RateLimiter:
    """简单的按平台最小间隔限速器 (避免触发 API 配额)。"""

    def __init__(self, min_interval: float = 0.0) -> None:
        self.min_interval = min_interval
        self._last: Dict[str, float] = {}

    def acquire(self, key: str) -> None:
        if self.min_interval <= 0:
            return
        now = time.monotonic()
        prev = self._last.get(key)
        if prev is not None:
            wait = self.min_interval - (now - prev)
            if wait > 0:
                time.sleep(wait)
        self._last[key] = time.monotonic()


__all__ = ["request_json", "RateLimiter", "USER_AGENT"]
