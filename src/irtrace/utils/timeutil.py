"""时间解析工具: 把各类日志时间戳归一化为 UTC datetime。"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Optional

# 常见日志时间格式 (无年份的 syslog 格式单独处理)
_PATTERNS = [
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%Y/%m/%d %H:%M:%S",
    # nginx/apache 必须在 syslog 之前: "%b %d" 会把 "13/Oct" 误当成无年份格式。
    "%d/%b/%Y:%H:%M:%S %z",
    "%d/%b/%Y:%H:%M:%S",
    "%b %d %H:%M:%S",        # syslog: Oct 12 19:59:55
    "%a %b %d %H:%M:%S %Y",  # `last` 输出
]

_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def parse_timestamp(value: str, *, default_year: Optional[int] = None) -> Optional[datetime]:
    """尽力把字符串解析为 UTC datetime; 失败返回 None。"""
    if not value:
        return None
    text = value.strip()
    # 去掉时区缩写 (CST/UTC/GMT 等无法可靠解析)
    text = re.sub(r"\s+[A-Z]{2,4}$", "", text)

    for fmt in _PATTERNS:
        try:
            dt = datetime.strptime(text, fmt)
        except ValueError:
            continue
        if "%Y" not in fmt and "%z" not in fmt:
            # 无年份格式 (syslog), 用 default_year 或当前年补齐
            year = default_year or now_utc().year
            dt = dt.replace(year=year)
            # 未来时间视为上一年 (跨年日志)
            if dt.replace(tzinfo=timezone.utc) > now_utc() + timedelta(days=1):
                dt = dt.replace(year=year - 1)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    return None


def fmt_local(dt: Optional[datetime], fmt: str = "%Y-%m-%d %H:%M:%S") -> str:
    if dt is None:
        return "-"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone().strftime(fmt)


__all__ = ["parse_timestamp", "now_utc", "fmt_local"]
