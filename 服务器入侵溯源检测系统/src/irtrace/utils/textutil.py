"""文本提取工具: 从日志/命令行中抽取 IOC。"""

from __future__ import annotations

import ipaddress
import re
from typing import List, Set

_RE_IP = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)
_RE_URL = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>)\]]+", re.I)
_RE_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|io|cn|ru|info|biz|xyz|top|club|online|site|shop|cc|tk|ml|ga|gq|pw|me|dev|app|cloud)\b",
    re.I,
)
_RE_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
_RE_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")


def _dedup(items: List[str]) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for i in items:
        if i not in seen:
            seen.add(i)
            out.append(i)
    return out


def extract_ips(text: str) -> List[str]:
    return _dedup(_RE_IP.findall(text or ""))


def extract_domains(text: str) -> List[str]:
    # 排除 IP 误匹配
    return _dedup([d for d in _RE_DOMAIN.findall(text or "") if not _RE_IP.fullmatch(d)])


def extract_urls(text: str) -> List[str]:
    return _dedup(_RE_URL.findall(text or ""))


def extract_hashes(text: str) -> List[str]:
    return _dedup(_RE_SHA256.findall(text or "") + _RE_MD5.findall(text or ""))


def is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved


__all__ = [
    "extract_ips",
    "extract_domains",
    "extract_urls",
    "extract_hashes",
    "is_private_ip",
]
