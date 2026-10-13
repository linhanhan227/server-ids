"""哈希工具。"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Optional, Union

_CHUNK = 1024 * 1024


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Union[str, Path], *, max_bytes: Optional[int] = None) -> Optional[str]:
    """计算文件 SHA256; 读取失败返回 None。"""
    h = hashlib.sha256()
    read = 0
    try:
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(_CHUNK)
                if not chunk:
                    break
                h.update(chunk)
                read += len(chunk)
                if max_bytes and read >= max_bytes:
                    break
    except OSError:
        return None
    return h.hexdigest()


def md5_file(path: Union[str, Path]) -> Optional[str]:
    h = hashlib.md5()  # noqa: S324 - 仅用于与威胁情报比对, 非安全用途
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(_CHUNK), b""):
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()


__all__ = ["sha256_bytes", "sha256_file", "md5_file"]
