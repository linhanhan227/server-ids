"""测试公共夹具。

每个用例使用独立工作区副本, 避免污染仓库里的 data/ 与 runs/。
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture()
def workspace(tmp_path: Path) -> Path:
    """复制规则与情报目录到临时工作区。"""
    ws = tmp_path / "ws"
    shutil.copytree(ROOT / "data", ws / "data")
    (ws / "runs").mkdir()
    return ws
