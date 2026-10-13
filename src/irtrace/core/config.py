"""运行配置。

全部放在 ``data/secrets.db`` 的 ``settings`` 表，由 Web UI 或接口写入。
不再读取 TOML / JSON。``--config`` 保留参数位，但会被拒绝。

约定：

- 检测只查本地库，不因为配置打开而自己去拉在线情报。
- ``ai.cross_validate`` 默认关闭。打开后，AI 辅助判定才会用已配置的
  在线情报接口做交叉验证。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from irtrace.settings import DEFAULTS, SettingsStore, load_settings

__all__ = ["DEFAULTS", "load_config", "load_settings"]


def load_config(path: str | Path | None = None, workspace: str | Path | None = None) -> Dict[str, Any]:
    """加载配置。传入文件路径会报错，避免再走 TOML。"""
    if path not in (None, ""):
        raise ValueError(
            "不再读取配置文件。请在 Web 控制台「设置」里修改，配置写入 data/secrets.db"
        )
    if workspace is None:
        workspace = Path.cwd()
    return SettingsStore(workspace).load()
