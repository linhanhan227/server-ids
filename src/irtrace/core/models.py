"""统一数据模型。

三类核心实体:
- ``Event``     : 归一化时间轴上的一个动作 (登录、进程启动、连接建立...)。
- ``Evidence``  : 从目标系统采集到的原始素材 (文件/命令输出), 带哈希用于防篡改。
- ``Finding``   : 分析器给出的结论 (可疑行为/失陷指标), 关联 Event 与 Evidence。
"""

from __future__ import annotations

import dataclasses
import enum
import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# 枚举
# --------------------------------------------------------------------------- #
class Severity(str, enum.Enum):
    """发现项严重级别。"""

    CRITICAL = "critical"   # 已确认失陷 (如 rootkit / 反弹 shell)
    HIGH = "high"           # 高度可疑, 需立即核查
    MEDIUM = "medium"       # 异常, 需结合上下文判断
    LOW = "low"             # 低风险 / 基线偏差
    INFO = "info"           # 信息性记录

    @property
    def weight(self) -> int:
        return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}[self.value]

    def __str__(self) -> str:  # pragma: no cover - 便捷输出
        return self.value


class Confidence(str, enum.Enum):
    """结论置信度。"""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Category(str, enum.Enum):
    """事件/证据分类, 用于时间线聚合与报告分组。"""

    AUTH = "auth"                 # 认证 / 登录
    PROCESS = "process"           # 进程
    NETWORK = "network"           # 网络连接
    PERSISTENCE = "persistence"   # 持久化
    ACCOUNT = "account"           # 账号 / 权限
    FILE = "file"                 # 文件系统
    LOG = "log"                   # 日志
    KERNEL = "kernel"             # 内核模块
    OTHER = "other"


# --------------------------------------------------------------------------- #
# 工具
# --------------------------------------------------------------------------- #
def _to_utc(dt: Optional[datetime]) -> Optional[datetime]:
    """把任意 datetime 归一化为带时区的 UTC。naive 时间按 UTC 解释。"""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _iso(dt: Optional[datetime]) -> Optional[str]:
    dt = _to_utc(dt)
    return dt.isoformat() if dt else None


class _Serializable:
    """混入: 提供 dict / json 序列化。"""

    def to_dict(self) -> Dict[str, Any]:  # pragma: no cover - 由子类实现
        raise NotImplementedError

    def to_json(self, **kw: Any) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, default=str, **kw)


# --------------------------------------------------------------------------- #
# Event
# --------------------------------------------------------------------------- #
@dataclass
class Event(_Serializable):
    """归一化事件。"""

    timestamp: Optional[datetime]
    category: Category
    source: str                       # 产生该事件的采集器名
    action: str                       # 动作短语, 如 "process_exec" / "ssh_login"
    message: str = ""
    host: str = ""
    user: str = ""
    pid: Optional[int] = None
    ppid: Optional[int] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    path: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])

    def to_dict(self) -> Dict[str, Any]:
        d = dataclasses.asdict(self)
        d["timestamp"] = _iso(self.timestamp)
        d["category"] = self.category.value
        return d

    @property
    def sort_key(self) -> datetime:
        """时间线排序键; 无时间戳的事件排到最后。"""
        return _to_utc(self.timestamp) or datetime.max.replace(tzinfo=timezone.utc)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Event":
        """从 JSON 报告还原事件, 供 ``analyze --run-dir`` 重放。"""
        payload = dict(data)
        ts = payload.get("timestamp")
        if isinstance(ts, str) and ts:
            try:
                parsed = datetime.fromisoformat(ts)
            except ValueError:
                parsed = None
            payload["timestamp"] = _to_utc(parsed)
        else:
            payload["timestamp"] = None
        cat = payload.get("category") or Category.OTHER.value
        try:
            payload["category"] = Category(cat)
        except ValueError:
            payload["category"] = Category.OTHER
        known = {f.name for f in dataclasses.fields(cls)}
        return cls(**{k: v for k, v in payload.items() if k in known})


# --------------------------------------------------------------------------- #
# Evidence
# --------------------------------------------------------------------------- #
@dataclass
class Evidence(_Serializable):
    """证据对象。``sha256`` 为空表示仅记录元数据 (如敏感文件不落盘)。"""

    source: str
    kind: str                         # file / command_output / artifact
    path: Optional[str] = None
    content: Optional[str] = None     # 落盘路径 (相对 run 目录) 或内联文本
    sha256: Optional[str] = None
    size: Optional[int] = None
    mtime: Optional[datetime] = None
    collected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    note: str = ""
    evidence_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])

    def to_dict(self) -> Dict[str, Any]:
        d = dataclasses.asdict(self)
        d["mtime"] = _iso(self.mtime)
        d["collected_at"] = _iso(self.collected_at)
        return d

    @staticmethod
    def hash_bytes(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------- #
# Finding
# --------------------------------------------------------------------------- #
@dataclass
class Finding(_Serializable):
    """分析结论。"""

    title: str
    severity: Severity
    analyzer: str
    description: str = ""
    confidence: Confidence = Confidence.MEDIUM
    category: Category = Category.OTHER
    mitre: List[str] = field(default_factory=list)      # ATT&CK 技术编号
    event_ids: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)
    finding_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])

    def to_dict(self) -> Dict[str, Any]:
        d = dataclasses.asdict(self)
        d["severity"] = self.severity.value
        d["confidence"] = self.confidence.value
        d["category"] = self.category.value
        return d


__all__ = [
    "Severity",
    "Confidence",
    "Category",
    "Event",
    "Evidence",
    "Finding",
]
