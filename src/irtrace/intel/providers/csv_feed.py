"""本地批量情报源 (离线)。

从 ``data/intel/`` 目录加载自建情报:
- ``*.json``: ``{"ips": [...], "domains": [...], "hashes": [...], "urls": [...]}``
  或顶层直接为数组 (需在配置中指定 ``type``)
- ``*.csv``: 每行 ``指标[,类型[,标签]]``; 首行为表头时自动识别

支持多文件合并, 适用于从其他平台导出的 IOC 清单。
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from irtrace.core.models import Severity
from irtrace.intel.base import ThreatIntelProvider
from irtrace.intel.models import IndicatorType, IntelVerdict
from irtrace.intel.registry import register_provider

_TYPE_ALIASES = {
    "ip": IndicatorType.IP, "ipv4": IndicatorType.IP, "ip-dst": IndicatorType.IP,
    "domain": IndicatorType.DOMAIN, "hostname": IndicatorType.DOMAIN,
    "url": IndicatorType.URL, "uri": IndicatorType.URL,
    "hash": IndicatorType.HASH, "sha256": IndicatorType.HASH,
    "md5": IndicatorType.HASH, "sha1": IndicatorType.HASH,
}


@register_provider
class CsvFeedProvider(ThreatIntelProvider):
    name = "csv_feed"
    description = "本地批量情报源 (data/intel/*.csv|*.json)"
    supports = (IndicatorType.IP, IndicatorType.DOMAIN,
                IndicatorType.HASH, IndicatorType.URL)
    requires_api_key = False
    offline = True
    weight = 1.0
    min_interval = 0.0

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(config)
        self._index: Optional[Dict[IndicatorType, Dict[str, str]]] = None

    # ------------------------------------------------------------------ #
    @property
    def feed_dir(self) -> Path:
        if self.config.get("feed_dir"):
            return Path(self.config["feed_dir"])
        ws = self.config.get("workspace")
        base = Path(ws) if ws else Path.cwd()
        return base / "data" / "intel"

    def _load(self) -> Dict[IndicatorType, Dict[str, str]]:
        if self._index is not None:
            return self._index

        index: Dict[IndicatorType, Dict[str, str]] = {t: {} for t in IndicatorType}
        d = self.feed_dir
        if d.is_dir():
            for f in sorted(d.iterdir()):
                try:
                    if f.suffix.lower() == ".json":
                        self._load_json(f, index)
                    elif f.suffix.lower() in (".csv", ".txt"):
                        self._load_csv(f, index)
                except (OSError, ValueError, json.JSONDecodeError):
                    continue
        self._index = index
        return index

    def _load_json(self, path: Path, index: Dict[IndicatorType, Dict[str, str]]) -> None:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, list):
            for item in data:
                if isinstance(item, str):
                    index[IndicatorType.IP][item.strip()] = f"{path.name}:list"
                elif isinstance(item, dict):
                    self._add_dict(item, index, path.name)
        elif isinstance(data, dict):
            for key, itype in (("ips", IndicatorType.IP),
                               ("domains", IndicatorType.DOMAIN),
                               ("hashes", IndicatorType.HASH),
                               ("urls", IndicatorType.URL)):
                for v in data.get(key, []) or []:
                    if v:
                        index[itype][str(v).strip().lower()] = path.name
            for item in data.get("indicators", []) or []:
                if isinstance(item, dict):
                    self._add_dict(item, index, path.name)

    @staticmethod
    def _add_dict(item: Dict[str, Any], index: Dict[IndicatorType, Dict[str, str]],
                  source: str) -> None:
        raw_type = str(item.get("type", "ip")).lower()
        itype = _TYPE_ALIASES.get(raw_type)
        value = item.get("value") or item.get("indicator")
        if itype and value:
            index[itype][str(value).strip().lower()] = (
                f"{source}:{item.get('tag') or item.get('tags') or ''}")

    def _load_csv(self, path: Path, index: Dict[IndicatorType, Dict[str, str]]) -> None:
        text = path.read_text(encoding="utf-8", errors="replace")
        reader = csv.reader(io.StringIO(text))
        for row in reader:
            if not row or not row[0].strip() or row[0].lstrip().startswith("#"):
                continue
            value = row[0].strip()
            raw_type = (row[1].strip().lower() if len(row) > 1 else "ip")
            itype = _TYPE_ALIASES.get(raw_type)
            if itype is None:
                if raw_type in ("type", "类型"):   # 表头
                    continue
                itype = IndicatorType.IP
            tag = row[2].strip() if len(row) > 2 else ""
            index[itype][value.lower()] = f"{path.name}:{tag}"

    # ------------------------------------------------------------------ #
    def _lookup(self, indicator: str, itype: IndicatorType) -> IntelVerdict:
        index = self._load()
        probe = indicator.strip().lower()
        hit = index.get(itype, {}).get(probe)

        if hit:
            source, _, tag = hit.partition(":")
            return self.verdict(
                indicator, itype, malicious=True, score=85.0,
                severity=Severity.HIGH, confidence=0.85,
                tags=["local-feed", f"ioc-{itype.value}"] + ([tag] if tag else []),
                description=f"命中本地情报源 {source}",
                raw={"source": source, "tag": tag},
            )
        return self.verdict(
            indicator, itype, malicious=False, score=0.0,
            severity=Severity.INFO, confidence=0.3,
            tags=["local-feed"], description="本地情报源无命中",
        )

    def feed_stats(self) -> Dict[str, int]:
        idx = self._load()
        return {t.value: len(v) for t, v in idx.items()}


__all__ = ["CsvFeedProvider"]
