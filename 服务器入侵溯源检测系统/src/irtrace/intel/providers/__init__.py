"""情报平台适配器集合。

离线源 (offline=True, 取证现场默认启用)
    - ``local_rules``  本地规则库 data/rules/ioc_rules.json
    - ``csv_feed``     本地批量情报源 data/intel/*.csv|*.json

在线源 (需在 [intel] 中显式开启并配置 API Key)
    - ``threatbook``   微步在线 ThreatBook
    - ``virustotal``   VirusTotal v3
    - ``abuseipdb``    AbuseIPDB v2
    - ``otx``          AlienVault OTX
    - ``misp``         自建 / 订阅 MISP 实例
"""

from irtrace.intel.registry import intel_registry  # noqa: F401

__all__ = ["intel_registry"]
