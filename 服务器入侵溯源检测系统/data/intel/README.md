# 本地情报源目录

`csv_feed` 情报源会加载本目录下的所有 `*.csv` 与 `*.json` 文件，用于**离线**批量导入 IOC。

## CSV 格式

```
指标,类型,标签
45.155.205.233,ip,mining-pool
evil.example.com,domain,phishing
<sha256>,hash,ransomware
```

- 类型可选：`ip` / `domain` / `url` / `hash`（`sha256`、`md5`、`sha1` 亦可）
- 以 `#` 开头的行视为注释
- 首行若为表头（类型列值为 `type` 或 `类型`）会自动跳过

## JSON 格式

```json
{
  "ips": ["45.155.205.233"],
  "domains": ["evil.example.com"],
  "hashes": ["e3b0c442..."],
  "urls": ["http://evil.example.com/x.sh"]
}
```

或使用通用指标数组：

```json
{
  "indicators": [
    {"value": "45.155.205.233", "type": "ip", "tag": "c2"},
    {"value": "evil.example.com", "type": "domain", "tag": "phishing"}
  ]
}
```

## 用途

- 导入从其他平台（微步 / VT / MISP / 内部 SOC）**导出的 IOC 清单**
- 在**无网络**的取证现场保持情报能力
- 与 `data/rules/ioc_rules.json` 互补：规则库放长期通用规则，本目录放项目/事件专属 IOC
