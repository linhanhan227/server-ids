"""网络采集器: 采集连接、监听端口与外联 IP。

数据来源 (按可用性降级):
1. ``ss -tunap`` (iproute2) —— 可关联进程
2. ``/proc/net/tcp`` ``/proc/net/tcp6`` ``/proc/net/udp`` —— 无外部依赖
3. ``netstat -tunap`` —— 老系统兜底
"""

from __future__ import annotations

import re
import struct
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from irtrace.collectors.base import BaseCollector
from irtrace.core.models import Category, Event
from irtrace.core.plugin import CollectResult
from irtrace.core.registry import register
from irtrace.utils.textutil import is_private_ip

# 常见后门 / 挖矿端口。与 data/rules/ioc_rules.json 的 suspicious_ports 对齐,
# 规则文件存在时以规则文件为准, 缺失时回落到此集合。
_DEFAULT_SUSPICIOUS_PORTS = {
    4444, 4445, 5555, 6666, 7777, 8888, 9999, 1337, 31337,
    12345, 54321, 6667, 1080, 3333, 14444,
}

# 本机落在这些端口上的已建立连接, 对端视为连入的客户端。
_SERVICE_PORTS = {22, 80, 443, 8080, 8443, 8000, 8888, 7000, 7500}

_TCP_STATES = {
    "01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1",
    "05": "FIN_WAIT2", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT",
    "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING",
}


@register
class NetworkCollector(BaseCollector):
    name = "network"
    description = "采集网络连接/监听端口/外联 IP, 标记可疑端口与非内网外联"
    category = Category.NETWORK
    requires_paths = ["/proc/net"]

    def collect(self, ctx) -> CollectResult:
        res = CollectResult()
        self._suspicious_ports = self._load_suspicious_ports(ctx)
        rows: List[str] = []
        seen: set = set()

        # 优先 ss (带进程信息)
        if ctx.which("ss"):
            out = ctx.run_command(["ss", "-tunap"])
            if out:
                res.evidence.append(
                    self.evidence_from_text(ctx, "ss-tunap.txt", out,
                                            note="ss -tunap 原始输出")
                )
                for line in out.splitlines()[1:]:
                    row = self._parse_ss(ctx, res, line)
                    if row:
                        rows.append(row)
                        seen.add(row.split("\t")[0])

        # 补充 /proc/net (无进程信息的兜底)
        for proto, path in (("tcp", "/proc/net/tcp"), ("tcp6", "/proc/net/tcp6"),
                            ("udp", "/proc/net/udp"), ("udp6", "/proc/net/udp6")):
            for row in self._parse_proc_net(ctx, res, path, proto):
                if row.split("\t")[0] not in seen:
                    rows.append(row)
                    seen.add(row.split("\t")[0])

        if rows:
            res.evidence.append(
                self.evidence_from_text(
                    ctx, "network-connections.tsv",
                    "LOCAL\tREMOTE\tSTATE\tPROCESS\n" + "\n".join(rows),
                    note="归一化连接表",
                )
            )
        res.stats = {"connections": len(rows)}
        return res

    # ------------------------------------------------------------------ #
    def _parse_ss(self, ctx, res: CollectResult, line: str) -> Optional[str]:
        parts = line.split()
        if len(parts) < 5:
            return None
        proto, state, local = parts[0], parts[1], parts[4]
        peer = parts[5] if len(parts) > 5 else "*:*"
        proc = ""
        m = re.search(r'users:\(\("([^"]+)".*?pid=(\d+)', line)
        if m:
            proc = f"{m.group(1)}/{m.group(2)}"
        self._emit(ctx, res, proto, state, local, peer, proc)
        return f"{local}\t{peer}\t{state}\t{proc}"

    def _parse_proc_net(self, ctx, res: CollectResult, path: str, proto: str) -> List[str]:
        rows: List[str] = []
        content = ctx.read_file(path)
        if not content:
            return rows
        is_v6 = proto.endswith("6")
        for line in content.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 4:
                continue
            local = self._decode_addr(parts[1], is_v6)
            peer = self._decode_addr(parts[2], is_v6)
            state = _TCP_STATES.get(parts[3], parts[3]) if proto.startswith("tcp") else "UDP"
            self._emit(ctx, res, proto, state, local, peer, "")
            rows.append(f"{local}\t{peer}\t{state}\t")
        return rows

    def _emit(self, ctx, res: CollectResult, proto: str, state: str,
              local: str, peer: str, proc: str) -> None:
        try:
            peer_ip = peer.rsplit(":", 1)[0].strip("[]")
            peer_port = int(peer.rsplit(":", 1)[1])
        except (ValueError, IndexError):
            return

        ports = getattr(self, "_suspicious_ports", _DEFAULT_SUSPICIOUS_PORTS)
        if state == "LISTEN":
            local_port = self._port_of(local)
            if local_port in ports:
                res.events.append(self.event(
                    ctx, action="suspicious_listen",
                    message=f"可疑监听端口 {local} ({proto}) 进程={proc or '?'}",
                    timestamp=datetime.now(timezone.utc),
                    dst_port=local_port,
                    tags=["suspicious-listen"], raw={"proto": proto, "proc": proc},
                ))
            return

        if state == "ESTABLISHED" and peer_ip and not is_private_ip(peer_ip):
            flags = []
            if peer_port in ports:
                flags.append("suspicious_port")
            # 本机落在常见服务端口上时, 对端是连进来的客户端。
            direction = "inbound" if self._port_of(local) in _SERVICE_PORTS else "outbound"
            res.events.append(self.event(
                ctx, action="external_connection",
                message=f"外联 {peer_ip}:{peer_port} ({proto}) 进程={proc or '?'}",
                timestamp=datetime.now(timezone.utc),
                src_ip=peer_ip if direction == "inbound" else None,
                dst_ip=None if direction == "inbound" else peer_ip,
                dst_port=peer_port,
                tags=["external-conn", direction] + flags,
                raw={"proto": proto, "proc": proc, "local": local,
                     "direction": direction},
            ))

    @staticmethod
    def _load_suspicious_ports(ctx) -> set:
        """优先用规则库里的 suspicious_ports, 读不到则用内置集合。"""
        from pathlib import Path
        import json
        path = Path(ctx.workspace) / "data" / "rules" / "ioc_rules.json"
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            ports = {int(p) for p in data.get("suspicious_ports", [])}
            return ports or set(_DEFAULT_SUSPICIOUS_PORTS)
        except (OSError, ValueError, json.JSONDecodeError):
            return set(_DEFAULT_SUSPICIOUS_PORTS)

    @staticmethod
    def _port_of(addr: str) -> int:
        try:
            return int(addr.rsplit(":", 1)[1])
        except (ValueError, IndexError):
            return 0

    @staticmethod
    def _decode_addr(hexaddr: str, is_v6: bool) -> str:
        """解析 /proc/net 中的 hex 地址为 ip:port。"""
        try:
            ip_hex, port_hex = hexaddr.split(":")
            port = int(port_hex, 16)
            if not is_v6:
                raw = bytes.fromhex(ip_hex)[::-1]  # 小端
                ip = ".".join(str(b) for b in raw)
            else:
                raw = bytes.fromhex(ip_hex)
                groups = struct.unpack("<8H", raw)
                # 折叠 IPv4-mapped
                if groups[:5] == (0, 0, 0, 0, 0) and groups[5] == 0xFFFF:
                    ip = ".".join(str(b) for b in raw[12:16])
                else:
                    ip = ":".join(f"{g:04x}" for g in groups)
            return f"{ip}:{port}"
        except (ValueError, struct.error):
            return "?:?"


__all__ = ["NetworkCollector"]
