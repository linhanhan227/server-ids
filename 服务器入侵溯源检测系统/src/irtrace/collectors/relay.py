"""中转进程识别。

进程采集器和网络关联共用。只认命令行里同时出现「转发工具」和
「对外监听 / 多跳目标」的进程, 避免把单独的 ssh 客户端当成跳板。

模型中转站是另一类: 进程对外提供 OpenAI 兼容接口, 同时配置了上游
模型地址。只有上游地址、没有对外监听的, 是本机调用方, 不算中转。
"""

from __future__ import annotations

import re

# 工具名必须是命令的第一个 token, 或路径的最后一段。
_TOOL = re.compile(
    r"(?:^|[\s/])("
    r"frpc|frps|npc|nps|gost|brook|lcx|portmap|rathole|"
    r"chisel|iodine|dnscat|reGeorg|neo-regeorg|suo5|venom|"
    r"ew|ew_for_linux|termite"
    r")(?:\s|$)",
    re.I,
)

# 这些参数说明进程在对外提供转发, 而不是本机临时连出去。
_FORWARD = re.compile(
    r"(?:-[LR]\s+\S*\d+:|-D\s+\d+|ProxyCommand|PermitTunnel|"
    r"gatewayports|tcp_listen|tcp_relay|socks5?://|relay://|"
    r"-listen\s+\S+:\d+|--remote\s+\S+|--server\s+\S+:\d+|"
    r"server_addr\s*=|bind_port\s*=)",
    re.I,
)

_CONFIG_HINT = re.compile(r"(?:frpc|frps|nps|npc|gost|chisel).*\.(?:ini|toml|yaml|yml|json)", re.I)

# 对外提供模型接口。只出现模型名不算。
_MODEL_LISTEN = re.compile(
    r"(?:--port\s+\d+|-(?:p|P)\s*\d+|0\.0\.0\.0:\d+|"
    r"(?:listen|bind)(?:=|\s+)\S*\d+|"
    r"(?:one-api|new-api|lobechat|chatgpt-next-web|open-webui|sillytavern))",
    re.I,
)
_MODEL_UPSTREAM = re.compile(
    r"(?:https?://[^\s\"']+/(?:v1|openai)(?:/|$)|"
    r"(?:BASE_URL|OPENAI_API_BASE|UPSTREAM|API_BASE)=https?://\S+|"
    r"(?:--base-url|--upstream|--api-base)\s+https?://\S+)",
    re.I,
)
_MODEL_GATEWAY = re.compile(
    r"(?:^|[\s/])(one-api|new-api|oneapi|newapi)(?:\s|$)",
    re.I,
)


def model_relay_flags(cmdline: str) -> list[str]:
    """模型中转站标签。必须同时有对外服务和上游地址, 或是专用网关进程。"""
    text = (cmdline or "").strip()
    if not text:
        return []
    flags: list[str] = []
    gateway = _MODEL_GATEWAY.search(text)
    if gateway:
        flags.append(f"model_gateway:{gateway.group(1).lower()}")
    if _MODEL_LISTEN.search(text):
        flags.append("model_listen")
    if _MODEL_UPSTREAM.search(text):
        flags.append("model_upstream")
    if gateway:
        return flags
    if "model_listen" in flags and "model_upstream" in flags:
        return flags
    return []


def is_model_relay(cmdline: str) -> bool:
    return bool(model_relay_flags(cmdline))


def relay_flags(cmdline: str) -> list[str]:
    """返回中转特征标签。空列表表示不像中转进程。"""
    text = (cmdline or "").strip()
    if not text:
        return []
    flags: list[str] = []
    tool = _TOOL.search(text)
    if tool:
        flags.append(f"relay_tool:{tool.group(1).lower()}")
    if _FORWARD.search(text):
        flags.append("port_forward")
    if _CONFIG_HINT.search(text):
        flags.append("relay_config")
    if "relay_tool" in " ".join(flags) and len(flags) == 1:
        # 只有工具名、没有转发参数时仍保留, 工具本身就是中转用途。
        return flags
    if "port_forward" in flags or "relay_config" in flags:
        return flags
    return []


def is_relay_process(cmdline: str) -> bool:
    return bool(relay_flags(cmdline))


__all__ = ["relay_flags", "is_relay_process", "model_relay_flags", "is_model_relay"]
