"""OpenAI 兼容与 Codex CLI 两种真实模型通道。

只发请求、解析返回。解析失败或网络失败直接报错，不编造结论。
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from irtrace.intel.http import request_json


class ModelError(RuntimeError):
    """模型没有返回可解析的真实结果。"""


@dataclass
class ModelConfig:
    """一次调用所需的连接信息。Key 不写入日志。"""

    base_url: str
    api_key: str = ""
    model: str = ""
    protocol: str = "openai"   # openai | codex
    timeout: int = 60

    @property
    def configured(self) -> bool:
        if self.protocol == "codex":
            return bool(self.model) and shutil.which("codex") is not None
        return bool(self.base_url and self.api_key and self.model)


class ModelClient:
    """按协议调用模型。`complete_json` 要求模型返回一个 JSON 对象。"""

    def __init__(self, config: ModelConfig) -> None:
        self.config = config

    def complete_json(self, system: str, user: str) -> Dict[str, Any]:
        if self.config.protocol == "codex":
            text = self._codex(system, user)
        else:
            text = self._openai(system, user)
        return _parse_json_object(text)

    # ------------------------------------------------------------------ #
    def _openai(self, system: str, user: str) -> str:
        cfg = self.config
        if not cfg.base_url or not cfg.api_key or not cfg.model:
            raise ModelError("OpenAI 兼容接口缺少 base_url、api_key 或 model")
        url = _chat_url(cfg.base_url)
        status, payload, error = request_json(
            url,
            method="POST",
            headers={"Authorization": f"Bearer {cfg.api_key}"},
            json_body={
                "model": cfg.model,
                "temperature": 0,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            },
            timeout=cfg.timeout,
            retries=0,
        )
        if error or not isinstance(payload, dict):
            raise ModelError(f"模型接口失败 ({status}): {error or '空响应'}")
        try:
            return str(payload["choices"][0]["message"]["content"])
        except (KeyError, IndexError, TypeError) as exc:
            raise ModelError(f"模型响应缺少 choices[0].message.content: {exc}") from exc

    def _codex(self, system: str, user: str) -> str:
        cfg = self.config
        binary = shutil.which("codex")
        if not binary:
            raise ModelError("未找到 codex 可执行文件")
        if not cfg.model:
            raise ModelError("Codex 调用缺少 model")
        prompt = f"{system}\n\n{user}\n\n只输出一个 JSON 对象，不要 Markdown。"
        cmd = [binary, "exec", "--skip-git-repo-check", "-m", cfg.model, prompt]
        try:
            proc = subprocess.run(
                cmd, check=False, capture_output=True, text=True, timeout=cfg.timeout,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ModelError(f"codex 执行失败: {exc}") from exc
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "").strip()[:300]
            raise ModelError(f"codex 退出码 {proc.returncode}: {detail}")
        return proc.stdout


def load_model_config(workspace, *, protocol: Optional[str] = None,
                      model: Optional[str] = None) -> ModelConfig:
    """配置优先级：显式参数 > 环境变量 > 密钥库 `ai_model`。"""
    stored: Dict[str, Any] = {}
    try:
        from irtrace.secrets import SecretStore
        row = SecretStore(workspace).get("ai_model")
        if row and row.get("enabled"):
            stored = {"api_key": row.get("api_key") or "", **(row.get("extra") or {})}
    except (OSError, ValueError):
        stored = {}

    chosen = (protocol or os.environ.get("IRTRACE_AI_PROTOCOL")
              or stored.get("protocol") or "openai")
    return ModelConfig(
        base_url=(os.environ.get("IRTRACE_AI_BASE_URL")
                  or stored.get("base_url") or ""),
        api_key=(os.environ.get("IRTRACE_AI_API_KEY") or stored.get("api_key") or ""),
        model=(model or os.environ.get("IRTRACE_AI_MODEL") or stored.get("model") or ""),
        protocol=str(chosen),
        timeout=int(os.environ.get("IRTRACE_AI_TIMEOUT") or stored.get("timeout") or 60),
    )


def _chat_url(base_url: str) -> str:
    """兼容三种写法：根域名、带 /v1、或已经是完整的 chat/completions。"""
    url = base_url.strip().rstrip("/")
    path = urlparse(url).path.rstrip("/")
    if path.endswith("/chat/completions"):
        return url
    if path.endswith("/v1"):
        return url + "/chat/completions"
    return url + "/v1/chat/completions"


def _parse_json_object(text: str) -> Dict[str, Any]:
    raw = (text or "").strip()
    if raw.startswith("```"):
        raw = raw.strip("`")
        if raw.lower().startswith("json"):
            raw = raw[4:].strip()
    start, end = raw.find("{"), raw.rfind("}")
    if start == -1 or end <= start:
        raise ModelError("模型没有返回 JSON 对象")
    try:
        data = json.loads(raw[start:end + 1])
    except json.JSONDecodeError as exc:
        raise ModelError(f"模型 JSON 无法解析: {exc}") from exc
    if not isinstance(data, dict):
        raise ModelError("模型返回的不是 JSON 对象")
    return data


__all__ = ["ModelClient", "ModelConfig", "ModelError", "load_model_config"]
