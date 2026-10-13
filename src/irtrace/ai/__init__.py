"""AI 辅助分析。模型调用必须走真实接口，不提供离线伪造结果。"""

from irtrace.ai.client import ModelClient, ModelConfig, ModelError

__all__ = ["ModelClient", "ModelConfig", "ModelError"]
