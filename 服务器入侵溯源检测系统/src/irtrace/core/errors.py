"""异常体系。"""


class IRTraceError(Exception):
    """框架基础异常。"""


class PluginError(IRTraceError):
    """插件加载 / 校验失败。"""


class CollectorError(IRTraceError):
    """采集阶段异常。"""


class AnalyzerError(IRTraceError):
    """分析阶段异常。"""


class ReporterError(IRTraceError):
    """报告生成异常。"""


class EvidenceIntegrityError(IRTraceError):
    """证据哈希链校验失败。"""
