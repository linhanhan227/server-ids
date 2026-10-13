"""采集器包。

内置采集器覆盖入侵溯源的核心取证面:

======================  ==========================================
采集器                   取证对象
======================  ==========================================
process                 进程树 / 可疑进程 / 中转与端口转发进程
network                 网络连接 / 监听端口 / 外联 IP
auth_log                认证日志 (成功/失败登录、sudo、新建会话)
persistence             持久化机制 (cron / systemd / rc / preload / SSH key)
account                 账号与提权面 (passwd / shadow / sudoers / 特权组)
filesystem              临时目录可执行文件 / SUID / 近期变更文件 / Web 目录 webshell
kernel                  内核模块 / LKM 异常 / 关键 sysctl
web_log                 Web 访问日志 / webshell 请求 / 扫描探测
command_history         shell 历史被清空或被启动脚本关闭
hidden_proc             /proc 有而 ps 没有的隐藏进程
process                 另标挖矿命令行、伪装内核线程、下载后执行
======================  ==========================================
"""

from irtrace.collectors.base import BaseCollector

__all__ = ["BaseCollector"]
