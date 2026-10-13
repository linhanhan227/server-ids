"""webshell 文件名与内容特征。

采集器和关联规则共用这一份, 避免访问日志认一个名字、磁盘扫描认另一个。
只认脚本扩展名上的已知外壳名, 以及脚本正文里的执行入口。
普通业务页面不在这里。
"""

from __future__ import annotations

import os
import re

# 文件名本身就说明用途。扩展名限定为可被 Web 服务器执行的脚本。
SHELL_NAME = re.compile(
    r"(?:^|/)(?:"
    r"\.?[a-z0-9_-]*(?:shell|webshell|cmd|c99|r57|b374k|wso|alfa|indoxploit)"
    r"[a-z0-9_-]*\.(?:php|phtml|php\d|jsp|jspx|asp|aspx|ashx|cgi)"
    r"|[a-f0-9]{16,}\.(?:php|jsp|asp)"
    r")(?:$|[?#])",
    re.I,
)

# 正文里同时出现执行入口和命令, 才算内容特征。单个函数名不够。
_BODY_EXEC = re.compile(
    r"(?:eval\s*\(\s*(?:base64_decode|gzinflate|str_rot13|assert)|"
    r"(?:system|passthru|shell_exec|popen|proc_open)\s*\()",
    re.I,
)
_BODY_HINT = re.compile(
    r"(?:/bin/(?:ba)?sh|cmd\.exe|whoami|uname\s+-a|/etc/passwd|"
    r"\$_(?:GET|POST|REQUEST)\s*\[)",
    re.I,
)

WEB_ROOTS = (
    "/var/www",
    "/usr/share/nginx/html",
    "/var/www/html",
    "/srv/www",
    "/srv/http",
)
SCRIPT_EXT = (".php", ".phtml", ".jsp", ".jspx", ".asp", ".aspx", ".ashx", ".cgi")
MAX_BODY_BYTES = 256 * 1024


def is_shell_path(path: str) -> bool:
    """路径最后一段命中已知 webshell 文件名。"""
    name = os.path.basename(path.split("?", 1)[0])
    return bool(SHELL_NAME.search("/" + name))


def body_looks_like_shell(text: str) -> bool:
    """脚本正文同时含执行入口和命令或请求参数。"""
    if not text:
        return False
    return bool(_BODY_EXEC.search(text) and _BODY_HINT.search(text))


def same_web_file(request_path: str, file_path: str) -> bool:
    """访问路径与磁盘路径指向同一脚本。

    站点根目录不固定, 用文件名对齐; 两边都有目录时再要求目录后缀一致,
    避免 ``/a.php`` 对上另一个目录里的同名文件。
    """
    req = request_path.split("?", 1)[0].rstrip("/")
    disk = file_path.rstrip("/")
    if not req or not disk:
        return False
    req_name = os.path.basename(req)
    disk_name = os.path.basename(disk)
    if not req_name or req_name != disk_name:
        return False
    req_dir = os.path.dirname(req).strip("/")
    if not req_dir:
        return True
    return disk.strip("/").endswith(req_dir + "/" + req_name) or disk.endswith(req)


__all__ = [
    "SHELL_NAME",
    "WEB_ROOTS",
    "SCRIPT_EXT",
    "MAX_BODY_BYTES",
    "is_shell_path",
    "body_looks_like_shell",
    "same_web_file",
]
