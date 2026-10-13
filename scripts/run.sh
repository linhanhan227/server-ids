#!/bin/sh
# 运行一次入侵检测。
# 用法:
#   scripts/run.sh                 自检后做完整检测，并打开控制台
#   scripts/run.sh --no-web        只检测，不开控制台
#   scripts/run.sh --web-only      只打开已有结果的控制台
#   scripts/run.sh --dry-run       不执行采集命令
# 其余参数原样传给 `irtrace run`，例如 --only process network
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$ROOT"
export PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}"

if [ -x "$ROOT/.venv/bin/python" ]; then
    PY="$ROOT/.venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
    PY=python3
else
    PY=python
fi

web=1
run=1
dry=""
pass=""
while [ $# -gt 0 ]; do
    case "$1" in
        --no-web) web=0 ;;
        --web-only) run=0 ;;
        --dry-run) dry="--dry-run" ;;
        *) pass="$pass \"$1\"" ;;
    esac
    shift
done

echo "工作区: $ROOT"
echo "Python: $PY"

if [ "$run" -eq 1 ]; then
    echo "--- 环境自检 ---"
    "$PY" -m irtrace doctor -w "$ROOT"
    echo "--- 开始检测 ---"
    # shellcheck disable=SC2086
    eval "\"$PY\" -m irtrace run -w \"$ROOT\" --format json markdown html $dry $pass"
fi

if [ "$web" -eq 1 ]; then
    echo "--- 控制台 http://127.0.0.1:8787 ---"
    exec "$PY" -m irtrace web -w "$ROOT" --port 8787
fi
