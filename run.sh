#!/bin/sh
# 一键启动本地安全扫描界面（只监听 127.0.0.1）
# 用法：./run.sh [--port 8765]
set -e
cd "$(dirname "$0")"
exec python3 web_app.py --open "$@"
