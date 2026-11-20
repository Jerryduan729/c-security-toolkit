#!/bin/sh
# 启动网页界面（Linux）
cd "$(dirname "$0")" || exit 1
chmod +x security-scan security-toolkit-web 2>/dev/null
exec ./security-toolkit-web "$@"
