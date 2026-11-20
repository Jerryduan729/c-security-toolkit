#!/bin/sh
# macOS 双击启动：在 Finder 里双击本文件即可打开网页界面。
# 首次运行若提示「无法打开，因为无法验证开发者」，右键 → 打开，或执行：
#   xattr -d com.apple.quarantine 启动-macos.command
cd "$(dirname "$0")" || exit 1

if ! command -v python3 >/dev/null 2>&1; then
    echo "未找到 python3。请安装 Python 3.10+（https://www.python.org/downloads/），"
    echo "或直接使用 dist/ 里的免安装版本：security-toolkit-web"
    printf "按回车关闭…"
    read -r _
    exit 1
fi

exec python3 web_app.py --open "$@"
