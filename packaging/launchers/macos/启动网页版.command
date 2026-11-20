#!/bin/sh
# 双击启动网页界面（macOS）
# 首次运行若提示「无法验证开发者」：右键 → 打开 → 再点「打开」
# 或在终端执行：xattr -dr com.apple.quarantine .
cd "$(dirname "$0")" || exit 1

# 解压工具可能丢掉执行权限，这里补回来
chmod +x security-scan security-toolkit-web 2>/dev/null
# 清掉下载隔离属性，避免 Gatekeeper 反复拦截
xattr -d com.apple.quarantine security-scan security-toolkit-web 2>/dev/null

exec ./security-toolkit-web --open "$@"
