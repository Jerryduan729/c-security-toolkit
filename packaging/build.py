#!/usr/bin/env python3
"""跨平台打包脚本：macOS（Apple Silicon / Intel）与 Windows 通用。

用法：
    python3 packaging/build.py            # 缺 PyInstaller 时提示安装
    python3 packaging/build.py --install  # 顺便用当前 Python 安装 PyInstaller

产物在 dist/：
    security-scan          命令行扫描器
    security-toolkit-web   本地网页界面（Windows 带 .exe 后缀）
"""

from __future__ import annotations

import argparse
import platform
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPEC = ROOT / "packaging" / "security_toolkit.spec"
TARGETS = ("security-scan", "security-toolkit-web")


def main() -> int:
    parser = argparse.ArgumentParser(description="打包为独立可执行文件")
    parser.add_argument("--install", action="store_true", help="安装 PyInstaller 后继续")
    args = parser.parse_args()

    if shutil.which("pyinstaller") is None:
        if not args.install:
            print("未找到 pyinstaller。先执行：\n  python3 -m pip install pyinstaller\n"
                  "或重跑本脚本并加 --install", file=sys.stderr)
            return 2
        subprocess.run([sys.executable, "-m", "pip", "install", "pyinstaller"], check=True)

    subprocess.run([
        "pyinstaller", "--noconfirm", "--clean", str(SPEC),
        "--distpath", str(ROOT / "dist"),
        "--workpath", str(ROOT / "build"),
    ], check=True, cwd=ROOT)

    suffix = ".exe" if platform.system() == "Windows" else ""
    print("\n打包完成：")
    for name in TARGETS:
        path = ROOT / "dist" / f"{name}{suffix}"
        size = path.stat().st_size / 1024 / 1024 if path.exists() else 0
        status = f"{size:.1f} MB" if path.exists() else "缺失"
        print(f"  {path.relative_to(ROOT)}  ({status})")
    print(f"\n平台：{platform.system()} {platform.machine()} / Python {platform.python_version()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
