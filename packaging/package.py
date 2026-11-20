#!/usr/bin/env python3
"""把 dist/ 里的可执行文件整理成「解压即用」的分发包。

用法：
    python3 packaging/package.py                 # 按当前平台打包
    python3 packaging/package.py --platform all  # 三平台都打（需要对应产物）
    python3 packaging/package.py --version 1.2.1 --dist dist --out release

为什么不用裸二进制分发：浏览器下载会丢掉可执行权限，还会附加 macOS 隔离属性，
用户双击必然没反应。压缩包可以保留权限位，并附带启动脚本与说明。
"""

from __future__ import annotations

import argparse
import hashlib
import platform
import shutil
import tarfile
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LAUNCHERS = ROOT / "packaging" / "launchers"

MACOS_README = """Security Toolkit {version} · macOS（Apple Silicon）
====================================================

第一次打开
----------
1. 把 SecurityToolkit 文件夹放到任意位置（不要直接在压缩包里运行）
2. 双击「启动网页版.command」
3. 如果提示「无法验证开发者」或「已损坏」：
   方式一：右键点「启动网页版.command」→ 打开 → 再点「打开」
   方式二：打开「终端」，执行下面这一行，然后重新双击
           xattr -dr com.apple.quarantine SecurityToolkit
   方式三：系统设置 → 隐私与安全性 → 找到被拦截的提示 → 仍要打开

浏览器会自动打开 http://127.0.0.1:8765

两个程序
--------
- 启动网页版.command   图形界面（推荐）
- security-scan        命令行扫描器

命令行用法
----------
  ./security-scan --version
  ./security-scan --authorized --source ./你的代码目录
  ./security-scan --authorized --source ./src --ai

说明
----
- 报告生成在本目录的 reports/ 下
- AI 功能需要环境变量 SECURITY_AI_API_KEY（可选）
- 架构为 arm64，仅支持 M1/M2/M3/M4 等 Apple Silicon
- 项目主页：https://github.com/Jerryduan729/c-security-toolkit
"""

WINDOWS_README = """Security Toolkit {version} · Windows（x64）
=============================================

第一次打开
----------
1. 把 SecurityToolkit 文件夹放到任意位置（不要直接在压缩包里运行）
2. 双击「启动网页版.bat」
3. 如果出现蓝色 SmartScreen 窗口：点「更多信息」→「仍要运行」
   （程序没有代码签名，这不是病毒；杀毒软件误报时把文件夹加入白名单）

浏览器会自动打开 http://127.0.0.1:8765

两个程序
--------
- 启动网页版.bat                  图形界面（推荐）
- security-scan.exe              命令行扫描器

命令行用法（cmd）
-----------------
  security-scan.exe --version
  security-scan.exe --authorized --source D:\\你的代码目录
  set SECURITY_AI_API_KEY=sk-xxxx & security-scan.exe --authorized --source . --ai

说明
----
- 报告生成在本目录的 reports\\ 下
- 架构为 x64（ARM 版 Windows 可通过系统自带的 x64 仿真运行）
- 项目主页：https://github.com/Jerryduan729/c-security-toolkit
"""

LINUX_README = """Security Toolkit {version} · Linux（x86_64）
=============================================

第一次打开
----------
1. 解压：tar -xzf SecurityToolkit-{version}-linux-x64.tar.gz
2. 进入目录：cd SecurityToolkit
3. 启动界面：./start-web.sh
   或直接扫描：./security-scan --authorized --source ./src

说明
----
- 报告生成在本目录的 reports/ 下
- 动态链接 glibc（Ubuntu 20.04+ / Debian 11+ 等）
- AI 功能需要环境变量 SECURITY_AI_API_KEY（可选）
- 项目主页：https://github.com/Jerryduan729/c-security-toolkit
"""

PLATFORMS = {
    "macos": {
        "label": "macos-arm64",
        "binary": "security-scan",
        "web": "security-toolkit-web",
        "launcher": LAUNCHERS / "macos" / "启动网页版.command",
        "readme": MACOS_README,
        "archive": "zip",
    },
    "windows": {
        "label": "windows-x64",
        "binary": "security-scan.exe",
        "web": "security-toolkit-web.exe",
        "launcher": LAUNCHERS / "windows" / "启动网页版.bat",
        "readme": WINDOWS_README,
        "archive": "zip",
    },
    "linux": {
        "label": "linux-x64",
        "binary": "security-scan",
        "web": "security-toolkit-web",
        "launcher": LAUNCHERS / "linux" / "start-web.sh",
        "readme": LINUX_README,
        "archive": "tar.gz",
    },
}


def host_platform() -> str:
    system = platform.system()
    return {"Darwin": "macos", "Windows": "windows", "Linux": "linux"}.get(system, "linux")


def _write_zip(source: Path, target: Path) -> None:
    """写 zip，并显式保留 Unix 权限位（浏览器下载后仍可执行）。"""
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(source.rglob("*")):
            if path.is_dir():
                continue
            arcname = path.relative_to(source.parent).as_posix()
            info = zipfile.ZipInfo(arcname)
            mode = 0o755 if path.stat().st_mode & 0o111 else 0o644
            info.external_attr = (0o100000 | mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, path.read_bytes())


def _write_tar(source: Path, target: Path) -> None:
    with tarfile.open(target, "w:gz") as archive:
        archive.add(source, arcname=source.name)


def build_platform(name: str, version: str, dist: Path, out: Path) -> Path | None:
    spec = PLATFORMS[name]
    binary, web = dist / spec["binary"], dist / spec["web"]
    if not binary.is_file() or not web.is_file():
        print(f"跳过 {name}：{dist} 下缺少 {spec['binary']} 或 {spec['web']}")
        return None

    with tempfile.TemporaryDirectory() as tmp:
        bundle = Path(tmp) / "SecurityToolkit"
        bundle.mkdir()
        shutil.copy2(binary, bundle / spec["binary"])
        shutil.copy2(web, bundle / spec["web"])
        launcher = bundle / spec["launcher"].name
        shutil.copy2(spec["launcher"], launcher)
        launcher.chmod(0o755)
        (bundle / "使用说明.txt").write_text(
            spec["readme"].format(version=version), encoding="utf-8"
        )
        for item in (bundle / spec["binary"], bundle / spec["web"]):
            item.chmod(0o755)

        out.mkdir(parents=True, exist_ok=True)
        target = out / f"SecurityToolkit-{version}-{spec['label']}.{spec['archive']}"
        if spec["archive"] == "zip":
            _write_zip(bundle, target)
        else:
            _write_tar(bundle, target)
    return target


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description="生成解压即用的分发包")
    parser.add_argument("--version", default="dev", help="版本号，用于命名压缩包")
    parser.add_argument("--platform", default="host", choices=("host", "all", *PLATFORMS))
    parser.add_argument("--dist", type=Path, default=ROOT / "dist", help="可执行文件目录")
    parser.add_argument("--out", type=Path, default=ROOT / "release", help="压缩包输出目录")
    args = parser.parse_args()

    targets = list(PLATFORMS) if args.platform == "all" else [
        host_platform() if args.platform == "host" else args.platform
    ]

    built: list[Path] = []
    for name in targets:
        archive = build_platform(name, args.version, args.dist, args.out)
        if archive:
            built.append(archive)
            print(f"已生成 {archive.relative_to(ROOT) if archive.is_relative_to(ROOT) else archive}"
                  f"  ({archive.stat().st_size / 1024 / 1024:.1f} MB)")
    if not built:
        print("没有生成任何分发包，请先执行 packaging/build.py")
        return 2
    print("\nSHA256：")
    for archive in built:
        print(f"  {sha256(archive)}  {archive.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
