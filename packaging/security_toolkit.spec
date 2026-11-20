# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller 打包配置：一次产出命令行版与网页版两个单文件程序。

在项目根目录执行（macOS / Windows 通用）：
    pyinstaller --noconfirm --clean packaging/security_toolkit.spec

产物：
    dist/security-scan          命令行扫描器（Windows 为 .exe）
    dist/security-toolkit-web   本地网页界面（Windows 为 .exe）
"""

from pathlib import Path

ROOT = Path(SPECPATH).parent  # noqa: F821 - SPECPATH 由 PyInstaller 注入

block_cipher = None
COMMON = dict(
    pathex=[str(ROOT)],
    binaries=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "unittest", "pydoc", "test", "pytest"],
    noarchive=False,
)

cli = Analysis([str(ROOT / "security_scan.py")], datas=[], **COMMON)
cli_pyz = PYZ(cli.pure, cli.zipped_data, cipher=block_cipher)
cli_exe = EXE(
    cli_pyz,
    cli.scripts,
    cli.binaries,
    cli.zipfiles,
    cli.datas,
    [],
    name="security-scan",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

web = Analysis(
    [str(ROOT / "web_app.py")],
    datas=[(str(ROOT / "web" / "index.html"), "web")],
    **COMMON,
)
web_pyz = PYZ(web.pure, web.zipped_data, cipher=block_cipher)
web_exe = EXE(
    web_pyz,
    web.scripts,
    web.binaries,
    web.zipfiles,
    web.datas,
    [],
    name="security-toolkit-web",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
