@echo off
chcp 65001 >nul
rem Windows 双击启动：打开本地网页界面
cd /d "%~dp0"

where py >nul 2>nul
if %errorlevel%==0 (
    py -3 web_app.py --open %*
) else (
    python web_app.py --open %*
)

if errorlevel 1 (
    echo.
    echo 启动失败：请确认已安装 Python 3.10+，或直接运行 dist\security-toolkit-web.exe
    pause
)
