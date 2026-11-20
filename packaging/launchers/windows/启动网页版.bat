@echo off
chcp 65001 >nul
rem 双击启动网页界面（Windows）
rem 首次运行若出现蓝色 SmartScreen 窗口：更多信息 -> 仍要运行
cd /d "%~dp0"
start "" "security-toolkit-web.exe"
