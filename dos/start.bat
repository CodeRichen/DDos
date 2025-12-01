@echo off
chcp 65001 >nul
cls
echo ====================================
echo    DDoS 攻擊控制台 - 快速啟動
echo ====================================
echo.
echo [1] 正在啟動 Flask 服務器...
echo.

cd /d "%~dp0"

python attack_server.py

pause
