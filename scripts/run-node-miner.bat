@echo off
setlocal
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0windows\run-node-miner.ps1" %*
exit /b %ERRORLEVEL%
