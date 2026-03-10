@echo off
setlocal
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0windows\run-miner.ps1" %*
exit /b %ERRORLEVEL%
