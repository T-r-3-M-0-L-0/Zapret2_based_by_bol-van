@echo off
:: ZAPRET2 SERVICE MANAGER - лаунчер для service2.ps1 (права запрашивает сам ps1)
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0service2.ps1"
