@echo off
setlocal
title StickDoc
cd /d "%~dp0"

rem Already elevated (or relaunched by us)? Then run the check.
if /i "%~1"=="--elevated" goto run
fltmc >nul 2>&1
if not errorlevel 1 goto run

echo Asking for administrator rights...
powershell -NoProfile -ExecutionPolicy Bypass -Command "try { Start-Process -FilePath '%~f0' -ArgumentList '--elevated' -Verb RunAs -ErrorAction Stop } catch { exit 1 }"
if errorlevel 1 (
  echo.
  echo No administrator rights. Running a limited check instead.
  echo.
  goto run
)
exit /b

:run
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0app\StickDoc.ps1"
echo.
pause
