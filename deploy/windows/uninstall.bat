@echo off
setlocal
chcp 437 >nul
rem rust_frp Windows client uninstaller (keeps files, removes task)

net session >nul 2>&1
if %errorlevel% neq 0 (
  powershell -NoProfile -Command "Start-Process -Verb RunAs -FilePath '%~f0'"
  exit /b 1
)

rem ---- must match install.bat ----
set TASKNAME=rust_frpc_win
rem ---------------------------------

echo Stopping task...
schtasks /End /TN "%TASKNAME%" >nul 2>&1
schtasks /Delete /TN "%TASKNAME%" /F >nul 2>&1
taskkill /IM rust_frpc.exe /F >nul 2>&1
echo Removed scheduled task and stopped rust_frpc.
echo Files in C:\frpc are kept (delete manually if you want).
pause
