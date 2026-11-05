@echo off
setlocal
chcp 437 >nul
rem ============================================================
rem  rust_frp Windows client in-place upgrade:
rem  stop task -> backup old exe -> swap in new exe -> restart
rem  Put the freshly built rust_frpc.exe next to this script.
rem ============================================================

net session >nul 2>&1
if %errorlevel% neq 0 (
  echo [i] Need administrator rights, asking for elevation...
  powershell -NoProfile -Command "Start-Process -Verb RunAs -FilePath '%~f0'"
  exit /b 1
)

rem ---- must match install.bat ----
set TASKNAME=rust_frpc_win
set DST=C:\frpc
rem ---------------------------------

if not exist "%~dp0rust_frpc.exe" (
  echo [x] put the NEW rust_frpc.exe in the same folder as this script.
  pause & exit /b 1
)

echo [1/4] stopping task %TASKNAME% ...
schtasks /End /TN "%TASKNAME%" >nul 2>&1
taskkill /F /IM rust_frpc.exe >nul 2>&1
ping -n 4 127.0.0.1 >nul

echo [2/4] backup old exe ...
if exist "%DST%\rust_frpc.exe" copy /Y "%DST%\rust_frpc.exe" "%DST%\rust_frpc.exe.bak" >nul

echo [3/4] swap in new exe ...
copy /Y "%~dp0rust_frpc.exe" "%DST%\rust_frpc.exe" >nul
if errorlevel 1 (
  echo [x] copy failed, restoring backup...
  copy /Y "%DST%\rust_frpc.exe.bak" "%DST%\rust_frpc.exe" >nul
  pause & exit /b 1
)

echo [4/4] starting task ...
schtasks /Run /TN "%TASKNAME%" >nul 2>&1
ping -n 7 127.0.0.1 >nul

echo.
echo ---- version: ----
"%DST%\rust_frpc.exe" --version
echo ---- listening: ----
netstat -ano | findstr "LISTENING" | findstr "127.0.0.1"
echo.
echo Done. Rollback if needed: copy %DST%\rust_frpc.exe.bak back.
pause
