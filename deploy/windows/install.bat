@echo off
setlocal
chcp 437 >nul
rem ============================================================
rem  rust_frp Windows visitor client - one-click installer
rem  (generic version, kept in repo: deploy/windows/install.bat)
rem
rem  Defaults (edit before use, or keep as-is):
rem    Target dir : C:\frpc
rem    Task name  : rust_frpc_win   (SYSTEM, AT STARTUP)
rem    Watchdog   : run.cmd auto-restarts frpc 10s after a crash
rem
rem  Expects in the SAME folder as this script:
rem    rust_frpc.exe  frpc.toml  ca.crt  client-<name>.crt
rem    client-<name>.key  run.cmd
rem  NOTE: cert/key file names vary per client machine; edit the
rem        copy lines below (and frpc.toml cert paths) to match.
rem ============================================================

net session >nul 2>&1
if %errorlevel% neq 0 (
  echo [i] Need administrator rights, asking for elevation...
  powershell -NoProfile -Command "Start-Process -Verb RunAs -FilePath '%~f0'"
  exit /b 1
)

rem ---- customize here ----
set TASKNAME=rust_frpc_win
set DST=C:\frpc
set CERT_CRT=client-win2.crt
set CERT_KEY=client-win2.key
rem ------------------------

set SRC=%~dp0

echo [1/5] install dir: %DST%
if not exist "%DST%" mkdir "%DST%"

echo [2/5] copy files
copy /Y "%SRC%rust_frpc.exe"   "%DST%\rust_frpc.exe"   >nul || goto :copyfail
copy /Y "%SRC%frpc.toml"       "%DST%\frpc.toml"       >nul || goto :copyfail
copy /Y "%SRC%%CERT_CRT%"      "%DST%\%CERT_CRT%"      >nul || goto :copyfail
copy /Y "%SRC%%CERT_KEY%"      "%DST%\%CERT_KEY%"      >nul || goto :copyfail
copy /Y "%SRC%ca.crt"          "%DST%\ca.crt"          >nul || goto :copyfail
copy /Y "%SRC%run.cmd"         "%DST%\run.cmd"         >nul || goto :copyfail

echo [3/5] verify config offline
"%DST%\rust_frpc.exe" verify -c "%DST%\frpc.toml"
if errorlevel 1 goto :verifyfail

echo [4/5] register scheduled task %TASKNAME% (SYSTEM / AT STARTUP)
schtasks /Delete /TN "%TASKNAME%" /F >nul 2>&1
schtasks /Create /TN "%TASKNAME%" /TR "%DST%\run.cmd" /SC ONSTART /RU SYSTEM /RL HIGHEST /F
if errorlevel 1 goto :taskfail

echo [5/5] start now
schtasks /Run /TN "%TASKNAME%" >nul
ping -n 8 127.0.0.1 >nul

echo.
echo ---- listening ports ----
netstat -ano | findstr "LISTENING" | findstr "127.0.0.1"
echo.
echo ---- last log lines ----
if exist "%DST%\frpc.log" powershell -NoProfile -Command "Get-Content '%DST%\frpc.log' -Tail 12"
echo.
echo Done.
pause
exit /b 0

:copyfail
echo [x] copy failed - check this folder contains all files.
pause
exit /b 1

:verifyfail
echo [x] config verify failed - check cert paths in %DST%\frpc.toml
pause
exit /b 1

:taskfail
echo [x] schtasks create failed
pause
exit /b 1
