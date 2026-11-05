@echo off
rem ============================================================
rem  rust_frpc watchdog launcher
rem  Started by the scheduled task (SYSTEM, AT STARTUP).
rem  Keeps frpc alive: if it exits, wait 10s and restart.
rem  Edit DST below if you installed somewhere other than C:\frpc
rem ============================================================
set DST=C:\frpc
cd /d %DST%
if not exist "%DST%\frpc.log" echo. > "%DST%\frpc.log"

:loop
echo [%date% %time%] starting rust_frpc >> "%DST%\frpc.log"
"%DST%\rust_frpc.exe" -c "%DST%\frpc.toml" >> "%DST%\frpc.log" 2>&1
echo [%date% %time%] rust_frpc exited, restart in 10s >> "%DST%\frpc.log"
ping -n 11 127.0.0.1 >nul
goto loop
