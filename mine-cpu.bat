@echo off
setlocal enabledelayedexpansion
title Irium CPU Miner
chcp 65001 >/dev/null 2>&1

REM ---------------------------------------------------------------
REM mine-cpu.bat - friendly entry point for Windows CPU miners.
REM
REM Drop this file alongside irium-miner.exe and double-click.
REM First run: asks for your Irium wallet address and saves it to
REM mine-config.txt next to the binary. Subsequent runs read the
REM address from there.
REM
REM The bundled irium-miner is a SOLO miner - it talks to a local
REM iriumd instance (default http://127.0.0.1:38300). Start the
REM Irium Core desktop app first OR run iriumd yourself before
REM launching this script. For pool CPU mining install cpuminer-opt
REM separately and point it at stratum+tcp://pool.irium.org:3335.
REM Auto-restarts on crash with a 5-second cool-down.
REM ---------------------------------------------------------------

set "SCRIPT_DIR=%~dp0"
set "MINER_EXE=%SCRIPT_DIR%irium-miner.exe"
set "CONFIG_FILE=%SCRIPT_DIR%mine-config.txt"
set "RPC_URL=http://127.0.0.1:38300"

if not exist "%MINER_EXE%" (
    color 0C
    echo.
    echo  ERROR: irium-miner.exe not found in this folder.
    echo.
    echo  This script expects to live alongside irium-miner.exe.
    echo  Both files must be in the same directory.
    echo.
    echo  Path checked: %MINER_EXE%
    echo.
    pause
    exit /b 1
)

set "WALLET="
if exist "%CONFIG_FILE%" (
    for /f "usebackq tokens=* delims=" %%i in ("%CONFIG_FILE%") do (
        if not defined WALLET set "WALLET=%%i"
    )
)

if not defined WALLET (
    color 0B
    echo.
    echo  ----------------------------------------------------------------
    echo                    Welcome to Irium CPU Mining
    echo  ----------------------------------------------------------------
    echo.
    echo  You will mine SHA-256d blocks against your LOCAL iriumd node
    echo  ^(solo mining^). When you find a block, the FULL reward goes
    echo  to your address. Make sure iriumd is running before you start.
    echo  Solo mining can take a long time on a CPU - for steady payouts
    echo  use the GPU miner with mine-gpu.bat against the official pool.
    echo.
    echo  Enter your Irium wallet address ^(starts with Q or P^):
    echo.
    set /p "WALLET=  Address: "
    if not defined WALLET (
        echo.
        echo  No address entered. Aborting.
        pause
        exit /b 1
    )
    > "%CONFIG_FILE%" echo !WALLET!
    echo.
    echo  Saved to %CONFIG_FILE% - delete it to re-enter the address.
    echo.
)

color 0A
echo.
echo  ----------------------------------------------------------------
echo                     Starting Irium CPU Miner
echo  ----------------------------------------------------------------
echo.
echo   RPC:     %RPC_URL%   ^(make sure iriumd is running^)
echo   Wallet:  %WALLET%
echo.
echo   The miner will auto-restart if it crashes.
echo   Close this window to stop.
echo.
echo  ----------------------------------------------------------------
echo.

set "IRIUM_MINER_ADDRESS=%WALLET%"
set "IRIUM_NODE_RPC=%RPC_URL%"

:loop
echo  [%TIME%] Launching irium-miner...
"%MINER_EXE%"
set "RC=!ERRORLEVEL!"
echo.
echo  [%TIME%] Miner exited with code !RC!. Restarting in 5 seconds...
echo  ^(Press Ctrl+C to stop^)
timeout /t 5 /nobreak >/dev/null
goto loop
