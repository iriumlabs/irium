@echo off
setlocal enabledelayedexpansion
title Irium GPU Miner
chcp 65001 >/dev/null 2>&1

REM ---------------------------------------------------------------
REM mine-gpu.bat - friendly entry point for Windows GPU miners.
REM
REM Drop this file alongside irium-miner-gpu.exe and double-click.
REM First run: asks for your Irium wallet address and saves it to
REM mine-config.txt next to the binary. Subsequent runs read the
REM address from there. Connects to the official Irium pool at
REM pool.irium.org:3335 (CPU/GPU profile). Auto-restarts on
REM crash with a 5-second cool-down. Close the window to stop.
REM ---------------------------------------------------------------

set "SCRIPT_DIR=%~dp0"
set "MINER_EXE=%SCRIPT_DIR%irium-miner-gpu.exe"
set "CONFIG_FILE=%SCRIPT_DIR%mine-config.txt"
set "POOL_URL=stratum+tcp://pool.irium.org:3335"

if not exist "%MINER_EXE%" (
    color 0C
    echo.
    echo  ERROR: irium-miner-gpu.exe not found in this folder.
    echo.
    echo  This script expects to live alongside irium-miner-gpu.exe.
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
    echo                    Welcome to Irium GPU Mining
    echo  ----------------------------------------------------------------
    echo.
    echo  You will mine SHA-256d shares against the Irium official pool
    echo  ^(pool.irium.org^). When one of your shares meets the
    echo  network target, the FULL block reward goes to YOUR address.
    echo  There is no pool fee.
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
echo                     Starting Irium GPU Miner
echo  ----------------------------------------------------------------
echo.
echo   Pool:    %POOL_URL%
echo   Wallet:  %WALLET%
echo   Worker:  %WALLET%.rig1
echo.
echo   The miner will auto-restart if it crashes.
echo   Close this window to stop.
echo.
echo  ----------------------------------------------------------------
echo.

:loop
echo  [%TIME%] Launching irium-miner-gpu...
"%MINER_EXE%" --wallet "%WALLET%" --pool "%POOL_URL%" --intensity 50
set "RC=!ERRORLEVEL!"
echo.
echo  [%TIME%] Miner exited with code !RC!. Restarting in 5 seconds...
echo  ^(Press Ctrl+C to stop^)
timeout /t 5 /nobreak >/dev/null
goto loop
