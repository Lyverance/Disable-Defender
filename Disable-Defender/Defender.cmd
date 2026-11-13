@echo off
cd /d "%~dp0"
title Defender

set "SCRIPTDIR=%~dp0"
set "ALLARGS=%*"

:: Refuse to run in Safe Mode
reg query "HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Option" >nul 2>&1
if %errorLevel% equ 0 (
    echo.
    echo  [ERROR] This script cannot run in Safe Mode.
    echo.
    echo  Reboot to normal mode first, then run Defender.cmd.
    echo.
    echo %ALLARGS%| find /i "/Unattended" >nul
    if errorlevel 1 pause
    exit /b 2
)

:: Auto-elevate: if not admin, relaunch with UAC.
:: ALLARGS is a fixed set of literal flag tokens (/Status, /Disable, /Restore,
:: /Unattended, /AllowReboot), never free text, so it can be embedded directly
:: without the quoting stage-normal.ps1's own path argument needs elsewhere.
net session >nul 2>&1
if %errorLevel% equ 0 goto :run
:: Interactive run: hand over to the elevated window and close this one at
:: once, so the user sees a single window. Only an unattended caller needs
:: to wait, because it reads the elevated copy's exit code.
echo %ALLARGS%| find /i "/Unattended" >nul
if errorlevel 1 goto :elevate_and_close
powershell -NoProfile -Command "$ErrorActionPreference = 'Stop'; $arguments = '/d /c {0}{0}{1}{0} {2}{0}' -f [char]34, ($env:SCRIPTDIR + 'Defender.cmd'), $env:ALLARGS; $process = Start-Process -FilePath $env:ComSpec -ArgumentList $arguments -Verb RunAs -PassThru; try { $process.WaitForExit(); exit $process.ExitCode } finally { $process.Dispose() }"
exit /b %errorLevel%

:elevate_and_close
powershell -NoProfile -Command "$ErrorActionPreference = 'Stop'; $arguments = '/d /c {0}{0}{1}{0} {2}{0}' -f [char]34, ($env:SCRIPTDIR + 'Defender.cmd'), $env:ALLARGS; Start-Process -FilePath $env:ComSpec -ArgumentList $arguments -Verb RunAs"
exit /b %errorLevel%

:run
powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPTDIR%.internal\entry.ps1" %*

:: errorLevel is volatile -- any subsequent command overwrites it, so save it immediately.
:: entry.ps1 and the action it calls handle their own pauses before a reboot;
:: here we only pause on a nonzero exit and only if /Unattended was not
:: passed, so an interactive user sees why before the window closes.
set "PS_EXIT=%errorLevel%"
if "%PS_EXIT%" neq "0" (
    echo.
    echo  [Script exited with error code %PS_EXIT%]
    echo %ALLARGS%| find /i "/Unattended" >nul
    if errorlevel 1 pause
)
exit /b %PS_EXIT%
