@echo off
rem Runs the Buck2 release that toolchains\buck2 pins through DotSlash from
rem PATH or the copy that bootstrap.ps1 installs into .tools. Add this
rem directory to PATH to run it as buck2.
setlocal
for %%I in ("%~dp0..") do set "ROOT=%%~fI"

where dotslash.exe >nul 2>&1
if not errorlevel 1 (
    set "DOTSLASH=dotslash.exe"
) else (
    if not exist "%ROOT%\.tools\bin\dotslash.exe" (
        rem Bootstrap messages go to stderr so they do not mix with Buck2 output.
        powershell -NoProfile -ExecutionPolicy Bypass -File "%ROOT%\bootstrap.ps1" 1>&2 || exit /b 1
    )
    set "DOTSLASH=%ROOT%\.tools\bin\dotslash.exe"
)

set "DOTSLASH_CACHE=%ROOT%\.tools\dotslash"
"%DOTSLASH%" "%ROOT%\toolchains\buck2" %*
exit /b %ERRORLEVEL%
