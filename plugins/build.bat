@echo off
REM Build RSH plugins
REM Requires Visual Studio or Build Tools with cl.exe in PATH

echo Building example plugin...
cl /LD /DRSH_PLUGIN_EXPORTS /O2 example_plugin.c /Fe:example.dll

if %ERRORLEVEL% EQU 0 (
    echo.
    echo Build successful! Copy example.dll to:
    echo   C:\ProgramData\remote-shell\plugins\
    echo.
    echo Then use: rsh -h HOST plugin list
) else (
    echo Build failed!
    exit /b 1
)
