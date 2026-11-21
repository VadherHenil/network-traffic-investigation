@echo off
setlocal EnableExtensions DisableDelayedExpansion
title HENIX
cd /d "%~dp0"
if not exist "app.py" (
    echo HENIX could not find app.py. Keep this launcher in the project folder.
    pause
    exit /b 1
)
if exist ".runtime\python-path.txt" (
    for /f "usebackq delims=" %%P in (".runtime\python-path.txt") do if exist "%%P" (
        "%%P" -c "import sys; sys.exit(sys.version_info < (3, 10))" >nul 2>&1
        if not errorlevel 1 (
            "%%P" app.py --port 0
            goto done
        )
    )
)
py -3 -c "import sys; sys.exit(sys.version_info < (3, 10))" >nul 2>&1
if not errorlevel 1 (
    py -3 app.py --port 0
    goto done
)
python -c "import sys; sys.exit(sys.version_info < (3, 10))" >nul 2>&1
if not errorlevel 1 (
    python app.py --port 0
    goto done
)
echo Install Python 3.10 or newer, then open this launcher again.
pause
exit /b 1
:done
if errorlevel 1 (
    pause
    exit /b 1
)
exit /b 0
