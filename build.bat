@echo off
REM Build LinkGuard as a standalone Windows executable using PyInstaller
REM Run this from the project root: build.bat

set PYTHON=C:\Users\gvaro\AppData\Local\Programs\Python\Python312\python.exe

echo Installing dependencies...
%PYTHON% -m pip install -r requirements.txt --quiet

echo Building executable...
%PYTHON% -m PyInstaller ^
  --onefile ^
  --windowed ^
  --name LinkGuard ^
  --icon NONE ^
  --add-data "." ^
  main.py

echo.
if exist dist\LinkGuard.exe (
    echo Build successful: dist\LinkGuard.exe
) else (
    echo Build FAILED - check output above
)
