@echo off
setlocal EnableExtensions
if not defined SIGIL_HOME set "SIGIL_HOME=%USERPROFILE%\.sigil"

set "SCRIPT=%~dp0sigil.py"
if not exist "%SCRIPT%" (
  echo sigil.py is missing next to sigil.cmd
  exit /b 1
)

set "PY="
where py >nul 2>&1 && set "PY=py -3"
if not defined PY where python3 >nul 2>&1 && set "PY=python3"
if not defined PY (
  for /f "delims=" %%I in ('where python 2^>nul') do (
    echo %%I | find /i "\WindowsApps\python.exe" >nul
    if errorlevel 1 (
      set "PY=%%I"
      goto :run
    )
  )
)

if not defined PY (
  echo.
  echo SIGIL needs a real Python, not the Microsoft Store stub.
  echo.
  echo   1. Install from https://www.python.org/downloads/
  echo      Check "Add python.exe to PATH" during setup.
  echo   2. Open a NEW PowerShell window and run:
  echo        py -3 -m pip install cryptography
  echo        .\sigil.cmd selftest
  echo.
  echo Or skip Python: double-click sigil.bundle.html
  echo.
  exit /b 1
)

:run
%PY% "%SCRIPT%" %*
exit /b %ERRORLEVEL%
